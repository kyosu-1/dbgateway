// Package mysql implements the analysis.Adapter for MySQL using the TiDB
// SQL parser (github.com/pingcap/tidb/pkg/parser) and go-sql-driver/mysql.
//
// Every session runs with a fixed sql_mode (see SQLMode) and the parser is
// configured with the same mode, so the analyzed statement is the executed
// statement.
package mysql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"time"

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
)

// Adapter is the MySQL adapter.
type Adapter struct {
	*Analyzer
}

var _ analysis.Adapter = (*Adapter)(nil)

// New returns a MySQL adapter. extraFunctions extends the function
// allowlist ("name" or "db.name").
func New(extraFunctions []string) *Adapter {
	return &Adapter{Analyzer: NewAnalyzer(NewFunctionAllowlist(extraFunctions))}
}

// conn holds the pools for one configured database.
type conn struct {
	cfg     *config.Database
	schema  string // the default database (MySQL "schema")
	read    *sql.DB
	replica *sql.DB // nil when no replica is configured
}

func (c *conn) Close() {
	_ = c.read.Close()
	if c.replica != nil {
		_ = c.replica.Close()
	}
}

// Connect opens the read pool (and the replica pool when configured).
// Pools connect lazily, so a database that is down does not prevent
// dbgateway from starting.
func (a *Adapter) Connect(_ context.Context, cfg *config.Database) (analysis.Conn, error) {
	read, err := newPool(cfg.Primary, cfg.Primary.ReadUser, cfg.Primary.PasswordEnv)
	if err != nil {
		return nil, fmt.Errorf("database %s: %w", cfg.Name, err)
	}
	c := &conn{cfg: cfg, schema: cfg.Primary.DBName, read: read}
	if cfg.Replica != nil {
		c.replica, err = newPool(*cfg.Replica, cfg.Replica.ReadUser, cfg.Replica.PasswordEnv)
		if err != nil {
			_ = read.Close()
			return nil, fmt.Errorf("database %s replica: %w", cfg.Name, err)
		}
	}
	return c, nil
}

// tlsConfig maps the sslmode setting to a TLS configuration:
//
//	disable      no TLS
//	require      TLS without certificate verification
//	verify-full  TLS, certificate verified against sslrootcert (or the
//	             system roots) and the host name
//
// verify-ca (verification without the host name check) is not supported.
func tlsConfig(ep config.Endpoint) (*tls.Config, error) {
	switch ep.SSLMode {
	case "disable":
		return nil, nil
	case "require":
		return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, nil //nolint:gosec // sslmode=require means no verification
	case "verify-full":
		tc := &tls.Config{ServerName: ep.Host, MinVersion: tls.VersionTLS12}
		if ep.SSLRootCert != "" {
			pem, err := os.ReadFile(ep.SSLRootCert)
			if err != nil {
				return nil, fmt.Errorf("read sslrootcert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("sslrootcert: no certificates found")
			}
			tc.RootCAs = pool
		}
		return tc, nil
	}
	return nil, fmt.Errorf("sslmode %q is not supported for mysql (use disable, require or verify-full)", ep.SSLMode)
}

func newPool(ep config.Endpoint, user, passwordEnv string) (*sql.DB, error) {
	mc := gomysql.NewConfig()
	mc.User = user
	if passwordEnv != "" {
		pw, ok := os.LookupEnv(passwordEnv)
		if !ok {
			return nil, fmt.Errorf("environment variable %s is not set", passwordEnv)
		}
		mc.Passwd = pw
	}
	mc.Net = "tcp"
	mc.Addr = net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	mc.DBName = ep.DBName
	tc, err := tlsConfig(ep)
	if err != nil {
		return nil, err
	}
	mc.TLS = tc
	mc.Timeout = 10 * time.Second
	mc.ParseTime = true
	mc.Loc = time.UTC
	mc.ConnectionAttributes = "program_name:dbgateway"
	mc.Logger = &gomysql.NopLogger{}
	// Explicitly keep the safe defaults: statements are sent as server-side
	// prepared statements, never with client-side interpolation, and the
	// server refuses several statements in one request.
	mc.InterpolateParams = false
	mc.MultiStatements = false
	mc.AllowAllFiles = false
	mc.AllowCleartextPasswords = false
	mc.AllowOldPasswords = false

	connector, err := gomysql.NewConnector(mc)
	if err != nil {
		return nil, errors.New("invalid connection settings") // never echo the configuration (it has the password)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(10)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return db, nil
}

func (c *conn) pool(replica bool) *sql.DB {
	if replica && c.replica != nil {
		return c.replica
	}
	return c.read
}

// withReadTx runs fn in a READ ONLY transaction on a dedicated connection
// with the fixed sql_mode, time zone and timeouts. MySQL has no statement
// to reset a session from SQL and go-sql-driver does not send
// COM_RESET_CONNECTION, so the connection is discarded afterwards instead
// of being returned to the pool: no session state can leak into the next
// request.
func (c *conn) withReadTx(ctx context.Context, opt analysis.ExecOptions, fn func(context.Context, *sql.Tx) error) error {
	timeout := opt.StatementTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()

	sc, err := c.pool(opt.Replica).Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() {
		// Returning ErrBadConn makes database/sql close the connection.
		_ = sc.Raw(func(any) error { return driver.ErrBadConn })
		_ = sc.Close()
	}()

	lock := opt.LockTimeout
	if lock <= 0 {
		lock = 2 * time.Second
	}
	lockSec := max(int64(math.Ceil(lock.Seconds())), 1)
	if _, err := sc.ExecContext(ctx, fmt.Sprintf(
		"SET SESSION sql_mode = '%s', SESSION time_zone = '+00:00', SESSION max_execution_time = %d, "+
			"SESSION lock_wait_timeout = %d, SESSION innodb_lock_wait_timeout = %d",
		SQLMode, max(timeout.Milliseconds(), 1), lockSec, lockSec)); err != nil {
		return fmt.Errorf("configure session: %w", err)
	}
	tx, err := sc.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	return fn(ctx, tx)
}

// Execute runs a read-only statement as a server-side prepared statement.
func (a *Adapter) Execute(ctx context.Context, ac analysis.Conn, query string, opt analysis.ExecOptions) (*analysis.Result, error) {
	if !opt.ReadOnly {
		return nil, errors.New("write execution is not supported yet for mysql")
	}
	c := ac.(*conn)
	res := &analysis.Result{TotalRows: -1}
	start := time.Now()
	err := c.withReadTx(ctx, opt, func(ctx context.Context, tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, query)
		if err != nil {
			return err
		}
		defer stmt.Close()
		rows, err := stmt.QueryContext(ctx)
		if err != nil {
			return err
		}
		defer rows.Close()
		types, err := rows.ColumnTypes()
		if err != nil {
			return err
		}
		typeNames := make([]string, len(types))
		for i, ct := range types {
			typeNames[i] = ct.DatabaseTypeName()
			res.Columns = append(res.Columns, analysis.ResultColumn{Name: ct.Name(), Type: typeNames[i]})
		}
		raw := make([]any, len(types))
		dest := make([]any, len(types))
		for i := range raw {
			dest[i] = &raw[i]
		}
		var produced int64
		for rows.Next() {
			produced++
			if res.Truncated {
				continue // keep counting to report the total
			}
			if err := rows.Scan(dest...); err != nil {
				return err
			}
			var size int64
			for _, v := range raw {
				size += valueSize(v)
			}
			if (opt.MaxRows > 0 && res.RowCount >= opt.MaxRows) || (opt.MaxBytes > 0 && res.Bytes+size > opt.MaxBytes) {
				res.Truncated = true
				continue
			}
			row := make([]any, len(raw))
			for i, v := range raw {
				row[i] = jsonValue(v, typeNames[i])
			}
			res.Rows = append(res.Rows, row)
			res.RowCount++
			res.Bytes += size
		}
		if err := rows.Err(); err != nil {
			if res.Truncated {
				// Counting the remainder failed (e.g. timeout); the
				// returned rows are still valid.
				return nil
			}
			return err
		}
		res.TotalRows = produced
		return nil
	})
	res.Duration = time.Since(start)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Estimate returns the optimizer estimate via EXPLAIN FORMAT=JSON. The SQL
// has already been analyzed as a single statement.
func (a *Adapter) Estimate(ctx context.Context, ac analysis.Conn, query string, opt analysis.ExecOptions) (*analysis.Estimate, error) {
	c := ac.(*conn)
	var est *analysis.Estimate
	err := c.withReadTx(ctx, opt, func(ctx context.Context, tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRowContext(ctx, "EXPLAIN FORMAT=JSON "+query).Scan(&raw); err != nil {
			return err
		}
		var err error
		est, err = parseExplain([]byte(raw))
		return err
	})
	if err != nil {
		return nil, err
	}
	return est, nil
}

// parseExplain extracts the row and cost estimate from EXPLAIN FORMAT=JSON
// output. Format version 1 (the MySQL 8.4 default) nests "table" objects
// with rows_produced_per_join under query_block; version 2 has
// estimated_rows and estimated_total_cost at the root.
func parseExplain(raw []byte) (*analysis.Estimate, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.New("unexpected EXPLAIN output")
	}
	if rows, ok := number(doc["estimated_rows"]); ok {
		cost, _ := number(doc["estimated_total_cost"])
		return &analysis.Estimate{Rows: rows, Cost: cost}, nil
	}
	qb, ok := doc["query_block"].(map[string]any)
	if !ok {
		return nil, errors.New("unexpected EXPLAIN output")
	}
	est := &analysis.Estimate{}
	if ci, ok := qb["cost_info"].(map[string]any); ok {
		est.Cost, _ = number(ci["query_cost"])
	}
	// The estimate is the largest per-join row count of the outer query
	// block's tables (the final join size); subqueries are not counted.
	var found bool
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if t, ok := x["table"].(map[string]any); ok {
				rows, ok := number(t["rows_produced_per_join"])
				if !ok {
					rows, ok = number(t["rows_examined_per_scan"])
				}
				if ok {
					found = true
					est.Rows = max(est.Rows, rows)
				}
			}
			for k, child := range x {
				if k == "table" || k == "attached_subqueries" || k == "optimized_away_subqueries" ||
					k == "select_list_subqueries" || k == "having_subqueries" || k == "order_by_subqueries" ||
					k == "group_by_subqueries" || k == "update_value_subqueries" {
					continue
				}
				walk(child)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(qb)
	if !found {
		if msg, _ := qb["message"].(string); msg == "No tables used" {
			est.Rows = 1
		}
	}
	return est, nil
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}
