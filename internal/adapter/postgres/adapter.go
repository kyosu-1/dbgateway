// Package postgres implements the analysis.Adapter for PostgreSQL using
// pg_query_go (the real PostgreSQL parser) and pgx.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
)

// Adapter is the PostgreSQL adapter.
type Adapter struct {
	*Analyzer
}

var _ analysis.Adapter = (*Adapter)(nil)

// New returns a PostgreSQL adapter. extraFunctions extends the function
// allowlist.
func New(extraFunctions []string) *Adapter {
	return &Adapter{Analyzer: NewAnalyzer(NewFunctionAllowlist(extraFunctions))}
}

// conn holds the pools for one configured database.
type conn struct {
	cfg     *config.Database
	read    *pgxpool.Pool
	replica *pgxpool.Pool // nil when no replica is configured
}

func (c *conn) Close() {
	c.read.Close()
	if c.replica != nil {
		c.replica.Close()
	}
}

// Connect opens the read pool (and the replica pool when configured).
// Pools connect lazily, so a database that is down does not prevent
// dbgateway from starting.
func (a *Adapter) Connect(ctx context.Context, cfg *config.Database) (analysis.Conn, error) {
	read, err := newPool(ctx, cfg.Primary, cfg.Primary.ReadUser, cfg.Primary.PasswordEnv, true)
	if err != nil {
		return nil, fmt.Errorf("database %s: %w", cfg.Name, err)
	}
	c := &conn{cfg: cfg, read: read}
	if cfg.Replica != nil {
		c.replica, err = newPool(ctx, *cfg.Replica, cfg.Replica.ReadUser, cfg.Replica.PasswordEnv, true)
		if err != nil {
			read.Close()
			return nil, fmt.Errorf("database %s replica: %w", cfg.Name, err)
		}
	}
	return c, nil
}

func newPool(ctx context.Context, ep config.Endpoint, user, passwordEnv string, readOnly bool) (*pgxpool.Pool, error) {
	u := url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%d", ep.Host, ep.Port),
		Path:   "/" + ep.DBName,
		User:   url.User(user),
	}
	q := url.Values{}
	q.Set("sslmode", ep.SSLMode)
	if ep.SSLRootCert != "" {
		q.Set("sslrootcert", ep.SSLRootCert)
	}
	q.Set("application_name", "dbgateway")
	u.RawQuery = q.Encode()

	pc, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		return nil, errors.New("invalid connection settings")
	}
	if err := configureAuth(ctx, pc, ep, user, passwordEnv); err != nil {
		return nil, err
	}
	pc.MaxConns = 10
	pc.MaxConnIdleTime = 5 * time.Minute
	// Extended protocol without a statement cache: the server refuses
	// multiple statements in one Parse, and DISCARD ALL after every request
	// would invalidate cached statements anyway.
	pc.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec
	if readOnly {
		// Defense in depth on top of READ ONLY transactions.
		pc.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	}
	return pgxpool.NewWithConfig(ctx, pc)
}

func (c *conn) pool(replica bool) *pgxpool.Pool {
	if replica && c.replica != nil {
		return c.replica
	}
	return c.read
}

// withReadTx runs fn in a READ ONLY transaction with timeouts and the fixed
// search path, then resets the connection state with DISCARD ALL. A
// connection whose state cannot be reset is destroyed rather than reused.
func (c *conn) withReadTx(ctx context.Context, opt analysis.ExecOptions, fn func(pgx.Tx) error) error {
	timeout := opt.StatementTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()

	pc, err := c.pool(opt.Replica).Acquire(ctx)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rcancel()
		if _, err := pc.Exec(rctx, "DISCARD ALL"); err != nil {
			raw := pc.Hijack()
			_ = raw.Close(rctx)
			return
		}
		pc.Release()
	}()

	tx, err := pc.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	lock := opt.LockTimeout
	if lock <= 0 {
		lock = 2 * time.Second
	}
	if _, err := tx.Exec(ctx,
		"SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $2, true), set_config('search_path', $3, true)",
		strconv.FormatInt(timeout.Milliseconds(), 10),
		strconv.FormatInt(lock.Milliseconds(), 10),
		searchPath(c.cfg.SearchPath),
	); err != nil {
		return fmt.Errorf("configure session: %w", err)
	}
	return fn(tx)
}

func searchPath(schemas []string) string {
	parts := make([]string, 0, len(schemas))
	for _, s := range schemas {
		parts = append(parts, pgx.Identifier{s}.Sanitize())
	}
	return strings.Join(parts, ", ")
}

// Execute runs a read-only statement. Phase 1 never executes writes.
func (a *Adapter) Execute(ctx context.Context, ac analysis.Conn, sql string, opt analysis.ExecOptions) (*analysis.Result, error) {
	if !opt.ReadOnly {
		return nil, errors.New("write execution is not supported (approvals are not enabled)")
	}
	c := ac.(*conn)
	res := &analysis.Result{TotalRows: -1}
	start := time.Now()
	err := c.withReadTx(ctx, opt, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql)
		if err != nil {
			return err
		}
		defer rows.Close()
		tm := tx.Conn().TypeMap()
		for _, fd := range rows.FieldDescriptions() {
			typ := strconv.FormatUint(uint64(fd.DataTypeOID), 10)
			if t, ok := tm.TypeForOID(fd.DataTypeOID); ok {
				typ = t.Name
			}
			res.Columns = append(res.Columns, analysis.ResultColumn{Name: fd.Name, Type: typ})
		}
		var produced int64
		for rows.Next() {
			produced++
			if res.Truncated {
				continue // keep counting to report the total
			}
			raw := rows.RawValues()
			var size int64
			for _, v := range raw {
				size += int64(len(v))
			}
			if (opt.MaxRows > 0 && res.RowCount >= opt.MaxRows) || (opt.MaxBytes > 0 && res.Bytes+size > opt.MaxBytes) {
				res.Truncated = true
				continue
			}
			vals, err := rows.Values()
			if err != nil {
				return err
			}
			row := make([]any, len(vals))
			for i, v := range vals {
				row[i] = jsonValue(v)
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

// Estimate returns the planner estimate via EXPLAIN (FORMAT JSON). The SQL
// has already been analyzed as a single statement.
func (a *Adapter) Estimate(ctx context.Context, ac analysis.Conn, sql string, opt analysis.ExecOptions) (*analysis.Estimate, error) {
	c := ac.(*conn)
	var est analysis.Estimate
	err := c.withReadTx(ctx, opt, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+sql).Scan(&raw); err != nil {
			return err
		}
		var plans []struct {
			Plan struct {
				Rows float64 `json:"Plan Rows"`
				Cost float64 `json:"Total Cost"`
			} `json:"Plan"`
		}
		if err := json.Unmarshal(raw, &plans); err != nil || len(plans) == 0 {
			return fmt.Errorf("unexpected EXPLAIN output")
		}
		est.Rows, est.Cost = plans[0].Plan.Rows, plans[0].Plan.Cost
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &est, nil
}
