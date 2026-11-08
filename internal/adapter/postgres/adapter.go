// Package postgres implements the analysis.Adapter for PostgreSQL using
// pg_query_go (the real PostgreSQL parser) and pgx.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
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
	// write is the write user's pool on the primary; nil when no write user
	// is configured or the pool could not be set up (writeErr says why).
	write    *pgxpool.Pool
	writeErr error
}

func (c *conn) Close() {
	c.read.Close()
	if c.replica != nil {
		c.replica.Close()
	}
	if c.write != nil {
		c.write.Close()
	}
}

// Connect opens the read pool (and the replica and write pools when
// configured). Pools connect lazily, so a database that is down does not
// prevent dbgateway from starting. A broken write configuration (e.g. a
// missing password variable) does not prevent reads; writes then fail.
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
	if cfg.Primary.WriteUser == "" {
		c.writeErr = errNoWriteUser
	} else if c.write, err = newPool(ctx, cfg.Primary, cfg.Primary.WriteUser, cfg.Primary.WritePasswordEnv, false); err != nil {
		c.writeErr = fmt.Errorf("database %s write user: %w", cfg.Name, err)
	}
	return c, nil
}

var errNoWriteUser = errors.New("no write user is configured for this database")

func (c *conn) writePool() (*pgxpool.Pool, error) {
	if c.write == nil {
		return nil, c.writeErr
	}
	return c.write, nil
}

func newPool(ctx context.Context, ep config.Endpoint, user, passwordEnv string, readOnly bool) (*pgxpool.Pool, error) {
	u := url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%d", ep.Host, ep.Port),
		Path:   "/" + ep.DBName,
	}
	if passwordEnv != "" {
		pw, ok := os.LookupEnv(passwordEnv)
		if !ok {
			return nil, fmt.Errorf("environment variable %s is not set", passwordEnv)
		}
		u.User = url.UserPassword(user, pw)
	} else {
		u.User = url.User(user)
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
		return nil, errors.New("invalid connection settings") // never echo the DSN (it has the password)
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

// withReadTx runs fn in a READ ONLY transaction on the read (or replica)
// pool; see withTx.
func (c *conn) withReadTx(ctx context.Context, opt analysis.ExecOptions, fn func(pgx.Tx) error) error {
	return c.withTx(ctx, c.pool(opt.Replica), pgx.ReadOnly, opt, fn)
}

// withTx runs fn in a transaction with the given access mode, timeouts and
// the fixed search path, then resets the connection state with DISCARD
// ALL. A connection whose state cannot be reset is destroyed rather than
// reused. The transaction is rolled back unless fn commits it.
func (c *conn) withTx(ctx context.Context, pool *pgxpool.Pool, mode pgx.TxAccessMode, opt analysis.ExecOptions, fn func(pgx.Tx) error) error {
	timeout := opt.StatementTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()

	pc, err := pool.Acquire(ctx)
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

	tx, err := pc.BeginTx(ctx, pgx.TxOptions{AccessMode: mode})
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

// Execute runs one statement. Reads run in a READ ONLY transaction on the
// read (or replica) pool. Writes (opt.ReadOnly == false) run on the write
// pool in a READ WRITE transaction that is committed only when the number
// of affected rows is within opt.MaxAffectedRows.
func (a *Adapter) Execute(ctx context.Context, ac analysis.Conn, sql string, opt analysis.ExecOptions) (*analysis.Result, error) {
	c := ac.(*conn)
	if !opt.ReadOnly {
		return c.executeWrite(ctx, sql, opt)
	}
	res := &analysis.Result{TotalRows: -1}
	start := time.Now()
	err := c.withReadTx(ctx, opt, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql)
		if err != nil {
			return err
		}
		defer rows.Close()
		produced, err := collectRows(tx, rows, opt, res)
		if err != nil {
			return err
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

// executeWrite runs a write and its RETURNING rows. Every row is consumed
// (the statement must complete) even when the returned rows are truncated.
func (c *conn) executeWrite(ctx context.Context, sql string, opt analysis.ExecOptions) (*analysis.Result, error) {
	if opt.MaxAffectedRows <= 0 {
		return nil, errors.New("refusing a write without an affected-rows limit")
	}
	pool, err := c.writePool()
	if err != nil {
		return nil, err
	}
	res := &analysis.Result{TotalRows: -1}
	start := time.Now()
	err = c.withTx(ctx, pool, pgx.ReadWrite, opt, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql)
		if err != nil {
			return err
		}
		produced, err := collectRows(tx, rows, opt, res)
		rows.Close()
		if err == nil {
			err = rows.Err()
		}
		if err != nil {
			return err
		}
		res.TotalRows = produced
		res.RowsAffected = rows.CommandTag().RowsAffected()
		if res.RowsAffected > opt.MaxAffectedRows {
			return &analysis.AffectedRowsError{Affected: res.RowsAffected, Max: opt.MaxAffectedRows}
		}
		return tx.Commit(ctx)
	})
	res.Duration = time.Since(start)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// collectRows reads the result rows into res within the row and byte
// limits, counting (but not keeping) rows beyond them. It returns the
// number of rows produced.
func collectRows(tx pgx.Tx, rows pgx.Rows, opt analysis.ExecOptions, res *analysis.Result) (int64, error) {
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
			return produced, err
		}
		row := make([]any, len(vals))
		for i, v := range vals {
			row[i] = jsonValue(v)
		}
		res.Rows = append(res.Rows, row)
		res.RowCount++
		res.Bytes += size
	}
	return produced, nil
}

// Estimate returns the planner estimate via EXPLAIN (FORMAT JSON). The SQL
// has already been analyzed as a single statement. Writes are planned by
// the write user (planning checks its privileges) inside a READ ONLY
// transaction: EXPLAIN without ANALYZE never executes the statement. For
// writes, Rows is the number of rows the statement is expected to modify.
func (a *Adapter) Estimate(ctx context.Context, ac analysis.Conn, sql string, opt analysis.ExecOptions) (*analysis.Estimate, error) {
	c := ac.(*conn)
	pool := c.pool(opt.Replica)
	if !opt.ReadOnly {
		var err error
		if pool, err = c.writePool(); err != nil {
			return nil, err
		}
	}
	var est *analysis.Estimate
	err := c.withTx(ctx, pool, pgx.ReadOnly, opt, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+sql).Scan(&raw); err != nil {
			return err
		}
		var err error
		est, err = parseExplain(raw, !opt.ReadOnly)
		return err
	})
	if err != nil {
		return nil, err
	}
	return est, nil
}

// planNode is a node of EXPLAIN (FORMAT JSON) output.
type planNode struct {
	NodeType string     `json:"Node Type"`
	Rows     float64    `json:"Plan Rows"`
	Cost     float64    `json:"Total Cost"`
	Plans    []planNode `json:"Plans"`
}

// parseExplain extracts the estimate. A ModifyTable node reports 0 rows
// unless the statement has RETURNING, so for writes the rows feeding every
// ModifyTable node (including those of writable CTEs) are summed instead.
func parseExplain(raw []byte, write bool) (*analysis.Estimate, error) {
	var plans []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) == 0 {
		return nil, fmt.Errorf("unexpected EXPLAIN output")
	}
	top := plans[0].Plan
	est := &analysis.Estimate{Rows: top.Rows, Cost: top.Cost}
	if !write {
		return est, nil
	}
	var modified float64
	found := false
	var walk func(n planNode)
	walk = func(n planNode) {
		if n.NodeType == "ModifyTable" {
			found = true
			if len(n.Plans) > 0 {
				modified += n.Plans[0].Rows
			}
		}
		for _, c := range n.Plans {
			walk(c)
		}
	}
	walk(top)
	if found {
		est.Rows = modified
	}
	return est, nil
}
