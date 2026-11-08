package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQL backend.
//
// The schema lives in migrations/postgres/ and uses the same version
// numbers, tables and columns as the SQLite migrations, with native types:
// timestamptz for times (written in UTC, truncated to milliseconds like
// SQLite's unix-millisecond columns) and jsonb for lists and documents.
//
// Several dbgateway instances may share one database. Every operation that
// SQLite makes atomic through its single writer is made atomic here with a
// conditional UPDATE ... WHERE <state> (RETURNING), a row lock (SELECT ...
// FOR UPDATE) or a transaction-scoped advisory lock (migrations, SCIM).

//go:embed migrations/postgres/*.sql
var pgMigrationFS embed.FS

// Advisory lock keys, shared by every instance using the same database.
// They start with "dbgw" (0x64626777) to stay clear of other applications.
const (
	pgLockMigrate int64 = 0x64626777_00000001
	pgLockSCIM    int64 = 0x64626777_00000002
)

// pgUniqueViolation is the SQLSTATE of a unique constraint violation.
const pgUniqueViolation = "23505"

// Postgres is a Store backed by PostgreSQL. It is safe for concurrent use,
// also by several processes sharing the database.
type Postgres struct {
	pool *pgxpool.Pool
}

var _ Store = (*Postgres)(nil)

// OpenPostgres connects to the PostgreSQL database at dsn (a URL or
// key=value connection string) and applies pending migrations. Concurrent
// instances serialize their migrations with an advisory lock.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// pgx redacts the password from parse errors.
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	// Session time zone UTC: timestamptz values are rendered and compared
	// in UTC regardless of the server default.
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	if cfg.ConnConfig.RuntimeParams["application_name"] == "" {
		cfg.ConnConfig.RuntimeParams["application_name"] = "dbgateway"
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	s := &Postgres{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the connection pool.
func (s *Postgres) Close() error {
	s.pool.Close()
	return nil
}

func (s *Postgres) migrate(ctx context.Context) error {
	names, err := fs.Glob(pgMigrationFS, "migrations/postgres/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		base := path.Base(name)
		version, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("store: bad migration name %q", base)
		}
		if err := s.applyMigration(ctx, version, name); err != nil {
			return fmt.Errorf("store: migration postgres/%s: %w", base, err)
		}
	}
	return nil
}

// applyMigration applies one migration in its own transaction, holding the
// migration advisory lock so that instances starting together apply each
// migration exactly once.
func (s *Postgres) applyMigration(ctx context.Context, version int, name string) error {
	body, err := pgMigrationFS.ReadFile(name)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, pgLockMigrate); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version    integer PRIMARY KEY,
			applied_at timestamptz NOT NULL
		)`); err != nil {
			return err
		}
		var applied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			return nil
		}
		// Without arguments pgx uses the simple protocol, which accepts
		// several statements.
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`, version, pgTime(time.Now()))
		return err
	})
}

// DeleteExpired removes expired sessions, codes and tokens.
func (s *Postgres) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	for _, table := range []string{"sessions", "auth_codes", "device_codes", "tokens", "passkey_enrollments", "webauthn_sessions"} {
		tag, err := s.pool.Exec(ctx, `DELETE FROM `+table+` WHERE expires_at < $1`, pgTime(before))
		if err != nil {
			return total, fmt.Errorf("store: delete expired %s: %w", table, err)
		}
		total += tag.RowsAffected()
	}
	return total, nil
}

// --- helpers (prefixed with pg to keep them apart from the SQLite ones) ---

// pgQuerier is implemented by *pgxpool.Pool and pgx.Tx.
type pgQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var (
	_ pgQuerier = (*pgxpool.Pool)(nil)
	_ pgQuerier = (pgx.Tx)(nil)
)

// inTx runs fn in a transaction (READ COMMITTED), committing if it returns
// nil and rolling back otherwise.
func (s *Postgres) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, fn)
}

// pgTime converts a time for storage: UTC, millisecond precision (the
// precision of the SQLite backend).
func pgTime(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

// pgNullTime is pgTime for nullable columns.
func pgNullTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := pgTime(*t)
	return &v
}

// fromPGTime normalizes a scanned time to UTC.
func fromPGTime(t time.Time) time.Time { return t.UTC() }

func fromPGNullTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}

// pgJSON returns a JSON document for a jsonb parameter, def when empty.
func pgJSON(b []byte, def string) string {
	if len(b) == 0 {
		return def
	}
	return string(b)
}

// pgNullJSON returns NULL for an empty document.
func pgNullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

func pgNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func pgIsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

func pgInsertErr(err error) error {
	if pgIsUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// pgArgs collects query arguments and returns their placeholders, for
// queries assembled from optional conditions.
type pgArgs []any

func (a *pgArgs) add(v any) string {
	*a = append(*a, v)
	return "$" + strconv.Itoa(len(*a))
}

// pgCollect scans every row with scan.
func pgCollect[T any](rows pgx.Rows, scan func(scanner) (T, error)) ([]T, error) {
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
