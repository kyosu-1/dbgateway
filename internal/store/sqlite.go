package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// SQLite is a Store backed by a single SQLite file.
type SQLite struct {
	db *sql.DB
}

var _ Store = (*SQLite)(nil)

// OpenSQLite opens (creating if needed) the SQLite database at path and
// applies pending migrations. path may be ":memory:" for tests.
func OpenSQLite(ctx context.Context, path string) (*SQLite, error) {
	memory := path == ":memory:"
	if !memory {
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("store: create directory: %w", err)
			}
		}
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_txlock", "immediate")
	if !memory {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(NORMAL)")
	}
	dsn := "file:" + path + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if memory {
		// Every connection to ":memory:" is a separate database.
		db.SetMaxOpenConns(1)
	}
	s := &SQLite{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	names, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		base := filepath.Base(name)
		version, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("store: bad migration name %q", base)
		}
		if err := s.applyMigration(ctx, version, name); err != nil {
			return fmt.Errorf("store: migration %s: %w", base, err)
		}
	}
	return nil
}

func (s *SQLite) applyMigration(ctx context.Context, version int, name string) error {
	body, err := migrationFS.ReadFile(name)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, string(body)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, version, time.Now().UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteExpired removes expired sessions, codes, tokens, enrollment links
// and WebAuthn ceremonies.
func (s *SQLite) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	ms := before.UnixMilli()
	var total int64
	for _, table := range []string{"sessions", "auth_codes", "device_codes", "tokens", "passkey_enrollments", "webauthn_sessions", "console_history", "quota_usage"} {
		res, err := s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE expires_at < ?`, ms)
		if err != nil {
			return total, fmt.Errorf("store: delete expired %s: %w", table, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// --- helpers ---

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v) }

func nullMS(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixMilli(), Valid: true}
}

func fromNullMS(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64)
	return &t
}

func encodeList(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func decodeList(s string) ([]string, error) {
	var v []string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("store: decode list: %w", err)
	}
	return v, nil
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func insertErr(err error) error {
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

type scanner interface{ Scan(dest ...any) error }
