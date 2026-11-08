package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// PostgresQuerier runs queries; *pgxpool.Pool, *pgx.Conn and pgx.Tx
// implement it.
type PostgresQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// pgCursor is the position of the last returned row.
type pgCursor struct {
	Seq int64 `json:"s"`
}

func (c pgCursor) encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodePGCursor(s string) (pgCursor, error) {
	var c pgCursor
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(b, &c) != nil || c.Seq <= 0 {
		return pgCursor{}, ErrInvalidCursor
	}
	return c, nil
}

// Search returns the entries matching f, newest first, like SearchPostgres.
func (s *PostgresSink) Search(ctx context.Context, f Filter) (Page, error) {
	return SearchPostgres(ctx, s.pool, f)
}

// SearchPostgres is Search for the PostgreSQL sink: it returns the entries
// of audit_log matching f, newest first, with the same filter semantics
// and page shape as the file search. The filter runs in SQL on the indexed
// columns and is re-checked on the decoded entries.
func SearchPostgres(ctx context.Context, db PostgresQuerier, f Filter) (Page, error) {
	var page Page
	limit := f.Limit
	if limit <= 0 {
		limit = defaultSearchLimit
	}
	limit = min(limit, MaxSearchLimit)

	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if f.Cursor != "" {
		c, err := decodePGCursor(f.Cursor)
		if err != nil {
			return page, err
		}
		where = append(where, "seq < "+arg(c.Seq))
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= "+arg(f.Since.UTC()))
	}
	if !f.Until.IsZero() {
		where = append(where, "ts < "+arg(f.Until.UTC()))
	}
	if f.RequestID != "" {
		where = append(where, "request_id = "+arg(f.RequestID))
	}
	if f.Database != "" {
		where = append(where, "database_name = "+arg(f.Database))
	}
	if f.Decision != "" {
		where = append(where, "decision = "+arg(f.Decision))
	}
	if f.Event != "" {
		where = append(where, "event = "+arg(f.Event))
	}
	if f.Principal != "" {
		p := arg(strings.ToLower(f.Principal))
		where = append(where, "(strpos(lower(principal_human), "+p+") > 0 OR strpos(lower(principal_agent), "+p+") > 0)")
	}
	if f.Table != "" {
		t := arg(strings.ToLower(f.Table))
		where = append(where, "EXISTS (SELECT 1 FROM unnest(tables) AS x(name) WHERE x.name = "+t+
			" OR right(x.name, length("+t+") + 1) = '.' || "+t+")")
	}
	q := `SELECT seq, line FROM audit_log`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY seq DESC LIMIT " + arg(limit)

	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	m := newMatcher(f)
	var n int
	var last int64
	for rows.Next() {
		var line string
		if err := rows.Scan(&last, &line); err != nil {
			return page, err
		}
		n++
		var e StoredEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			page.Skipped++
			continue
		}
		if !m.match(&e) {
			continue
		}
		page.Entries = append(page.Entries, e)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if n == limit {
		page.NextCursor = pgCursor{Seq: last}.encode()
	}
	return page, nil
}
