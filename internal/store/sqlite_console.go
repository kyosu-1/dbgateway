package store

import (
	"context"
	"database/sql"
	"time"
)

const consoleHistoryColumns = `id, email, database_name, sql_text, reason, status, row_count, request_id, created_at, expires_at`

// AddConsoleHistory stores an entry and trims the person's history.
func (s *SQLite) AddConsoleHistory(ctx context.Context, h *ConsoleHistory) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var rows sql.NullInt64
		if h.RowCount != nil {
			rows = sql.NullInt64{Int64: *h.RowCount, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO console_history (`+consoleHistoryColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.ID, h.Email, h.Database, h.SQL, h.Reason, h.Status, rows, h.RequestID, ms(h.CreatedAt), ms(h.ExpiresAt)); err != nil {
			return insertErr(err)
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM console_history WHERE email = ? AND id NOT IN (
			SELECT id FROM console_history WHERE email = ? ORDER BY created_at DESC, id DESC LIMIT ?)`, h.Email, h.Email, MaxConsoleHistory)
		return err
	})
}

// ListConsoleHistory returns the unexpired entries of email, newest first.
func (s *SQLite) ListConsoleHistory(ctx context.Context, email string, limit int, now time.Time) ([]*ConsoleHistory, error) {
	if limit <= 0 || limit > MaxConsoleHistory {
		limit = MaxConsoleHistory
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+consoleHistoryColumns+` FROM console_history
		WHERE email = ? AND expires_at > ? ORDER BY created_at DESC, id DESC LIMIT ?`, email, ms(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ConsoleHistory
	for rows.Next() {
		h, err := scanConsoleHistory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// GetConsoleHistory returns an unexpired entry of email.
func (s *SQLite) GetConsoleHistory(ctx context.Context, email, id string, now time.Time) (*ConsoleHistory, error) {
	h, err := scanConsoleHistory(s.db.QueryRowContext(ctx, `SELECT `+consoleHistoryColumns+` FROM console_history
		WHERE email = ? AND id = ? AND expires_at > ?`, email, id, ms(now)))
	return h, notFound(err)
}

func scanConsoleHistory(sc scanner) (*ConsoleHistory, error) {
	var h ConsoleHistory
	var rows sql.NullInt64
	var created, expires int64
	if err := sc.Scan(&h.ID, &h.Email, &h.Database, &h.SQL, &h.Reason, &h.Status, &rows, &h.RequestID, &created, &expires); err != nil {
		return nil, err
	}
	if rows.Valid {
		h.RowCount = &rows.Int64
	}
	h.CreatedAt, h.ExpiresAt = fromMS(created), fromMS(expires)
	return &h, nil
}

const savedQueryColumns = `id, email, name, database_name, sql_text, created_at, updated_at`

// CreateSavedQuery stores a query unless the person has too many.
func (s *SQLite) CreateSavedQuery(ctx context.Context, q *SavedQuery) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM console_saved_queries WHERE email = ?`, q.Email).Scan(&n); err != nil {
			return err
		}
		if n >= MaxSavedQueries {
			return ErrLimit
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO console_saved_queries (`+savedQueryColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			q.ID, q.Email, q.Name, q.Database, q.SQL, ms(q.CreatedAt), ms(q.UpdatedAt))
		return insertErr(err)
	})
}

// ListSavedQueries returns the queries of email ordered by name.
func (s *SQLite) ListSavedQueries(ctx context.Context, email string) ([]*SavedQuery, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+savedQueryColumns+` FROM console_saved_queries WHERE email = ? ORDER BY name, id`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SavedQuery
	for rows.Next() {
		q, err := scanSavedQuery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// GetSavedQuery returns a query of email.
func (s *SQLite) GetSavedQuery(ctx context.Context, email, id string) (*SavedQuery, error) {
	q, err := scanSavedQuery(s.db.QueryRowContext(ctx, `SELECT `+savedQueryColumns+` FROM console_saved_queries WHERE email = ? AND id = ?`, email, id))
	return q, notFound(err)
}

// DeleteSavedQuery removes a query of email.
func (s *SQLite) DeleteSavedQuery(ctx context.Context, email, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM console_saved_queries WHERE email = ? AND id = ?`, email, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanSavedQuery(sc scanner) (*SavedQuery, error) {
	var q SavedQuery
	var created, updated int64
	if err := sc.Scan(&q.ID, &q.Email, &q.Name, &q.Database, &q.SQL, &created, &updated); err != nil {
		return nil, err
	}
	q.CreatedAt, q.UpdatedAt = fromMS(created), fromMS(updated)
	return &q, nil
}
