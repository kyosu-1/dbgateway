package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// AddConsoleHistory stores an entry and trims the person's history.
func (s *Postgres) AddConsoleHistory(ctx context.Context, h *ConsoleHistory) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO console_history (`+consoleHistoryColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			h.ID, h.Email, h.Database, h.SQL, h.Reason, h.Status, h.RowCount, h.RequestID, pgTime(h.CreatedAt), pgTime(h.ExpiresAt)); err != nil {
			return pgInsertErr(err)
		}
		_, err := tx.Exec(ctx, `DELETE FROM console_history WHERE email = $1 AND id NOT IN (
			SELECT id FROM console_history WHERE email = $1 ORDER BY created_at DESC, id DESC LIMIT $2)`, h.Email, MaxConsoleHistory)
		return err
	})
}

// ListConsoleHistory returns the unexpired entries of email, newest first.
func (s *Postgres) ListConsoleHistory(ctx context.Context, email string, limit int, now time.Time) ([]*ConsoleHistory, error) {
	if limit <= 0 || limit > MaxConsoleHistory {
		limit = MaxConsoleHistory
	}
	rows, err := s.pool.Query(ctx, `SELECT `+consoleHistoryColumns+` FROM console_history
		WHERE email = $1 AND expires_at > $2 ORDER BY created_at DESC, id DESC LIMIT $3`, email, pgTime(now), limit)
	if err != nil {
		return nil, err
	}
	return pgCollect(rows, pgScanConsoleHistory)
}

// GetConsoleHistory returns an unexpired entry of email.
func (s *Postgres) GetConsoleHistory(ctx context.Context, email, id string, now time.Time) (*ConsoleHistory, error) {
	h, err := pgScanConsoleHistory(s.pool.QueryRow(ctx, `SELECT `+consoleHistoryColumns+` FROM console_history
		WHERE email = $1 AND id = $2 AND expires_at > $3`, email, id, pgTime(now)))
	return h, pgNotFound(err)
}

func pgScanConsoleHistory(sc scanner) (*ConsoleHistory, error) {
	var h ConsoleHistory
	if err := sc.Scan(&h.ID, &h.Email, &h.Database, &h.SQL, &h.Reason, &h.Status, &h.RowCount, &h.RequestID, &h.CreatedAt, &h.ExpiresAt); err != nil {
		return nil, err
	}
	return &h, nil
}

// CreateSavedQuery stores a query unless the person has too many. The
// count and insert run under a per-person advisory lock so that parallel
// requests on several instances cannot exceed the limit.
func (s *Postgres) CreateSavedQuery(ctx context.Context, q *SavedQuery) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('console_saved_queries:' || $1))`, q.Email); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM console_saved_queries WHERE email = $1`, q.Email).Scan(&n); err != nil {
			return err
		}
		if n >= MaxSavedQueries {
			return ErrLimit
		}
		_, err := tx.Exec(ctx, `INSERT INTO console_saved_queries (`+savedQueryColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			q.ID, q.Email, q.Name, q.Database, q.SQL, pgTime(q.CreatedAt), pgTime(q.UpdatedAt))
		return pgInsertErr(err)
	})
}

// ListSavedQueries returns the queries of email ordered by name.
func (s *Postgres) ListSavedQueries(ctx context.Context, email string) ([]*SavedQuery, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+savedQueryColumns+` FROM console_saved_queries WHERE email = $1 ORDER BY name, id`, email)
	if err != nil {
		return nil, err
	}
	return pgCollect(rows, pgScanSavedQuery)
}

// GetSavedQuery returns a query of email.
func (s *Postgres) GetSavedQuery(ctx context.Context, email, id string) (*SavedQuery, error) {
	q, err := pgScanSavedQuery(s.pool.QueryRow(ctx, `SELECT `+savedQueryColumns+` FROM console_saved_queries WHERE email = $1 AND id = $2`, email, id))
	return q, pgNotFound(err)
}

// DeleteSavedQuery removes a query of email.
func (s *Postgres) DeleteSavedQuery(ctx context.Context, email, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM console_saved_queries WHERE email = $1 AND id = $2`, email, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func pgScanSavedQuery(sc scanner) (*SavedQuery, error) {
	var q SavedQuery
	if err := sc.Scan(&q.ID, &q.Email, &q.Name, &q.Database, &q.SQL, &q.CreatedAt, &q.UpdatedAt); err != nil {
		return nil, err
	}
	return &q, nil
}
