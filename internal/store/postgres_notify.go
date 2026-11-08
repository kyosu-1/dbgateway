package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Notifier state (migration 0005), PostgreSQL version of sqlite_notify.go.

// CreateSlackLinkCode stores a linking code (by hash) for email, deleting
// earlier codes of the same user and every expired code.
func (s *Postgres) CreateSlackLinkCode(ctx context.Context, email, codeHash string, created, expires time.Time) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM slack_link_codes WHERE email = $1 OR expires_at < $2`, email, pgTime(created)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO slack_link_codes (code_hash, email, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
			codeHash, email, pgTime(created), pgTime(expires))
		return pgInsertErr(err)
	})
}

// ConsumeSlackLinkCode uses a linking code once and links slackUser to the
// user who issued it. The DELETE ... RETURNING makes the code single-use
// across instances. It returns ErrNotFound for unknown, used or expired
// codes (expired codes are deleted too).
func (s *Postgres) ConsumeSlackLinkCode(ctx context.Context, codeHash, slackUser string, now time.Time) (string, error) {
	var email string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var expires time.Time
		if err := tx.QueryRow(ctx, `DELETE FROM slack_link_codes WHERE code_hash = $1 RETURNING email, expires_at`, codeHash).
			Scan(&email, &expires); err != nil {
			return pgNotFound(err)
		}
		if !now.Before(fromPGTime(expires)) {
			return errExpiredCode
		}
		if _, err := tx.Exec(ctx, `DELETE FROM slack_links WHERE email = $1 OR slack_user = $2`, email, slackUser); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO slack_links (email, slack_user, linked_at) VALUES ($1, $2, $3)`, email, slackUser, pgTime(now))
		return err
	})
	if errors.Is(err, errExpiredCode) {
		_, _ = s.pool.Exec(ctx, `DELETE FROM slack_link_codes WHERE code_hash = $1`, codeHash)
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return email, nil
}

// GetSlackLinkByEmail returns the link of a dbgateway user.
func (s *Postgres) GetSlackLinkByEmail(ctx context.Context, email string) (*SlackLink, error) {
	return s.getSlackLink(ctx, `email = $1`, email)
}

// GetSlackLinkBySlackUser returns the link of a Slack user.
func (s *Postgres) GetSlackLinkBySlackUser(ctx context.Context, slackUser string) (*SlackLink, error) {
	return s.getSlackLink(ctx, `slack_user = $1`, slackUser)
}

func (s *Postgres) getSlackLink(ctx context.Context, where, arg string) (*SlackLink, error) {
	var l SlackLink
	var at time.Time
	if err := s.pool.QueryRow(ctx, `SELECT email, slack_user, linked_at FROM slack_links WHERE `+where, arg).Scan(&l.Email, &l.SlackUser, &at); err != nil {
		return nil, pgNotFound(err)
	}
	l.LinkedAt = fromPGTime(at)
	return &l, nil
}

// DeleteSlackLink removes the link of a dbgateway user (no error when none).
func (s *Postgres) DeleteSlackLink(ctx context.Context, email string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM slack_links WHERE email = $1`, email)
	return err
}

// DeleteSlackLinkBySlackUser removes the link of a Slack user and returns
// the e-mail it was linked to (ErrNotFound when there was none).
func (s *Postgres) DeleteSlackLinkBySlackUser(ctx context.Context, slackUser string) (string, error) {
	var email string
	if err := s.pool.QueryRow(ctx, `DELETE FROM slack_links WHERE slack_user = $1 RETURNING email`, slackUser).Scan(&email); err != nil {
		return "", pgNotFound(err)
	}
	return email, nil
}

// SaveSlackThread records the thread of a request in a channel.
func (s *Postgres) SaveSlackThread(ctx context.Context, t *SlackThread) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO slack_threads (request_id, channel, target, ts, event_json, created_at) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (request_id, channel) DO UPDATE SET target = excluded.target, ts = excluded.ts,
			event_json = excluded.event_json, created_at = excluded.created_at`,
		t.RequestID, t.Channel, t.Target, t.TS, string(t.EventJSON), pgTime(t.CreatedAt))
	return err
}

// ListSlackThreads returns the threads of a request, oldest first.
func (s *Postgres) ListSlackThreads(ctx context.Context, requestID string) ([]*SlackThread, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT request_id, channel, target, ts, event_json, created_at FROM slack_threads
		WHERE request_id = $1 ORDER BY created_at, channel`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SlackThread
	for rows.Next() {
		var t SlackThread
		var ev string
		var at time.Time
		if err := rows.Scan(&t.RequestID, &t.Channel, &t.Target, &t.TS, &ev, &at); err != nil {
			return nil, err
		}
		t.EventJSON, t.CreatedAt = []byte(ev), fromPGTime(at)
		out = append(out, &t)
	}
	return out, rows.Err()
}

// SwapNotifyState sets key to value and returns the previous value. The
// row lock serializes concurrent instances.
func (s *Postgres) SwapNotifyState(ctx context.Context, key, value string, now time.Time) (previous string, found bool, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		switch err := tx.QueryRow(ctx, `SELECT value FROM notify_state WHERE key = $1 FOR UPDATE`, key).Scan(&previous); {
		case err == nil:
			found = true
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO notify_state (key, value, updated_at) VALUES ($1, $2, $3)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, value, pgTime(now))
		return err
	})
	return previous, found, err
}
