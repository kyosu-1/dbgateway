package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Notifier state (migration 0005). These methods are used by
// internal/notify through its own interface; they are not part of Store.

// SlackLink links a dbgateway user to a Slack user.
type SlackLink struct {
	Email     string
	SlackUser string
	LinkedAt  time.Time
}

// SlackThread is the Slack message that started the thread of an
// approval request in one channel.
type SlackThread struct {
	RequestID string
	Channel   string // channel ID returned by Slack
	Target    string // configured destination ("#name" or an ID)
	TS        string
	// EventJSON is the approval_requested event (no literals), used to
	// re-render the message.
	EventJSON []byte
	CreatedAt time.Time
}

// CreateSlackLinkCode stores a linking code (by hash) for email. Earlier
// codes of the same user and every expired code are deleted, so at most
// one code per user is valid.
func (s *SQLite) CreateSlackLinkCode(ctx context.Context, email, codeHash string, created, expires time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM slack_link_codes WHERE email = ? OR expires_at < ?`, email, ms(created)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO slack_link_codes (code_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?)`,
			codeHash, email, ms(created), ms(expires))
		return insertErr(err)
	})
}

// ConsumeSlackLinkCode uses a linking code once and links slackUser to the
// user who issued it, replacing any earlier link of either side. It
// returns ErrNotFound when the code does not exist, was used or expired.
func (s *SQLite) ConsumeSlackLinkCode(ctx context.Context, codeHash, slackUser string, now time.Time) (string, error) {
	var email string
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var expires int64
		err := tx.QueryRowContext(ctx, `DELETE FROM slack_link_codes WHERE code_hash = ? RETURNING email, expires_at`, codeHash).
			Scan(&email, &expires)
		if err != nil {
			return notFound(err)
		}
		if !now.Before(fromMS(expires)) {
			return errExpiredCode
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM slack_links WHERE email = ? OR slack_user = ?`, email, slackUser); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO slack_links (email, slack_user, linked_at) VALUES (?, ?, ?)`, email, slackUser, ms(now))
		return err
	})
	if errors.Is(err, errExpiredCode) {
		// The expired code was not deleted (the transaction rolled back);
		// delete it now so that it cannot be retried.
		_, _ = s.db.ExecContext(ctx, `DELETE FROM slack_link_codes WHERE code_hash = ?`, codeHash)
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return email, nil
}

var errExpiredCode = errors.New("store: expired code")

// GetSlackLinkByEmail returns the link of a dbgateway user.
func (s *SQLite) GetSlackLinkByEmail(ctx context.Context, email string) (*SlackLink, error) {
	return s.getSlackLink(ctx, `email = ?`, email)
}

// GetSlackLinkBySlackUser returns the link of a Slack user.
func (s *SQLite) GetSlackLinkBySlackUser(ctx context.Context, slackUser string) (*SlackLink, error) {
	return s.getSlackLink(ctx, `slack_user = ?`, slackUser)
}

func (s *SQLite) getSlackLink(ctx context.Context, where, arg string) (*SlackLink, error) {
	var l SlackLink
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT email, slack_user, linked_at FROM slack_links WHERE `+where, arg).Scan(&l.Email, &l.SlackUser, &at)
	if err != nil {
		return nil, notFound(err)
	}
	l.LinkedAt = fromMS(at)
	return &l, nil
}

// DeleteSlackLink removes the link of a dbgateway user (no error when
// there is none).
func (s *SQLite) DeleteSlackLink(ctx context.Context, email string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM slack_links WHERE email = ?`, email)
	return err
}

// DeleteSlackLinkBySlackUser removes the link of a Slack user and returns
// the e-mail it was linked to (ErrNotFound when there was none).
func (s *SQLite) DeleteSlackLinkBySlackUser(ctx context.Context, slackUser string) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx, `DELETE FROM slack_links WHERE slack_user = ? RETURNING email`, slackUser).Scan(&email)
	if err != nil {
		return "", notFound(err)
	}
	return email, nil
}

// SaveSlackThread records the thread of a request in a channel (replacing
// an earlier one in the same channel).
func (s *SQLite) SaveSlackThread(ctx context.Context, t *SlackThread) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO slack_threads (request_id, channel, target, ts, event_json, created_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (request_id, channel) DO UPDATE SET target = excluded.target, ts = excluded.ts,
			event_json = excluded.event_json, created_at = excluded.created_at`,
		t.RequestID, t.Channel, t.Target, t.TS, string(t.EventJSON), ms(t.CreatedAt))
	return err
}

// ListSlackThreads returns the threads of a request, oldest first.
func (s *SQLite) ListSlackThreads(ctx context.Context, requestID string) ([]*SlackThread, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT request_id, channel, target, ts, event_json, created_at FROM slack_threads
		WHERE request_id = ? ORDER BY created_at, channel`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SlackThread
	for rows.Next() {
		var t SlackThread
		var ev string
		var at int64
		if err := rows.Scan(&t.RequestID, &t.Channel, &t.Target, &t.TS, &ev, &at); err != nil {
			return nil, err
		}
		t.EventJSON, t.CreatedAt = []byte(ev), fromMS(at)
		out = append(out, &t)
	}
	return out, rows.Err()
}

// SwapNotifyState sets key to value and returns the previous value (found
// is false when the key was not set).
func (s *SQLite) SwapNotifyState(ctx context.Context, key, value string, now time.Time) (previous string, found bool, err error) {
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		switch err := tx.QueryRowContext(ctx, `SELECT value FROM notify_state WHERE key = ?`, key).Scan(&previous); {
		case err == nil:
			found = true
		case errors.Is(err, sql.ErrNoRows):
		default:
			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO notify_state (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, value, ms(now))
		return err
	})
	return previous, found, err
}
