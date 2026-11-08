package store

import (
	"context"
	"time"
)

// UpsertUser inserts the user or updates the IdP groups snapshot and last
// login time.
func (s *SQLite) UpsertUser(ctx context.Context, u *User) error {
	now := u.LastLoginAt
	if now.IsZero() {
		now = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (email, idp_groups, created_at, last_login_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (email) DO UPDATE SET idp_groups = excluded.idp_groups, last_login_at = excluded.last_login_at`,
		u.Email, encodeList(u.IDPGroups), ms(now), ms(now))
	return err
}

// GetUser returns a user by email.
func (s *SQLite) GetUser(ctx context.Context, email string) (*User, error) {
	var u User
	var groups string
	var created, last int64
	err := s.db.QueryRowContext(ctx, `SELECT email, idp_groups, created_at, last_login_at FROM users WHERE email = ?`, email).
		Scan(&u.Email, &groups, &created, &last)
	if err != nil {
		return nil, notFound(err)
	}
	if u.IDPGroups, err = decodeList(groups); err != nil {
		return nil, err
	}
	u.CreatedAt, u.LastLoginAt = fromMS(created), fromMS(last)
	return &u, nil
}

// CreateSession stores a browser session.
func (s *SQLite) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		sess.IDHash, sess.Email, ms(sess.CreatedAt), ms(sess.ExpiresAt))
	return insertErr(err)
}

// GetSession returns a session by the hash of its ID. Expiry is checked by
// the caller.
func (s *SQLite) GetSession(ctx context.Context, idHash string) (*Session, error) {
	var sess Session
	var created, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT id_hash, email, created_at, expires_at FROM sessions WHERE id_hash = ?`, idHash).
		Scan(&sess.IDHash, &sess.Email, &created, &expires)
	if err != nil {
		return nil, notFound(err)
	}
	sess.CreatedAt, sess.ExpiresAt = fromMS(created), fromMS(expires)
	return &sess, nil
}

// DeleteSession removes a session. Deleting a missing session is not an
// error.
func (s *SQLite) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// CreateClient stores a dynamically registered OAuth client.
func (s *SQLite) CreateClient(ctx context.Context, c *Client) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) VALUES (?, ?, ?, ?)`,
		c.ClientID, c.ClientName, encodeList(c.RedirectURIs), ms(c.CreatedAt))
	return insertErr(err)
}

// GetClient returns a registered client.
func (s *SQLite) GetClient(ctx context.Context, clientID string) (*Client, error) {
	var c Client
	var uris string
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT client_id, client_name, redirect_uris, created_at FROM oauth_clients WHERE client_id = ?`, clientID).
		Scan(&c.ClientID, &c.ClientName, &uris, &created)
	if err != nil {
		return nil, notFound(err)
	}
	if c.RedirectURIs, err = decodeList(uris); err != nil {
		return nil, err
	}
	c.CreatedAt = fromMS(created)
	return &c, nil
}

// CountClients returns the number of registered clients.
func (s *SQLite) CountClients(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_clients`).Scan(&n)
	return n, err
}
