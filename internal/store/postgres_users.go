package store

import (
	"context"
	"time"
)

const pgUserColumns = `email, idp_groups, created_at, last_login_at`

// UpsertUser inserts the user or updates the IdP groups snapshot and last
// login time.
func (s *Postgres) UpsertUser(ctx context.Context, u *User) error {
	now := u.LastLoginAt
	if now.IsZero() {
		now = time.Now()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO users (email, idp_groups, created_at, last_login_at) VALUES ($1, $2, $3, $3)
		ON CONFLICT (email) DO UPDATE SET idp_groups = excluded.idp_groups, last_login_at = excluded.last_login_at`,
		u.Email, encodeList(u.IDPGroups), pgTime(now))
	return err
}

// GetUser returns a user by email.
func (s *Postgres) GetUser(ctx context.Context, email string) (*User, error) {
	u, err := pgScanUser(s.pool.QueryRow(ctx, `SELECT `+pgUserColumns+` FROM users WHERE email = $1`, email))
	return u, pgNotFound(err)
}

// ListUsers returns every user ordered by e-mail.
func (s *Postgres) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+pgUserColumns+` FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	return pgCollect(rows, pgScanUser)
}

func pgScanUser(row scanner) (*User, error) {
	var u User
	var groups string
	if err := row.Scan(&u.Email, &groups, &u.CreatedAt, &u.LastLoginAt); err != nil {
		return nil, err
	}
	var err error
	if u.IDPGroups, err = decodeList(groups); err != nil {
		return nil, err
	}
	u.CreatedAt, u.LastLoginAt = fromPGTime(u.CreatedAt), fromPGTime(u.LastLoginAt)
	return &u, nil
}

// CreateSession stores a browser session.
func (s *Postgres) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (id_hash, email, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		sess.IDHash, sess.Email, pgTime(sess.CreatedAt), pgTime(sess.ExpiresAt))
	return pgInsertErr(err)
}

// GetSession returns a session by the hash of its ID. Expiry is checked by
// the caller.
func (s *Postgres) GetSession(ctx context.Context, idHash string) (*Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `SELECT id_hash, email, created_at, expires_at FROM sessions WHERE id_hash = $1`, idHash).
		Scan(&sess.IDHash, &sess.Email, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		return nil, pgNotFound(err)
	}
	sess.CreatedAt, sess.ExpiresAt = fromPGTime(sess.CreatedAt), fromPGTime(sess.ExpiresAt)
	return &sess, nil
}

// DeleteSession removes a session. Deleting a missing session is not an
// error.
func (s *Postgres) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id_hash = $1`, idHash)
	return err
}

// CreateClient stores a dynamically registered OAuth client.
func (s *Postgres) CreateClient(ctx context.Context, c *Client) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) VALUES ($1, $2, $3, $4)`,
		c.ClientID, c.ClientName, encodeList(c.RedirectURIs), pgTime(c.CreatedAt))
	return pgInsertErr(err)
}

// GetClient returns a registered client.
func (s *Postgres) GetClient(ctx context.Context, clientID string) (*Client, error) {
	var c Client
	var uris string
	err := s.pool.QueryRow(ctx, `SELECT client_id, client_name, redirect_uris, created_at FROM oauth_clients WHERE client_id = $1`, clientID).
		Scan(&c.ClientID, &c.ClientName, &uris, &c.CreatedAt)
	if err != nil {
		return nil, pgNotFound(err)
	}
	if c.RedirectURIs, err = decodeList(uris); err != nil {
		return nil, err
	}
	c.CreatedAt = fromPGTime(c.CreatedAt)
	return &c, nil
}

// CountClients returns the number of registered clients.
func (s *Postgres) CountClients(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients`).Scan(&n)
	return n, err
}
