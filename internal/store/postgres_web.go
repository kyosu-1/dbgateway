package store

import (
	"context"
	"time"
)

// Web UI state (migration 0004), PostgreSQL version of sqlite_web.go.

// SetSessionStepUp records a re-authentication on a session.
func (s *Postgres) SetSessionStepUp(ctx context.Context, idHash, method string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET step_up_method = $1, step_up_at = $2 WHERE id_hash = $3`, method, pgTime(at), idHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CreatePasskey stores a passkey.
func (s *Postgres) CreatePasskey(ctx context.Context, p *Passkey) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO passkeys (`+passkeyColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		p.ID, p.Email, p.UserHandle, p.Name, string(p.Credential), pgTime(p.CreatedAt), pgNullTime(p.LastUsedAt))
	return pgInsertErr(err)
}

// GetPasskey returns a passkey by credential ID.
func (s *Postgres) GetPasskey(ctx context.Context, id string) (*Passkey, error) {
	p, err := pgScanPasskey(s.pool.QueryRow(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE id = $1`, id))
	return p, pgNotFound(err)
}

// ListPasskeys returns the passkeys of a person, oldest first.
func (s *Postgres) ListPasskeys(ctx context.Context, email string) ([]*Passkey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE email = $1 ORDER BY created_at, id`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Passkey
	for rows.Next() {
		p, err := pgScanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePasskeyUse stores the updated credential record and the time of use.
func (s *Postgres) UpdatePasskeyUse(ctx context.Context, id string, credential []byte, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE passkeys SET credential = $1, last_used_at = $2 WHERE id = $3`, string(credential), pgTime(at), id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePasskey removes a passkey owned by email.
func (s *Postgres) DeletePasskey(ctx context.Context, email, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM passkeys WHERE id = $1 AND email = $2`, id, email)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func pgScanPasskey(sc scanner) (*Passkey, error) {
	var p Passkey
	var cred string
	var created time.Time
	var used *time.Time
	if err := sc.Scan(&p.ID, &p.Email, &p.UserHandle, &p.Name, &cred, &created, &used); err != nil {
		return nil, err
	}
	p.Credential, p.CreatedAt, p.LastUsedAt = []byte(cred), fromPGTime(created), fromPGNullTime(used)
	return &p, nil
}

// CreatePasskeyEnrollment stores an enrollment link.
func (s *Postgres) CreatePasskeyEnrollment(ctx context.Context, e *PasskeyEnrollment) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO passkey_enrollments (token_hash, email, created_at, expires_at, used_at) VALUES ($1, $2, $3, $4, $5)`,
		e.TokenHash, e.Email, pgTime(e.CreatedAt), pgTime(e.ExpiresAt), pgNullTime(e.UsedAt))
	return pgInsertErr(err)
}

// GetPasskeyEnrollment returns an unused, unexpired enrollment link.
func (s *Postgres) GetPasskeyEnrollment(ctx context.Context, tokenHash string, now time.Time) (*PasskeyEnrollment, error) {
	e, err := pgScanEnrollment(s.pool.QueryRow(ctx, `SELECT token_hash, email, created_at, expires_at, used_at
		FROM passkey_enrollments WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2`, tokenHash, pgTime(now)))
	return e, pgNotFound(err)
}

// ConsumePasskeyEnrollment marks an unused, unexpired link as used. The
// conditional UPDATE ... RETURNING makes it single-use across instances.
func (s *Postgres) ConsumePasskeyEnrollment(ctx context.Context, tokenHash string, now time.Time) (*PasskeyEnrollment, error) {
	e, err := pgScanEnrollment(s.pool.QueryRow(ctx, `UPDATE passkey_enrollments SET used_at = $1
		WHERE token_hash = $2 AND used_at IS NULL AND expires_at > $1
		RETURNING token_hash, email, created_at, expires_at, used_at`, pgTime(now), tokenHash))
	if err != nil {
		return nil, pgNotFound(err)
	}
	return e, nil
}

func pgScanEnrollment(sc scanner) (*PasskeyEnrollment, error) {
	var e PasskeyEnrollment
	var created, expires time.Time
	var used *time.Time
	if err := sc.Scan(&e.TokenHash, &e.Email, &created, &expires, &used); err != nil {
		return nil, err
	}
	e.CreatedAt, e.ExpiresAt, e.UsedAt = fromPGTime(created), fromPGTime(expires), fromPGNullTime(used)
	return &e, nil
}

// CreateWebAuthnSession stores a ceremony in progress.
func (s *Postgres) CreateWebAuthnSession(ctx context.Context, w *WebAuthnSession) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO webauthn_sessions (id_hash, purpose, email, data, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		w.IDHash, w.Purpose, w.Email, string(w.Data), pgTime(w.CreatedAt), pgTime(w.ExpiresAt))
	return pgInsertErr(err)
}

// ConsumeWebAuthnSession deletes and returns an unexpired ceremony
// (DELETE ... RETURNING: single-use across instances).
func (s *Postgres) ConsumeWebAuthnSession(ctx context.Context, idHash string, now time.Time) (*WebAuthnSession, error) {
	var out WebAuthnSession
	var data string
	var created, expires time.Time
	err := s.pool.QueryRow(ctx, `DELETE FROM webauthn_sessions WHERE id_hash = $1
		RETURNING id_hash, purpose, email, data, created_at, expires_at`, idHash).
		Scan(&out.IDHash, &out.Purpose, &out.Email, &data, &created, &expires)
	if err != nil {
		return nil, pgNotFound(err)
	}
	out.Data, out.CreatedAt, out.ExpiresAt = []byte(data), fromPGTime(created), fromPGTime(expires)
	if !now.Before(out.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &out, nil
}
