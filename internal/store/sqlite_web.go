package store

import (
	"context"
	"database/sql"
	"time"
)

// SetSessionStepUp records a re-authentication on a session.
func (s *SQLite) SetSessionStepUp(ctx context.Context, idHash, method string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET step_up_method = ?, step_up_at = ? WHERE id_hash = ?`, method, ms(at), idHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const passkeyColumns = `id, email, user_handle, name, credential, created_at, last_used_at`

// CreatePasskey stores a passkey.
func (s *SQLite) CreatePasskey(ctx context.Context, p *Passkey) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO passkeys (`+passkeyColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Email, p.UserHandle, p.Name, string(p.Credential), ms(p.CreatedAt), nullMS(p.LastUsedAt))
	return insertErr(err)
}

// GetPasskey returns a passkey by credential ID.
func (s *SQLite) GetPasskey(ctx context.Context, id string) (*Passkey, error) {
	p, err := scanPasskey(s.db.QueryRowContext(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE id = ?`, id))
	return p, notFound(err)
}

// ListPasskeys returns the passkeys of a person, oldest first.
func (s *SQLite) ListPasskeys(ctx context.Context, email string) ([]*Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE email = ? ORDER BY created_at, id`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePasskeyUse stores the updated credential record and the time of use.
func (s *SQLite) UpdatePasskeyUse(ctx context.Context, id string, credential []byte, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE passkeys SET credential = ?, last_used_at = ? WHERE id = ?`, string(credential), ms(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePasskey removes a passkey owned by email.
func (s *SQLite) DeletePasskey(ctx context.Context, email, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ? AND email = ?`, id, email)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanPasskey(sc scanner) (*Passkey, error) {
	var p Passkey
	var cred string
	var created int64
	var used sql.NullInt64
	if err := sc.Scan(&p.ID, &p.Email, &p.UserHandle, &p.Name, &cred, &created, &used); err != nil {
		return nil, err
	}
	p.Credential, p.CreatedAt, p.LastUsedAt = []byte(cred), fromMS(created), fromNullMS(used)
	return &p, nil
}

// CreatePasskeyEnrollment stores an enrollment link.
func (s *SQLite) CreatePasskeyEnrollment(ctx context.Context, e *PasskeyEnrollment) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO passkey_enrollments (token_hash, email, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?)`,
		e.TokenHash, e.Email, ms(e.CreatedAt), ms(e.ExpiresAt), nullMS(e.UsedAt))
	return insertErr(err)
}

// GetPasskeyEnrollment returns an unused, unexpired enrollment link.
func (s *SQLite) GetPasskeyEnrollment(ctx context.Context, tokenHash string, now time.Time) (*PasskeyEnrollment, error) {
	e, err := scanEnrollment(s.db.QueryRowContext(ctx, `SELECT token_hash, email, created_at, expires_at, used_at
		FROM passkey_enrollments WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`, tokenHash, ms(now)))
	return e, notFound(err)
}

// ConsumePasskeyEnrollment marks an unused, unexpired link as used.
func (s *SQLite) ConsumePasskeyEnrollment(ctx context.Context, tokenHash string, now time.Time) (*PasskeyEnrollment, error) {
	var out *PasskeyEnrollment
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE passkey_enrollments SET used_at = ?
			WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`, ms(now), tokenHash, ms(now))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		out, err = scanEnrollment(tx.QueryRowContext(ctx, `SELECT token_hash, email, created_at, expires_at, used_at
			FROM passkey_enrollments WHERE token_hash = ?`, tokenHash))
		return err
	})
	if err != nil {
		return nil, notFound(err)
	}
	return out, nil
}

func scanEnrollment(sc scanner) (*PasskeyEnrollment, error) {
	var e PasskeyEnrollment
	var created, expires int64
	var used sql.NullInt64
	if err := sc.Scan(&e.TokenHash, &e.Email, &created, &expires, &used); err != nil {
		return nil, err
	}
	e.CreatedAt, e.ExpiresAt, e.UsedAt = fromMS(created), fromMS(expires), fromNullMS(used)
	return &e, nil
}

// CreateWebAuthnSession stores a ceremony in progress.
func (s *SQLite) CreateWebAuthnSession(ctx context.Context, w *WebAuthnSession) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO webauthn_sessions (id_hash, purpose, email, data, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		w.IDHash, w.Purpose, w.Email, string(w.Data), ms(w.CreatedAt), ms(w.ExpiresAt))
	return insertErr(err)
}

// ConsumeWebAuthnSession deletes and returns an unexpired ceremony.
func (s *SQLite) ConsumeWebAuthnSession(ctx context.Context, idHash string, now time.Time) (*WebAuthnSession, error) {
	var out WebAuthnSession
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var data string
		var created, expires int64
		if err := tx.QueryRowContext(ctx, `SELECT id_hash, purpose, email, data, created_at, expires_at FROM webauthn_sessions WHERE id_hash = ?`, idHash).
			Scan(&out.IDHash, &out.Purpose, &out.Email, &data, &created, &expires); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_sessions WHERE id_hash = ?`, idHash); err != nil {
			return err
		}
		out.Data, out.CreatedAt, out.ExpiresAt = []byte(data), fromMS(created), fromMS(expires)
		return nil
	})
	if err != nil {
		return nil, notFound(err)
	}
	if !now.Before(out.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &out, nil
}
