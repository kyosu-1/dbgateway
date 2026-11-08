package store

import (
	"context"
	"database/sql"
	"time"
)

// CreateAuthCode stores an authorization code.
func (s *SQLite) CreateAuthCode(ctx context.Context, c *AuthCode) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_codes (code_hash, client_id, client_name, redirect_uri, code_challenge, scopes, resource,
			email, agent_name, databases, family_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.CodeHash, c.ClientID, c.ClientName, c.RedirectURI, c.CodeChallenge, encodeList(c.Scopes), c.Resource,
		c.Email, c.AgentName, encodeList(c.Databases), c.FamilyID, ms(c.CreatedAt), ms(c.ExpiresAt))
	return insertErr(err)
}

// ConsumeAuthCode atomically marks the code as used.
func (s *SQLite) ConsumeAuthCode(ctx context.Context, codeHash string, now time.Time) (*AuthCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, err := scanAuthCode(tx.QueryRowContext(ctx, `
		SELECT code_hash, client_id, client_name, redirect_uri, code_challenge, scopes, resource,
			email, agent_name, databases, family_id, created_at, expires_at, used_at
		FROM auth_codes WHERE code_hash = ?`, codeHash))
	if err != nil {
		return nil, notFound(err)
	}
	if c.UsedAt != nil {
		return c, ErrAlreadyUsed
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_codes SET used_at = ? WHERE code_hash = ?`, ms(now), codeHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	c.UsedAt = &now
	return c, nil
}

func scanAuthCode(row scanner) (*AuthCode, error) {
	var c AuthCode
	var scopes, dbs string
	var created, expires int64
	var used sql.NullInt64
	if err := row.Scan(&c.CodeHash, &c.ClientID, &c.ClientName, &c.RedirectURI, &c.CodeChallenge, &scopes, &c.Resource,
		&c.Email, &c.AgentName, &dbs, &c.FamilyID, &created, &expires, &used); err != nil {
		return nil, err
	}
	var err error
	if c.Scopes, err = decodeList(scopes); err != nil {
		return nil, err
	}
	if c.Databases, err = decodeList(dbs); err != nil {
		return nil, err
	}
	c.CreatedAt, c.ExpiresAt, c.UsedAt = fromMS(created), fromMS(expires), fromNullMS(used)
	return &c, nil
}

const deviceColumns = `device_code_hash, user_code_hash, client_id, scopes, status, email, interval_ms,
	last_polled_at, created_at, expires_at`

// CreateDeviceCode stores a device authorization.
func (s *SQLite) CreateDeviceCode(ctx context.Context, d *DeviceCode) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO device_codes (`+deviceColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceCodeHash, d.UserCodeHash, d.ClientID, encodeList(d.Scopes), string(d.Status), d.Email,
		d.Interval.Milliseconds(), nullMS(d.LastPolledAt), ms(d.CreatedAt), ms(d.ExpiresAt))
	return insertErr(err)
}

// GetDeviceCodeByUserCode looks a device authorization up by user code hash.
func (s *SQLite) GetDeviceCodeByUserCode(ctx context.Context, userCodeHash string) (*DeviceCode, error) {
	d, err := scanDeviceCode(s.db.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM device_codes WHERE user_code_hash = ?`, userCodeHash))
	return d, notFound(err)
}

// PollDeviceCode returns the device code before this poll and records the
// poll time.
func (s *SQLite) PollDeviceCode(ctx context.Context, deviceCodeHash string, now time.Time) (*DeviceCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := scanDeviceCode(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM device_codes WHERE device_code_hash = ?`, deviceCodeHash))
	if err != nil {
		return nil, notFound(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_codes SET last_polled_at = ? WHERE device_code_hash = ?`, ms(now), deviceCodeHash); err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

// SetDeviceCodeInterval updates the polling interval.
func (s *SQLite) SetDeviceCodeInterval(ctx context.Context, deviceCodeHash string, interval time.Duration) error {
	_, err := s.db.ExecContext(ctx, `UPDATE device_codes SET interval_ms = ? WHERE device_code_hash = ?`, interval.Milliseconds(), deviceCodeHash)
	return err
}

// DecideDeviceCode approves or denies a pending, unexpired device code.
func (s *SQLite) DecideDeviceCode(ctx context.Context, userCodeHash, email string, approve bool, now time.Time) error {
	status := DeviceDenied
	if approve {
		status = DeviceApproved
	}
	res, err := s.db.ExecContext(ctx, `UPDATE device_codes SET status = ?, email = ?
		WHERE user_code_hash = ? AND status = ? AND expires_at > ?`,
		string(status), email, userCodeHash, string(DevicePending), ms(now))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrNotFound
	}
	return nil
}

// ConsumeDeviceCode atomically moves an approved, unexpired code to
// consumed.
func (s *SQLite) ConsumeDeviceCode(ctx context.Context, deviceCodeHash string, now time.Time) (*DeviceCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE device_codes SET status = ?
		WHERE device_code_hash = ? AND status = ? AND expires_at > ?`,
		string(DeviceConsumed), deviceCodeHash, string(DeviceApproved), ms(now))
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return nil, ErrNotFound
	}
	d, err := scanDeviceCode(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM device_codes WHERE device_code_hash = ?`, deviceCodeHash))
	if err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

func scanDeviceCode(row scanner) (*DeviceCode, error) {
	var d DeviceCode
	var scopes, status string
	var interval, created, expires int64
	var polled sql.NullInt64
	if err := row.Scan(&d.DeviceCodeHash, &d.UserCodeHash, &d.ClientID, &scopes, &status, &d.Email, &interval,
		&polled, &created, &expires); err != nil {
		return nil, err
	}
	var err error
	if d.Scopes, err = decodeList(scopes); err != nil {
		return nil, err
	}
	d.Status = DeviceStatus(status)
	d.Interval = time.Duration(interval) * time.Millisecond
	d.LastPolledAt, d.CreatedAt, d.ExpiresAt = fromNullMS(polled), fromMS(created), fromMS(expires)
	return &d, nil
}
