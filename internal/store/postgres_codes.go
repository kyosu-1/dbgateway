package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const pgAuthCodeColumns = `code_hash, client_id, client_name, redirect_uri, code_challenge, scopes, resource,
	email, agent_name, databases, family_id, created_at, expires_at, used_at`

// CreateAuthCode stores an authorization code.
func (s *Postgres) CreateAuthCode(ctx context.Context, c *AuthCode) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO auth_codes (`+pgAuthCodeColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL)`,
		c.CodeHash, c.ClientID, c.ClientName, c.RedirectURI, c.CodeChallenge, encodeList(c.Scopes), c.Resource,
		c.Email, c.AgentName, encodeList(c.Databases), c.FamilyID, pgTime(c.CreatedAt), pgTime(c.ExpiresAt))
	return pgInsertErr(err)
}

// ConsumeAuthCode atomically marks the code as used. Of concurrent callers
// (on any instance) exactly one gets the code without ErrAlreadyUsed.
func (s *Postgres) ConsumeAuthCode(ctx context.Context, codeHash string, now time.Time) (*AuthCode, error) {
	c, err := pgScanAuthCode(s.pool.QueryRow(ctx, `UPDATE auth_codes SET used_at = $2
		WHERE code_hash = $1 AND used_at IS NULL RETURNING `+pgAuthCodeColumns, codeHash, pgTime(now)))
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	c, err = pgScanAuthCode(s.pool.QueryRow(ctx, `SELECT `+pgAuthCodeColumns+` FROM auth_codes WHERE code_hash = $1`, codeHash))
	if err != nil {
		return nil, pgNotFound(err)
	}
	return c, ErrAlreadyUsed
}

func pgScanAuthCode(row scanner) (*AuthCode, error) {
	var c AuthCode
	var scopes, dbs string
	if err := row.Scan(&c.CodeHash, &c.ClientID, &c.ClientName, &c.RedirectURI, &c.CodeChallenge, &scopes, &c.Resource,
		&c.Email, &c.AgentName, &dbs, &c.FamilyID, &c.CreatedAt, &c.ExpiresAt, &c.UsedAt); err != nil {
		return nil, err
	}
	var err error
	if c.Scopes, err = decodeList(scopes); err != nil {
		return nil, err
	}
	if c.Databases, err = decodeList(dbs); err != nil {
		return nil, err
	}
	c.CreatedAt, c.ExpiresAt, c.UsedAt = fromPGTime(c.CreatedAt), fromPGTime(c.ExpiresAt), fromPGNullTime(c.UsedAt)
	return &c, nil
}

// CreateDeviceCode stores a device authorization.
func (s *Postgres) CreateDeviceCode(ctx context.Context, d *DeviceCode) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO device_codes (`+deviceColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		d.DeviceCodeHash, d.UserCodeHash, d.ClientID, encodeList(d.Scopes), string(d.Status), d.Email,
		d.Interval.Milliseconds(), pgNullTime(d.LastPolledAt), pgTime(d.CreatedAt), pgTime(d.ExpiresAt))
	return pgInsertErr(err)
}

// GetDeviceCodeByUserCode looks a device authorization up by user code hash.
func (s *Postgres) GetDeviceCodeByUserCode(ctx context.Context, userCodeHash string) (*DeviceCode, error) {
	d, err := pgScanDeviceCode(s.pool.QueryRow(ctx, `SELECT `+deviceColumns+` FROM device_codes WHERE user_code_hash = $1`, userCodeHash))
	return d, pgNotFound(err)
}

// PollDeviceCode returns the device code before this poll and records the
// poll time. The row is locked so that concurrent polls are serialized.
func (s *Postgres) PollDeviceCode(ctx context.Context, deviceCodeHash string, now time.Time) (*DeviceCode, error) {
	var d *DeviceCode
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		d, err = pgScanDeviceCode(tx.QueryRow(ctx, `SELECT `+deviceColumns+` FROM device_codes WHERE device_code_hash = $1 FOR UPDATE`, deviceCodeHash))
		if err != nil {
			return pgNotFound(err)
		}
		_, err = tx.Exec(ctx, `UPDATE device_codes SET last_polled_at = $1 WHERE device_code_hash = $2`, pgTime(now), deviceCodeHash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// SetDeviceCodeInterval updates the polling interval.
func (s *Postgres) SetDeviceCodeInterval(ctx context.Context, deviceCodeHash string, interval time.Duration) error {
	_, err := s.pool.Exec(ctx, `UPDATE device_codes SET interval_ms = $1 WHERE device_code_hash = $2`, interval.Milliseconds(), deviceCodeHash)
	return err
}

// DecideDeviceCode approves or denies a pending, unexpired device code.
func (s *Postgres) DecideDeviceCode(ctx context.Context, userCodeHash, email string, approve bool, now time.Time) error {
	status := DeviceDenied
	if approve {
		status = DeviceApproved
	}
	tag, err := s.pool.Exec(ctx, `UPDATE device_codes SET status = $1, email = $2
		WHERE user_code_hash = $3 AND status = $4 AND expires_at > $5`,
		string(status), email, userCodeHash, string(DevicePending), pgTime(now))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// ConsumeDeviceCode atomically moves an approved, unexpired code to
// consumed.
func (s *Postgres) ConsumeDeviceCode(ctx context.Context, deviceCodeHash string, now time.Time) (*DeviceCode, error) {
	d, err := pgScanDeviceCode(s.pool.QueryRow(ctx, `UPDATE device_codes SET status = $1
		WHERE device_code_hash = $2 AND status = $3 AND expires_at > $4 RETURNING `+deviceColumns,
		string(DeviceConsumed), deviceCodeHash, string(DeviceApproved), pgTime(now)))
	return d, pgNotFound(err)
}

func pgScanDeviceCode(row scanner) (*DeviceCode, error) {
	var d DeviceCode
	var scopes, status string
	var interval int64
	if err := row.Scan(&d.DeviceCodeHash, &d.UserCodeHash, &d.ClientID, &scopes, &status, &d.Email, &interval,
		&d.LastPolledAt, &d.CreatedAt, &d.ExpiresAt); err != nil {
		return nil, err
	}
	var err error
	if d.Scopes, err = decodeList(scopes); err != nil {
		return nil, err
	}
	d.Status = DeviceStatus(status)
	d.Interval = time.Duration(interval) * time.Millisecond
	d.LastPolledAt, d.CreatedAt, d.ExpiresAt = fromPGNullTime(d.LastPolledAt), fromPGTime(d.CreatedAt), fromPGTime(d.ExpiresAt)
	return &d, nil
}
