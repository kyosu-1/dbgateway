// Package store is the management database of dbgateway: users, browser
// sessions, OAuth clients, authorization and device codes, tokens, approval
// requests and break-glass grants.
//
// Secrets (tokens, codes, session IDs) are never stored. Callers pass the
// SHA-256 hash of the secret (see HashSecret) and look rows up by that hash.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

var (
	// ErrNotFound is returned when a row does not exist (or is not in the
	// state the operation requires).
	ErrNotFound = errors.New("store: not found")
	// ErrAlreadyUsed is returned by ConsumeAuthCode when the code was
	// already exchanged. The returned code is non-nil so the caller can
	// revoke the tokens issued from it.
	ErrAlreadyUsed = errors.New("store: already used")
	// ErrConflict is returned when a row with the same key already exists.
	ErrConflict = errors.New("store: conflict")
)

// HashSecret returns the hex SHA-256 of a secret. Only this hash is stored.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// User is a human who has logged in at least once.
type User struct {
	Email string
	// IDPGroups is the snapshot of the IdP groups taken at the last login.
	IDPGroups   []string
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// Session is a browser login session.
type Session struct {
	IDHash    string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Client is an OAuth client registered with Dynamic Client Registration.
type Client struct {
	ClientID     string
	ClientName   string
	RedirectURIs []string
	CreatedAt    time.Time
}

// AuthCode is a one-time OAuth authorization code.
type AuthCode struct {
	CodeHash      string
	ClientID      string
	ClientName    string
	RedirectURI   string
	CodeChallenge string // S256
	Scopes        []string
	Resource      string
	Email         string // the human who consented
	AgentName     string
	Databases     []string
	// FamilyID is assigned to every token issued from this code, so that a
	// replayed code can revoke them all.
	FamilyID  string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// DeviceStatus is the state of a device authorization.
type DeviceStatus string

const (
	DevicePending  DeviceStatus = "pending"
	DeviceApproved DeviceStatus = "approved"
	DeviceDenied   DeviceStatus = "denied"
	DeviceConsumed DeviceStatus = "consumed"
)

// DeviceCode is an RFC 8628 device authorization.
type DeviceCode struct {
	DeviceCodeHash string
	UserCodeHash   string
	ClientID       string
	Scopes         []string
	Status         DeviceStatus
	Email          string // set when approved or denied
	Interval       time.Duration
	LastPolledAt   *time.Time
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// TokenType distinguishes access tokens from refresh tokens.
type TokenType string

const (
	TokenAccess  TokenType = "access"
	TokenRefresh TokenType = "refresh"
)

// Token is an issued access or refresh token.
type Token struct {
	ID         string
	Hash       string
	Type       TokenType
	Kind       identity.Kind
	Human      string // email of the human (owner, or the one an agent acts for)
	Agent      string
	ClientID   string
	ClientName string
	Scopes     []string
	Databases  []string
	Audience   string
	// FamilyID groups the tokens of one grant (refresh rotation chain).
	FamilyID string
	// ParentID is the token this one was derived from: the previous refresh
	// token on rotation, or the human token an agent token was minted with.
	ParentID  string
	CreatedAt time.Time
	ExpiresAt time.Time
	// UsedAt is set when a refresh token has been rotated.
	UsedAt    *time.Time
	RevokedAt *time.Time
}

// Active reports whether the token is neither revoked nor expired at now.
func (t *Token) Active(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// Store is the management database. Implementations must be safe for
// concurrent use.
type Store interface {
	UpsertUser(ctx context.Context, u *User) error
	GetUser(ctx context.Context, email string) (*User, error)
	// RecordLogin upserts the user at login. It returns ErrUserInactive for
	// users deactivated through SCIM; with SCIM enabled, SCIM-managed users
	// keep their SCIM groups instead of the login-time IdP groups.
	RecordLogin(ctx context.Context, email string, loginGroups []string, now time.Time, scimEnabled bool) error
	// UserActive reports whether the user may authenticate (false only for
	// users deactivated or deleted through SCIM).
	UserActive(ctx context.Context, email string) (bool, error)
	// ListUsers returns every known user ordered by e-mail.
	ListUsers(ctx context.Context) ([]*User, error)

	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, idHash string) (*Session, error)
	DeleteSession(ctx context.Context, idHash string) error

	CreateClient(ctx context.Context, c *Client) error
	GetClient(ctx context.Context, clientID string) (*Client, error)
	CountClients(ctx context.Context) (int, error)

	CreateAuthCode(ctx context.Context, c *AuthCode) error
	// ConsumeAuthCode atomically marks the code as used and returns it. If
	// it was already used it returns the code and ErrAlreadyUsed.
	ConsumeAuthCode(ctx context.Context, codeHash string, now time.Time) (*AuthCode, error)

	CreateDeviceCode(ctx context.Context, d *DeviceCode) error
	GetDeviceCodeByUserCode(ctx context.Context, userCodeHash string) (*DeviceCode, error)
	// PollDeviceCode returns the device code as it was before this poll and
	// records now as the last poll time.
	PollDeviceCode(ctx context.Context, deviceCodeHash string, now time.Time) (*DeviceCode, error)
	// SetDeviceCodeInterval changes the minimum polling interval.
	SetDeviceCodeInterval(ctx context.Context, deviceCodeHash string, interval time.Duration) error
	// DecideDeviceCode approves or denies a pending, unexpired device code.
	// It returns ErrNotFound if there is no such code.
	DecideDeviceCode(ctx context.Context, userCodeHash, email string, approve bool, now time.Time) error
	// ConsumeDeviceCode atomically moves an approved code to consumed and
	// returns it. It returns ErrNotFound if the code is not approved.
	ConsumeDeviceCode(ctx context.Context, deviceCodeHash string, now time.Time) (*DeviceCode, error)

	CreateToken(ctx context.Context, t *Token) error
	GetToken(ctx context.Context, id string) (*Token, error)
	GetTokenByHash(ctx context.Context, hash string) (*Token, error)
	// ListTokens returns the tokens of a human, newest first.
	ListTokens(ctx context.Context, human string) ([]*Token, error)
	// MarkTokenUsed atomically sets used_at on an unused, unrevoked token
	// and reports whether it did. False means the token was already used.
	MarkTokenUsed(ctx context.Context, id string, now time.Time) (bool, error)
	// RevokeToken revokes a token, its whole family and every token derived
	// from them (transitively). It returns the number of tokens revoked.
	RevokeToken(ctx context.Context, id string, now time.Time) (int64, error)
	// RevokeFamily revokes every token of a family and their descendants.
	RevokeFamily(ctx context.Context, familyID string, now time.Time) (int64, error)

	// DeleteExpired removes sessions, codes and tokens that expired before
	// the given time. It returns the number of rows removed.
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)

	ApprovalStore

	Close() error
}
