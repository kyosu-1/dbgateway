package store

import (
	"context"
	"time"
)

// Passkey is a registered WebAuthn credential of a person.
type Passkey struct {
	// ID is the base64url (unpadded) credential ID.
	ID    string
	Email string
	// UserHandle is the random WebAuthn user handle of the person; every
	// passkey of one person carries the same handle.
	UserHandle []byte
	// Name is the label shown on the account page.
	Name string
	// Credential is the credential record (JSON), owned by the auth package.
	Credential []byte
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// PasskeyEnrollment is a one-time passkey enrollment link (only the hash of
// its token is stored).
type PasskeyEnrollment struct {
	TokenHash string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// WebAuthnSession is a WebAuthn ceremony in progress (between the begin and
// finish requests). Data is the library's session data (JSON).
type WebAuthnSession struct {
	IDHash    string
	Purpose   string // login | register | stepup | enroll
	Email     string // empty for discoverable login
	Data      []byte
	CreatedAt time.Time
	ExpiresAt time.Time
}

// WebStore persists what the web UI needs beyond the OAuth server: session
// step-up, passkeys, enrollment links and WebAuthn ceremonies.
type WebStore interface {
	// SetSessionStepUp records a re-authentication on a browser session.
	// It returns ErrNotFound if the session does not exist.
	SetSessionStepUp(ctx context.Context, idHash, method string, at time.Time) error

	CreatePasskey(ctx context.Context, p *Passkey) error
	GetPasskey(ctx context.Context, id string) (*Passkey, error)
	// ListPasskeys returns the passkeys of a person, oldest first.
	ListPasskeys(ctx context.Context, email string) ([]*Passkey, error)
	// UpdatePasskeyUse stores the updated credential record (sign counter,
	// flags) and the time of use.
	UpdatePasskeyUse(ctx context.Context, id string, credential []byte, at time.Time) error
	// DeletePasskey removes a passkey of email. It returns ErrNotFound if
	// there is no such passkey owned by email.
	DeletePasskey(ctx context.Context, email, id string) error

	CreatePasskeyEnrollment(ctx context.Context, e *PasskeyEnrollment) error
	// GetPasskeyEnrollment returns an enrollment link that is unused and
	// unexpired at now, or ErrNotFound.
	GetPasskeyEnrollment(ctx context.Context, tokenHash string, now time.Time) (*PasskeyEnrollment, error)
	// ConsumePasskeyEnrollment atomically marks an unused, unexpired link as
	// used and returns it. It returns ErrNotFound otherwise.
	ConsumePasskeyEnrollment(ctx context.Context, tokenHash string, now time.Time) (*PasskeyEnrollment, error)

	CreateWebAuthnSession(ctx context.Context, s *WebAuthnSession) error
	// ConsumeWebAuthnSession atomically deletes and returns an unexpired
	// ceremony. It returns ErrNotFound if it does not exist, was already
	// consumed, or has expired.
	ConsumeWebAuthnSession(ctx context.Context, idHash string, now time.Time) (*WebAuthnSession, error)
}
