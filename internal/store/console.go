package store

import (
	"context"
	"time"
)

// Web SQL editor state (migration 0006). Every method takes the owner's
// e-mail and only ever touches that person's rows.

// ConsoleHistory is one statement a person ran in the SQL editor.
type ConsoleHistory struct {
	ID        string
	Email     string
	Database  string
	SQL       string // as typed, literals included
	Reason    string
	Status    string // ok, pending, denied or error
	RowCount  *int64
	RequestID string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// SavedQuery is a statement a person saved by name.
type SavedQuery struct {
	ID        string
	Email     string
	Name      string
	Database  string
	SQL       string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// MaxConsoleHistory is the number of history entries kept per person;
// older ones are removed when a new one is added.
const MaxConsoleHistory = 500

// MaxSavedQueries is the number of saved queries a person may have.
const MaxSavedQueries = 200

// ConsoleStore keeps the SQL editor's history and saved queries.
type ConsoleStore interface {
	// AddConsoleHistory stores an entry and keeps only the newest
	// MaxConsoleHistory entries of that person.
	AddConsoleHistory(ctx context.Context, h *ConsoleHistory) error
	// ListConsoleHistory returns the unexpired entries of email, newest first.
	ListConsoleHistory(ctx context.Context, email string, limit int, now time.Time) ([]*ConsoleHistory, error)
	// GetConsoleHistory returns an unexpired entry of email, or ErrNotFound.
	GetConsoleHistory(ctx context.Context, email, id string, now time.Time) (*ConsoleHistory, error)

	// CreateSavedQuery stores a query. It returns ErrLimit when email
	// already has MaxSavedQueries.
	CreateSavedQuery(ctx context.Context, q *SavedQuery) error
	// ListSavedQueries returns the queries of email ordered by name.
	ListSavedQueries(ctx context.Context, email string) ([]*SavedQuery, error)
	// GetSavedQuery returns a query of email, or ErrNotFound.
	GetSavedQuery(ctx context.Context, email, id string) (*SavedQuery, error)
	// DeleteSavedQuery removes a query of email, or returns ErrNotFound.
	DeleteSavedQuery(ctx context.Context, email, id string) error
}
