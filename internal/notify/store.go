package notify

import (
	"context"
	"time"

	"github.com/kyosu-1/dbgateway/internal/store"
)

// LinkStore persists Slack links and one-time linking codes.
// *store.SQLite implements it.
type LinkStore interface {
	CreateSlackLinkCode(ctx context.Context, email, codeHash string, created, expires time.Time) error
	ConsumeSlackLinkCode(ctx context.Context, codeHash, slackUser string, now time.Time) (string, error)
	GetSlackLinkByEmail(ctx context.Context, email string) (*store.SlackLink, error)
	GetSlackLinkBySlackUser(ctx context.Context, slackUser string) (*store.SlackLink, error)
	DeleteSlackLink(ctx context.Context, email string) error
	DeleteSlackLinkBySlackUser(ctx context.Context, slackUser string) (string, error)
}

// ThreadStore persists the Slack message of each approval request.
type ThreadStore interface {
	SaveSlackThread(ctx context.Context, t *store.SlackThread) error
	ListSlackThreads(ctx context.Context, requestID string) ([]*store.SlackThread, error)
}

// StateStore persists small notifier state (the last configuration
// version).
type StateStore interface {
	SwapNotifyState(ctx context.Context, key, value string, now time.Time) (previous string, found bool, err error)
}

// UserStore resolves dbgateway users (for the default PrincipalResolver).
type UserStore interface {
	GetUser(ctx context.Context, email string) (*store.User, error)
	UserActive(ctx context.Context, email string) (bool, error)
}

// Store is everything the dispatcher needs. *store.SQLite implements it.
type Store interface {
	LinkStore
	ThreadStore
	StateStore
	UserStore
}

var _ Store = (*store.SQLite)(nil)
