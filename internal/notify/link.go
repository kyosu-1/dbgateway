package notify

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kyosu-1/dbgateway/internal/store"
)

// LinkCodeTTL is how long a linking code is valid.
const LinkCodeTTL = 10 * time.Minute

// Linking codes use Crockford's base32 alphabet (no I, L, O, U) and are
// shown as XXXX-XXXX (40 bits). With a 10-minute lifetime, one valid code
// per user and a per-Slack-user attempt limit, guessing is impractical.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Link attempt limit per Slack user.
const (
	maxLinkFailures   = 5
	linkFailureWindow = 10 * time.Minute
)

// ErrBadCode is returned when a linking code is wrong, used or expired.
var ErrBadCode = errors.New("notify: invalid or expired linking code")

// ErrTooManyAttempts is returned after too many wrong linking codes.
var ErrTooManyAttempts = errors.New("notify: too many linking attempts")

// SlackLinker links dbgateway users to Slack users. The web account page
// uses Linked, IssueCode and Unlink; the Slack command `/dbgw link <code>`
// completes the link.
type SlackLinker struct {
	st     LinkStore
	now    func() time.Time
	logger *slog.Logger

	mu       sync.Mutex
	failures map[string][]time.Time // Slack user → recent wrong codes
}

// NewSlackLinker returns a linker. now and logger may be nil.
func NewSlackLinker(st LinkStore, now func() time.Time, logger *slog.Logger) *SlackLinker {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SlackLinker{st: st, now: now, logger: logger, failures: map[string][]time.Time{}}
}

func opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// Linked returns the Slack user ID linked to email.
func (l *SlackLinker) Linked(email string) (slackUser string, ok bool) {
	ctx, cancel := opCtx()
	defer cancel()
	link, err := l.st.GetSlackLinkByEmail(ctx, normEmail(email))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			l.logger.Warn("notify: look up Slack link failed", "err", err)
		}
		return "", false
	}
	return link.SlackUser, true
}

// IssueCode creates a one-time linking code for email, valid for
// LinkCodeTTL. Only its hash is stored; issuing a new code invalidates the
// previous one.
func (l *SlackLinker) IssueCode(email string) (code string, expires time.Time, err error) {
	email = normEmail(email)
	if email == "" {
		return "", time.Time{}, errors.New("notify: email required")
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	raw := make([]byte, 8)
	for i, v := range b {
		raw[i] = codeAlphabet[int(v)%len(codeAlphabet)] // 256 % 32 == 0: unbiased
	}
	code = string(raw[:4]) + "-" + string(raw[4:])
	now := l.now()
	expires = now.Add(LinkCodeTTL)
	ctx, cancel := opCtx()
	defer cancel()
	if err := l.st.CreateSlackLinkCode(ctx, email, store.HashSecret(normCode(code)), now, expires); err != nil {
		return "", time.Time{}, err
	}
	return code, expires, nil
}

// Unlink removes the Slack link of email (no error when there is none).
func (l *SlackLinker) Unlink(email string) error {
	ctx, cancel := opCtx()
	defer cancel()
	return l.st.DeleteSlackLink(ctx, normEmail(email))
}

// normCode upper-cases a code and drops separators and spaces, and maps
// the characters Crockford's base32 treats as aliases.
func normCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Link consumes code and links slackUser to the account that issued it.
func (l *SlackLinker) Link(ctx context.Context, code, slackUser string) (email string, err error) {
	if l.tooMany(slackUser) {
		return "", ErrTooManyAttempts
	}
	c := normCode(code)
	if len(c) != 8 {
		l.recordFailure(slackUser)
		return "", ErrBadCode
	}
	email, err = l.st.ConsumeSlackLinkCode(ctx, store.HashSecret(c), slackUser, l.now())
	if errors.Is(err, store.ErrNotFound) {
		l.recordFailure(slackUser)
		return "", ErrBadCode
	}
	return email, err
}

// LinkedEmail returns the dbgateway user linked to a Slack user.
func (l *SlackLinker) LinkedEmail(ctx context.Context, slackUser string) (string, bool, error) {
	link, err := l.st.GetSlackLinkBySlackUser(ctx, slackUser)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return link.Email, true, nil
}

// UnlinkSlackUser removes the link of a Slack user.
func (l *SlackLinker) UnlinkSlackUser(ctx context.Context, slackUser string) (string, bool, error) {
	email, err := l.st.DeleteSlackLinkBySlackUser(ctx, slackUser)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return email, true, nil
}

func (l *SlackLinker) recent(slackUser string) []time.Time {
	cutoff := l.now().Add(-linkFailureWindow)
	var keep []time.Time
	for _, t := range l.failures[slackUser] {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.failures, slackUser)
	} else {
		l.failures[slackUser] = keep
	}
	return keep
}

func (l *SlackLinker) tooMany(slackUser string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(slackUser)) >= maxLinkFailures
}

func (l *SlackLinker) recordFailure(slackUser string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[slackUser] = append(l.recent(slackUser), l.now())
}
