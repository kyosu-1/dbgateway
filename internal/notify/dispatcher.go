package notify

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slack-go/slack"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/policy"
)

// Rejecter rejects approval requests; *approval.Service implements it.
type Rejecter interface {
	Reject(ctx context.Context, approver *identity.Principal, id, comment string) (*approval.Request, error)
}

var _ Rejecter = (*approval.Service)(nil)

// PrincipalResolver builds the principal of a human (with their dbgateway
// groups) from their e-mail address. It must fail for deactivated users.
type PrincipalResolver func(ctx context.Context, email string) (*identity.Principal, error)

// Options configures a Dispatcher.
type Options struct {
	Config *config.Config // required
	// Store keeps Slack threads and links. Nil disables threads, mentions
	// of linked users, DMs and the Slack commands.
	Store Store
	// Approvals enables the reject button (see also SetApprovals).
	Approvals Rejecter
	// PrincipalResolver resolves the human behind a linked Slack user for
	// the reject button. Defaults to the store's user (deactivated users
	// are refused) with groups from RBAC.ResolveGroups.
	PrincipalResolver PrincipalResolver
	// RBAC defaults to policy.NewRBAC(Config).
	RBAC   *policy.RBAC
	Logger *slog.Logger
	// Getenv defaults to os.Getenv (tokens, webhook URLs, webhook secret).
	Getenv func(string) string
	// HTTPClient sends webhooks. Defaults to a client with a 5s timeout.
	HTTPClient *http.Client
	// SlackAPIURL overrides the Slack Web API base URL (tests).
	SlackAPIURL string
	// QueueSize bounds the number of pending events (default 1024). When
	// full, new events are dropped and counted.
	QueueSize int
	// WebhookBackoff is the first retry delay of webhooks (default 1s,
	// doubled on each retry).
	WebhookBackoff time.Duration
	Now            func() time.Time
}

// Stats are delivery counters.
type Stats struct {
	Published int64 // events accepted
	Dropped   int64 // events dropped because a queue was full or closed
	Delivered int64 // messages delivered (Slack posts, webhook requests)
	Failed    int64 // deliveries that failed after retries
	Skipped   int64 // deliveries skipped (no linked user, unset webhook URL)
}

type stats struct {
	published, dropped, delivered, failed, skipped atomic.Int64
}

// Dispatcher routes events to Slack and webhooks. It implements
// events.Publisher: Publish never blocks and never fails; delivery
// happens in a background worker, in order.
type Dispatcher struct {
	cfg      *config.Config
	logger   *slog.Logger
	m        msgs
	routes   []route
	st       Store
	rbac     *policy.RBAC
	now      func() time.Time
	getenv   func(string) string
	slackURL string

	slack   *slackSink   // nil when Slack is disabled
	webhook *webhookSink // nil when no route has a webhook
	linker  *SlackLinker // nil without a store

	approvals atomic.Pointer[Rejecter]
	resolver  atomic.Pointer[PrincipalResolver]

	queue  chan events.Event
	mu     sync.RWMutex
	closed bool
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	stats  stats
	// inflight counts events and webhook jobs not yet fully handled.
	inflight atomic.Int64

	lastDropLog atomic.Int64
}

var _ events.Publisher = (*Dispatcher)(nil)

// New returns a running dispatcher. Call Close to stop it, and Run to
// serve Slack interactions (Socket Mode).
func New(opts Options) *Dispatcher {
	d := &Dispatcher{cfg: opts.Config, logger: opts.Logger, st: opts.Store, rbac: opts.RBAC, now: opts.Now,
		getenv: opts.Getenv, slackURL: opts.SlackAPIURL, done: make(chan struct{})}
	if d.logger == nil {
		d.logger = slog.Default()
	}
	if d.rbac == nil {
		d.rbac = policy.NewRBAC(d.cfg)
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.getenv == nil {
		d.getenv = os.Getenv
	}
	size := opts.QueueSize
	if size <= 0 {
		size = 1024
	}
	d.queue = make(chan events.Event, size)
	d.m = newMsgs(d.cfg.NotificationsLanguage)
	d.routes = compileRoutes(d.cfg, d.logger)
	d.ctx, d.cancel = context.WithCancel(context.Background())
	if opts.Approvals != nil {
		d.SetApprovals(opts.Approvals)
	}
	if opts.PrincipalResolver != nil {
		d.SetPrincipalResolver(opts.PrincipalResolver)
	}
	if d.st != nil {
		d.linker = NewSlackLinker(d.st, d.now, d.logger)
	}

	if d.cfg.SlackEnabled() {
		if tok := d.getenv(d.cfg.Slack.BotTokenEnv); tok != "" {
			d.slack = &slackSink{api: d.slackClient(tok), st: d.st, m: d.m, logger: d.logger, now: d.now, stats: &d.stats}
		} else {
			d.logger.Warn("notify: Slack bot token not set; Slack notifications disabled", "env", d.cfg.Slack.BotTokenEnv)
		}
	}
	if d.hasWebhooks() {
		client := opts.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 5 * time.Second}
		}
		backoff := opts.WebhookBackoff
		if backoff <= 0 {
			backoff = time.Second
		}
		var secret []byte
		if env := d.cfg.NotificationsWebhookSecretEnv; env != "" {
			secret = []byte(d.getenv(env))
		}
		d.webhook = &webhookSink{client: client, getenv: d.getenv, secret: secret, backoff: backoff, maxAttempts: 3,
			m: d.m, logger: d.logger, stats: &d.stats, queue: make(chan webhookJob, size), done: make(chan struct{})}
		go d.webhook.run(d.ctx)
	}
	go d.run()
	return d
}

func (d *Dispatcher) slackClient(token string, opts ...slack.Option) *slack.Client {
	if d.slackURL != "" {
		u := d.slackURL
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
		opts = append(opts, slack.OptionAPIURL(u))
	}
	return slack.New(token, opts...)
}

func (d *Dispatcher) hasWebhooks() bool {
	for _, r := range d.cfg.Notifications {
		if r.To.WebhookEnv != "" {
			return true
		}
	}
	return false
}

// SetApprovals sets the approval service used by the reject button.
func (d *Dispatcher) SetApprovals(r Rejecter) { d.approvals.Store(&r) }

// SetPrincipalResolver replaces the default principal resolution (e.g.
// with the auth package's).
func (d *Dispatcher) SetPrincipalResolver(f PrincipalResolver) { d.resolver.Store(&f) }

// Linker returns the Slack linker for the web account page, or nil when
// the dispatcher has no store.
func (d *Dispatcher) Linker() *SlackLinker { return d.linker }

// Stats returns the delivery counters.
func (d *Dispatcher) Stats() Stats {
	return Stats{Published: d.stats.published.Load(), Dropped: d.stats.dropped.Load(), Delivered: d.stats.delivered.Load(),
		Failed: d.stats.failed.Load(), Skipped: d.stats.skipped.Load()}
}

// Publish implements events.Publisher. It never blocks: when the queue is
// full (or the dispatcher is closed) the event is dropped and counted.
func (d *Dispatcher) Publish(_ context.Context, e events.Event) {
	if e.Time.IsZero() {
		e.Time = d.now()
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		d.stats.dropped.Add(1)
		return
	}
	select {
	case d.queue <- e:
		d.inflight.Add(1)
		d.stats.published.Add(1)
	default:
		d.stats.dropped.Add(1)
		// Log at most once a minute.
		now := d.now().Unix()
		if last := d.lastDropLog.Load(); now-last >= 60 && d.lastDropLog.CompareAndSwap(last, now) {
			d.logger.Warn("notify: queue full; events dropped", "dropped_total", d.stats.dropped.Load())
		}
	}
}

func (d *Dispatcher) run() {
	defer close(d.done)
	for e := range d.queue {
		d.dispatch(e)
		d.inflight.Add(-1)
	}
}

// dispatch delivers one event. A panic in a sink is contained: it must
// never take the server down.
func (d *Dispatcher) dispatch(e events.Event) {
	defer func() {
		if r := recover(); r != nil {
			d.stats.failed.Add(1)
			d.logger.Error("notify: panic while delivering", "event", e.Type, "panic", r)
		}
	}()
	t := resolve(d.routes, e, d.logger)
	if d.slack != nil {
		ctx, cancel := context.WithTimeout(d.ctx, time.Minute)
		d.slack.deliver(ctx, e, t)
		cancel()
	} else if t.slack() {
		d.stats.skipped.Add(1)
	}
	if d.webhook != nil {
		for _, env := range t.webhooks {
			d.webhook.enqueue(env, e, &d.inflight)
		}
	}
}

// Close stops accepting events and waits (up to 10s) for queued events to
// be delivered.
func (d *Dispatcher) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	close(d.queue)
	d.mu.Unlock()

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	select {
	case <-d.done:
	case <-deadline.C:
	}
	if d.webhook != nil {
		close(d.webhook.queue)
		select {
		case <-d.webhook.done:
		case <-deadline.C:
		}
	}
	d.cancel()
}

// flush waits until every event published so far has been handled,
// including queued webhooks (tests).
func (d *Dispatcher) flush(timeout time.Duration) bool {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if d.inflight.Load() == 0 {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}
