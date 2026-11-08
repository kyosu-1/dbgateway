package notify

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
)

// Anomaly kinds (Detail["anomaly"] of anomaly_detected).
const (
	AnomalyDenials = "denials"
	AnomalyRows    = "rows"
)

// Anomaly windows.
const (
	DenialWindow = 10 * time.Minute
	RowsWindow   = time.Hour
)

// AnomalyOptions configures an Anomaly detector.
type AnomalyOptions struct {
	// Config provides the thresholds (anomaly.denials_per_10m,
	// anomaly.rows_per_hour) and the database labels. Required.
	Config *config.Config
	Now    func() time.Time
}

// Anomaly is an events.Publisher middleware that forwards every event to
// next and emits anomaly_detected when one requester
//
//   - is denied more than anomaly.denials_per_10m times within 10 minutes
//     (counted from the query_denied events passing through), or
//   - receives more than anomaly.rows_per_hour rows within an hour
//     (reported by the gateway through ObserveRows).
//
// The requester is the human (for agents, the human they act for). After
// an anomaly is reported for a requester, the same kind is not reported
// again for that requester until its window has passed.
type Anomaly struct {
	next        events.Publisher
	cfg         *config.Config
	now         func() time.Time
	maxDenials  int
	maxRows     int64
	mu          sync.Mutex
	denials     map[string][]time.Time
	rows        map[string][]rowBucket
	quietUntil  map[string]time.Time // key: kind + "\x00" + requester
	lastCleanup time.Time
}

type rowBucket struct {
	minute time.Time
	n      int64
}

var _ events.Publisher = (*Anomaly)(nil)

// NewAnomaly wraps next.
func NewAnomaly(next events.Publisher, opts AnomalyOptions) *Anomaly {
	a := &Anomaly{next: next, cfg: opts.Config, now: opts.Now, maxDenials: opts.Config.Anomaly.DenialsPer10m,
		maxRows: opts.Config.Anomaly.RowsPerHour, denials: map[string][]time.Time{}, rows: map[string][]rowBucket{},
		quietUntil: map[string]time.Time{}}
	if a.now == nil {
		a.now = time.Now
	}
	if a.maxDenials <= 0 {
		a.maxDenials = config.DefaultDenialsPer10m
	}
	if a.maxRows <= 0 {
		a.maxRows = config.DefaultRowsPerHour
	}
	return a
}

// requesterKey identifies the requester of an event.
func requesterKey(p *events.Principal) string {
	if p == nil {
		return ""
	}
	if p.Human != "" {
		return strings.ToLower(p.Human)
	}
	return "client:" + p.ClientID
}

// Publish implements events.Publisher.
func (a *Anomaly) Publish(ctx context.Context, e events.Event) {
	a.next.Publish(ctx, e)
	if e.Type != events.QueryDenied {
		return
	}
	key := requesterKey(e.Principal)
	if key == "" {
		return
	}
	now := a.now()
	a.mu.Lock()
	a.cleanup(now)
	cutoff := now.Add(-DenialWindow)
	ts := a.denials[key]
	for len(ts) > 0 && !ts[0].After(cutoff) {
		ts = ts[1:]
	}
	ts = append(ts, now)
	// Only the last maxDenials+1 timestamps matter.
	if len(ts) > a.maxDenials+1 {
		ts = ts[len(ts)-a.maxDenials-1:]
	}
	a.denials[key] = ts
	fire := len(ts) > a.maxDenials && a.arm(AnomalyDenials, key, now, DenialWindow)
	count := len(ts)
	a.mu.Unlock()
	if fire {
		a.emit(ctx, e.Principal, e.Database, AnomalyDenials, int64(count), int64(a.maxDenials), DenialWindow)
	}
}

// ObserveRows records that n rows were returned to p from database. The
// gateway calls it after every successful read (and break-glass write
// with RETURNING). It is cheap and never blocks on delivery.
func (a *Anomaly) ObserveRows(p *events.Principal, database string, n int64) {
	key := requesterKey(p)
	if key == "" || n <= 0 {
		return
	}
	now := a.now()
	minute := now.Truncate(time.Minute)
	a.mu.Lock()
	a.cleanup(now)
	cutoff := now.Add(-RowsWindow)
	bs := a.rows[key]
	for len(bs) > 0 && !bs[0].minute.After(cutoff) {
		bs = bs[1:]
	}
	if len(bs) > 0 && bs[len(bs)-1].minute.Equal(minute) {
		bs[len(bs)-1].n += n
	} else {
		bs = append(bs, rowBucket{minute: minute, n: n})
	}
	a.rows[key] = bs
	var total int64
	for _, b := range bs {
		total += b.n
	}
	fire := total > a.maxRows && a.arm(AnomalyRows, key, now, RowsWindow)
	a.mu.Unlock()
	if fire {
		a.emit(context.Background(), p, database, AnomalyRows, total, a.maxRows, RowsWindow)
	}
}

// arm reports whether an anomaly of kind may be reported for key now, and
// if so silences it for the window. Called with mu held.
func (a *Anomaly) arm(kind, key string, now time.Time, window time.Duration) bool {
	k := kind + "\x00" + key
	if now.Before(a.quietUntil[k]) {
		return false
	}
	a.quietUntil[k] = now.Add(window)
	return true
}

// cleanup drops idle requesters every few minutes. Called with mu held.
func (a *Anomaly) cleanup(now time.Time) {
	if now.Sub(a.lastCleanup) < 5*time.Minute {
		return
	}
	a.lastCleanup = now
	for k, ts := range a.denials {
		if len(ts) == 0 || !ts[len(ts)-1].After(now.Add(-DenialWindow)) {
			delete(a.denials, k)
		}
	}
	for k, bs := range a.rows {
		if len(bs) == 0 || !bs[len(bs)-1].minute.After(now.Add(-RowsWindow)) {
			delete(a.rows, k)
		}
	}
	for k, t := range a.quietUntil {
		if !now.Before(t) {
			delete(a.quietUntil, k)
		}
	}
}

func (a *Anomaly) emit(ctx context.Context, p *events.Principal, database, kind string, count, threshold int64, window time.Duration) {
	e := events.Event{
		Type: events.AnomalyDetected, Time: a.now(), Database: database, Status: kind,
		Detail: map[string]string{
			"anomaly": kind, "count": strconv.FormatInt(count, 10), "threshold": strconv.FormatInt(threshold, 10),
			"window": window.String(),
		},
	}
	if p != nil {
		cp := *p
		e.Principal = &cp
	}
	if db := a.cfg.Database(database); db != nil {
		e.Labels = db.Labels
	}
	a.next.Publish(context.WithoutCancel(ctx), e)
}
