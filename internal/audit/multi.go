package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Record is one stored audit line handed to a Forwarder.
type Record struct {
	// Line is the JSON line as stored by the primary sink (without the
	// trailing newline), including its hash.
	Line []byte
	// Hash is the line's own hash (the "hash" field).
	Hash string
	// At is the time the line was written.
	At time.Time
}

// Forwarder sends stored audit lines to a secondary destination (a SIEM,
// an OpenTelemetry collector). Forwarding is best effort: it never decides
// whether a request succeeds.
type Forwarder interface {
	// Name identifies the forwarder in logs and statistics.
	Name() string
	// Forward sends a batch of records. It is never called concurrently
	// for the same forwarder and must honor ctx.
	Forward(ctx context.Context, batch []Record) error
	// Shutdown flushes and releases resources.
	Shutdown(ctx context.Context) error
}

const (
	forwardQueueSize = 4096
	forwardMaxBatch  = 256
	forwardTimeout   = 30 * time.Second
	shutdownTimeout  = 10 * time.Second
	dropLogInterval  = time.Minute
)

// MultiSink writes to a primary sink and copies every stored line to
// forwarders.
//
// The primary sink is authoritative: Append fails if and only if the
// primary fails, so the caller fails closed exactly as with the primary
// alone. Forwarders run asynchronously, each behind a bounded queue; when a
// queue is full the line is dropped for that forwarder (never blocking the
// request), and drops and failures are counted and logged.
type MultiSink struct {
	primary Sink
	logger  *slog.Logger

	mu     sync.RWMutex // guards closed and sends on the queues
	closed bool
	fwds   []*forwarderQueue
	wg     sync.WaitGroup
}

var _ Sink = (*MultiSink)(nil)

type forwarderQueue struct {
	f  Forwarder
	ch chan Record

	sent, dropped, failed atomic.Uint64
	lastLog               atomic.Int64 // unix nanos of the last drop/failure log
}

// ForwarderStats are the counters of one forwarder.
type ForwarderStats struct {
	Name string
	// Sent is the number of records forwarded successfully.
	Sent uint64
	// Dropped is the number of records discarded because the queue was
	// full or the sink was closing.
	Dropped uint64
	// Failed is the number of records the forwarder failed to send.
	Failed uint64
}

// NewMultiSink returns a sink writing to primary and forwarding to
// forwarders. Close closes the primary and shuts the forwarders down.
func NewMultiSink(primary Sink, forwarders ...Forwarder) *MultiSink {
	m := &MultiSink{primary: primary, logger: slog.Default()}
	for _, f := range forwarders {
		q := &forwarderQueue{f: f, ch: make(chan Record, forwardQueueSize)}
		m.fwds = append(m.fwds, q)
		m.wg.Add(1)
		go m.run(q)
	}
	return m
}

// SetLogger sets the logger for drop and failure reports. Call it before
// the first Append.
func (m *MultiSink) SetLogger(l *slog.Logger) {
	if l != nil {
		m.logger = l
	}
}

// LastHash returns the primary sink's last hash.
func (m *MultiSink) LastHash() (string, error) { return m.primary.LastHash() }

// Append stores line in the primary sink, then queues it for the
// forwarders without waiting.
func (m *MultiSink) Append(line []byte, at time.Time) error {
	if err := m.primary.Append(line, at); err != nil {
		return err
	}
	if len(m.fwds) == 0 {
		return nil
	}
	rec := Record{Line: append([]byte(nil), line...), Hash: lineHash(line), At: at}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, q := range m.fwds {
		if m.closed {
			q.dropped.Add(1)
			continue
		}
		select {
		case q.ch <- rec:
		default:
			q.dropped.Add(1)
			m.report(q, "audit forwarder queue full; entry dropped", nil)
		}
	}
	return nil
}

// Close stops accepting records, lets the forwarders drain their queues
// (bounded by a timeout), shuts them down and closes the primary sink.
func (m *MultiSink) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	for _, q := range m.fwds {
		close(q.ch)
	}
	m.mu.Unlock()

	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		m.logger.Warn("audit forwarders did not drain in time; remaining entries are dropped")
	}

	var errs []error
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, q := range m.fwds {
		if err := q.f.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("audit forwarder %s: shutdown: %w", q.f.Name(), err))
		}
		if d, f := q.dropped.Load(), q.failed.Load(); d > 0 || f > 0 {
			m.logger.Warn("audit forwarder totals", "forwarder", q.f.Name(), "sent", q.sent.Load(), "dropped", d, "failed", f)
		}
	}
	if err := m.primary.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Stats returns the counters of every forwarder.
func (m *MultiSink) Stats() []ForwarderStats {
	out := make([]ForwarderStats, 0, len(m.fwds))
	for _, q := range m.fwds {
		out = append(out, ForwarderStats{Name: q.f.Name(), Sent: q.sent.Load(), Dropped: q.dropped.Load(), Failed: q.failed.Load()})
	}
	return out
}

func (m *MultiSink) run(q *forwarderQueue) {
	defer m.wg.Done()
	batch := make([]Record, 0, forwardMaxBatch)
	for rec := range q.ch {
		batch = append(batch[:0], rec)
	fill:
		for len(batch) < forwardMaxBatch {
			select {
			case r, ok := <-q.ch:
				if !ok {
					break fill
				}
				batch = append(batch, r)
			default:
				break fill
			}
		}
		m.forward(q, batch)
	}
}

func (m *MultiSink) forward(q *forwarderQueue, batch []Record) {
	ctx, cancel := context.WithTimeout(context.Background(), forwardTimeout)
	defer cancel()
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return q.f.Forward(ctx, batch)
	}()
	if err != nil {
		q.failed.Add(uint64(len(batch)))
		m.report(q, "audit forwarding failed", err)
		return
	}
	q.sent.Add(uint64(len(batch)))
}

// report logs a drop or failure at most once per dropLogInterval per
// forwarder, with the running totals.
func (m *MultiSink) report(q *forwarderQueue, msg string, err error) {
	now := time.Now().UnixNano()
	last := q.lastLog.Load()
	if now-last < int64(dropLogInterval) || !q.lastLog.CompareAndSwap(last, now) {
		return
	}
	attrs := []any{"forwarder", q.f.Name(), "dropped_total", q.dropped.Load(), "failed_total", q.failed.Load()}
	if err != nil {
		attrs = append(attrs, "err", err)
	}
	m.logger.Warn(msg, attrs...)
}

// lineHash extracts the hash from an encoded line ("...,"hash":"<64 hex>"}").
func lineHash(line []byte) string {
	if len(line) < hashSuffixLen {
		return ""
	}
	return string(line[len(line)-66 : len(line)-2])
}
