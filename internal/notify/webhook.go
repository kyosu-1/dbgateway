package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/kyosu-1/dbgateway/internal/events"
)

// Webhook request headers.
const (
	HeaderSignature = "X-Dbgw-Signature"
	HeaderEvent     = "X-Dbgw-Event"
)

// WebhookPayload is the JSON body POSTed to webhooks: the event fields
// (normalized SQL only; Detail restricted to fields that never carry
// query data) plus a one-line Text summary.
type WebhookPayload struct {
	events.Event
	Text string `json:"text"`
}

// Sign returns the X-Dbgw-Signature value of body: "sha256=" followed by
// the hex HMAC-SHA256 of the body with key.
func Sign(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type webhookJob struct {
	env  string
	body []byte
	typ  events.Type
	// inflight is decremented once the job is handled.
	inflight *atomic.Int64
}

// webhookSink POSTs events to the URLs held in environment variables, in
// its own goroutine so that retries never delay Slack delivery.
type webhookSink struct {
	client      *http.Client
	getenv      func(string) string
	secret      []byte
	backoff     time.Duration
	maxAttempts int
	m           msgs
	logger      *slog.Logger
	stats       *stats
	queue       chan webhookJob
	done        chan struct{}
}

func (w *webhookSink) enqueue(env string, e events.Event, inflight *atomic.Int64) {
	body, err := json.Marshal(WebhookPayload{Event: sanitize(e), Text: w.m.summary(e)})
	if err != nil {
		w.stats.failed.Add(1)
		return
	}
	select {
	case w.queue <- webhookJob{env: env, body: body, typ: e.Type, inflight: inflight}:
		inflight.Add(1)
	default:
		w.stats.dropped.Add(1)
		w.logger.Warn("notify: webhook queue full; event dropped", "event", e.Type, "webhook_env", env)
	}
}

func (w *webhookSink) run(ctx context.Context) {
	defer close(w.done)
	for job := range w.queue {
		w.send(ctx, job)
		job.inflight.Add(-1)
	}
}

// send POSTs one job, retrying network errors, 429 and 5xx with
// exponential backoff, at most maxAttempts times in total.
func (w *webhookSink) send(ctx context.Context, job webhookJob) {
	target := w.getenv(job.env)
	if target == "" {
		w.stats.skipped.Add(1)
		w.logger.Debug("notify: webhook URL not set", "webhook_env", job.env)
		return
	}
	if u, err := url.Parse(target); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		w.stats.failed.Add(1)
		w.logger.Warn("notify: webhook URL is not an http(s) URL", "webhook_env", job.env)
		return
	}
	delay := w.backoff
	var lastErr error
	for attempt := 1; attempt <= w.maxAttempts; attempt++ {
		retry, err := w.post(ctx, target, job)
		if err == nil {
			w.stats.delivered.Add(1)
			return
		}
		lastErr = err
		if !retry || attempt == w.maxAttempts {
			break
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			attempt = w.maxAttempts
		}
		delay *= 2
	}
	w.stats.failed.Add(1)
	// The URL is never logged: it often embeds a secret.
	w.logger.Warn("notify: webhook delivery failed", "event", job.typ, "webhook_env", job.env, "err", lastErr)
}

func (w *webhookSink) post(ctx context.Context, target string, job webhookJob) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(job.body))
	if err != nil {
		return false, fmt.Errorf("build request: %w", sanitizeURLError(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dbgateway")
	req.Header.Set(HeaderEvent, string(job.typ))
	if len(w.secret) > 0 {
		req.Header.Set(HeaderSignature, Sign(w.secret, job.body))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return true, sanitizeURLError(err)
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, fmt.Errorf("status %d", resp.StatusCode)
	default:
		return false, fmt.Errorf("status %d", resp.StatusCode)
	}
}

// sanitizeURLError drops the URL from *url.Error so that it is not logged.
func sanitizeURLError(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}
