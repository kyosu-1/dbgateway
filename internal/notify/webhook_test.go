package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
)

type hookServer struct {
	srv      *httptest.Server
	attempts atomic.Int32
	mu       sync.Mutex
	bodies   [][]byte
	headers  []http.Header
	status   func(attempt int32) int
}

func newHookServer(t *testing.T, status func(attempt int32) int) *hookServer {
	h := &hookServer{status: status}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := h.attempts.Add(1)
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.bodies = append(h.bodies, body)
		h.headers = append(h.headers, r.Header.Clone())
		h.mu.Unlock()
		w.WriteHeader(h.status(n))
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func webhookDispatcher(t *testing.T, h *hookServer, secret string) *Dispatcher {
	cfg := testConfig(config.NotificationRoute{Events: []string{"execution_finished", "query_denied"},
		To: config.NotificationTarget{WebhookEnv: "TEST_HOOK"}})
	cfg.Slack = nil
	env := map[string]string{"TEST_HOOK": h.srv.URL + "/hook?token=s3cr3t"}
	if secret != "" {
		cfg.NotificationsWebhookSecretEnv = "TEST_HOOK_SECRET"
		env["TEST_HOOK_SECRET"] = secret
	}
	d := New(Options{Config: cfg, Logger: quietLogger(), Getenv: testEnv(env), WebhookBackoff: time.Millisecond})
	t.Cleanup(d.Close)
	return d
}

func TestWebhookPayloadAndSignature(t *testing.T) {
	h := newHookServer(t, func(int32) int { return http.StatusOK })
	d := webhookDispatcher(t, h, "hook-key")
	e := approvalEvent(events.ExecutionFinished, "failed")
	e.Detail["error"] = "Key (email)=(" + secretLiteral + ") already exists"
	e.Detail["rows_affected"] = "0"
	d.Publish(context.Background(), e)
	if !d.flush(5 * time.Second) {
		t.Fatal("not flushed")
	}
	if h.attempts.Load() != 1 {
		t.Fatalf("attempts = %d", h.attempts.Load())
	}
	body, hdr := h.bodies[0], h.headers[0]
	if hdr.Get("User-Agent") != "dbgateway" || hdr.Get("Content-Type") != "application/json" || hdr.Get(HeaderEvent) != "execution_finished" {
		t.Errorf("headers = %v", hdr)
	}
	if got, want := hdr.Get(HeaderSignature), Sign([]byte("hook-key"), body); got != want || !strings.HasPrefix(got, "sha256=") {
		t.Errorf("signature = %q, want %q", got, want)
	}
	if strings.Contains(string(body), secretLiteral) {
		t.Errorf("payload leaks the literal: %s", body)
	}
	var p map[string]any
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	if p["type"] != "execution_finished" || p["request_id"] != "req_abc" || p["sql"] != "UPDATE users SET email = $1 WHERE id = $2" ||
		p["status"] != "failed" || p["text"] == "" {
		t.Errorf("payload = %v", p)
	}
	detail, _ := p["detail"].(map[string]any)
	if detail["rows_affected"] != "0" || detail["risk"] != "high" || detail["error"] != nil {
		t.Errorf("detail = %v", detail)
	}
	if d.Stats().Delivered != 1 {
		t.Errorf("stats = %+v", d.Stats())
	}
}

func TestWebhookUnsigned(t *testing.T) {
	h := newHookServer(t, func(int32) int { return http.StatusNoContent })
	d := webhookDispatcher(t, h, "")
	d.Publish(context.Background(), approvalEvent(events.QueryDenied, "deny"))
	d.flush(5 * time.Second)
	if h.attempts.Load() != 1 || h.headers[0].Get(HeaderSignature) != "" {
		t.Errorf("attempts = %d, signature = %q", h.attempts.Load(), h.headers[0].Get(HeaderSignature))
	}
}

func TestWebhookRetries(t *testing.T) {
	for _, tt := range []struct {
		name      string
		status    func(int32) int
		attempts  int32
		delivered int64
		failed    int64
	}{
		{"recovers", func(n int32) int { return map[bool]int{true: 503, false: 200}[n < 3] }, 3, 1, 0},
		{"429 retried", func(n int32) int { return map[bool]int{true: 429, false: 200}[n < 2] }, 2, 1, 0},
		{"gives up", func(int32) int { return 500 }, 3, 0, 1},
		{"4xx not retried", func(int32) int { return 400 }, 1, 0, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHookServer(t, tt.status)
			d := webhookDispatcher(t, h, "")
			d.Publish(context.Background(), approvalEvent(events.QueryDenied, "deny"))
			if !d.flush(5 * time.Second) {
				t.Fatal("not flushed")
			}
			s := d.Stats()
			if h.attempts.Load() != tt.attempts || s.Delivered != tt.delivered || s.Failed != tt.failed {
				t.Errorf("attempts = %d, stats = %+v", h.attempts.Load(), s)
			}
		})
	}
}

func TestWebhookUnreachableAndUnset(t *testing.T) {
	cfg := testConfig(config.NotificationRoute{Events: []string{"query_denied"}, To: config.NotificationTarget{WebhookEnv: "TEST_HOOK"}})
	cfg.Slack = nil
	d := New(Options{Config: cfg, Logger: quietLogger(), Getenv: testEnv(map[string]string{"TEST_HOOK": "http://127.0.0.1:1/x"}),
		WebhookBackoff: time.Millisecond})
	defer d.Close()
	d.Publish(context.Background(), approvalEvent(events.QueryDenied, "deny"))
	d.flush(5 * time.Second)
	if s := d.Stats(); s.Failed != 1 {
		t.Errorf("unreachable: stats = %+v", s)
	}

	d2 := New(Options{Config: cfg, Logger: quietLogger(), Getenv: testEnv(nil)})
	defer d2.Close()
	d2.Publish(context.Background(), approvalEvent(events.QueryDenied, "deny"))
	d2.flush(5 * time.Second)
	if s := d2.Stats(); s.Skipped != 1 || s.Failed != 0 {
		t.Errorf("unset: stats = %+v", s)
	}
}
