package notify

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
)

type recorder struct {
	mu     sync.Mutex
	events []events.Event
}

func (r *recorder) Publish(_ context.Context, e events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) anomalies() []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.Event
	for _, e := range r.events {
		if e.Type == events.AnomalyDetected {
			out = append(out, e)
		}
	}
	return out
}

func TestAnomalyDenials(t *testing.T) {
	now := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	cfg := testConfig()
	cfg.Databases = []config.Database{{Name: "prod-main", Labels: map[string]string{"env": "prod"}}}
	rec := &recorder{}
	a := NewAnomaly(rec, AnomalyOptions{Config: cfg, Now: func() time.Time { return now }}) // threshold 3 per 10m
	agent := &events.Principal{Kind: "agent", Human: "Taro@example.com", Agent: "claude-code"}
	deny := func(p *events.Principal) {
		a.Publish(context.Background(), events.Event{Type: events.QueryDenied, Database: "prod-main", Principal: p, Status: "deny"})
	}

	for range 3 {
		deny(agent)
		now = now.Add(time.Minute)
	}
	if len(rec.anomalies()) != 0 {
		t.Fatal("anomaly at the threshold")
	}
	if len(rec.events) != 3 {
		t.Fatalf("events not forwarded: %d", len(rec.events))
	}
	// The same human through another agent counts toward the same requester.
	deny(&events.Principal{Kind: "human", Human: "taro@example.com"})
	got := rec.anomalies()
	if len(got) != 1 {
		t.Fatalf("anomalies = %d", len(got))
	}
	e := got[0]
	if e.Detail["anomaly"] != AnomalyDenials || e.Detail["count"] != "4" || e.Detail["threshold"] != "3" ||
		e.Labels["env"] != "prod" || e.Database != "prod-main" || e.Principal == nil {
		t.Errorf("anomaly = %+v", e)
	}
	// Silenced for the window.
	deny(agent)
	deny(agent)
	if len(rec.anomalies()) != 1 {
		t.Errorf("repeated within the window: %d", len(rec.anomalies()))
	}
	// Other requesters are independent.
	for range 3 {
		deny(&events.Principal{Kind: "human", Human: "hanako@example.com"})
	}
	if len(rec.anomalies()) != 1 {
		t.Errorf("other requester triggered: %d", len(rec.anomalies()))
	}
	// After the window: old denials expire, a new burst reports again.
	now = now.Add(11 * time.Minute)
	deny(agent)
	if len(rec.anomalies()) != 1 {
		t.Error("old denials still counted")
	}
	for range 3 {
		deny(agent)
	}
	if len(rec.anomalies()) != 2 {
		t.Errorf("anomalies after window = %d", len(rec.anomalies()))
	}
}

func TestAnomalyRows(t *testing.T) {
	now := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	rec := &recorder{}
	a := NewAnomaly(rec, AnomalyOptions{Config: testConfig(), Now: func() time.Time { return now }}) // 1000 rows per hour
	p := &events.Principal{Kind: "agent", Human: "taro@example.com", Agent: "claude-code"}

	a.ObserveRows(p, "prod-main", 600)
	now = now.Add(30 * time.Minute)
	a.ObserveRows(p, "prod-main", 400) // 1000: not more than the threshold
	if len(rec.anomalies()) != 0 {
		t.Fatal("anomaly at the threshold")
	}
	now = now.Add(31 * time.Minute) // the first 600 left the window
	a.ObserveRows(p, "prod-main", 500)
	if len(rec.anomalies()) != 0 {
		t.Fatal("expired rows counted")
	}
	a.ObserveRows(p, "prod-main", 200) // 400 + 500 + 200 = 1100
	got := rec.anomalies()
	if len(got) != 1 || got[0].Detail["anomaly"] != AnomalyRows || got[0].Detail["count"] != "1100" || got[0].Detail["threshold"] != "1000" {
		t.Fatalf("anomalies = %+v", got)
	}
	a.ObserveRows(p, "prod-main", 5000)
	if len(rec.anomalies()) != 1 {
		t.Error("repeated within the window")
	}
	a.ObserveRows(nil, "prod-main", 5000)
	a.ObserveRows(p, "prod-main", 0)
	// Cleanup drops idle requesters.
	now = now.Add(3 * time.Hour)
	a.ObserveRows(&events.Principal{Human: "other@example.com"}, "x", 1)
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.rows) != 1 || len(a.quietUntil) != 0 {
		t.Errorf("not cleaned up: rows=%d quiet=%d", len(a.rows), len(a.quietUntil))
	}
}

func TestConfigChanged(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	changed, prev, err := ConfigChanged(ctx, st, "v1")
	if err != nil || changed || prev != "" {
		t.Fatalf("first start = %v %q %v", changed, prev, err)
	}
	changed, _, err = ConfigChanged(ctx, st, "v1")
	if err != nil || changed {
		t.Fatalf("same version = %v %v", changed, err)
	}
	changed, prev, err = ConfigChanged(ctx, st, "v2")
	if err != nil || !changed || prev != "v1" {
		t.Fatalf("new version = %v %q %v", changed, prev, err)
	}
	e := ConfigChangedEvent(prev, "v2")
	if e.Type != events.ConfigChanged || e.Detail["previous_version"] != "v1" || e.Detail["version"] != "v2" {
		t.Errorf("event = %+v", e)
	}
	blocks := newMsgs("ja").blocks(e, renderOpts{})
	if s := blockJSON(t, blocks); !strings.Contains(s, "v1 → v2") || !strings.Contains(s, "設定が変わりました") {
		t.Errorf("blocks = %s", s)
	}
}
