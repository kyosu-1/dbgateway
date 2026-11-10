package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type quotaEnv struct {
	gw    *gateway.Gateway
	fa    *gatewaytest.Adapter
	rec   *recorder
	clock *clock
	audit *bytes.Buffer
}

// auditEntries returns the audit log entries written so far.
func (e *quotaEnv) auditEntries(t *testing.T) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	for line := range strings.SplitSeq(strings.TrimSpace(e.audit.String()), "\n") {
		var en audit.Entry
		if err := json.Unmarshal([]byte(line), &en); err != nil {
			t.Fatal(err)
		}
		out = append(out, en)
	}
	return out
}

func newQuotaGateway(t *testing.T, yaml string, qs store.QuotaStore) *quotaEnv {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	al, err := audit.New(audit.NewStdoutSink(buf))
	if err != nil {
		t.Fatal(err)
	}
	if qs == nil {
		st, err := store.OpenSQLite(context.Background(), ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		qs = st
	}
	e := &quotaEnv{fa: gatewaytest.New(), rec: &recorder{}, clock: &clock{t: time.Date(2026, 11, 11, 10, 0, 30, 0, time.UTC)}, audit: buf}
	e.fa.Set(func(a *gatewaytest.Adapter) {
		a.Result = analysis.Result{Columns: []analysis.ResultColumn{{Name: "id", Type: "int8"}},
			Rows: [][]any{{int64(1)}, {int64(2)}}}
	})
	e.gw, err = gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": e.fa}, Audit: al,
		Events: e.rec, QuotaStore: qs, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.gw.Close(); _ = al.Close() })
	return e
}

const quotaYAML = unitYAML + `
quotas:
  - name: agent-rows
    when: principal.kind == "agent" && database.labels.env == "prod"
    rows_per_hour: 5
    hint: Ask the data platform team for a higher quota.
`

func taroAgent(name string) *identity.Principal {
	return &identity.Principal{Kind: identity.KindAgent, Human: "Taro@example.com", Agent: name, Groups: []string{"dev"},
		Scopes: []string{identity.ScopeRead}}
}

const quotaSQL = "SELECT id FROM users WHERE id > 0"

func TestQuotaRowsCountedAndDenied(t *testing.T) {
	e := newQuotaGateway(t, quotaYAML, nil)
	for i := range 2 {
		if r := run(e.gw, taroAgent("claude"), "prod", quotaSQL); r.Status != gateway.StatusOK || r.RowCount != 2 || r.Truncated {
			t.Fatalf("read %d: %+v", i, r)
		}
	}
	// 4 of 5 rows used: the next read is cut to the one row left.
	r := run(e.gw, taroAgent("claude"), "prod", quotaSQL)
	if r.Status != gateway.StatusOK || r.RowCount != 1 || !r.Truncated || !strings.Contains(r.Hint, `quota "agent-rows"`) {
		t.Fatalf("capped read: %+v", r)
	}
	if got := e.fa.Execs()[2].Opts.MaxRows; got != 1 {
		t.Fatalf("max rows = %d", got)
	}

	// Used up: denied before it runs, for every agent of the same person.
	for _, name := range []string{"claude", "another-agent"} {
		r = run(e.gw, taroAgent(name), "prod", quotaSQL)
		if r.Status != gateway.StatusDenied || r.Stage != "policy" || r.Rule != "quota:agent-rows" ||
			!strings.Contains(r.Reason, "5 of 5 rows in the last hour (rows_per_hour)") ||
			!strings.Contains(r.Hint, "2026-11-11T11:00:00Z (in 1h00m)") || !strings.Contains(r.Hint, "data platform team") {
			t.Fatalf("%s: %+v", name, r)
		}
	}
	if n := len(e.fa.Execs()); n != 3 {
		t.Fatalf("executions = %d", n)
	}
	evs := e.rec.all()
	if len(evs) != 2 || evs[0].Type != events.QueryDenied || evs[0].Detail["rule"] != "quota:agent-rows" || evs[0].Principal.Human != "Taro@example.com" {
		t.Fatalf("events = %+v", evs)
	}
	last := e.auditEntries(t)[4]
	if last.Decision != config.ActionDeny || last.Rule != "quota:agent-rows" || last.Extra["quota_limit"] != "rows_per_hour" {
		t.Fatalf("audit = %+v", last)
	}

	// The quota does not match the person's own reads.
	if r := run(e.gw, taro, "prod", quotaSQL); r.Status != gateway.StatusOK || r.RowCount != 2 {
		t.Fatalf("human read: %+v", r)
	}
	// Nor another person's agents.
	hanakoAgent := &identity.Principal{Kind: identity.KindAgent, Human: "hanako@example.com", Agent: "claude", Groups: []string{"sre"},
		Scopes: []string{identity.ScopeRead}}
	if r := run(e.gw, hanakoAgent, "prod", quotaSQL); r.Status != gateway.StatusOK {
		t.Fatalf("hanako's agent: %+v", r)
	}

	// The window slides by minutes: 59 minutes later the first reads are
	// still in it, an hour later they are not.
	e.clock.Advance(59 * time.Minute)
	if r := run(e.gw, taroAgent("claude"), "prod", quotaSQL); r.Status != gateway.StatusDenied {
		t.Fatalf("after 59m: %+v", r)
	}
	e.clock.Advance(time.Minute)
	if r := run(e.gw, taroAgent("claude"), "prod", quotaSQL); r.Status != gateway.StatusOK || r.RowCount != 2 {
		t.Fatalf("after 1h: %+v", r)
	}
}

func TestQuotaQueriesPerMinute(t *testing.T) {
	e := newQuotaGateway(t, unitYAML+`
quotas:
  - { name: burst, queries_per_minute: 2 }
  - { name: hourly, queries_per_hour: 4 }
`, nil)
	for range 2 {
		if r := run(e.gw, taro, "prod", quotaSQL); r.Status != gateway.StatusOK {
			t.Fatalf("read: %+v", r)
		}
	}
	r := run(e.gw, taro, "prod", quotaSQL)
	if r.Status != gateway.StatusDenied || r.Rule != "quota:burst" || !strings.Contains(r.Reason, "2 of 2 queries in the last minute") ||
		!strings.Contains(r.Hint, "10:01:00Z (in 30s)") {
		t.Fatalf("burst: %+v", r)
	}
	// Denied reads do not count.
	e.clock.Advance(30 * time.Second)
	for range 2 {
		if r := run(e.gw, taro, "prod", quotaSQL); r.Status != gateway.StatusOK {
			t.Fatalf("next minute: %+v", r)
		}
	}
	// Both limits used up: the one that frees up last is reported.
	r = run(e.gw, taro, "prod", quotaSQL)
	if r.Status != gateway.StatusDenied || r.Rule != "quota:hourly" || !strings.Contains(r.Hint, "11:00:00Z") {
		t.Fatalf("hourly: %+v", r)
	}
	// explain_policy reports the quota that would deny.
	ex, err := e.gw.ExplainPolicy(context.Background(), taro, gateway.ExplainRequest{Database: "prod", SQL: quotaSQL})
	if err != nil || ex.Decision != config.ActionDeny || ex.Rule != "quota:hourly" || ex.Stage != "policy" || ex.Hint == "" {
		t.Fatalf("explain = %+v, %v", ex, err)
	}
	// Writes are not subject to quotas.
	r = run(e.gw, hanako, "prod", "UPDATE users SET plan = 'pro' WHERE id = 1")
	if r.Rule == "quota:hourly" || r.Rule == "quota:burst" {
		t.Fatalf("write: %+v", r)
	}
}

func TestQuotaShadowMode(t *testing.T) {
	e := newQuotaGateway(t, "server: { mode: shadow }\n"+quotaYAML, nil)
	for range 3 {
		if r := run(e.gw, taroAgent("claude"), "prod", quotaSQL); r.Status != gateway.StatusOK || r.RowCount != 2 || r.Truncated {
			t.Fatalf("read: %+v", r)
		}
	}
	// Used up (6 of 5): allowed, and the would-be denial is recorded.
	if r := run(e.gw, taroAgent("claude"), "prod", quotaSQL); r.Status != gateway.StatusOK {
		t.Fatalf("shadow: %+v", r)
	}
	last := e.auditEntries(t)[3]
	if last.Decision != config.ActionAllow || last.ShadowDeniedBy != "quota:agent-rows" {
		t.Fatalf("audit = %+v", last)
	}
	ex, err := e.gw.ExplainPolicy(context.Background(), taroAgent("claude"), gateway.ExplainRequest{Database: "prod", SQL: quotaSQL})
	if err != nil || ex.Decision != config.ActionAllow || ex.ShadowDeniedBy != "quota:agent-rows" {
		t.Fatalf("explain = %+v, %v", ex, err)
	}
	if len(e.rec.all()) != 0 {
		t.Fatal("shadow mode must not publish denials")
	}
}

// failingQuotaStore fails reads or writes of quota usage.
type failingQuotaStore struct {
	store.QuotaStore
	failList, failAdd bool
}

var errStoreDown = errors.New("store down")

func (f *failingQuotaStore) ListQuotaUsage(ctx context.Context, r string, q []string, since time.Time) ([]store.QuotaUsage, error) {
	if f.failList {
		return nil, errStoreDown
	}
	return f.QuotaStore.ListQuotaUsage(ctx, r, q, since)
}

func (f *failingQuotaStore) AddQuotaUsage(ctx context.Context, u []store.QuotaUsage) error {
	if f.failAdd {
		return errStoreDown
	}
	return f.QuotaStore.AddQuotaUsage(ctx, u)
}

func TestQuotaStoreErrorsFailClosed(t *testing.T) {
	st, err := store.OpenSQLite(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fs := &failingQuotaStore{QuotaStore: st, failList: true}
	e := newQuotaGateway(t, quotaYAML, fs)

	// Usage cannot be read: the read does not run.
	r := run(e.gw, taroAgent("claude"), "prod", quotaSQL)
	if r.Status != gateway.StatusError || !strings.Contains(r.Reason, "quota usage could not be checked") || len(e.fa.Execs()) != 0 {
		t.Fatalf("list failure: %+v", r)
	}
	if _, err := e.gw.ExplainPolicy(context.Background(), taroAgent("claude"), gateway.ExplainRequest{Database: "prod", SQL: quotaSQL}); err == nil {
		t.Fatal("explain must fail too")
	}
	// Usage cannot be recorded: the result is withheld.
	fs.failList, fs.failAdd = false, true
	r = run(e.gw, taroAgent("claude"), "prod", quotaSQL)
	if r.Status != gateway.StatusError || r.Rows != nil || !strings.Contains(r.Reason, "result is withheld") || len(e.fa.Execs()) != 1 {
		t.Fatalf("add failure: %+v", r)
	}
	// Reads no quota applies to never touch the store.
	if r := run(e.gw, taro, "prod", quotaSQL); r.Status != gateway.StatusOK {
		t.Fatalf("no quota: %+v", r)
	}
}

func TestQuotasNeedAStore(t *testing.T) {
	cfg, err := config.Parse([]byte(quotaYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": gatewaytest.New()}}); err == nil {
		t.Fatal("quotas without a store must be refused")
	}
}
