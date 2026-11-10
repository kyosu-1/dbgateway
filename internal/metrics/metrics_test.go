package metrics_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/metrics"
	"github.com/kyosu-1/dbgateway/internal/notify"
)

const testYAML = `
auth: { dev_login: true }
server: { metrics_listen: 127.0.0.1:9090 }
databases:
  - name: prod
    primary: { host: localhost, read_user: r, sslmode: disable }
groups:
  - { name: dev, members: [taro@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier] }
data_classes:
  - { column_pattern: "public\\.users\\.(id|plan|name)", class: public }
`

func newMetrics(t *testing.T) (*metrics.Metrics, *config.Config) {
	t.Helper()
	cfg, err := config.Parse([]byte(testYAML))
	if err != nil {
		t.Fatal(err)
	}
	return metrics.New(metrics.Options{Config: cfg, Version: "v1.2.3"}), cfg
}

// scrape fetches /metrics in the Prometheus text format.
func scrape(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %q", ct)
	}
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

// expect checks that each line (a series and its value) is in the output.
func expect(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(l) + `$`).MatchString(out) {
			t.Errorf("missing %q", l)
		}
	}
}

func TestRuntimeAndBuildInfo(t *testing.T) {
	m, cfg := newMetrics(t)
	out := scrape(t, m)
	expect(t, out,
		`dbgateway_build_info{config_version="`+cfg.Version+`",version="v1.2.3"} 1`,
		`dbgateway_audit_write_failures_total 0`,
	)
	for _, name := range []string{"go_goroutines", "go_memstats_alloc_bytes", "process_start_time_seconds"} {
		if !strings.Contains(out, "\n"+name+" ") {
			t.Errorf("missing %s", name)
		}
	}
}

func TestRequestMetricsFromGateway(t *testing.T) {
	m, cfg := newMetrics(t)
	sink, err := audit.OpenFileSink(t.TempDir(), 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.New(sink)
	if err != nil {
		t.Fatal(err)
	}
	al.SetErrorObserver(m.AuditWriteFailed)
	fa := gatewaytest.New()
	fa.Set(func(a *gatewaytest.Adapter) {
		a.Result = analysis.Result{Columns: []analysis.ResultColumn{{Name: "id", Type: "int8"}},
			Rows: [][]any{{int64(1)}, {int64(2)}}}
	})
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": fa}, Audit: al,
		Events: m, Observer: m})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close(); _ = al.Close() })
	m.WatchPools(gw.PoolStats)

	human := &identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Groups: []string{"dev"}}
	agent := &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "secret-agent-name",
		Groups: []string{"dev"}, Scopes: []string{identity.ScopeRead}}
	ctx := context.Background()
	exec := func(p *identity.Principal, db, sql string) *gateway.ExecuteResponse {
		return gw.ExecuteSQL(ctx, p, gateway.ExecuteRequest{Database: db, SQL: sql, Reason: "metrics test: count requests"})
	}
	var rids []string
	for _, r := range []*gateway.ExecuteResponse{
		exec(agent, "prod", "SELECT id FROM users WHERE name = 'hanako'"),
		exec(agent, "prod", "SELECT id FROM users"),
		exec(human, "prod", "UPDATE users SET plan = 'pro' WHERE id = 1"),
		exec(human, "attacker-chosen-name", "SELECT 1"),
	} {
		rids = append(rids, r.RequestID)
	}
	_, _ = gw.SearchObjects(ctx, human, gateway.SearchRequest{Database: "prod"})

	out := scrape(t, m)
	expect(t, out,
		`dbgateway_requests_total{database="prod",decision="allow",event="query",kind="agent",stage="policy"} 2`,
		`dbgateway_requests_total{database="prod",decision="deny",event="query",kind="human",stage="policy"} 1`,
		`dbgateway_requests_total{database="",decision="deny",event="query",kind="human",stage="role"} 1`,
		`dbgateway_requests_total{database="prod",decision="allow",event="search",kind="human",stage=""} 1`,
		`dbgateway_request_duration_seconds_count{database="prod",decision="allow",event="query"} 2`,
		`dbgateway_rows_returned_bucket{database="prod",kind="agent",le="1"} 0`,
		`dbgateway_rows_returned_bucket{database="prod",kind="agent",le="10"} 2`,
		`dbgateway_rows_returned_sum{database="prod",kind="agent"} 4`,
		`dbgateway_rows_returned_count{database="prod",kind="agent"} 2`,
		`dbgateway_catalog_loads_total{database="prod",result="ok"} 1`,
		`dbgateway_catalog_load_duration_seconds_count{database="prod"} 1`,
		`dbgateway_events_total{type="query_denied"} 2`,
		`dbgateway_audit_write_failures_total 0`,
	)
	// The fake adapter has no pools; nothing is exported for it.
	if strings.Contains(out, "dbgateway_db_pool_connections{") {
		t.Error("pool metrics for an adapter without pools")
	}
	// No identities, SQL, tables, values or request IDs in labels.
	forbidden := append([]string{"taro@example.com", "secret-agent-name", "attacker-chosen-name", "users", "hanako", "SELECT", "UPDATE"}, rids...)
	for _, s := range forbidden {
		if strings.Contains(out, s) {
			t.Errorf("output contains %q", s)
		}
	}
}

func TestAuditWriteFailures(t *testing.T) {
	m, _ := newMetrics(t)
	m.AuditWriteFailed(errors.New("disk full"))
	m.AuditWriteFailed(errors.New("disk full"))
	expect(t, scrape(t, m), `dbgateway_audit_write_failures_total 2`)
}

func TestApprovalTransitions(t *testing.T) {
	m, _ := newMetrics(t)
	ctx := context.Background()
	p := &events.Principal{Kind: "agent", Human: "taro@example.com", Agent: "claude"}
	for _, e := range []events.Event{
		{Type: events.ApprovalRequested, Database: "prod", Status: "pending", Principal: p, SQL: "UPDATE users SET plan = $1"},
		{Type: events.ApprovalDecided, Database: "prod", Status: "pending", Actor: "hanako@example.com"},
		{Type: events.ApprovalDecided, Database: "prod", Status: "approved"},
		{Type: events.ExecutionFinished, Database: "prod", Status: "succeeded"},
		{Type: events.ApprovalRequested, Database: "prod", Status: "pending"},
		{Type: events.ApprovalDecided, Database: "prod", Status: "rejected"},
		{Type: events.ApprovalDecided, Database: "prod", Status: "expired"},
		{Type: events.ApprovalDecided, Database: "prod", Status: "canceled"},
		{Type: events.ExecutionFinished, Database: "prod", Status: "failed"},
		{Type: events.ApprovalDecided, Database: "gone", Status: "something-new"},
		{Type: events.BreakGlassUsed, Database: "prod", Actor: "hanako@example.com"},
		{Type: events.ConfigChanged},
	} {
		m.Publish(ctx, e)
	}
	out := scrape(t, m)
	expect(t, out,
		`dbgateway_approval_transitions_total{database="prod",status="submitted"} 2`,
		`dbgateway_approval_transitions_total{database="prod",status="step_approved"} 1`,
		`dbgateway_approval_transitions_total{database="prod",status="approved"} 1`,
		`dbgateway_approval_transitions_total{database="prod",status="rejected"} 1`,
		`dbgateway_approval_transitions_total{database="prod",status="expired"} 1`,
		`dbgateway_approval_transitions_total{database="prod",status="canceled"} 1`,
		`dbgateway_approval_transitions_total{database="prod",status="succeeded"} 1`,
		`dbgateway_approval_transitions_total{database="prod",status="failed"} 1`,
		`dbgateway_approval_transitions_total{database="",status="other"} 1`,
		`dbgateway_events_total{type="approval_requested"} 2`,
		`dbgateway_events_total{type="approval_decided"} 6`,
		`dbgateway_events_total{type="execution_finished"} 2`,
		`dbgateway_events_total{type="break_glass_used"} 1`,
		`dbgateway_events_total{type="config_changed"} 1`,
	)
	for _, s := range []string{"taro@example.com", "hanako@example.com", "claude", "UPDATE", "gone"} {
		if strings.Contains(out, s) {
			t.Errorf("output contains %q", s)
		}
	}
}

func TestScrapeTimeCollectors(t *testing.T) {
	m, _ := newMetrics(t)
	m.WatchPools(func() []gateway.PoolStats {
		return []gateway.PoolStats{
			{Database: "prod", PoolStats: analysis.PoolStats{Pool: "read", Open: 5, InUse: 2, Idle: 3, Max: 10, WaitCount: 7, WaitDuration: 1500 * time.Millisecond}},
			{Database: "prod", PoolStats: analysis.PoolStats{Pool: "write", Open: 1, InUse: 1, Max: 4}},
		}
	})
	m.WatchNotifications(func() notify.Stats {
		return notify.Stats{Published: 10, Dropped: 1, Delivered: 8, Failed: 2, Skipped: 3}
	})
	m.WatchAuditForwarders(func() []audit.ForwarderStats {
		return []audit.ForwarderStats{{Name: "otlp", Sent: 100, Dropped: 4, Failed: 5}}
	})
	expect(t, scrape(t, m),
		`dbgateway_db_pool_connections{database="prod",pool="read",state="in_use"} 2`,
		`dbgateway_db_pool_connections{database="prod",pool="read",state="idle"} 3`,
		`dbgateway_db_pool_max_connections{database="prod",pool="read"} 10`,
		`dbgateway_db_pool_waits_total{database="prod",pool="read"} 7`,
		`dbgateway_db_pool_wait_seconds_total{database="prod",pool="read"} 1.5`,
		`dbgateway_db_pool_connections{database="prod",pool="write",state="in_use"} 1`,
		`dbgateway_notification_events_total{result="published"} 10`,
		`dbgateway_notification_events_total{result="dropped"} 1`,
		`dbgateway_notification_deliveries_total{result="delivered"} 8`,
		`dbgateway_notification_deliveries_total{result="failed"} 2`,
		`dbgateway_notification_deliveries_total{result="skipped"} 3`,
		`dbgateway_audit_forwarded_records_total{forwarder="otlp",result="sent"} 100`,
		`dbgateway_audit_forwarded_records_total{forwarder="otlp",result="dropped"} 4`,
		`dbgateway_audit_forwarded_records_total{forwarder="otlp",result="failed"} 5`,
	)
}
