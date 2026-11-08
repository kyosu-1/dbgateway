package gateway_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

const unitYAML = `
auth: { dev_login: true }
approvals: { enabled: true }
databases:
  - name: prod
    labels: { env: prod }
    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }
  - name: nowrite
    labels: { env: prod }
    primary: { host: localhost, read_user: r, sslmode: disable }
groups:
  - { name: dev, members: [taro@example.com] }
  - { name: sre, members: [hanako@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier] }
  - { group: sre, databases: "*", roles: [querier, writer, approver] }
unmask:
  - { user: hanako@example.com, databases: [prod] }
data_classes:
  - { columns: [public.users.email], class: masked }
  - { column_pattern: "public\\.users\\.(id|plan|name)", class: public }
approval_rules:
  - { name: default, when: "true", steps: [{ role: approver }] }
`

type recorder struct {
	mu  sync.Mutex
	evs []events.Event
}

func (r *recorder) Publish(_ context.Context, e events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, e)
}

func (r *recorder) all() []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]events.Event(nil), r.evs...)
}

func newUnitGateway(t *testing.T, yaml string) (*gateway.Gateway, *gatewaytest.Adapter, *recorder, *audit.Logger) {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	sink, err := audit.OpenFileSink(t.TempDir(), 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.New(sink)
	if err != nil {
		t.Fatal(err)
	}
	fa := gatewaytest.New()
	rec := &recorder{}
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": fa}, Audit: al, Events: rec})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close(); _ = al.Close() })
	return gw, fa, rec, al
}

var (
	taro   = &identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Groups: []string{"dev"}}
	hanako = &identity.Principal{Kind: identity.KindHuman, Human: "hanako@example.com", Groups: []string{"sre"}}
)

func run(gw *gateway.Gateway, p *identity.Principal, db, sql string) *gateway.ExecuteResponse {
	return gw.ExecuteSQL(context.Background(), p, gateway.ExecuteRequest{Database: db, SQL: sql, Reason: "unit test: verify the gateway"})
}

func TestWriteRoleAndWriteUser(t *testing.T) {
	gw, fa, rec, _ := newUnitGateway(t, unitYAML)
	r := run(gw, taro, "prod", "UPDATE users SET plan = 'pro' WHERE id = 1")
	if r.Status != gateway.StatusDenied || r.Rule != "role:writer" || r.Stage != "role" {
		t.Fatalf("writer role: %+v", r)
	}
	r = run(gw, hanako, "nowrite", "UPDATE users SET plan = 'pro' WHERE id = 1")
	if r.Status != gateway.StatusDenied || r.Rule != "builtin:no-write-user" {
		t.Fatalf("no write user: %+v", r)
	}
	// Without an approval service, approve decisions are denied (fail closed).
	r = run(gw, hanako, "prod", "UPDATE users SET plan = 'pro' WHERE id = 1")
	if r.Status != gateway.StatusDenied || r.Rule != "builtin:approval-unavailable" {
		t.Fatalf("no approval service: %+v", r)
	}
	if len(fa.Writes()) != 0 {
		t.Fatal("nothing must be written")
	}
	evs := rec.all()
	if len(evs) != 3 {
		t.Fatalf("query_denied events = %d", len(evs))
	}
	for _, e := range evs {
		if e.Type != events.QueryDenied || strings.Contains(e.SQL, "'pro'") || e.Detail["rule"] == "" {
			t.Errorf("event %+v", e)
		}
	}
	if evs[2].SQL == "" || len(evs[2].Tables) != 1 || evs[2].Labels["env"] != "prod" {
		t.Errorf("event details: %+v", evs[2])
	}
}

func TestListDatabasesCanWrite(t *testing.T) {
	gw, _, _, _ := newUnitGateway(t, unitYAML)
	for _, d := range gw.ListDatabases(hanako) {
		if want := d.Name == "prod"; d.CanWrite != want {
			t.Errorf("%s: can_write = %v", d.Name, d.CanWrite)
		}
	}
	for _, d := range gw.ListDatabases(taro) {
		if d.CanWrite {
			t.Errorf("taro can_write on %s", d.Name)
		}
	}
}

func TestUnmaskForHumansOnly(t *testing.T) {
	gw, fa, _, _ := newUnitGateway(t, unitYAML)
	fa.Set(func(a *gatewaytest.Adapter) {
		a.Result = analysis.Result{Columns: []analysis.ResultColumn{{Name: "id", Type: "int8"}, {Name: "email", Type: "text"}},
			Rows: [][]any{{int64(1), "user1@example.com"}}}
	})
	r := run(gw, taro, "prod", "SELECT id, email FROM users WHERE id = 1")
	if r.Status != gateway.StatusOK || r.Rows[0][1] == "user1@example.com" || !r.Columns[1].Masked {
		t.Fatalf("taro must see the email masked: %+v", r)
	}
	r = run(gw, hanako, "prod", "SELECT id, email FROM users WHERE id = 1")
	if r.Status != gateway.StatusOK || r.Rows[0][1] != "user1@example.com" || r.Columns[1].Masked {
		t.Fatalf("hanako has unmask: %+v", r)
	}
	agent := &identity.Principal{Kind: identity.KindAgent, Human: "hanako@example.com", Agent: "claude", Groups: []string{"sre"},
		Scopes: []string{identity.ScopeRead}}
	r = run(gw, agent, "prod", "SELECT id, email FROM users WHERE id = 1")
	if r.Status != gateway.StatusOK || r.Rows[0][1] == "user1@example.com" {
		t.Fatalf("unmask must never apply to agents: %+v", r)
	}
}

func TestExplainPolicyWithoutApprovals(t *testing.T) {
	gw, fa, _, _ := newUnitGateway(t, unitYAML)
	fa.Set(func(a *gatewaytest.Adapter) { a.EstimateRows = 3 })
	ctx := context.Background()
	resp, err := gw.ExplainPolicy(ctx, taro, gateway.ExplainRequest{Database: "prod", SQL: "SELECT id, email FROM users WHERE id = 1"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != config.ActionAllow || resp.Risk != config.RiskLow || len(resp.Output) != 2 || !resp.Output[1].Masked || resp.Output[0].Masked {
		t.Fatalf("read: %+v", resp)
	}
	resp, _ = gw.ExplainPolicy(ctx, hanako, gateway.ExplainRequest{Database: "prod", SQL: "UPDATE users SET plan = 'x' WHERE id = 1 RETURNING email"})
	// No approval service connected: reported as denied, like ExecuteSQL.
	if resp.Decision != config.ActionDeny || resp.ApprovalRule != "default" || resp.MaxAffectedRows != 6 || resp.Output[0].Masked {
		t.Fatalf("write: %+v", resp)
	}
	resp, _ = gw.ExplainPolicy(ctx, hanako, gateway.ExplainRequest{Database: "prod", SQL: "DROP TABLE users"})
	if resp.Decision != config.ActionDeny || resp.Rule != "default-deny-ddl" || resp.Hint == "" {
		t.Fatalf("ddl: %+v", resp)
	}
	if _, err := gw.ExplainPolicy(ctx, taro, gateway.ExplainRequest{Database: "nope", SQL: "SELECT 1"}); err != gateway.ErrNoAccess {
		t.Fatalf("unknown database: %v", err)
	}
	if len(fa.Execs()) != 0 {
		t.Fatal("explain must not execute")
	}
}

func TestApprovalsDisabledDeniesWrites(t *testing.T) {
	gw, _, _, _ := newUnitGateway(t, strings.Replace(unitYAML, "approvals: { enabled: true }", "", 1))
	r := run(gw, hanako, "prod", "UPDATE users SET plan = 'pro' WHERE id = 1")
	if r.Status != gateway.StatusDenied || r.Rule != "no-matching-rule" && r.Rule != "builtin:approval-not-enabled" {
		t.Fatalf("got %+v", r)
	}
}
