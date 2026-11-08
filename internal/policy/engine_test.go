package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

const baseYAML = `
auth: { dev_login: true }
databases:
  - name: prod-main
    labels: { env: prod }
    primary: { host: localhost, read_user: r, sslmode: disable }
  - name: staging
    labels: { env: staging }
    primary: { host: localhost, read_user: r, sslmode: disable }
groups:
  - { name: data-team, oidc_group: data-team }
  - { name: sre, members: [hanako@example.com] }
role_bindings:
  - group: data-team
    databases: { labels: { env: prod } }
    roles: [querier]
  - group: sre
    databases: "*"
    roles: [viewer]
`

func mustConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(baseYAML + extra))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func read() Stmt { return Stmt{Kind: "select"} }

func TestAllowRuleMustExcludeWrites(t *testing.T) {
	for _, when := range []string{`true`, `stmt.kind == "select"`, `!stmt.is_write`, `principal.kind == "human"`} {
		_, err := config.Parse([]byte(baseYAML + "policies:\n  - { name: bad, when: '" + when + "', action: allow }\n"))
		if err != nil {
			t.Fatalf("config parse: %v", err)
		}
		cfg := mustConfig(t, "policies:\n  - { name: bad, when: '"+when+"', action: allow }\n")
		if _, err := Compile(cfg); err == nil || !strings.Contains(err.Error(), "could match") {
			t.Errorf("when %q: expected allow-write error, got %v", when, err)
		}
	}
	for _, when := range []string{
		`stmt.kind == "select" && !stmt.is_write`,
		`stmt.kind == "select" && !stmt.is_write && database.labels.env == "prod"`,
		`!stmt.is_write && stmt.kind == "select" && principal.kind == "agent"`,
	} {
		cfg := mustConfig(t, "policies:\n  - { name: ok, when: '"+when+"', action: allow }\n")
		if _, err := Compile(cfg); err != nil {
			t.Errorf("when %q: unexpected error %v", when, err)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	cfg := mustConfig(t, "policies:\n  - { name: typo, when: 'stmt.kindd == \"select\"', action: deny }\n")
	if _, err := Compile(cfg); err == nil || !strings.Contains(err.Error(), "kindd") {
		t.Errorf("expected undefined field error, got %v", err)
	}
	cfg = mustConfig(t, "policies:\n  - { name: notbool, when: 'stmt.kind', action: deny }\n")
	if _, err := Compile(cfg); err == nil {
		t.Errorf("expected non-bool error")
	}
}

func TestEvaluate(t *testing.T) {
	cfg := mustConfig(t, `
policies:
  - name: deny-ddl
    when: stmt.kind == "ddl"
    action: deny
  - name: deny-unbounded-writes
    when: stmt.is_write && !stmt.has_where
    action: deny
  - name: agents-never-see-no-ai
    when: principal.kind == "agent" && columns.exists(c, c.class == "no_ai")
    action: deny
    message: "AIに送らない列です"
  - name: big-reads
    when: database.labels.env == "staging" && estimate.rows > 1000000
    action: deny
  - name: reads
    when: stmt.kind == "select" && !stmt.is_write
    action: allow
    require: { replica: true, max_rows: 100 }
  - name: writes
    when: stmt.is_write
    action: approve
`)
	e, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !e.NeedsEstimate() {
		t.Error("NeedsEstimate should be true")
	}
	agent := Principal{Kind: "agent", Human: "taro@example.com"}
	human := Principal{Kind: "human", Human: "taro@example.com"}
	prod := Database{Name: "prod-main", Labels: map[string]string{"env": "prod"}}
	tests := []struct {
		name   string
		in     Input
		action string
		rule   string
	}{
		{"read allowed", Input{Principal: agent, Database: prod, Stmt: read()}, "allow", "reads"},
		{"ddl denied", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "ddl"}}, "deny", "deny-ddl"},
		{"unbounded write", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "delete", IsWrite: true}}, "deny", "deny-unbounded-writes"},
		{"write needs approval (phase 1 denies)", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "update", IsWrite: true, HasWhere: true}}, "deny", RuleWriteNotEnabled},
		{"writable cte", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "select", IsWrite: true, HasWhere: true}}, "deny", RuleWriteNotEnabled},
		{"no_ai for agent", Input{Principal: agent, Database: prod, Stmt: read(), Columns: []Column{{Name: "public.t.body", Class: "no_ai", Usage: []string{"output"}}}}, "deny", "agents-never-see-no-ai"},
		{"no_ai for human", Input{Principal: human, Database: prod, Stmt: read(), Columns: []Column{{Name: "public.t.body", Class: "no_ai", Usage: []string{"output"}}}}, "allow", "reads"},
		{"masked in where for agent", Input{Principal: agent, Database: prod, Stmt: read(), Columns: []Column{{Name: "public.users.email", Class: "masked", Usage: []string{"filter"}}}}, "deny", RuleSensitivePredicate},
		{"masked in output for agent", Input{Principal: agent, Database: prod, Stmt: read(), Columns: []Column{{Name: "public.users.email", Class: "masked", Usage: []string{"output"}}}}, "allow", "reads"},
		{"masked in where for human", Input{Principal: human, Database: prod, Stmt: read(), Columns: []Column{{Name: "public.users.email", Class: "masked", Usage: []string{"filter"}}}}, "allow", "reads"},
		{"unknown never allowed", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "select", Unknown: true}}, "deny", RuleUnknown},
		{"estimate", Input{Principal: human, Database: Database{Name: "staging", Labels: map[string]string{"env": "staging"}}, Stmt: read(), Estimate: Estimate{Rows: 2e6}}, "deny", "big-reads"},
		// prod has no "staging"; db without env label must not break evaluation
		{"missing label", Input{Principal: human, Database: Database{Name: "x", Labels: map[string]string{}}, Stmt: read()}, "allow", "reads"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := e.Evaluate(tt.in)
			if d.Action != tt.action || d.Rule != tt.rule {
				t.Errorf("got %s/%s (%s), want %s/%s", d.Action, d.Rule, d.Message, tt.action, tt.rule)
			}
			if d.Action == "deny" && (d.Message == "" || d.Hint == "") {
				t.Errorf("deny without message/hint: %+v", d)
			}
		})
	}
	d := e.Evaluate(Input{Principal: agent, Database: prod, Stmt: read()})
	if !d.Require.Replica || d.Require.MaxRows != 100 {
		t.Errorf("require not propagated: %+v", d.Require)
	}
}

func TestDefaultPoliciesAndShadow(t *testing.T) {
	cfg := mustConfig(t, "")
	e, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := Principal{Kind: "human"}
	if d := e.Evaluate(Input{Principal: p, Stmt: read()}); d.Action != "allow" {
		t.Errorf("default read: %+v", d)
	}
	if d := e.Evaluate(Input{Principal: p, Stmt: Stmt{Kind: "update", IsWrite: true, HasWhere: true}}); d.Action != "deny" {
		t.Errorf("default write: %+v", d)
	}

	shadow := mustConfig(t, `
server: { mode: shadow }
policies:
  - { name: deny-users, when: 'stmt.tables.exists(t, t.name == "users")', action: deny }
  - { name: reads, when: 'stmt.kind == "select" && !stmt.is_write', action: allow }
`)
	e, err = Compile(shadow)
	if err != nil {
		t.Fatal(err)
	}
	users := Stmt{Kind: "select", Tables: []Table{{Schema: "public", Name: "users"}}}
	d := e.Evaluate(Input{Principal: p, Stmt: users})
	if d.Action != "allow" || d.ShadowDeniedBy != "deny-users" {
		t.Errorf("shadow read: %+v", d)
	}
	// Shadow never relaxes writes or built-in guards.
	if d := e.Evaluate(Input{Principal: p, Stmt: Stmt{Kind: "delete", IsWrite: true, HasWhere: true}}); d.Action != "deny" {
		t.Errorf("shadow write: %+v", d)
	}
	agent := Principal{Kind: "agent"}
	cols := []Column{{Name: "public.users.email", Class: "masked", Usage: []string{"filter"}}}
	if d := e.Evaluate(Input{Principal: agent, Stmt: users, Columns: cols}); d.Action != "deny" || d.Rule != RuleSensitivePredicate {
		t.Errorf("shadow guard: %+v", d)
	}
}

func TestRBAC(t *testing.T) {
	cfg := mustConfig(t, `
  - group: data-team
    databases: [staging]
    roles: [querier]
    expires_at: 2000-01-01T00:00:00Z
`)
	// The extra binding above is appended to role_bindings (already expired).
	r := NewRBAC(cfg)
	prod, staging := cfg.Database("prod-main"), cfg.Database("staging")

	groups := r.ResolveGroups("taro@example.com", []string{"data-team"})
	if len(groups) != 1 || groups[0] != "data-team" {
		t.Fatalf("groups = %v", groups)
	}
	if g := r.ResolveGroups("HANAKO@example.com", nil); len(g) != 1 || g[0] != "sre" {
		t.Errorf("static members = %v", g)
	}

	human := &identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Groups: groups}
	if !r.Has(human, prod, identity.RoleQuerier) || !r.Has(human, prod, identity.RoleViewer) {
		t.Error("querier on prod expected (and viewer implied)")
	}
	if r.Has(human, staging, identity.RoleQuerier) {
		t.Error("expired binding must not apply")
	}

	agent := &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Groups: groups,
		Scopes: []string{identity.ScopeRead}, Databases: []string{"staging"}}
	if r.Has(agent, prod, identity.RoleQuerier) {
		t.Error("agent restricted to staging must not reach prod")
	}
	agent.Databases = nil
	if !r.Has(agent, prod, identity.RoleQuerier) {
		t.Error("agent should inherit querier")
	}
	agent.Scopes = nil
	if r.Has(agent, prod, identity.RoleQuerier) {
		t.Error("agent without scope must not query")
	}
	r.now = func() time.Time { return time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) }
	if !r.Has(human, staging, identity.RoleQuerier) {
		t.Error("binding valid before expiry")
	}
}
