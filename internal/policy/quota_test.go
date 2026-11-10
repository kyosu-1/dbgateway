package policy

import (
	"strings"
	"testing"
)

func quotaNames(e *Engine, in Input) []string {
	var out []string
	for _, q := range e.Quotas(in) {
		out = append(out, q.Name)
	}
	return out
}

func TestQuotaSelection(t *testing.T) {
	cfg := mustConfig(t, `
quotas:
  - name: everyone
    queries_per_hour: 1000
  - name: agents-prod
    when: principal.kind == "agent" && database.labels.env == "prod"
    rows_per_hour: 100
  - name: data-team
    when: '"data-team" in principal.groups && database.name == "staging"'
    rows_per_day: 10
  - name: orders
    when: stmt.tables.exists(t, t.fqn == "public.orders")
    rows_per_hour: 5
  - name: tier
    when: database.labels.tier == "gold"
    rows_per_hour: 5
`)
	e, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	agentProd := Input{Principal: Principal{Kind: "agent", Human: "a@example.com"},
		Database: Database{Name: "prod-main", Labels: map[string]string{"env": "prod", "tier": "silver"}}, Stmt: read()}
	if got := strings.Join(quotaNames(e, agentProd), ","); got != "everyone,agents-prod" {
		t.Errorf("agent on prod: %s", got)
	}
	human := Input{Principal: Principal{Kind: "human", Groups: []string{"data-team"}},
		Database: Database{Name: "staging", Labels: map[string]string{"env": "staging", "tier": "silver"}},
		Stmt:     Stmt{Kind: "select", Tables: []Table{{Schema: "public", Name: "orders", FQN: "public.orders", Read: true}}}}
	if got := strings.Join(quotaNames(e, human), ","); got != "everyone,data-team,orders" {
		t.Errorf("human on staging: %s", got)
	}
	// A condition that fails to evaluate (missing label) matches; CEL's
	// && still short-circuits on a false operand.
	noLabels := Input{Principal: Principal{Kind: "agent"}, Database: Database{Name: "x", Labels: map[string]string{}}, Stmt: read()}
	if got := strings.Join(quotaNames(e, noLabels), ","); got != "everyone,agents-prod,tier" {
		t.Errorf("missing labels: %s", got)
	}
}

func TestQuotaCompileErrors(t *testing.T) {
	for _, tt := range []struct{ when, want string }{
		{`principal.kind`, "boolean"},
		{`estimate.rows > 10`, "undeclared reference to 'estimate'"},
		{`risk == "high"`, "undeclared reference to 'risk'"},
		{`principal.nope == "x"`, "nope"},
	} {
		cfg := mustConfig(t, "quotas:\n  - { name: q, when: '"+tt.when+"', rows_per_hour: 1 }\n")
		if _, err := Compile(cfg); err == nil || !strings.Contains(err.Error(), "quotas[0] (q).when") || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.when, err, tt.want)
		}
	}
}
