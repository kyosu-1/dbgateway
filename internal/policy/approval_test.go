package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

const approvalsYAML = `
approvals: { enabled: true }
risk:
  high:
    - stmt.is_write && estimate.rows > 1000
    - stmt.is_write && columns.exists(c, c.class != "public")
  medium:
    - stmt.is_write
approval_rules:
  - name: prod-high-risk
    when: database.labels.env == "prod" && risk == "high"
    steps: [{ role: approver }, { group: sre }]
  - name: prod-default
    when: database.labels.env == "prod"
    steps: [{ role: approver }]
policies:
  - { name: deny-ddl, when: 'stmt.kind == "ddl"', action: deny }
  - { name: deny-unbounded-writes, when: 'stmt.is_write && !stmt.has_where', action: deny }
  - { name: reads, when: 'stmt.kind == "select" && !stmt.is_write', action: allow }
  - { name: approve-big-reads, when: 'stmt.kind == "select" && risk == "high"', action: approve }
  - { name: writes, when: stmt.is_write, action: approve, require: { step_up: true, reason: true } }
`

func update() Stmt { return Stmt{Kind: "update", IsWrite: true, HasWhere: true} }

func TestRiskAndApprovalRules(t *testing.T) {
	cfg := mustConfig(t, approvalsYAML)
	e, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !e.NeedsEstimate() {
		t.Error("risk conditions reference estimate")
	}
	human := Principal{Kind: "human", Human: "taro@example.com"}
	agent := Principal{Kind: "agent", Human: "taro@example.com"}
	prod := Database{Name: "prod-main", Labels: map[string]string{"env": "prod"}}
	staging := Database{Name: "staging", Labels: map[string]string{"env": "staging"}}
	nolabel := Database{Name: "x", Labels: map[string]string{}}
	masked := []Column{{Name: "public.users.email", Class: "masked", Usage: []string{"write"}}}
	maskedFilter := []Column{{Name: "public.users.email", Class: "masked", Usage: []string{"filter"}}}

	tests := []struct {
		name         string
		in           Input
		action, rule string
		risk         string
		approvalRule string
	}{
		{"read is low risk", Input{Principal: human, Database: prod, Stmt: read()}, "allow", "reads", "low", ""},
		{"small write is medium", Input{Principal: human, Database: prod, Stmt: update(), Estimate: Estimate{Rows: 1}}, "approve", "writes", "medium", "prod-default"},
		{"big write is high", Input{Principal: human, Database: prod, Stmt: update(), Estimate: Estimate{Rows: 5000}}, "approve", "writes", "high", "prod-high-risk"},
		{"sensitive column is high", Input{Principal: human, Database: prod, Stmt: update(), Columns: masked}, "approve", "writes", "high", "prod-high-risk"},
		{"no approval route on staging", Input{Principal: human, Database: staging, Stmt: update()}, "deny", RuleNoApprovalRoute, "medium", ""},
		{"approval rule error denies", Input{Principal: human, Database: nolabel, Stmt: update()}, "deny", RuleApprovalRuleError, "medium", ""},
		{"policy deny wins", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "delete", IsWrite: true}}, "deny", "deny-unbounded-writes", "medium", ""},
		{"agent sensitive predicate on write", Input{Principal: agent, Database: prod, Stmt: update(), Columns: maskedFilter}, "deny", RuleSensitivePredicate, "high", ""},
		{"human sensitive predicate on write", Input{Principal: human, Database: prod, Stmt: update(), Columns: maskedFilter}, "approve", "writes", "high", "prod-high-risk"},
		{"unknown write", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "update", IsWrite: true, HasWhere: true, Unknown: true}}, "deny", RuleUnknown, "medium", ""},
		{"truncate", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "truncate", IsWrite: true, HasWhere: true}}, "deny", RuleTruncate, "medium", ""},
		{"writable cte", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "select", IsWrite: true, HasWhere: true}}, "approve", "writes", "medium", "prod-default"},
		{"ddl", Input{Principal: human, Database: prod, Stmt: Stmt{Kind: "ddl"}}, "deny", "deny-ddl", "low", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := e.Evaluate(tt.in)
			got := ""
			if d.ApprovalRule != nil {
				got = d.ApprovalRule.Name
			}
			if d.Action != tt.action || d.Rule != tt.rule || d.Risk != tt.risk || got != tt.approvalRule {
				t.Errorf("got %s/%s risk=%s approval=%s (%s), want %s/%s risk=%s approval=%s",
					d.Action, d.Rule, d.Risk, got, d.Message, tt.action, tt.rule, tt.risk, tt.approvalRule)
			}
			if d.Action == "deny" && (d.Message == "" || d.Hint == "") {
				t.Errorf("deny without message/hint: %+v", d)
			}
		})
	}

	// require.step_up is kept on the decision (satisfied by the approvers'
	// step-up) and reason stays required.
	d := e.Evaluate(Input{Principal: human, Database: prod, Stmt: update()})
	if !d.Require.StepUp || !d.Require.Reason {
		t.Errorf("require not propagated: %+v", d.Require)
	}
}

func TestApproveOnlyForWrites(t *testing.T) {
	cfg := mustConfig(t, `
approvals: { enabled: true }
risk: { high: ['estimate.rows > 1000'] }
approval_rules: [{ name: all, when: "true", steps: [{ role: approver }] }]
policies:
  - { name: big-reads, when: 'stmt.kind == "select" && risk == "high"', action: approve }
  - { name: reads, when: 'stmt.kind == "select" && !stmt.is_write', action: allow, require: { step_up: true } }
`)
	e, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := Principal{Kind: "human"}
	if d := e.Evaluate(Input{Principal: p, Stmt: read(), Estimate: Estimate{Rows: 5000}}); d.Action != "deny" || d.Rule != RuleApproveNotWrite {
		t.Errorf("approved read: %+v", d)
	}
	// Step-up for reads is still not implemented.
	if d := e.Evaluate(Input{Principal: p, Stmt: read()}); d.Action != "deny" || d.Rule != RuleStepUpNotEnabled {
		t.Errorf("step-up read: %+v", d)
	}
}

func TestApprovalsDisabledStillDenies(t *testing.T) {
	cfg := mustConfig(t, `
approval_rules: [{ name: all, when: "true", steps: [{ role: approver }] }]
policies:
  - { name: writes, when: stmt.is_write, action: approve }
`)
	e, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d := e.Evaluate(Input{Principal: Principal{Kind: "human"}, Stmt: update()})
	if d.Action != "deny" || d.Rule != RuleWriteNotEnabled || d.ApprovalRule != nil {
		t.Errorf("got %+v", d)
	}
}

func TestDefaultPoliciesWithApprovals(t *testing.T) {
	cfg := mustConfig(t, `
approvals: { enabled: true }
approval_rules: [{ name: all, when: "true", steps: [{ role: approver }] }]
`)
	e, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := Principal{Kind: "human"}
	if d := e.Evaluate(Input{Principal: p, Stmt: read()}); d.Action != "allow" {
		t.Errorf("read: %+v", d)
	}
	if d := e.Evaluate(Input{Principal: p, Stmt: update()}); d.Action != "approve" || d.ApprovalRule.Name != "all" {
		t.Errorf("write: %+v", d)
	}
	if d := e.Evaluate(Input{Principal: p, Stmt: Stmt{Kind: "ddl"}}); d.Action != "deny" || d.Rule != "default-deny-ddl" {
		t.Errorf("ddl: %+v", d)
	}
}

func TestApprovalCompileErrors(t *testing.T) {
	for want, extra := range map[string]string{
		"risk.high[0]":                `risk: { high: ['stmt.kindd == "update"'] }`,
		"risk.medium[0]":              `risk: { medium: ['risk == "high"'] }`, // risk conditions cannot use risk
		"approval_rules[0] (r).when":  `approval_rules: [{ name: r, when: 'stmt.kind', steps: [{ role: approver }] }]`,
		"approval_rules[0] (r2).when": `approval_rules: [{ name: r2, when: 'nope == 1', steps: [{ role: approver }] }]`,
	} {
		cfg := mustConfig(t, "approvals: { enabled: true }\n"+extra+"\n")
		if _, err := Compile(cfg); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
}

func TestRBACUserBindingsAndUnmask(t *testing.T) {
	cfg := mustConfig(t, `
  - user: Jiro@Example.com
    databases: [staging]
    roles: [querier, writer]
  - group: sre
    databases: [prod-main]
    roles: [approver]
unmask:
  - { user: hanako@example.com, databases: [prod-main] }
  - { group: data-team, databases: [staging], expires_at: 2000-01-01T00:00:00Z }
`)
	r := NewRBAC(cfg)
	prod, staging := cfg.Database("prod-main"), cfg.Database("staging")
	jiro := &identity.Principal{Kind: identity.KindHuman, Human: "jiro@example.com"}
	if !r.Has(jiro, staging, identity.RoleWriter) || r.Has(jiro, prod, identity.RoleQuerier) {
		t.Errorf("user binding: %v / %v", r.Roles(jiro, staging), r.Roles(jiro, prod))
	}
	jiroAgent := &identity.Principal{Kind: identity.KindAgent, Human: "jiro@example.com", Scopes: []string{identity.ScopeRead}}
	if r.Has(jiroAgent, staging, identity.RoleWriter) || !r.Has(jiroAgent, staging, identity.RoleQuerier) {
		t.Errorf("agent without write scope: %v", r.Roles(jiroAgent, staging))
	}
	jiroAgent.Scopes = append(jiroAgent.Scopes, identity.ScopeWrite)
	if !r.Has(jiroAgent, staging, identity.RoleWriter) {
		t.Errorf("agent with write scope: %v", r.Roles(jiroAgent, staging))
	}
	if !r.HumanHas("hanako@example.com", []string{"sre"}, prod, identity.RoleApprover) || r.HumanHas("taro@example.com", []string{"data-team"}, prod, identity.RoleApprover) {
		t.Error("HumanHas")
	}

	hanako := &identity.Principal{Kind: identity.KindHuman, Human: "hanako@example.com", Groups: []string{"sre"}}
	if !r.HasUnmask(hanako, prod) || r.HasUnmask(hanako, staging) {
		t.Error("unmask by user")
	}
	hanakoAgent := &identity.Principal{Kind: identity.KindAgent, Human: "hanako@example.com", Groups: []string{"sre"}}
	if r.HasUnmask(hanakoAgent, prod) {
		t.Error("unmask must never apply to agents")
	}
	taro := &identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Groups: []string{"data-team"}}
	if r.HasUnmask(taro, staging) {
		t.Error("expired unmask")
	}
	r.now = func() time.Time { return time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) }
	if !r.HasUnmask(taro, staging) {
		t.Error("unmask by group before expiry")
	}
	known := r.KnownHumans()
	if len(known) != 2 || known[0] != "hanako@example.com" || known[1] != "jiro@example.com" {
		t.Errorf("KnownHumans = %v", known)
	}
}

// Ensure the risk level is visible to policy rules too.
func TestRiskVisibleToPolicies(t *testing.T) {
	cfg := mustConfig(t, approvalsYAML)
	e, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d := e.Evaluate(Input{Principal: Principal{Kind: "human"}, Database: Database{Labels: map[string]string{"env": "prod"}}, Stmt: read()})
	if d.Risk != config.RiskLow {
		t.Errorf("risk = %s", d.Risk)
	}
}
