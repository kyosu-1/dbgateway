package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

const baseYAML = `
auth: { dev_login: true }
databases:
  - name: prod-main
    labels: { env: prod }
    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }
  - name: staging
    labels: { env: staging }
    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }
groups:
  - { name: sre, members: [hanako@example.com] }
  - { name: dba, oidc_group: dba }
`

func TestApprovalsParse(t *testing.T) {
	cfg, err := Parse([]byte(baseYAML + `
approvals: { enabled: true }
role_bindings:
  - { group: sre, databases: "*", roles: [querier, writer, approver] }
  - { user: jiro@example.com, databases: [staging], roles: [writer], expires_at: 2030-01-01T00:00:00Z }
risk:
  high: ['stmt.is_write && estimate.rows > 1000']
  medium: ['stmt.is_write']
approval_rules:
  - name: prod-high-risk
    when: database.labels.env == "prod" && risk == "high"
    steps:
      - { role: approver, count: 1 }
      - { group: dba, count: 2 }
    expire_after: 2h
    max_affected_rows: 500
  - name: default
    when: "true"
    steps: [{ role: approver }]
unmask:
  - { user: hanako@example.com, databases: [prod-main], expires_at: 2030-01-01T00:00:00Z }
  - { group: dba, databases: { labels: { env: prod } } }
break_glass:
  databases: { labels: { env: prod } }
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Approvals.Enabled || cfg.Approvals.DefaultMaxAffectedRatio != 2.0 || cfg.Approvals.StepUpMaxAge.D() != 5*time.Minute {
		t.Errorf("approvals defaults: %+v", cfg.Approvals)
	}
	if len(cfg.Risk.High) != 1 || len(cfg.Risk.Medium) != 1 {
		t.Errorf("risk: %+v", cfg.Risk)
	}
	r := cfg.ApprovalRule("prod-high-risk")
	if r == nil || len(r.Steps) != 2 || r.Steps[1].Group != "dba" || r.Steps[1].Count != 2 || r.ExpireAfter.D() != 2*time.Hour || r.MaxAffectedRows != 500 {
		t.Errorf("rule: %+v", r)
	}
	d := cfg.ApprovalRule("default")
	if d.Steps[0].Role != identity.RoleApprover || d.Steps[0].Count != 1 || d.ExpireAfter.D() != time.Hour {
		t.Errorf("rule defaults: %+v", d)
	}
	if cfg.RoleBindings[1].User != "jiro@example.com" || len(cfg.Unmask) != 2 || cfg.BreakGlass.MaxDuration.D() != time.Hour {
		t.Errorf("bindings/unmask/break_glass: %+v %+v %+v", cfg.RoleBindings, cfg.Unmask, cfg.BreakGlass)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "approval") || strings.Contains(w, "no effect") {
			t.Errorf("unexpected warning: %s", w)
		}
	}
	// Default policies when approvals are enabled.
	if len(cfg.Policies) != 3 || cfg.Policies[2].Action != ActionApprove || cfg.Policies[0].Action != ActionDeny {
		t.Errorf("default policies: %+v", cfg.Policies)
	}
}

func TestApprovalsDisabledDefaultsAndWarnings(t *testing.T) {
	cfg, err := Parse([]byte(baseYAML + `
role_bindings:
  - { group: sre, databases: "*", roles: [querier, writer] }
approval_rules:
  - { name: r, when: "true", steps: [{ role: approver }] }
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Policies) != 1 || cfg.Policies[0].Name != "default-reads" {
		t.Errorf("policies: %+v", cfg.Policies)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "writer") || !strings.Contains(joined, "approval_rules: approvals.enabled is false") {
		t.Errorf("warnings: %v", cfg.Warnings)
	}
}

func TestApprovalsWarnings(t *testing.T) {
	cfg, err := Parse([]byte(`
auth: { dev_login: true }
approvals: { enabled: true }
databases:
  - name: db
    primary: { host: localhost, read_user: r, sslmode: disable }
`))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "no approval rule") || !strings.Contains(joined, "write_user") {
		t.Errorf("warnings: %v", cfg.Warnings)
	}
}

func TestApprovalsValidation(t *testing.T) {
	cases := map[string]string{
		"steps: at least one":           `approval_rules: [{ name: r, when: "true", steps: [] }]`,
		"exactly one of role or group":  `approval_rules: [{ name: r, when: "true", steps: [{ role: approver, group: sre }] }]`,
		"must be approver or admin":     `approval_rules: [{ name: r, when: "true", steps: [{ role: writer }] }]`,
		"unknown group \"nope\"":        `approval_rules: [{ name: r, when: "true", steps: [{ group: nope }] }]`,
		"count: must be at least 1":     `approval_rules: [{ name: r, when: "true", steps: [{ role: approver, count: -1 }] }]`,
		"approval_rules[1].name":        "approval_rules:\n  - { name: r, when: \"true\", steps: [{ role: approver }] }\n  - { name: r, when: \"true\", steps: [{ role: approver }] }",
		"when: required":                `approval_rules: [{ name: r, steps: [{ role: approver }] }]`,
		"expire_after":                  `approval_rules: [{ name: r, when: "true", steps: [{ role: approver }], expire_after: 30d }]`,
		"exactly one of group or user":  `role_bindings: [{ group: sre, user: a@example.com, databases: "*", roles: [querier] }]`,
		"unmask[0]: exactly one":        `unmask: [{ databases: "*" }]`,
		"unmask[0].databases: required": `unmask: [{ user: a@example.com }]`,
		"unknown database \"x\"":        `unmask: [{ user: a@example.com, databases: [x] }]`,
		"break_glass.databases":         `break_glass: { max_duration: 1h }`,
		"break_glass.max_duration":      `break_glass: { max_duration: 48h, databases: "*" }`,
		"default_max_affected_ratio":    `approvals: { enabled: true, default_max_affected_ratio: -1 }`,
		"step_up_max_age":               `approvals: { enabled: true, step_up_max_age: 2h }`,
		"risk.high[0]: empty":           `risk: { high: [" "] }`,
	}
	for want, extra := range cases {
		_, err := Parse([]byte(baseYAML + extra + "\n"))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
}

func TestMaxAffectedRows(t *testing.T) {
	cfg := &Config{Approvals: Approvals{DefaultMaxAffectedRatio: 2}}
	for _, tt := range []struct {
		rule *ApprovalRule
		est  float64
		want int64
	}{
		{nil, 0, 1},
		{nil, 0.2, 1},
		{nil, 1, 2},
		{nil, 10.3, 21},
		{&ApprovalRule{MaxAffectedRows: 5}, 1000, 5},
		{&ApprovalRule{}, 3, 6},
	} {
		if got := cfg.MaxAffectedRows(tt.rule, tt.est); got != tt.want {
			t.Errorf("MaxAffectedRows(%v, %v) = %d, want %d", tt.rule, tt.est, got, tt.want)
		}
	}
	if !slices.Contains([]int64{1}, cfg.MaxAffectedRows(nil, -5)) {
		t.Error("negative estimate must give 1")
	}
}
