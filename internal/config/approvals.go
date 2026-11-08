package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

// Approvals enables the approval workflow for writes (phase 2).
//
// When disabled (the default), every write is denied as in phase 1.
type Approvals struct {
	Enabled bool `yaml:"enabled"`
	// DefaultMaxAffectedRatio bounds the rows a write may affect: the
	// planner estimate times this ratio, at least one row. An approval
	// rule's max_affected_rows takes precedence.
	DefaultMaxAffectedRatio float64 `yaml:"default_max_affected_ratio"`
	// StepUpMaxAge is how recent the approver's re-authentication (passkey
	// or IdP) must be when approving or elevating.
	StepUpMaxAge Duration `yaml:"step_up_max_age"`
}

// Risk lists the CEL conditions of each risk level. They are evaluated
// high first, then medium; no match means low.
type Risk struct {
	High   []string `yaml:"high"`
	Medium []string `yaml:"medium"`
}

// Risk levels.
const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

// ApprovalRule decides who approves a request the policy marked "approve".
// Rules are evaluated top to bottom and the first match wins.
type ApprovalRule struct {
	Name  string         `yaml:"name"`
	When  string         `yaml:"when"`
	Steps []ApprovalStep `yaml:"steps"`
	// ExpireAfter is the time allowed to complete every step.
	ExpireAfter Duration `yaml:"expire_after"`
	// MaxAffectedRows overrides the estimate-based limit when set.
	MaxAffectedRows int64 `yaml:"max_affected_rows"`
}

// ApprovalStep is one sequential stage: Count distinct people who hold
// Role on the database, or who belong to Group, must approve.
type ApprovalStep struct {
	Role  identity.Role `yaml:"role"`
	Group string        `yaml:"group"`
	Count int           `yaml:"count"`
}

// Unmask grants a human the right to see masked columns unmasked. It is
// separate from roles and never applies to agents.
type Unmask struct {
	User      string           `yaml:"user"`
	Group     string           `yaml:"group"`
	Databases DatabaseSelector `yaml:"databases"`
	ExpiresAt *time.Time       `yaml:"expires_at"`
}

// BreakGlass configures emergency elevation: a human with the approver
// role may, with a reason and step-up authentication, run writes without
// approval for a limited time.
type BreakGlass struct {
	MaxDuration Duration         `yaml:"max_duration"`
	Databases   DatabaseSelector `yaml:"databases"`
}

// Defaults for the approvals section.
const (
	DefaultMaxAffectedRatio = 2.0
	DefaultStepUpMaxAge     = 5 * time.Minute
	DefaultExpireAfter      = time.Hour
	DefaultBreakGlassMax    = time.Hour
)

// ApprovalDefaultPolicies is used instead of DefaultPolicies when approvals
// are enabled and no policies are configured: DDL is denied, plain reads
// are allowed and writes need approval.
var ApprovalDefaultPolicies = []Rule{
	{
		Name:   "default-deny-ddl",
		When:   `stmt.kind == "ddl"`,
		Action: ActionDeny,
		Hint:   "スキーマ変更はdbgatewayでは実行しません。マイグレーションファイルを作成し、PRでレビューを受けて適用してください。",
	},
	{Name: "default-reads", When: `stmt.kind == "select" && !stmt.is_write`, Action: ActionAllow},
	{Name: "default-writes", When: `stmt.is_write`, Action: ActionApprove},
}

// defaultPolicies returns the policies used when none are configured.
func (c *Config) defaultPolicies() []Rule {
	if c.Approvals.Enabled {
		return ApprovalDefaultPolicies
	}
	return DefaultPolicies
}

func (c *Config) applyApprovalDefaults() {
	if c.Approvals.DefaultMaxAffectedRatio == 0 {
		c.Approvals.DefaultMaxAffectedRatio = DefaultMaxAffectedRatio
	}
	if c.Approvals.StepUpMaxAge == 0 {
		c.Approvals.StepUpMaxAge = Duration(DefaultStepUpMaxAge)
	}
	for i := range c.ApprovalRules {
		r := &c.ApprovalRules[i]
		if r.ExpireAfter == 0 {
			r.ExpireAfter = Duration(DefaultExpireAfter)
		}
		for j := range r.Steps {
			if r.Steps[j].Count == 0 {
				r.Steps[j].Count = 1
			}
		}
	}
	if c.BreakGlass != nil && c.BreakGlass.MaxDuration == 0 {
		c.BreakGlass.MaxDuration = Duration(DefaultBreakGlassMax)
	}
}

// validateApprovals checks the approvals, risk, approval_rules, unmask and
// break_glass sections. CEL conditions are compiled by the policy package.
func (c *Config) validateApprovals(groupNames, dbNames map[string]bool, add func(string, ...any)) {
	a := c.Approvals
	if a.DefaultMaxAffectedRatio <= 0 {
		add("approvals.default_max_affected_ratio: must be positive")
	}
	if a.StepUpMaxAge.D() <= 0 || a.StepUpMaxAge.D() > time.Hour {
		add("approvals.step_up_max_age: must be between 0 and 1h")
	}

	for i, w := range c.Risk.High {
		if strings.TrimSpace(w) == "" {
			add("risk.high[%d]: empty condition", i)
		}
	}
	for i, w := range c.Risk.Medium {
		if strings.TrimSpace(w) == "" {
			add("risk.medium[%d]: empty condition", i)
		}
	}

	names := map[string]bool{}
	for i, r := range c.ApprovalRules {
		p := fmt.Sprintf("approval_rules[%d]", i)
		if r.Name == "" {
			add("%s.name: required", p)
		} else if names[r.Name] {
			add("%s.name: duplicate %q", p, r.Name)
		}
		names[r.Name] = true
		if strings.TrimSpace(r.When) == "" {
			add("%s.when: required", p)
		}
		if len(r.Steps) == 0 {
			add("%s.steps: at least one step is required", p)
		}
		for j, s := range r.Steps {
			sp := fmt.Sprintf("%s.steps[%d]", p, j)
			switch {
			case (s.Role == "") == (s.Group == ""):
				add("%s: exactly one of role or group is required", sp)
			case s.Role != "" && s.Role != identity.RoleApprover && s.Role != identity.RoleAdmin:
				// Only roles that cannot be held by the requester's agents
				// make sense as approvers.
				add("%s.role: must be approver or admin (got %q)", sp, s.Role)
			case s.Group != "" && !groupNames[s.Group]:
				add("%s.group: unknown group %q", sp, s.Group)
			}
			if s.Count < 1 {
				add("%s.count: must be at least 1", sp)
			}
		}
		if r.ExpireAfter.D() <= 0 || r.ExpireAfter.D() > 7*24*time.Hour {
			add("%s.expire_after: must be between 0 and 7d", p)
		}
		if r.MaxAffectedRows < 0 {
			add("%s.max_affected_rows: must be positive", p)
		}
	}

	for i, u := range c.Unmask {
		p := fmt.Sprintf("unmask[%d]", i)
		if (u.User == "") == (u.Group == "") {
			add("%s: exactly one of user or group is required", p)
		}
		if u.Group != "" && !groupNames[u.Group] {
			add("%s.group: unknown group %q", p, u.Group)
		}
		validateSelector(u.Databases, p+".databases", dbNames, add)
	}

	if bg := c.BreakGlass; bg != nil {
		if bg.MaxDuration.D() <= 0 || bg.MaxDuration.D() > 24*time.Hour {
			add("break_glass.max_duration: must be between 0 and 24h")
		}
		validateSelector(bg.Databases, "break_glass.databases", dbNames, add)
	}

	if a.Enabled {
		if len(c.ApprovalRules) == 0 {
			c.warn("approval_rules: approvals are enabled but no approval rule is configured; every write will be denied (no approval route)")
		}
		for _, db := range c.Databases {
			if db.Primary.WriteUser == "" {
				c.warn("databases[%s].primary.write_user: not set; writes to this database will be denied", db.Name)
			}
		}
	} else {
		if len(c.Risk.High)+len(c.Risk.Medium) > 0 || len(c.ApprovalRules) > 0 {
			c.warn("risk/approval_rules: approvals.enabled is false; these sections are ignored and writes are always denied")
		}
		if c.BreakGlass != nil {
			c.warn("break_glass: approvals.enabled is false; break-glass elevation is unavailable")
		}
	}
}

func validateSelector(s DatabaseSelector, p string, dbNames map[string]bool, add func(string, ...any)) {
	if !s.All && len(s.Names) == 0 && len(s.Labels) == 0 {
		add("%s: required", p)
	}
	for _, n := range s.Names {
		if !dbNames[n] {
			add("%s: unknown database %q", p, n)
		}
	}
}

// MaxAffectedRows returns the limit on rows a write may affect: the rule's
// max_affected_rows when set, otherwise the estimate times
// default_max_affected_ratio, rounded up and at least one row.
func (c *Config) MaxAffectedRows(rule *ApprovalRule, estimateRows float64) int64 {
	if rule != nil && rule.MaxAffectedRows > 0 {
		return rule.MaxAffectedRows
	}
	limit := estimateRows * c.Approvals.DefaultMaxAffectedRatio
	if limit < 1 {
		return 1
	}
	if limit > 1<<53 {
		return 1 << 53
	}
	n := int64(limit)
	if float64(n) < limit {
		n++
	}
	return n
}

// ApprovalRule returns the approval rule with the given name, or nil.
func (c *Config) ApprovalRule(name string) *ApprovalRule {
	for i := range c.ApprovalRules {
		if c.ApprovalRules[i].Name == name {
			return &c.ApprovalRules[i]
		}
	}
	return nil
}
