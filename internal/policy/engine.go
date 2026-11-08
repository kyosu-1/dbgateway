// Package policy evaluates role bindings and the CEL policy rules.
package policy

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/ext"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// CEL input types. Field names exposed to CEL are the snake_case `cel` tags.

// Principal is the `principal` variable.
type Principal struct {
	Kind     string   `cel:"kind"`
	Human    string   `cel:"human"`
	Agent    string   `cel:"agent"`
	ClientID string   `cel:"client_id"`
	Groups   []string `cel:"groups"`
}

// Database is the `database` variable.
type Database struct {
	Name   string            `cel:"name"`
	Type   string            `cel:"type"`
	Labels map[string]string `cel:"labels"`
}

// Stmt is the `stmt` variable.
type Stmt struct {
	Kind      string   `cel:"kind"`
	IsWrite   bool     `cel:"is_write"`
	HasWhere  bool     `cel:"has_where"`
	Tables    []Table  `cel:"tables"`
	Functions []string `cel:"functions"`
	Unknown   bool     `cel:"unknown"`
}

// Table is an element of stmt.tables.
type Table struct {
	Schema string `cel:"schema"`
	Name   string `cel:"name"`
	FQN    string `cel:"fqn"`
	Read   bool   `cel:"read"`
	Write  bool   `cel:"write"`
}

// Column is an element of `columns`.
type Column struct {
	Name         string   `cel:"name"` // schema.table.column
	Schema       string   `cel:"schema"`
	Table        string   `cel:"table"`
	Column       string   `cel:"column"`
	Class        string   `cel:"class"`
	SemanticType string   `cel:"semantic_type"`
	Usage        []string `cel:"usage"`
}

// Estimate is the `estimate` variable.
type Estimate struct {
	Rows float64 `cel:"rows"`
	Cost float64 `cel:"cost"`
}

// Input is everything a rule can look at.
type Input struct {
	Principal Principal
	Database  Database
	Stmt      Stmt
	Columns   []Column
	Estimate  Estimate
	Risk      string
}

// Decision is the result of policy evaluation.
type Decision struct {
	Action  string // allow | approve | deny
	Stage   analysis.Stage
	Rule    string
	Message string
	Hint    string
	Require config.Require
	// Risk is the computed risk level (low | medium | high).
	Risk string
	// ApprovalRule is the matched approval rule when Action is approve.
	ApprovalRule *config.ApprovalRule
	// ShadowDeniedBy is set in shadow mode when a rule (or no match) would
	// have denied this read; the request is allowed and the would-be denial
	// is recorded in the audit log.
	ShadowDeniedBy string
}

type compiledRule struct {
	rule config.Rule
	prg  cel.Program
}

type compiledApprovalRule struct {
	rule *config.ApprovalRule
	prg  cel.Program
}

// Engine evaluates the configured rules top to bottom, first match wins.
type Engine struct {
	rules         []compiledRule
	mode          config.Mode
	needsEstimate bool

	approvals     bool
	riskHigh      []cel.Program
	riskMedium    []cel.Program
	approvalRules []compiledApprovalRule
}

// Built-in rule names (always enforced, also in shadow mode).
const (
	RuleNoMatch            = "no-matching-rule"
	RuleUnknown            = "builtin:unanalyzable"
	RuleSensitivePredicate = "builtin:sensitive-predicate"
	RuleWriteNotEnabled    = "builtin:approval-not-enabled"
	RuleStepUpNotEnabled   = "builtin:step-up-not-enabled"
	RuleWriteGuard         = "builtin:write-guard"
	RuleNoApprovalRoute    = "builtin:no-approval-route"
	RuleApprovalRuleError  = "builtin:approval-rule-error"
	RuleApproveNotWrite    = "builtin:approve-non-write"
	RuleTruncate           = "builtin:truncate"
)

// newEnv returns the CEL environment of policy rules and approval rules.
func newEnv() (*cel.Env, error) {
	return newEnvOpts(cel.Variable("risk", cel.StringType))
}

// newRiskEnv is the environment of risk conditions: everything except
// `risk` itself.
func newRiskEnv() (*cel.Env, error) {
	return newEnvOpts()
}

func newEnvOpts(extra ...cel.EnvOption) (*cel.Env, error) {
	opts := []cel.EnvOption{
		ext.NativeTypes(ext.ParseStructTags(true),
			reflect.TypeFor[Principal](), reflect.TypeFor[Database](), reflect.TypeFor[Stmt](),
			reflect.TypeFor[Table](), reflect.TypeFor[Column](), reflect.TypeFor[Estimate]()),
		ext.Strings(),
		// Lets `estimate.rows > 1000` compare a double with an int literal.
		cel.CrossTypeNumericComparisons(true),
		cel.Variable("principal", cel.ObjectType("policy.Principal")),
		cel.Variable("database", cel.ObjectType("policy.Database")),
		cel.Variable("stmt", cel.ObjectType("policy.Stmt")),
		cel.Variable("columns", cel.ListType(cel.ObjectType("policy.Column"))),
		cel.Variable("estimate", cel.ObjectType("policy.Estimate")),
	}
	return cel.NewEnv(append(opts, extra...)...)
}

// Compile type-checks every rule and verifies that no allow rule can ever
// match a write or DDL statement.
func Compile(cfg *config.Config) (*Engine, error) {
	env, err := newEnv()
	if err != nil {
		return nil, err
	}
	e := &Engine{mode: cfg.Server.Mode, approvals: cfg.Approvals.Enabled}
	var errs []error
	for i, r := range cfg.Policies {
		ast, prg, err := compileBool(env, r.When)
		if err != nil {
			errs = append(errs, fmt.Errorf("policies[%d] (%s).when: %w", i, r.Name, err))
			continue
		}
		if r.Action == config.ActionAllow {
			if err := checkAllowExcludesWrites(env, ast); err != nil {
				errs = append(errs, fmt.Errorf("policies[%d] (%s): %w", i, r.Name, err))
				continue
			}
		}
		if strings.Contains(r.When, "estimate") {
			e.needsEstimate = true
		}
		e.rules = append(e.rules, compiledRule{rule: r, prg: prg})
	}
	if err := e.compileApprovals(env, cfg); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return e, nil
}

// compileBool compiles a CEL condition that must evaluate to a boolean.
func compileBool(env *cel.Env, expr string) (*cel.Ast, cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, nil, iss.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return nil, nil, errors.New("must be a boolean expression")
	}
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, nil, err
	}
	return ast, prg, nil
}

// checkAllowExcludesWrites partially evaluates the condition with only the
// statement type known. If it is not definitely false for a write, or for
// a DDL statement, the rule could auto-allow something that must go through
// approval, which is a configuration error.
func checkAllowExcludesWrites(env *cel.Env, ast *cel.Ast) error {
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
	if err != nil {
		return err
	}
	unknownExcept := func(known ...string) []*cel.AttributePatternType {
		pats := []*cel.AttributePatternType{
			cel.AttributePattern("principal"), cel.AttributePattern("database"),
			cel.AttributePattern("columns"), cel.AttributePattern("estimate"), cel.AttributePattern("risk"),
		}
		for _, f := range []string{"kind", "is_write", "has_where", "tables", "functions", "unknown"} {
			if !slices.Contains(known, f) {
				pats = append(pats, cel.AttributePattern("stmt").QualString(f))
			}
		}
		return pats
	}
	cases := []struct {
		desc  string
		stmt  Stmt
		known []string
	}{
		{"a write statement", Stmt{IsWrite: true}, []string{"is_write"}},
		{"a DDL statement", Stmt{Kind: string(analysis.KindDDL)}, []string{"kind", "is_write"}},
	}
	for _, c := range cases {
		vars, err := cel.PartialVars(map[string]any{"stmt": c.stmt}, unknownExcept(c.known...)...)
		if err != nil {
			return err
		}
		out, _, err := prg.Eval(vars)
		if err == nil && !types.IsUnknown(out) && out == types.False {
			continue
		}
		return fmt.Errorf("action allow could match %s; writes must go through approval. "+
			"Restrict the condition, e.g. `stmt.kind == \"select\" && !stmt.is_write && ...`", c.desc)
	}
	return nil
}

// NeedsEstimate reports whether any rule references `estimate`, so the
// caller only runs EXPLAIN when it matters.
func (e *Engine) NeedsEstimate() bool { return e.needsEstimate }

func (in Input) activation() map[string]any {
	cols := in.Columns
	if cols == nil {
		cols = []Column{}
	}
	return map[string]any{
		"principal": in.Principal,
		"database":  in.Database,
		"stmt":      in.Stmt,
		"columns":   cols,
		"estimate":  in.Estimate,
		"risk":      in.Risk,
	}
}

// Evaluate returns the decision for in.
//
// Order: when approvals are enabled the risk level is computed first (so
// rules can use `risk`). Then the first matching configured rule decides.
// A rule whose condition fails to evaluate (e.g. a missing label) matches
// if it is a deny rule and is skipped otherwise (fail closed). Then
// built-in guards apply to anything that would be allowed or approved, and
// an approve decision is routed to the first matching approval rule.
func (e *Engine) Evaluate(in Input) Decision {
	in.Risk = config.RiskLow
	if e.approvals {
		in.Risk = e.risk(in)
	}
	act := in.activation()
	d := Decision{
		Action:  config.ActionDeny,
		Stage:   analysis.StagePolicy,
		Rule:    RuleNoMatch,
		Message: "Denied because no policy matched (the default is deny).",
		Hint:    "If this is a read-only SELECT, ask an administrator to add a policy.",
	}
	for _, cr := range e.rules {
		out, _, err := cr.prg.Eval(act)
		matched := err == nil && out == types.True
		if err != nil && cr.rule.Action == config.ActionDeny {
			matched = true
		}
		if !matched {
			continue
		}
		d = Decision{Action: cr.rule.Action, Stage: analysis.StagePolicy, Rule: cr.rule.Name, Require: cr.rule.Require,
			Message: cr.rule.Message, Hint: cr.rule.Hint}
		if d.Action == config.ActionDeny && d.Message == "" {
			d.Message = fmt.Sprintf("Denied by policy %q.", cr.rule.Name)
		}
		break
	}
	d = e.decide(in, d)
	d.Risk = in.Risk
	return d
}

func (e *Engine) decide(in Input, d Decision) Decision {
	isRead := in.Stmt.Kind == string(analysis.KindSelect) && !in.Stmt.IsWrite
	if d.Action == config.ActionDeny {
		if e.mode == config.ModeShadow && isRead {
			d = Decision{Action: config.ActionAllow, Stage: analysis.StagePolicy, Rule: d.Rule, ShadowDeniedBy: d.Rule}
		} else {
			if d.Hint == "" {
				d.Hint = e.defaultHint(in.Stmt)
			}
			return d
		}
	}

	if d.Action == config.ActionApprove || !isRead {
		if !e.approvals {
			return Decision{
				Action: config.ActionDeny, Stage: analysis.StagePolicy, Rule: RuleWriteNotEnabled,
				Message: "Writes require approvals, but approvals are not enabled (approvals.enabled).",
				Hint:    "Run a read-only SELECT instead, or ask a person to make the change.",
			}
		}
		return e.approve(in, d)
	}
	if g := e.guards(in); g != nil {
		g.ShadowDeniedBy = d.ShadowDeniedBy
		return *g
	}
	if d.Require.StepUp {
		// Step-up of the requester is not implemented. For writes the
		// approvers' step-up covers it (see approve).
		return Decision{
			Action: config.ActionDeny, Stage: analysis.StagePolicy, Rule: RuleStepUpNotEnabled,
			Message: fmt.Sprintf("Policy %q requires the user to re-verify their identity (step-up authentication), but step-up authentication is not supported for reads.", d.Rule),
			Hint:    "Contact an administrator.",
		}
	}
	return d
}

// guards are the built-in checks that apply to every allowed read, in
// every mode.
func (e *Engine) guards(in Input) *Decision {
	if in.Stmt.IsWrite || in.Stmt.Kind != string(analysis.KindSelect) {
		return &Decision{Action: config.ActionDeny, Stage: analysis.StagePolicy, Rule: RuleWriteGuard,
			Message: "Only read statements can be run.", Hint: "Express it as a SELECT statement."}
	}
	return commonGuards(in)
}

// commonGuards apply to allowed reads and to writes awaiting approval:
// statements that could not be fully analyzed are never executed, and
// agents may not use sensitive columns in predicates (a result order or an
// affected-row count would reveal their values).
func commonGuards(in Input) *Decision {
	if in.Stmt.Unknown {
		return &Decision{Action: config.ActionDeny, Stage: analysis.StagePolicy, Rule: RuleUnknown,
			Message: "Part of the SQL (the tables or columns it references) could not be determined, so it is not run automatically.",
			Hint:    "Name existing tables and columns explicitly (avoid * and complex functions) and rewrite it in a simpler form."}
	}
	if in.Principal.Kind == string(identity.KindAgent) {
		for _, c := range in.Columns {
			if c.Class == config.ClassPublic {
				continue
			}
			for _, u := range c.Usage {
				if u == string(analysis.UsageFilter) || u == string(analysis.UsageGroup) || u == string(analysis.UsageOrder) {
					return &Decision{Action: config.ActionDeny, Stage: analysis.StagePolicy, Rule: RuleSensitivePredicate,
						Message: fmt.Sprintf("Column %s (class %s) is used in a condition, aggregation or sort (%s). Its values could be inferred, so it cannot be used this way in queries from AI agents.", c.Name, c.Class, u),
						Hint:    "Rewrite the query without using this column in WHERE / JOIN / GROUP BY / ORDER BY, etc. If the column is safe to expose, ask an administrator to classify it as public in data_classes."}
				}
			}
		}
	}
	return nil
}

func (e *Engine) defaultHint(st Stmt) string {
	switch {
	case st.Kind == string(analysis.KindDDL):
		return "dbgateway does not run schema changes. Write a migration file, get it reviewed in a PR, and apply it."
	case st.IsWrite && !st.HasWhere:
		return "There is no WHERE clause. Narrow down the target rows."
	case st.IsWrite && !e.approvals:
		return "Writes can be requested once approvals are enabled."
	case st.IsWrite:
		return "This write is not allowed by policy. If it is needed, contact an administrator."
	}
	return "Revise the query or contact an administrator."
}
