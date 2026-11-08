package policy

import (
	"errors"
	"fmt"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
)

// compileApprovals compiles the risk conditions and the approval rules.
// Risk conditions cannot reference `risk`; approval rules can.
func (e *Engine) compileApprovals(env *cel.Env, cfg *config.Config) error {
	renv, err := newRiskEnv()
	if err != nil {
		return err
	}
	var errs []error
	compileRisk := func(level string, exprs []string) []cel.Program {
		var out []cel.Program
		for i, w := range exprs {
			_, prg, err := compileBool(renv, w)
			if err != nil {
				errs = append(errs, fmt.Errorf("risk.%s[%d]: %w", level, i, err))
				continue
			}
			if strings.Contains(w, "estimate") {
				e.needsEstimate = true
			}
			out = append(out, prg)
		}
		return out
	}
	e.riskHigh = compileRisk(config.RiskHigh, cfg.Risk.High)
	e.riskMedium = compileRisk(config.RiskMedium, cfg.Risk.Medium)
	for i := range cfg.ApprovalRules {
		r := &cfg.ApprovalRules[i]
		_, prg, err := compileBool(env, r.When)
		if err != nil {
			errs = append(errs, fmt.Errorf("approval_rules[%d] (%s).when: %w", i, r.Name, err))
			continue
		}
		e.approvalRules = append(e.approvalRules, compiledApprovalRule{rule: r, prg: prg})
	}
	return errors.Join(errs...)
}

// risk returns the risk level of in: the first level (high, then medium)
// with a matching condition, otherwise low. A condition that fails to
// evaluate counts as a match (fail closed: higher risk).
func (e *Engine) risk(in Input) string {
	act := in.activation()
	delete(act, "risk")
	matches := func(prgs []cel.Program) bool {
		for _, prg := range prgs {
			out, _, err := prg.Eval(act)
			if err != nil || out == types.True {
				return true
			}
		}
		return false
	}
	switch {
	case matches(e.riskHigh):
		return config.RiskHigh
	case matches(e.riskMedium):
		return config.RiskMedium
	}
	return config.RiskLow
}

// approve finishes an approve decision (approvals enabled): built-in guards,
// then the first matching approval rule. The policy's step_up requirement
// is satisfied by the approvers' step-up, which is always required.
func (e *Engine) approve(in Input, d Decision) Decision {
	deny := func(rule, msg, hint string) Decision {
		return Decision{Action: config.ActionDeny, Stage: analysis.StagePolicy, Rule: rule, Message: msg, Hint: hint}
	}
	switch {
	case d.Action != config.ActionApprove:
		// An allow rule can never match a write (checked at compile time);
		// keep a guard anyway.
		return deny(RuleWriteGuard, "Writes cannot run without approval.", "Ask an administrator to review the policy.")
	case !in.Stmt.IsWrite:
		return deny(RuleApproveNotWrite,
			fmt.Sprintf("Policy %q requires approval, but only writes (INSERT / UPDATE / DELETE / MERGE) can be approved and run.", d.Rule),
			"If this is a read, narrow the conditions and run it again. Apply DDL with a migration file and a PR.")
	case in.Stmt.Kind == string(analysis.KindTruncate):
		return deny(RuleTruncate,
			"TRUNCATE is not run even with approval, because its affected rows cannot be checked.",
			"Request a DELETE ... WHERE that narrows down the target rows instead.")
	}
	if g := commonGuards(in); g != nil {
		return *g
	}
	act := in.activation()
	for _, ar := range e.approvalRules {
		out, _, err := ar.prg.Eval(act)
		if err != nil {
			// Falling through to a later (possibly weaker) rule would be
			// fail-open, so an unevaluable rule denies.
			return deny(RuleApprovalRuleError,
				fmt.Sprintf("Denied because the condition of approval rule %q could not be evaluated (%v).", ar.rule.Name, err),
				"Ask an administrator to check the approval rule's condition (for databases that may lack the label, write `\"env\" in database.labels && ...`).")
		}
		if out == types.True {
			d.ApprovalRule = ar.rule
			return d
		}
	}
	return deny(RuleNoApprovalRoute,
		"This write needs approval, but no approval rule matches (there is no approval route).",
		"Ask an administrator to add an approval rule (approval_rules).")
}
