package gateway

import (
	"context"
	"slices"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/mask"
)

// ExplainRequest is the input of ExplainPolicy.
type ExplainRequest struct {
	Database string
	SQL      string
	TraceID  string
}

// ExplainResponse says what ExecuteSQL would do with a statement, without
// executing it.
type ExplainResponse struct {
	RequestID string `json:"request_id"`
	Database  string `json:"database"`
	// Decision is allow, approve or deny.
	Decision string `json:"decision"`
	Stage    string `json:"stage,omitempty"`
	Rule     string `json:"rule,omitempty"`
	// Reason and Hint explain a denial.
	Reason string `json:"reason,omitempty"`
	Hint   string `json:"hint,omitempty"`
	// ShadowDeniedBy is set in shadow mode when a rule would have denied.
	ShadowDeniedBy string `json:"shadow_denied_by,omitempty"`
	Risk           string `json:"risk,omitempty"`

	// For approve decisions.
	ApprovalRule    string                `json:"approval_rule,omitempty"`
	ApprovalSteps   []config.ApprovalStep `json:"approval_steps,omitzero"`
	ExpireAfter     string                `json:"expire_after,omitempty"`
	Approvers       []string              `json:"approvers,omitzero"`
	MaxAffectedRows int64                 `json:"max_affected_rows,omitzero"`
	// BreakGlass is true when the caller's active elevation would run the
	// write immediately.
	BreakGlass bool `json:"break_glass,omitzero"`

	RequiresReason bool `json:"requires_specific_reason,omitzero"`

	Statement *StatementInfo     `json:"statement,omitempty"`
	Estimate  *analysis.Estimate `json:"estimate,omitempty"`
	// Columns are every referenced column with its class and usage.
	Columns []ExplainColumn `json:"columns,omitzero"`
	// Output describes how each result column would be returned.
	Output []ExplainOutput `json:"output,omitzero"`
}

// StatementInfo summarizes the analysis.
type StatementInfo struct {
	Kind    string   `json:"kind"`
	IsWrite bool     `json:"is_write"`
	Tables  []string `json:"tables,omitzero"`
}

// ExplainColumn is a referenced column.
type ExplainColumn struct {
	Name  string   `json:"name"`
	Class string   `json:"class"`
	Usage []string `json:"usage,omitzero"`
}

// ExplainOutput is an output column and its treatment.
type ExplainOutput struct {
	Name     string `json:"name"`
	Class    string `json:"class"`
	Masked   bool   `json:"masked,omitzero"`
	Withheld bool   `json:"withheld,omitzero"`
}

// ExplainPolicy evaluates sql for p exactly like ExecuteSQL (role, analysis,
// classification, risk, policy, approval rule) but never executes it; only
// the planner estimate (EXPLAIN) may run. It is audited as event "explain".
func (g *Gateway) ExplainPolicy(ctx context.Context, p *identity.Principal, req ExplainRequest) (*ExplainResponse, error) {
	rid := NewRequestID()
	entry := &audit.Entry{RequestID: rid, TraceID: req.TraceID, Event: "explain", Principal: principalInfo(p),
		Database: req.Database, SQLSHA256: sha256Hex(req.SQL)}
	d := g.dbs[req.Database]
	if d == nil || !g.RBAC.Has(p, d.cfg, identity.RoleQuerier) {
		entry.Decision, entry.Stage, entry.Rule = config.ActionDeny, string(analysis.StageRole), "role:querier"
		_ = g.writeAudit(entry)
		return nil, ErrNoAccess
	}
	normalized := ""
	if n, ok := d.adapter.(Normalizer); ok {
		normalized = n.Normalize(req.SQL)
	}
	ev, _, err := g.evaluate(ctx, p, d, req.SQL)
	if err != nil {
		return nil, dbUnavailable(err)
	}
	dec := ev.Decision
	resp := &ExplainResponse{RequestID: rid, Database: d.cfg.Name, Decision: dec.Action, Stage: string(dec.Stage), Rule: dec.Rule,
		ShadowDeniedBy: dec.ShadowDeniedBy, Risk: dec.Risk, Estimate: ev.Estimate, RequiresReason: dec.Require.Reason}
	if dec.Action == config.ActionDeny {
		resp.Reason, resp.Hint = dec.Message, dec.Hint
	}
	if ev.Analysis != nil {
		normalized = ev.Analysis.Normalized
		st := ev.Analysis.Statement
		resp.Statement = &StatementInfo{Kind: string(st.Kind), IsWrite: st.IsWrite, Tables: TableNames(ev.Analysis)}
		for _, c := range ev.Columns {
			resp.Columns = append(resp.Columns, ExplainColumn{Name: c.Name, Class: c.Class, Usage: c.Usage})
		}
		if plans, err := g.plan(d.cfg, ev.Analysis.Output, p); err == nil {
			for i, o := range ev.Analysis.Output {
				resp.Output = append(resp.Output, ExplainOutput{Name: o.Name, Class: plans[i].Class,
					Masked: plans[i].Treatment == mask.Mask, Withheld: plans[i].Treatment == mask.Withhold})
			}
		} else if dec.Action != config.ActionDeny {
			resp.Decision, resp.Rule, resp.Reason, resp.Hint = config.ActionDeny, ruleUntraceable, msgUntraceable, hintUntraceable
		}
	}
	if ev.NeedsApproval() && resp.Decision == config.ActionApprove {
		rule := dec.ApprovalRule
		resp.ApprovalRule, resp.ApprovalSteps, resp.ExpireAfter = rule.Name, slices.Clone(rule.Steps), rule.ExpireAfter.String()
		resp.MaxAffectedRows = g.cfg.MaxAffectedRows(rule, ev.EstimateRows())
		if g.approvals == nil {
			resp.Decision, resp.Rule = config.ActionDeny, "builtin:approval-unavailable"
			resp.Reason, resp.Hint = "承認サービスが利用できないため、書き込みを受け付けられません。", "管理者に問い合わせてください。"
		} else {
			if approvers, err := g.approvals.CandidateApprovers(ctx, p, d.cfg, rule); err == nil {
				resp.Approvers = approvers
			}
			resp.BreakGlass = !p.IsAgent() && g.approvals.ElevationActive(ctx, p, d.cfg.Name)
		}
	}

	entry.SQL = redactedSQL(g.cfg, req.SQL, normalized)
	if ev.Analysis != nil {
		entry.Analysis = analysisInfo(ev)
	}
	if ev.Estimate != nil {
		entry.Estimate = &audit.EstimateInfo{Rows: ev.Estimate.Rows, Cost: ev.Estimate.Cost}
	}
	entry.Decision, entry.Stage, entry.Rule = resp.Decision, resp.Stage, resp.Rule
	entry.Extra = map[string]any{"risk": resp.Risk}
	if resp.ApprovalRule != "" {
		entry.Extra["approval_rule"] = resp.ApprovalRule
	}
	if err := g.writeAudit(entry); err != nil {
		return nil, errAuditUnavailable
	}
	return resp, nil
}
