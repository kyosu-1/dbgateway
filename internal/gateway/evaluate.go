// Package gateway orchestrates a request through every stage: role check,
// SQL analysis, classification, policy, execution, masking and audit.
// Transports (MCP today; CLI and web console later) call into it so that
// humans and AI go through exactly the same checks.
package gateway

import (
	"context"
	"fmt"
	"slices"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/mask"
	"github.com/kyosu-1/dbgateway/internal/policy"
)

// Analyzer is the part of an adapter needed to evaluate a statement.
type Analyzer interface {
	Analyze(ctx context.Context, sql string, cat *analysis.Catalog) (*analysis.QueryAnalysis, error)
}

// Evaluator decides what happens to a statement without executing it. It
// is shared by execute_sql and `dbgw policy test`.
type Evaluator struct {
	Config     *config.Config
	RBAC       *policy.RBAC
	Engine     *policy.Engine
	Classifier *mask.Classifier
}

// NewEvaluator builds an evaluator from the configuration.
func NewEvaluator(cfg *config.Config) (*Evaluator, error) {
	eng, err := policy.Compile(cfg)
	if err != nil {
		return nil, err
	}
	return &Evaluator{Config: cfg, RBAC: policy.NewRBAC(cfg), Engine: eng, Classifier: mask.NewClassifier(cfg)}, nil
}

// EstimateFunc returns the planner estimate on demand. write is true for
// write statements, which are planned by the write user.
type EstimateFunc func(ctx context.Context, write bool) (*analysis.Estimate, error)

// Evaluation is the outcome of Evaluate.
type Evaluation struct {
	Analysis *analysis.QueryAnalysis
	Columns  []policy.Column
	Estimate *analysis.Estimate
	Decision policy.Decision
}

// Allowed reports whether the statement may be executed.
func (e *Evaluation) Allowed() bool { return e.Decision.Action == config.ActionAllow }

// NeedsApproval reports whether the statement may be executed after
// approval (the decision is approve and an approval rule matched).
func (e *Evaluation) NeedsApproval() bool {
	return e.Decision.Action == config.ActionApprove && e.Decision.ApprovalRule != nil
}

// EstimateRows returns the planner's row estimate, or 0 when unknown.
func (e *Evaluation) EstimateRows() float64 {
	if e.Estimate == nil {
		return 0
	}
	return e.Estimate.Rows
}

func deny(stage analysis.Stage, rule, msg, hint string) policy.Decision {
	return policy.Decision{Action: config.ActionDeny, Stage: stage, Rule: rule, Message: msg, Hint: hint}
}

// Evaluate runs the role check, analysis, classification and policy.
//
// restore recognizes restore statements of backed-up writes; without it
// (nil), statements referencing the backup schema are denied.
func (e *Evaluator) Evaluate(ctx context.Context, p *identity.Principal, db *config.Database, an Analyzer, sql string, cat *analysis.Catalog, estimate EstimateFunc, restore RestoreFunc) *Evaluation {
	ev := &Evaluation{}
	if !e.RBAC.Has(p, db, identity.RoleQuerier) {
		ev.Decision = deny(analysis.StageRole, "role:querier",
			fmt.Sprintf("You do not have permission (querier role) to run queries on database %s.", db.Name),
			"Use list_databases to see the databases you can use. If you need access, ask an administrator to assign you a role.")
		return ev
	}

	qa, err := an.Analyze(ctx, sql, cat)
	if err != nil {
		if r, ok := analysis.AsRejection(err); ok {
			ev.Decision = deny(analysis.StageParse, "parse:"+r.Code, r.Reason, r.Hint)
		} else {
			ev.Decision = deny(analysis.StageParse, "parse:error", "Could not parse the SQL.", "Check that it is a single valid SQL statement.")
		}
		return ev
	}
	ev.Analysis = qa
	// Restores read their backup table as the table it was copied from.
	mapped, msg, ok := checkRestore(ctx, db, sql, qa, restore)
	if !ok {
		ev.Decision = deny(analysis.StagePolicy, ruleBackupProtected, msg, hintBackupProtected)
		return ev
	}
	ev.Columns = e.classifyColumns(db, p.Kind, mapped.Columns)

	st := &qa.Statement
	approvals := e.Config.Approvals.Enabled
	if st.IsWrite && approvals {
		if !e.RBAC.Has(p, db, identity.RoleWriter) {
			hint := "If you need to write, ask an administrator to assign you the writer role."
			if p.IsAgent() {
				hint = "The agent token lacks the write scope (" + identity.ScopeWrite + "), or the person it acts for lacks the writer role. If a write is needed, ask a person to request it."
			}
			ev.Decision = deny(analysis.StageRole, "role:writer",
				fmt.Sprintf("You do not have permission (writer role) to request writes on database %s.", db.Name), hint)
			return ev
		}
		if db.Primary.WriteUser == "" {
			ev.Decision = deny(analysis.StagePolicy, "builtin:no-write-user",
				fmt.Sprintf("Database %s has no write user configured, so writes are not possible.", db.Name),
				"Contact an administrator.")
			return ev
		}
	}

	in := policy.Input{
		Principal: policy.Principal{Kind: string(p.Kind), Human: p.Human, Agent: p.Agent, ClientID: p.ClientID, Groups: p.Groups},
		Database:  policy.Database{Name: db.Name, Type: db.Type, Labels: labels(db)},
		Stmt:      stmtInput(&mapped),
		Columns:   ev.Columns,
	}
	// Writes are always estimated when approvals are enabled: the risk level
	// and the affected-rows limit depend on it. TRUNCATE cannot be
	// explained (and is denied by the policy engine).
	needEstimate := !st.Unknown && ((e.Engine.NeedsEstimate() && st.Kind == analysis.KindSelect && !st.IsWrite) ||
		(approvals && st.IsWrite && st.Kind != analysis.KindTruncate))
	if needEstimate && estimate != nil {
		est, err := estimate(ctx, st.IsWrite)
		if err != nil {
			ev.Decision = deny(analysis.StagePolicy, "builtin:estimate-failed",
				fmt.Sprintf("The row estimate (EXPLAIN) failed, so the statement was not run, for safety (%s).", sanitizeDBError(err)),
				"Check that the SQL is correct.")
			return ev
		}
		ev.Estimate = est
		in.Estimate = policy.Estimate{Rows: est.Rows, Cost: est.Cost}
	}
	ev.Decision = e.Engine.Evaluate(in)
	return ev
}

func labels(db *config.Database) map[string]string {
	if db.Labels == nil {
		return map[string]string{}
	}
	return db.Labels
}

func stmtInput(st *analysis.Statement) policy.Stmt {
	s := policy.Stmt{Kind: string(st.Kind), IsWrite: st.IsWrite, HasWhere: st.HasWhere, Functions: st.Functions, Unknown: st.Unknown}
	if s.Functions == nil {
		s.Functions = []string{}
	}
	for _, t := range st.Tables {
		s.Tables = append(s.Tables, policy.Table{Schema: t.Schema, Name: t.Name, FQN: t.FQN(), Read: t.Read, Write: t.Write})
	}
	if s.Tables == nil {
		s.Tables = []policy.Table{}
	}
	return s
}

func (e *Evaluator) classifyColumns(db *config.Database, kind identity.Kind, refs []analysis.ColumnRef) []policy.Column {
	out := make([]policy.Column, 0, len(refs))
	for _, c := range refs {
		cl := e.Classifier.Classify(db, analysis.ColumnID{Schema: c.Schema, Table: c.Table, Column: c.Column}, kind)
		usage := make([]string, 0, len(c.Usages))
		for _, u := range c.Usages {
			usage = append(usage, string(u))
		}
		slices.Sort(usage)
		out = append(out, policy.Column{Name: c.FQN(), Schema: c.Schema, Table: c.Table, Column: c.Column,
			Class: cl.Class, SemanticType: cl.SemanticType, Usage: usage})
	}
	return out
}
