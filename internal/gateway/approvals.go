package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// Approvals is what the gateway needs from the approval service
// (internal/approval implements it). The gateway submits writes that need
// approval; the approval service later calls ExecuteApproved to run them.
type Approvals interface {
	// SubmitWrite stores a new approval request for a write the policy
	// marked approve and returns where it stands.
	SubmitWrite(ctx context.Context, sub *Submission) (*PendingApproval, error)
	// CandidateApprovers lists the people who could approve the first step
	// of a request by p on db under rule (for explain_policy).
	CandidateApprovers(ctx context.Context, p *identity.Principal, db *config.Database, rule *config.ApprovalRule) ([]string, error)
	// ElevationActive reports whether the human p has an active break-glass
	// elevation on db.
	ElevationActive(ctx context.Context, p *identity.Principal, db string) bool
}

// Submission is a write to submit for approval.
type Submission struct {
	// RequestID is the gateway request ID; the approval request uses it so
	// that the audit entries of the query and the approval correlate.
	RequestID  string
	TraceID    string
	Principal  *identity.Principal
	Database   *config.Database
	SQL        string
	Reason     string
	Evaluation *Evaluation // Decision.Action == approve, ApprovalRule set
	// MaxAffectedRows is the limit shown to approvers and enforced when the
	// write runs.
	MaxAffectedRows int64
}

// PendingApproval tells the requester where a submitted write stands.
type PendingApproval struct {
	ID        string
	Approvers []string // who can approve the next step
	ExpiresAt time.Time
	URL       string // approval page
}

// SetApprovals connects the approval service. It must be called before the
// gateway serves requests. Without it, writes needing approval are denied.
func (g *Gateway) SetApprovals(a Approvals) { g.approvals = a }

// ApprovedWrite identifies an approved write to execute. Everything is
// re-checked against the current configuration before it runs.
type ApprovedWrite struct {
	RequestID string
	Database  string
	SQL       string
	// ApprovalRule is the rule the request was approved under; the
	// re-evaluation must route to the same rule.
	ApprovalRule    string
	MaxAffectedRows int64
}

// WriteResult is the outcome of an executed write. Rows are the RETURNING
// rows, masked exactly like read results for the requester.
type WriteResult struct {
	Columns      []ResultColumn `json:"columns,omitzero"`
	Rows         [][]any        `json:"rows,omitzero"`
	RowCount     int            `json:"row_count"`
	Truncated    bool           `json:"truncated,omitzero"`
	RowsAffected int64          `json:"rows_affected"`
	DurationMS   int64          `json:"duration_ms"`
	// Bytes and MaskedColumns are for the audit log.
	Bytes         int64    `json:"-"`
	MaskedColumns []string `json:"-"`
}

// DecisionChangedError is returned by ExecuteApproved when re-evaluation
// with the current configuration no longer approves the write under the
// same approval rule.
type DecisionChangedError struct {
	Decision     string // current action
	Rule         string
	ApprovalRule string // current approval rule, if any
	Message      string
}

func (e *DecisionChangedError) Error() string {
	return fmt.Sprintf("the decision changed (now %s, rule %s, approval rule %q)", e.Decision, e.Rule, e.ApprovalRule)
}

// ErrUnknownDatabase is returned by ExecuteApproved when the database is
// no longer configured.
var ErrUnknownDatabase = errors.New("the database is no longer configured")

// ExecuteApproved runs an approved write for its requester p. The role
// (writer) and the policy are re-evaluated with the current configuration
// first; if the write is no longer approved under the same approval rule it
// returns a *DecisionChangedError without executing. The write runs in a
// read-write transaction and is rolled back when it affects more than
// w.MaxAffectedRows rows (*analysis.AffectedRowsError).
//
// The caller (the approval service) is responsible for the audit log.
func (g *Gateway) ExecuteApproved(ctx context.Context, p *identity.Principal, w ApprovedWrite) (*WriteResult, error) {
	d := g.dbs[w.Database]
	if d == nil {
		return nil, ErrUnknownDatabase
	}
	ev, conn, err := g.evaluate(ctx, p, d, w.SQL)
	if err != nil {
		return nil, err
	}
	dec := ev.Decision
	if !ev.NeedsApproval() || dec.ApprovalRule.Name != w.ApprovalRule {
		ce := &DecisionChangedError{Decision: dec.Action, Rule: dec.Rule, Message: dec.Message}
		if dec.ApprovalRule != nil {
			ce.ApprovalRule = dec.ApprovalRule.Name
		}
		return nil, ce
	}
	return g.runWrite(ctx, p, d, conn, w.SQL, ev, w.MaxAffectedRows)
}

// runWrite executes an evaluated write and masks its RETURNING rows.
func (g *Gateway) runWrite(ctx context.Context, p *identity.Principal, d *database, conn analysis.Conn, sql string, ev *Evaluation, maxAffected int64) (*WriteResult, error) {
	plans, err := g.plan(d.cfg, ev.Analysis.Output, p)
	if err != nil {
		return nil, errUntraceable
	}
	limits := d.cfg.Limits
	opts := analysis.ExecOptions{ReadOnly: false, MaxRows: limits.MaxRows, MaxBytes: int64(limits.MaxBytes),
		StatementTimeout: limits.StatementTimeout.D(), LockTimeout: limits.LockTimeout.D(), MaxAffectedRows: maxAffected}
	if m := ev.Decision.Require.MaxRows; m > 0 && (opts.MaxRows <= 0 || m < opts.MaxRows) {
		opts.MaxRows = m
	}
	res, err := d.adapter.Execute(ctx, conn, sql, opts)
	if err != nil {
		return nil, err
	}
	if len(res.Columns) != len(plans) {
		// The write is committed; only the RETURNING rows are withheld.
		return &WriteResult{RowsAffected: res.RowsAffected, DurationMS: res.Duration.Milliseconds()}, errColumnMismatch
	}
	wr := &WriteResult{RowCount: res.RowCount, Truncated: res.Truncated, RowsAffected: res.RowsAffected,
		DurationMS: res.Duration.Milliseconds(), Bytes: res.Bytes}
	cols, rows, masked, err := g.applyMasking(p.Kind, plans, res)
	if err != nil {
		// The write is committed; only the RETURNING rows are withheld.
		return &WriteResult{RowsAffected: res.RowsAffected, DurationMS: res.Duration.Milliseconds()}, err
	}
	wr.Columns, wr.Rows, wr.MaskedColumns = cols, rows, masked
	return wr, nil
}

var (
	errUntraceable    = errors.New("cannot trace the result columns")
	errColumnMismatch = errors.New("the result columns do not match the analysis")
)

// DescribeError converts an error from ExecuteApproved (or a database
// error) into a message safe to show to the requester and approvers, and
// the SQLSTATE when there is one.
func DescribeError(err error) (string, string) {
	var ce *DecisionChangedError
	var ae *analysis.AffectedRowsError
	switch {
	case errors.As(err, &ce):
		msg := fmt.Sprintf("Not executed because the decision has changed (current decision: %s, rule: %s", ce.Decision, ce.Rule)
		if ce.ApprovalRule != "" {
			msg += ", approval rule: " + ce.ApprovalRule
		}
		msg += ")."
		if ce.Message != "" {
			msg += " " + ce.Message
		}
		return msg, ""
	case errors.As(err, &ae):
		return fmt.Sprintf("Rolled back: %d rows were affected, exceeding the limit of %d rows.", ae.Affected, ae.Max), ""
	case errors.Is(err, ErrUnknownDatabase):
		return "Not executed because the database was removed from the configuration.", ""
	case errors.Is(err, errUntraceable):
		return msgUntraceable, ""
	case errors.Is(err, errColumnMismatch):
		return "The write completed, but the RETURNING columns do not match the analysis, so no rows are returned.", ""
	}
	return describeDBError(err)
}

// breakGlassWrite executes an approve-decision write immediately for a
// human with an active elevation. An audit entry is written before the
// write runs (an unaudited write must never happen) and another with the
// result afterwards.
func (g *Gateway) breakGlassWrite(ctx context.Context, p *identity.Principal, d *database, conn analysis.Conn, req ExecuteRequest,
	ev *Evaluation, resp *ExecuteResponse, entry *audit.Entry, finish func() *ExecuteResponse, failed func(string, string) *ExecuteResponse) *ExecuteResponse {
	entry.Extra["break_glass"] = true
	pre := *entry
	pre.Extra = map[string]any{"break_glass": true, "phase": "start", "risk": ev.Decision.Risk,
		"approval_rule": ev.Decision.ApprovalRule.Name, "max_affected_rows": resp.MaxAffectedRows}
	if err := g.writeAudit(&pre); err != nil {
		return &ExecuteResponse{Status: StatusError, RequestID: resp.RequestID, Reason: errAuditUnavailable.Error()}
	}
	entry.Extra["phase"] = "finish"
	resp.BreakGlass = true
	wr, err := g.runWrite(ctx, p, d, conn, req.SQL, ev, resp.MaxAffectedRows)
	if err != nil {
		msg, code := DescribeError(err)
		if wr != nil { // committed, but the RETURNING rows are withheld
			entry.Extra["rows_affected"] = wr.RowsAffected
			msg += fmt.Sprintf(" (rows affected: %d)", wr.RowsAffected)
		}
		return failed(msg, code)
	}
	resp.Status, resp.Notice = StatusOK, DataNotice
	resp.Columns, resp.Rows, resp.RowCount, resp.Truncated = wr.Columns, wr.Rows, wr.RowCount, wr.Truncated
	affected := wr.RowsAffected
	resp.RowsAffected = &affected
	resp.Hint = "Executed without approval because a break-glass elevation is active (recorded in the audit log)."
	entry.Result = &audit.ResultInfo{Rows: wr.RowCount, Bytes: wr.Bytes, DurationMS: wr.DurationMS, Truncated: wr.Truncated,
		MaskedColumns: wr.MaskedColumns}
	entry.Extra["rows_affected"] = wr.RowsAffected
	return finish()
}

// publishDenied emits query_denied. Only the normalized SQL is included,
// never the raw SQL (even when the audit log records it).
func (g *Gateway) publishDenied(ctx context.Context, p *identity.Principal, req ExecuteRequest, resp *ExecuteResponse, normalized string, ev *Evaluation) {
	e := events.Event{
		Type: events.QueryDenied, Time: time.Now(), RequestID: resp.RequestID, Database: req.Database,
		Principal: EventPrincipal(p), SQL: normalized, Reason: req.Reason, Status: config.ActionDeny,
		Detail: map[string]string{"stage": resp.Stage, "rule": resp.Rule, "message": resp.Reason},
	}
	if d := g.dbs[req.Database]; d != nil {
		e.Labels = d.cfg.Labels
	}
	if ev != nil && ev.Analysis != nil {
		e.Tables = TableNames(ev.Analysis)
	}
	if ev != nil && ev.Estimate != nil {
		rows := ev.Estimate.Rows
		e.EstimateRows = &rows
	}
	g.events.Publish(ctx, e)
}

// EventPrincipal converts a principal for events.
func EventPrincipal(p *identity.Principal) *events.Principal {
	if p == nil {
		return nil
	}
	return &events.Principal{Kind: string(p.Kind), Human: p.Human, Agent: p.Agent, ClientID: p.ClientID}
}

// TableNames returns the schema-qualified tables of an analysis.
func TableNames(qa *analysis.QueryAnalysis) []string {
	var out []string
	for _, t := range qa.Statement.Tables {
		out = append(out, t.FQN())
	}
	return out
}
