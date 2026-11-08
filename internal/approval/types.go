package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// Status is the state of a request.
type Status = store.ApprovalStatus

// Request states.
const (
	StatusPending   = store.ApprovalPending
	StatusApproved  = store.ApprovalApproved
	StatusRunning   = store.ApprovalRunning
	StatusSucceeded = store.ApprovalSucceeded
	StatusFailed    = store.ApprovalFailed
	StatusRejected  = store.ApprovalRejected
	StatusExpired   = store.ApprovalExpired
	StatusCanceled  = store.ApprovalCanceled
)

// Grant is a break-glass elevation.
type Grant = store.Grant

// Errors returned by the service. Callers map them to user-facing
// messages; ErrNotFound must be presented exactly like a nonexistent ID.
var (
	ErrNotFound       = errors.New("approval: request not found")
	ErrAgent          = errors.New("approval: only humans can approve, reject or elevate")
	ErrSelfApproval   = errors.New("approval: the requester cannot decide their own request")
	ErrAlreadyActed   = errors.New("approval: you already approved a step of this request")
	ErrNotEligible    = errors.New("approval: you are not an approver for this step")
	ErrNotRequester   = errors.New("approval: only the requester can cancel a request")
	ErrStepUpRequired = errors.New("approval: a recent step-up authentication is required")
	ErrNotPending     = errors.New("approval: the request is no longer pending")
	ErrExpired        = errors.New("approval: the request has expired")
	ErrIntegrity      = errors.New("approval: the request failed its integrity check")
	ErrConflict       = errors.New("approval: the request changed concurrently; retry")
	ErrUnavailable    = errors.New("approval: approvals are not enabled")
	ErrBreakGlassOff  = errors.New("approval: break-glass elevation is not configured")
	ErrReasonRequired = errors.New("approval: a reason is required")
	ErrInvalidRequest = errors.New("approval: invalid request")
)

// StepUp is the proof of a recent re-authentication of the acting human,
// taken from their browser session (the auth layer records it).
type StepUp struct {
	Method string    // "passkey", "idp" or "dev"
	At     time.Time // when the re-authentication happened
}

// Requester identifies who submitted a request.
type Requester struct {
	Kind     identity.Kind `json:"kind"`
	Human    string        `json:"human"`
	Agent    string        `json:"agent,omitempty"`
	ClientID string        `json:"client_id,omitempty"`
}

// Column is a column referenced by the statement, with its data class.
type Column struct {
	Name  string   `json:"name"`
	Class string   `json:"class"`
	Usage []string `json:"usage,omitempty"`
}

// Analysis summarizes the statement for approvers.
type Analysis struct {
	Kind    string   `json:"kind"`
	Tables  []string `json:"tables,omitempty"`
	Columns []Column `json:"columns,omitempty"`
}

// Step is one stage of the approval rule, frozen at submission.
type Step struct {
	Role  identity.Role `json:"role,omitempty"`
	Group string        `json:"group,omitempty"`
	Count int           `json:"count"`
}

// Approval records one approver's decision on a step.
type Approval struct {
	Step         int       `json:"step"`
	Approver     string    `json:"approver"`
	At           time.Time `json:"at"`
	StepUpMethod string    `json:"step_up_method"`
	StepUpAt     time.Time `json:"step_up_at"`
}

// Result is the outcome of an executed request. Rows are the RETURNING
// rows, masked as they would be for the requester.
type Result struct {
	RowsAffected int64                  `json:"rows_affected"`
	Columns      []gateway.ResultColumn `json:"columns,omitempty"`
	Rows         [][]any                `json:"rows,omitempty"`
	RowCount     int                    `json:"row_count"`
	Truncated    bool                   `json:"truncated,omitempty"`
	DurationMS   int64                  `json:"duration_ms"`
	// Error is set when the request failed (or when a committed write's
	// RETURNING rows had to be withheld).
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"` // SQLSTATE
}

// Request is an approval request as seen by a viewer.
type Request struct {
	ID        string    `json:"id"`
	Status    Status    `json:"status"`
	Requester Requester `json:"requester"`
	Database  string    `json:"database"`
	// SQL is the raw statement, for the approval page and get_request. It
	// is empty in List results.
	SQL string `json:"sql,omitempty"`
	// NormalizedSQL has literals replaced by placeholders.
	NormalizedSQL string `json:"normalized_sql"`
	// Reason is free text written by the requester (possibly an AI agent):
	// display it as inert text.
	Reason          string     `json:"reason"`
	Analysis        Analysis   `json:"analysis"`
	EstimateRows    float64    `json:"estimate_rows"`
	MaxAffectedRows int64      `json:"max_affected_rows"`
	Risk            string     `json:"risk"`
	ApprovalRule    string     `json:"approval_rule"`
	Steps           []Step     `json:"steps"`
	Approvals       []Approval `json:"approvals"`
	// CurrentStep is the index of the step awaiting approval; equal to
	// len(Steps) once every step is approved.
	CurrentStep   int        `json:"current_step"`
	ConfigVersion string     `json:"config_version"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	// DecidedBy and Comment record a rejection or cancellation.
	DecidedBy  string     `json:"decided_by,omitempty"`
	Comment    string     `json:"comment,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Result     *Result    `json:"result,omitempty"`
	// URL is the approval page.
	URL string `json:"url"`

	version     int64
	bindingHash string
}

// currentStep returns the first step that still needs approvals.
func currentStep(steps []Step, approvals []Approval) int {
	for i, s := range steps {
		n := 0
		for _, a := range approvals {
			if a.Step == i {
				n++
			}
		}
		if n < s.Count {
			return i
		}
	}
	return len(steps)
}

// bindingHash fixes what was approved: database, raw SQL, requester,
// approval rule and configuration version. Fields are length-prefixed so
// that no two different inputs share an encoding.
func bindingHash(db, sql string, req Requester, rule, version string) string {
	h := sha256.New()
	for _, f := range []string{db, sql, string(req.Kind), req.Human, req.Agent, req.ClientID, rule, version} {
		fmt.Fprintf(h, "%d:%s;", len(f), f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (r *Request) computeHash() string {
	return bindingHash(r.Database, r.SQL, r.Requester, r.ApprovalRule, r.ConfigVersion)
}

// fromStore converts a stored request.
func fromStore(row *store.ApprovalRequest, publicURL string) (*Request, error) {
	r := &Request{
		ID: row.ID, Status: row.Status,
		Requester: Requester{Kind: row.RequesterKind, Human: row.RequesterHuman, Agent: row.RequesterAgent, ClientID: row.RequesterClientID},
		Database:  row.Database, SQL: row.RawSQL, NormalizedSQL: row.NormalizedSQL, Reason: row.Reason,
		EstimateRows: row.EstimateRows, MaxAffectedRows: row.MaxAffectedRows, Risk: row.Risk, ApprovalRule: row.ApprovalRule,
		ConfigVersion: row.ConfigVersion, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, DecidedAt: row.DecidedAt,
		DecidedBy: row.DecidedBy, Comment: row.Comment, StartedAt: row.StartedAt, FinishedAt: row.FinishedAt,
		URL: requestURL(publicURL, row.ID), version: row.Version, bindingHash: row.BindingHash,
	}
	if err := json.Unmarshal(row.AnalysisJSON, &r.Analysis); err != nil {
		return nil, fmt.Errorf("approval: decode analysis of %s: %w", row.ID, err)
	}
	if err := json.Unmarshal(row.StepsJSON, &r.Steps); err != nil {
		return nil, fmt.Errorf("approval: decode steps of %s: %w", row.ID, err)
	}
	if err := json.Unmarshal(row.ApprovalsJSON, &r.Approvals); err != nil {
		return nil, fmt.Errorf("approval: decode approvals of %s: %w", row.ID, err)
	}
	if r.Approvals == nil {
		r.Approvals = []Approval{}
	}
	if len(row.ResultJSON) > 0 {
		r.Result = &Result{}
		if err := json.Unmarshal(row.ResultJSON, r.Result); err != nil {
			return nil, fmt.Errorf("approval: decode result of %s: %w", row.ID, err)
		}
	}
	r.CurrentStep = currentStep(r.Steps, r.Approvals)
	return r, nil
}

func requestURL(publicURL, id string) string {
	return publicURL + "/approvals/" + id
}
