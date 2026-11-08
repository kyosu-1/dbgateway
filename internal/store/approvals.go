package store

import (
	"context"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

// ApprovalStatus is the state of an approval request.
//
//	pending → approved → running → succeeded | failed
//	pending → rejected | expired | canceled
type ApprovalStatus string

const (
	ApprovalPending   ApprovalStatus = "pending"
	ApprovalApproved  ApprovalStatus = "approved"
	ApprovalRunning   ApprovalStatus = "running"
	ApprovalSucceeded ApprovalStatus = "succeeded"
	ApprovalFailed    ApprovalStatus = "failed"
	ApprovalRejected  ApprovalStatus = "rejected"
	ApprovalExpired   ApprovalStatus = "expired"
	ApprovalCanceled  ApprovalStatus = "canceled"
)

// Final reports whether no further transition is possible.
func (s ApprovalStatus) Final() bool {
	switch s {
	case ApprovalSucceeded, ApprovalFailed, ApprovalRejected, ApprovalExpired, ApprovalCanceled:
		return true
	}
	return false
}

// ApprovalRequest is a write waiting for (or done with) approval. The JSON
// fields are opaque to the store; the approval package owns their schema.
type ApprovalRequest struct {
	ID                string
	RequesterKind     identity.Kind
	RequesterHuman    string
	RequesterAgent    string
	RequesterClientID string
	Database          string
	// RawSQL is shown only on the approval page and used for execution.
	RawSQL string
	// NormalizedSQL has literals replaced by placeholders (lists, events).
	NormalizedSQL string
	Reason        string
	AnalysisJSON  []byte
	EstimateRows  float64
	// MaxAffectedRows is the limit shown to approvers and enforced at
	// execution.
	MaxAffectedRows int64
	Risk            string
	ApprovalRule    string
	StepsJSON       []byte
	ApprovalsJSON   []byte
	ConfigVersion   string
	BindingHash     string
	Status          ApprovalStatus
	// Version increases with every update of the approvals (optimistic
	// concurrency for UpdateApprovals).
	Version    int64
	CreatedAt  time.Time
	ExpiresAt  time.Time
	DecidedAt  *time.Time
	DecidedBy  string // who rejected or canceled
	Comment    string // rejection / cancellation comment
	StartedAt  *time.Time
	FinishedAt *time.Time
	ResultJSON []byte
}

// ApprovalFilter narrows ListApprovalRequests. Zero fields do not filter.
type ApprovalFilter struct {
	RequesterHuman string
	Database       string
	Statuses       []ApprovalStatus
	// ExpiresBefore selects requests whose expires_at is before it.
	ExpiresBefore time.Time
	// Limit caps the number of rows (default 100, max 1000). Rows are
	// returned newest first.
	Limit int
}

// ApprovalTransition carries the fields set by TransitionApprovalRequest.
// At is stored as decided_at for approved/rejected/expired/canceled, as
// started_at for running, and as finished_at for succeeded/failed.
type ApprovalTransition struct {
	At        time.Time
	DecidedBy string
	Comment   string
	Result    []byte
}

// Grant is a break-glass elevation: until ExpiresAt, writes by Human to
// Databases run without approval.
type Grant struct {
	ID           string
	Human        string
	Databases    []string
	Reason       string
	StepUpMethod string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// ApprovalStore persists approval requests and break-glass grants.
type ApprovalStore interface {
	CreateApprovalRequest(ctx context.Context, r *ApprovalRequest) error
	GetApprovalRequest(ctx context.Context, id string) (*ApprovalRequest, error)
	ListApprovalRequests(ctx context.Context, f ApprovalFilter) ([]*ApprovalRequest, error)
	// UpdateApprovals stores the approvals of a pending request and moves
	// it to status (pending or approved) only if its version is still
	// version; decidedAt is stored when non-nil. It returns ErrConflict when
	// the request is no longer pending or was updated concurrently, and
	// ErrNotFound when it does not exist.
	UpdateApprovals(ctx context.Context, id string, version int64, approvalsJSON []byte, status ApprovalStatus, decidedAt *time.Time) error
	// TransitionApprovalRequest moves a request from one status to another
	// with a conditional update, so that exactly one caller wins (e.g. only
	// one worker moves approved → running). It returns ErrConflict when the
	// request is not in status from, and ErrNotFound when it does not exist.
	TransitionApprovalRequest(ctx context.Context, id string, from, to ApprovalStatus, t ApprovalTransition) error

	CreateGrant(ctx context.Context, g *Grant) error
	// ListActiveGrants returns the grants of human that have not expired at
	// now, newest first.
	ListActiveGrants(ctx context.Context, human string, now time.Time) ([]*Grant, error)
}
