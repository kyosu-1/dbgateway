// Package events defines the operational events dbgateway emits (approval
// requests, decisions, executions, denials, break-glass use, ...) and the
// Publisher interface that notifiers (Slack, webhooks) implement.
//
// Events never carry literal values, raw SQL or query results: only the
// normalized SQL (literals replaced by placeholders), table names,
// estimates, the caller's stated reason and who did what.
package events

import (
	"context"
	"time"
)

// Type is the kind of event.
type Type string

const (
	// ApprovalRequested: a write was submitted for approval.
	ApprovalRequested Type = "approval_requested"
	// ApprovalDecided: an approver approved a step, the request was fully
	// approved, rejected, canceled by the requester or expired. Status
	// tells which.
	ApprovalDecided Type = "approval_decided"
	// ExecutionFinished: an approved write succeeded or failed.
	ExecutionFinished Type = "execution_finished"
	// QueryDenied: a request was denied (parse, role or policy stage).
	QueryDenied Type = "query_denied"
	// BreakGlassUsed: a human elevated to run writes without approval.
	BreakGlassUsed Type = "break_glass_used"
	// AnomalyDetected: unusual activity (many denials, large reads).
	AnomalyDetected Type = "anomaly_detected"
	// ConfigChanged: the configuration version changed since the last start.
	ConfigChanged Type = "config_changed"
)

// Principal identifies the requester.
type Principal struct {
	Kind     string `json:"kind"`
	Human    string `json:"human"`
	Agent    string `json:"agent,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// Event is one notification-worthy occurrence.
type Event struct {
	Type      Type      `json:"type"`
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id,omitempty"`
	Database  string    `json:"database,omitempty"`
	// Labels are the database labels, for routing (e.g. env=prod).
	Labels    map[string]string `json:"labels,omitempty"`
	Principal *Principal        `json:"principal,omitempty"`
	// SQL is the normalized SQL (literals replaced by placeholders). Never
	// the raw SQL.
	SQL          string   `json:"sql,omitempty"`
	Tables       []string `json:"tables,omitempty"`
	EstimateRows *float64 `json:"estimate_rows,omitempty"`
	// Reason is the requester's stated reason. It is free text written by
	// the requester (possibly an AI agent): render it inert (no links or
	// mentions).
	Reason string `json:"reason,omitempty"`
	// Status is the request status after the event (approval events) or
	// the decision (query_denied: "deny").
	Status string `json:"status,omitempty"`
	// Approvers are the people who can act on the request next.
	Approvers []string `json:"approvers,omitempty"`
	// Actor is the human who caused the event (approver, rejecter,
	// elevated human), when different from the requester.
	Actor string `json:"actor,omitempty"`
	// URL is the approval page of the request, when there is one.
	URL string `json:"url,omitempty"`
	// Detail carries event-specific fields (rule, risk, rows affected,
	// error, step, ...). Values are never query data.
	Detail map[string]string `json:"detail,omitempty"`
}

// Publisher receives events. Implementations must not block the caller
// for long and must never fail it: delivery is asynchronous and best
// effort (the approval page and get_request are the source of truth).
type Publisher interface {
	Publish(ctx context.Context, e Event)
}

// Nop discards every event.
type Nop struct{}

// Publish implements Publisher.
func (Nop) Publish(context.Context, Event) {}

// PublisherFunc adapts a function to Publisher.
type PublisherFunc func(ctx context.Context, e Event)

// Publish implements Publisher.
func (f PublisherFunc) Publish(ctx context.Context, e Event) { f(ctx, e) }

// Multi fans out events to several publishers.
type Multi []Publisher

// Publish implements Publisher.
func (m Multi) Publish(ctx context.Context, e Event) {
	for _, p := range m {
		p.Publish(ctx, e)
	}
}
