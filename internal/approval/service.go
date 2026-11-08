package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// Executor runs approved writes; *gateway.Gateway implements it.
type Executor interface {
	ExecuteApproved(ctx context.Context, p *identity.Principal, w gateway.ApprovedWrite) (*gateway.WriteResult, error)
}

// Options configures a Service.
type Options struct {
	Config *config.Config // required
	Store  store.Store    // required
	// Executor runs approved writes (the gateway). Required.
	Executor Executor
	// Audit records every state change. Required: without it every
	// operation fails (no audit, no write).
	Audit *audit.Logger
	// RBAC defaults to policy.NewRBAC(Config).
	RBAC *policy.RBAC
	// Events defaults to events.Nop.
	Events events.Publisher
	Logger *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
	// Interval of the Run loop (default 30s).
	Interval time.Duration
}

// Service is the approval workflow. It is safe for concurrent use and for
// use by several dbgateway instances sharing one store.
type Service struct {
	cfg      *config.Config
	st       store.Store
	exec     Executor
	audit    *audit.Logger
	rbac     *policy.RBAC
	events   events.Publisher
	logger   *slog.Logger
	now      func() time.Time
	interval time.Duration

	wg sync.WaitGroup // in-flight executions
}

var _ gateway.Approvals = (*Service)(nil)

// New returns a service.
func New(opts Options) *Service {
	s := &Service{cfg: opts.Config, st: opts.Store, exec: opts.Executor, audit: opts.Audit, rbac: opts.RBAC,
		events: opts.Events, logger: opts.Logger, now: opts.Now, interval: opts.Interval}
	if s.rbac == nil {
		s.rbac = policy.NewRBAC(opts.Config)
	}
	if s.events == nil {
		s.events = events.Nop{}
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.interval <= 0 {
		s.interval = 30 * time.Second
	}
	return s
}

// Wait blocks until in-flight executions have finished.
func (s *Service) Wait() { s.wg.Wait() }

// ---------------------------------------------------------------------------
// Submission

// SubmitWrite implements gateway.Approvals.
func (s *Service) SubmitWrite(ctx context.Context, sub *gateway.Submission) (*gateway.PendingApproval, error) {
	r, err := s.Submit(ctx, sub)
	if err != nil {
		return nil, err
	}
	approvers, err := s.Approvers(ctx, r)
	if err != nil {
		s.logger.Warn("list approvers failed", "err", err, "request_id", r.ID)
	}
	return &gateway.PendingApproval{ID: r.ID, Approvers: approvers, ExpiresAt: r.ExpiresAt, URL: r.URL}, nil
}

// Submit stores a new approval request for a write evaluated by the
// gateway (the decision must be approve with an approval rule).
func (s *Service) Submit(ctx context.Context, sub *gateway.Submission) (*Request, error) {
	if !s.cfg.Approvals.Enabled {
		return nil, ErrUnavailable
	}
	if sub == nil || sub.Principal == nil || sub.Database == nil || sub.Evaluation == nil || sub.Evaluation.Analysis == nil ||
		!sub.Evaluation.NeedsApproval() || strings.TrimSpace(sub.SQL) == "" {
		return nil, ErrInvalidRequest
	}
	ev, p := sub.Evaluation, sub.Principal
	rule := ev.Decision.ApprovalRule
	now := s.now()
	id := sub.RequestID
	if id == "" {
		id = gateway.NewRequestID()
	}
	r := &Request{
		ID: id, Status: StatusPending,
		Requester: Requester{Kind: p.Kind, Human: p.Human, Agent: p.Agent, ClientID: p.ClientID},
		Database:  sub.Database.Name, SQL: sub.SQL, NormalizedSQL: ev.Analysis.Normalized, Reason: sub.Reason,
		Analysis:     Analysis{Kind: string(ev.Analysis.Statement.Kind), Tables: gateway.TableNames(ev.Analysis)},
		EstimateRows: ev.EstimateRows(), MaxAffectedRows: sub.MaxAffectedRows, Risk: ev.Decision.Risk, ApprovalRule: rule.Name,
		Approvals: []Approval{}, ConfigVersion: s.cfg.Version, CreatedAt: now, ExpiresAt: now.Add(rule.ExpireAfter.D()),
		URL: requestURL(s.cfg.Server.PublicURL, id),
	}
	if r.MaxAffectedRows <= 0 {
		r.MaxAffectedRows = s.cfg.MaxAffectedRows(rule, r.EstimateRows)
	}
	for _, c := range ev.Columns {
		r.Analysis.Columns = append(r.Analysis.Columns, Column{Name: c.Name, Class: c.Class, Usage: c.Usage})
	}
	for _, st := range rule.Steps {
		r.Steps = append(r.Steps, Step{Role: st.Role, Group: st.Group, Count: st.Count})
	}
	r.bindingHash = r.computeHash()

	analysisJSON, _ := json.Marshal(r.Analysis)
	stepsJSON, _ := json.Marshal(r.Steps)
	row := &store.ApprovalRequest{
		ID: r.ID, RequesterKind: p.Kind, RequesterHuman: p.Human, RequesterAgent: p.Agent, RequesterClientID: p.ClientID,
		Database: r.Database, RawSQL: r.SQL, NormalizedSQL: r.NormalizedSQL, Reason: r.Reason, AnalysisJSON: analysisJSON,
		EstimateRows: r.EstimateRows, MaxAffectedRows: r.MaxAffectedRows, Risk: r.Risk, ApprovalRule: r.ApprovalRule,
		StepsJSON: stepsJSON, ApprovalsJSON: []byte("[]"), ConfigVersion: r.ConfigVersion, BindingHash: r.bindingHash,
		Status: StatusPending, CreatedAt: now, ExpiresAt: r.ExpiresAt,
	}
	if err := s.st.CreateApprovalRequest(ctx, row); err != nil {
		return nil, fmt.Errorf("approval: store request: %w", err)
	}
	if err := s.writeAudit(r, "submitted", p.Human, map[string]any{"trace_id": sub.TraceID}, nil); err != nil {
		// Never keep a request whose submission is not audited.
		_ = s.st.TransitionApprovalRequest(context.WithoutCancel(ctx), r.ID, StatusPending, StatusCanceled,
			store.ApprovalTransition{At: now, DecidedBy: "dbgateway", Comment: "audit log unavailable"})
		return nil, err
	}
	approvers, _ := s.Approvers(ctx, r)
	s.publish(ctx, events.ApprovalRequested, r, "", approvers, nil)
	return r, nil
}

// ---------------------------------------------------------------------------
// Reading

// load returns the request without any visibility check.
func (s *Service) load(ctx context.Context, id string) (*Request, error) {
	row, err := s.st.GetApprovalRequest(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return fromStore(row, s.cfg.Server.PublicURL)
}

// Get returns a request if viewer may see it: the requester (the human and
// any of their agents) or a human eligible to approve one of its steps (or
// who already acted on it). Everyone else gets ErrNotFound.
func (s *Service) Get(ctx context.Context, viewer *identity.Principal, id string) (*Request, error) {
	r, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	if !s.canView(viewer, r) {
		return nil, ErrNotFound
	}
	return r, nil
}

// Scope selects which requests List returns.
type Scope string

const (
	// ScopeMine: requests submitted by the viewer's human or their agents.
	ScopeMine Scope = "mine"
	// ScopeAwaitingMe: pending requests whose current step the viewer can
	// approve (humans only).
	ScopeAwaitingMe Scope = "awaiting_me"
	// ScopeDecided: requests that are no longer pending and that the
	// viewer may see.
	ScopeDecided Scope = "decided"
)

// ListFilter narrows List.
type ListFilter struct {
	Scope    Scope // default ScopeMine
	Database string
	Limit    int // default 50, max 200
}

// scanLimit bounds the rows examined for the approver scopes.
const scanLimit = 1000

// List returns requests for viewer, newest first. The raw SQL is omitted.
func (s *Service) List(ctx context.Context, viewer *identity.Principal, f ListFilter) ([]*Request, error) {
	if viewer == nil {
		return nil, ErrNotFound
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 200)
	sf := store.ApprovalFilter{Database: f.Database, Limit: limit}
	keep := func(*Request) bool { return true }
	now := s.now()
	switch f.Scope {
	case "", ScopeMine:
		sf.RequesterHuman = viewer.Human
	case ScopeAwaitingMe:
		if viewer.Kind != identity.KindHuman {
			return []*Request{}, nil
		}
		sf.Statuses, sf.Limit = []Status{StatusPending}, scanLimit
		keep = func(r *Request) bool { return now.Before(r.ExpiresAt) && s.canApproveCurrent(viewer, r) == nil }
	case ScopeDecided:
		sf.Statuses = []Status{StatusApproved, StatusRunning, StatusSucceeded, StatusFailed, StatusRejected, StatusExpired, StatusCanceled}
		sf.Limit = scanLimit
		keep = func(r *Request) bool { return s.canView(viewer, r) }
	default:
		return nil, ErrInvalidRequest
	}
	rows, err := s.st.ListApprovalRequests(ctx, sf)
	if err != nil {
		return nil, err
	}
	out := []*Request{}
	for _, row := range rows {
		r, err := fromStore(row, s.cfg.Server.PublicURL)
		if err != nil {
			s.logger.Error("decode approval request", "err", err)
			continue
		}
		if !keep(r) {
			continue
		}
		r.SQL = ""
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// canView implements the visibility rule of Get.
func (s *Service) canView(viewer *identity.Principal, r *Request) bool {
	if viewer == nil || viewer.Human == "" {
		return false
	}
	if sameHuman(viewer.Human, r.Requester.Human) {
		return true
	}
	if viewer.Kind != identity.KindHuman {
		return false
	}
	if sameHuman(viewer.Human, r.DecidedBy) || slices.ContainsFunc(r.Approvals, func(a Approval) bool { return sameHuman(a.Approver, viewer.Human) }) {
		return true
	}
	db := s.cfg.Database(r.Database)
	for _, st := range r.Steps {
		if s.eligible(viewer.Human, viewer.Groups, db, st) {
			return true
		}
	}
	return false
}

// eligible reports whether the human may approve step on db.
func (s *Service) eligible(email string, groups []string, db *config.Database, st Step) bool {
	if db == nil || email == "" {
		return false
	}
	if st.Group != "" {
		return slices.Contains(groups, st.Group)
	}
	return st.Role != "" && s.rbac.HumanHas(email, groups, db, st.Role)
}

func sameHuman(a, b string) bool { return a != "" && strings.EqualFold(a, b) }

// canApproveCurrent checks every constraint on approving r's current step
// except the step-up and the request state.
func (s *Service) canApproveCurrent(p *identity.Principal, r *Request) error {
	switch {
	case p.Kind != identity.KindHuman:
		return ErrAgent
	case sameHuman(p.Human, r.Requester.Human):
		return ErrSelfApproval
	case slices.ContainsFunc(r.Approvals, func(a Approval) bool { return sameHuman(a.Approver, p.Human) }):
		return ErrAlreadyActed
	case r.CurrentStep >= len(r.Steps):
		return ErrNotPending
	case !s.eligible(p.Human, p.Groups, s.cfg.Database(r.Database), r.Steps[r.CurrentStep]):
		return ErrNotEligible
	}
	return nil
}

// Approvers returns the known users eligible to approve r's next step,
// excluding the requester and those who already approved. Known users are
// the store's users plus the people named in the configuration.
func (s *Service) Approvers(ctx context.Context, r *Request) ([]string, error) {
	if r.CurrentStep >= len(r.Steps) {
		return []string{}, nil
	}
	exclude := []string{r.Requester.Human}
	for _, a := range r.Approvals {
		exclude = append(exclude, a.Approver)
	}
	return s.candidates(ctx, s.cfg.Database(r.Database), r.Steps[r.CurrentStep], exclude)
}

// CandidateApprovers implements gateway.Approvals: who could approve the
// first step of a request by p on db under rule.
func (s *Service) CandidateApprovers(ctx context.Context, p *identity.Principal, db *config.Database, rule *config.ApprovalRule) ([]string, error) {
	if rule == nil || len(rule.Steps) == 0 {
		return []string{}, nil
	}
	st := rule.Steps[0]
	return s.candidates(ctx, db, Step{Role: st.Role, Group: st.Group, Count: st.Count}, []string{p.Human})
}

func (s *Service) candidates(ctx context.Context, db *config.Database, st Step, exclude []string) ([]string, error) {
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	idp := map[string][]string{}
	for _, u := range users {
		idp[strings.ToLower(u.Email)] = u.IDPGroups
	}
	for _, e := range s.rbac.KnownHumans() {
		if _, ok := idp[e]; !ok {
			idp[e] = nil
		}
	}
	out := []string{}
	for email, groups := range idp {
		if slices.ContainsFunc(exclude, func(x string) bool { return sameHuman(x, email) }) {
			continue
		}
		if s.eligible(email, s.rbac.ResolveGroups(email, groups), db, st) {
			out = append(out, email)
		}
	}
	slices.Sort(out)
	return out, nil
}

// groupsOf resolves a human's dbgateway groups from the IdP groups
// snapshot of their last login and the current configuration.
func (s *Service) groupsOf(ctx context.Context, email string) ([]string, error) {
	var idpGroups []string
	u, err := s.st.GetUser(ctx, email)
	switch {
	case err == nil:
		idpGroups = u.IDPGroups
	case errors.Is(err, store.ErrNotFound):
	default:
		return nil, err
	}
	return s.rbac.ResolveGroups(email, idpGroups), nil
}

// ---------------------------------------------------------------------------
// Audit and events

// writeAudit records a state change of r (event "approval"). actor is the
// human who caused it, or "dbgateway".
func (s *Service) writeAudit(r *Request, action, actor string, extra map[string]any, result *audit.ResultInfo) error {
	if s.audit == nil {
		return errors.New("approval: no audit log configured")
	}
	sql := r.NormalizedSQL
	if s.cfg.Audit.LogRawSQL {
		sql = r.SQL
	}
	x := map[string]any{"action": action, "status": string(r.Status), "actor": actor, "approval_rule": r.ApprovalRule, "risk": r.Risk}
	for k, v := range extra {
		x[k] = v
	}
	e := &audit.Entry{
		RequestID: r.ID, Event: "approval",
		Principal: audit.PrincipalInfo{Kind: string(r.Requester.Kind), Human: r.Requester.Human, Agent: r.Requester.Agent, ClientID: r.Requester.ClientID},
		Database:  r.Database, SQL: sql, SQLSHA256: sha256Hex(r.SQL), Reason: r.Reason,
		Decision: config.ActionApprove, Stage: "approval", ConfigVersion: s.cfg.Version, Result: result, Extra: x,
	}
	if err := s.audit.Write(e); err != nil {
		s.logger.Error("audit write failed", "err", err, "request_id", r.ID, "action", action)
		return fmt.Errorf("approval: audit: %w", err)
	}
	return nil
}

// publish emits an event about r. Only the normalized SQL is included.
func (s *Service) publish(ctx context.Context, t events.Type, r *Request, actor string, approvers []string, detail map[string]string) {
	est := r.EstimateRows
	e := events.Event{
		Type: t, Time: s.now(), RequestID: r.ID, Database: r.Database,
		Principal: &events.Principal{Kind: string(r.Requester.Kind), Human: r.Requester.Human, Agent: r.Requester.Agent, ClientID: r.Requester.ClientID},
		SQL:       r.NormalizedSQL, Tables: r.Analysis.Tables, EstimateRows: &est, Reason: r.Reason, Status: string(r.Status),
		Approvers: approvers, Actor: actor, URL: r.URL,
		Detail: map[string]string{"risk": r.Risk, "approval_rule": r.ApprovalRule, "max_affected_rows": fmt.Sprint(r.MaxAffectedRows)},
	}
	if db := s.cfg.Database(r.Database); db != nil {
		e.Labels = db.Labels
	}
	for k, v := range detail {
		e.Detail[k] = v
	}
	s.events.Publish(context.WithoutCancel(ctx), e)
}
