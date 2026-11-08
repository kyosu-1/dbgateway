package approval

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

const testYAML = `
server: { public_url: "https://dbgw.example.com" }
auth: { dev_login: true }
approvals: { enabled: true }
databases:
  - name: prod
    labels: { env: prod }
    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }
groups:
  - { name: dev, members: [taro@example.com, jiro@example.com] }
  - { name: sre, members: [hanako@example.com, ken@example.com] }
  - { name: dba, members: [dba@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier, writer] }
  - { group: sre, databases: "*", roles: [querier, writer, approver] }
data_classes:
  - { columns: [public.users.email], class: masked }
  - { column_pattern: "public\\.users\\.(id|plan|name)", class: public }
risk:
  high: ['stmt.is_write && estimate.rows > 100']
  medium: ['stmt.is_write']
approval_rules:
  - name: two-step
    when: risk == "high"
    steps: [{ role: approver }, { group: dba }]
    expire_after: 2h
  - name: default
    when: "true"
    steps: [{ role: approver }]
    expire_after: 30m
break_glass:
  max_duration: 1h
  databases: [prod]
`

var (
	taroAgent = &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude-code", ClientID: "c1",
		Groups: []string{"dev"}, Scopes: []string{identity.ScopeRead, identity.ScopeWrite}}
	taro       = &identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Groups: []string{"dev"}}
	jiro       = &identity.Principal{Kind: identity.KindHuman, Human: "jiro@example.com", Groups: []string{"dev"}}
	hanako     = &identity.Principal{Kind: identity.KindHuman, Human: "hanako@example.com", Groups: []string{"sre"}}
	ken        = &identity.Principal{Kind: identity.KindHuman, Human: "ken@example.com", Groups: []string{"sre"}}
	dba        = &identity.Principal{Kind: identity.KindHuman, Human: "dba@example.com", Groups: []string{"dba"}}
	hanakoAgnt = &identity.Principal{Kind: identity.KindAgent, Human: "hanako@example.com", Agent: "claude-code",
		Groups: []string{"sre"}, Scopes: []string{identity.ScopeRead, identity.ScopeWrite}}
)

type recorder struct {
	mu  sync.Mutex
	evs []events.Event
}

func (r *recorder) Publish(_ context.Context, e events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, e)
}

func (r *recorder) types() []events.Type {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.Type
	for _, e := range r.evs {
		out = append(out, e.Type)
	}
	return out
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	t     *testing.T
	cfg   *config.Config
	gw    *gateway.Gateway
	svc   *Service
	st    store.Store
	fa    *gatewaytest.Adapter
	rec   *recorder
	clock *clock
	dir   string
}

func newEnv(t *testing.T, yaml string) *env {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, fa: gatewaytest.New(), clock: &clock{t: time.Now()}}
	// Every test statement returns (id, email).
	e.fa.Result = analysis.Result{Columns: []analysis.ResultColumn{{Name: "id", Type: "int8"}, {Name: "email", Type: "text"}},
		Rows: [][]any{{int64(1), "user1@example.com"}}}
	e.build(yaml)
	return e
}

// build (re)creates the gateway and service for a configuration, keeping
// the store, the fake database and the clock.
func (e *env) build(yaml string) {
	t := e.t
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	e.dir = t.TempDir()
	sink, err := audit.OpenFileSink(e.dir, 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.New(sink)
	if err != nil {
		t.Fatal(err)
	}
	e.rec = &recorder{}
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": e.fa}, Audit: al, Events: e.rec})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = New(Options{Config: cfg, Store: e.st, Executor: gw, Audit: al, Events: e.rec, Now: e.clock.Now, Logger: slog.New(slog.DiscardHandler)})
	gw.SetApprovals(e.svc)
	t.Cleanup(func() { e.svc.Wait(); gw.Close(); _ = al.Close() })
	e.cfg, e.gw = cfg, gw
}

func (e *env) submit(p *identity.Principal, sql string) *gateway.ExecuteResponse {
	e.t.Helper()
	r := e.gw.ExecuteSQL(context.Background(), p, gateway.ExecuteRequest{Database: "prod", SQL: sql, Reason: "support ticket #1234: fix plan"})
	if r.Status != gateway.StatusPending {
		e.t.Fatalf("submit %q: %s %s %s %s", sql, r.Status, r.Rule, r.Reason, r.Hint)
	}
	return r
}

func (e *env) stepUp() StepUp { return StepUp{Method: "passkey", At: e.clock.Now().Add(-time.Minute)} }

func (e *env) get(id string) *Request {
	e.t.Helper()
	e.svc.Wait()
	r, err := e.svc.load(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

const update = "UPDATE users SET plan = 'pro' WHERE id = 1 RETURNING id, email"

func TestSubmitApproveExecute(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	e.fa.Set(func(a *gatewaytest.Adapter) {
		a.EstimateRows = 1
		a.Result = analysis.Result{Columns: []analysis.ResultColumn{{Name: "id", Type: "int8"}, {Name: "email", Type: "text"}},
			Rows: [][]any{{int64(1), "user1@example.com"}}}
	})
	resp := e.submit(taroAgent, update)
	if !slices.Equal(resp.Approvers, []string{"hanako@example.com", "ken@example.com"}) || resp.ApprovalURL != "https://dbgw.example.com/approvals/"+resp.RequestID ||
		resp.ExpiresAt == nil || resp.ApprovalRule != "default" || resp.Risk != "medium" || resp.MaxAffectedRows != 2 {
		t.Fatalf("pending response: %+v", resp)
	}
	if len(e.fa.Writes()) != 0 {
		t.Fatal("must not execute before approval")
	}

	// Visibility: requester (human and agent) and approvers; others get "not found".
	for _, p := range []*identity.Principal{taro, taroAgent, hanako, ken} {
		if _, err := e.svc.Get(ctx, p, resp.RequestID); err != nil {
			t.Errorf("%s/%s: %v", p.Human, p.Kind, err)
		}
	}
	for _, p := range []*identity.Principal{jiro, dba, hanakoAgnt, nil} {
		if _, err := e.svc.Get(ctx, p, resp.RequestID); !errors.Is(err, ErrNotFound) {
			t.Errorf("%v: want ErrNotFound, got %v", p, err)
		}
	}
	if _, err := e.svc.Get(ctx, hanako, "req_nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v", err)
	}

	r, err := e.svc.Approve(ctx, ken, resp.RequestID, e.stepUp())
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusApproved || r.CurrentStep != 1 || r.Approvals[0].Approver != "ken@example.com" || r.Approvals[0].StepUpMethod != "passkey" {
		t.Fatalf("approved: %+v", r)
	}
	r = e.get(resp.RequestID)
	if r.Status != StatusSucceeded || r.Result == nil || r.Result.RowsAffected != 1 || r.StartedAt == nil || r.FinishedAt == nil {
		t.Fatalf("executed: %+v %+v", r, r.Result)
	}
	// RETURNING rows are masked as for the requester (an agent).
	if r.Result.Rows[0][1] == "user1@example.com" || !r.Result.Columns[1].Masked {
		t.Fatalf("RETURNING not masked: %+v", r.Result)
	}
	w := e.fa.Writes()
	if len(w) != 1 || w[0].SQL != update || w[0].Opts.MaxAffectedRows != 2 || w[0].Opts.ReadOnly {
		t.Fatalf("writes: %+v", w)
	}
	// One-time use: a second claim does nothing.
	if e.svc.execute(ctx, resp.RequestID) {
		t.Fatal("an executed request was claimed again")
	}
	if _, err := e.svc.Approve(ctx, hanako, resp.RequestID, e.stepUp()); !errors.Is(err, ErrNotPending) {
		t.Fatalf("approve after execution: %v", err)
	}
	if got := e.rec.types(); !slices.Equal(got, []events.Type{events.ApprovalRequested, events.ApprovalDecided, events.ExecutionFinished}) {
		t.Fatalf("events = %v", got)
	}
	for _, ev := range e.rec.evs {
		if strings.Contains(ev.SQL, "'pro'") || ev.SQL == "" || ev.RequestID != resp.RequestID || ev.Principal.Agent != "claude-code" {
			t.Errorf("event %+v", ev)
		}
	}
	rep, err := audit.VerifyDir(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	// query (approve) + submitted + approved + running + succeeded
	if rep.Entries != 5 {
		t.Errorf("audit entries = %d, want 5", rep.Entries)
	}
}

func TestApprovalConstraints(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	id := e.submit(taroAgent, update).RequestID

	cases := []struct {
		name string
		p    *identity.Principal
		su   StepUp
		want error
	}{
		{"agent cannot approve", hanakoAgnt, e.stepUp(), ErrAgent},
		{"requester's own human cannot approve an agent request", taro, e.stepUp(), ErrSelfApproval},
		{"not an approver", jiro, e.stepUp(), ErrNotFound},
		{"missing step-up", hanako, StepUp{}, ErrStepUpRequired},
		{"step-up without method", hanako, StepUp{At: e.clock.Now()}, ErrStepUpRequired},
		{"old step-up", hanako, StepUp{Method: "passkey", At: e.clock.Now().Add(-6 * time.Minute)}, ErrStepUpRequired},
		{"step-up from the future", hanako, StepUp{Method: "passkey", At: e.clock.Now().Add(time.Hour)}, ErrStepUpRequired},
	}
	for _, c := range cases {
		if _, err := e.svc.Approve(ctx, c.p, id, c.su); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	if r := e.get(id); r.Status != StatusPending || len(r.Approvals) != 0 {
		t.Fatalf("state changed: %+v", r)
	}

	// A human approver cannot approve their own request.
	own := e.submit(hanako, update).RequestID
	if _, err := e.svc.Approve(ctx, hanako, own, e.stepUp()); !errors.Is(err, ErrSelfApproval) {
		t.Errorf("own request: %v", err)
	}
	if len(e.fa.Writes()) != 0 {
		t.Fatal("nothing must be executed")
	}
}

func TestTwoStepApproval(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	e.fa.Set(func(a *gatewaytest.Adapter) { a.EstimateRows = 500; a.Affected = 400 })
	resp := e.submit(taroAgent, "UPDATE users SET plan = 'pro' WHERE id > 1 RETURNING id, email")
	if resp.ApprovalRule != "two-step" || resp.Risk != "high" || resp.MaxAffectedRows != 1000 {
		t.Fatalf("pending: %+v", resp)
	}
	id := resp.RequestID
	// The step-2 group member can see the request but not approve step 1.
	if _, err := e.svc.Approve(ctx, dba, id, e.stepUp()); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("dba at step 1: %v", err)
	}
	r, err := e.svc.Approve(ctx, hanako, id, e.stepUp())
	if err != nil || r.Status != StatusPending || r.CurrentStep != 1 {
		t.Fatalf("step 1: %+v %v", r, err)
	}
	if approvers, _ := e.svc.Approvers(ctx, r); !slices.Equal(approvers, []string{"dba@example.com"}) {
		t.Fatalf("step 2 approvers: %v", approvers)
	}
	if _, err := e.svc.Approve(ctx, hanako, id, e.stepUp()); !errors.Is(err, ErrAlreadyActed) {
		t.Fatalf("same person twice: %v", err)
	}
	if _, err := e.svc.Approve(ctx, ken, id, e.stepUp()); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("approver at the dba step: %v", err)
	}
	if len(e.fa.Writes()) != 0 {
		t.Fatal("executed before the last step")
	}
	if r, err = e.svc.Approve(ctx, dba, id, e.stepUp()); err != nil || r.Status != StatusApproved {
		t.Fatalf("step 2: %+v %v", r, err)
	}
	if r = e.get(id); r.Status != StatusSucceeded || r.Result.RowsAffected != 400 || len(r.Approvals) != 2 {
		t.Fatalf("result: %+v", r)
	}
}

func TestExpiry(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	a := e.submit(taroAgent, update).RequestID
	b := e.submit(taroAgent, update).RequestID
	e.clock.Add(31 * time.Minute)
	if _, err := e.svc.Approve(ctx, hanako, a, e.stepUp()); !errors.Is(err, ErrExpired) {
		t.Fatalf("approve expired: %v", err)
	}
	if r := e.get(a); r.Status != StatusExpired || r.DecidedAt == nil {
		t.Fatalf("a: %+v", r)
	}
	e.svc.Sweep(ctx)
	if r := e.get(b); r.Status != StatusExpired {
		t.Fatalf("b after sweep: %+v", r)
	}
	if len(e.fa.Writes()) != 0 {
		t.Fatal("expired requests must not execute")
	}
}

func TestCancelAndReject(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	id := e.submit(taroAgent, update).RequestID
	if _, err := e.svc.Cancel(ctx, hanako, id); !errors.Is(err, ErrNotRequester) {
		t.Fatalf("approver cancel: %v", err)
	}
	if _, err := e.svc.Cancel(ctx, jiro, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger cancel: %v", err)
	}
	r, err := e.svc.Cancel(ctx, taro, id) // the human may cancel their agent's request
	if err != nil || r.Status != StatusCanceled || r.DecidedBy != "taro@example.com" {
		t.Fatalf("cancel: %+v %v", r, err)
	}
	if _, err := e.svc.Approve(ctx, hanako, id, e.stepUp()); !errors.Is(err, ErrNotPending) {
		t.Fatalf("approve canceled: %v", err)
	}

	id = e.submit(taroAgent, update).RequestID
	if _, err := e.svc.Reject(ctx, taro, id, "no"); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("self reject: %v", err)
	}
	if _, err := e.svc.Reject(ctx, hanakoAgnt, id, "no"); !errors.Is(err, ErrAgent) {
		t.Fatalf("agent reject: %v", err)
	}
	r, err = e.svc.Reject(ctx, ken, id, "The scope is too broad")
	if err != nil || r.Status != StatusRejected || r.DecidedBy != "ken@example.com" || r.Comment != "The scope is too broad" {
		t.Fatalf("reject: %+v %v", r, err)
	}
	if _, err := e.svc.Cancel(ctx, taroAgent, id); !errors.Is(err, ErrNotPending) {
		t.Fatalf("cancel rejected: %v", err)
	}
	if len(e.fa.Writes()) != 0 {
		t.Fatal("nothing must execute")
	}
}

func TestConcurrentApprovalExecutesOnce(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	id := e.submit(taroAgent, update).RequestID
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, p := range []*identity.Principal{hanako, ken} {
		wg.Go(func() { _, errs[i] = e.svc.Approve(ctx, p, id, e.stepUp()) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrNotPending):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("successful approvals = %d (%v)", ok, errs)
	}
	// Concurrent claims and sweeps must not re-run it.
	for range 4 {
		wg.Go(func() { e.svc.execute(ctx, id) })
	}
	wg.Wait()
	e.svc.Sweep(ctx)
	if r := e.get(id); r.Status != StatusSucceeded {
		t.Fatalf("status %s", r.Status)
	}
	if n := len(e.fa.Writes()); n != 1 {
		t.Fatalf("writes = %d, want 1", n)
	}
}

// tamperStore changes the SQL of a request once it has been approved, as
// if someone edited the management database.
type tamperStore struct {
	store.Store
	mu      sync.Mutex
	pending bool // tamper pending requests too
}

func (s *tamperStore) GetApprovalRequest(ctx context.Context, id string) (*store.ApprovalRequest, error) {
	r, err := s.Store.GetApprovalRequest(ctx, id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil && (r.Status == store.ApprovalRunning || s.pending) {
		r.RawSQL = "UPDATE users SET plan = 'pro'"
	}
	return r, err
}

func TestBindingHashMismatch(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	ts := &tamperStore{Store: e.st}
	e.svc.st = ts
	id := e.submit(taroAgent, update).RequestID
	if _, err := e.svc.Approve(ctx, hanako, id, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	r := e.get(id)
	if r.Status != StatusFailed || !strings.Contains(r.Result.Error, "binding hash") {
		t.Fatalf("tampered after approval: %+v %+v", r, r.Result)
	}
	if len(e.fa.Writes()) != 0 {
		t.Fatal("a tampered request was executed")
	}

	// Tampered while pending: approval refuses and closes the request.
	id = e.submit(taroAgent, update).RequestID
	ts.mu.Lock()
	ts.pending = true
	ts.mu.Unlock()
	if _, err := e.svc.Approve(ctx, hanako, id, e.stepUp()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered pending: %v", err)
	}
	if r := e.get(id); r.Status != StatusRejected || r.DecidedBy != "dbgateway" {
		t.Fatalf("tampered pending state: %+v", r)
	}
}

func TestDecisionChangedBeforeExecution(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	id := e.submit(taroAgent, update).RequestID

	// The policy now denies writes to users.
	e.build(strings.Replace(testYAML, "risk:", `policies:
  - { name: freeze, when: 'stmt.is_write', action: deny, message: "Change freeze in effect" }
risk:`, 1))
	if _, err := e.svc.Approve(ctx, hanako, id, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	r := e.get(id)
	if r.Status != StatusFailed || !strings.Contains(r.Result.Error, "decision has changed") || !strings.Contains(r.Result.Error, "freeze") {
		t.Fatalf("policy change: %+v %+v", r, r.Result)
	}

	// The requester lost the writer role.
	e.build(testYAML)
	id = e.submit(taroAgent, update).RequestID
	e.build(strings.Replace(testYAML, "{ group: dev, databases: \"*\", roles: [querier, writer] }", "{ group: dev, databases: \"*\", roles: [querier] }", 1))
	if _, err := e.svc.Approve(ctx, hanako, id, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	r = e.get(id)
	if r.Status != StatusFailed || !strings.Contains(r.Result.Error, "role:writer") {
		t.Fatalf("role change: %+v %+v", r, r.Result)
	}

	// The approval rule changed (a different rule would match now).
	e.build(testYAML)
	id = e.submit(taroAgent, update).RequestID
	e.build(strings.Replace(testYAML, "name: default", "name: renamed", 1))
	if _, err := e.svc.Approve(ctx, hanako, id, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	if r = e.get(id); r.Status != StatusFailed || !strings.Contains(r.Result.Error, "renamed") {
		t.Fatalf("rule change: %+v %+v", r, r.Result)
	}
	if len(e.fa.Writes()) != 0 {
		t.Fatal("nothing must execute when the decision changed")
	}
}

func TestMaxAffectedRowsRollback(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	e.fa.Set(func(a *gatewaytest.Adapter) { a.EstimateRows = 1; a.Affected = 5 })
	id := e.submit(taroAgent, update).RequestID
	if _, err := e.svc.Approve(ctx, hanako, id, e.stepUp()); err != nil {
		t.Fatal(err)
	}
	r := e.get(id)
	if r.Status != StatusFailed || !strings.Contains(r.Result.Error, "5 rows") || !strings.Contains(r.Result.Error, "2 rows") {
		t.Fatalf("got %+v %+v", r, r.Result)
	}
}

func TestBreakGlass(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	su := e.stepUp()
	if _, err := e.svc.Elevate(ctx, taro, []string{"prod"}, "incident #1", 0, su); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("non-approver: %v", err)
	}
	if _, err := e.svc.Elevate(ctx, hanakoAgnt, []string{"prod"}, "incident #1", 0, su); !errors.Is(err, ErrAgent) {
		t.Fatalf("agent: %v", err)
	}
	if _, err := e.svc.Elevate(ctx, hanako, []string{"prod"}, "incident #1", 0, StepUp{}); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("no step-up: %v", err)
	}
	if _, err := e.svc.Elevate(ctx, hanako, []string{"prod"}, " ", 0, su); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := e.svc.Elevate(ctx, hanako, []string{"prod"}, "incident #1", 2*time.Hour, su); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("too long: %v", err)
	}
	if _, err := e.svc.Elevate(ctx, hanako, []string{"nope"}, "incident #1", 0, su); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("unknown database: %v", err)
	}
	if e.svc.ElevationActive(ctx, hanako, "prod") {
		t.Fatal("not elevated yet")
	}
	g, err := e.svc.Elevate(ctx, hanako, []string{"prod"}, "incident #1", 30*time.Minute, su)
	if err != nil || g.Human != "hanako@example.com" || !g.ExpiresAt.Equal(e.clock.Now().Add(30*time.Minute)) {
		t.Fatalf("elevate: %+v %v", g, err)
	}
	if !e.svc.ElevationActive(ctx, hanako, "prod") || e.svc.ElevationActive(ctx, hanakoAgnt, "prod") || e.svc.ElevationActive(ctx, ken, "prod") {
		t.Fatal("ElevationActive")
	}
	if !slices.Contains(e.rec.types(), events.BreakGlassUsed) {
		t.Fatalf("events: %v", e.rec.types())
	}

	r := e.gw.ExecuteSQL(ctx, hanako, gateway.ExecuteRequest{Database: "prod", SQL: update, Reason: "incident #1: fix plan"})
	if r.Status != gateway.StatusOK || !r.BreakGlass || r.RowsAffected == nil || *r.RowsAffected != 1 {
		t.Fatalf("break-glass write: %+v", r)
	}
	// Policy and affected-row limits still apply.
	e.fa.Set(func(a *gatewaytest.Adapter) { a.Affected = 50 })
	r = e.gw.ExecuteSQL(ctx, hanako, gateway.ExecuteRequest{Database: "prod", SQL: update, Reason: "incident #1: fix plan"})
	if r.Status != gateway.StatusError || !strings.Contains(r.Reason, "Rolled back") {
		t.Fatalf("break-glass limit: %+v", r)
	}
	if r := e.gw.ExecuteSQL(ctx, hanako, gateway.ExecuteRequest{Database: "prod", SQL: "DROP TABLE users", Reason: "incident #1: fix plan"}); r.Status != gateway.StatusDenied {
		t.Fatalf("break-glass ddl: %+v", r)
	}
	// Agents never use break-glass.
	e.fa.Set(func(a *gatewaytest.Adapter) { a.Affected = 1 })
	e.submit(hanakoAgnt, update)

	e.clock.Add(31 * time.Minute)
	if e.svc.ElevationActive(ctx, hanako, "prod") {
		t.Fatal("elevation must expire")
	}
	if n := len(e.fa.Writes()); n != 2 {
		t.Fatalf("writes = %d", n)
	}
}

func TestStaleRunningMarkedFailed(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	ts := &blockingExecutor{}
	e.svc.exec = ts
	id := e.submit(taroAgent, update).RequestID
	// Simulate a crash after the claim: approved → running, nothing else.
	now := e.clock.Now()
	if err := e.st.UpdateApprovals(ctx, id, 0, []byte(`[]`), store.ApprovalApproved, &now); err != nil {
		t.Fatal(err)
	}
	if err := e.st.TransitionApprovalRequest(ctx, id, store.ApprovalApproved, store.ApprovalRunning, store.ApprovalTransition{At: now}); err != nil {
		t.Fatal(err)
	}
	e.svc.Sweep(ctx)
	if r := e.get(id); r.Status != StatusRunning {
		t.Fatalf("fresh running request touched: %s", r.Status)
	}
	e.clock.Add(5 * time.Minute)
	e.svc.Sweep(ctx)
	r := e.get(id)
	if r.Status != StatusFailed || !strings.Contains(r.Result.Error, "result is unknown") {
		t.Fatalf("stale: %+v %+v", r, r.Result)
	}
	if ts.calls != 0 {
		t.Fatal("a stale request must never be re-run")
	}
}

type blockingExecutor struct{ calls int }

func (b *blockingExecutor) ExecuteApproved(context.Context, *identity.Principal, gateway.ApprovedWrite) (*gateway.WriteResult, error) {
	b.calls++
	return nil, errors.New("unexpected")
}

func TestResumeApprovedOnSweep(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	id := e.submit(taroAgent, update).RequestID
	now := e.clock.Now()
	// Approved, but the process stopped before starting the execution.
	if err := e.st.UpdateApprovals(ctx, id, 0, []byte(`[]`), store.ApprovalApproved, &now); err != nil {
		t.Fatal(err)
	}
	e.svc.Sweep(ctx)
	if r := e.get(id); r.Status != StatusSucceeded {
		t.Fatalf("status %s", r.Status)
	}
}

func TestList(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	a := e.submit(taroAgent, update).RequestID
	b := e.submit(hanako, update).RequestID
	c := e.submit(taro, update).RequestID
	if _, err := e.svc.Reject(ctx, ken, c, ""); err != nil {
		t.Fatal(err)
	}
	ids := func(rs []*Request, err error) []string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rs {
			if r.SQL != "" {
				t.Errorf("list must not carry raw SQL: %s", r.SQL)
			}
			out = append(out, r.ID)
		}
		slices.Sort(out)
		return out
	}
	sorted := func(v ...string) []string { slices.Sort(v); return v }
	if got := ids(e.svc.List(ctx, taroAgent, ListFilter{})); !slices.Equal(got, sorted(a, c)) {
		t.Errorf("mine (agent): %v", got)
	}
	if got := ids(e.svc.List(ctx, ken, ListFilter{Scope: ScopeAwaitingMe})); !slices.Equal(got, sorted(a, b)) {
		t.Errorf("awaiting ken: %v", got)
	}
	if got := ids(e.svc.List(ctx, hanako, ListFilter{Scope: ScopeAwaitingMe})); !slices.Equal(got, sorted(a)) {
		t.Errorf("awaiting hanako (not her own): %v", got)
	}
	if got := ids(e.svc.List(ctx, hanakoAgnt, ListFilter{Scope: ScopeAwaitingMe})); len(got) != 0 {
		t.Errorf("agents await nothing: %v", got)
	}
	if got := ids(e.svc.List(ctx, hanako, ListFilter{Scope: ScopeDecided})); !slices.Equal(got, sorted(c)) {
		t.Errorf("decided: %v", got)
	}
	if got := ids(e.svc.List(ctx, jiro, ListFilter{Scope: ScopeDecided})); len(got) != 0 {
		t.Errorf("decided for a stranger: %v", got)
	}
	if _, err := e.svc.List(ctx, jiro, ListFilter{Scope: "bogus"}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("bad scope: %v", err)
	}
}

func TestExplainPolicyListsApprovers(t *testing.T) {
	e := newEnv(t, testYAML)
	resp, err := e.gw.ExplainPolicy(context.Background(), taroAgent, gateway.ExplainRequest{Database: "prod", SQL: update})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != config.ActionApprove || resp.ApprovalRule != "default" || !slices.Equal(resp.Approvers, []string{"hanako@example.com", "ken@example.com"}) ||
		len(resp.Output) != 2 || !resp.Output[1].Masked || resp.BreakGlass {
		t.Fatalf("explain: %+v", resp)
	}
	if len(e.fa.Execs()) != 0 {
		t.Fatal("explain must not execute")
	}
}

func TestApproversIncludeStoreUsers(t *testing.T) {
	yaml := strings.Replace(testYAML, "groups:\n", "groups:\n  - { name: oncall, oidc_group: oncall }\n", 1)
	yaml = strings.Replace(yaml, "role_bindings:\n", "role_bindings:\n  - { group: oncall, databases: \"*\", roles: [approver] }\n", 1)
	e := newEnv(t, yaml)
	ctx := context.Background()
	// Known through the IdP groups snapshot of their last login only.
	if err := e.st.UpsertUser(ctx, &store.User{Email: "oncall@example.com", IDPGroups: []string{"oncall"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.UpsertUser(ctx, &store.User{Email: "other@example.com", IDPGroups: []string{"marketing"}}); err != nil {
		t.Fatal(err)
	}
	resp := e.submit(taroAgent, update)
	if !slices.Equal(resp.Approvers, []string{"hanako@example.com", "ken@example.com", "oncall@example.com"}) {
		t.Fatalf("approvers = %v", resp.Approvers)
	}
	oncall := &identity.Principal{Kind: identity.KindHuman, Human: "oncall@example.com", Groups: []string{"oncall"}}
	if _, err := e.svc.Approve(ctx, oncall, resp.RequestID, e.stepUp()); err != nil {
		t.Fatal(err)
	}
}
