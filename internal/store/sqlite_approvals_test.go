package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

func newApproval(id string, now time.Time) *ApprovalRequest {
	return &ApprovalRequest{
		ID: id, RequesterKind: identity.KindAgent, RequesterHuman: "taro@example.com", RequesterAgent: "claude-code",
		RequesterClientID: "client-1", Database: "prod-main", RawSQL: "UPDATE users SET plan = 'pro' WHERE id = 1",
		NormalizedSQL: "UPDATE users SET plan = $1 WHERE id = $2", Reason: "support ticket #1",
		AnalysisJSON: []byte(`{"kind":"update"}`), EstimateRows: 1, MaxAffectedRows: 2, Risk: "medium",
		ApprovalRule: "prod-default", StepsJSON: []byte(`[{"role":"approver","count":1}]`), ConfigVersion: "abc",
		BindingHash: "hash", Status: ApprovalPending, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func TestApprovalRequestRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.UnixMilli(time.Now().UnixMilli())
	r := newApproval("req_1", now)
	if err := s.CreateApprovalRequest(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateApprovalRequest(ctx, r); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	got, err := s.GetApprovalRequest(ctx, "req_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.RawSQL != r.RawSQL || got.RequesterKind != identity.KindAgent || string(got.ApprovalsJSON) != "[]" ||
		got.ResultJSON != nil || !got.ExpiresAt.Equal(r.ExpiresAt) || got.DecidedAt != nil || got.MaxAffectedRows != 2 {
		t.Fatalf("got %+v", got)
	}
	if _, err := s.GetApprovalRequest(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestListApprovalRequests(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	for i, id := range []string{"req_a", "req_b", "req_c"} {
		r := newApproval(id, now.Add(time.Duration(i)*time.Second))
		if id == "req_c" {
			r.RequesterHuman, r.Database, r.ExpiresAt = "hanako@example.com", "staging", now.Add(-time.Minute)
		}
		if err := s.CreateApprovalRequest(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.ListApprovalRequests(ctx, ApprovalFilter{})
	if err != nil || len(all) != 3 || all[0].ID != "req_c" {
		t.Fatalf("all = %v, %v", ids(all), err)
	}
	mine, _ := s.ListApprovalRequests(ctx, ApprovalFilter{RequesterHuman: "taro@example.com"})
	if len(mine) != 2 {
		t.Fatalf("mine = %v", ids(mine))
	}
	expired, _ := s.ListApprovalRequests(ctx, ApprovalFilter{Statuses: []ApprovalStatus{ApprovalPending}, ExpiresBefore: now})
	if len(expired) != 1 || expired[0].ID != "req_c" {
		t.Fatalf("expired = %v", ids(expired))
	}
	limited, _ := s.ListApprovalRequests(ctx, ApprovalFilter{Database: "prod-main", Limit: 1})
	if len(limited) != 1 || limited[0].ID != "req_b" {
		t.Fatalf("limited = %v", ids(limited))
	}
	none, _ := s.ListApprovalRequests(ctx, ApprovalFilter{Statuses: []ApprovalStatus{ApprovalSucceeded, ApprovalFailed}})
	if len(none) != 0 {
		t.Fatalf("none = %v", ids(none))
	}
}

func ids(rs []*ApprovalRequest) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func TestUpdateApprovalsOptimisticConcurrency(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	if err := s.CreateApprovalRequest(ctx, newApproval("req_1", now)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateApprovals(ctx, "req_1", 0, []byte(`[{"approver":"a"}]`), ApprovalPending, nil); err != nil {
		t.Fatal(err)
	}
	// A second writer that read version 0 loses.
	if err := s.UpdateApprovals(ctx, "req_1", 0, []byte(`[{"approver":"b"}]`), ApprovalApproved, &now); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if err := s.UpdateApprovals(ctx, "req_1", 1, []byte(`[{"approver":"a"},{"approver":"b"}]`), ApprovalApproved, &now); err != nil {
		t.Fatal(err)
	}
	r, _ := s.GetApprovalRequest(ctx, "req_1")
	if r.Status != ApprovalApproved || r.Version != 2 || r.DecidedAt == nil || string(r.ApprovalsJSON) != `[{"approver":"a"},{"approver":"b"}]` {
		t.Fatalf("got %+v", r)
	}
	// Not pending any more.
	if err := s.UpdateApprovals(ctx, "req_1", 2, []byte(`[]`), ApprovalPending, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("not pending: %v", err)
	}
	if err := s.UpdateApprovals(ctx, "nope", 0, []byte(`[]`), ApprovalPending, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.UpdateApprovals(ctx, "req_1", 2, []byte(`[]`), ApprovalRunning, nil); err == nil {
		t.Fatal("invalid status accepted")
	}
}

func TestTransitionApprovalRequest(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	s.CreateApprovalRequest(ctx, newApproval("req_1", now))
	if err := s.TransitionApprovalRequest(ctx, "req_1", ApprovalApproved, ApprovalRunning, ApprovalTransition{At: now}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong from: %v", err)
	}
	if err := s.TransitionApprovalRequest(ctx, "req_1", ApprovalPending, ApprovalRejected,
		ApprovalTransition{At: now, DecidedBy: "hanako@example.com", Comment: "too broad"}); err != nil {
		t.Fatal(err)
	}
	r, _ := s.GetApprovalRequest(ctx, "req_1")
	if r.Status != ApprovalRejected || r.DecidedBy != "hanako@example.com" || r.Comment != "too broad" || r.DecidedAt == nil {
		t.Fatalf("got %+v", r)
	}
	if err := s.TransitionApprovalRequest(ctx, "req_1", ApprovalPending, ApprovalCanceled, ApprovalTransition{At: now}); !errors.Is(err, ErrConflict) {
		t.Fatalf("final state changed: %v", err)
	}
	if err := s.TransitionApprovalRequest(ctx, "nope", ApprovalPending, ApprovalCanceled, ApprovalTransition{At: now}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.TransitionApprovalRequest(ctx, "req_1", ApprovalRejected, ApprovalPending, ApprovalTransition{At: now}); err == nil {
		t.Fatal("transition back to pending accepted")
	}

	s.CreateApprovalRequest(ctx, newApproval("req_2", now))
	s.UpdateApprovals(ctx, "req_2", 0, []byte(`[]`), ApprovalApproved, &now)
	s.TransitionApprovalRequest(ctx, "req_2", ApprovalApproved, ApprovalRunning, ApprovalTransition{At: now})
	if err := s.TransitionApprovalRequest(ctx, "req_2", ApprovalRunning, ApprovalSucceeded,
		ApprovalTransition{At: now, Result: []byte(`{"rows_affected":1}`)}); err != nil {
		t.Fatal(err)
	}
	r, _ = s.GetApprovalRequest(ctx, "req_2")
	if r.Status != ApprovalSucceeded || r.StartedAt == nil || r.FinishedAt == nil || string(r.ResultJSON) != `{"rows_affected":1}` {
		t.Fatalf("got %+v", r)
	}
}

// Only one of many concurrent workers may claim an approved request.
func TestTransitionConcurrentClaim(t *testing.T) {
	ctx := context.Background()
	s, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "dbgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.CreateApprovalRequest(ctx, newApproval("req_1", now))
	if err := s.UpdateApprovals(ctx, "req_1", 0, []byte(`[]`), ApprovalApproved, &now); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			err := s.TransitionApprovalRequest(ctx, "req_1", ApprovalApproved, ApprovalRunning, ApprovalTransition{At: now})
			switch {
			case err == nil:
				wins.Add(1)
			case !errors.Is(err, ErrConflict):
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("wins = %d, want 1", wins.Load())
	}
}

func TestGrantsAndListUsers(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	s.CreateGrant(ctx, &Grant{ID: "g1", Human: "hanako@example.com", Databases: []string{"prod-main"}, Reason: "incident",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)})
	s.CreateGrant(ctx, &Grant{ID: "g2", Human: "hanako@example.com", Databases: []string{"prod-main", "staging"}, Reason: "incident",
		StepUpMethod: "passkey", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	gs, err := s.ListActiveGrants(ctx, "hanako@example.com", now)
	if err != nil || len(gs) != 1 || gs[0].ID != "g2" || len(gs[0].Databases) != 2 || gs[0].StepUpMethod != "passkey" {
		t.Fatalf("grants = %+v, %v", gs, err)
	}
	if gs, _ := s.ListActiveGrants(ctx, "taro@example.com", now); len(gs) != 0 {
		t.Fatalf("other human: %+v", gs)
	}

	s.UpsertUser(ctx, &User{Email: "b@example.com", IDPGroups: []string{"x"}})
	s.UpsertUser(ctx, &User{Email: "a@example.com"})
	us, err := s.ListUsers(ctx)
	if err != nil || len(us) != 2 || us[0].Email != "a@example.com" || us[1].IDPGroups[0] != "x" {
		t.Fatalf("users = %+v, %v", us, err)
	}
}
