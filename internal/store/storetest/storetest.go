// Package storetest is the conformance suite of the management-DB
// backends. Every backend (SQLite, PostgreSQL) runs the same tests through
// Run, so a behavior is specified once and holds for both.
//
// When adding a store method, add its tests here (not in a backend's own
// test file) so that every backend is checked against them.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/notify"
	"github.com/kyosu-1/dbgateway/internal/scim"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// Backend is everything a management-DB backend implements.
type Backend interface {
	store.Store
	scim.Store
	notify.Store
}

// Harness opens stores of the backend under test. Both functions register
// their own cleanup with t.
type Harness struct {
	// Open returns a store on an empty database.
	Open func(t *testing.T) Backend
	// OpenInstances returns n stores, each with its own connection pool,
	// on one empty database: n dbgateway instances sharing the management
	// database.
	OpenInstances func(t *testing.T, n int) []Backend
}

// Run runs the whole suite. Tests run sequentially, so a harness may reuse
// one database and empty it in Open.
func Run(t *testing.T, h Harness) {
	tests := []struct {
		name string
		fn   func(*testing.T, Harness)
	}{
		{"UserUpsert", testUserUpsert},
		{"SessionsAndClients", testSessionsAndClients},
		{"AuthCodeConsumeOnce", testAuthCodeConsumeOnce},
		{"DeviceCodeLifecycle", testDeviceCodeLifecycle},
		{"TokenRevokeCascade", testTokenRevokeCascade},
		{"DeleteExpired", testDeleteExpired},
		{"ApprovalRequestRoundTrip", testApprovalRequestRoundTrip},
		{"ListApprovalRequests", testListApprovalRequests},
		{"UpdateApprovalsOptimisticConcurrency", testUpdateApprovalsOptimisticConcurrency},
		{"TransitionApprovalRequest", testTransitionApprovalRequest},
		{"GrantsAndListUsers", testGrantsAndListUsers},
		{"UserActiveAndRecordLogin", testUserActiveAndRecordLogin},
		{"SCIMConflictsAndMembers", testSCIMConflictsAndMembers},
		{"SCIMGroupRenameAndDelete", testSCIMGroupRenameAndDelete},
		{"SCIMLockOutRevokesDerivedTokens", testSCIMLockOutRevokesDerivedTokens},
		{"InstancesClaimApprovalOnce", testInstancesClaimApprovalOnce},
		{"InstancesSingleUseSecrets", testInstancesSingleUseSecrets},
		{"InstancesUpdateApprovalsOnce", testInstancesUpdateApprovalsOnce},
		{"SlackLinksAndThreads", testSlackLinksAndThreads},
		{"InstancesSlackCodeOnce", testInstancesSlackCodeOnce},
		{"ConsoleHistory", testConsoleHistory},
		{"SavedQueries", testSavedQueries},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.fn(t, h) })
	}
}

// JSONEqual reports whether two JSON documents are equal after decoding
// (backends may normalize whitespace and key order, e.g. jsonb).
func JSONEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func testUserUpsert(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	if _, err := s.GetUser(ctx, "x@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	t1 := time.Now().Add(-time.Hour)
	must(t, s.UpsertUser(ctx, &store.User{Email: "x@example.com", IDPGroups: []string{"a"}, LastLoginAt: t1}))
	must(t, s.UpsertUser(ctx, &store.User{Email: "x@example.com", IDPGroups: []string{"b", "c"}}))
	u, err := s.GetUser(ctx, "x@example.com")
	if err != nil || len(u.IDPGroups) != 2 || u.CreatedAt.UnixMilli() != t1.UnixMilli() || !u.LastLoginAt.After(t1) {
		t.Fatalf("user = %+v, %v", u, err)
	}
	// A nil group list is stored as an empty list.
	must(t, s.UpsertUser(ctx, &store.User{Email: "y@example.com"}))
	if u, err := s.GetUser(ctx, "y@example.com"); err != nil || u.IDPGroups == nil || len(u.IDPGroups) != 0 {
		t.Fatalf("user without groups = %+v, %v", u, err)
	}
}

func testSessionsAndClients(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.UnixMilli(time.Now().UnixMilli())
	sess := &store.Session{IDHash: store.HashSecret("sid"), Email: "a@example.com", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	must(t, s.CreateSession(ctx, sess))
	if err := s.CreateSession(ctx, sess); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate session: %v", err)
	}
	got, err := s.GetSession(ctx, sess.IDHash)
	if err != nil || got.Email != "a@example.com" || !got.CreatedAt.Equal(now) || !got.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("session = %+v, %v", got, err)
	}
	must(t, s.DeleteSession(ctx, sess.IDHash))
	must(t, s.DeleteSession(ctx, sess.IDHash)) // missing is fine
	if _, err := s.GetSession(ctx, sess.IDHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted session: %v", err)
	}

	if n, err := s.CountClients(ctx); err != nil || n != 0 {
		t.Fatalf("CountClients = %d, %v", n, err)
	}
	c := &store.Client{ClientID: "c1", ClientName: "Claude", RedirectURIs: []string{"http://127.0.0.1/cb", "https://x/cb"}, CreatedAt: now}
	must(t, s.CreateClient(ctx, c))
	if err := s.CreateClient(ctx, c); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate client: %v", err)
	}
	gc, err := s.GetClient(ctx, "c1")
	if err != nil || gc.ClientName != "Claude" || !slices.Equal(gc.RedirectURIs, c.RedirectURIs) || !gc.CreatedAt.Equal(now) {
		t.Fatalf("client = %+v, %v", gc, err)
	}
	if _, err := s.GetClient(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing client: %v", err)
	}
	if n, err := s.CountClients(ctx); err != nil || n != 1 {
		t.Fatalf("CountClients = %d, %v", n, err)
	}
}

func testAuthCodeConsumeOnce(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	c := &store.AuthCode{CodeHash: store.HashSecret("code"), ClientID: "c", RedirectURI: "http://127.0.0.1/cb", CodeChallenge: "x",
		Scopes: []string{"db:read"}, Email: "a@example.com", Databases: []string{"db"}, FamilyID: "f", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	must(t, s.CreateAuthCode(ctx, c))
	if err := s.CreateAuthCode(ctx, c); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate code: %v", err)
	}
	got, err := s.ConsumeAuthCode(ctx, c.CodeHash, now)
	if err != nil || got.FamilyID != "f" || got.Databases[0] != "db" || got.UsedAt == nil {
		t.Fatalf("consume = %+v, %v", got, err)
	}
	got, err = s.ConsumeAuthCode(ctx, c.CodeHash, now)
	if !errors.Is(err, store.ErrAlreadyUsed) || got == nil || got.FamilyID != "f" || got.UsedAt == nil {
		t.Fatalf("second consume = %+v, %v", got, err)
	}
	if _, err := s.ConsumeAuthCode(ctx, store.HashSecret("nope"), now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func testDeviceCodeLifecycle(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	d := &store.DeviceCode{DeviceCodeHash: store.HashSecret("dc"), UserCodeHash: store.HashSecret("UC"), ClientID: "dbgw-cli",
		Scopes: []string{"db:read"}, Status: store.DevicePending, Interval: 5 * time.Second, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	must(t, s.CreateDeviceCode(ctx, d))
	if _, err := s.ConsumeDeviceCode(ctx, d.DeviceCodeHash, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("consume pending: %v", err)
	}
	if got, err := s.GetDeviceCodeByUserCode(ctx, d.UserCodeHash); err != nil || got.Interval != 5*time.Second || got.Scopes[0] != "db:read" {
		t.Fatalf("by user code = %+v, %v", got, err)
	}
	if _, err := s.GetDeviceCodeByUserCode(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user code: %v", err)
	}
	p, err := s.PollDeviceCode(ctx, d.DeviceCodeHash, now)
	if err != nil || p.LastPolledAt != nil {
		t.Fatalf("poll = %+v, %v", p, err)
	}
	p, err = s.PollDeviceCode(ctx, d.DeviceCodeHash, now.Add(time.Second))
	if err != nil || p.LastPolledAt == nil || p.LastPolledAt.UnixMilli() != now.UnixMilli() {
		t.Fatalf("last poll not recorded: %+v, %v", p, err)
	}
	if _, err := s.PollDeviceCode(ctx, "nope", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("poll missing: %v", err)
	}
	must(t, s.SetDeviceCodeInterval(ctx, d.DeviceCodeHash, 10*time.Second))
	if err := s.DecideDeviceCode(ctx, d.UserCodeHash, "a@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideDeviceCode(ctx, d.UserCodeHash, "b@example.com", false, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second decide: %v", err)
	}
	got, err := s.ConsumeDeviceCode(ctx, d.DeviceCodeHash, now)
	if err != nil || got.Email != "a@example.com" || got.Status != store.DeviceConsumed || got.Interval != 10*time.Second {
		t.Fatalf("consume = %+v, %v", got, err)
	}
	if _, err := s.ConsumeDeviceCode(ctx, d.DeviceCodeHash, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("double consume: %v", err)
	}

	// Expired codes can be neither decided nor consumed.
	e := &store.DeviceCode{DeviceCodeHash: store.HashSecret("dc2"), UserCodeHash: store.HashSecret("UC2"), ClientID: "dbgw-cli",
		Status: store.DevicePending, Interval: time.Second, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}
	must(t, s.CreateDeviceCode(ctx, e))
	if err := s.DecideDeviceCode(ctx, e.UserCodeHash, "a@example.com", true, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("decide expired: %v", err)
	}
}

func tok(id, family, parent string, typ store.TokenType, exp time.Time) *store.Token {
	return &store.Token{ID: id, Hash: store.HashSecret(id), Type: typ, Kind: identity.KindAgent, Human: "a@example.com",
		ClientID: "c", Scopes: []string{"db:read"}, Audience: "aud", FamilyID: family, ParentID: parent,
		CreatedAt: time.Now(), ExpiresAt: exp}
}

func testTokenRevokeCascade(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	exp := time.Now().Add(time.Hour)
	for _, tk := range []*store.Token{
		tok("human", "", "", store.TokenAccess, exp),
		tok("agent1", "", "human", store.TokenAccess, exp),
		tok("agent2", "", "agent1", store.TokenAccess, exp), // grandchild
		tok("at1", "fam", "", store.TokenAccess, exp),
		tok("rt1", "fam", "", store.TokenRefresh, exp),
		tok("rt2", "fam", "rt1", store.TokenRefresh, exp),
		tok("other", "", "", store.TokenAccess, exp),
	} {
		must(t, s.CreateToken(ctx, tk))
	}
	if err := s.CreateToken(ctx, tok("human", "", "", store.TokenAccess, exp)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate insert: %v", err)
	}
	now := time.Now()
	n, err := s.RevokeToken(ctx, "human", now)
	if err != nil || n != 3 {
		t.Fatalf("revoke human = %d, %v", n, err)
	}
	if n, err := s.RevokeToken(ctx, "human", now); err != nil || n != 0 {
		t.Fatalf("revoke again = %d, %v", n, err)
	}
	n, err = s.RevokeFamily(ctx, "fam", now)
	if err != nil || n != 3 {
		t.Fatalf("revoke family = %d, %v", n, err)
	}
	if n, err := s.RevokeFamily(ctx, "", now); err != nil || n != 0 {
		t.Fatalf("revoke empty family = %d, %v", n, err)
	}
	other, err := s.GetTokenByHash(ctx, store.HashSecret("other"))
	if err != nil || !other.Active(now) || other.Kind != identity.KindAgent || other.Scopes[0] != "db:read" {
		t.Fatalf("unrelated token = %+v, %v", other, err)
	}
	if rt2, err := s.GetToken(ctx, "rt2"); err != nil || rt2.RevokedAt == nil || rt2.Type != store.TokenRefresh || rt2.ParentID != "rt1" {
		t.Fatalf("rt2 = %+v, %v", rt2, err)
	}
	if _, err := s.GetToken(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing token: %v", err)
	}
	ok, _ := s.MarkTokenUsed(ctx, "other", now)
	ok2, _ := s.MarkTokenUsed(ctx, "other", now)
	if !ok || ok2 {
		t.Fatalf("MarkTokenUsed = %v, %v", ok, ok2)
	}
	if ok, _ := s.MarkTokenUsed(ctx, "rt2", now); ok {
		t.Fatal("MarkTokenUsed on a revoked token")
	}
	list, err := s.ListTokens(ctx, "a@example.com")
	if err != nil || len(list) != 7 {
		t.Fatalf("list = %d, %v", len(list), err)
	}
}

func testDeleteExpired(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	must(t, s.CreateToken(ctx, tok("old", "", "", store.TokenAccess, now.Add(-time.Hour))))
	must(t, s.CreateToken(ctx, tok("new", "", "", store.TokenAccess, now.Add(time.Hour))))
	must(t, s.CreateSession(ctx, &store.Session{IDHash: "s", Email: "a", CreatedAt: now, ExpiresAt: now.Add(-time.Minute)}))
	n, err := s.DeleteExpired(ctx, now)
	if err != nil || n != 2 {
		t.Fatalf("DeleteExpired = %d, %v", n, err)
	}
	if _, err := s.GetToken(ctx, "new"); err != nil {
		t.Fatal(err)
	}
}

func newApproval(id string, now time.Time) *store.ApprovalRequest {
	return &store.ApprovalRequest{
		ID: id, RequesterKind: identity.KindAgent, RequesterHuman: "taro@example.com", RequesterAgent: "claude-code",
		RequesterClientID: "client-1", Database: "prod-main", RawSQL: "UPDATE users SET plan = 'pro' WHERE id = 1",
		NormalizedSQL: "UPDATE users SET plan = $1 WHERE id = $2", Reason: "support ticket #1",
		AnalysisJSON: []byte(`{"kind":"update"}`), EstimateRows: 1.5, MaxAffectedRows: 2, Risk: "medium",
		ApprovalRule: "prod-default", StepsJSON: []byte(`[{"role":"approver","count":1}]`), ConfigVersion: "abc",
		BindingHash: "hash", Status: store.ApprovalPending, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func testApprovalRequestRoundTrip(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.UnixMilli(time.Now().UnixMilli())
	r := newApproval("req_1", now)
	must(t, s.CreateApprovalRequest(ctx, r))
	if err := s.CreateApprovalRequest(ctx, r); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	got, err := s.GetApprovalRequest(ctx, "req_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.RawSQL != r.RawSQL || got.NormalizedSQL != r.NormalizedSQL || got.RequesterKind != identity.KindAgent ||
		!JSONEqual(got.ApprovalsJSON, []byte("[]")) || !JSONEqual(got.AnalysisJSON, r.AnalysisJSON) || !JSONEqual(got.StepsJSON, r.StepsJSON) ||
		got.ResultJSON != nil || !got.CreatedAt.Equal(r.CreatedAt) || !got.ExpiresAt.Equal(r.ExpiresAt) || got.DecidedAt != nil ||
		got.MaxAffectedRows != 2 || got.EstimateRows != 1.5 || got.Status != store.ApprovalPending || got.Version != 0 ||
		got.RequesterClientID != "client-1" || got.BindingHash != "hash" {
		t.Fatalf("got %+v", got)
	}
	if _, err := s.GetApprovalRequest(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	// Empty documents get their defaults.
	e := newApproval("req_2", now)
	e.AnalysisJSON, e.StepsJSON = nil, nil
	must(t, s.CreateApprovalRequest(ctx, e))
	if got, err := s.GetApprovalRequest(ctx, "req_2"); err != nil || !JSONEqual(got.AnalysisJSON, []byte("{}")) || !JSONEqual(got.StepsJSON, []byte("[]")) {
		t.Fatalf("defaults = %+v, %v", got, err)
	}
}

func testListApprovalRequests(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	for i, id := range []string{"req_a", "req_b", "req_c"} {
		r := newApproval(id, now.Add(time.Duration(i)*time.Second))
		if id == "req_c" {
			r.RequesterHuman, r.Database, r.ExpiresAt = "hanako@example.com", "staging", now.Add(-time.Minute)
		}
		must(t, s.CreateApprovalRequest(ctx, r))
	}
	all, err := s.ListApprovalRequests(ctx, store.ApprovalFilter{})
	if err != nil || len(all) != 3 || all[0].ID != "req_c" {
		t.Fatalf("all = %v, %v", ids(all), err)
	}
	mine, _ := s.ListApprovalRequests(ctx, store.ApprovalFilter{RequesterHuman: "taro@example.com"})
	if len(mine) != 2 {
		t.Fatalf("mine = %v", ids(mine))
	}
	expired, _ := s.ListApprovalRequests(ctx, store.ApprovalFilter{Statuses: []store.ApprovalStatus{store.ApprovalPending}, ExpiresBefore: now})
	if len(expired) != 1 || expired[0].ID != "req_c" {
		t.Fatalf("expired = %v", ids(expired))
	}
	limited, _ := s.ListApprovalRequests(ctx, store.ApprovalFilter{Database: "prod-main", Limit: 1})
	if len(limited) != 1 || limited[0].ID != "req_b" {
		t.Fatalf("limited = %v", ids(limited))
	}
	none, _ := s.ListApprovalRequests(ctx, store.ApprovalFilter{Statuses: []store.ApprovalStatus{store.ApprovalSucceeded, store.ApprovalFailed}})
	if len(none) != 0 {
		t.Fatalf("none = %v", ids(none))
	}
	two, _ := s.ListApprovalRequests(ctx, store.ApprovalFilter{Statuses: []store.ApprovalStatus{store.ApprovalPending, store.ApprovalApproved}, Database: "prod-main"})
	if len(two) != 2 || two[0].ID != "req_b" || two[1].ID != "req_a" {
		t.Fatalf("two = %v", ids(two))
	}
}

func ids(rs []*store.ApprovalRequest) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func testUpdateApprovalsOptimisticConcurrency(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	must(t, s.CreateApprovalRequest(ctx, newApproval("req_1", now)))
	must(t, s.UpdateApprovals(ctx, "req_1", 0, []byte(`[{"approver":"a"}]`), store.ApprovalPending, nil))
	if r, _ := s.GetApprovalRequest(ctx, "req_1"); r.DecidedAt != nil || r.Version != 1 {
		t.Fatalf("after first approval: %+v", r)
	}
	// A second writer that read version 0 loses.
	if err := s.UpdateApprovals(ctx, "req_1", 0, []byte(`[{"approver":"b"}]`), store.ApprovalApproved, &now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
	must(t, s.UpdateApprovals(ctx, "req_1", 1, []byte(`[{"approver":"a"},{"approver":"b"}]`), store.ApprovalApproved, &now))
	r, _ := s.GetApprovalRequest(ctx, "req_1")
	if r.Status != store.ApprovalApproved || r.Version != 2 || r.DecidedAt == nil || r.DecidedAt.UnixMilli() != now.UnixMilli() ||
		!JSONEqual(r.ApprovalsJSON, []byte(`[{"approver":"a"},{"approver":"b"}]`)) {
		t.Fatalf("got %+v", r)
	}
	// Not pending any more.
	if err := s.UpdateApprovals(ctx, "req_1", 2, []byte(`[]`), store.ApprovalPending, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("not pending: %v", err)
	}
	if err := s.UpdateApprovals(ctx, "nope", 0, []byte(`[]`), store.ApprovalPending, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.UpdateApprovals(ctx, "req_1", 2, []byte(`[]`), store.ApprovalRunning, nil); err == nil {
		t.Fatal("invalid status accepted")
	}
}

func testTransitionApprovalRequest(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	must(t, s.CreateApprovalRequest(ctx, newApproval("req_1", now)))
	if err := s.TransitionApprovalRequest(ctx, "req_1", store.ApprovalApproved, store.ApprovalRunning, store.ApprovalTransition{At: now}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("wrong from: %v", err)
	}
	must(t, s.TransitionApprovalRequest(ctx, "req_1", store.ApprovalPending, store.ApprovalRejected,
		store.ApprovalTransition{At: now, DecidedBy: "hanako@example.com", Comment: "too broad"}))
	r, _ := s.GetApprovalRequest(ctx, "req_1")
	if r.Status != store.ApprovalRejected || r.DecidedBy != "hanako@example.com" || r.Comment != "too broad" || r.DecidedAt == nil || r.Version != 1 {
		t.Fatalf("got %+v", r)
	}
	if err := s.TransitionApprovalRequest(ctx, "req_1", store.ApprovalPending, store.ApprovalCanceled, store.ApprovalTransition{At: now}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("final state changed: %v", err)
	}
	if err := s.TransitionApprovalRequest(ctx, "nope", store.ApprovalPending, store.ApprovalCanceled, store.ApprovalTransition{At: now}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.TransitionApprovalRequest(ctx, "req_1", store.ApprovalRejected, store.ApprovalPending, store.ApprovalTransition{At: now}); err == nil {
		t.Fatal("transition back to pending accepted")
	}

	must(t, s.CreateApprovalRequest(ctx, newApproval("req_2", now)))
	must(t, s.UpdateApprovals(ctx, "req_2", 0, []byte(`[]`), store.ApprovalApproved, &now))
	must(t, s.TransitionApprovalRequest(ctx, "req_2", store.ApprovalApproved, store.ApprovalRunning, store.ApprovalTransition{At: now}))
	must(t, s.TransitionApprovalRequest(ctx, "req_2", store.ApprovalRunning, store.ApprovalSucceeded,
		store.ApprovalTransition{At: now, Result: []byte(`{"rows_affected":1}`)}))
	r, _ = s.GetApprovalRequest(ctx, "req_2")
	if r.Status != store.ApprovalSucceeded || r.StartedAt == nil || r.FinishedAt == nil || !JSONEqual(r.ResultJSON, []byte(`{"rows_affected":1}`)) {
		t.Fatalf("got %+v", r)
	}
}

func testGrantsAndListUsers(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	must(t, s.CreateGrant(ctx, &store.Grant{ID: "g1", Human: "hanako@example.com", Databases: []string{"prod-main"}, Reason: "incident",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}))
	must(t, s.CreateGrant(ctx, &store.Grant{ID: "g2", Human: "hanako@example.com", Databases: []string{"prod-main", "staging"}, Reason: "incident",
		StepUpMethod: "passkey", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
	if err := s.CreateGrant(ctx, &store.Grant{ID: "g2", Human: "x", CreatedAt: now, ExpiresAt: now}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate grant: %v", err)
	}
	gs, err := s.ListActiveGrants(ctx, "hanako@example.com", now)
	if err != nil || len(gs) != 1 || gs[0].ID != "g2" || len(gs[0].Databases) != 2 || gs[0].StepUpMethod != "passkey" {
		t.Fatalf("grants = %+v, %v", gs, err)
	}
	if gs, _ := s.ListActiveGrants(ctx, "taro@example.com", now); len(gs) != 0 {
		t.Fatalf("other human: %+v", gs)
	}

	must(t, s.UpsertUser(ctx, &store.User{Email: "b@example.com", IDPGroups: []string{"x"}}))
	must(t, s.UpsertUser(ctx, &store.User{Email: "a@example.com"}))
	us, err := s.ListUsers(ctx)
	if err != nil || len(us) != 2 || us[0].Email != "a@example.com" || us[1].IDPGroups[0] != "x" {
		t.Fatalf("users = %+v, %v", us, err)
	}
}

func testUserActiveAndRecordLogin(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()

	// Users never provisioned through SCIM are active and keep the login
	// snapshot.
	if ok, err := s.UserActive(ctx, "nobody@example.com"); err != nil || !ok {
		t.Fatalf("unknown user: %v %v", ok, err)
	}
	must(t, s.RecordLogin(ctx, "Plain@Example.com", []string{"g1"}, now, true))
	if u, err := s.GetUser(ctx, "plain@example.com"); err != nil || !slices.Equal(u.IDPGroups, []string{"g1"}) {
		t.Fatalf("plain user = %+v, %v", u, err)
	}

	u := &store.SCIMUser{ID: "u1", Email: "Taro@Example.com", UserName: "taro", Active: true}
	must(t, s.CreateSCIMUser(ctx, u, now))
	if u.Email != "taro@example.com" {
		t.Fatalf("email not normalised: %q", u.Email)
	}
	must(t, s.CreateSCIMGroup(ctx, &store.SCIMGroup{ID: "g", DisplayName: "scim-group", Members: []store.SCIMMember{{UserID: "u1"}}}, now))
	must(t, s.RecordLogin(ctx, "taro@example.com", []string{"oidc-group"}, now, true))
	if got, _ := s.GetUser(ctx, "taro@example.com"); !slices.Equal(got.IDPGroups, []string{"scim-group"}) {
		t.Fatalf("scim enabled: %v", got.IDPGroups)
	}
	must(t, s.RecordLogin(ctx, "taro@example.com", []string{"oidc-group"}, now, false))
	if got, _ := s.GetUser(ctx, "taro@example.com"); !slices.Equal(got.IDPGroups, []string{"oidc-group"}) {
		t.Fatalf("scim disabled: %v", got.IDPGroups)
	}

	// Deactivated: locked out even when SCIM is disabled later.
	if _, err := s.UpdateSCIMUser(ctx, "u1", now, func(u *store.SCIMUser) error { u.Active = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UserActive(ctx, "TARO@example.com"); ok {
		t.Fatal("inactive user reported active")
	}
	for _, enabled := range []bool{true, false} {
		if err := s.RecordLogin(ctx, "taro@example.com", nil, now, enabled); !errors.Is(err, store.ErrUserInactive) {
			t.Fatalf("RecordLogin(scim=%v) = %v", enabled, err)
		}
	}
	if got, _ := s.GetUser(ctx, "taro@example.com"); len(got.IDPGroups) != 0 {
		t.Fatalf("inactive user keeps groups %v", got.IDPGroups)
	}

	// Deleted: tombstone keeps the lock until re-provisioned.
	must(t, s.DeleteSCIMUser(ctx, "u1", now))
	if ok, _ := s.UserActive(ctx, "taro@example.com"); ok {
		t.Fatal("deleted user reported active")
	}
	if _, err := s.GetSCIMUser(ctx, "u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted user visible: %v", err)
	}
	if err := s.DeleteSCIMUser(ctx, "u1", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
	if err := s.CreateSCIMUser(ctx, &store.SCIMUser{ID: "u2", Email: "taro@example.com", UserName: "TARO", Active: true}, now); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	if ok, _ := s.UserActive(ctx, "taro@example.com"); !ok {
		t.Fatal("re-provisioned user inactive")
	}
}

func testSCIMConflictsAndMembers(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	mk := func(id, email, name string) error {
		return s.CreateSCIMUser(ctx, &store.SCIMUser{ID: id, Email: email, UserName: name, Active: true,
			Emails: []store.SCIMEmail{{Value: email, Type: "work", Primary: true}}}, now)
	}
	must(t, mk("a", "a@example.com", "a"))
	if err := mk("b", "A@example.com", "b"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same email: %v", err)
	}
	if err := mk("c", "c@example.com", "A"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same userName: %v", err)
	}
	if err := mk("d", "", "d"); err == nil {
		t.Fatal("user without email accepted")
	}
	if u, err := s.GetSCIMUser(ctx, "a"); err != nil || len(u.Emails) != 1 || !u.Emails[0].Primary || u.Emails[0].Type != "work" || !u.Active {
		t.Fatalf("user a = %+v, %v", u, err)
	}
	if err := s.CreateSCIMGroup(ctx, &store.SCIMGroup{ID: "g", DisplayName: "G", Members: []store.SCIMMember{{UserID: "zzz"}}}, now); !errors.Is(err, store.ErrUnknownMember) {
		t.Fatalf("unknown member: %v", err)
	}
	if _, err := s.GetSCIMGroup(ctx, "g", true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("failed create left a group: %v", err)
	}
	must(t, s.CreateSCIMGroup(ctx, &store.SCIMGroup{ID: "g", DisplayName: "G", Members: []store.SCIMMember{{UserID: "a"}, {UserID: "a"}}}, now))
	if err := s.CreateSCIMGroup(ctx, &store.SCIMGroup{ID: "g2", DisplayName: "g"}, now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same display name: %v", err)
	}
	g, err := s.GetSCIMGroup(ctx, "g", true)
	if err != nil || len(g.Members) != 1 || g.Members[0].UserName != "a" {
		t.Fatalf("group = %+v, %v", g, err)
	}
	if g, err := s.GetSCIMGroup(ctx, "g", false); err != nil || g.Members != nil {
		t.Fatalf("group without members = %+v, %v", g, err)
	}
	gs, total, err := s.ListSCIMGroups(ctx, store.SCIMGroupFilter{DisplayName: "g", MemberID: "a"}, 0, 10, false)
	if err != nil || total != 1 || len(gs) != 1 || gs[0].Members != nil {
		t.Fatalf("list groups = %v %d %v", gs, total, err)
	}
	if gs, total, err := s.ListSCIMGroups(ctx, store.SCIMGroupFilter{}, 0, 0, true); err != nil || total != 1 || gs != nil {
		t.Fatalf("count groups = %v %d %v", gs, total, err)
	}
	us, total, err := s.ListSCIMUsers(ctx, store.SCIMUserFilter{Email: "A@EXAMPLE.COM"}, 0, 10)
	if err != nil || total != 1 || us[0].ID != "a" || len(us[0].Groups) != 1 || us[0].Groups[0].DisplayName != "G" {
		t.Fatalf("list users = %v %d %v", us, total, err)
	}
	if us, total, err := s.ListSCIMUsers(ctx, store.SCIMUserFilter{UserName: "A"}, 0, 10); err != nil || total != 1 || len(us) != 1 {
		t.Fatalf("list by userName = %v %d %v", us, total, err)
	}
	// Paging, oldest first.
	must(t, s.CreateSCIMUser(ctx, &store.SCIMUser{ID: "e", Email: "e@example.com", UserName: "e", Active: true}, now.Add(time.Second)))
	if us, total, err := s.ListSCIMUsers(ctx, store.SCIMUserFilter{}, 1, 10); err != nil || total != 2 || len(us) != 1 || us[0].ID != "e" {
		t.Fatalf("page 2 = %v %d %v", us, total, err)
	}
	if us, total, err := s.ListSCIMUsers(ctx, store.SCIMUserFilter{}, 5, 10); err != nil || total != 2 || len(us) != 0 {
		t.Fatalf("past the end = %v %d %v", us, total, err)
	}
	// fn errors abort the update.
	boom := errors.New("boom")
	if _, err := s.UpdateSCIMGroup(ctx, "g", now, func(g *store.SCIMGroup) error { g.Members = nil; return boom }); !errors.Is(err, boom) {
		t.Fatalf("update err = %v", err)
	}
	if g, _ := s.GetSCIMGroup(ctx, "g", true); len(g.Members) != 1 {
		t.Fatal("aborted update changed members")
	}
	if _, err := s.UpdateSCIMUser(ctx, "a", now, func(u *store.SCIMUser) error { u.UserName = "E"; return nil }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rename to taken userName: %v", err)
	}
	if _, err := s.UpdateSCIMUser(ctx, "nope", now, func(*store.SCIMUser) error { return nil }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
}

func testSCIMGroupRenameAndDelete(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	for _, id := range []string{"u1", "u2"} {
		must(t, s.CreateSCIMUser(ctx, &store.SCIMUser{ID: id, Email: id + "@example.com", UserName: id, Active: true}, now))
		must(t, s.RecordLogin(ctx, id+"@example.com", nil, now, true))
	}
	must(t, s.CreateSCIMGroup(ctx, &store.SCIMGroup{ID: "g", DisplayName: "dev", Members: []store.SCIMMember{{UserID: "u1"}}}, now))
	groups := func(email string) []string {
		t.Helper()
		u, err := s.GetUser(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		return u.IDPGroups
	}
	if g := groups("u1@example.com"); !slices.Equal(g, []string{"dev"}) {
		t.Fatalf("u1 groups = %v", g)
	}
	g, err := s.UpdateSCIMGroup(ctx, "g", now, func(g *store.SCIMGroup) error {
		g.DisplayName, g.ExternalID = "developers", "ext-1"
		g.Members = []store.SCIMMember{{UserID: "u2"}}
		return nil
	})
	if err != nil || g.DisplayName != "developers" || g.ExternalID != "ext-1" || len(g.Members) != 1 || g.Members[0].UserID != "u2" {
		t.Fatalf("updated group = %+v, %v", g, err)
	}
	if g := groups("u1@example.com"); len(g) != 0 {
		t.Fatalf("removed member keeps %v", g)
	}
	if g := groups("u2@example.com"); !slices.Equal(g, []string{"developers"}) {
		t.Fatalf("u2 groups = %v", g)
	}
	if u, err := s.GetSCIMUser(ctx, "u2"); err != nil || len(u.Groups) != 1 || u.Groups[0].ID != "g" {
		t.Fatalf("u2 = %+v, %v", u, err)
	}
	must(t, s.DeleteSCIMGroup(ctx, "g", now))
	if g := groups("u2@example.com"); len(g) != 0 {
		t.Fatalf("deleted group still in %v", g)
	}
	if err := s.DeleteSCIMGroup(ctx, "g", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
	// Changing the email locks the old identity out.
	must(t, s.CreateSession(ctx, &store.Session{IDHash: "s1", Email: "u1@example.com", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
	if _, err := s.UpdateSCIMUser(ctx, "u1", now, func(u *store.SCIMUser) error { u.Email = "U1-new@example.com"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "s1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old email's session survived: %v", err)
	}
	if u, err := s.GetSCIMUser(ctx, "u1"); err != nil || u.Email != "u1-new@example.com" {
		t.Fatalf("u1 = %+v, %v", u, err)
	}
}

func testSCIMLockOutRevokesDerivedTokens(t *testing.T, h Harness) {
	ctx := context.Background()
	s := h.Open(t)
	now := time.Now()
	exp := now.Add(time.Hour)
	tokens := []*store.Token{
		{ID: "t1", Hash: "h1", Type: store.TokenRefresh, Kind: identity.KindHuman, Human: "taro@example.com", FamilyID: "f1", CreatedAt: now, ExpiresAt: exp},
		{ID: "t2", Hash: "h2", Type: store.TokenAccess, Kind: identity.KindHuman, Human: "taro@example.com", FamilyID: "f1", CreatedAt: now, ExpiresAt: exp},
		{ID: "t3", Hash: "h3", Type: store.TokenAccess, Kind: identity.KindAgent, Human: "Taro@Example.com", Agent: "x", ParentID: "t2", CreatedAt: now, ExpiresAt: exp},
		{ID: "other", Hash: "h4", Type: store.TokenAccess, Kind: identity.KindHuman, Human: "hanako@example.com", CreatedAt: now, ExpiresAt: exp},
	}
	for _, tk := range tokens {
		must(t, s.CreateToken(ctx, tk))
	}
	must(t, s.CreateSession(ctx, &store.Session{IDHash: "s", Email: "Taro@example.com", CreatedAt: now, ExpiresAt: exp}))
	must(t, s.CreateSCIMUser(ctx, &store.SCIMUser{ID: "u", Email: "taro@example.com", UserName: "taro", Active: false}, now))
	for _, id := range []string{"t1", "t2", "t3"} {
		if tk, _ := s.GetToken(ctx, id); tk.RevokedAt == nil {
			t.Fatalf("%s not revoked", id)
		}
	}
	if tk, _ := s.GetToken(ctx, "other"); tk.RevokedAt != nil {
		t.Fatal("another user's token revoked")
	}
	if _, err := s.GetSession(ctx, "s"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session survived lock-out: %v", err)
	}
}

// race runs fn concurrently once per instance (times rounds) and waits.
func race(n int, fn func(i int)) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			fn(i)
		})
	}
	close(start)
	wg.Wait()
}

// Exactly one of several instances racing for an approved request moves
// it to running (and therefore executes it).
func testInstancesClaimApprovalOnce(t *testing.T, h Harness) {
	ctx := context.Background()
	const instances, perInstance, requests = 4, 4, 5
	stores := h.OpenInstances(t, instances)
	now := time.Now()
	for r := range requests {
		id := fmt.Sprintf("req_%d", r)
		must(t, stores[0].CreateApprovalRequest(ctx, newApproval(id, now)))
		must(t, stores[0].UpdateApprovals(ctx, id, 0, []byte(`[]`), store.ApprovalApproved, &now))
	}
	for r := range requests {
		id := fmt.Sprintf("req_%d", r)
		var wins atomic.Int32
		race(instances*perInstance, func(i int) {
			err := stores[i%instances].TransitionApprovalRequest(ctx, id, store.ApprovalApproved, store.ApprovalRunning, store.ApprovalTransition{At: now})
			switch {
			case err == nil:
				wins.Add(1)
			case !errors.Is(err, store.ErrConflict):
				t.Errorf("unexpected error: %v", err)
			}
		})
		if wins.Load() != 1 {
			t.Fatalf("%s: wins = %d, want 1", id, wins.Load())
		}
		if got, err := stores[1].GetApprovalRequest(ctx, id); err != nil || got.Status != store.ApprovalRunning || got.Version != 2 {
			t.Fatalf("%s = %+v, %v", id, got, err)
		}
	}
}

// Authorization codes, device codes and refresh tokens are single use
// across instances.
func testInstancesSingleUseSecrets(t *testing.T, h Harness) {
	ctx := context.Background()
	const n = 8
	stores := h.OpenInstances(t, 4)
	now := time.Now()
	exp := now.Add(time.Hour)
	must(t, stores[0].CreateAuthCode(ctx, &store.AuthCode{CodeHash: "code", ClientID: "c", FamilyID: "f", CreatedAt: now, ExpiresAt: exp}))
	must(t, stores[0].CreateDeviceCode(ctx, &store.DeviceCode{DeviceCodeHash: "dc", UserCodeHash: "uc", ClientID: "c",
		Status: store.DevicePending, Interval: time.Second, CreatedAt: now, ExpiresAt: exp}))
	must(t, stores[0].DecideDeviceCode(ctx, "uc", "a@example.com", true, now))
	must(t, stores[0].CreateToken(ctx, tok("rt", "fam", "", store.TokenRefresh, exp)))

	var codeWins, deviceWins, tokenWins atomic.Int32
	race(n, func(i int) {
		s := stores[i%len(stores)]
		switch c, err := s.ConsumeAuthCode(ctx, "code", now); {
		case err == nil:
			codeWins.Add(1)
		case errors.Is(err, store.ErrAlreadyUsed) && c != nil && c.FamilyID == "f":
		default:
			t.Errorf("ConsumeAuthCode: %+v, %v", c, err)
		}
		switch _, err := s.ConsumeDeviceCode(ctx, "dc", now); {
		case err == nil:
			deviceWins.Add(1)
		case !errors.Is(err, store.ErrNotFound):
			t.Errorf("ConsumeDeviceCode: %v", err)
		}
		ok, err := s.MarkTokenUsed(ctx, "rt", now)
		if err != nil {
			t.Errorf("MarkTokenUsed: %v", err)
		}
		if ok {
			tokenWins.Add(1)
		}
	})
	if codeWins.Load() != 1 || deviceWins.Load() != 1 || tokenWins.Load() != 1 {
		t.Fatalf("wins: code %d, device %d, token %d; want 1 each", codeWins.Load(), deviceWins.Load(), tokenWins.Load())
	}
}

// Of approvers on different instances who read the same version, exactly
// one records their approval.
func testInstancesUpdateApprovalsOnce(t *testing.T, h Harness) {
	ctx := context.Background()
	stores := h.OpenInstances(t, 4)
	now := time.Now()
	must(t, stores[0].CreateApprovalRequest(ctx, newApproval("req_1", now)))
	var wins atomic.Int32
	race(8, func(i int) {
		err := stores[i%len(stores)].UpdateApprovals(ctx, "req_1", 0, fmt.Appendf(nil, `[{"approver":"%d"}]`, i), store.ApprovalPending, nil)
		switch {
		case err == nil:
			wins.Add(1)
		case !errors.Is(err, store.ErrConflict):
			t.Errorf("unexpected error: %v", err)
		}
	})
	if wins.Load() != 1 {
		t.Fatalf("wins = %d, want 1", wins.Load())
	}
	if r, err := stores[0].GetApprovalRequest(ctx, "req_1"); err != nil || r.Version != 1 {
		t.Fatalf("request = %+v, %v", r, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func testSlackLinksAndThreads(t *testing.T, h Harness) {
	ctx := context.Background()
	st := h.Open(t)
	now := time.Now().UTC().Truncate(time.Millisecond)

	if err := st.CreateSlackLinkCode(ctx, "taro@example.com", "h1", now, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A new code replaces the old one.
	if err := st.CreateSlackLinkCode(ctx, "taro@example.com", "h2", now, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsumeSlackLinkCode(ctx, "h1", "U1", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replaced code: %v", err)
	}
	email, err := st.ConsumeSlackLinkCode(ctx, "h2", "U1", now)
	if err != nil || email != "taro@example.com" {
		t.Fatalf("consume: %q %v", email, err)
	}
	if _, err := st.ConsumeSlackLinkCode(ctx, "h2", "U1", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("reused code: %v", err)
	}
	if l, err := st.GetSlackLinkBySlackUser(ctx, "U1"); err != nil || l.Email != "taro@example.com" {
		t.Fatalf("link: %+v %v", l, err)
	}
	// Expired codes are refused.
	_ = st.CreateSlackLinkCode(ctx, "hanako@example.com", "h3", now, now.Add(time.Minute))
	if _, err := st.ConsumeSlackLinkCode(ctx, "h3", "U2", now.Add(2*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired code: %v", err)
	}
	if e, err := st.DeleteSlackLinkBySlackUser(ctx, "U1"); err != nil || e != "taro@example.com" {
		t.Fatalf("unlink: %q %v", e, err)
	}
	if _, err := st.GetSlackLinkByEmail(ctx, "taro@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after unlink: %v", err)
	}

	th := &store.SlackThread{RequestID: "req_1", Channel: "C1", Target: "#db", TS: "1.1", EventJSON: []byte(`{"a":1}`), CreatedAt: now}
	if err := st.SaveSlackThread(ctx, th); err != nil {
		t.Fatal(err)
	}
	th.TS = "1.2"
	if err := st.SaveSlackThread(ctx, th); err != nil {
		t.Fatal(err)
	}
	ths, err := st.ListSlackThreads(ctx, "req_1")
	if err != nil || len(ths) != 1 || ths[0].TS != "1.2" || !JSONEqual(ths[0].EventJSON, []byte(`{"a":1}`)) {
		t.Fatalf("threads: %+v %v", ths, err)
	}

	prev, found, err := st.SwapNotifyState(ctx, "config_version", "v1", now)
	if err != nil || found || prev != "" {
		t.Fatalf("first swap: %q %v %v", prev, found, err)
	}
	prev, found, err = st.SwapNotifyState(ctx, "config_version", "v2", now)
	if err != nil || !found || prev != "v1" {
		t.Fatalf("second swap: %q %v %v", prev, found, err)
	}
}

// A linking code is consumed by exactly one instance.
func testInstancesSlackCodeOnce(t *testing.T, h Harness) {
	ctx := context.Background()
	sts := h.OpenInstances(t, 4)
	now := time.Now().UTC()
	if err := sts[0].CreateSlackLinkCode(ctx, "taro@example.com", "hx", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var wins atomic.Int32
	for i, st := range sts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := st.ConsumeSlackLinkCode(ctx, "hx", fmt.Sprintf("U%d", i), now); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("code consumed %d times", wins.Load())
	}
}

func testConsoleHistory(t *testing.T, h Harness) {
	st := h.Open(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	rows := int64(2)
	add := func(id, email string, at time.Time, ttl time.Duration) {
		t.Helper()
		must(t, st.AddConsoleHistory(ctx, &store.ConsoleHistory{ID: id, Email: email, Database: "prod", SQL: "SELECT 1 WHERE x = 'a@example.com'",
			Reason: "ticket #1", Status: "ok", RowCount: &rows, RequestID: "req_" + id, CreatedAt: at, ExpiresAt: at.Add(ttl)}))
	}
	add("h1", "taro@example.com", now.Add(-2*time.Minute), time.Hour)
	add("h2", "taro@example.com", now.Add(-time.Minute), time.Hour)
	add("h3", "hanako@example.com", now, time.Hour)
	add("old", "taro@example.com", now.Add(-2*time.Hour), time.Hour) // expired

	list, err := st.ListConsoleHistory(ctx, "taro@example.com", 10, now)
	must(t, err)
	if len(list) != 2 || list[0].ID != "h2" || list[1].ID != "h1" {
		t.Fatalf("history: %+v", list)
	}
	if got := list[0]; got.SQL != "SELECT 1 WHERE x = 'a@example.com'" || got.RowCount == nil || *got.RowCount != 2 || !got.CreatedAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("entry: %+v", got)
	}
	if _, err := st.GetConsoleHistory(ctx, "hanako@example.com", "h1", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another person's entry: %v", err)
	}
	if _, err := st.GetConsoleHistory(ctx, "taro@example.com", "old", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired entry: %v", err)
	}
	// Only the newest MaxConsoleHistory entries are kept.
	for i := range store.MaxConsoleHistory {
		add(fmt.Sprintf("n%04d", i), "taro@example.com", now.Add(time.Duration(i)*time.Millisecond), time.Hour)
	}
	list, err = st.ListConsoleHistory(ctx, "taro@example.com", 0, now)
	must(t, err)
	if len(list) != store.MaxConsoleHistory || list[len(list)-1].ID != "n0000" {
		t.Fatalf("trimmed history: %d entries, oldest %s", len(list), list[len(list)-1].ID)
	}
	// DeleteExpired removes expired history.
	if _, err := st.DeleteExpired(ctx, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListConsoleHistory(ctx, "hanako@example.com", 0, now); len(list) != 0 {
		t.Fatalf("after DeleteExpired: %+v", list)
	}
}

func testSavedQueries(t *testing.T, h Harness) {
	st := h.Open(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	save := func(id, email, name string) error {
		return st.CreateSavedQuery(ctx, &store.SavedQuery{ID: id, Email: email, Name: name, Database: "prod", SQL: "SELECT " + id, CreatedAt: now, UpdatedAt: now})
	}
	must(t, save("q2", "taro@example.com", "b plans"))
	must(t, save("q1", "taro@example.com", "a users"))
	must(t, save("q3", "hanako@example.com", "mine"))
	list, err := st.ListSavedQueries(ctx, "taro@example.com")
	must(t, err)
	if len(list) != 2 || list[0].ID != "q1" || list[1].Name != "b plans" || list[1].SQL != "SELECT q2" {
		t.Fatalf("saved: %+v", list)
	}
	if _, err := st.GetSavedQuery(ctx, "taro@example.com", "q3"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another person's query: %v", err)
	}
	if err := st.DeleteSavedQuery(ctx, "taro@example.com", "q3"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete another person's query: %v", err)
	}
	must(t, st.DeleteSavedQuery(ctx, "taro@example.com", "q1"))
	if _, err := st.GetSavedQuery(ctx, "taro@example.com", "q1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	for i := range store.MaxSavedQueries - 1 {
		must(t, save(fmt.Sprintf("m%03d", i), "taro@example.com", "m"))
	}
	if err := save("over", "taro@example.com", "over"); !errors.Is(err, store.ErrLimit) {
		t.Fatalf("over the limit: %v", err)
	}
}
