package api

import (
	"context"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgconn"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
	"github.com/kyosu-1/dbgateway/gen/dbgateway/v1/dbgatewayv1connect"
	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
)

const gatewayConfig = `
server:
  listen: 127.0.0.1:8443
  public_url: http://127.0.0.1:8443
auth:
  dev_login: true
  agent_tokens: { max_ttl: 1h }
approvals: { enabled: true }
databases:
  - name: prod
    labels: { env: prod }
    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }
groups:
  - { name: dev, members: [taro@example.com] }
  - { name: sre, members: [hanako@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier, writer] }
  - { group: sre, databases: "*", roles: [querier, writer, approver] }
data_classes:
  - { columns: [public.users.email], class: masked }
  - { column_pattern: "public\\.users\\.(id|plan|name)", class: public }
approval_rules:
  - { name: default, when: "true", steps: [{ role: approver }], expire_after: 30m }
`

type gwEnv struct {
	client   dbgatewayv1connect.GatewayServiceClient
	auth     *auth.Server
	store    store.Store
	fa       *gatewaytest.Adapter
	auditDir string
}

func newGatewayEnv(t *testing.T, yaml string, withApprovals bool) *gwEnv {
	t.Helper()
	ctx := context.Background()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := auth.New(ctx, auth.Options{Config: cfg, Store: st, RBAC: policy.NewRBAC(cfg), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sink, err := audit.OpenFileSink(dir, 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.New(sink)
	if err != nil {
		t.Fatal(err)
	}
	fa := gatewaytest.New()
	fa.Result = analysis.Result{Columns: []analysis.ResultColumn{{Name: "id", Type: "int8"}, {Name: "email", Type: "text"}},
		Rows: [][]any{{int64(1), "user1@example.com"}}}
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": fa}, Audit: al, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	var svc *approval.Service
	if withApprovals {
		svc = approval.New(approval.Options{Config: cfg, Store: st, Executor: gw, Audit: al, Logger: logger})
		gw.SetApprovals(svc)
	}
	mux := http.NewServeMux()
	path, h := NewGatewayService(a, gw, svc, cfg)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		if svc != nil {
			svc.Wait()
		}
		gw.Close()
		_ = al.Close()
		st.Close()
	})
	return &gwEnv{client: dbgatewayv1connect.NewGatewayServiceClient(srv.Client(), srv.URL), auth: a, store: st, fa: fa, auditDir: dir}
}

func (e *gwEnv) humanToken(t *testing.T, email string) string {
	t.Helper()
	raw := auth.AccessTokenPrefix + "test-" + email
	now := time.Now()
	if err := e.store.CreateToken(context.Background(), &store.Token{
		ID: "tok_human_" + email, Hash: store.HashSecret(raw), Type: store.TokenAccess, Kind: identity.KindHuman,
		Human: email, ClientID: auth.CLIClientID, Scopes: []string{identity.ScopeRead},
		Audience: "http://127.0.0.1:8443", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *gwEnv) agentToken(t *testing.T, human string) string {
	t.Helper()
	ctx := context.Background()
	p, err := e.auth.Authenticate(ctx, human)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := e.auth.MintAgentToken(ctx, p, auth.AgentTokenRequest{AgentName: "claude", Databases: []string{"prod"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *gwEnv) exec(t *testing.T, token, sql string) *dbgatewayv1.ExecuteSQLResponse {
	t.Helper()
	resp, err := e.client.ExecuteSQL(context.Background(), withBearer(&dbgatewayv1.ExecuteSQLRequest{
		Database: "prod", Sql: sql, Reason: "API test: verify the gateway service mapping"}, token))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg
}

func TestExecuteSQLMapping(t *testing.T) {
	e := newGatewayEnv(t, gatewayConfig, true)
	taro := e.humanToken(t, "taro@example.com")

	t.Run("ok with masking", func(t *testing.T) {
		r := e.exec(t, taro, "SELECT id, email FROM users WHERE id = 1")
		if r.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_OK || r.RequestId == "" || r.Notice != gateway.DataNotice {
			t.Fatalf("resp = %v", r)
		}
		if len(r.Columns) != 2 || r.Columns[0].Masked || !r.Columns[1].Masked || r.Columns[1].Class != "masked" || r.Columns[0].Type != "int8" {
			t.Fatalf("columns = %v", r.Columns)
		}
		if len(r.Rows) != 1 || r.RowCount != 1 || r.Rows[0].Values[0].GetNumberValue() != 1 {
			t.Fatalf("rows = %v", r.Rows)
		}
		if v := r.Rows[0].Values[1].GetStringValue(); v == "" || v == "user1@example.com" {
			t.Fatalf("email not masked: %q", v)
		}
	})

	t.Run("denied", func(t *testing.T) {
		r := e.exec(t, taro, "DROP TABLE users")
		if r.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_DENIED || r.Rule != "default-deny-ddl" || r.Stage == "" || r.Reason == "" || r.Hint == "" {
			t.Fatalf("resp = %v", r)
		}
		if len(r.Rows) != 0 || len(r.Columns) != 0 {
			t.Fatal("a denial must not carry results")
		}
		resp, err := e.client.ExecuteSQL(context.Background(), withBearer(&dbgatewayv1.ExecuteSQLRequest{Database: "prod", Sql: "SELECT 1"}, taro))
		if err != nil || resp.Msg.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_DENIED || resp.Msg.Rule != "builtin:reason-required" {
			t.Fatalf("empty reason: %v, %v", resp, err)
		}
		r = e.execOn(t, taro, "nope", "SELECT 1")
		if r.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_DENIED || r.Rule != "role:querier" {
			t.Fatalf("unknown database: %v", r)
		}
	})

	t.Run("error", func(t *testing.T) {
		e.fa.Set(func(a *gatewaytest.Adapter) {
			a.ExecErr = &pgconn.PgError{Code: "42703", Message: `column "x" does not exist`}
		})
		defer e.fa.Set(func(a *gatewaytest.Adapter) { a.ExecErr = nil })
		r := e.exec(t, taro, "SELECT id FROM users WHERE id = 1")
		if r.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_ERROR || r.Code != "42703" || !strings.Contains(r.Reason, "does not exist") {
			t.Fatalf("resp = %v", r)
		}
	})

	t.Run("pending", func(t *testing.T) {
		r := e.exec(t, taro, "UPDATE users SET plan = 'pro' WHERE id = 1")
		if r.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_PENDING || r.RequestId == "" || r.ApprovalRule != "default" ||
			r.ApprovalUrl != "http://127.0.0.1:8443/approvals/"+r.RequestId || r.ExpireTime == nil || r.Risk == "" ||
			!slices.Contains(r.Approvers, "hanako@example.com") || r.MaxAffectedRows <= 0 {
			t.Fatalf("resp = %v", r)
		}
		if len(e.fa.Writes()) != 0 {
			t.Fatal("a pending write must not run")
		}
	})

	t.Run("invalid arguments", func(t *testing.T) {
		for name, req := range map[string]*dbgatewayv1.ExecuteSQLRequest{
			"no database": {Sql: "SELECT 1", Reason: "x"},
			"no sql":      {Database: "prod", Sql: "  ", Reason: "x"},
		} {
			if _, err := e.client.ExecuteSQL(context.Background(), withBearer(req, taro)); code(err) != connect.CodeInvalidArgument {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

func (e *gwEnv) execOn(t *testing.T, token, db, sql string) *dbgatewayv1.ExecuteSQLResponse {
	t.Helper()
	resp, err := e.client.ExecuteSQL(context.Background(), withBearer(&dbgatewayv1.ExecuteSQLRequest{
		Database: db, Sql: sql, Reason: "API test: verify the gateway service mapping"}, token))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg
}

func TestGatewayServiceRefusesAgentsAndAnonymous(t *testing.T) {
	e := newGatewayEnv(t, gatewayConfig, true)
	ctx := context.Background()
	agent := e.agentToken(t, e.humanToken(t, "taro@example.com"))
	if _, err := e.client.ExecuteSQL(ctx, withBearer(&dbgatewayv1.ExecuteSQLRequest{Database: "prod", Sql: "SELECT 1", Reason: "x"}, agent)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("agent execute: %v", err)
	}
	if _, err := e.client.ListDatabases(ctx, withBearer(&dbgatewayv1.ListDatabasesRequest{}, agent)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("agent list: %v", err)
	}
	if _, err := e.client.ListRequests(ctx, withBearer(&dbgatewayv1.ListRequestsRequest{}, agent)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("agent list requests: %v", err)
	}
	for name, tok := range map[string]string{"none": "", "unknown": auth.AccessTokenPrefix + "zzz"} {
		if _, err := e.client.ListDatabases(ctx, withBearer(&dbgatewayv1.ListDatabasesRequest{}, tok)); code(err) != connect.CodeUnauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(e.fa.Execs()) != 0 {
		t.Fatal("nothing must run")
	}
}

func TestListDatabasesSearchExplain(t *testing.T) {
	e := newGatewayEnv(t, gatewayConfig, true)
	ctx := context.Background()
	taro := e.humanToken(t, "taro@example.com")

	dbs, err := e.client.ListDatabases(ctx, withBearer(&dbgatewayv1.ListDatabasesRequest{}, taro))
	if err != nil {
		t.Fatal(err)
	}
	if dbs.Msg.Principal != "taro@example.com" || len(dbs.Msg.Databases) != 1 {
		t.Fatalf("dbs = %v", dbs.Msg)
	}
	d := dbs.Msg.Databases[0]
	if d.Name != "prod" || d.Type != "postgres" || d.Labels["env"] != "prod" || !d.CanRead || !d.CanWrite || !slices.Contains(d.Roles, "writer") {
		t.Fatalf("db = %v", d)
	}

	sr, err := e.client.SearchObjects(ctx, withBearer(&dbgatewayv1.SearchObjectsRequest{Database: "prod", Keyword: "users"}, taro))
	if err != nil {
		t.Fatal(err)
	}
	if len(sr.Msg.Objects) != 1 || sr.Msg.Objects[0].Name != "users" || sr.Msg.RequestId == "" {
		t.Fatalf("search = %v", sr.Msg)
	}
	for _, c := range sr.Msg.Objects[0].Columns {
		if (c.Name == "email") != c.Masked {
			t.Errorf("column %s masked = %v", c.Name, c.Masked)
		}
	}
	if _, err := e.client.SearchObjects(ctx, withBearer(&dbgatewayv1.SearchObjectsRequest{Database: "nope"}, taro)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("unknown db search: %v", err)
	}
	if _, err := e.client.SearchObjects(ctx, withBearer(&dbgatewayv1.SearchObjectsRequest{}, taro)); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("no db search: %v", err)
	}

	ex, err := e.client.ExplainPolicy(ctx, withBearer(&dbgatewayv1.ExplainPolicyRequest{Database: "prod",
		Sql: "UPDATE users SET plan = 'x' WHERE id = 1 RETURNING id, email"}, taro))
	if err != nil {
		t.Fatal(err)
	}
	m := ex.Msg
	if m.Decision != dbgatewayv1.PolicyDecision_POLICY_DECISION_APPROVE || m.ApprovalRule != "default" || len(m.ApprovalSteps) != 1 ||
		m.ApprovalSteps[0].Role != "approver" || m.ExpireAfter.AsDuration() != 30*time.Minute || !slices.Contains(m.Approvers, "hanako@example.com") ||
		m.Statement == nil || !m.Statement.IsWrite || m.Estimate == nil || len(m.Output) != 2 || !m.Output[1].Masked || m.Output[0].Masked {
		t.Fatalf("explain = %v", m)
	}
	ex, err = e.client.ExplainPolicy(ctx, withBearer(&dbgatewayv1.ExplainPolicyRequest{Database: "prod", Sql: "DROP TABLE users"}, taro))
	if err != nil || ex.Msg.Decision != dbgatewayv1.PolicyDecision_POLICY_DECISION_DENY || ex.Msg.Hint == "" {
		t.Fatalf("explain ddl = %v, %v", ex, err)
	}
	if _, err := e.client.ExplainPolicy(ctx, withBearer(&dbgatewayv1.ExplainPolicyRequest{Database: "nope", Sql: "SELECT 1"}, taro)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("unknown db explain: %v", err)
	}
	if len(e.fa.Execs()) != 0 {
		t.Fatal("search and explain must not execute")
	}
}

func TestApprovalRequestRPCs(t *testing.T) {
	e := newGatewayEnv(t, gatewayConfig, true)
	ctx := context.Background()
	taro := e.humanToken(t, "taro@example.com")
	hanako := e.humanToken(t, "hanako@example.com")
	nobody := e.humanToken(t, "nobody@example.com")

	first := e.exec(t, taro, "UPDATE users SET plan = 'pro' WHERE id = 1")
	second := e.exec(t, taro, "UPDATE users SET plan = 'free' WHERE id = 2")
	if first.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_PENDING || second.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_PENDING {
		t.Fatalf("not pending: %v / %v", first, second)
	}

	got, err := e.client.GetRequest(ctx, withBearer(&dbgatewayv1.GetRequestRequest{Id: first.RequestId}, taro))
	if err != nil {
		t.Fatal(err)
	}
	r := got.Msg.Request
	if r.Id != first.RequestId || r.Status != dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_PENDING || r.Sql != "UPDATE users SET plan = 'pro' WHERE id = 1" ||
		r.Requester.Kind != dbgatewayv1.TokenKind_TOKEN_KIND_HUMAN || r.Requester.Human != "taro@example.com" || r.Database != "prod" ||
		r.ApprovalRule != "default" || len(r.Steps) != 1 || r.Kind == "" || len(r.Tables) != 1 || r.Url == "" || r.ExpireTime == nil || got.Msg.Notice != "" {
		t.Fatalf("request = %v", r)
	}
	// Invisible and nonexistent requests look the same.
	for name, id := range map[string]string{"invisible": first.RequestId, "missing": "req_nope"} {
		if _, err := e.client.GetRequest(ctx, withBearer(&dbgatewayv1.GetRequestRequest{Id: id}, nobody)); code(err) != connect.CodeNotFound {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.client.GetRequest(ctx, withBearer(&dbgatewayv1.GetRequestRequest{Id: " "}, taro)); code(err) != connect.CodeInvalidArgument {
		t.Errorf("empty id: %v", err)
	}

	list := func(tok string, scope dbgatewayv1.RequestScope) []*dbgatewayv1.ApprovalRequest {
		t.Helper()
		resp, err := e.client.ListRequests(ctx, withBearer(&dbgatewayv1.ListRequestsRequest{Scope: scope}, tok))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg.Requests
	}
	if mine := list(taro, dbgatewayv1.RequestScope_REQUEST_SCOPE_UNSPECIFIED); len(mine) != 2 || mine[0].Sql != "" || mine[0].NormalizedSql == "" {
		t.Fatalf("mine = %v", mine)
	}
	if aw := list(hanako, dbgatewayv1.RequestScope_REQUEST_SCOPE_AWAITING_ME); len(aw) != 2 {
		t.Fatalf("awaiting hanako = %v", aw)
	}
	if aw := list(taro, dbgatewayv1.RequestScope_REQUEST_SCOPE_AWAITING_ME); len(aw) != 0 {
		t.Fatalf("awaiting taro = %v", aw)
	}
	if _, err := e.client.ListRequests(ctx, withBearer(&dbgatewayv1.ListRequestsRequest{Scope: 99}, taro)); code(err) != connect.CodeInvalidArgument {
		t.Errorf("bad scope: %v", err)
	}

	// The requester cannot reject; outsiders cannot see; an approver can.
	if _, err := e.client.RejectRequest(ctx, withBearer(&dbgatewayv1.RejectRequestRequest{Id: first.RequestId}, taro)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("self reject: %v", err)
	}
	if _, err := e.client.RejectRequest(ctx, withBearer(&dbgatewayv1.RejectRequestRequest{Id: first.RequestId}, nobody)); code(err) != connect.CodeNotFound {
		t.Fatalf("outsider reject: %v", err)
	}
	if _, err := e.client.RejectRequest(ctx, withBearer(&dbgatewayv1.RejectRequestRequest{Id: first.RequestId, Comment: strings.Repeat("x", 1001)}, hanako)); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("long comment: %v", err)
	}
	rej, err := e.client.RejectRequest(ctx, withBearer(&dbgatewayv1.RejectRequestRequest{Id: first.RequestId, Comment: "use the batch job"}, hanako))
	if err != nil {
		t.Fatal(err)
	}
	if rr := rej.Msg.Request; rr.Status != dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_REJECTED || rr.DecidedBy != "hanako@example.com" ||
		rr.Comment != "use the batch job" || rr.DecideTime == nil {
		t.Fatalf("rejected = %v", rr)
	}
	if _, err := e.client.CancelRequest(ctx, withBearer(&dbgatewayv1.CancelRequestRequest{Id: first.RequestId}, taro)); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("cancel after reject: %v", err)
	}

	// Only the requester can cancel.
	if _, err := e.client.CancelRequest(ctx, withBearer(&dbgatewayv1.CancelRequestRequest{Id: second.RequestId}, hanako)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign cancel: %v", err)
	}
	can, err := e.client.CancelRequest(ctx, withBearer(&dbgatewayv1.CancelRequestRequest{Id: second.RequestId}, taro))
	if err != nil || can.Msg.Request.Status != dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_CANCELED {
		t.Fatalf("cancel = %v, %v", can, err)
	}
	if dec := list(taro, dbgatewayv1.RequestScope_REQUEST_SCOPE_DECIDED); len(dec) != 2 {
		t.Fatalf("decided = %v", dec)
	}
	if len(e.fa.Writes()) != 0 {
		t.Fatal("nothing must be written")
	}
}

func TestGatewayServiceWithoutApprovals(t *testing.T) {
	e := newGatewayEnv(t, gatewayConfig, false)
	ctx := context.Background()
	taro := e.humanToken(t, "taro@example.com")
	r := e.exec(t, taro, "UPDATE users SET plan = 'pro' WHERE id = 1")
	if r.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_DENIED || r.Rule != "builtin:approval-unavailable" {
		t.Fatalf("write without approvals: %v", r)
	}
	if _, err := e.client.GetRequest(ctx, withBearer(&dbgatewayv1.GetRequestRequest{Id: "req_x"}, taro)); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("get: %v", err)
	}
	if _, err := e.client.ListRequests(ctx, withBearer(&dbgatewayv1.ListRequestsRequest{}, taro)); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("list: %v", err)
	}
	if _, err := e.client.CancelRequest(ctx, withBearer(&dbgatewayv1.CancelRequestRequest{Id: "req_x"}, taro)); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := e.client.RejectRequest(ctx, withBearer(&dbgatewayv1.RejectRequestRequest{Id: "req_x"}, taro)); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("reject: %v", err)
	}
}

func TestTraceparentRecorded(t *testing.T) {
	e := newGatewayEnv(t, gatewayConfig, true)
	taro := e.humanToken(t, "taro@example.com")
	const trace = "4bf92f3577b34da6a3ce929d0e0e4736"
	req := withBearer(&dbgatewayv1.ExecuteSQLRequest{Database: "prod", Sql: "SELECT id FROM users WHERE id = 1", Reason: "API test: trace correlation"}, taro)
	req.Header().Set("traceparent", "00-"+trace+"-00f067aa0ba902b7-01")
	if _, err := e.client.ExecuteSQL(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var found bool
	_ = filepath.WalkDir(e.auditDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(path)
			found = found || strings.Contains(string(b), `"trace_id":"`+trace+`"`)
		}
		return nil
	})
	if !found {
		t.Fatal("trace id not in the audit log")
	}
}

func TestTraceID(t *testing.T) {
	for in, want := range map[string]string{
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01":  "4bf92f3577b34da6a3ce929d0e0e4736",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01":  "",
		"00-4bf92f3577b34da6a3ce929d0e0e473\n-00f067aa0ba902b7-01": "",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01":  "",
		"garbage": "",
		"":        "",
	} {
		h := http.Header{}
		h.Set("traceparent", in)
		if got := traceID(h); got != want {
			t.Errorf("traceID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValueConversion(t *testing.T) {
	big := int64(1)<<53 + 1
	cases := []struct {
		in   any
		want any
	}{
		{nil, nil},
		{true, true},
		{"x", "x"},
		{int64(42), 42.0},
		{int32(-7), -7.0},
		{big, "9007199254740993"},
		{-big, "-9007199254740993"},
		{uint64(math.MaxUint64), "18446744073709551615"},
		{1.5, 1.5},
		{math.NaN(), "NaN"},
		{math.Inf(1), "+Inf"},
		{[]any{int64(1), "a", nil}, []any{1.0, "a", nil}},
		{map[string]any{"k": big}, map[string]any{"k": "9007199254740993"}},
		{time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "2026-01-02T03:04:05Z"},
		{struct {
			A int `json:"a"`
		}{3}, map[string]any{"a": 3.0}},
	}
	for _, c := range cases {
		got := value(c.in).AsInterface()
		if !equalJSONish(got, c.want) {
			t.Errorf("value(%#v) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func equalJSONish(a, b any) bool {
	switch x := a.(type) {
	case []any:
		y, ok := b.([]any)
		return ok && slices.EqualFunc(x, y, equalJSONish)
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			if !equalJSONish(v, y[k]) {
				return false
			}
		}
		return true
	}
	return a == b
}

func TestExecuteResponseConversion(t *testing.T) {
	total := int64(1000)
	r := executeResponse(&gateway.ExecuteResponse{Status: "something-new", RequestID: "req_1",
		Columns: []gateway.ResultColumn{{Name: "secret", Type: "text", Withheld: true, Class: "no_ai"}},
		Rows:    [][]any{{nil}}, RowCount: 1, TotalRows: &total, Truncated: true})
	if r.Status != dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_ERROR {
		t.Errorf("unknown status must map to error, got %v", r.Status)
	}
	if !r.Columns[0].Withheld || r.Columns[0].Class != "no_ai" || r.GetTotalRows() != 1000 || !r.Truncated {
		t.Errorf("resp = %v", r)
	}
	if policyDecision("weird") != dbgatewayv1.PolicyDecision_POLICY_DECISION_DENY {
		t.Error("unknown decision must map to deny")
	}
}
