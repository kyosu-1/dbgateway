package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
	"github.com/kyosu-1/dbgateway/gen/dbgateway/v1/dbgatewayv1connect"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
)

const testConfig = `
server:
  listen: 127.0.0.1:8443
  public_url: http://127.0.0.1:8443
auth:
  dev_login: true
  agent_tokens: { max_ttl: 1h }
databases:
  - name: prod-main
    primary: { host: localhost, read_user: r, sslmode: disable }
  - name: analytics
    primary: { host: localhost, read_user: r, sslmode: disable }
groups:
  - name: data-team
    members: [taro@example.com]
role_bindings:
  - group: data-team
    databases: ["prod-main"]
    roles: [querier]
`

type env struct {
	client dbgatewayv1connect.TokenServiceClient
	auth   *auth.Server
	store  store.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(context.Background(), auth.Options{
		Config: cfg, Store: st, RBAC: policy.NewRBAC(cfg),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	path, h := NewTokenService(a, st, cfg)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() { srv.Close(); st.Close() })
	return &env{client: dbgatewayv1connect.NewTokenServiceClient(srv.Client(), srv.URL), auth: a, store: st}
}

// humanToken stores a CLI token for email and returns its raw value.
func (e *env) humanToken(t *testing.T, email string, ttl time.Duration) string {
	t.Helper()
	raw := auth.AccessTokenPrefix + "test-" + email
	now := time.Now()
	if err := e.store.CreateToken(context.Background(), &store.Token{
		ID: "tok_human_" + email, Hash: store.HashSecret(raw), Type: store.TokenAccess, Kind: identity.KindHuman,
		Human: email, ClientID: auth.CLIClientID, Scopes: []string{identity.ScopeRead},
		Audience: "http://127.0.0.1:8443", CreatedAt: now, ExpiresAt: now.Add(ttl),
	}); err != nil {
		t.Fatal(err)
	}
	return raw
}

func withBearer[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	return req
}

func code(err error) connect.Code {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Code()
	}
	return connect.CodeUnknown
}

func TestCreateListRevoke(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	human := e.humanToken(t, "taro@example.com", 12*time.Hour)

	resp, err := e.client.CreateAgentToken(ctx, withBearer(&dbgatewayv1.CreateAgentTokenRequest{
		AgentName: "ci-report", Databases: []string{"prod-main"}, TtlSeconds: 999999,
	}, human))
	if err != nil {
		t.Fatal(err)
	}
	tok := resp.Msg.Token
	if tok.Kind != dbgatewayv1.TokenKind_TOKEN_KIND_AGENT || tok.AgentName != "ci-report" || tok.ClientId != auth.CLIClientID ||
		tok.ParentId != "tok_human_taro@example.com" || !slices.Equal(tok.Scopes, []string{"db:read"}) {
		t.Fatalf("token = %+v", tok)
	}
	if d := time.Until(resp.Msg.ExpireTime.AsTime()); d > time.Hour+time.Minute || d < 59*time.Minute {
		t.Fatalf("ttl not capped: %v", d)
	}

	// The minted token works at the MCP endpoint as an agent.
	ti, err := e.auth.VerifyToken(ctx, resp.Msg.AccessToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := auth.PrincipalFromTokenInfo(ti)
	if p.Kind != identity.KindAgent || p.Human != "taro@example.com" || !slices.Equal(p.Databases, []string{"prod-main"}) {
		t.Fatalf("principal = %+v", p)
	}

	// An agent token cannot mint, list or revoke tokens.
	_, err = e.client.CreateAgentToken(ctx, withBearer(&dbgatewayv1.CreateAgentTokenRequest{AgentName: "x", Databases: []string{"prod-main"}}, resp.Msg.AccessToken))
	if code(err) != connect.CodePermissionDenied {
		t.Fatalf("agent mint: %v", err)
	}
	if _, err := e.client.ListTokens(ctx, withBearer(&dbgatewayv1.ListTokensRequest{}, resp.Msg.AccessToken)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("agent list: %v", err)
	}

	list, err := e.client.ListTokens(ctx, withBearer(&dbgatewayv1.ListTokensRequest{}, human))
	if err != nil || len(list.Msg.Tokens) != 2 {
		t.Fatalf("list = %v, %v", list, err)
	}

	// Someone else cannot revoke it.
	other := e.humanToken(t, "hanako@example.com", time.Hour)
	if _, err := e.client.RevokeToken(ctx, withBearer(&dbgatewayv1.RevokeTokenRequest{Id: tok.Id}, other)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign revoke: %v", err)
	}
	if _, err := e.client.RevokeToken(ctx, withBearer(&dbgatewayv1.RevokeTokenRequest{Id: "nope"}, human)); code(err) != connect.CodeNotFound {
		t.Fatalf("missing revoke: %v", err)
	}
	if _, err := e.client.RevokeToken(ctx, withBearer(&dbgatewayv1.RevokeTokenRequest{Id: tok.Id}, human)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.VerifyToken(ctx, resp.Msg.AccessToken, nil); err == nil {
		t.Fatal("revoked token still valid")
	}
	list, _ = e.client.ListTokens(ctx, withBearer(&dbgatewayv1.ListTokensRequest{}, human))
	all, _ := e.client.ListTokens(ctx, withBearer(&dbgatewayv1.ListTokensRequest{IncludeInactive: true}, human))
	if len(list.Msg.Tokens) != 1 || len(all.Msg.Tokens) != 2 || all.Msg.Tokens[0].RevokeTime == nil && all.Msg.Tokens[1].RevokeTime == nil {
		t.Fatalf("after revoke: active=%d all=%d", len(list.Msg.Tokens), len(all.Msg.Tokens))
	}

	// Revoking the human token revokes the agent tokens minted from it.
	resp, _ = e.client.CreateAgentToken(ctx, withBearer(&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a", Databases: []string{"prod-main"}}, human))
	if _, err := e.client.RevokeToken(ctx, withBearer(&dbgatewayv1.RevokeTokenRequest{Id: "tok_human_taro@example.com"}, human)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.VerifyToken(ctx, resp.Msg.AccessToken, nil); err == nil {
		t.Fatal("child agent token valid after parent revoked")
	}
}

func TestCreateAgentTokenValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	human := e.humanToken(t, "taro@example.com", time.Hour)
	for name, tc := range map[string]struct {
		req  *dbgatewayv1.CreateAgentTokenRequest
		want connect.Code
	}{
		"no databases":    {&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a"}, connect.CodeInvalidArgument},
		"no agent name":   {&dbgatewayv1.CreateAgentTokenRequest{Databases: []string{"prod-main"}}, connect.CodeInvalidArgument},
		"write scope":     {&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a", Databases: []string{"prod-main"}, Scopes: []string{"db:write"}}, connect.CodeInvalidArgument},
		"no access":       {&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a", Databases: []string{"analytics"}}, connect.CodePermissionDenied},
		"unknown db":      {&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a", Databases: []string{"nope"}}, connect.CodePermissionDenied},
		"wildcard":        {&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a", Databases: []string{"*"}}, connect.CodeInvalidArgument},
		"negative ttl":    {&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a", Databases: []string{"prod-main"}, TtlSeconds: -1}, connect.CodeInvalidArgument},
		"control in name": {&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a\nb", Databases: []string{"prod-main"}}, connect.CodeInvalidArgument},
	} {
		if _, err := e.client.CreateAgentToken(ctx, withBearer(tc.req, human)); code(err) != tc.want {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// A user without any role cannot mint.
	nobody := e.humanToken(t, "nobody@example.com", time.Hour)
	if _, err := e.client.CreateAgentToken(ctx, withBearer(&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a", Databases: []string{"prod-main"}}, nobody)); code(err) != connect.CodePermissionDenied {
		t.Errorf("no roles: %v", err)
	}
	// The agent token never outlives the human token.
	raw := auth.AccessTokenPrefix + "short"
	now := time.Now()
	if err := e.store.CreateToken(ctx, &store.Token{
		ID: "tok_short", Hash: store.HashSecret(raw), Type: store.TokenAccess, Kind: identity.KindHuman,
		Human: "taro@example.com", ClientID: auth.CLIClientID, Scopes: []string{identity.ScopeRead},
		Audience: "http://127.0.0.1:8443", CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := e.client.CreateAgentToken(ctx, withBearer(&dbgatewayv1.CreateAgentTokenRequest{AgentName: "a", Databases: []string{"prod-main"}}, raw))
	if err != nil {
		t.Fatal(err)
	}
	if exp := resp.Msg.ExpireTime.AsTime(); exp.After(now.Add(10*time.Minute + time.Second)) {
		t.Fatalf("agent token outlives its parent: %v", exp)
	}
}

func TestUnauthenticated(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for name, tok := range map[string]string{"none": "", "garbage": "abc", "unknown": auth.AccessTokenPrefix + "zzz"} {
		if _, err := e.client.ListTokens(ctx, withBearer(&dbgatewayv1.ListTokensRequest{}, tok)); code(err) != connect.CodeUnauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
	expired := e.humanToken(t, "taro@example.com", -time.Minute)
	if _, err := e.client.ListTokens(ctx, withBearer(&dbgatewayv1.ListTokensRequest{}, expired)); code(err) != connect.CodeUnauthenticated {
		t.Errorf("expired: %v", err)
	}
}
