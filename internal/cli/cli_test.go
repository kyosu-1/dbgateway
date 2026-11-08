package cli

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kyosu-1/dbgateway/internal/api"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
)

func TestCredentialsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dbgw", "credentials.json")
	old := credentialsPath
	credentialsPath = func() (string, error) { return path, nil }
	t.Cleanup(func() { credentialsPath = old })

	if c, err := loadCredentials(); err != nil || c != nil {
		t.Fatalf("empty load = %v, %v", c, err)
	}
	want := &Credentials{Server: "https://dbgw.example.com", AccessToken: "dbgw_at_x", ExpiresAt: time.Now().Add(time.Hour).Round(time.Second)}
	if err := saveCredentials(want); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	di, _ := os.Stat(filepath.Dir(path))
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("perms: file %v dir %v", fi.Mode().Perm(), di.Mode().Perm())
	}
	got, err := loadCredentials()
	if err != nil || got.Server != want.Server || got.AccessToken != want.AccessToken || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("load = %+v, %v", got, err)
	}
	if err := deleteCredentials(); err != nil {
		t.Fatal(err)
	}
	if c, _ := loadCredentials(); c != nil {
		t.Fatal("not deleted")
	}
}

func TestNormalizeServer(t *testing.T) {
	for in, ok := range map[string]bool{
		"https://dbgw.example.com/": true, "http://127.0.0.1:8443": true, "http://localhost:8443": true,
		"http://dbgw.example.com": false, "ftp://x": false, "https://u:p@x.example": false, "dbgw.example.com": false,
	} {
		if _, err := normalizeServer(in); (err == nil) != ok {
			t.Errorf("%s: %v", in, err)
		}
	}
}

const relayConfig = `
server:
  listen: 127.0.0.1:8443
  public_url: %s
auth:
  dev_login: true
databases:
  - name: prod-main
    primary: { host: localhost, read_user: r, sslmode: disable }
groups:
  - name: data-team
    members: [taro@example.com]
role_bindings:
  - group: data-team
    databases: ["prod-main"]
    roles: [querier]
`

// TestStdioRelay runs the relay against a bearer-protected upstream MCP
// server and checks that calls arrive as the agent.
func TestStdioRelay(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewUnstartedServer(nil)
	public := "http://" + srv.Listener.Addr().String()
	cfg, err := config.Parse([]byte(strings.Replace(relayConfig, "%s", public, 1)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a, err := auth.New(ctx, auth.Options{Config: cfg, Store: st, RBAC: policy.NewRBAC(cfg), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}

	upstream := mcp.NewServer(&mcp.Implementation{Name: "dbgateway"}, &mcp.ServerOptions{Instructions: "be careful"})
	mcp.AddTool(upstream, &mcp.Tool{Name: "whoami", Description: "who is calling"},
		func(ctx context.Context, req *mcp.CallToolRequest, in struct {
			Echo string `json:"echo"`
		}) (*mcp.CallToolResult, any, error) {
			p := auth.PrincipalFromTokenInfo(req.Extra.TokenInfo)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(p.Kind) + "|" + p.Human + "|" + p.Agent + "|" + in.Echo}}}, nil, nil
		})
	mux := http.NewServeMux()
	a.Register(mux)
	path, h := api.NewTokenService(a, st, cfg)
	mux.Handle(path, h)
	mux.Handle("/mcp", mcpauth.RequireBearerToken(a.VerifyToken, &mcpauth.RequireBearerTokenOptions{
		ResourceMetadataURL: a.ResourceMetadataURL(), Scopes: []string{identity.ScopeRead},
	})(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upstream }, nil)))
	srv.Config.Handler = mux
	srv.Start()
	defer srv.Close()

	// A human CLI token, as `dbgw login` would have saved.
	raw := auth.AccessTokenPrefix + "relay-test"
	now := time.Now()
	if err := st.CreateToken(ctx, &store.Token{ID: "tok_h", Hash: store.HashSecret(raw), Type: store.TokenAccess, Kind: identity.KindHuman,
		Human: "taro@example.com", ClientID: auth.CLIClientID, Scopes: []string{identity.ScopeRead}, Audience: public,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	creds := &Credentials{Server: public, AccessToken: raw, ExpiresAt: now.Add(time.Hour)}

	// The human token itself is refused by the MCP endpoint.
	req, _ := http.NewRequest("POST", public+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+raw)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("human token at /mcp: %v %v", resp.StatusCode, err)
	}

	ts := &agentTokenSource{client: tokenServiceClient(creds), agent: "claude-desktop", databases: []string{"prod-main"}}
	localServer, localClient := mcp.NewInMemoryTransports()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runStdioRelay(runCtx, slog.New(slog.NewTextHandler(io.Discard, nil)), public+"/mcp", ts, localServer)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, err := client.Connect(ctx, localClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if got := cs.InitializeResult().Instructions; got != "be careful" {
		t.Errorf("instructions = %q", got)
	}
	tools, err := cs.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "whoami" {
		t.Fatalf("tools = %v, %v", tools, err)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "whoami", Arguments: map[string]any{"echo": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Content[0].(*mcp.TextContent).Text; got != "agent|taro@example.com|claude-desktop|hi" {
		t.Fatalf("whoami = %q", got)
	}

	// After the agent token is revoked, the relay re-mints one.
	tok, _ := ts.Token(ctx)
	if p, err := a.Authenticate(ctx, tok); err != nil {
		t.Fatal(err)
	} else if _, err := st.RevokeToken(ctx, p.TokenID, time.Now()); err != nil {
		t.Fatal(err)
	}
	cs.CallTool(ctx, &mcp.CallToolParams{Name: "whoami", Arguments: map[string]any{"echo": "x"}}) // 401 -> invalidate
	tok2, err := ts.Token(ctx)
	if err != nil || tok2 == tok {
		t.Fatalf("token not re-minted after 401: %v", err)
	}
	cancel()
}
