//go:build integration

// End-to-end test: the real server stack, an OAuth client discovering the
// authorization server from the MCP endpoint, a browser completing login
// and consent, and an MCP client calling the tools against PostgreSQL.
//
//	docker compose -f examples/dev/compose.yaml up -d --wait
//	go test -tags integration ./internal/server/
package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/server"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type stack struct {
	base     string
	auditDir string
}

func start(t *testing.T) *stack {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	dir := t.TempDir()
	t.Setenv("DBGW_E2E_PASSWORD", env("DBGW_TEST_PG_PASSWORD", "reader"))
	yaml := fmt.Sprintf(`
server: { listen: "%[1]s", public_url: "http://%[1]s" }
auth: { dev_login: true }
store: { path: "%[2]s/db.sqlite" }
audit: { dir: "%[2]s/audit" }
databases:
  - name: dev-main
    labels: { env: prod }
    primary: { host: %[3]s, port: %[4]s, dbname: app, read_user: dbgw_reader, password_env: DBGW_E2E_PASSWORD, sslmode: %[5]s, sslrootcert: "%[6]s" }
groups:
  - { name: developers, members: [taro@example.com] }
role_bindings:
  - { group: developers, databases: "*", roles: [querier] }
data_classes:
  - { columns: ["public.users.email"], class: masked, semantic_type: contact }
  - { columns: ["public.support_tickets.body"], class: no_ai }
  - { column_pattern: "public\\.[a-z_]+\\.(id|user_id|plan|status|reason|name)", class: public }
semantic_types:
  contact: { method: partial }
policies:
  - { name: agents-never-see-no-ai, when: 'principal.kind == "agent" && columns.exists(c, c.class == "no_ai")', action: deny }
  - { name: reads, when: 'stmt.kind == "select" && !stmt.is_write', action: allow }
`, addr, dir, env("DBGW_TEST_PG_HOST", "127.0.0.1"), env("DBGW_TEST_PG_PORT", "55432"),
		env("DBGW_TEST_PG_SSLMODE", "disable"), env("DBGW_TEST_PG_SSLROOTCERT", ""))
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := server.New(context.Background(), cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close(); srv.Close() })
	return &stack{base: "http://" + addr, auditDir: filepath.Join(dir, "audit")}
}

func getJSON(t *testing.T, u string, v any) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func form(t *testing.T, c *http.Client, method, u string, values url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if values != nil {
		body = strings.NewReader(values.Encode())
	}
	req, _ := http.NewRequest(method, u, body)
	if values != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func csrf(t *testing.T, page string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no csrf in page")
	}
	return html.UnescapeString(m[1])
}

// oauth performs discovery, registration, login, consent and the token
// exchange, returning an access token for the MCP resource.
func oauth(t *testing.T, s *stack) string {
	t.Helper()
	// 1. The MCP endpoint challenges with the resource metadata URL.
	resp, err := http.Post(s.base+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /mcp: %d", resp.StatusCode)
	}
	m := regexp.MustCompile(`resource_metadata="([^"]+)"`).FindStringSubmatch(resp.Header.Get("WWW-Authenticate"))
	if m == nil {
		t.Fatalf("no resource_metadata in %q", resp.Header.Get("WWW-Authenticate"))
	}
	// 2. Protected resource metadata → authorization server metadata.
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	getJSON(t, m[1], &prm)
	var asm struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		RegistrationEndpoint  string `json:"registration_endpoint"`
	}
	getJSON(t, prm.AuthorizationServers[0]+"/.well-known/oauth-authorization-server", &asm)

	// 3. Dynamic client registration (public client, loopback redirect).
	redirect := "http://127.0.0.1:33418/callback"
	b, _ := json.Marshal(map[string]any{"client_name": "E2E Client", "redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none"})
	resp, err = http.Post(asm.RegistrationEndpoint, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()

	// 4. Browser: login, then consent.
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	_, page := form(t, browser, "GET", s.base+"/login", nil)
	if r, _ := form(t, browser, "POST", s.base+"/login", url.Values{"csrf": {csrf(t, page)}, "email": {"taro@example.com"}}); r.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", r.StatusCode)
	}
	verifier := "e2e-verifier-0123456789-0123456789-0123456789-abcdef"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {redirect},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {"st"}, "scope": {"db:read"}, "resource": {prm.Resource},
	}
	r, page := form(t, browser, "GET", asm.AuthorizationEndpoint+"?"+q.Encode(), nil)
	if r.StatusCode != http.StatusOK || !strings.Contains(page, "dev-main") {
		t.Fatalf("consent page: %d", r.StatusCode)
	}
	post := url.Values{}
	for k, v := range q {
		post[k] = v
	}
	post.Set("csrf", csrf(t, page))
	post.Set("action", "approve")
	post.Set("agent_name", "e2e-agent")
	post.Set("database", "dev-main")
	r, _ = form(t, browser, "POST", asm.AuthorizationEndpoint, post)
	loc, _ := url.Parse(r.Header.Get("Location"))
	if r.StatusCode != http.StatusFound || loc.Query().Get("state") != "st" || loc.Query().Get("code") == "" {
		t.Fatalf("consent redirect: %d %s", r.StatusCode, loc)
	}

	// 5. Token exchange with PKCE.
	r, body := form(t, http.DefaultClient, "POST", asm.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {reg.ClientID}, "code": {loc.Query().Get("code")},
		"code_verifier": {verifier}, "redirect_uri": {redirect}, "resource": {prm.Resource},
	})
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal([]byte(body), &tok)
	if r.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("token: %d %s", r.StatusCode, body)
	}
	return tok.AccessToken
}

type bearer struct {
	token string
	next  http.RoundTripper
}

func (b *bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (*mcp.CallToolResult, map[string]any) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var out map[string]any
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	return res, out
}

func TestEndToEnd(t *testing.T) {
	s := start(t)
	token := oauth(t, s)

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   s.base + "/mcp",
		HTTPClient: &http.Client{Transport: &bearer{token: token, next: http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "execute_sql,list_databases,search_objects" && len(names) != 3 {
		t.Fatalf("tools = %v", names)
	}

	_, out := call(t, cs, "list_databases", map[string]any{})
	if !strings.Contains(fmt.Sprint(out), "dev-main") || !strings.Contains(fmt.Sprint(out["principal"]), "e2e-agent") {
		t.Fatalf("list_databases = %v", out)
	}

	_, out = call(t, cs, "search_objects", map[string]any{"database": "dev-main", "keyword": "users"})
	if !strings.Contains(fmt.Sprint(out["objects"]), "email") {
		t.Fatalf("search_objects = %v", out)
	}

	res, out := call(t, cs, "execute_sql", map[string]any{"database": "dev-main",
		"sql": "SELECT id, email, plan FROM users WHERE id = 3", "reason": "e2e: confirm masking for support ticket 1234"})
	if res.IsError || out["status"] != "ok" {
		t.Fatalf("execute_sql: %v", out)
	}
	row := out["rows"].([]any)[0].([]any)
	if row[1] != "u***@example.com" {
		t.Fatalf("email not masked: %v", row)
	}

	res, out = call(t, cs, "execute_sql", map[string]any{"database": "dev-main",
		"sql": "SELECT body FROM support_tickets", "reason": "e2e: no_ai columns must be denied"})
	if !res.IsError || out["status"] != "denied" || out["rule"] != "agents-never-see-no-ai" {
		t.Fatalf("no_ai: %v", out)
	}
	res, out = call(t, cs, "execute_sql", map[string]any{"database": "dev-main",
		"sql": "UPDATE users SET plan = 'pro' WHERE id = 1", "reason": "e2e: writes are denied in phase 1"})
	if !res.IsError || out["status"] != "denied" {
		t.Fatalf("write: %v", out)
	}

	rep, err := audit.VerifyDir(s.auditDir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries < 4 {
		t.Errorf("audit entries = %d", rep.Entries)
	}
	raw, _ := os.ReadFile(func() string { m, _ := filepath.Glob(filepath.Join(s.auditDir, "*.jsonl")); return m[0] }())
	if !strings.Contains(string(raw), `"agent":"e2e-agent"`) || !strings.Contains(string(raw), `"human":"taro@example.com"`) {
		t.Errorf("audit log lacks agent/human identity")
	}

	// A human CLI-style token or a garbage token must not reach /mcp.
	bad := mcp.NewClient(&mcp.Implementation{Name: "bad", Version: "1"}, nil)
	if _, err := bad.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   s.base + "/mcp",
		HTTPClient: &http.Client{Transport: &bearer{token: "dbgw_at_invalid", next: http.DefaultTransport}},
	}, nil); err == nil {
		t.Error("invalid token accepted")
	}
}
