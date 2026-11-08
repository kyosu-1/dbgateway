//go:build cloud

// Package cloud verifies a deployed dbgateway end to end: passkey sign-in
// (no IdP, no dev login), OAuth for an MCP client, masked reads, a write
// submitted for approval, approval by another person with a passkey
// step-up, and the write executed by dbgateway's background loop.
//
// It is configured only through environment variables (printed by
// deploy/*/verify-env.sh):
//
//	DBGW_CLOUD_URL              public URL (server.public_url)
//	DBGW_CLOUD_CONNECT_ADDR     optional host:port to dial instead of the URL host (e.g. an ALB)
//	DBGW_CLOUD_CA_FILE          optional PEM to trust in addition to the system roots
//	DBGW_CLOUD_HEADER           optional "Name: value" header sent with every request
//	                            (e.g. X-Serverless-Authorization for Cloud Run IAM)
//	DBGW_CLOUD_DB               database name (default cloud-main)
//	DBGW_CLOUD_ENROLL_REQUESTER one-time passkey enrollment link of the requester
//	DBGW_CLOUD_ENROLL_APPROVER  one-time passkey enrollment link of the approver
//
//	go test -tags cloud -count=1 -v ./test/cloud/
package cloud

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kyosu-1/dbgateway/internal/testutil/webauthntest"
)

type target struct {
	base      string
	db        string
	transport http.RoundTripper
}

func env(t *testing.T, k string, required bool) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" && required {
		t.Skipf("%s is not set (see deploy/*/verify-env.sh)", k)
	}
	return v
}

// headerTransport adds a fixed header to every request.
type headerTransport struct {
	name, value string
	next        http.RoundTripper
}

func (h *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(h.name, h.value)
	return h.next.RoundTrip(r)
}

func newTarget(t *testing.T) *target {
	t.Helper()
	base := strings.TrimRight(env(t, "DBGW_CLOUD_URL", true), "/")
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tlsCfg := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	if f := env(t, "DBGW_CLOUD_CA_FILE", false); f != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(f)
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			t.Fatalf("DBGW_CLOUD_CA_FILE: %v", err)
		}
		tlsCfg.RootCAs = pool
	}
	tr.TLSClientConfig = tlsCfg
	if addr := env(t, "DBGW_CLOUD_CONNECT_ADDR", false); addr != "" {
		d := &net.Dialer{Timeout: 10 * time.Second}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}
	}
	var rt http.RoundTripper = tr
	if h := env(t, "DBGW_CLOUD_HEADER", false); h != "" {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			t.Fatal("DBGW_CLOUD_HEADER must be 'Name: value'")
		}
		rt = &headerTransport{name: strings.TrimSpace(name), value: strings.TrimSpace(value), next: rt}
	}
	db := env(t, "DBGW_CLOUD_DB", false)
	if db == "" {
		db = "cloud-main"
	}
	return &target{base: base, db: db, transport: rt}
}

// browser is a cookie-keeping client that does not follow redirects.
func (tg *target) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Transport: tg.transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func do(t *testing.T, c *http.Client, method, u string, body io.Reader, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func form(t *testing.T, c *http.Client, u string, v url.Values) (*http.Response, string) {
	t.Helper()
	return do(t, c, "POST", u, strings.NewReader(v.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

var (
	csrfInputRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	csrfDataRe  = regexp.MustCompile(`data-csrf="([^"]+)"`)
)

func find(t *testing.T, re *regexp.Regexp, page, what string) string {
	t.Helper()
	m := re.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no %s in page:\n%.2000s", what, page)
	}
	return html.UnescapeString(m[1])
}

// enroll registers a passkey through a one-time enrollment link and
// returns the signed-in browser (its session is stepped up with the
// passkey).
func (tg *target) enroll(t *testing.T, link string) *http.Client {
	t.Helper()
	if !strings.HasPrefix(link, tg.base+"/") {
		t.Fatalf("enrollment link %q is not under %s", link, tg.base)
	}
	b := tg.browser()
	resp, _ := do(t, b, "GET", link, nil, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("enrollment link: %d (already used or expired?)", resp.StatusCode)
	}
	_, page := do(t, b, "GET", tg.base+"/passkeys/enroll", nil, nil)
	csrf := find(t, csrfDataRe, page, "enrollment csrf")
	dev, err := webauthntest.New(tg.base)
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf}
	resp, opts := do(t, b, "POST", tg.base+"/passkeys/enroll/begin", strings.NewReader("{}"), hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll begin: %d %s", resp.StatusCode, opts)
	}
	att, err := dev.Create([]byte(opts))
	if err != nil {
		t.Fatal(err)
	}
	resp, body := do(t, b, "POST", tg.base+"/passkeys/enroll/finish", bytes.NewReader(att), hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll finish: %d %s", resp.StatusCode, body)
	}
	return b
}

// oauth runs discovery, dynamic client registration, consent (with write
// requests) and the PKCE token exchange for the signed-in browser.
func (tg *target) oauth(t *testing.T, b *http.Client) string {
	t.Helper()
	api := &http.Client{Transport: tg.transport, Timeout: 30 * time.Second}
	resp, _ := do(t, api, "POST", tg.base+"/mcp", strings.NewReader("{}"), map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /mcp: %d", resp.StatusCode)
	}
	m := regexp.MustCompile(`resource_metadata="([^"]+)"`).FindStringSubmatch(resp.Header.Get("WWW-Authenticate"))
	if m == nil {
		t.Fatalf("no resource_metadata in %q", resp.Header.Get("WWW-Authenticate"))
	}
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	_, body := do(t, api, "GET", m[1], nil, nil)
	if err := json.Unmarshal([]byte(body), &prm); err != nil || prm.Resource != tg.base+"/mcp" {
		t.Fatalf("protected resource metadata: %v %s", err, body)
	}
	var asm struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		RegistrationEndpoint  string `json:"registration_endpoint"`
	}
	_, body = do(t, api, "GET", prm.AuthorizationServers[0]+"/.well-known/oauth-authorization-server", nil, nil)
	if err := json.Unmarshal([]byte(body), &asm); err != nil {
		t.Fatal(err)
	}

	redirect := "http://127.0.0.1:33418/callback"
	reg, _ := json.Marshal(map[string]any{"client_name": "dbgateway cloud check", "redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none"})
	resp, body = do(t, api, "POST", asm.RegistrationEndpoint, bytes.NewReader(reg), map[string]string{"Content-Type": "application/json"})
	var client struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal([]byte(body), &client); err != nil || client.ClientID == "" {
		t.Fatalf("registration: %d %s", resp.StatusCode, body)
	}

	verifier := "cloud-check-verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {client.ClientID}, "redirect_uri": {redirect},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {"st"}, "scope": {"db:read db:write"}, "resource": {prm.Resource},
	}
	resp, page := do(t, b, "GET", asm.AuthorizationEndpoint+"?"+q.Encode(), nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, tg.db) {
		t.Fatalf("consent page: %d", resp.StatusCode)
	}
	post := url.Values{}
	for k, v := range q {
		post[k] = v
	}
	post.Set("csrf", find(t, csrfInputRe, page, "consent csrf"))
	post.Set("action", "approve")
	post.Set("agent_name", "cloud-check-agent")
	post.Set("database", tg.db)
	post.Set("write", "1")
	resp, _ = form(t, b, asm.AuthorizationEndpoint, post)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("consent: %d %s", resp.StatusCode, loc)
	}
	resp, body = form(t, api, asm.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {client.ClientID}, "code": {loc.Query().Get("code")},
		"code_verifier": {verifier}, "redirect_uri": {redirect}, "resource": {prm.Resource},
	})
	var tok struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(tok.Scope, "db:write") {
		t.Fatalf("write scope not granted: %q", tok.Scope)
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

func firstCell(t *testing.T, out map[string]any) any {
	t.Helper()
	rows, _ := out["rows"].([]any)
	if out["status"] != "ok" || len(rows) == 0 {
		t.Fatalf("query result: %v", out)
	}
	return rows[0].([]any)[0]
}

func TestDeployedGateway(t *testing.T) {
	tg := newTarget(t)
	reqLink := env(t, "DBGW_CLOUD_ENROLL_REQUESTER", true)
	apprLink := env(t, "DBGW_CLOUD_ENROLL_APPROVER", true)

	// Reachability: the OAuth metadata is public. (/healthz cannot be used
	// from outside on Cloud Run, which reserves paths ending in "z".)
	resp, body := do(t, &http.Client{Transport: tg.transport, Timeout: 30 * time.Second}, "GET", tg.base+"/.well-known/oauth-protected-resource", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, tg.base+"/mcp") {
		t.Fatalf("protected resource metadata: %d %.300s", resp.StatusCode, body)
	}

	// 1. The requester signs in with a passkey and connects an MCP client.
	requester := tg.enroll(t, reqLink)
	token := tg.oauth(t, requester)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "cloud-check", Version: "1"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: tg.base + "/mcp", HTTPClient: &http.Client{Transport: &bearer{token: token, next: tg.transport}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	_, out := call(t, cs, "list_databases", map[string]any{})
	if !strings.Contains(fmt.Sprint(out["databases"]), tg.db) {
		t.Fatalf("list_databases: %v", out)
	}

	// 2. Reads go through IAM database authentication and come back masked.
	_, out = call(t, cs, "execute_sql", map[string]any{"database": tg.db, "sql": "SELECT email FROM users WHERE id = 3",
		"reason": "cloud check: confirm masking of user e-mail addresses"})
	if email := fmt.Sprint(firstCell(t, out)); !strings.HasPrefix(email, "u***@") {
		t.Fatalf("email not masked: %v", email)
	}
	_, out = call(t, cs, "execute_sql", map[string]any{"database": tg.db, "sql": "SELECT current_user",
		"reason": "cloud check: confirm the database user used for reads"})
	t.Logf("reads run as database user %v", firstCell(t, out))

	_, out = call(t, cs, "execute_sql", map[string]any{"database": tg.db, "sql": "SELECT plan FROM users WHERE id = 21",
		"reason": "cloud check: read the current plan of user 21"})
	orig := fmt.Sprint(firstCell(t, out))
	target := map[string]string{"pro": "free", "free": "pro"}[orig]

	// 3. A write is submitted for approval.
	res, out := call(t, cs, "execute_sql", map[string]any{"database": tg.db,
		"sql":    fmt.Sprintf("UPDATE users SET plan = '%s' WHERE id = 21", target),
		"reason": "cloud check: change the plan of user 21 to verify approvals"})
	if res.IsError || out["status"] != "pending" {
		t.Fatalf("write submission: %v", out)
	}
	id := out["request_id"].(string)
	t.Logf("write %s pending; approvers %v", id, out["approvers"])

	// 4. The approver signs in with a passkey (the session is stepped up)
	//    and approves in the web UI.
	approver := tg.enroll(t, apprLink)
	_, page := do(t, approver, "GET", tg.base+"/approvals/"+id, nil, nil)
	if !strings.Contains(page, "/approvals/"+id+"/approve") {
		t.Fatalf("approver cannot approve:\n%.2000s", page)
	}
	resp, _ = form(t, approver, tg.base+"/approvals/"+id+"/approve", url.Values{"csrf": {find(t, csrfInputRe, page, "approval csrf")}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "done=approved") {
		t.Fatalf("approve: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 5. dbgateway executes the write in the background.
	var status string
	for range 60 {
		_, out = call(t, cs, "get_request", map[string]any{"request_id": id})
		req, _ := out["request"].(map[string]any)
		status, _ = req["status"].(string)
		if status == "succeeded" || status == "failed" {
			t.Logf("request %s: %v", status, req["result"])
			break
		}
		time.Sleep(time.Second)
	}
	if status != "succeeded" {
		t.Fatalf("request = %v", out)
	}
	_, out = call(t, cs, "execute_sql", map[string]any{"database": tg.db, "sql": "SELECT plan FROM users WHERE id = 21",
		"reason": "cloud check: verify the approved plan change of user 21"})
	if got := fmt.Sprint(firstCell(t, out)); got != target {
		t.Fatalf("plan = %s, want %s", got, target)
	}

	// 6. Denials still apply in the cloud.
	res, out = call(t, cs, "execute_sql", map[string]any{"database": tg.db, "sql": "SELECT 1; DROP TABLE users",
		"reason": "cloud check: multiple statements must be rejected"})
	if !res.IsError || out["status"] != "denied" {
		t.Fatalf("multi-statement: %v", out)
	}
}
