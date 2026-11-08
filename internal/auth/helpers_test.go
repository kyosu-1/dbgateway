package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
)

const testConfig = `
server:
  listen: 127.0.0.1:8443
  public_url: %s
auth:
  dev_login: true
  allow_insecure_client_metadata: true
  agent_tokens: { max_ttl: 1h, refresh: true }
databases:
  - name: prod-main
    labels: { env: prod }
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

// clock is a controllable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t     *testing.T
	srv   *httptest.Server
	auth  *Server
	store store.Store
	cfg   *config.Config
	clock *clock
}

// newEnv starts an auth server. yamlTmpl must contain one %s for the
// public URL; mutate may adjust the parsed config.
func newEnv(t *testing.T, yamlTmpl string, mutate func(*config.Config)) *env {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	public := "http://" + srv.Listener.Addr().String()
	cfg, err := config.Parse([]byte(fmt.Sprintf(yamlTmpl, public)))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(cfg)
	}
	st, err := store.OpenSQLite(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), Options{
		Config: cfg, Store: st, RBAC: policy.NewRBAC(cfg),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Now()}
	a.now = c.now
	mux := http.NewServeMux()
	a.Register(mux)
	srv.Config.Handler = mux
	srv.Start()
	t.Cleanup(func() { srv.Close(); st.Close() })
	return &env{t: t, srv: srv, auth: a, store: st, cfg: cfg, clock: c}
}

// browser returns an HTTP client with a cookie jar that does not follow
// redirects.
func (e *env) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (e *env) url(path string) string { return e.srv.URL + path }

func do(t *testing.T, c *http.Client, method, u string, form url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept-Language", "en")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfFrom(t *testing.T, page string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no csrf token in page:\n%s", page)
	}
	return html.UnescapeString(m[1])
}

// login signs in through the dev login form.
func (e *env) login(c *http.Client, email string) {
	t := e.t
	t.Helper()
	_, page := do(t, c, "GET", e.url("/login"), nil)
	resp, _ := do(t, c, "POST", e.url("/login"), url.Values{"csrf": {csrfFrom(t, page)}, "email": {email}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: status %d", resp.StatusCode)
	}
}

// registerClient registers a DCR client and returns its client_id.
func (e *env) registerClient(redirectURIs ...string) string {
	t := e.t
	t.Helper()
	b, _ := json.Marshal(map[string]any{"client_name": "Test Client", "redirect_uris": redirectURIs, "token_endpoint_auth_method": "none"})
	resp, err := http.Post(e.url("/register"), "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, out)
	}
	return out["client_id"].(string)
}

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-padding-for-length"

func authorizeQuery(clientID, redirectURI, resource string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {s256(testVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
		"scope":                 {"db:read"},
		"resource":              {resource},
	}
}

// consent runs GET /authorize + POST approve and returns the redirect URL.
func (e *env) consent(c *http.Client, q url.Values, form url.Values) *url.URL {
	t := e.t
	t.Helper()
	resp, page := do(t, c, "GET", e.url("/authorize?"+q.Encode()), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize: status %d\n%s", resp.StatusCode, page)
	}
	post := url.Values{}
	for k, v := range q {
		post[k] = v
	}
	post.Set("csrf", csrfFrom(t, page))
	for k, v := range form {
		post[k] = v
	}
	resp, page = do(t, c, "POST", e.url("/authorize"), post)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("consent: status %d\n%s", resp.StatusCode, page)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func approveForm(dbs ...string) url.Values {
	return url.Values{"action": {"approve"}, "agent_name": {"claude-code"}, "database": dbs}
}

// token posts to the token endpoint.
func (e *env) token(form url.Values) (int, map[string]any) {
	t := e.t
	t.Helper()
	resp, body := do(t, http.DefaultClient, "POST", e.url("/token"), form)
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("token response %q: %v", body, err)
	}
	return resp.StatusCode, out
}

// authCodeTokens runs the full flow for a fresh DCR client and returns the
// token response.
func (e *env) authCodeTokens() (clientID string, tokens map[string]any) {
	t := e.t
	t.Helper()
	redirect := "http://127.0.0.1:9999/callback"
	clientID = e.registerClient(redirect)
	b := e.browser()
	e.login(b, "taro@example.com")
	loc := e.consent(b, authorizeQuery(clientID, redirect, e.auth.ResourceURL()), approveForm("prod-main"))
	status, out := e.token(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"code_verifier": {testVerifier}, "redirect_uri": {redirect}, "resource": {e.auth.ResourceURL()},
	})
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, out)
	}
	return clientID, out
}

type configT = config.Config

func regexpFind(t *testing.T, s, expr string) string {
	t.Helper()
	m := regexp.MustCompile(expr).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("%s not found", expr)
	}
	return html.UnescapeString(m[1])
}

func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func mustJSON(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
}
