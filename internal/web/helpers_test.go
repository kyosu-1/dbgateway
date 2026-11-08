package web

import (
	"context"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

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

// testYAML has one %s for the public URL and one %s for the audit dir.
const testYAML = `
server: { listen: "127.0.0.1:8443", public_url: "%s" }
auth: { dev_login: true }
audit: { dir: "%s", output: file }
approvals: { enabled: true, step_up_max_age: 5m }
databases:
  - name: prod
    labels: { env: prod }
    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }
  - name: staging
    primary: { host: localhost, read_user: r, sslmode: disable }
groups:
  - { name: dev, members: [taro@example.com, jiro@example.com] }
  - { name: sre, members: [hanako@example.com, ken@example.com] }
  - { name: security, members: [sec@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier, writer] }
  - { group: sre, databases: "*", roles: [querier, writer, approver] }
  - { user: jiro@example.com, databases: [staging], roles: [approver], expires_at: 2099-01-01T00:00:00Z }
  - { user: root@example.com, databases: [staging], roles: [admin] }
auditors:
  - { group: security }
data_classes:
  - { columns: [public.users.email], class: masked }
  - { column_pattern: "public\\.users\\.(id|plan|name)", class: public }
risk:
  medium: ['stmt.is_write']
approval_rules:
  - name: default
    when: "true"
    steps: [{ role: approver }]
    expire_after: 30m
break_glass:
  max_duration: 1h
  databases: [prod]
`

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
	srv   *httptest.Server
	cfg   *config.Config
	st    store.Store
	gw    *gateway.Gateway
	svc   *approval.Service
	fa    *gatewaytest.Adapter
	clock *clock
}

func newEnv(t *testing.T, mutate func(string) string) *env {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	public := "http://" + srv.Listener.Addr().String()
	yaml := fmt.Sprintf(testYAML, public, t.TempDir())
	if mutate != nil {
		yaml = mutate(yaml)
	}
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	sink, err := audit.OpenFileSink(cfg.Audit.Dir, 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.New(sink)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	e := &env{t: t, srv: srv, cfg: cfg, st: st, fa: gatewaytest.New(), clock: &clock{t: time.Now()}}
	e.fa.Set(func(a *gatewaytest.Adapter) {
		a.EstimateRows = 1
		a.Result = analysis.Result{Columns: []analysis.ResultColumn{{Name: "id", Type: "int8"}, {Name: "email", Type: "text"}},
			Rows: [][]any{{int64(1), "user1@example.com"}}}
	})
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": e.fa}, Audit: al, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	svc := approval.New(approval.Options{Config: cfg, Store: st, Executor: gw, Audit: al, Logger: logger, Now: e.clock.Now})
	gw.SetApprovals(svc)
	rbac := policy.NewRBAC(cfg)
	a, err := auth.New(context.Background(), auth.Options{Config: cfg, Store: st, RBAC: rbac, Logger: logger, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	app, err := New(Options{Config: cfg, Store: st, Auth: a, Gateway: gw, Approvals: svc, RBAC: rbac, Logger: logger, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.Register(mux)
	app.Register(mux)
	srv.Config.Handler = mux
	srv.Start()
	t.Cleanup(func() { srv.Close(); svc.Wait(); gw.Close(); _ = al.Close(); st.Close() })
	e.cfg, e.gw, e.svc = cfg, gw, svc
	return e
}

func (e *env) url(path string) string { return e.srv.URL + path }

// browser is a cookie-carrying client that does not follow redirects.
func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

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

// login signs in with the dev login form and returns the browser and its
// CSRF token.
func (e *env) login(email string) (*http.Client, string) {
	t := e.t
	t.Helper()
	c := browser()
	_, page := do(t, c, "GET", e.url("/login"), nil)
	resp, _ := do(t, c, "POST", e.url("/login"), url.Values{"csrf": {csrfFrom(t, page)}, "email": {email}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login %s: status %d", email, resp.StatusCode)
	}
	_, page = do(t, c, "GET", e.url("/account"), nil)
	return c, csrfFrom(t, page)
}

// stepUp re-verifies with the dev confirmation.
func (e *env) stepUp(c *http.Client, csrf string) {
	e.t.Helper()
	resp, _ := do(e.t, c, "POST", e.url("/stepup/dev"), url.Values{"csrf": {csrf}, "next": {"/account"}})
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("dev step-up: %d", resp.StatusCode)
	}
}

var (
	taroHuman = identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Groups: []string{"dev"}}
	taroAgent = &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude-code", ClientID: "c1",
		Groups: []string{"dev"}, Scopes: []string{identity.ScopeRead, identity.ScopeWrite}}
)

// submit makes taro's agent request a write and returns the request ID.
func (e *env) submit(sql, reason string) string {
	e.t.Helper()
	r := e.gw.ExecuteSQL(context.Background(), taroAgent, gateway.ExecuteRequest{Database: "prod", SQL: sql, Reason: reason})
	if r.Status != gateway.StatusPending {
		e.t.Fatalf("submit: %+v", r)
	}
	return r.RequestID
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

func mustContain(t *testing.T, page string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(page, w) {
			t.Fatalf("page does not contain %q:\n%s", w, page)
		}
	}
}

func mustNotContain(t *testing.T, page string, bad ...string) {
	t.Helper()
	for _, b := range bad {
		if strings.Contains(page, b) {
			t.Fatalf("page contains %q:\n%s", b, page)
		}
	}
}
