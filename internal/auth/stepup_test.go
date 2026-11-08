package auth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
)

func TestIdPStepUp(t *testing.T) {
	idp := newFakeIdP(t)
	t.Setenv("DBGW_TEST_OIDC_CLIENT_ID", "dbgw-client")
	e := newEnv(t, oidcConfig, func(c *config.Config) { c.Auth.OIDC.Issuer = idp.srv.URL })

	// Follow an IdP round trip starting at path; returns the final
	// response from dbgateway's callback.
	roundTrip := func(b *http.Client, path string) *http.Response {
		resp, _ := do(t, b, "GET", e.url(path), nil) // -> IdP
		resp, _ = do(t, b, "GET", resp.Header.Get("Location"), nil)
		if !strings.HasPrefix(resp.Header.Get("Location"), e.url("/oidc/callback")) {
			t.Fatalf("IdP did not redirect back: %q", resp.Header.Get("Location"))
		}
		resp, _ = do(t, b, "GET", resp.Header.Get("Location"), nil)
		return resp
	}

	idp.claims = map[string]any{"email": "taro@example.com", "email_verified": true}
	b := e.browser()
	if resp := roundTrip(b, "/login/sso?next=%2Faccount"); resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	if idp.lastAuthorize.Get("max_age") != "" {
		t.Fatal("login asked for max_age")
	}
	if _, ok := e.auth.StepUp(reqWithCookies(t, e, b)); ok {
		t.Fatal("a plain IdP login counts as step-up")
	}

	_, page := do(t, b, "GET", e.url("/stepup?next=%2Fapprovals%2Freq_1"), nil)
	if !strings.Contains(page, `href="/stepup/idp?next=%2Fapprovals%2Freq_1"`) {
		t.Fatalf("step-up page:\n%s", page)
	}

	// auth_time must be present and recent.
	idp.claims = map[string]any{"email": "taro@example.com", "email_verified": true}
	if resp := roundTrip(b, "/stepup/idp?next=%2Fapprovals%2Freq_1"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("step-up without auth_time: %d", resp.StatusCode)
	}
	if q := idp.lastAuthorize; q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Fatalf("step-up authorization request: %v", q)
	}
	idp.claims["auth_time"] = e.clock.now().Add(-time.Hour).Unix()
	if resp := roundTrip(b, "/stepup/idp?next=%2Fapprovals%2Freq_1"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("step-up with an old auth_time: %d", resp.StatusCode)
	}
	// Another IdP account cannot step up this session.
	idp.claims = map[string]any{"email": "jiro@example.com", "email_verified": true, "auth_time": e.clock.now().Unix()}
	if resp := roundTrip(b, "/stepup/idp?next=%2Fapprovals%2Freq_1"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("step-up with another account: %d", resp.StatusCode)
	}
	idp.claims = map[string]any{"email": "taro@example.com", "email_verified": true, "auth_time": e.clock.now().Unix()}
	resp := roundTrip(b, "/stepup/idp?next=%2Fapprovals%2Freq_1")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/approvals/req_1" {
		t.Fatalf("step-up: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	su, ok := e.auth.StepUp(reqWithCookies(t, e, b))
	if !ok || su.Method != StepUpIdP {
		t.Fatalf("step-up after IdP: %+v %v", su, ok)
	}
	// It expires after approvals.step_up_max_age.
	e.clock.advance(e.cfg.Approvals.StepUpMaxAge.D() + time.Minute)
	if _, ok := e.auth.StepUp(reqWithCookies(t, e, b)); ok {
		t.Fatal("stale step-up accepted")
	}
	// The dev confirmation is not available without dev_login.
	if resp, _ := do(t, b, "POST", e.url("/stepup/dev"), url.Values{}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("dev step-up without dev_login: %d", resp.StatusCode)
	}
}

func TestDevStepUpNeedsCSRF(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	b := e.browser()
	e.login(b, "taro@example.com")
	if resp, _ := do(t, b, "POST", e.url("/stepup/dev"), url.Values{"csrf": {"x"}, "next": {"/account"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("dev step-up without csrf: %d", resp.StatusCode)
	}
	_, page := do(t, b, "GET", e.url("/stepup?next=%2Faccount"), nil)
	resp, _ := do(t, b, "POST", e.url("/stepup/dev"), url.Values{"csrf": {csrfFrom(t, page)}, "next": {"//evil.example"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
		t.Fatalf("dev step-up: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, ok := e.auth.StepUp(reqWithCookies(t, e, b)); !ok {
		t.Fatal("no step-up after the dev confirmation")
	}
}

// reqWithCookies builds a request carrying the browser's cookies.
func reqWithCookies(t *testing.T, e *env, b *http.Client) *http.Request {
	t.Helper()
	u, _ := url.Parse(e.srv.URL)
	r, _ := http.NewRequest("GET", e.url("/"), nil)
	for _, c := range b.Jar.Cookies(u) {
		r.AddCookie(c)
	}
	return r
}
