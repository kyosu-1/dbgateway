package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

func TestDeviceFlow(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	ctx := context.Background()

	if resp, _ := do(t, http.DefaultClient, "POST", e.url("/device_authorization"), url.Values{"client_id": {"other"}}); resp.StatusCode != 401 {
		t.Fatalf("foreign client: %d", resp.StatusCode)
	}
	resp, body := do(t, http.DefaultClient, "POST", e.url("/device_authorization"), url.Values{"client_id": {CLIClientID}, "scope": {"db:read"}})
	if resp.StatusCode != 200 {
		t.Fatalf("device_authorization: %d %s", resp.StatusCode, body)
	}
	var da deviceAuthResponse
	mustJSON(t, body, &da)
	if len(da.UserCode) != 9 || da.UserCode[4] != '-' || da.VerificationURI != e.url("/device") ||
		da.ExpiresIn != 600 || da.Interval != 5 || !strings.Contains(da.VerificationURIComplete, "user_code=") {
		t.Fatalf("bad response: %+v", da)
	}
	poll := func() (int, map[string]any) {
		return e.token(url.Values{"grant_type": {GrantTypeDeviceCode}, "client_id": {CLIClientID}, "device_code": {da.DeviceCode}})
	}
	if _, out := poll(); out["error"] != "authorization_pending" {
		t.Fatalf("first poll: %v", out)
	}
	if _, out := poll(); out["error"] != "slow_down" {
		t.Fatalf("fast poll: %v", out)
	}
	e.clock.advance(11 * time.Second) // interval grew to 10s
	if _, out := poll(); out["error"] != "authorization_pending" {
		t.Fatalf("poll after wait: %v", out)
	}

	// The user approves in the browser (login required).
	b := e.browser()
	resp, _ = do(t, b, "GET", da.VerificationURIComplete, nil)
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
		t.Fatalf("device page without session: %d", resp.StatusCode)
	}
	e.login(b, "taro@example.com")
	_, page := do(t, b, "GET", da.VerificationURIComplete, nil)
	if !strings.Contains(page, `value="`+da.UserCode+`"`) {
		t.Fatalf("code not prefilled:\n%s", page)
	}
	csrf := csrfFrom(t, page)
	resp, _ = do(t, b, "POST", e.url("/device"), url.Values{"csrf": {csrf}, "user_code": {"BBBB-BBBB"}, "action": {"approve"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown code: %d", resp.StatusCode)
	}
	// Lower case and no dash are accepted.
	code := strings.ToLower(strings.ReplaceAll(da.UserCode, "-", ""))
	resp, page = do(t, b, "POST", e.url("/device"), url.Values{"csrf": {csrf}, "user_code": {code}, "action": {"approve"}})
	if resp.StatusCode != 200 || !strings.Contains(page, "Return to your terminal") || strings.Contains(page, `name="user_code"`) {
		t.Fatalf("approve: %d\n%s", resp.StatusCode, page)
	}

	e.clock.advance(11 * time.Second)
	status, tok := poll()
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	if _, ok := tok["refresh_token"]; ok {
		t.Fatal("CLI token must not have a refresh token")
	}
	if tok["expires_in"].(float64) != e.cfg.Auth.CLITokenTTL.D().Seconds() {
		t.Fatalf("expires_in = %v", tok["expires_in"])
	}
	p, err := e.auth.Authenticate(ctx, tok["access_token"].(string))
	if err != nil || p.Kind != identity.KindHuman || p.Human != "taro@example.com" || p.ClientID != CLIClientID {
		t.Fatalf("principal = %+v, %v", p, err)
	}
	if _, err := e.auth.VerifyToken(ctx, tok["access_token"].(string), nil); err == nil {
		t.Fatal("human CLI token accepted at the MCP endpoint")
	}
	e.clock.advance(11 * time.Second)
	if _, out := poll(); out["error"] != "invalid_grant" {
		t.Fatalf("poll after use: %v", out)
	}
}

func TestDeviceDeniedAndExpired(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	start := func() deviceAuthResponse {
		_, body := do(t, http.DefaultClient, "POST", e.url("/device_authorization"), url.Values{"client_id": {CLIClientID}})
		var da deviceAuthResponse
		mustJSON(t, body, &da)
		return da
	}
	poll := func(dc string) map[string]any {
		_, out := e.token(url.Values{"grant_type": {GrantTypeDeviceCode}, "client_id": {CLIClientID}, "device_code": {dc}})
		return out
	}
	denied := start()
	b := e.browser()
	e.login(b, "taro@example.com")
	_, page := do(t, b, "GET", e.url("/device"), nil)
	do(t, b, "POST", e.url("/device"), url.Values{"csrf": {csrfFrom(t, page)}, "user_code": {denied.UserCode}, "action": {"deny"}})
	if out := poll(denied.DeviceCode); out["error"] != "access_denied" {
		t.Fatalf("denied: %v", out)
	}
	expired := start()
	e.clock.advance(deviceCodeTTL + time.Second)
	if out := poll(expired.DeviceCode); out["error"] != "expired_token" {
		t.Fatalf("expired: %v", out)
	}
}

func TestUserCode(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		c := newUserCode()
		if normalizeUserCode(c) != c || seen[c] {
			t.Fatalf("bad or duplicate code %q", c)
		}
		seen[c] = true
	}
	for _, bad := range []string{"", "ABCD-EFGH", "BCDF-GHJ", "BCDF-GHJKL", "BCDF_GHJK"} {
		if normalizeUserCode(bad) != "" {
			t.Errorf("normalizeUserCode(%q) accepted", bad)
		}
	}
}
