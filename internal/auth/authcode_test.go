package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

func TestMetadata(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, body := do(t, http.DefaultClient, "GET", e.url(path), nil)
		if resp.StatusCode != 200 || !strings.Contains(body, `"resource":"`+e.auth.ResourceURL()+`"`) ||
			!strings.Contains(body, `"authorization_servers":["`+e.srv.URL+`"]`) {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	resp, body := do(t, http.DefaultClient, "GET", e.url("/.well-known/oauth-authorization-server"), nil)
	for _, want := range []string{`"issuer":"` + e.srv.URL + `"`, `"client_id_metadata_document_supported":true`,
		`"code_challenge_methods_supported":["S256"]`, GrantTypeDeviceCode, `"token_endpoint_auth_methods_supported":["none"]`} {
		if !strings.Contains(body, want) {
			t.Errorf("AS metadata missing %s: %s", want, body)
		}
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS header")
	}
}

func TestAuthCodeFlow(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	redirect := "http://127.0.0.1:9999/callback"
	clientID := e.registerClient(redirect)
	b := e.browser()

	// Without a session, /authorize sends the user to the login page.
	q := authorizeQuery(clientID, redirect, e.auth.ResourceURL())
	resp, _ := do(t, b, "GET", e.url("/authorize?"+q.Encode()), nil)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("expected login redirect, got %d %q", resp.StatusCode, loc)
	}
	e.login(b, "taro@example.com")

	// The consent page shows the client, the self-reported marker, and
	// disables databases the user cannot access.
	_, page := do(t, b, "GET", e.url("/authorize?"+q.Encode()), nil)
	for _, want := range []string{"Test Client", "Self-reported name", "Read prod-main", "analytics (unavailable)", `lang="en"`} {
		if !strings.Contains(page, want) {
			t.Errorf("consent page missing %q", want)
		}
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("missing CSP header")
	}

	loc := e.consent(b, q, approveForm("prod-main"))
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != redirect {
		t.Fatalf("redirected to %s", got)
	}
	if loc.Query().Get("state") != "xyz" || loc.Query().Get("iss") != e.srv.URL || loc.Query().Get("code") == "" {
		t.Fatalf("bad redirect params: %v", loc.Query())
	}
	status, tok := e.token(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"code_verifier": {testVerifier}, "redirect_uri": {redirect}, "resource": {e.auth.ResourceURL()},
	})
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	at, _ := tok["access_token"].(string)
	if !strings.HasPrefix(at, AccessTokenPrefix) || !strings.HasPrefix(tok["refresh_token"].(string), RefreshTokenPrefix) ||
		tok["token_type"] != "Bearer" || tok["scope"] != "db:read" || tok["expires_in"].(float64) != 3600 {
		t.Fatalf("bad token response: %v", tok)
	}

	ti, err := e.auth.VerifyToken(context.Background(), at, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := PrincipalFromTokenInfo(ti)
	if p == nil || p.Kind != identity.KindAgent || p.Human != "taro@example.com" || p.Agent != "claude-code" ||
		p.ClientID != clientID || p.ClientName != "Test Client" || !slices.Equal(p.Databases, []string{"prod-main"}) ||
		!slices.Equal(p.Groups, []string{"data-team"}) || !p.HasScope(identity.ScopeRead) || p.TokenID == "" {
		t.Fatalf("principal = %+v", p)
	}
	if ti.UserID != "taro@example.com" || ti.Expiration.IsZero() {
		t.Fatalf("token info = %+v", ti)
	}

	// The raw token is never stored.
	if _, err := e.store.GetTokenByHash(context.Background(), at); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("raw token found in the store")
	}
}

func TestConsentDenyAndNoDatabase(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	redirect := "http://127.0.0.1:9999/callback"
	clientID := e.registerClient(redirect)
	b := e.browser()
	e.login(b, "taro@example.com")
	q := authorizeQuery(clientID, redirect, "")
	for name, form := range map[string]url.Values{
		"cancel":      {"action": {"deny"}},
		"no database": {"action": {"approve"}, "agent_name": {"x"}},
	} {
		loc := e.consent(b, q, form)
		if loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
			t.Errorf("%s: redirect = %s", name, loc)
		}
	}
	// A database the user cannot access is refused (page, no code).
	_, page := do(t, b, "GET", e.url("/authorize?"+q.Encode()), nil)
	post := url.Values{"csrf": {csrfFrom(t, page)}, "action": {"approve"}, "agent_name": {"x"}, "database": {"analytics"}}
	for k, v := range q {
		post[k] = v
	}
	resp, _ := do(t, b, "POST", e.url("/authorize"), post)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("inaccessible database: status %d", resp.StatusCode)
	}
	// Missing CSRF token.
	post.Del("csrf")
	post.Set("database", "prod-main")
	resp, _ = do(t, b, "POST", e.url("/authorize"), post)
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("missing csrf: status %d", resp.StatusCode)
	}
}

func TestAuthorizeRedirectValidation(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	clientID := e.registerClient("http://127.0.0.1/callback", "https://app.example.com/cb")
	b := e.browser()
	e.login(b, "taro@example.com")
	for redirect, ok := range map[string]bool{
		"http://127.0.0.1:5555/callback":   true, // any loopback port
		"http://127.0.0.1/callback":        true,
		"https://app.example.com/cb":       true,
		"https://app.example.com/cb2":      false,
		"https://app.example.com:444/cb":   false,
		"http://127.0.0.1:5555/other":      false,
		"http://evil.example.com/callback": false,
		"":                                 false,
	} {
		resp, _ := do(t, b, "GET", e.url("/authorize?"+authorizeQuery(clientID, redirect, "").Encode()), nil)
		if ok && resp.StatusCode != http.StatusOK {
			t.Errorf("%q: status %d, want 200", redirect, resp.StatusCode)
		}
		if !ok && (resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "") {
			t.Errorf("%q: status %d location %q, want error page", redirect, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// Unknown client: error page, never a redirect.
	resp, _ := do(t, b, "GET", e.url("/authorize?"+authorizeQuery("nope", "http://127.0.0.1/callback", "").Encode()), nil)
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("unknown client: %d", resp.StatusCode)
	}
	// After the redirect URI is validated, protocol errors go to the client.
	q := authorizeQuery(clientID, "http://127.0.0.1/callback", "https://other.example.com/mcp")
	resp, _ = do(t, b, "GET", e.url("/authorize?"+q.Encode()), nil)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=invalid_target") {
		t.Fatalf("wrong resource: %d %q", resp.StatusCode, loc)
	}
	q = authorizeQuery(clientID, "http://127.0.0.1/callback", "")
	q.Set("code_challenge_method", "plain")
	resp, _ = do(t, b, "GET", e.url("/authorize?"+q.Encode()), nil)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("plain PKCE: %d %q", resp.StatusCode, loc)
	}
}

func TestTokenRejections(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	redirect := "http://127.0.0.1:9999/callback"
	clientID := e.registerClient(redirect)
	b := e.browser()
	e.login(b, "taro@example.com")
	newCode := func() string {
		return e.consent(b, authorizeQuery(clientID, redirect, e.auth.ResourceURL()), approveForm("prod-main")).Query().Get("code")
	}
	exchange := func(code string, mod func(url.Values)) (int, map[string]any) {
		f := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
			"code_verifier": {testVerifier}, "redirect_uri": {redirect}}
		if mod != nil {
			mod(f)
		}
		return e.token(f)
	}
	cases := map[string]func(url.Values){
		"pkce mismatch":  func(f url.Values) { f.Set("code_verifier", strings.Repeat("a", 43)) },
		"wrong redirect": func(f url.Values) { f.Set("redirect_uri", "http://127.0.0.1:9999/other") },
		"no redirect":    func(f url.Values) { f.Del("redirect_uri") },
		"wrong client":   func(f url.Values) { f.Set("client_id", "dcr_other") },
		"wrong resource": func(f url.Values) { f.Set("resource", "https://other.example.com/mcp") },
		"client secret":  func(f url.Values) { f.Set("client_secret", "x") },
	}
	for name, mod := range cases {
		status, out := exchange(newCode(), mod)
		if status == 200 || out["error"] == nil {
			t.Errorf("%s: accepted (%d %v)", name, status, out)
		}
	}
	// Expired code.
	code := newCode()
	e.clock.advance(2 * authCodeTTL)
	if status, out := exchange(code, nil); out["error"] != "invalid_grant" {
		t.Errorf("expired code: %d %v", status, out)
	}

	// Reused code: rejected, and the tokens it issued are revoked.
	code = newCode()
	status, out := exchange(code, nil)
	if status != 200 {
		t.Fatalf("first exchange: %d %v", status, out)
	}
	status, out2 := exchange(code, nil)
	if status != 400 || out2["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", status, out2)
	}
	if _, err := e.auth.VerifyToken(context.Background(), out["access_token"].(string), nil); !errors.Is(err, mcpauth.ErrInvalidToken) {
		t.Fatalf("token from reused code still valid: %v", err)
	}

	if status, out := e.token(url.Values{"grant_type": {"password"}, "client_id": {clientID}}); out["error"] != "unsupported_grant_type" {
		t.Errorf("password grant: %d %v", status, out)
	}
}

func TestRefreshRotation(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	clientID, tok := e.authCodeTokens()
	rt1 := tok["refresh_token"].(string)
	refresh := func(rt string) (int, map[string]any) {
		return e.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {rt}})
	}
	status, tok2 := refresh(rt1)
	if status != 200 || tok2["refresh_token"] == rt1 || tok2["access_token"] == tok["access_token"] {
		t.Fatalf("refresh: %d %v", status, tok2)
	}
	if _, err := e.auth.VerifyToken(context.Background(), tok2["access_token"].(string), nil); err != nil {
		t.Fatal(err)
	}
	// Wrong client.
	if status, _ := e.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {"other"}, "refresh_token": {tok2["refresh_token"].(string)}}); status == 200 {
		t.Fatal("refresh accepted for another client")
	}
	// Reusing the rotated token revokes the whole family.
	if status, out := refresh(rt1); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", status, out)
	}
	if status, _ := refresh(tok2["refresh_token"].(string)); status == 200 {
		t.Fatal("new refresh token still valid after reuse detection")
	}
	for _, at := range []any{tok["access_token"], tok2["access_token"]} {
		if _, err := e.auth.VerifyToken(context.Background(), at.(string), nil); err == nil {
			t.Fatal("access token still valid after reuse detection")
		}
	}
}

func TestRefreshDisabled(t *testing.T) {
	e := newEnv(t, testConfig, func(c *configT) { c.Auth.AgentTokens.Refresh = false })
	_, tok := e.authCodeTokens()
	if _, ok := tok["refresh_token"]; ok {
		t.Fatal("refresh token issued although disabled")
	}
}

func TestVerifyRejections(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	ctx := context.Background()
	now := e.clock.now()
	insert := func(mod func(*store.Token)) string {
		raw, hash := newSecret(AccessTokenPrefix)
		tk := &store.Token{ID: newID("tok_"), Hash: hash, Type: store.TokenAccess, Kind: identity.KindAgent,
			Human: "taro@example.com", Agent: "a", ClientID: "c", Scopes: []string{"db:read"}, Databases: []string{"prod-main"},
			Audience: e.auth.ResourceURL(), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		mod(tk)
		if err := e.store.CreateToken(ctx, tk); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	good := insert(func(*store.Token) {})
	if _, err := e.auth.VerifyToken(ctx, good, nil); err != nil {
		t.Fatalf("good token: %v", err)
	}
	cases := map[string]string{
		"audience mismatch": insert(func(t *store.Token) { t.Audience = "https://other.example.com/mcp" }),
		"expired":           insert(func(t *store.Token) { t.ExpiresAt = now.Add(-time.Second) }),
		"revoked":           insert(func(t *store.Token) { r := now; t.RevokedAt = &r }),
		"refresh as access": insert(func(t *store.Token) { t.Type = store.TokenRefresh }),
		"no databases":      insert(func(t *store.Token) { t.Databases = nil }),
		"human at mcp":      insert(func(t *store.Token) { t.Kind = identity.KindHuman; t.Audience = e.srv.URL }),
		"unknown":           AccessTokenPrefix + "nope",
		"malformed":         "Bearer xyz",
	}
	for name, raw := range cases {
		if _, err := e.auth.VerifyToken(ctx, raw, nil); !errors.Is(err, mcpauth.ErrInvalidToken) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A human CLI token authenticates for the API but not for MCP.
	human := insert(func(t *store.Token) {
		t.Kind = identity.KindHuman
		t.Audience = e.srv.URL
		t.Databases = nil
		t.Agent = ""
	})
	p, err := e.auth.Authenticate(ctx, human)
	if err != nil || p.Kind != identity.KindHuman || !slices.Equal(p.Groups, []string{"data-team"}) {
		t.Fatalf("Authenticate human = %+v, %v", p, err)
	}
	if _, err := e.auth.Authenticate(ctx, cases["audience mismatch"]); err == nil {
		t.Fatal("Authenticate accepted agent token with foreign audience")
	}
}

func TestRevokeEndpointAndAccountPage(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	ctx := context.Background()
	clientID, tok := e.authCodeTokens()
	at := tok["access_token"].(string)

	// Foreign client: 200 but no effect.
	resp, _ := do(t, http.DefaultClient, "POST", e.url("/revoke"), url.Values{"token": {at}, "client_id": {"other"}})
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if _, err := e.auth.VerifyToken(ctx, at, nil); err != nil {
		t.Fatal("revoked by a foreign client")
	}
	// Revoking the refresh token revokes the family, access token included.
	resp, _ = do(t, http.DefaultClient, "POST", e.url("/revoke"), url.Values{"token": {tok["refresh_token"].(string)}, "client_id": {clientID}})
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if _, err := e.auth.VerifyToken(ctx, at, nil); !errors.Is(err, mcpauth.ErrInvalidToken) {
		t.Fatalf("revoked token accepted: %v", err)
	}

	// Account page: list and revoke a grant.
	_, tok = e.authCodeTokens()
	b := e.browser()
	e.login(b, "taro@example.com")
	resp, page := do(t, b, "GET", e.url("/account"), nil)
	if resp.StatusCode != 200 || !strings.Contains(page, "claude-code") || !strings.Contains(page, "prod-main (read)") ||
		!strings.Contains(page, "querier") || strings.Count(page, `action="/account/revoke"`) != 1 {
		t.Fatalf("account page: %d\n%s", resp.StatusCode, page)
	}
	id := regexpFind(t, page, `name="id" value="([^"]+)"`)
	resp, _ = do(t, b, "POST", e.url("/account/revoke"), url.Values{"csrf": {csrfFrom(t, page)}, "id": {id}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("account revoke: %d", resp.StatusCode)
	}
	if _, err := e.auth.VerifyToken(ctx, tok["access_token"].(string), nil); err == nil {
		t.Fatal("token valid after account revoke")
	}
	// Someone else cannot revoke it.
	other := e.browser()
	e.login(other, "hanako@example.com")
	_, page = do(t, other, "GET", e.url("/account"), nil)
	resp, _ = do(t, other, "POST", e.url("/account/revoke"), url.Values{"csrf": {csrfFrom(t, page)}, "id": {id}})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign revoke: %d", resp.StatusCode)
	}
}

func TestLanguageSelection(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	b := e.browser()
	req, _ := http.NewRequest("GET", e.url("/login"), nil)
	req.Header.Set("Accept-Language", "ja-JP,ja;q=0.9")
	resp, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(resp)
	if !strings.Contains(body, `lang="ja"`) || !strings.Contains(body, "開発用ログイン") {
		t.Fatalf("expected Japanese page:\n%s", body)
	}
	// ?lang=en sets the cookie and redirects without the parameter.
	resp, _ = do(t, b, "GET", e.url("/login?next=%2Faccount&lang=en"), nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?next=%2Faccount" {
		t.Fatalf("switch: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	req, _ = http.NewRequest("GET", e.url("/login"), nil)
	req.Header.Set("Accept-Language", "ja")
	resp, _ = b.Do(req)
	if body := readAll(resp); !strings.Contains(body, "Development login") {
		t.Fatalf("cookie did not win over Accept-Language:\n%s", body)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/authorize?x=1":        "/authorize?x=1",
		"//evil.example.com":    "/account",
		"https://evil.example":  "/account",
		"/\\evil.example.com":   "/account",
		"":                      "/account",
		"javascript:alert(1)":   "/account",
		"/device?user_code=ABC": "/device?user_code=ABC",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunCleanup(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	_, _ = e.authCodeTokens()
	e.clock.advance(30 * 24 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.auth.RunCleanup(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		list, err := e.store.ListTokens(context.Background(), "taro@example.com")
		if err == nil && len(list) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tokens after cleanup = %d, %v", len(list), err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
