package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
)

// fakeIdP is a minimal OIDC provider: discovery, JWKS, authorize (auto
// approves) and a token endpoint returning an RS256 ID token.
type fakeIdP struct {
	srv           *httptest.Server
	key           *rsa.PrivateKey
	claims        map[string]any
	nonces        map[string]string // code -> nonce
	challenges    map[string]string // code -> PKCE challenge
	sawPKCEVerify bool
	lastAuthorize url.Values // query of the last authorization request
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, nonces: map[string]string{}, challenges: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" {
			http.Error(w, "pkce required", 400)
			return
		}
		f.lastAuthorize = q
		code := randomToken(8)
		f.nonces[code] = q.Get("nonce")
		f.challenges[code] = q.Get("code_challenge")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		code := r.PostForm.Get("code")
		if s256(r.PostForm.Get("code_verifier")) != f.challenges[code] {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		f.sawPKCEVerify = true
		claims := map[string]any{"iss": f.srv.URL, "sub": "u1", "aud": "dbgw-client", "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "nonce": f.nonces[code]}
		for k, v := range f.claims {
			claims[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": f.sign(t, claims)})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (f *fakeIdP) sign(t *testing.T, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

const oidcConfig = `
server:
  listen: 127.0.0.1:8443
  public_url: %s
auth:
  oidc:
    issuer: http://placeholder
    client_id_env: DBGW_TEST_OIDC_CLIENT_ID
groups:
  - name: data-team
    oidc_group: idp-data
`

func TestOIDCLogin(t *testing.T) {
	idp := newFakeIdP(t)
	t.Setenv("DBGW_TEST_OIDC_CLIENT_ID", "dbgw-client")
	e := newEnv(t, oidcConfig, func(c *config.Config) { c.Auth.OIDC.Issuer = idp.srv.URL })

	login := func(claims map[string]any) (*http.Client, *http.Response) {
		idp.claims = claims
		b := e.browser()
		resp, page := do(t, b, "GET", e.url("/login?next=%2Fdevice"), nil)
		if resp.StatusCode != 200 || !strings.Contains(page, "Sign in with SSO") {
			t.Fatalf("login page: %d", resp.StatusCode)
		}
		sso := regexpFind(t, page, `href="(/login/sso[^"]*)"`)
		resp, _ = do(t, b, "GET", e.url(sso), nil) // -> IdP
		resp, _ = do(t, b, "GET", resp.Header.Get("Location"), nil)
		if !strings.HasPrefix(resp.Header.Get("Location"), e.url("/oidc/callback")) {
			t.Fatalf("IdP did not redirect back: %q", resp.Header.Get("Location"))
		}
		resp, _ = do(t, b, "GET", resp.Header.Get("Location"), nil)
		return b, resp
	}

	_, resp := login(map[string]any{"email": "Taro@Example.com", "email_verified": true, "groups": []string{"idp-data", "other"}})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/device" {
		t.Fatalf("callback: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !idp.sawPKCEVerify {
		t.Fatal("PKCE verifier not sent to the IdP")
	}
	u, err := e.store.GetUser(t.Context(), "taro@example.com")
	if err != nil || !slices.Equal(u.IDPGroups, []string{"idp-data", "other"}) {
		t.Fatalf("user = %+v, %v", u, err)
	}
	p, err := e.auth.humanPrincipal(t.Context(), "taro@example.com")
	if err != nil || !slices.Equal(p.Groups, []string{"data-team"}) {
		t.Fatalf("groups = %v, %v", p.Groups, err)
	}

	for name, claims := range map[string]map[string]any{
		"unverified email": {"email": "x@example.com", "email_verified": false},
		"no email":         {"email_verified": true},
	} {
		if _, resp := login(claims); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
	}

	// A forged state is refused.
	b := e.browser()
	do(t, b, "GET", e.url("/login/sso"), nil)
	resp, _ = do(t, b, "GET", e.url("/oidc/callback?code=x&state=forged"), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged state: %d", resp.StatusCode)
	}
}

func TestLoginPageSSOAndDev(t *testing.T) {
	idp := newFakeIdP(t)
	t.Setenv("DBGW_TEST_OIDC_CLIENT_ID", "dbgw-client")
	e := newEnv(t, oidcConfig, func(c *config.Config) { c.Auth.OIDC.Issuer = idp.srv.URL; c.Auth.DevLogin = true })
	_, page := do(t, e.browser(), "GET", e.url("/login"), nil)
	for _, want := range []string{"Sign in with SSO", strings.TrimPrefix(idp.srv.URL, "http://"), "Development login is enabled", `action="/login"`} {
		if !strings.Contains(page, want) {
			t.Errorf("login page missing %q", want)
		}
	}
	if strings.Contains(page, `class="devbanner"`) {
		t.Error("global dev banner duplicated on the login page")
	}
}
