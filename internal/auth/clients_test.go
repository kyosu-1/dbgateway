package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestCIMD(t *testing.T) {
	var doc map[string]any
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/client.json", http.StatusFound)
		default:
			json.NewEncoder(w).Encode(doc)
		}
	}))
	defer md.Close()
	clientID := md.URL + "/client.json"
	redirect := "http://127.0.0.1:7777/cb"

	e := newEnv(t, testConfig, nil)
	b := e.browser()
	e.login(b, "taro@example.com")

	doc = map[string]any{"client_id": clientID, "client_name": "Claude Code", "redirect_uris": []string{"http://127.0.0.1/cb"}, "token_endpoint_auth_method": "none"}
	resp, page := do(t, b, "GET", e.url("/authorize?"+authorizeQuery(clientID, redirect, "").Encode()), nil)
	if resp.StatusCode != 200 || !strings.Contains(page, "Claude Code") || !strings.Contains(page, "Client metadata verified") {
		t.Fatalf("CIMD consent: %d\n%s", resp.StatusCode, page)
	}
	loc := e.consent(b, authorizeQuery(clientID, redirect, ""), approveForm("prod-main"))
	status, out := e.token(url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"code_verifier": {testVerifier}, "redirect_uri": {redirect}})
	if status != 200 {
		t.Fatalf("token: %d %v", status, out)
	}
	ti, err := e.auth.VerifyToken(context.Background(), out["access_token"].(string), nil)
	if err != nil || PrincipalFromTokenInfo(ti).ClientID != clientID {
		t.Fatalf("verify: %v", err)
	}

	// Redirect URI not in the document.
	resp, _ = do(t, b, "GET", e.url("/authorize?"+authorizeQuery(clientID, "https://evil.example.com/cb", "").Encode()), nil)
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("unregistered redirect: %d", resp.StatusCode)
	}

	// Invalid documents (fresh fetcher each time to bypass the cache).
	for name, d := range map[string]map[string]any{
		"client_id mismatch":  {"client_id": md.URL + "/other.json", "redirect_uris": []string{redirect}},
		"no redirect uris":    {"client_id": clientID},
		"confidential client": {"client_id": clientID, "redirect_uris": []string{redirect}, "token_endpoint_auth_method": "client_secret_basic"},
		"bad redirect":        {"client_id": clientID, "redirect_uris": []string{"http://evil.example.com/cb"}},
	} {
		doc = d
		f := newCIMDFetcher(true)
		if _, err := f.get(context.Background(), clientID); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Redirects are not followed.
	doc = map[string]any{"client_id": md.URL + "/redirect", "redirect_uris": []string{redirect}}
	if _, err := newCIMDFetcher(true).get(context.Background(), md.URL+"/redirect"); err == nil {
		t.Error("redirect followed")
	}
	// Without the dev flag, http and loopback are refused.
	strict := newCIMDFetcher(false)
	if _, err := strict.get(context.Background(), clientID); err == nil {
		t.Error("http client_id accepted without allow_insecure_client_metadata")
	}
	if _, err := strict.get(context.Background(), "https://127.0.0.1:1/client.json"); err == nil {
		t.Error("loopback https accepted")
	}
}

func TestCIMDURLShape(t *testing.T) {
	f := newCIMDFetcher(false)
	for id, ok := range map[string]bool{
		"https://app.example.com/oauth/client.json": true,
		"https://app.example.com":                   false,
		"https://app.example.com/":                  false,
		"http://app.example.com/c.json":             false,
		"https://u:p@app.example.com/c.json":        false,
		"https://app.example.com/a/../c.json":       false,
		"https://app.example.com/c.json#x":          false,
	} {
		if err := f.validateClientIDURL(id); (err == nil) != ok {
			t.Errorf("%s: err = %v", id, err)
		}
	}
	for ip, public := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.0.0.1": false, "192.168.1.1": false, "172.16.0.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fd00::1": false, "::ffff:10.0.0.1": false,
		"64:ff9b::a00:1": false,
	} {
		if got := publicIP(netip.MustParseAddr(ip).Unmap()); got != public {
			t.Errorf("publicIP(%s) = %v", ip, got)
		}
	}
}

func TestDCR(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	post := func(body string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", e.url("/register"), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		json.NewDecoder(r.Body).Decode(&out)
		r.Body.Close()
		return r.StatusCode, out
	}
	status, out := post(`{"client_name":"My Agent","redirect_uris":["http://localhost:3000/cb","https://app.example.com/cb"]}`)
	if status != 201 || out["token_endpoint_auth_method"] != "none" || !strings.HasPrefix(out["client_id"].(string), "dcr_") {
		t.Fatalf("register: %d %v", status, out)
	}
	c, err := e.store.GetClient(context.Background(), out["client_id"].(string))
	if err != nil || c.ClientName != "My Agent" || len(c.RedirectURIs) != 2 {
		t.Fatalf("stored client = %+v, %v", c, err)
	}
	for name, body := range map[string]string{
		"http non-loopback": `{"redirect_uris":["http://app.example.com/cb"]}`,
		"no redirect":       `{"redirect_uris":[]}`,
		"fragment":          `{"redirect_uris":["https://app.example.com/cb#x"]}`,
		"custom scheme":     `{"redirect_uris":["myapp://cb"]}`,
		"confidential":      `{"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		"implicit":          `{"redirect_uris":["https://app.example.com/cb"],"response_types":["token"]}`,
		"too many":          `{"redirect_uris":["https://a.example/1","https://a.example/2","https://a.example/3","https://a.example/4","https://a.example/5","https://a.example/6","https://a.example/7","https://a.example/8","https://a.example/9","https://a.example/10","https://a.example/11"]}`,
		"bad json":          `{`,
		"oversized":         `{"client_name":"` + strings.Repeat("a", maxRegisterBytes) + `","redirect_uris":["https://a.example/cb"]}`,
	} {
		if status, out := post(body); status != 400 {
			t.Errorf("%s: %d %v", name, status, out)
		}
	}
}
