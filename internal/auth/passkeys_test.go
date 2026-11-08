package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// authenticator is a virtual WebAuthn authenticator: ES256, "none"
// attestation, user verification always performed. It holds one
// discoverable credential once created.
type authenticator struct {
	t      *testing.T
	origin string
	rpID   string
	key    *ecdsa.PrivateKey
	credID []byte
	user   []byte // user handle stored with the credential
	count  uint32
}

func newAuthenticator(t *testing.T, origin string) *authenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(origin)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &authenticator{t: t, origin: origin, rpID: u.Hostname(), key: key, credID: id}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func (a *authenticator) authData(flags byte, attested []byte) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	a.count++
	var buf bytes.Buffer
	buf.Write(rp[:])
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.BigEndian, a.count)
	buf.Write(attested)
	return buf.Bytes()
}

// create answers navigator.credentials.create() options.
func (a *authenticator) create(optsJSON string) []byte {
	t := a.t
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
			AuthenticatorSelection struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optsJSON), &opts); err != nil {
		t.Fatalf("creation options %s: %v", optsJSON, err)
	}
	pk := opts.PublicKey
	if pk.RP.ID != a.rpID || pk.AuthenticatorSelection.ResidentKey != "required" || pk.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("unexpected creation options: %s", optsJSON)
	}
	a.user, _ = base64.RawURLEncoding.DecodeString(pk.User.ID)
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7},
		Curve:         1,
		XCoord:        a.key.X.FillBytes(make([]byte, 32)),
		YCoord:        a.key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	var attested bytes.Buffer
	attested.Write(make([]byte, 16)) // AAGUID
	_ = binary.Write(&attested, binary.BigEndian, uint16(len(a.credID)))
	attested.Write(a.credID)
	attested.Write(cose)
	att, err := webauthncbor.Marshal(struct {
		Fmt      string         `cbor:"fmt"`
		AttStmt  map[string]any `cbor:"attStmt"`
		AuthData []byte         `cbor:"authData"`
	}{"none", map[string]any{}, a.authData(0x45, attested.Bytes())}) // UP | UV | AT
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u(a.clientData("webauthn.create", pk.Challenge)),
			"attestationObject": b64u(att),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{},
	})
	return body
}

// get answers navigator.credentials.get() options.
func (a *authenticator) get(optsJSON string) []byte {
	t := a.t
	var opts struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optsJSON), &opts); err != nil {
		t.Fatalf("request options %s: %v", optsJSON, err)
	}
	if opts.PublicKey.UserVerification != "required" {
		t.Fatalf("user verification not required: %s", optsJSON)
	}
	cd := a.clientData("webauthn.get", opts.PublicKey.Challenge)
	ad := a.authData(0x05, nil) // UP | UV
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig), "userHandle": b64u(a.user),
		},
		"clientExtensionResults": map[string]any{},
	})
	return body
}

// newLocalhostEnv is newEnv with a host-name public URL (WebAuthn relying
// party IDs cannot be IP addresses).
func newLocalhostEnv(t *testing.T, yamlTmpl string, mutate func(*config.Config)) *env {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	_, port, _ := strings.Cut(srv.Listener.Addr().String(), ":")
	public := "http://localhost:" + port
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
	c := &clock{t: time.Now()}
	a, err := New(context.Background(), Options{Config: cfg, Store: st, RBAC: policy.NewRBAC(cfg),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if a.wa == nil {
		t.Fatal("passkeys unavailable")
	}
	mux := http.NewServeMux()
	a.Register(mux)
	srv.Config.Handler = mux
	srv.Start()
	t.Cleanup(func() { srv.Close(); st.Close() })
	return &env{t: t, srv: srv, auth: a, store: st, cfg: cfg, clock: c}
}

// script posts JSON like /static/webauthn.js.
func script(t *testing.T, c *http.Client, u, csrf string, body []byte) (int, string) {
	t.Helper()
	if body == nil {
		body = []byte("{}")
	}
	req, _ := http.NewRequest("POST", u, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Accept-Language", "en")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, readAll(resp)
}

func (e *env) sessionStepUp(c *http.Client) (string, time.Time) {
	e.t.Helper()
	u, _ := url.Parse(e.srv.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookieName {
			s, err := e.store.GetSession(context.Background(), store.HashSecret(ck.Value))
			if err != nil {
				e.t.Fatal(err)
			}
			if s.StepUpAt == nil {
				return s.StepUpMethod, time.Time{}
			}
			return s.StepUpMethod, *s.StepUpAt
		}
	}
	return "", time.Time{}
}

func redirectOf(t *testing.T, body string) string {
	t.Helper()
	var out map[string]string
	mustJSON(t, body, &out)
	return out["redirect"]
}

func TestPasskeyRegisterStepUpDelete(t *testing.T) {
	e := newLocalhostEnv(t, testConfig, nil)
	origin := e.cfg.Server.PublicURL
	b := e.browser()
	e.login(b, "taro@example.com")
	_, page := do(t, b, "GET", e.url("/account"), nil)
	csrf := csrfFrom(t, page)
	// Adding a passkey needs a fresh step-up first.
	if !strings.Contains(page, `href="/stepup?next=%2Faccount%23passkeys"`) || strings.Contains(page, `data-webauthn="create"`) {
		t.Fatalf("account page before step-up:\n%s", page)
	}
	if status, _ := script(t, b, e.url("/passkeys/register/begin"), csrf, nil); status != http.StatusForbidden {
		t.Fatalf("register without step-up: %d", status)
	}
	resp, _ := do(t, b, "POST", e.url("/stepup/dev"), url.Values{"csrf": {csrf}, "next": {"/account"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("dev step-up: %d", resp.StatusCode)
	}
	if m, _ := e.sessionStepUp(b); m != StepUpDev {
		t.Fatalf("step-up method %q", m)
	}
	_, page = do(t, b, "GET", e.url("/account"), nil)
	if !strings.Contains(page, `data-webauthn="create"`) || !strings.Contains(page, `src="/static/webauthn.js"`) {
		t.Fatalf("account page after step-up:\n%s", page)
	}
	// CSRF is required for script requests.
	if status, _ := script(t, b, e.url("/passkeys/register/begin"), "bad", nil); status != http.StatusForbidden {
		t.Fatalf("register with a bad csrf token: %d", status)
	}

	dev := newAuthenticator(t, origin)
	status, opts := script(t, b, e.url("/passkeys/register/begin"), csrf, nil)
	if status != http.StatusOK {
		t.Fatalf("register begin: %d %s", status, opts)
	}
	cred := dev.create(opts)
	status, body := script(t, b, e.url("/passkeys/register/finish?name=MacBook"), csrf, cred)
	if status != http.StatusOK || redirectOf(t, body) != "/account?passkey=added" {
		t.Fatalf("register finish: %d %s", status, body)
	}
	// A ceremony can be finished once.
	if status, _ := script(t, b, e.url("/passkeys/register/finish"), csrf, cred); status != http.StatusBadRequest {
		t.Fatalf("register replay: %d", status)
	}
	_, page = do(t, b, "GET", e.url("/account?passkey=added"), nil)
	if !strings.Contains(page, "MacBook") || !strings.Contains(page, "Passkey added.") {
		t.Fatalf("account page after registration:\n%s", page)
	}
	// The same authenticator cannot be registered twice: it is excluded.
	_, opts = script(t, b, e.url("/passkeys/register/begin"), csrf, nil)
	if !strings.Contains(opts, b64u(dev.credID)) {
		t.Fatalf("existing passkey not excluded: %s", opts)
	}

	// Step-up with the passkey after the dev step-up has gone stale.
	e.clock.advance(10 * time.Minute)
	status, opts = script(t, b, e.url("/passkeys/stepup/begin"), csrf, nil)
	if status != http.StatusOK || !strings.Contains(opts, b64u(dev.credID)) {
		t.Fatalf("step-up begin: %d %s", status, opts)
	}
	status, body = script(t, b, e.url("/passkeys/stepup/finish?next=%2Fapprovals%2Freq_1"), csrf, dev.get(opts))
	if status != http.StatusOK || redirectOf(t, body) != "/approvals/req_1" {
		t.Fatalf("step-up finish: %d %s", status, body)
	}
	if m, at := e.sessionStepUp(b); m != StepUpPasskey || !at.Equal(e.clock.now().Truncate(time.Millisecond)) {
		t.Fatalf("step-up after passkey: %q %v", m, at)
	}
	// A different key with the same credential ID is rejected.
	forged := newAuthenticator(t, origin)
	forged.credID, forged.user = dev.credID, dev.user
	_, opts = script(t, b, e.url("/passkeys/stepup/begin"), csrf, nil)
	if status, _ := script(t, b, e.url("/passkeys/stepup/finish"), csrf, forged.get(opts)); status != http.StatusForbidden {
		t.Fatalf("forged assertion: %d", status)
	}
	// An assertion for another origin is rejected.
	phish := *dev
	phish.origin = "https://evil.example"
	_, opts = script(t, b, e.url("/passkeys/stepup/begin"), csrf, nil)
	if status, _ := script(t, b, e.url("/passkeys/stepup/finish"), csrf, phish.get(opts)); status != http.StatusForbidden {
		t.Fatalf("assertion for another origin: %d", status)
	}

	// Another user cannot delete taro's passkey.
	other := e.browser()
	e.login(other, "jiro@example.com")
	_, opage := do(t, other, "GET", e.url("/account"), nil)
	if resp, _ := do(t, other, "POST", e.url("/account/passkeys/delete"), url.Values{"csrf": {csrfFrom(t, opage)}, "id": {b64u(dev.credID)}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete by another user: %d", resp.StatusCode)
	}
	resp, _ = do(t, b, "POST", e.url("/account/passkeys/delete"), url.Values{"csrf": {csrf}, "id": {b64u(dev.credID)}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if status, _ := script(t, b, e.url("/passkeys/stepup/begin"), csrf, nil); status != http.StatusBadRequest {
		t.Fatalf("step-up without passkeys: %d", status)
	}
	// Passkey sign-in needs auth.passkeys.
	if status, _ := script(t, e.browser(), e.url("/passkeys/login/begin"), "", nil); status != http.StatusNotFound {
		t.Fatalf("passkey login without auth.passkeys: %d", status)
	}
}

const passkeyConfig = `
server:
  listen: 127.0.0.1:8443
  public_url: %s
auth:
  passkeys: true
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

func TestPasskeyEnrollmentAndLogin(t *testing.T) {
	e := newLocalhostEnv(t, passkeyConfig, nil)
	origin := e.cfg.Server.PublicURL
	link, expires, err := CreatePasskeyEnrollment(context.Background(), e.store, e.cfg, "taro@example.com", e.clock.now())
	if err != nil || !strings.HasPrefix(link, origin+"/passkeys/enroll/"+EnrollTokenPrefix) || expires.Sub(e.clock.now()) != EnrollmentTTL {
		t.Fatalf("enrollment link %q %v %v", link, expires, err)
	}
	path := strings.TrimPrefix(link, origin)

	b := e.browser()
	resp, _ := do(t, b, "GET", e.url(path), nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/passkeys/enroll" {
		t.Fatalf("enrollment link: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, page := do(t, b, "GET", e.url("/passkeys/enroll"), nil)
	csrf := regexpFind(t, page, `data-csrf="([^"]+)"`)
	if !strings.Contains(page, "taro@example.com") {
		t.Fatalf("enrollment page:\n%s", page)
	}
	if status, _ := script(t, b, e.url("/passkeys/enroll/begin"), "bad", nil); status != http.StatusForbidden {
		t.Fatalf("enroll with a bad csrf token: %d", status)
	}
	dev := newAuthenticator(t, origin)
	status, opts := script(t, b, e.url("/passkeys/enroll/begin"), csrf, nil)
	if status != http.StatusOK {
		t.Fatalf("enroll begin: %d %s", status, opts)
	}
	status, body := script(t, b, e.url("/passkeys/enroll/finish"), csrf, dev.create(opts))
	if status != http.StatusOK || redirectOf(t, body) != "/account?passkey=enrolled" {
		t.Fatalf("enroll finish: %d %s", status, body)
	}
	resp, page = do(t, b, "GET", e.url("/account?passkey=enrolled"), nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Signed in with a passkey") {
		t.Fatalf("account after enrollment: %d\n%s", resp.StatusCode, page)
	}
	if m, _ := e.sessionStepUp(b); m != StepUpPasskey {
		t.Fatalf("enrollment session step-up %q", m)
	}
	// The link works once.
	if resp, _ := do(t, e.browser(), "GET", e.url(path), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("reused enrollment link: %d", resp.StatusCode)
	}

	// Discoverable sign-in from a fresh browser.
	nb := e.browser()
	_, page = do(t, nb, "GET", e.url("/login?next=%2Faccount"), nil)
	if !strings.Contains(page, `data-begin="/passkeys/login/begin"`) || !strings.Contains(page, `data-finish="/passkeys/login/finish?next=%2Faccount"`) {
		t.Fatalf("login page:\n%s", page)
	}
	status, opts = script(t, nb, e.url("/passkeys/login/begin"), "", nil)
	if status != http.StatusOK || strings.Contains(opts, "allowCredentials") {
		t.Fatalf("login begin: %d %s", status, opts)
	}
	status, body = script(t, nb, e.url("/passkeys/login/finish?next=%2Faccount"), "", dev.get(opts))
	if status != http.StatusOK || redirectOf(t, body) != "/account" {
		t.Fatalf("login finish: %d %s", status, body)
	}
	if resp, _ := do(t, nb, "GET", e.url("/account"), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("account after passkey login: %d", resp.StatusCode)
	}
	// An unknown credential cannot sign in.
	stranger := newAuthenticator(t, origin)
	stranger.user = dev.user
	_, opts = script(t, e.browser(), e.url("/passkeys/login/begin"), "", nil)
	sb := e.browser()
	_, opts = script(t, sb, e.url("/passkeys/login/begin"), "", nil)
	if status, _ := script(t, sb, e.url("/passkeys/login/finish"), "", stranger.get(opts)); status != http.StatusForbidden {
		t.Fatalf("unknown credential: %d", status)
	}
	// A credential answered with someone else's user handle is refused.
	mismatch := *dev
	mismatch.user = []byte("someone-else-handle-0123456789ab")
	_, opts = script(t, sb, e.url("/passkeys/login/begin"), "", nil)
	if status, _ := script(t, sb, e.url("/passkeys/login/finish"), "", mismatch.get(opts)); status != http.StatusForbidden {
		t.Fatalf("user handle mismatch: %d", status)
	}

	// A user deactivated through SCIM cannot sign in with a passkey.
	sq := e.store.(*store.SQLite)
	u := &store.SCIMUser{UserName: "taro@example.com", Email: "taro@example.com", Active: true}
	if err := sq.CreateSCIMUser(context.Background(), u, e.clock.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := sq.UpdateSCIMUser(context.Background(), u.ID, e.clock.now(), func(x *store.SCIMUser) error { x.Active = false; return nil }); err != nil {
		t.Fatal(err)
	}
	db := e.browser()
	_, opts = script(t, db, e.url("/passkeys/login/begin"), "", nil)
	if status, _ := script(t, db, e.url("/passkeys/login/finish"), "", dev.get(opts)); status != http.StatusForbidden {
		t.Fatalf("deactivated user: %d", status)
	}
}

func TestPasskeysNeedAHostName(t *testing.T) {
	// 127.0.0.1 cannot be a relying party ID: passkeys are off, the rest
	// works.
	e := newEnv(t, testConfig, nil)
	if e.auth.PasskeysEnabled() {
		t.Fatal("passkeys enabled for an IP public URL")
	}
	b := e.browser()
	e.login(b, "taro@example.com")
	_, page := do(t, b, "GET", e.url("/account"), nil)
	if strings.Contains(page, `id="passkeys"`) {
		t.Fatal("passkey section shown")
	}
	if status, _ := script(t, b, e.url("/passkeys/register/begin"), csrfFrom(t, page), nil); status != http.StatusNotFound {
		t.Fatalf("register begin: %d", status)
	}
}
