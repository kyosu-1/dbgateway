package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
)

const (
	tokenEnv  = "DBGW_TEST_SCIM_TOKEN"
	testToken = "scim-test-token-0123456789abcdef0123456789abcdef"
)

const testConfig = `
server: { public_url: "https://dbgw.example.com" }
auth: { dev_login: true }
scim: { enabled: true, token_env: DBGW_TEST_SCIM_TOKEN }
databases:
  - name: main
    primary: { host: localhost, read_user: r, sslmode: disable }
groups:
  - name: admins
    oidc_group: dbgw-admins
  - name: analysts
    oidc_group: dbgw-analysts
role_bindings:
  - group: analysts
    databases: [main]
    roles: [querier]
`

type env struct {
	t   *testing.T
	h   http.Handler
	st  *store.SQLite
	cfg *config.Config
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	t.Setenv(tokenEnv, testToken)
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, cfg: cfg, now: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)}
	e.h = NewHandler(Options{Config: cfg, Store: st, Now: func() time.Time { return e.now }})
	return e
}

type response struct {
	code int
	hdr  http.Header
	body map[string]any
	raw  string
}

func (e *env) req(method, path string, body any) response {
	e.t.Helper()
	return e.reqWith(method, path, body, "Bearer "+testToken)
}

func (e *env) reqWith(method, path string, body any, auth string) response {
	e.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, path, rd)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	r.Header.Set("Content-Type", ContentType)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	res := response{code: w.Code, hdr: w.Header(), raw: w.Body.String()}
	if w.Body.Len() > 0 && strings.HasPrefix(w.Header().Get("Content-Type"), ContentType) {
		if err := json.Unmarshal(w.Body.Bytes(), &res.body); err != nil {
			e.t.Fatalf("%s %s: invalid JSON %q: %v", method, path, w.Body.String(), err)
		}
	}
	return res
}

func (e *env) must(res response, code int) response {
	e.t.Helper()
	if res.code != code {
		e.t.Fatalf("status = %d, want %d; body = %s", res.code, code, res.raw)
	}
	return res
}

func (e *env) createUser(userName, email string) string {
	e.t.Helper()
	body := map[string]any{
		"schemas":  []string{schemaUser},
		"userName": userName,
		"name":     map[string]any{"givenName": "Taro", "familyName": "Yamada"},
		"active":   true,
	}
	if email != "" {
		body["emails"] = []map[string]any{{"value": email, "type": "work", "primary": true}}
	}
	res := e.must(e.req(http.MethodPost, "/scim/v2/Users", body), http.StatusCreated)
	return res.body["id"].(string)
}

func (e *env) createGroup(name string, members ...string) string {
	e.t.Helper()
	var ms []map[string]any
	for _, m := range members {
		ms = append(ms, map[string]any{"value": m})
	}
	body := map[string]any{"schemas": []string{schemaGroup}, "displayName": name, "members": ms}
	res := e.must(e.req(http.MethodPost, "/scim/v2/Groups", body), http.StatusCreated)
	return res.body["id"].(string)
}

func (e *env) idpGroups(email string) []string {
	e.t.Helper()
	u, err := e.st.GetUser(context.Background(), email)
	if err != nil {
		e.t.Fatalf("GetUser(%s): %v", email, err)
	}
	return u.IDPGroups
}

func patchBody(ops ...map[string]any) map[string]any {
	return map[string]any{"schemas": []string{schemaPatchOp}, "Operations": ops}
}

func scimType(res response) string {
	s, _ := res.body["scimType"].(string)
	return s
}

func TestDisabled(t *testing.T) {
	cfg, err := config.Parse([]byte("auth: { dev_login: true }\n"))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.OpenSQLite(context.Background(), ":memory:")
	defer st.Close()
	for _, h := range []http.Handler{NewHandler(Options{Config: cfg, Store: st}), NewHandler(Options{})} {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		r.Header.Set("Authorization", "Bearer "+testToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("disabled: status = %d", w.Code)
		}
	}
}

func TestAuth(t *testing.T) {
	e := newEnv(t)
	for _, auth := range []string{"", "Bearer", "Bearer wrong", "Basic " + testToken, "Bearer " + testToken + "x", testToken} {
		res := e.reqWith(http.MethodGet, "/scim/v2/Users", nil, auth)
		if res.code != http.StatusUnauthorized {
			t.Fatalf("auth %q: status = %d", auth, res.code)
		}
		if res.body["status"] != "401" || !slices.Contains(toStrings(res.body["schemas"]), schemaError) {
			t.Fatalf("auth %q: body = %s", auth, res.raw)
		}
		if res.hdr.Get("WWW-Authenticate") == "" {
			t.Fatal("missing WWW-Authenticate")
		}
	}
	e.must(e.reqWith(http.MethodGet, "/scim/v2/Users", nil, "bearer  "+testToken), http.StatusOK)

	// Without a configured token nothing is accepted, not even an empty one.
	t.Setenv(tokenEnv, "")
	h := NewHandler(Options{Config: e.cfg, Store: e.st})
	for _, auth := range []string{"Bearer ", "Bearer " + testToken} {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("no token configured, auth %q: status = %d", auth, w.Code)
		}
	}
}

func toStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			s, _ := x.(string)
			out = append(out, s)
		}
	}
	return out
}

func TestUserCRUD(t *testing.T) {
	e := newEnv(t)
	res := e.must(e.req(http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":    []string{schemaUser, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"},
		"userName":   "Taro@Example.com",
		"externalId": "00u1",
		"name":       map[string]any{"givenName": "Taro", "familyName": "Yamada"},
		"emails":     []map[string]any{{"value": "Taro@Example.com", "type": "work", "primary": true}},
		"active":     true,
		"title":      "ignored",
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{"department": "x"},
	}), http.StatusCreated)
	id := res.body["id"].(string)
	if !strings.HasPrefix(res.hdr.Get("Content-Type"), ContentType) {
		t.Fatalf("content type = %q", res.hdr.Get("Content-Type"))
	}
	if loc := res.hdr.Get("Location"); loc != "https://dbgw.example.com/scim/v2/Users/"+id {
		t.Fatalf("Location = %q", loc)
	}
	meta := res.body["meta"].(map[string]any)
	if meta["resourceType"] != "User" || meta["location"] != res.hdr.Get("Location") || meta["created"] != "2026-11-08T10:00:00Z" {
		t.Fatalf("meta = %v", meta)
	}
	if res.body["userName"] != "Taro@Example.com" || res.body["active"] != true || res.body["externalId"] != "00u1" {
		t.Fatalf("body = %s", res.raw)
	}

	// Duplicate userName (case-insensitive) → 409 uniqueness.
	dup := e.req(http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "taro@example.com"})
	if dup.code != http.StatusConflict || scimType(dup) != "uniqueness" {
		t.Fatalf("duplicate: %d %s", dup.code, dup.raw)
	}

	got := e.must(e.req(http.MethodGet, "/scim/v2/Users/"+id, nil), http.StatusOK)
	if got.body["name"].(map[string]any)["familyName"] != "Yamada" {
		t.Fatalf("get = %s", got.raw)
	}
	e.must(e.req(http.MethodGet, "/scim/v2/Users/nope", nil), http.StatusNotFound)

	// PUT replaces; active is kept when omitted.
	put := e.must(e.req(http.MethodPut, "/scim/v2/Users/"+id, map[string]any{
		"schemas":     []string{schemaUser},
		"userName":    "taro@example.com",
		"displayName": "Yamada Taro",
		"emails":      []map[string]any{{"value": "taro@example.com", "primary": true}},
	}), http.StatusOK)
	if put.body["displayName"] != "Yamada Taro" || put.body["name"] != nil || put.body["active"] != true || put.body["externalId"] != nil {
		t.Fatalf("put = %s", put.raw)
	}

	// PATCH with paths.
	p := e.must(e.req(http.MethodPatch, "/scim/v2/Users/"+id, patchBody(
		map[string]any{"op": "replace", "path": "name.givenName", "value": "Hanako"},
		map[string]any{"op": "add", "path": "externalId", "value": "ext-2"},
		map[string]any{"op": "Replace", "path": "displayName", "value": "H"},
		map[string]any{"op": "remove", "path": "displayName"},
		map[string]any{"op": "replace", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "x"},
	)), http.StatusOK)
	if p.body["name"].(map[string]any)["givenName"] != "Hanako" || p.body["externalId"] != "ext-2" || p.body["displayName"] != nil {
		t.Fatalf("patch = %s", p.raw)
	}

	e.must(e.req(http.MethodDelete, "/scim/v2/Users/"+id, nil), http.StatusNoContent)
	e.must(e.req(http.MethodGet, "/scim/v2/Users/"+id, nil), http.StatusNotFound)
	e.must(e.req(http.MethodDelete, "/scim/v2/Users/"+id, nil), http.StatusNotFound)
}

func TestUserValidation(t *testing.T) {
	e := newEnv(t)
	tests := []struct {
		name     string
		body     any
		scimType string
	}{
		{"no userName", map[string]any{"emails": []map[string]any{{"value": "a@example.com"}}}, "invalidValue"},
		{"no email", map[string]any{"userName": "taro"}, "invalidValue"},
		{"bad email", map[string]any{"userName": "taro", "emails": []map[string]any{{"value": "not an email"}}}, "invalidValue"},
		{"bad json", `{"userName":`, "invalidSyntax"},
		{"trailing data", `{"userName":"a@example.com"} {}`, "invalidSyntax"},
		{"bad active", map[string]any{"userName": "a@example.com", "active": "maybe"}, "invalidValue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := e.req(http.MethodPost, "/scim/v2/Users", tt.body)
			if res.code != http.StatusBadRequest || scimType(res) != tt.scimType {
				t.Fatalf("status = %d, body = %s", res.code, res.raw)
			}
		})
	}
	// A userName that is not an email is fine when there is an email.
	e.createUser("taro", "taro@example.com")
	// The primary email wins over userName.
	res := e.must(e.req(http.MethodGet, `/scim/v2/Users?filter=emails.value%20eq%20%22TARO@example.com%22`, nil), http.StatusOK)
	if res.body["totalResults"] != float64(1) {
		t.Fatalf("by email: %s", res.raw)
	}
}

func TestUserListFilterAndPaging(t *testing.T) {
	e := newEnv(t)
	var ids []string
	for i := range 5 {
		ids = append(ids, e.createUser(fmt.Sprintf("user%d@example.com", i), ""))
		e.now = e.now.Add(time.Second)
	}
	list := func(q string) response {
		return e.must(e.req(http.MethodGet, "/scim/v2/Users"+q, nil), http.StatusOK)
	}
	res := list("")
	if res.body["totalResults"] != float64(5) || res.body["itemsPerPage"] != float64(5) || res.body["startIndex"] != float64(1) {
		t.Fatalf("list = %s", res.raw)
	}
	if !slices.Contains(toStrings(res.body["schemas"]), schemaListResponse) {
		t.Fatal("schemas")
	}
	res = list("?startIndex=2&count=2")
	rs := res.body["Resources"].([]any)
	if res.body["totalResults"] != float64(5) || len(rs) != 2 || rs[0].(map[string]any)["id"] != ids[1] || res.body["startIndex"] != float64(2) {
		t.Fatalf("page = %s", res.raw)
	}
	res = list("?startIndex=9")
	if res.body["totalResults"] != float64(5) || len(res.body["Resources"].([]any)) != 0 {
		t.Fatalf("past end = %s", res.raw)
	}
	res = list("?count=0")
	if res.body["totalResults"] != float64(5) || len(res.body["Resources"].([]any)) != 0 {
		t.Fatalf("count=0 = %s", res.raw)
	}

	// Okta: filter=userName eq "x" (case-insensitive).
	res = list(`?filter=userName%20eq%20%22USER3@example.com%22`)
	rs = res.body["Resources"].([]any)
	if res.body["totalResults"] != float64(1) || rs[0].(map[string]any)["id"] != ids[3] {
		t.Fatalf("filter = %s", res.raw)
	}
	res = list(`?filter=userName%20eq%20%22nobody@example.com%22`)
	if res.body["totalResults"] != float64(0) {
		t.Fatalf("no match = %s", res.raw)
	}
	res = list(`?filter=id%20eq%20%22` + ids[0] + `%22%20and%20userName%20eq%20%22user1@example.com%22`)
	if res.body["totalResults"] != float64(0) {
		t.Fatalf("contradiction = %s", res.raw)
	}
	for _, bad := range []string{`title%20eq%20%22x%22`, `userName%20co%20%22x%22`, `userName%20eq%20%22x%22%20or%20id%20eq%20%22y%22`} {
		res := e.req(http.MethodGet, "/scim/v2/Users?filter="+bad, nil)
		if res.code != http.StatusBadRequest || scimType(res) != "invalidFilter" {
			t.Fatalf("filter %s: %d %s", bad, res.code, res.raw)
		}
	}
	res = e.req(http.MethodGet, "/scim/v2/Users?count=abc", nil)
	if res.code != http.StatusBadRequest {
		t.Fatalf("bad count: %d", res.code)
	}
}

// seedTokens creates an active human token, an agent token derived from
// it, and a browser session for email. It returns the token IDs.
func (e *env) seedTokens(email string) []string {
	e.t.Helper()
	ctx := context.Background()
	exp := e.now.Add(time.Hour)
	human := &store.Token{ID: "h-" + email, Hash: store.HashSecret("h" + email), Type: store.TokenAccess, Kind: identity.KindHuman,
		Human: email, ClientID: "cli", Audience: "https://dbgw.example.com", FamilyID: "fam-" + email, CreatedAt: e.now, ExpiresAt: exp}
	agent := &store.Token{ID: "a-" + email, Hash: store.HashSecret("a" + email), Type: store.TokenAccess, Kind: identity.KindAgent,
		Human: strings.ToUpper(email), Agent: "claude", ClientID: "mcp", Databases: []string{"main"}, Audience: "https://dbgw.example.com/mcp",
		ParentID: human.ID, CreatedAt: e.now, ExpiresAt: exp}
	for _, tk := range []*store.Token{human, agent} {
		if err := e.st.CreateToken(ctx, tk); err != nil {
			e.t.Fatal(err)
		}
	}
	if err := e.st.CreateSession(ctx, &store.Session{IDHash: store.HashSecret("s" + email), Email: email, CreatedAt: e.now, ExpiresAt: exp}); err != nil {
		e.t.Fatal(err)
	}
	return []string{human.ID, agent.ID}
}

func (e *env) assertLockedOut(email string, tokenIDs []string, locked bool) {
	e.t.Helper()
	ctx := context.Background()
	for _, id := range tokenIDs {
		tk, err := e.st.GetToken(ctx, id)
		if err != nil {
			e.t.Fatal(err)
		}
		if (tk.RevokedAt != nil) != locked {
			e.t.Fatalf("token %s revoked = %v, want %v", id, tk.RevokedAt != nil, locked)
		}
	}
	_, err := e.st.GetSession(ctx, store.HashSecret("s"+email))
	if errors.Is(err, store.ErrNotFound) != locked {
		e.t.Fatalf("session gone = %v (err %v), want %v", errors.Is(err, store.ErrNotFound), err, locked)
	}
	active, err := e.st.UserActive(ctx, email)
	if err != nil || active == locked {
		e.t.Fatalf("UserActive = %v, %v; want %v", active, err, !locked)
	}
}

func TestDeactivationRevokesTokensAndSessions(t *testing.T) {
	tests := []struct {
		name string
		op   map[string]any
	}{
		{"okta path-less", map[string]any{"op": "replace", "value": map[string]any{"active": false}}},
		{"entra string value", map[string]any{"op": "Replace", "path": "active", "value": "False"}},
		{"bool path", map[string]any{"op": "replace", "path": "active", "value": false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			const email = "taro@example.com"
			id := e.createUser(email, email)
			tokens := e.seedTokens(email)
			e.assertLockedOut(email, tokens, false)

			res := e.must(e.req(http.MethodPatch, "/scim/v2/Users/"+id, patchBody(tt.op)), http.StatusOK)
			if res.body["active"] != false {
				t.Fatalf("active = %v", res.body["active"])
			}
			e.assertLockedOut(email, tokens, true)
			if err := e.st.RecordLogin(context.Background(), email, nil, e.now, true); !errors.Is(err, store.ErrUserInactive) {
				t.Fatalf("RecordLogin = %v", err)
			}
			// The deactivated user is still visible to the IdP.
			e.must(e.req(http.MethodGet, "/scim/v2/Users/"+id, nil), http.StatusOK)

			// Reactivation lets the user log in again (old tokens stay revoked).
			e.must(e.req(http.MethodPatch, "/scim/v2/Users/"+id, patchBody(
				map[string]any{"op": "replace", "path": "active", "value": "true"})), http.StatusOK)
			if ok, _ := e.st.UserActive(context.Background(), email); !ok {
				t.Fatal("not active after reactivation")
			}
			if err := e.st.RecordLogin(context.Background(), email, nil, e.now, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPutInactiveAndCreateInactive(t *testing.T) {
	e := newEnv(t)
	const email = "jiro@example.com"
	tokens := e.seedTokens(email) // logged in before SCIM provisioning
	res := e.must(e.req(http.MethodPost, "/scim/v2/Users", map[string]any{"userName": email, "active": false}), http.StatusCreated)
	if res.body["active"] != false {
		t.Fatal("active")
	}
	e.assertLockedOut(email, tokens, true)

	const other = "saburo@example.com"
	id := e.createUser(other, "")
	tokens = e.seedTokens(other)
	e.must(e.req(http.MethodPut, "/scim/v2/Users/"+id, map[string]any{"userName": other, "active": false}), http.StatusOK)
	e.assertLockedOut(other, tokens, true)
}

func TestDeleteUserLocksOut(t *testing.T) {
	e := newEnv(t)
	const email = "taro@example.com"
	id := e.createUser(email, email)
	gid := e.createGroup("dbgw-analysts", id)
	tokens := e.seedTokens(email)
	e.must(e.req(http.MethodDelete, "/scim/v2/Users/"+id, nil), http.StatusNoContent)
	e.assertLockedOut(email, tokens, true)
	g := e.must(e.req(http.MethodGet, "/scim/v2/Groups/"+gid, nil), http.StatusOK)
	if len(g.body["members"].([]any)) != 0 {
		t.Fatalf("members after delete = %s", g.raw)
	}
	if res := e.must(e.req(http.MethodGet, `/scim/v2/Users?filter=userName%20eq%20%22taro@example.com%22`, nil), http.StatusOK); res.body["totalResults"] != float64(0) {
		t.Fatal("deleted user listed")
	}
	// Adding the deleted user to a group fails.
	res := e.req(http.MethodPatch, "/scim/v2/Groups/"+gid, patchBody(map[string]any{"op": "add", "path": "members", "value": []map[string]any{{"value": id}}}))
	if res.code != http.StatusBadRequest || scimType(res) != "invalidValue" {
		t.Fatalf("add deleted member: %d %s", res.code, res.raw)
	}
	// The IdP can provision the user again.
	id2 := e.createUser(email, email)
	if id2 == id {
		t.Fatal("same id")
	}
	if ok, _ := e.st.UserActive(context.Background(), email); !ok {
		t.Fatal("not active after re-provisioning")
	}
}

func TestGroupMembershipFeedsIDPGroups(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const email = "taro@example.com"
	rbac := policy.NewRBAC(e.cfg)

	// The user logged in before SCIM: login snapshot from the id_token.
	if err := e.st.RecordLogin(ctx, email, []string{"dbgw-admins"}, e.now, true); err != nil {
		t.Fatal(err)
	}
	if got := rbac.ResolveGroups(email, e.idpGroups(email)); !slices.Equal(got, []string{"admins"}) {
		t.Fatalf("before SCIM: %v", got)
	}

	// Provisioning replaces the snapshot with the (empty) SCIM groups.
	uid := e.createUser(email, email)
	if got := e.idpGroups(email); len(got) != 0 {
		t.Fatalf("after provisioning: %v", got)
	}
	other := e.createUser("hanako@example.com", "")

	gid := e.createGroup("dbgw-analysts", uid)
	if got := e.idpGroups(email); !slices.Equal(got, []string{"dbgw-analysts"}) {
		t.Fatalf("after group create: %v", got)
	}
	if got := rbac.ResolveGroups(email, e.idpGroups(email)); !slices.Equal(got, []string{"analysts"}) {
		t.Fatalf("resolved: %v", got)
	}
	u := e.must(e.req(http.MethodGet, "/scim/v2/Users/"+uid, nil), http.StatusOK)
	if gs := u.body["groups"].([]any); len(gs) != 1 || gs[0].(map[string]any)["display"] != "dbgw-analysts" {
		t.Fatalf("user groups = %s", u.raw)
	}

	// A login keeps the SCIM groups and ignores the id_token groups.
	if err := e.st.RecordLogin(ctx, email, []string{"dbgw-admins"}, e.now, true); err != nil {
		t.Fatal(err)
	}
	if got := e.idpGroups(email); !slices.Equal(got, []string{"dbgw-analysts"}) {
		t.Fatalf("after login: %v", got)
	}

	// Okta: add members, rename via path-less replace.
	gid2 := e.createGroup("dbgw-ops")
	e.must(e.req(http.MethodPatch, "/scim/v2/Groups/"+gid2, patchBody(
		map[string]any{"op": "add", "path": "members", "value": []map[string]any{{"value": uid, "display": email}, {"value": other}}},
	)), http.StatusNoContent)
	if got := e.idpGroups(email); !slices.Equal(got, []string{"dbgw-analysts", "dbgw-ops"}) {
		t.Fatalf("after add: %v", got)
	}
	e.must(e.req(http.MethodPatch, "/scim/v2/Groups/"+gid2, patchBody(
		map[string]any{"op": "replace", "value": map[string]any{"id": gid2, "displayName": "dbgw-admins"}},
	)), http.StatusNoContent)
	if got := e.idpGroups(email); !slices.Equal(got, []string{"dbgw-admins", "dbgw-analysts"}) {
		t.Fatalf("after rename: %v", got)
	}

	// Okta: remove with a filter path; Entra: remove with a value list.
	e.must(e.req(http.MethodPatch, "/scim/v2/Groups/"+gid2, patchBody(
		map[string]any{"op": "remove", "path": `members[value eq "` + uid + `"]`},
	)), http.StatusNoContent)
	if got := e.idpGroups(email); !slices.Equal(got, []string{"dbgw-analysts"}) {
		t.Fatalf("after filtered remove: %v", got)
	}
	e.must(e.req(http.MethodPatch, "/scim/v2/Groups/"+gid, patchBody(
		map[string]any{"op": "Remove", "path": "members", "value": []map[string]any{{"value": uid}}},
	)), http.StatusNoContent)
	if got := e.idpGroups(email); len(got) != 0 {
		t.Fatalf("after value remove: %v", got)
	}

	// Replace the member list.
	e.must(e.req(http.MethodPatch, "/scim/v2/Groups/"+gid, patchBody(
		map[string]any{"op": "replace", "path": "members", "value": []map[string]any{{"value": uid}}},
	)), http.StatusNoContent)
	if got := e.idpGroups(email); !slices.Equal(got, []string{"dbgw-analysts"}) {
		t.Fatalf("after replace: %v", got)
	}

	// Deactivation clears the groups; reactivation restores them.
	e.must(e.req(http.MethodPatch, "/scim/v2/Users/"+uid, patchBody(map[string]any{"op": "replace", "path": "active", "value": false})), http.StatusOK)
	if got := e.idpGroups(email); len(got) != 0 {
		t.Fatalf("inactive: %v", got)
	}
	e.must(e.req(http.MethodPatch, "/scim/v2/Users/"+uid, patchBody(map[string]any{"op": "replace", "path": "active", "value": true})), http.StatusOK)
	if got := e.idpGroups(email); !slices.Equal(got, []string{"dbgw-analysts"}) {
		t.Fatalf("reactivated: %v", got)
	}

	// Deleting the group removes it from the members.
	e.must(e.req(http.MethodDelete, "/scim/v2/Groups/"+gid, nil), http.StatusNoContent)
	if got := e.idpGroups(email); len(got) != 0 {
		t.Fatalf("after group delete: %v", got)
	}
	e.must(e.req(http.MethodGet, "/scim/v2/Groups/"+gid, nil), http.StatusNotFound)

	// With SCIM disabled, the login snapshot applies again.
	if err := e.st.RecordLogin(ctx, email, []string{"dbgw-admins"}, e.now, false); err != nil {
		t.Fatal(err)
	}
	if got := e.idpGroups(email); !slices.Equal(got, []string{"dbgw-admins"}) {
		t.Fatalf("scim disabled login: %v", got)
	}
}

func TestEmailChangeRetiresOldIdentity(t *testing.T) {
	e := newEnv(t)
	const oldEmail, newEmail = "old@example.com", "new@example.com"
	if err := e.st.RecordLogin(context.Background(), oldEmail, nil, e.now, true); err != nil {
		t.Fatal(err)
	}
	id := e.createUser(oldEmail, oldEmail)
	e.createGroup("dbgw-analysts", id)
	tokens := e.seedTokens(oldEmail)
	res := e.must(e.req(http.MethodPatch, "/scim/v2/Users/"+id, patchBody(
		map[string]any{"op": "replace", "path": `emails[type eq "work"].value`, "value": newEmail},
		map[string]any{"op": "replace", "path": "userName", "value": newEmail},
	)), http.StatusOK)
	emails := res.body["emails"].([]any)
	if len(emails) != 1 || emails[0].(map[string]any)["value"] != newEmail {
		t.Fatalf("emails = %s", res.raw)
	}
	for _, id := range tokens {
		if tk, _ := e.st.GetToken(context.Background(), id); tk.RevokedAt == nil {
			t.Fatalf("old identity token %s not revoked", id)
		}
	}
	if got := e.idpGroups(oldEmail); len(got) != 0 {
		t.Fatalf("old identity keeps groups %v", got)
	}
}

func TestUserPatchEmails(t *testing.T) {
	e := newEnv(t)
	id := e.createUser("taro", "taro@example.com")
	res := e.must(e.req(http.MethodPatch, "/scim/v2/Users/"+id, patchBody(
		map[string]any{"op": "add", "path": "emails", "value": []map[string]any{{"value": "home@example.net", "type": "home"}}},
		map[string]any{"op": "add", "path": `emails[type eq "other"].value`, "value": "other@example.org"},
		map[string]any{"op": "replace", "path": `emails[value eq "home@example.net"].primary`, "value": true},
	)), http.StatusOK)
	emails := res.body["emails"].([]any)
	if len(emails) != 3 {
		t.Fatalf("emails = %s", res.raw)
	}
	primaries := 0
	for _, x := range emails {
		if x.(map[string]any)["primary"] == true {
			primaries++
			if x.(map[string]any)["value"] != "home@example.net" {
				t.Fatalf("wrong primary: %s", res.raw)
			}
		}
	}
	if primaries != 1 {
		t.Fatalf("primaries = %d", primaries)
	}
	// The identity followed the primary email.
	if l := e.must(e.req(http.MethodGet, `/scim/v2/Users?filter=emails%20eq%20%22home@example.net%22`, nil), http.StatusOK); l.body["totalResults"] != float64(1) {
		t.Fatalf("identity: %s", l.raw)
	}
	res = e.must(e.req(http.MethodPatch, "/scim/v2/Users/"+id, patchBody(
		map[string]any{"op": "remove", "path": `emails[type eq "other"]`},
	)), http.StatusOK)
	if len(res.body["emails"].([]any)) != 2 {
		t.Fatalf("after remove = %s", res.raw)
	}

	for _, tt := range []struct {
		op       map[string]any
		scimType string
	}{
		{map[string]any{"op": "remove"}, "noTarget"},
		{map[string]any{"op": "remove", "path": "userName"}, "invalidValue"},
		{map[string]any{"op": "move", "path": "userName"}, "invalidSyntax"},
		{map[string]any{"op": "replace", "path": "active", "value": "yes"}, "invalidValue"},
		{map[string]any{"op": "replace", "path": "emails[", "value": "x"}, "invalidPath"},
		{map[string]any{"op": "replace", "value": "not an object"}, "invalidValue"},
		{map[string]any{"op": "remove", "path": "emails"}, ""}, // leaves only userName "taro": no identity
	} {
		res := e.req(http.MethodPatch, "/scim/v2/Users/"+id, patchBody(tt.op))
		want := tt.scimType
		if want == "" {
			want = "invalidValue"
		}
		if res.code != http.StatusBadRequest || scimType(res) != want {
			t.Fatalf("op %v: %d %s", tt.op, res.code, res.raw)
		}
	}
	// Failed PATCHes change nothing.
	if g := e.must(e.req(http.MethodGet, "/scim/v2/Users/"+id, nil), http.StatusOK); len(g.body["emails"].([]any)) != 2 {
		t.Fatalf("after failed patches = %s", g.raw)
	}
	res = e.req(http.MethodPatch, "/scim/v2/Users/"+id, map[string]any{"Operations": []any{}})
	if res.code != http.StatusBadRequest {
		t.Fatalf("empty ops: %d", res.code)
	}
}

func TestGroupCRUDAndFilters(t *testing.T) {
	e := newEnv(t)
	u1 := e.createUser("a@example.com", "")
	u2 := e.createUser("b@example.com", "")
	res := e.must(e.req(http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas": []string{schemaGroup}, "displayName": "dbgw-analysts", "externalId": "okta-1",
		"members": []map[string]any{{"value": u1}, {"value": u2, "type": "User"}},
	}), http.StatusCreated)
	gid := res.body["id"].(string)
	if res.hdr.Get("Location") != "https://dbgw.example.com/scim/v2/Groups/"+gid || len(res.body["members"].([]any)) != 2 {
		t.Fatalf("create = %s", res.raw)
	}
	m := res.body["members"].([]any)[0].(map[string]any)
	if m["value"] != u1 || m["display"] != "a@example.com" || m["$ref"] != "https://dbgw.example.com/scim/v2/Users/"+u1 {
		t.Fatalf("member = %v", m)
	}
	dup := e.req(http.MethodPost, "/scim/v2/Groups", map[string]any{"displayName": "DBGW-Analysts"})
	if dup.code != http.StatusConflict || scimType(dup) != "uniqueness" {
		t.Fatalf("dup = %d %s", dup.code, dup.raw)
	}
	bad := e.req(http.MethodPost, "/scim/v2/Groups", map[string]any{"displayName": "x", "members": []map[string]any{{"value": "nope"}}})
	if bad.code != http.StatusBadRequest || scimType(bad) != "invalidValue" {
		t.Fatalf("unknown member = %d %s", bad.code, bad.raw)
	}
	bad = e.req(http.MethodPost, "/scim/v2/Groups", map[string]any{"displayName": "x", "members": []map[string]any{{"value": gid, "type": "Group"}}})
	if bad.code != http.StatusBadRequest {
		t.Fatalf("nested group = %d %s", bad.code, bad.raw)
	}
	if bad := e.req(http.MethodPost, "/scim/v2/Groups", map[string]any{"displayName": " "}); bad.code != http.StatusBadRequest {
		t.Fatalf("empty name = %d", bad.code)
	}
	e.createGroup("dbgw-ops", u2)

	list := func(q string) response { return e.must(e.req(http.MethodGet, "/scim/v2/Groups"+q, nil), http.StatusOK) }
	res = list(`?filter=displayName%20eq%20%22dbgw-analysts%22`)
	rs := res.body["Resources"].([]any)
	if res.body["totalResults"] != float64(1) || rs[0].(map[string]any)["id"] != gid {
		t.Fatalf("by name = %s", res.raw)
	}
	res = list(`?filter=displayName%20eq%20%22dbgw-analysts%22&excludedAttributes=members`)
	if _, ok := res.body["Resources"].([]any)[0].(map[string]any)["members"]; ok {
		t.Fatalf("members not excluded = %s", res.raw)
	}
	res = list(`?filter=externalId%20eq%20%22okta-1%22`)
	if res.body["totalResults"] != float64(1) {
		t.Fatalf("by externalId = %s", res.raw)
	}
	// Entra: id eq ... and members[value eq ...]
	res = list(`?filter=id%20eq%20%22` + gid + `%22%20and%20members%5Bvalue%20eq%20%22` + u1 + `%22%5D&excludedAttributes=members`)
	if res.body["totalResults"] != float64(1) {
		t.Fatalf("member filter = %s", res.raw)
	}
	res = list(`?filter=members.value%20eq%20%22` + u2 + `%22`)
	if res.body["totalResults"] != float64(2) {
		t.Fatalf("member.value filter = %s", res.raw)
	}
	res = list("?count=1")
	if res.body["totalResults"] != float64(2) || len(res.body["Resources"].([]any)) != 1 {
		t.Fatalf("paging = %s", res.raw)
	}
	if res := e.req(http.MethodGet, `/scim/v2/Groups?filter=userName%20eq%20%22x%22`, nil); res.code != http.StatusBadRequest {
		t.Fatalf("bad group filter = %d", res.code)
	}

	g := e.must(e.req(http.MethodGet, "/scim/v2/Groups/"+gid+"?excludedAttributes=members", nil), http.StatusOK)
	if _, ok := g.body["members"]; ok || g.body["displayName"] != "dbgw-analysts" {
		t.Fatalf("get excluded = %s", g.raw)
	}

	// PUT without members renames and keeps the members.
	put := e.must(e.req(http.MethodPut, "/scim/v2/Groups/"+gid, map[string]any{"displayName": "dbgw-analysts-2"}), http.StatusOK)
	if put.body["displayName"] != "dbgw-analysts-2" || len(put.body["members"].([]any)) != 2 || put.body["externalId"] != nil {
		t.Fatalf("put = %s", put.raw)
	}
	// PUT with members replaces them.
	put = e.must(e.req(http.MethodPut, "/scim/v2/Groups/"+gid, map[string]any{"displayName": "dbgw-analysts-2", "members": []map[string]any{{"value": u2}}}), http.StatusOK)
	if ms := put.body["members"].([]any); len(ms) != 1 || ms[0].(map[string]any)["value"] != u2 {
		t.Fatalf("put members = %s", put.raw)
	}
	// Remove all members; rename conflict.
	e.must(e.req(http.MethodPatch, "/scim/v2/Groups/"+gid, patchBody(map[string]any{"op": "remove", "path": "members"})), http.StatusNoContent)
	if g := e.must(e.req(http.MethodGet, "/scim/v2/Groups/"+gid, nil), http.StatusOK); len(g.body["members"].([]any)) != 0 {
		t.Fatalf("remove all = %s", g.raw)
	}
	conflict := e.req(http.MethodPatch, "/scim/v2/Groups/"+gid, patchBody(map[string]any{"op": "replace", "path": "displayName", "value": "dbgw-ops"}))
	if conflict.code != http.StatusConflict {
		t.Fatalf("rename conflict = %d %s", conflict.code, conflict.raw)
	}
	for _, op := range []map[string]any{
		{"op": "remove", "path": "displayName"},
		{"op": "add", "path": `members[value eq "x"]`, "value": "y"},
		{"op": "replace", "path": "displayName", "value": ""},
	} {
		if res := e.req(http.MethodPatch, "/scim/v2/Groups/"+gid, patchBody(op)); res.code != http.StatusBadRequest {
			t.Fatalf("op %v: %d %s", op, res.code, res.raw)
		}
	}
	e.must(e.req(http.MethodPatch, "/scim/v2/Groups/nope", patchBody(map[string]any{"op": "remove", "path": "members"})), http.StatusNotFound)
}

func TestDiscoveryAndRouting(t *testing.T) {
	e := newEnv(t)
	sp := e.must(e.req(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil), http.StatusOK)
	if sp.body["patch"].(map[string]any)["supported"] != true || sp.body["bulk"].(map[string]any)["supported"] != false {
		t.Fatalf("spc = %s", sp.raw)
	}
	rt := e.must(e.req(http.MethodGet, "/scim/v2/ResourceTypes", nil), http.StatusOK)
	if rt.body["totalResults"] != float64(2) {
		t.Fatalf("resource types = %s", rt.raw)
	}
	e.must(e.req(http.MethodGet, "/scim/v2/ResourceTypes/User", nil), http.StatusOK)
	sc := e.must(e.req(http.MethodGet, "/scim/v2/Schemas", nil), http.StatusOK)
	if sc.body["totalResults"] != float64(2) {
		t.Fatalf("schemas = %s", sc.raw)
	}
	one := e.must(e.req(http.MethodGet, "/scim/v2/Schemas/"+schemaGroup, nil), http.StatusOK)
	if one.body["name"] != "Group" {
		t.Fatalf("schema = %s", one.raw)
	}
	e.must(e.req(http.MethodGet, "/scim/v2/Schemas/urn:x", nil), http.StatusNotFound)
	e.must(e.req(http.MethodGet, "/scim/v2/Me", nil), http.StatusNotFound)
	e.must(e.req(http.MethodGet, "/scim/v2/Users/a/b", nil), http.StatusNotFound)
	e.must(e.req(http.MethodGet, "/scim/v2", nil), http.StatusNotFound)
	e.must(e.req(http.MethodGet, "/other", nil), http.StatusNotFound)
	e.must(e.req(http.MethodDelete, "/scim/v2/Users", nil), http.StatusMethodNotAllowed)
	e.must(e.req(http.MethodPost, "/scim/v2/Users/x", nil), http.StatusMethodNotAllowed)
	e.must(e.req(http.MethodPost, "/scim/v2/ServiceProviderConfig", nil), http.StatusMethodNotAllowed)
	big := `{"userName":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	e.must(e.req(http.MethodPost, "/scim/v2/Users", big), http.StatusRequestEntityTooLarge)
}

func TestParseFilter(t *testing.T) {
	tests := []struct {
		in   string
		want []filterTerm
		err  bool
	}{
		{`userName eq "taro@example.com"`, []filterTerm{{"username", "taro@example.com"}}, false},
		{`UserName EQ "Taro"`, []filterTerm{{"username", "Taro"}}, false},
		{`externalId eq "00u1"`, []filterTerm{{"externalid", "00u1"}}, false},
		{`displayName eq "dbgw \"quoted\" é"`, []filterTerm{{"displayname", `dbgw "quoted" é`}}, false},
		{`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "x"`, []filterTerm{{"username", "x"}}, false},
		{`id eq "1" and members[value eq "2"]`, []filterTerm{{"id", "1"}, {"members.value", "2"}}, false},
		{`members.value eq "2"`, []filterTerm{{"members.value", "2"}}, false},
		{`emails[type eq "work"]`, []filterTerm{{"emails.type", "work"}}, false},
		{`active eq true`, []filterTerm{{"active", "true"}}, false},
		{`  userName   eq   "x"  `, []filterTerm{{"username", "x"}}, false},
		{``, nil, true},
		{`userName`, nil, true},
		{`userName eq`, nil, true},
		{`userName eq "x`, nil, true},
		{`userName ne "x"`, nil, true},
		{`userName sw "x"`, nil, true},
		{`userName pr`, nil, true},
		{`userName eq "x" or id eq "y"`, nil, true},
		{`not (userName eq "x")`, nil, true},
		{`(userName eq "x")`, nil, true},
		{`members[value eq "x"`, nil, true},
		{`userName eq "x" and`, nil, true},
		{strings.Repeat("a", maxFilterLen+1), nil, true},
	}
	for _, tt := range tests {
		got, err := parseFilter(tt.in)
		if (err != nil) != tt.err {
			t.Errorf("parseFilter(%q) err = %v", tt.in, err)
			continue
		}
		if err != nil {
			var se *Error
			if !errors.As(err, &se) || se.ScimType != "invalidFilter" {
				t.Errorf("parseFilter(%q) err = %v, want invalidFilter", tt.in, err)
			}
			continue
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("parseFilter(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		in   string
		want attrPath
		err  bool
	}{
		{"active", attrPath{attr: "active"}, false},
		{"name.givenName", attrPath{attr: "name", sub: "givenname"}, false},
		{`emails[type eq "work"].value`, attrPath{attr: "emails", filter: &filterTerm{"type", "work"}, sub: "value"}, false},
		{`members[value eq "abc"]`, attrPath{attr: "members", filter: &filterTerm{"value", "abc"}}, false},
		{"urn:ietf:params:scim:schemas:core:2.0:User:name.familyName", attrPath{attr: "name", sub: "familyname"}, false},
		{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value",
			attrPath{attr: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:manager.value"}, false},
		{"", attrPath{}, true},
		{"emails[", attrPath{}, true},
		{`emails[type eq "work"]x`, attrPath{}, true},
		{`name.givenName[type eq "x"]`, attrPath{}, true},
		{"a b", attrPath{}, true},
	}
	for _, tt := range tests {
		got, err := parsePath(tt.in)
		if (err != nil) != tt.err {
			t.Errorf("parsePath(%q) err = %v", tt.in, err)
			continue
		}
		if err != nil {
			continue
		}
		if got.attr != tt.want.attr || got.sub != tt.want.sub || (got.filter == nil) != (tt.want.filter == nil) ||
			(got.filter != nil && *got.filter != *tt.want.filter) {
			t.Errorf("parsePath(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func FuzzParseFilter(f *testing.F) {
	for _, s := range []string{`userName eq "x"`, `id eq "1" and members[value eq "2"]`, `a[b[c eq "d"]]`, `"\`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseFilter(s)
		_, _ = parsePath(s)
	})
}
