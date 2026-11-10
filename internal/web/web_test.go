package web

import (
	"bytes"
	"context"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/store"
)

const update = "UPDATE users SET plan = 'pro' WHERE id = 48213 RETURNING id, email"

// The reason is written by an agent: it must be shown as inert text.
const agentReason = "ticket #1234 <a href=\"https://evil.example\">click</a> @channel ‮evil"

func TestNavShowsOnlyPermittedSections(t *testing.T) {
	e := newEnv(t, nil)
	e.submit(update, agentReason)
	for _, tt := range []struct {
		email string
		want  []string
		not   []string
	}{
		{"hanako@example.com", []string{`href="/approvals"`, `href="/requests"`, `href="/console"`, `<span class="nav-badge" aria-hidden="true">1</span>`},
			[]string{`href="/audit"`, `href="/users"`}},
		{"taro@example.com", []string{`href="/requests"`, `href="/console"`}, []string{`href="/approvals"`, `href="/audit"`}},
		{"sec@example.com", []string{`href="/audit"`, `href="/users"`}, []string{`href="/approvals"`, `href="/console"`}},
		{"root@example.com", []string{`href="/audit"`, `href="/users"`}, []string{`href="/approvals"`}},
	} {
		c, _ := e.login(tt.email)
		_, page := do(t, c, "GET", e.url("/account"), nil)
		mustContain(t, page, tt.want...)
		mustNotContain(t, page, tt.not...)
	}
	// The root page goes to the first permitted section.
	c, _ := e.login("hanako@example.com")
	if resp, _ := do(t, c, "GET", e.url("/"), nil); resp.Header.Get("Location") != "/approvals" {
		t.Fatalf("root redirect: %q", resp.Header.Get("Location"))
	}
}

func TestPagesNeedASession(t *testing.T) {
	e := newEnv(t, nil)
	id := e.submit(update, "ticket #1")
	for _, path := range []string{"/approvals", "/approvals/" + id, "/requests", "/console", "/audit", "/users", "/breakglass"} {
		resp, _ := do(t, browser(), "GET", e.url(path), nil)
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
			t.Errorf("GET %s without session: %d %q", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// A bearer token (agents) never opens the web UI.
	req, _ := http.NewRequest("GET", e.url("/approvals"), nil)
	req.Header.Set("Authorization", "Bearer dbgw_at_whatever")
	resp, err := browser().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("bearer: %d", resp.StatusCode)
	}
	for _, path := range []string{"/approvals/" + id + "/approve", "/approvals/" + id + "/reject", "/requests/" + id + "/cancel", "/console", "/breakglass"} {
		if resp, _ := do(t, browser(), "POST", e.url(path), url.Values{}); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("POST %s without session: %d", path, resp.StatusCode)
		}
	}
}

func TestApproveRequiresStepUp(t *testing.T) {
	e := newEnv(t, nil)
	id := e.submit(update, agentReason)
	c, csrf := e.login("hanako@example.com")

	resp, page := do(t, c, "GET", e.url("/approvals"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approvals: %d", resp.StatusCode)
	}
	mustContain(t, page, "Update 1 row in users", "claude-code · on behalf of taro@example.com", "prod", "/approvals/"+id, "left")

	resp, page = do(t, c, "GET", e.url("/approvals/"+id), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail: %d", resp.StatusCode)
	}
	mustContain(t, page,
		"written by the agent",
		`<span class="sql-str">&#39;pro&#39;</span>`, // raw SQL with literals
		"Hide values",
		"ticket #1234 &lt;a href=&#34;https://evil.example&#34;&gt;click&lt;/a&gt; @channel �evil", // inert, no bidi override
		"Step 1 of 1", `action="/approvals/`+id+`/reject"`, `formaction="/approvals/`+id+`/approve"`,
		"Rolls back if more than 2 rows change")
	mustNotContain(t, page, `<a href="https://evil.example"`, "‮")

	// CSRF is required.
	if resp, _ := do(t, c, "POST", e.url("/approvals/"+id+"/approve"), url.Values{"csrf": {"nope"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("approve without csrf: %d", resp.StatusCode)
	}
	// Without a step-up the user is sent to /stepup and back.
	resp, _ = do(t, c, "POST", e.url("/approvals/"+id+"/approve"), url.Values{"csrf": {csrf}})
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/stepup?next=") {
		t.Fatalf("approve without step-up: %d %q", resp.StatusCode, loc)
	}
	if r, _ := e.svc.Get(context.Background(), &taroHuman, id); r.Status != approval.StatusPending {
		t.Fatalf("approved without step-up: %s", r.Status)
	}
	_, page = do(t, c, "GET", e.url(loc), nil)
	mustContain(t, page, `action="/stepup/dev"`)
	next, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/stepup?next="))
	resp, _ = do(t, c, "POST", e.url("/stepup/dev"), url.Values{"csrf": {csrf}, "next": {next}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != next {
		t.Fatalf("dev step-up: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, page = do(t, c, "GET", e.url(next), nil)
	mustContain(t, page, "You&#39;re verified")

	resp, _ = do(t, c, "POST", e.url("/approvals/"+id+"/approve"), url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/approvals/"+id+"?done=approved" {
		t.Fatalf("approve: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	e.svc.Wait()
	r, err := e.svc.Get(context.Background(), &taroHuman, id)
	if err != nil || r.Status != approval.StatusSucceeded || r.Approvals[0].StepUpMethod != "dev" {
		t.Fatalf("after approve: %+v %v", r, err)
	}
	_, page = do(t, c, "GET", e.url("/approvals/"+id+"?done=approved"), nil)
	mustContain(t, page, "Approved.", "1 rows changed", "<th scope=\"col\"><span class=\"th-flag\">", "email", `class="masked"`)
	mustNotContain(t, page, "user1@example.com") // RETURNING email is masked

	// Approving again fails with a friendly message.
	resp, page = do(t, c, "POST", e.url("/approvals/"+id+"/approve"), url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second approve: %d", resp.StatusCode)
	}
	mustContain(t, page, "no longer pending")

	// The step-up expires.
	e.clock.Add(6 * time.Minute)
	id2 := e.submit(update, "ticket #2")
	resp, _ = do(t, c, "POST", e.url("/approvals/"+id2+"/approve"), url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/stepup?") {
		t.Fatalf("approve with an old step-up: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRequesterAndOthersCannotApprove(t *testing.T) {
	e := newEnv(t, nil)
	id := e.submit(update, "ticket #1")

	// The requester sees the request but cannot decide it.
	c, csrf := e.login("taro@example.com")
	resp, page := do(t, c, "GET", e.url("/approvals/"+id), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("requester detail: %d", resp.StatusCode)
	}
	mustContain(t, page, "Withdraw request")
	mustNotContain(t, page, "/approve\"", ">Reject<")
	e.stepUp(c, csrf)
	resp, page = do(t, c, "POST", e.url("/approvals/"+id+"/approve"), url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("self approval: %d", resp.StatusCode)
	}
	mustContain(t, page, "can&#39;t decide your own request")
	// The approvals list is for approvers only.
	if resp, _ := do(t, c, "GET", e.url("/approvals"), nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("requester list: %d", resp.StatusCode)
	}

	// Someone who is neither requester nor approver: not found.
	c, csrf = e.login("ken@example.com") // sre: approver on prod
	if resp, _ := do(t, c, "GET", e.url("/approvals/"+id), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("approver detail: %d", resp.StatusCode)
	}
	c, csrf = e.login("sec@example.com")
	if resp, _ := do(t, c, "GET", e.url("/approvals/"+id), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("outsider detail: %d", resp.StatusCode)
	}
	e.stepUp(c, csrf)
	if resp, _ := do(t, c, "POST", e.url("/approvals/"+id+"/approve"), url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("outsider approve: %d", resp.StatusCode)
	}
	if resp, _ := do(t, c, "POST", e.url("/approvals/"+id+"/reject"), url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("outsider reject: %d", resp.StatusCode)
	}
}

func TestRejectAndRequesterView(t *testing.T) {
	e := newEnv(t, nil)
	id := e.submit(update, "ticket #1")
	c, csrf := e.login("hanako@example.com")
	resp, _ := do(t, c, "POST", e.url("/approvals/"+id+"/reject"), url.Values{"csrf": {csrf}, "comment": {"too broad <b>"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/approvals/"+id+"?done=rejected" {
		t.Fatalf("reject: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, page := do(t, c, "GET", e.url("/approvals?tab=decided"), nil)
	mustContain(t, page, "Rejected", "/approvals/"+id)

	c, _ = e.login("taro@example.com")
	_, page = do(t, c, "GET", e.url("/requests?status=closed"), nil)
	mustContain(t, page, "Rejected", "claude-code · prod · “too broad &lt;b&gt;”")
	_, page = do(t, c, "GET", e.url("/requests?status=pending"), nil)
	mustContain(t, page, "No requests.")
}

func TestCancel(t *testing.T) {
	e := newEnv(t, nil)
	id := e.submit(update, "ticket #1")
	// Another developer cannot cancel taro's request.
	c, csrf := e.login("jiro@example.com")
	if resp, _ := do(t, c, "POST", e.url("/requests/"+id+"/cancel"), url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cancel by another user: %d", resp.StatusCode)
	}
	c, csrf = e.login("taro@example.com")
	_, page := do(t, c, "GET", e.url("/requests"), nil)
	mustContain(t, page, `action="/requests/`+id+`/cancel"`, "Pending")
	if resp, _ := do(t, c, "POST", e.url("/requests/"+id+"/cancel"), url.Values{}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cancel without csrf: %d", resp.StatusCode)
	}
	resp, _ := do(t, c, "POST", e.url("/requests/"+id+"/cancel"), url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/requests?canceled=1" {
		t.Fatalf("cancel: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, page = do(t, c, "GET", e.url("/requests?canceled=1"), nil)
	mustContain(t, page, "Withdrawn.")
	mustNotContain(t, page, `/cancel"`)
}

func TestConsole(t *testing.T) {
	e := newEnv(t, nil)
	c, csrf := e.login("taro@example.com")
	resp, page := do(t, c, "GET", e.url("/console?db=prod"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("console: %d", resp.StatusCode)
	}
	mustContain(t, page, `<option value="prod" selected>`, "users", `class="class-badge">masked<`, "Reads return at most 1000 rows")

	run := func(form url.Values) (int, string) {
		form.Set("csrf", csrf)
		resp, page := do(t, c, "POST", e.url("/console"), form)
		return resp.StatusCode, page
	}
	// Read: masked columns are marked and masked.
	status, page := run(url.Values{"db": {"prod"}, "sql": {"SELECT id, email FROM users"}, "reason": {"ticket #1234 investigation"}, "action": {"run"}})
	if status != http.StatusOK {
		t.Fatalf("run: %d", status)
	}
	mustContain(t, page, "1 rows", `class="masked"`, "Allowed")
	mustNotContain(t, page, "user1@example.com")
	// Denied (DDL), with the reason.
	_, page = run(url.Values{"db": {"prod"}, "sql": {"DROP TABLE users"}, "reason": {"ticket #1234 cleanup"}, "action": {"run"}})
	mustContain(t, page, "Denied", "Hint:")
	// Write: pending, linked to the approval page.
	_, page = run(url.Values{"db": {"prod"}, "sql": {update}, "reason": {"ticket #1234 plan fix"}, "action": {"run"}})
	mustContain(t, page, "Submitted for approval", `href="/approvals/req_`, "hanako@example.com")
	list, _ := e.svc.List(context.Background(), &taroHuman, approval.ListFilter{})
	if len(list) != 1 || list[0].Requester.ClientID != ConsoleClientID {
		t.Fatalf("console request: %+v", list)
	}
	// Explain does not execute.
	before := len(e.fa.Execs())
	_, page = run(url.Values{"db": {"prod"}, "sql": {update}, "action": {"explain"}})
	mustContain(t, page, "Decision", "Requested", "<code>default</code>")
	if len(e.fa.Execs()) != before {
		t.Fatal("explain executed the statement")
	}
	// Reason is required to run.
	if status, page := run(url.Values{"db": {"prod"}, "sql": {"SELECT 1"}, "action": {"run"}}); status != http.StatusBadRequest || !strings.Contains(page, "Enter a reason") {
		t.Fatalf("no reason: %d", status)
	}
	// Only readable databases (the form field is not trusted).
	if status, _ := run(url.Values{"db": {"nope"}, "sql": {"SELECT 1"}, "reason": {"ticket #1234 check"}, "action": {"run"}}); status != http.StatusForbidden {
		t.Fatalf("unknown database: %d", status)
	}
	// CSRF.
	if resp, _ := do(t, c, "POST", e.url("/console"), url.Values{"db": {"prod"}, "sql": {"SELECT 1"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("console without csrf: %d", resp.StatusCode)
	}
	// Someone without a querier role has no console.
	c, _ = e.login("sec@example.com")
	if resp, _ := do(t, c, "GET", e.url("/console"), nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("console without roles: %d", resp.StatusCode)
	}
}

func TestAudit(t *testing.T) {
	e := newEnv(t, nil)
	id := e.submit(update, "ticket #1234 plan fix")
	e.gw.ExecuteSQL(context.Background(), taroAgent, gateway.ExecuteRequest{Database: "prod", SQL: "DROP TABLE users", Reason: "ticket #1 cleanup"})

	for _, email := range []string{"taro@example.com", "hanako@example.com"} {
		c, _ := e.login(email)
		if resp, _ := do(t, c, "GET", e.url("/audit"), nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s audit: %d", email, resp.StatusCode)
		}
		if resp, _ := do(t, c, "GET", e.url("/audit/"+id), nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s audit entry: %d", email, resp.StatusCode)
		}
	}
	c, _ := e.login("sec@example.com")
	resp, page := do(t, c, "GET", e.url("/audit"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit: %d", resp.StatusCode)
	}
	mustContain(t, page, "Write to users", "claude-code (taro@example.com) · prod", "Denied", "Requested", "/audit/"+id)
	_, page = do(t, c, "GET", e.url("/audit?decision=deny"), nil)
	mustContain(t, page, "Denied")
	mustNotContain(t, page, "/audit/"+id+`"`)
	_, page = do(t, c, "GET", e.url("/audit?table=users&principal=claude&db=prod&period=7d"), nil)
	mustContain(t, page, "/audit/"+id)
	_, page = do(t, c, "GET", e.url("/audit?db=staging"), nil)
	mustContain(t, page, "No matching entries.")

	resp, page = do(t, c, "GET", e.url("/audit/"+id), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit entry: %d", resp.StatusCode)
	}
	mustContain(t, page, "Write to users", "values redacted", "written by the agent", "ticket #1234 plan fix", "Entries for this request", "Approval: submitted")
	mustNotContain(t, page, "&#39;pro&#39;") // literals are not logged
	if resp, _ := do(t, c, "GET", e.url("/audit/req_nope"), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing entry: %d", resp.StatusCode)
	}
	// Admins may look too.
	c, _ = e.login("root@example.com")
	if resp, _ := do(t, c, "GET", e.url("/audit"), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin audit: %d", resp.StatusCode)
	}
}

func TestAuditNotFile(t *testing.T) {
	e := newEnv(t, func(y string) string { return strings.Replace(y, "output: file", "output: stdout", 1) })
	c, _ := e.login("sec@example.com")
	resp, page := do(t, c, "GET", e.url("/audit"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit: %d", resp.StatusCode)
	}
	mustContain(t, page, "isn&#39;t written to files")
}

func TestUsersAndProposal(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.login("taro@example.com")
	if resp, _ := do(t, c, "GET", e.url("/users"), nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("users as developer: %d", resp.StatusCode)
	}
	if resp, _ := do(t, c, "GET", e.url("/users/jiro@example.com/propose"), nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("propose as developer: %d", resp.StatusCode)
	}
	c, _ = e.login("sec@example.com")
	resp, page := do(t, c, "GET", e.url("/users"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("users: %d", resp.StatusCode)
	}
	// Store users and people named in the configuration.
	mustContain(t, page, "taro@example.com", "ken@example.com", "root@example.com", "Admin", "Never signed in")
	_, page = do(t, c, "GET", e.url("/users?group=sre"), nil)
	mustContain(t, page, "hanako@example.com")
	mustNotContain(t, page, "taro@example.com")

	resp, page = do(t, c, "GET", e.url("/users/jiro@example.com"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("user: %d", resp.StatusCode)
	}
	mustContain(t, page, "querier, writer", "from group dev", "approver: personal binding · until", "Propose a role change")
	if resp, _ := do(t, c, "GET", e.url("/users/nobody@example.com"), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown user: %d", resp.StatusCode)
	}

	future := time.Now().Add(48 * time.Hour).Format("2006-01-02T15:04")
	q := url.Values{"generate": {"1"}, "db": {"prod", "staging"}, "role": {"approver", "querier"}, "expires": {future}, "reason": {"on-call next week"}}
	resp, page = do(t, c, "GET", e.url("/users/jiro@example.com/propose?"+q.Encode()), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("propose: %d\n%s", resp.StatusCode, page)
	}
	mustContain(t, page,
		"role_bindings:\n  - user: jiro@example.com\n    databases: [&#34;prod&#34;, &#34;staging&#34;]\n    roles: [querier, approver]\n    expires_at: ",
		"Grant querier, approver on prod, staging to jiro@example.com",
		"on-call next week", "Generated by sec@example.com", `src="/static/copy.js"`, `data-copy="yaml-out"`)
	// Invalid input is reported.
	q = url.Values{"generate": {"1"}, "db": {"nope"}, "role": {"superuser"}, "expires": {"2000-01-01T00:00"}}
	resp, page = do(t, c, "GET", e.url("/users/jiro@example.com/propose?"+q.Encode()), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid proposal: %d", resp.StatusCode)
	}
	mustContain(t, page, "Unknown database.", "Unknown role.", "must be in the future", "Enter a reason.")
	mustNotContain(t, page, "role_bindings:\n")
}

func TestBreakGlass(t *testing.T) {
	e := newEnv(t, nil)
	c, csrf := e.login("taro@example.com") // writer, not approver
	if resp, _ := do(t, c, "GET", e.url("/breakglass"), nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("breakglass as developer: %d", resp.StatusCode)
	}
	e.stepUp(c, csrf)
	if resp, _ := do(t, c, "POST", e.url("/breakglass"), url.Values{"csrf": {csrf}, "db": {"prod"}, "duration": {"30m"}, "reason": {"INC-1"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("elevate as developer: %d", resp.StatusCode)
	}

	c, csrf = e.login("hanako@example.com")
	resp, page := do(t, c, "GET", e.url("/breakglass"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("breakglass: %d", resp.StatusCode)
	}
	mustContain(t, page, `value="prod" checked`, "Verify and elevate", "warn-panel")
	mustNotContain(t, page, `value="staging"`) // not selected by break_glass.databases
	form := url.Values{"csrf": {csrf}, "db": {"prod"}, "duration": {"30m"}, "reason": {"INC-123 fixing orders"}}
	resp, _ = do(t, c, "POST", e.url("/breakglass"), form)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/stepup?next=") {
		t.Fatalf("elevate without step-up: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	e.stepUp(c, csrf)
	// Hidden fields are not trusted: staging is not eligible.
	bad := url.Values{"csrf": {csrf}, "db": {"staging"}, "duration": {"30m"}, "reason": {"INC-123"}}
	if resp, _ := do(t, c, "POST", e.url("/breakglass"), bad); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("elevate on staging: %d", resp.StatusCode)
	}
	long := url.Values{"csrf": {csrf}, "db": {"prod"}, "duration": {"2h"}, "reason": {"INC-123"}}
	if resp, _ := do(t, c, "POST", e.url("/breakglass"), long); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("elevate too long: %d", resp.StatusCode)
	}
	resp, _ = do(t, c, "POST", e.url("/breakglass"), form)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/breakglass?granted=1" {
		t.Fatalf("elevate: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, page = do(t, c, "GET", e.url("/breakglass?granted=1"), nil)
	mustContain(t, page, "Elevated.", "Active elevations", "INC-123 fixing orders")
	_, page = do(t, c, "GET", e.url("/account"), nil)
	mustContain(t, page, "Elevated until", `href="/breakglass"`)
}

func TestPasskeyCmd(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/dbgateway.yaml"
	yaml := "server: { public_url: \"https://dbgw.example.com\" }\nauth: { passkeys: true }\nstore: { path: \"" + dir + "/dbgw.db\" }\n"
	if err := writeFile(cfgPath, yaml); err != nil {
		t.Fatal(err)
	}
	cmd := PasskeyCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"enroll", "--config", cfgPath, "--email", "Taro@Example.com"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	link := strings.TrimSpace(out.String())
	const prefix = "https://dbgw.example.com/passkeys/enroll/dbgw_pe_"
	if !strings.HasPrefix(link, prefix) || !strings.Contains(errOut.String(), "taro@example.com") && !strings.Contains(errOut.String(), "Taro@Example.com") {
		t.Fatalf("output %q / %q", link, errOut.String())
	}
	st, err := store.OpenSQLite(context.Background(), dir+"/dbgw.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	token := strings.TrimPrefix(link, "https://dbgw.example.com/passkeys/enroll/")
	en, err := st.GetPasskeyEnrollment(context.Background(), store.HashSecret(token), time.Now())
	if err != nil || en.Email != "taro@example.com" || en.ExpiresAt.Sub(time.Now()) < 23*time.Hour {
		t.Fatalf("enrollment: %+v %v", en, err)
	}
	// auth.passkeys is required.
	if err := writeFile(cfgPath, "auth: { dev_login: true }\nstore: { path: \""+dir+"/dbgw.db\" }\n"); err != nil {
		t.Fatal(err)
	}
	cmd = PasskeyCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"enroll", "--config", cfgPath, "--email", "taro@example.com"})
	if err := cmd.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "auth.passkeys") {
		t.Fatalf("without auth.passkeys: %v", err)
	}
}

// Opening the console lists the schema without writing an audit entry;
// a search typed into the box is audited.
func TestConsoleSchemaListIsNotAudited(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.login("taro@example.com")
	searches := func() int {
		page, err := audit.Search(e.cfg.Audit.Dir, audit.Filter{Event: "search", Limit: audit.MaxSearchLimit})
		if err != nil {
			t.Fatal(err)
		}
		return len(page.Entries)
	}
	for range 3 {
		if resp, page := do(t, c, "GET", e.url("/console?db=prod"), nil); resp.StatusCode != http.StatusOK || !strings.Contains(page, "users") {
			t.Fatalf("console: %d", resp.StatusCode)
		}
	}
	if n := searches(); n != 0 {
		t.Fatalf("opening the console wrote %d search entries", n)
	}
	if resp, _ := do(t, c, "GET", e.url("/console?db=prod&q=users"), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("console search: %d", resp.StatusCode)
	}
	if n := searches(); n != 1 {
		t.Fatalf("a typed search wrote %d entries, want 1", n)
	}
}

// The SQL editor keeps each person's history, runs only the selection,
// saves queries per person and exports masked reads.
func TestConsoleHistorySavedExport(t *testing.T) {
	e := newEnv(t, nil)
	c, csrf := e.login("taro@example.com")
	post := func(form url.Values) (*http.Response, string) {
		form.Set("csrf", csrf)
		if form.Get("db") == "" {
			form.Set("db", "prod")
		}
		return do(t, c, "POST", e.url("/console"), form)
	}

	// The page loads the editor with a style nonce in its CSP.
	resp, page := do(t, c, "GET", e.url("/console?db=prod"), nil)
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'self' 'nonce-") || !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("CSP: %q", csp)
	}
	mustContain(t, page, `name="dbgw-style-nonce"`, `src="/static/editor.js?v=`, `id="console-schema"`)

	// Run only the selected statement.
	_, page = post(url.Values{"sql": {"SELECT 1;\nSELECT id, email FROM users"}, "run_sql": {"SELECT id, email FROM users"},
		"reason": {"ticket #1234 investigation"}, "action": {"run"}})
	mustContain(t, page, "1 rows")
	if execs := e.fa.Execs(); execs[len(execs)-1].SQL != "SELECT id, email FROM users" {
		t.Fatalf("ran %q", execs[len(execs)-1].SQL)
	}
	hist, err := e.st.ListConsoleHistory(context.Background(), "taro@example.com", 10, time.Now())
	if err != nil || len(hist) != 1 || hist[0].SQL != "SELECT id, email FROM users" || hist[0].Status != "ok" || *hist[0].RowCount != 1 {
		t.Fatalf("history: %v %+v", err, hist)
	}
	_, page = do(t, c, "GET", e.url("/console?db=prod&panel=history"), nil)
	mustContain(t, page, `href="/console?history=`+hist[0].ID+`"`, "ticket #1234 investigation")
	_, page = do(t, c, "GET", e.url("/console?history="+hist[0].ID), nil)
	mustContain(t, page, `data-prefill="history"`, ">SELECT id, email FROM users</textarea>", `value="ticket #1234 investigation"`)
	// Another person cannot open it.
	c2, csrf2 := e.login("hanako@example.com")
	_, page = do(t, c2, "GET", e.url("/console?history="+hist[0].ID), nil)
	mustNotContain(t, page, "SELECT id, email FROM users", `data-prefill=`)

	// Save, list, open and delete.
	_, page = post(url.Values{"sql": {"SELECT id FROM users"}, "save_name": {"my users"}, "action": {"save"}})
	mustContain(t, page, "Query saved.", "my users")
	saved, _ := e.st.ListSavedQueries(context.Background(), "taro@example.com")
	if len(saved) != 1 || saved[0].SQL != "SELECT id FROM users" || saved[0].Database != "prod" {
		t.Fatalf("saved: %+v", saved)
	}
	_, page = do(t, c, "GET", e.url("/console?saved="+saved[0].ID), nil)
	mustContain(t, page, `data-prefill="saved"`, `data-prefill-name="my users"`)
	_, page = post(url.Values{"sql": {"SELECT 1"}, "save_name": {""}, "action": {"save"}})
	mustContain(t, page, "Enter a name")
	do(t, c2, "POST", e.url("/console/saved/"+saved[0].ID+"/delete"), url.Values{"csrf": {csrf2}})
	if saved, _ := e.st.ListSavedQueries(context.Background(), "taro@example.com"); len(saved) != 1 {
		t.Fatal("another person must not delete the query")
	}
	resp, _ = do(t, c, "POST", e.url("/console/saved/"+saved[0].ID+"/delete"), url.Values{"csrf": {csrf}, "db": {"prod"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if saved, _ := e.st.ListSavedQueries(context.Background(), "taro@example.com"); len(saved) != 0 {
		t.Fatalf("not deleted: %+v", saved)
	}

	// Export: masked CSV, audited; writes are refused.
	resp, body := post(url.Values{"sql": {"SELECT id, email FROM users"}, "reason": {"ticket #1234 export"}, "format": {"csv"}, "action": {"export"}})
	if !strings.HasPrefix(resp.Header.Get("Content-Disposition"), `attachment; filename="dbgw-prod-`) || resp.Header.Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatalf("export headers: %v", resp.Header)
	}
	if !strings.Contains(body, "id,email\r\n1,") || strings.Contains(body, "user1@example.com") {
		t.Fatalf("export body: %q", body)
	}
	_, page = post(url.Values{"sql": {update}, "reason": {"ticket #1234 export"}, "format": {"csv"}, "action": {"export"}})
	mustContain(t, page, "Denied")
	exports, err := audit.Search(e.cfg.Audit.Dir, audit.Filter{Event: "export", Limit: audit.MaxSearchLimit})
	if err != nil || len(exports.Entries) != 2 {
		t.Fatalf("export audit: %v %d", err, len(exports.Entries))
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{"=SUM(A1)": "'=SUM(A1)", "+1": "'+1", "-1": "'-1", "@x": "'@x", "a=b": "a=b", "": ""} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApprovalShowsBackupAndRestore(t *testing.T) {
	e := newEnv(t, nil)
	e.fa.Set(func(a *gatewaytest.Adapter) {
		a.Result.Backup = &analysis.BackupResult{Schema: "dbgw_backup", Table: "req_x", Source: "public.users", Rows: 1,
			RestoreSQL: `UPDATE "public"."users" AS t SET "plan" = b."plan" FROM "dbgw_backup"."req_x" AS b WHERE t."id" = b."id"`}
	})
	id := e.submit(update, agentReason)
	c, csrf := e.login("hanako@example.com")
	do(t, c, "POST", e.url("/stepup/dev"), url.Values{"csrf": {csrf}, "next": {"/approvals/" + id}})
	if resp, _ := do(t, c, "POST", e.url("/approvals/"+id+"/approve"), url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("approve: %d", resp.StatusCode)
	}
	e.svc.Wait()
	_, page := do(t, c, "GET", e.url("/approvals/"+id), nil)
	mustContain(t, page, "Backup", "The 1 changed rows were saved to dbgw_backup.req_x", `href="/console?restore=`+id+`"`)

	// The requester opens the restore statement in the SQL editor.
	c2, _ := e.login("taro@example.com")
	_, page = do(t, c2, "GET", e.url("/console?restore="+id), nil)
	mustContain(t, page, `data-prefill="restore"`, "FROM &#34;dbgw_backup&#34;.&#34;req_x&#34; AS b", "Restore the rows changed by request "+id)
	// An unknown request opens an empty editor.
	_, page = do(t, c2, "GET", e.url("/console?restore=req_nope"), nil)
	mustNotContain(t, page, `data-prefill=`)
}
