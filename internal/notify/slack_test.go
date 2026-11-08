package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
)

const secretLiteral = "hanako-secret@example.org"

func approvalEvent(t events.Type, status string) events.Event {
	est := 42.0
	return events.Event{
		Type: t, Time: time.Date(2026, 11, 8, 1, 2, 3, 0, time.UTC), RequestID: "req_abc", Database: "prod-main",
		Labels:    map[string]string{"env": "prod"},
		Principal: &events.Principal{Kind: "agent", Human: "taro@example.com", Agent: "claude-code", ClientID: "c1"},
		SQL:       "UPDATE users SET email = $1 WHERE id = $2", Tables: []string{"public.users"}, EstimateRows: &est,
		Reason: "<!channel> 問い合わせ#12 <https://evil.example|click> & fix", Status: status,
		Approvers: []string{"hanako@example.com", "jiro@example.com"},
		URL:       "https://dbgw.example.com/approvals/req_abc",
		Detail:    map[string]string{"risk": "high", "approval_rule": "prod-writes", "max_affected_rows": "84"},
	}
}

func newSlackDispatcher(t *testing.T, fs *fakeSlack, cfg *config.Config, extraEnv map[string]string) (*Dispatcher, func()) {
	t.Helper()
	st := openStore(t)
	d := New(Options{Config: cfg, Store: st, Logger: quietLogger(), Getenv: testEnv(extraEnv), SlackAPIURL: fs.srv.URL,
		WebhookBackoff: time.Millisecond})
	t.Cleanup(d.Close)
	link(t, st, "hanako@example.com", "UHANAKO")
	link(t, st, "taro@example.com", "UTARO")
	return d, func() {
		t.Helper()
		if !d.flush(5 * time.Second) {
			t.Fatal("dispatcher did not flush")
		}
	}
}

func TestApprovalMessageThreadAndUpdate(t *testing.T) {
	fs := newFakeSlack(t)
	cfg := testConfig(
		config.NotificationRoute{Events: []string{"approval_requested"}, To: config.NotificationTarget{Slack: "#db-approvals", Mention: config.MentionApprovers}},
		config.NotificationRoute{Events: []string{"approval_decided", "execution_finished"}, To: config.NotificationTarget{Slack: config.SlackRequester}},
		// A route to the same channel must not post a second top-level message.
		config.NotificationRoute{Events: []string{"execution_finished"}, To: config.NotificationTarget{Slack: "#db-approvals"}},
	)
	d, flush := newSlackDispatcher(t, fs, cfg, nil)

	d.Publish(context.Background(), approvalEvent(events.ApprovalRequested, "pending"))
	flush()
	posts := fs.byMethod("chat.postMessage")
	if len(posts) != 1 {
		t.Fatalf("posts = %d, want 1", len(posts))
	}
	root := posts[0].Form
	if root.Get("channel") != "#db-approvals" || root.Get("thread_ts") != "" {
		t.Errorf("root channel = %q thread_ts = %q", root.Get("channel"), root.Get("thread_ts"))
	}
	blocks := unescapeJSON(root.Get("blocks"))
	for _, want := range []string{
		`"type":"header"`, "承認依頼 · prod-main",
		"claude-code · taro@example.com の代理",
		"```UPDATE users SET email = $1 WHERE id = $2```",
		"public.users", "42", "高",
		`"action_id":"dbgw_open"`, "承認画面を開く", `"url":"https://dbgw.example.com/approvals/req_abc"`,
		`"action_id":"dbgw_reject"`, `"value":"req_abc"`, "却下",
		"<@UHANAKO>", "jiro@example.com", // linked approvers are mentioned, others shown as text
		`"verbatim":true`,
	} {
		if !strings.Contains(blocks, want) {
			t.Errorf("root blocks missing %q\n%s", want, blocks)
		}
	}
	// The reason is plain text: no mention or link can be formed.
	if !strings.Contains(blocks, `{"type":"plain_text","text":"<!channel> 問い合わせ#12 <https://evil.example|click> & fix"`) {
		t.Errorf("reason is not plain text:\n%s", blocks)
	}
	if strings.Count(blocks, "<!channel>") != 1 || strings.Count(blocks, "evil.example") != 1 {
		t.Errorf("reason appears outside the plain text section")
	}
	if root.Get("unfurl_links") != "false" || root.Get("unfurl_media") != "false" {
		t.Errorf("unfurl not disabled: %v", root)
	}

	// A step approval: thread reply mentioning nobody (route has no mention for decided), root updated.
	dec := approvalEvent(events.ApprovalDecided, "rejected")
	dec.Actor, dec.Approvers = "hanako@example.com", nil
	d.Publish(context.Background(), dec)
	flush()
	posts = fs.byMethod("chat.postMessage")
	if len(posts) != 3 { // root, thread reply, DM to the requester
		t.Fatalf("posts = %d, want 3: %+v", len(posts), posts)
	}
	reply := posts[1].Form
	if reply.Get("channel") != "CDBAPPROVALS" || reply.Get("thread_ts") != "1700000000.000001" {
		t.Errorf("reply channel/thread = %q %q", reply.Get("channel"), reply.Get("thread_ts"))
	}
	if !strings.Contains(reply.Get("blocks"), "却下（hanako@example.com）") {
		t.Errorf("reply = %s", reply.Get("blocks"))
	}
	updates := fs.byMethod("chat.update")
	if len(updates) != 1 {
		t.Fatalf("updates = %d", len(updates))
	}
	up := updates[0].Form
	if up.Get("channel") != "CDBAPPROVALS" || up.Get("ts") != "1700000000.000001" {
		t.Errorf("update target = %q %q", up.Get("channel"), up.Get("ts"))
	}
	if strings.Contains(up.Get("blocks"), "dbgw_reject") || !strings.Contains(up.Get("blocks"), "dbgw_open") ||
		!strings.Contains(up.Get("blocks"), "却下（hanako@example.com）") {
		t.Errorf("updated root = %s", up.Get("blocks"))
	}
	if opens := fs.byMethod("conversations.open"); len(opens) != 1 || opens[0].Form.Get("users") != "UTARO" {
		t.Errorf("DM open = %+v", opens)
	}
	if posts[2].Form.Get("channel") != "DTARO" || strings.Contains(posts[2].Form.Get("blocks"), "dbgw_reject") {
		t.Errorf("DM = %+v", posts[2].Form)
	}

	// execution_finished: in the thread (not a new top-level post in
	// #db-approvals), with the error text withheld.
	fin := approvalEvent(events.ExecutionFinished, "failed")
	fin.Detail["error"] = `duplicate key value violates unique constraint "users_email_key": Key (email)=(` + secretLiteral + `) already exists`
	fin.Detail["rows_affected"] = "0"
	d.Publish(context.Background(), fin)
	flush()
	posts = fs.byMethod("chat.postMessage")
	if len(posts) != 5 { // + thread reply + DM
		t.Fatalf("posts = %d, want 5", len(posts))
	}
	if posts[3].Form.Get("thread_ts") != "1700000000.000001" {
		t.Errorf("execution result not in thread: %v", posts[3].Form)
	}
	for _, c := range fs.snapshot() {
		for k, vs := range c.Form {
			for _, v := range vs {
				if strings.Contains(v, secretLiteral) {
					t.Errorf("%s %s leaks the literal: %s", c.Method, k, v)
				}
			}
		}
	}
	if !strings.Contains(posts[3].Form.Get("blocks"), "実行に失敗しました") {
		t.Errorf("failure text missing: %s", posts[3].Form.Get("blocks"))
	}
	if s := d.Stats(); s.Failed != 0 || s.Published != 3 {
		t.Errorf("stats = %+v", s)
	}
}

func TestEscapeAndSafeRendering(t *testing.T) {
	if got := escape(`<@U1> & <!here> <https://x|y>`); got != "&lt;@U1&gt; &amp; &lt;!here&gt; &lt;https://x|y&gt;" {
		t.Errorf("escape = %q", got)
	}
	m := newMsgs("ja")
	e := approvalEvent(events.QueryDenied, "deny")
	e.Tables = []string{"<@UEVIL>"}
	e.Principal.Agent = "<!channel>"
	e.SQL = "SELECT 1 ``` <@U2>"
	e.URL = "javascript:alert(1)"
	e.Reason = "inert" // the reason is plain text (checked above)
	e.Detail["message"] = "syntax error at or near \"" + secretLiteral + "\""
	var all strings.Builder
	for _, b := range m.blocks(e, renderOpts{reject: true}) {
		all.WriteString(blockJSON(t, b))
	}
	s := all.String()
	for _, bad := range []string{"<@UEVIL>", "<!channel>", "<@U2>", "javascript:", secretLiteral, "``` <"} {
		if strings.Contains(s, bad) {
			t.Errorf("rendered blocks contain %q:\n%s", bad, s)
		}
	}
}

func TestSlackFailureIsCountedNotFatal(t *testing.T) {
	fs := newFakeSlack(t)
	fs.fail = true
	cfg := testConfig(config.NotificationRoute{Events: []string{"query_denied"}, To: config.NotificationTarget{Slack: "#sec"}})
	d, flush := newSlackDispatcher(t, fs, cfg, nil)
	d.Publish(context.Background(), approvalEvent(events.QueryDenied, "deny"))
	flush()
	if s := d.Stats(); s.Failed != 1 || s.Delivered != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestPublishNeverBlocks(t *testing.T) {
	fs := newFakeSlack(t)
	fs.block = make(chan struct{})
	cfg := testConfig(config.NotificationRoute{Events: []string{"query_denied"}, To: config.NotificationTarget{Slack: "#sec"}})
	d := New(Options{Config: cfg, Logger: quietLogger(), Getenv: testEnv(nil), SlackAPIURL: fs.srv.URL, QueueSize: 2})
	start := time.Now()
	for range 50 {
		d.Publish(context.Background(), approvalEvent(events.QueryDenied, "deny"))
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Publish blocked for %v", time.Since(start))
	}
	if s := d.Stats(); s.Dropped < 45 {
		t.Errorf("dropped = %d", s.Dropped)
	}
	close(fs.block)
	d.Close()
	d.Close() // idempotent
	d.Publish(context.Background(), approvalEvent(events.QueryDenied, "deny"))
}
