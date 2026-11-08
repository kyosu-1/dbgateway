package notify

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// fakeRejecter records Reject calls.
type fakeRejecter struct {
	mu    sync.Mutex
	calls []rejectCall
	err   error
}

type rejectCall struct {
	p       identity.Principal
	id      string
	comment string
}

func (f *fakeRejecter) Reject(_ context.Context, p *identity.Principal, id, comment string) (*approval.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, rejectCall{*p, id, comment})
	if f.err != nil {
		return nil, f.err
	}
	return &approval.Request{ID: id, Status: approval.StatusRejected}, nil
}

func (f *fakeRejecter) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func rejectEvent(slackUser, requestID string) socketmode.Event {
	cb := slack.InteractionCallback{
		Type:    slack.InteractionTypeBlockActions,
		User:    slack.User{ID: slackUser},
		Channel: slack.Channel{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "CDBAPPROVALS"}}},
		ActionCallback: slack.ActionCallbacks{BlockActions: []*slack.BlockAction{
			{ActionID: ActionReject, BlockID: blockActions, Value: requestID},
		}},
	}
	return socketmode.Event{Type: socketmode.EventTypeInteractive, Data: cb, Request: &socketmode.Request{Type: "interactive", EnvelopeID: "env-" + slackUser}}
}

func TestRejectButton(t *testing.T) {
	fs := newFakeSlack(t)
	cfg := testConfig(config.NotificationRoute{Events: []string{"approval_requested"}, To: config.NotificationTarget{Slack: "#db-approvals"}})
	d, _ := newSlackDispatcher(t, fs, cfg, nil)
	st := d.st.(*store.SQLite)
	ctx := context.Background()
	if err := st.UpsertUser(ctx, &store.User{Email: "hanako@example.com", IDPGroups: []string{"idp-dba"}}); err != nil {
		t.Fatal(err)
	}
	rej := &fakeRejecter{}
	d.SetApprovals(rej)

	var acks []string
	var ackMu sync.Mutex
	ack := func(req socketmode.Request, payload any) {
		ackMu.Lock()
		defer ackMu.Unlock()
		if payload != nil {
			t.Errorf("interactive ack with payload %v", payload)
		}
		acks = append(acks, req.EnvelopeID)
	}
	ephemerals := func() []slackCall { return fs.byMethod("chat.postEphemeral") }

	// Linked approver: the request is rejected as that human, with groups
	// resolved from the stored IdP groups.
	d.handleSocketEvent(ctx, rejectEvent("UHANAKO", "req_abc"), ack)
	waitFor(t, "ephemeral reply", func() bool { return len(ephemerals()) == 1 })
	if rej.n() != 1 {
		t.Fatalf("reject calls = %d", rej.n())
	}
	c := rej.calls[0]
	if c.p.Kind != identity.KindHuman || c.p.Human != "hanako@example.com" || !slices.Contains(c.p.Groups, "dba") ||
		c.id != "req_abc" || c.comment != RejectComment {
		t.Errorf("reject call = %+v", c)
	}
	e := ephemerals()[0].Form
	if e.Get("user") != "UHANAKO" || e.Get("channel") != "CDBAPPROVALS" || !strings.Contains(e.Get("text"), "却下しました") {
		t.Errorf("ephemeral = %v", e)
	}

	// Already decided.
	rej.err = approval.ErrNotPending
	d.HandleInteraction(ctx, rejectEvent("UHANAKO", "req_abc").Data.(slack.InteractionCallback))
	if got := ephemerals()[1].Form.Get("text"); !strings.Contains(got, "すでに処理済み") {
		t.Errorf("not pending reply = %q", got)
	}
	// Not an approver (or invisible request).
	for _, err := range []error{approval.ErrNotEligible, approval.ErrNotFound} {
		rej.err = err
		d.HandleInteraction(ctx, rejectEvent("UHANAKO", "req_abc").Data.(slack.InteractionCallback))
		if got := ephemerals()[len(ephemerals())-1].Form.Get("text"); !strings.Contains(got, "権限がありません") {
			t.Errorf("%v reply = %q", err, got)
		}
	}
	rej.err = approval.ErrSelfApproval
	d.HandleInteraction(ctx, rejectEvent("UTARO", "req_abc").Data.(slack.InteractionCallback))
	if got := ephemerals()[len(ephemerals())-1].Form.Get("text"); !strings.Contains(got, "自分の申請") {
		t.Errorf("self reply = %q", got)
	}

	// Unlinked Slack user: nothing is rejected.
	before := rej.n()
	d.HandleInteraction(ctx, rejectEvent("USTRANGER", "req_abc").Data.(slack.InteractionCallback))
	if rej.n() != before {
		t.Error("unlinked user reached Reject")
	}
	if got := ephemerals()[len(ephemerals())-1].Form.Get("text"); !strings.Contains(got, "紐づいていません") {
		t.Errorf("unlinked reply = %q", got)
	}

	// Deactivated user (SCIM): refused before Reject.
	if err := st.CreateSCIMUser(ctx, &store.SCIMUser{ID: "s1", Email: "taro@example.com", UserName: "taro", Active: false}, time.Now()); err != nil {
		t.Fatal(err)
	}
	rej.err = nil
	before = rej.n()
	d.HandleInteraction(ctx, rejectEvent("UTARO", "req_abc").Data.(slack.InteractionCallback))
	if rej.n() != before {
		t.Error("deactivated user reached Reject")
	}
	if got := ephemerals()[len(ephemerals())-1].Form.Get("text"); !strings.Contains(got, "権限がありません") {
		t.Errorf("deactivated reply = %q", got)
	}

	// A custom resolver (e.g. the auth package's) replaces the default.
	d.SetPrincipalResolver(func(_ context.Context, email string) (*identity.Principal, error) {
		return &identity.Principal{Kind: identity.KindHuman, Human: email, Groups: []string{"from-resolver"}}, nil
	})
	d.HandleInteraction(ctx, rejectEvent("UHANAKO", "req_abc").Data.(slack.InteractionCallback))
	if rej.n() != before+1 || !slices.Equal(rej.calls[before].p.Groups, []string{"from-resolver"}) {
		t.Errorf("custom resolver not used: %+v", rej.calls)
	}
	d.SetPrincipalResolver(func(context.Context, string) (*identity.Principal, error) {
		return &identity.Principal{Kind: identity.KindAgent, Human: "x"}, nil
	})
	d.HandleInteraction(ctx, rejectEvent("UHANAKO", "req_abc").Data.(slack.InteractionCallback))
	if rej.n() != before+1 {
		t.Error("an agent principal reached Reject")
	}

	// The URL button only needs an ack.
	cb := rejectEvent("UHANAKO", "req_abc").Data.(slack.InteractionCallback)
	cb.ActionCallback.BlockActions[0].ActionID = ActionOpen
	n := len(ephemerals())
	d.HandleInteraction(ctx, cb)
	if len(ephemerals()) != n {
		t.Error("URL button produced a reply")
	}
	ackMu.Lock()
	defer ackMu.Unlock()
	if len(acks) != 1 || acks[0] != "env-UHANAKO" {
		t.Errorf("acks = %v", acks)
	}
}

func TestRejectButtonWithoutApprovals(t *testing.T) {
	fs := newFakeSlack(t)
	cfg := testConfig(config.NotificationRoute{Events: []string{"approval_requested"}, To: config.NotificationTarget{Slack: "#db-approvals"}})
	d, _ := newSlackDispatcher(t, fs, cfg, nil)
	d.HandleInteraction(context.Background(), rejectEvent("UHANAKO", "req_abc").Data.(slack.InteractionCallback))
	if got := fs.byMethod("chat.postEphemeral"); len(got) != 1 || !strings.Contains(got[0].Form.Get("text"), "有効になっていません") {
		t.Errorf("reply = %+v", got)
	}
}

func TestRunWithoutTokens(t *testing.T) {
	cfg := testConfig(config.NotificationRoute{Events: []string{"approval_requested"}, To: config.NotificationTarget{Slack: "#db-approvals"}})
	for name, env := range map[string]map[string]string{
		"no bot token": {"TEST_SLACK_BOT": ""},
		"no app token": {"TEST_SLACK_APP": ""},
	} {
		d := New(Options{Config: cfg, Logger: quietLogger(), Getenv: testEnv(env)})
		done := make(chan error, 1)
		go func() { done <- d.Run(context.Background()) }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s: Run = %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s: Run did not return", name)
		}
		d.Close()
	}
}

func TestSlashCommandsAndLinking(t *testing.T) {
	fs := newFakeSlack(t)
	cfg := testConfig(config.NotificationRoute{Events: []string{"approval_requested"}, To: config.NotificationTarget{Slack: "#db-approvals"}})
	now := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	clock := &now
	st := openStore(t)
	d := New(Options{Config: cfg, Store: st, Logger: quietLogger(), Getenv: testEnv(nil), SlackAPIURL: fs.srv.URL,
		Now: func() time.Time { return *clock }})
	t.Cleanup(d.Close)
	ctx := context.Background()
	l := d.Linker()
	cmd := func(user, text string) string {
		var reply any
		evt := socketmode.Event{Type: socketmode.EventTypeSlashCommand,
			Data:    slack.SlashCommand{Command: "/dbgw", Text: text, UserID: user},
			Request: &socketmode.Request{EnvelopeID: "e"}}
		d.handleSocketEvent(ctx, evt, func(_ socketmode.Request, p any) { reply = p })
		m, _ := reply.(map[string]any)
		if m["response_type"] != "ephemeral" {
			t.Errorf("response_type = %v", m["response_type"])
		}
		s, _ := m["text"].(string)
		return s
	}

	if _, ok := l.Linked("Taro@Example.com"); ok {
		t.Fatal("linked before linking")
	}
	code, exp, err := l.IssueCode("Taro@Example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(now.Add(10*time.Minute)) || len(code) != 9 || code[4] != '-' {
		t.Errorf("code = %q expires %v", code, exp)
	}
	if got := cmd("UTARO", "whoami"); !strings.Contains(got, "ありません") {
		t.Errorf("whoami before = %q", got)
	}
	// Codes are case- and separator-insensitive.
	if got := cmd("UTARO", "link "+strings.ToLower(strings.ReplaceAll(code, "-", " "))); !strings.Contains(got, "taro@example.com と紐づけました") {
		t.Fatalf("link = %q", got)
	}
	if u, ok := l.Linked("taro@example.com"); !ok || u != "UTARO" {
		t.Errorf("Linked = %q %v", u, ok)
	}
	if got := cmd("UTARO", "whoami"); !strings.Contains(got, "taro@example.com") {
		t.Errorf("whoami = %q", got)
	}
	// One-time.
	if got := cmd("UOTHER", "link "+code); !strings.Contains(got, "正しくないか") {
		t.Errorf("reused code = %q", got)
	}
	// Expiry.
	code2, _, _ := l.IssueCode("hanako@example.com")
	later := now.Add(11 * time.Minute)
	clock = &later
	if got := cmd("UHANAKO", "link "+code2); !strings.Contains(got, "期限が切れて") {
		t.Errorf("expired code = %q", got)
	}
	// Issuing a new code invalidates the previous one.
	code3, _, _ := l.IssueCode("hanako@example.com")
	code4, _, _ := l.IssueCode("hanako@example.com")
	if got := cmd("UHANAKO", "link "+code3); !strings.Contains(got, "正しくないか") {
		t.Errorf("superseded code = %q", got)
	}
	// Too many wrong codes lock the Slack user out for a while.
	for range 5 {
		cmd("UHANAKO", "link AAAA-AAAA")
	}
	if got := cmd("UHANAKO", "link "+code4); !strings.Contains(got, "試行回数") {
		t.Errorf("rate limit = %q", got)
	}
	evenLater := later.Add(11 * time.Minute)
	clock = &evenLater
	code5, _, _ := l.IssueCode("hanako@example.com")
	if got := cmd("UHANAKO", "link "+code5); !strings.Contains(got, "hanako@example.com と紐づけました") {
		t.Errorf("after lockout = %q", got)
	}

	if got := cmd("UTARO", "unlink"); !strings.Contains(got, "解除しました") {
		t.Errorf("unlink = %q", got)
	}
	if got := cmd("UTARO", "unlink"); !strings.Contains(got, "ありません") {
		t.Errorf("unlink twice = %q", got)
	}
	if err := l.Unlink("hanako@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Linked("hanako@example.com"); ok {
		t.Error("still linked after Unlink")
	}
	for _, text := range []string{"", "help", "link"} {
		if got := cmd("UTARO", text); !strings.Contains(got, "使い方") {
			t.Errorf("%q = %q", text, got)
		}
	}
	if len(fs.snapshot()) != 0 {
		t.Errorf("slash commands called the Web API: %+v", fs.snapshot())
	}
}
