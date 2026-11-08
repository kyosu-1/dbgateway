package notify

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/slack-go/slack"

	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// slackSink posts events to Slack with the bot token.
type slackSink struct {
	api    *slack.Client
	st     Store // nil: no threads, mentions or DMs
	m      msgs
	logger *slog.Logger
	now    func() time.Time
	stats  *stats
}

// isFollowUp reports whether t continues the thread of an approval
// request.
func isFollowUp(t events.Type) bool {
	return t == events.ApprovalDecided || t == events.ExecutionFinished
}

// deliver sends e to its Slack targets. Follow-up events of a request
// whose approval message was posted are replied in that thread (and the
// message's status is updated), whatever the routes say; a route to the
// same channel does not post again.
func (s *slackSink) deliver(ctx context.Context, e events.Event, t targets) {
	handled := map[string]bool{}
	if isFollowUp(e.Type) && e.RequestID != "" && s.st != nil {
		threads, err := s.st.ListSlackThreads(ctx, e.RequestID)
		if err != nil {
			s.fail("load threads", e, "", err)
		}
		for _, th := range threads {
			mention := t.channels[th.Target] || t.channels[th.Channel]
			s.reply(ctx, e, th, mention)
			s.updateRoot(ctx, e, th)
			handled[th.Target], handled[th.Channel] = true, true
		}
	}
	for _, ch := range t.order {
		if !handled[ch] {
			s.postChannel(ctx, e, ch, t.channels[ch])
		}
	}
	if t.requester {
		s.dmRequester(ctx, e)
	}
}

func (s *slackSink) postChannel(ctx context.Context, e events.Event, target string, mention bool) {
	o := renderOpts{reject: e.Type == events.ApprovalRequested && e.Status == "pending"}
	if mention {
		o.mentions = s.mentions(ctx, e.Approvers)
	}
	var channel, ts string
	err := s.call(ctx, func() (err error) {
		channel, ts, err = s.api.PostMessageContext(ctx, target, s.msgOptions(e, s.m.blocks(e, o))...)
		return err
	})
	if err != nil {
		s.fail("post message", e, target, err)
		return
	}
	s.stats.delivered.Add(1)
	if e.Type == events.ApprovalRequested && e.RequestID != "" && s.st != nil {
		raw, _ := json.Marshal(sanitize(e))
		th := &store.SlackThread{RequestID: e.RequestID, Channel: channel, Target: target, TS: ts, EventJSON: raw, CreatedAt: s.now()}
		if err := s.st.SaveSlackThread(ctx, th); err != nil {
			s.fail("save thread", e, target, err)
		}
	}
}

func (s *slackSink) reply(ctx context.Context, e events.Event, th *store.SlackThread, mention bool) {
	mentions := ""
	if mention && e.Status == "pending" {
		mentions = s.mentions(ctx, e.Approvers)
	}
	opts := append(s.msgOptions(e, s.m.replyBlocks(e, mentions)), slack.MsgOptionTS(th.TS))
	err := s.call(ctx, func() error {
		_, _, err := s.api.PostMessageContext(ctx, th.Channel, opts...)
		return err
	})
	if err != nil {
		s.fail("post thread reply", e, th.Target, err)
		return
	}
	s.stats.delivered.Add(1)
}

// updateRoot re-renders the approval request message with the new status;
// the reject button goes away once the request is no longer pending.
func (s *slackSink) updateRoot(ctx context.Context, e events.Event, th *store.SlackThread) {
	var base events.Event
	if err := json.Unmarshal(th.EventJSON, &base); err != nil {
		s.fail("decode thread event", e, th.Target, err)
		return
	}
	base.Status, base.Actor = e.Status, e.Actor
	if base.Detail == nil {
		base.Detail = map[string]string{}
	}
	base.Detail["step"] = e.Detail["step"]
	blocks := s.m.blocks(base, renderOpts{reject: base.Status == "pending"})
	err := s.call(ctx, func() error {
		_, _, _, err := s.api.UpdateMessageContext(ctx, th.Channel, th.TS,
			slack.MsgOptionBlocks(blocks...), slack.MsgOptionText(s.m.summary(base), false))
		return err
	})
	if err != nil {
		s.fail("update message", e, th.Target, err)
	}
}

func (s *slackSink) dmRequester(ctx context.Context, e events.Event) {
	if e.Principal == nil || e.Principal.Human == "" || s.st == nil {
		return
	}
	user, ok := s.slackUser(ctx, e.Principal.Human)
	if !ok {
		s.stats.skipped.Add(1)
		s.logger.Debug("notify: requester has no linked Slack user", "event", e.Type, "request_id", e.RequestID)
		return
	}
	err := s.call(ctx, func() error {
		ch, _, _, err := s.api.OpenConversationContext(ctx, &slack.OpenConversationParameters{Users: []string{user}})
		if err != nil {
			return err
		}
		_, _, err = s.api.PostMessageContext(ctx, ch.ID, s.msgOptions(e, s.m.blocks(e, renderOpts{}))...)
		return err
	})
	if err != nil {
		s.fail("direct message", e, "requester", err)
		return
	}
	s.stats.delivered.Add(1)
}

func (s *slackSink) msgOptions(e events.Event, blocks []slack.Block) []slack.MsgOption {
	return []slack.MsgOption{
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionText(s.m.summary(e), false), // fallback for notifications; escaped by slack-go
		slack.MsgOptionDisableLinkUnfurl(),
		slack.MsgOptionDisableMediaUnfurl(),
	}
}

// mentions renders approvers as Slack mentions when linked, otherwise as
// (escaped) e-mail addresses.
func (s *slackSink) mentions(ctx context.Context, approvers []string) string {
	parts := make([]string, 0, len(approvers))
	for _, a := range approvers {
		if u, ok := s.slackUser(ctx, a); ok && validSlackID(u) {
			parts = append(parts, "<@"+u+">")
		} else {
			parts = append(parts, escape(a))
		}
	}
	return strings.Join(parts, ", ")
}

func (s *slackSink) slackUser(ctx context.Context, email string) (string, bool) {
	if s.st == nil {
		return "", false
	}
	l, err := s.st.GetSlackLinkByEmail(ctx, strings.ToLower(email))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("notify: look up Slack link failed", "err", err)
		}
		return "", false
	}
	return l.SlackUser, true
}

// validSlackID reports whether id looks like a Slack user ID (so that it
// cannot inject markup into a mention).
func validSlackID(id string) bool {
	if id == "" || len(id) > 32 {
		return false
	}
	for _, r := range id {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// call runs a Slack API call, waiting out one rate limit (up to 30s).
func (s *slackSink) call(ctx context.Context, f func() error) error {
	err := f()
	var rl *slack.RateLimitedError
	if errors.As(err, &rl) && rl.RetryAfter <= 30*time.Second {
		select {
		case <-time.After(rl.RetryAfter):
		case <-ctx.Done():
			return err
		}
		err = f()
	}
	return err
}

// fail counts and logs a delivery failure. Only the event type, request
// ID, configured target and the error are logged (no message content).
func (s *slackSink) fail(op string, e events.Event, target string, err error) {
	s.stats.failed.Add(1)
	s.logger.Warn("notify: Slack "+op+" failed", "event", e.Type, "request_id", e.RequestID, "target", target, "err", err)
}
