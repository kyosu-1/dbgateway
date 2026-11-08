package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// SlackCommand is the slash command of the Slack app.
const SlackCommand = "/dbgw"

// RejectComment is the comment recorded for rejections from Slack.
const RejectComment = "Slackから却下"

// Run serves Slack interactions (the reject button and /dbgw) over Socket
// Mode until ctx is cancelled, reconnecting with backoff. It returns nil
// immediately when Slack is disabled or a token is missing. Only an
// outbound WebSocket is used; nothing listens for Slack.
func (d *Dispatcher) Run(ctx context.Context) error {
	if d.slack == nil {
		return nil
	}
	appToken := d.getenv(d.cfg.Slack.AppTokenEnv)
	if appToken == "" {
		d.logger.Warn("notify: Slack app token not set; the reject button and /dbgw are disabled", "env", d.cfg.Slack.AppTokenEnv)
		return nil
	}
	api := d.slackClient(d.getenv(d.cfg.Slack.BotTokenEnv), slack.OptionAppLevelToken(appToken))
	smc := socketmode.New(api)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-smc.Events:
				if !ok {
					return
				}
				d.handleSocketEvent(ctx, evt, func(req socketmode.Request, payload any) {
					if err := smc.AckCtx(ctx, req.EnvelopeID, payload); err != nil {
						d.logger.Warn("notify: Slack ack failed", "err", err)
					}
				})
			}
		}
	}()
	backoff := 5 * time.Second
	for {
		start := time.Now()
		err := smc.RunContext(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(start) > 5*time.Minute {
			backoff = 5 * time.Second
		}
		d.logger.Warn("notify: Slack Socket Mode disconnected; reconnecting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 2*time.Minute)
	}
}

// handleSocketEvent handles one Socket Mode event. ack acknowledges the
// envelope (with an optional response payload). Interactions are acked
// first and handled asynchronously; slash commands are answered in the
// ack (an ephemeral reply).
func (d *Dispatcher) handleSocketEvent(ctx context.Context, evt socketmode.Event, ack func(socketmode.Request, any)) {
	switch evt.Type {
	case socketmode.EventTypeInteractive:
		cb, ok := evt.Data.(slack.InteractionCallback)
		if !ok || evt.Request == nil {
			return
		}
		ack(*evt.Request, nil)
		go func() {
			hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			d.HandleInteraction(hctx, cb)
		}()
	case socketmode.EventTypeSlashCommand:
		cmd, ok := evt.Data.(slack.SlashCommand)
		if !ok || evt.Request == nil {
			return
		}
		hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		reply := d.HandleSlashCommand(hctx, cmd)
		cancel()
		ack(*evt.Request, map[string]any{"response_type": "ephemeral", "text": reply})
	case socketmode.EventTypeEventsAPI:
		if evt.Request != nil {
			ack(*evt.Request, nil)
		}
	case socketmode.EventTypeConnected:
		d.logger.Info("notify: Slack Socket Mode connected")
	case socketmode.EventTypeInvalidAuth:
		d.logger.Error("notify: Slack rejected the app token")
	}
}

// HandleInteraction handles a block action. Only the reject button does
// something: the clicking Slack user must be linked to a dbgateway user
// who may reject the request; the outcome is told ephemerally, and the
// message itself is updated through the approval_decided event.
func (d *Dispatcher) HandleInteraction(ctx context.Context, cb slack.InteractionCallback) {
	if cb.Type != slack.InteractionTypeBlockActions || d.slack == nil {
		return
	}
	var requestID string
	for _, a := range cb.ActionCallback.BlockActions {
		if a.ActionID == ActionReject {
			requestID = a.Value
		}
	}
	if requestID == "" {
		return // e.g. the URL button
	}
	reply := d.reject(ctx, cb.User.ID, requestID)
	channel := cb.Channel.ID
	if channel == "" {
		channel = cb.Container.ChannelID
	}
	if channel == "" {
		return
	}
	_, err := d.slack.api.PostEphemeralContext(ctx, channel, cb.User.ID, slack.MsgOptionText(reply, false))
	if err != nil {
		d.logger.Warn("notify: Slack ephemeral reply failed", "err", err)
	}
}

// reject rejects requestID on behalf of the dbgateway user linked to
// slackUser and returns the reply to show.
func (d *Dispatcher) reject(ctx context.Context, slackUser, requestID string) string {
	rp := d.approvals.Load()
	if rp == nil || *rp == nil {
		return d.m.t("reply.unavailable")
	}
	if d.linker == nil {
		return d.m.t("reply.not_linked")
	}
	email, ok, err := d.linker.LinkedEmail(ctx, slackUser)
	if err != nil {
		d.logger.Warn("notify: look up Slack link failed", "err", err)
		return d.m.t("reply.error")
	}
	if !ok {
		return d.m.t("reply.not_linked")
	}
	p, err := d.resolvePrincipal(ctx, email)
	if err != nil {
		d.logger.Warn("notify: resolve principal for Slack reject failed", "err", err)
		return d.m.t("reply.not_eligible")
	}
	_, err = (*rp).Reject(ctx, p, requestID, RejectComment)
	switch {
	case err == nil:
		return d.m.t("reply.rejected", requestID)
	case errors.Is(err, approval.ErrSelfApproval):
		return d.m.t("reply.self")
	case errors.Is(err, approval.ErrNotFound), errors.Is(err, approval.ErrNotEligible), errors.Is(err, approval.ErrAgent):
		// ErrNotFound is presented like "not eligible": the request may
		// exist but be invisible to this user.
		return d.m.t("reply.not_eligible")
	case errors.Is(err, approval.ErrNotPending), errors.Is(err, approval.ErrExpired), errors.Is(err, approval.ErrIntegrity):
		return d.m.t("reply.not_pending")
	case errors.Is(err, approval.ErrUnavailable):
		return d.m.t("reply.unavailable")
	default:
		d.logger.Warn("notify: Slack reject failed", "request_id", requestID, "err", err)
		return d.m.t("reply.error")
	}
}

// resolvePrincipal builds the human principal of email.
func (d *Dispatcher) resolvePrincipal(ctx context.Context, email string) (*identity.Principal, error) {
	if f := d.resolver.Load(); f != nil && *f != nil {
		p, err := (*f)(ctx, email)
		if err != nil {
			return nil, err
		}
		if p == nil || p.Kind != identity.KindHuman {
			return nil, errors.New("notify: resolver returned no human principal")
		}
		return p, nil
	}
	if d.st == nil {
		return nil, errors.New("notify: no store")
	}
	active, err := d.st.UserActive(ctx, email)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, fmt.Errorf("notify: user is deactivated")
	}
	var idpGroups []string
	u, err := d.st.GetUser(ctx, email)
	switch {
	case err == nil:
		idpGroups = u.IDPGroups
	case errors.Is(err, store.ErrNotFound):
	default:
		return nil, err
	}
	return &identity.Principal{Kind: identity.KindHuman, Human: email, Groups: d.rbac.ResolveGroups(email, idpGroups)}, nil
}

// HandleSlashCommand handles `/dbgw link <code>`, `/dbgw unlink` and
// `/dbgw whoami` and returns the (ephemeral) reply.
func (d *Dispatcher) HandleSlashCommand(ctx context.Context, cmd slack.SlashCommand) string {
	if cmd.Command != SlackCommand || d.linker == nil {
		return d.m.t("reply.help")
	}
	args := strings.Fields(cmd.Text)
	if len(args) == 0 {
		return d.m.t("reply.help")
	}
	switch strings.ToLower(args[0]) {
	case "link":
		if len(args) < 2 {
			return d.m.t("reply.help")
		}
		email, err := d.linker.Link(ctx, strings.Join(args[1:], ""), cmd.UserID)
		switch {
		case err == nil:
			return d.m.t("reply.linked", email)
		case errors.Is(err, ErrBadCode):
			return d.m.t("reply.bad_code")
		case errors.Is(err, ErrTooManyAttempts):
			return d.m.t("reply.too_many")
		default:
			d.logger.Warn("notify: Slack link failed", "err", err)
			return d.m.t("reply.error")
		}
	case "unlink":
		email, ok, err := d.linker.UnlinkSlackUser(ctx, cmd.UserID)
		switch {
		case err != nil:
			d.logger.Warn("notify: Slack unlink failed", "err", err)
			return d.m.t("reply.error")
		case !ok:
			return d.m.t("reply.nothing_linked")
		default:
			return d.m.t("reply.unlinked", email)
		}
	case "whoami":
		email, ok, err := d.linker.LinkedEmail(ctx, cmd.UserID)
		switch {
		case err != nil:
			d.logger.Warn("notify: look up Slack link failed", "err", err)
			return d.m.t("reply.error")
		case !ok:
			return d.m.t("reply.nothing_linked")
		default:
			return d.m.t("reply.whoami", email)
		}
	default:
		return d.m.t("reply.help")
	}
}
