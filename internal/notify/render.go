package notify

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/slack-go/slack"

	"github.com/kyosu-1/dbgateway/internal/events"
)

// Block Kit identifiers.
const (
	ActionReject = "dbgw_reject"
	ActionOpen   = "dbgw_open"
	blockActions = "dbgw_actions"
	blockStatus  = "dbgw_status"
)

// Slack limits (section text 3000, header 150, field 2000 characters).
const (
	maxSQL    = 2500
	maxReason = 2000
	maxField  = 1900
	maxHeader = 150
)

// escape makes text inert in Slack mrkdwn: with &, < and > escaped no
// link, user/channel mention or @here/@channel can be formed. Text
// objects are also sent with verbatim=true, which disables Slack's
// automatic linking of URLs and names.
func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func mrkdwn(s string) *slack.TextBlockObject {
	return slack.NewTextBlockObject(slack.MarkdownType, s, false, true)
}

func plain(s string) *slack.TextBlockObject {
	return slack.NewTextBlockObject(slack.PlainTextType, s, false, false)
}

// field renders "*label*\nvalue" with the value escaped.
func field(label, value string) *slack.TextBlockObject {
	return mrkdwn("*" + label + "*\n" + escape(truncate(value, maxField)))
}

// codeBlock renders SQL in a code block. Triple backticks inside would end
// the block early, so they are broken up.
func codeBlock(sql string) string {
	sql = strings.ReplaceAll(truncate(sql, maxSQL), "```", "`​``")
	return "```" + escape(sql) + "```"
}

func formatRows(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) }

// safeURL reports whether u can be used for a URL button.
func safeURL(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "https" || p.Scheme == "http") && p.Host != "" && len(u) <= 3000
}

// renderOpts tunes a message.
type renderOpts struct {
	// mentions is the pre-rendered (safe) mention line, or "".
	mentions string
	// reject adds the reject button (approval_requested in a channel).
	reject bool
}

// blocks renders an event as a top-level message.
func (m msgs) blocks(e events.Event, o renderOpts) []slack.Block {
	head := m.title(e.Type)
	if e.Database != "" {
		head += " · " + e.Database
	}
	out := []slack.Block{slack.NewHeaderBlock(plain(truncate(head, maxHeader)))}

	var fields []*slack.TextBlockObject
	add := func(label, value string) {
		if value != "" && len(fields) < 10 {
			fields = append(fields, field(label, value))
		}
	}
	add(m.t("field.requester"), m.requester(e.Principal))
	add(m.t("field.database"), e.Database)
	if r := e.Detail["risk"]; r != "" {
		add(m.t("field.risk"), m.risk(r))
	}
	if e.EstimateRows != nil {
		add(m.t("field.estimate"), formatRows(*e.EstimateRows))
	}
	add(m.t("field.tables"), strings.Join(e.Tables, ", "))
	add(m.t("field.rule"), e.Detail["rule"])
	add(m.t("field.stage"), e.Detail["stage"])
	if e.Type == events.ExecutionFinished {
		add(m.t("field.rows_affected"), e.Detail["rows_affected"])
	}
	if e.Actor != "" && e.Type != events.ApprovalRequested {
		add(m.t("field.actor"), e.Actor)
	}
	if e.Type == events.BreakGlassUsed {
		add(m.t("field.databases"), e.Detail["databases"])
		add(m.t("field.expires_at"), e.Detail["expires_at"])
	}
	if e.Type == events.AnomalyDetected {
		add(m.t("field.anomaly"), m.anomaly(e))
	}
	if e.Type == events.ConfigChanged {
		add(m.t("field.version"), m.t("config.changed", e.Detail["previous_version"], e.Detail["version"]))
	}
	if len(fields) > 0 {
		out = append(out, slack.NewSectionBlock(nil, fields, nil))
	}
	if e.SQL != "" {
		out = append(out, slack.NewSectionBlock(mrkdwn("*"+m.t("field.sql")+"*\n"+codeBlock(e.SQL)), nil, nil))
	}
	if e.Reason != "" {
		// plain_text: never parsed for links, mentions or formatting.
		out = append(out,
			slack.NewContextBlock("", mrkdwn("*"+m.t("field.reason")+"*")),
			slack.NewSectionBlock(plain(truncate(e.Reason, maxReason)), nil, nil))
	}
	if e.Type == events.ExecutionFinished && e.Status == "failed" {
		out = append(out, slack.NewSectionBlock(plain(m.t("exec.failed")), nil, nil))
	}
	if o.mentions != "" {
		out = append(out, slack.NewSectionBlock(mrkdwn("*"+m.t("field.approvers")+"*: "+o.mentions), nil, nil))
	}
	if e.Status != "" {
		out = append(out, slack.NewContextBlock(blockStatus, mrkdwn("*"+m.t("field.status")+"*: "+escape(m.status(e)))))
	}
	var buttons []slack.BlockElement
	if e.URL != "" && safeURL(e.URL) {
		buttons = append(buttons, slack.NewButtonBlockElement(ActionOpen, e.RequestID, plain(m.t("button.open"))).WithURL(e.URL))
	}
	if o.reject && e.RequestID != "" {
		confirm := slack.NewConfirmationBlockObject(plain(m.t("confirm.title")), plain(m.t("confirm.text")),
			plain(m.t("confirm.yes")), plain(m.t("confirm.no")))
		buttons = append(buttons, slack.NewButtonBlockElement(ActionReject, e.RequestID, plain(m.t("button.reject"))).
			WithStyle(slack.StyleDanger).WithConfirm(confirm))
	}
	if len(buttons) > 0 {
		out = append(out, slack.NewActionBlock(blockActions, buttons...))
	}
	out = append(out, slack.NewContextBlock("", mrkdwn(escape(m.footer(e)))))
	return out
}

// footer is the request ID and time.
func (m msgs) footer(e events.Event) string {
	var parts []string
	if e.RequestID != "" {
		parts = append(parts, e.RequestID)
	}
	if !e.Time.IsZero() {
		parts = append(parts, e.Time.UTC().Format(time.RFC3339))
	}
	return strings.Join(parts, " · ")
}

// replyBlocks renders a follow-up event (decision, execution) as a reply
// in the thread of the approval request message.
func (m msgs) replyBlocks(e events.Event, mentions string) []slack.Block {
	text := "*" + m.title(e.Type) + "*: " + escape(m.status(e))
	if e.Type == events.ExecutionFinished && e.Detail["rows_affected"] != "" {
		text += "\n" + m.t("field.rows_affected") + ": " + escape(e.Detail["rows_affected"])
	}
	out := []slack.Block{slack.NewSectionBlock(mrkdwn(text), nil, nil)}
	if e.Type == events.ExecutionFinished && e.Status == "failed" {
		out = append(out, slack.NewSectionBlock(plain(m.t("exec.failed")), nil, nil))
	}
	if mentions != "" {
		out = append(out, slack.NewSectionBlock(mrkdwn("*"+m.t("field.approvers")+"*: "+mentions), nil, nil))
	}
	return out
}
