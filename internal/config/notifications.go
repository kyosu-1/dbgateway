package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
)

// NotificationRoute sends the listed events, when the condition holds, to
// the targets in To. Every matching route is used (not first match).
//
//	notifications:
//	  - events: [approval_requested]
//	    to: { slack: "#db-approvals", mention: approvers }
//	  - events: [query_denied]
//	    when: database.labels.env == "prod"
//	    to: { slack: "#security-alerts", webhook_env: PAGERDUTY_WEBHOOK_URL }
type NotificationRoute struct {
	Events []string `yaml:"events"`
	// When is an optional CEL condition over `database` (name, labels) and
	// `event` (type, status, risk). A condition that fails to evaluate (for
	// example a missing label) does not match.
	When string             `yaml:"when"`
	To   NotificationTarget `yaml:"to"`
}

// NotificationTarget says where a route delivers.
type NotificationTarget struct {
	// Slack is a channel ("#name" or a channel ID such as C0123ABC) or
	// "requester" (a direct message to the requester's linked Slack user).
	Slack string `yaml:"slack"`
	// Mention "approvers" mentions the people who can act on the request
	// (by their linked Slack users) in the channel message.
	Mention string `yaml:"mention"`
	// WebhookEnv names the environment variable holding a webhook URL that
	// receives the event as JSON.
	WebhookEnv string `yaml:"webhook_env"`
}

// Notification target keywords.
const (
	SlackRequester   = "requester"
	MentionApprovers = "approvers"
)

// SlackSettings names the environment variables holding the Slack tokens.
// Slack is used in Socket Mode (an outbound WebSocket only).
type SlackSettings struct {
	// AppTokenEnv holds the app-level token (xapp-…, connections:write).
	// Default SLACK_APP_TOKEN.
	AppTokenEnv string `yaml:"app_token_env"`
	// BotTokenEnv holds the bot token (xoxb-…). Default SLACK_BOT_TOKEN.
	BotTokenEnv string `yaml:"bot_token_env"`
}

// AnomalySettings are the thresholds of anomaly_detected.
type AnomalySettings struct {
	// DenialsPer10m: more denials than this for one requester within ten
	// minutes is an anomaly. Default 10.
	DenialsPer10m int `yaml:"denials_per_10m"`
	// RowsPerHour: more rows returned to one requester within an hour than
	// this is an anomaly. Default 100000.
	RowsPerHour int64 `yaml:"rows_per_hour"`
}

// NotificationSettings are the top-level settings that accompany
// `notifications`. They are inlined into Config.
type NotificationSettings struct {
	Slack   *SlackSettings  `yaml:"slack"`
	Anomaly AnomalySettings `yaml:"anomaly"`
	// NotificationsLanguage is the language of notification messages:
	// "en" (default) or "ja".
	NotificationsLanguage string `yaml:"notifications_language"`
	// NotificationsWebhookSecretEnv names the environment variable holding
	// the HMAC-SHA256 key that signs webhook bodies (X-Dbgw-Signature).
	NotificationsWebhookSecretEnv string `yaml:"notifications_webhook_secret_env"`
}

// Defaults of the notification settings.
const (
	DefaultSlackAppTokenEnv = "SLACK_APP_TOKEN"
	DefaultSlackBotTokenEnv = "SLACK_BOT_TOKEN"
	DefaultDenialsPer10m    = 10
	DefaultRowsPerHour      = 100000
)

// NotificationEvents are the event names a route may subscribe to.
var NotificationEvents = []string{
	"approval_requested", "approval_decided", "execution_finished", "query_denied",
	"break_glass_used", "anomaly_detected", "config_changed",
}

// NotifyDatabase is the `database` variable of a route condition.
type NotifyDatabase struct {
	Name   string            `cel:"name"`
	Labels map[string]string `cel:"labels"`
}

// NotifyEvent is the `event` variable of a route condition.
type NotifyEvent struct {
	Type   string `cel:"type"`
	Status string `cel:"status"`
	Risk   string `cel:"risk"`
}

// NotificationCELEnv is the CEL environment of route conditions.
func NotificationCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		ext.NativeTypes(ext.ParseStructTags(true), reflect.TypeFor[NotifyDatabase](), reflect.TypeFor[NotifyEvent]()),
		ext.Strings(),
		cel.Variable("database", cel.ObjectType("config.NotifyDatabase")),
		cel.Variable("event", cel.ObjectType("config.NotifyEvent")),
	)
}

// CompileNotificationWhen compiles a route condition, which must be a
// boolean expression.
func CompileNotificationWhen(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return nil, errors.New("must be a boolean expression")
	}
	return env.Program(ast)
}

// NotificationsEnabled reports whether any notification route is
// configured.
func (c *Config) NotificationsEnabled() bool { return len(c.Notifications) > 0 }

// SlackEnabled reports whether Slack is configured (a slack section or a
// route with a Slack target).
func (c *Config) SlackEnabled() bool {
	if !c.NotificationsEnabled() {
		return false
	}
	if c.Slack != nil {
		return true
	}
	return slices.ContainsFunc(c.Notifications, func(r NotificationRoute) bool { return r.To.Slack != "" })
}

var (
	slackChannelID = regexp.MustCompile(`^[CG][A-Z0-9]{2,}$`)
	slackChannel   = regexp.MustCompile(`^#[^\s#,<>@]{1,80}$`)
	envName        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// validateNotifications fills the defaults of the notification settings
// and validates the routes.
func (c *Config) validateNotifications(add func(string, ...any)) {
	if c.Anomaly.DenialsPer10m == 0 {
		c.Anomaly.DenialsPer10m = DefaultDenialsPer10m
	}
	if c.Anomaly.RowsPerHour == 0 {
		c.Anomaly.RowsPerHour = DefaultRowsPerHour
	}
	if c.Anomaly.DenialsPer10m < 0 || c.Anomaly.RowsPerHour < 0 {
		add("anomaly: thresholds must be positive")
	}
	switch c.NotificationsLanguage {
	case "":
		c.NotificationsLanguage = "en"
	case "ja", "en":
	default:
		add("notifications_language: must be \"ja\" or \"en\"")
	}
	if c.SlackEnabled() {
		if c.Slack == nil {
			c.Slack = &SlackSettings{}
		}
		if c.Slack.AppTokenEnv == "" {
			c.Slack.AppTokenEnv = DefaultSlackAppTokenEnv
		}
		if c.Slack.BotTokenEnv == "" {
			c.Slack.BotTokenEnv = DefaultSlackBotTokenEnv
		}
		for _, e := range []struct{ field, name string }{
			{"slack.app_token_env", c.Slack.AppTokenEnv}, {"slack.bot_token_env", c.Slack.BotTokenEnv},
		} {
			switch {
			case !envName.MatchString(e.name):
				add("%s: %q is not an environment variable name", e.field, e.name)
			case os.Getenv(e.name) == "":
				c.warn("%s: %s is not set; Slack notifications are disabled", e.field, e.name)
			}
		}
	}
	if s := c.NotificationsWebhookSecretEnv; s != "" {
		if !envName.MatchString(s) {
			add("notifications_webhook_secret_env: %q is not an environment variable name", s)
		} else if os.Getenv(s) == "" {
			c.warn("notifications_webhook_secret_env: %s is not set; webhook bodies are not signed", s)
		}
	}
	if len(c.Notifications) == 0 {
		return
	}
	env, err := NotificationCELEnv()
	if err != nil {
		add("notifications: %v", err)
		return
	}
	for i, r := range c.Notifications {
		p := fmt.Sprintf("notifications[%d]", i)
		if len(r.Events) == 0 {
			add("%s.events: at least one event is required", p)
		}
		for _, e := range r.Events {
			if !slices.Contains(NotificationEvents, e) {
				add("%s.events: unknown event %q (known: %v)", p, e, NotificationEvents)
			}
		}
		if r.When != "" {
			if _, err := CompileNotificationWhen(env, r.When); err != nil {
				add("%s.when: %v", p, err)
			}
		}
		t := r.To
		if t.Slack == "" && t.WebhookEnv == "" {
			add("%s.to: set slack and/or webhook_env", p)
		}
		if t.Slack != "" && t.Slack != SlackRequester && !slackChannel.MatchString(t.Slack) && !slackChannelID.MatchString(t.Slack) {
			add("%s.to.slack: must be \"#channel\", a channel ID or %q", p, SlackRequester)
		}
		switch t.Mention {
		case "":
		case MentionApprovers:
			if t.Slack == "" || t.Slack == SlackRequester {
				add("%s.to.mention: requires a Slack channel", p)
			}
		default:
			add("%s.to.mention: must be %q", p, MentionApprovers)
		}
		if t.WebhookEnv != "" {
			if !envName.MatchString(t.WebhookEnv) {
				add("%s.to.webhook_env: %q is not an environment variable name", p, t.WebhookEnv)
			} else if os.Getenv(t.WebhookEnv) == "" {
				c.warn("%s.to.webhook_env: %s is not set; this webhook is skipped", p, t.WebhookEnv)
			}
		}
	}
}
