package config

import (
	"strings"
	"testing"
)

func TestNotificationsConfig(t *testing.T) {
	const base = "auth: { dev_login: true }\n"
	t.Setenv("DBGW_TEST_HOOK", "https://hooks.example.com/x")
	c, err := Parse([]byte(base + `
notifications:
  - events: [approval_requested]
    to: { slack: "#db-approvals", mention: approvers }
  - events: [approval_decided, execution_finished]
    to: { slack: requester }
  - events: [query_denied]
    when: database.labels.env == "prod" && event.status == "deny"
    to: { slack: "#security-alerts", webhook_env: DBGW_TEST_HOOK }
anomaly: { denials_per_10m: 5 }
`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.NotificationsEnabled() || !c.SlackEnabled() {
		t.Fatal("notifications/slack not enabled")
	}
	if c.Slack.AppTokenEnv != DefaultSlackAppTokenEnv || c.Slack.BotTokenEnv != DefaultSlackBotTokenEnv {
		t.Errorf("slack defaults = %+v", c.Slack)
	}
	if c.Anomaly.DenialsPer10m != 5 || c.Anomaly.RowsPerHour != DefaultRowsPerHour {
		t.Errorf("anomaly = %+v", c.Anomaly)
	}
	if c.NotificationsLanguage != "ja" {
		t.Errorf("language = %q", c.NotificationsLanguage)
	}

	for _, tt := range []struct{ yaml, want string }{
		{"notifications: [{events: [nope], to: {slack: '#a'}}]", "unknown event"},
		{"notifications: [{events: [], to: {slack: '#a'}}]", "at least one event"},
		{"notifications: [{events: [query_denied], when: 'database.nope == 1', to: {slack: '#a'}}]", ".when"},
		{"notifications: [{events: [query_denied], when: 'database.name', to: {slack: '#a'}}]", "boolean"},
		{"notifications: [{events: [query_denied], to: {}}]", "set slack and/or webhook_env"},
		{"notifications: [{events: [query_denied], to: {slack: 'general'}}]", "to.slack"},
		{"notifications: [{events: [query_denied], to: {slack: requester, mention: approvers}}]", "requires a Slack channel"},
		{"notifications: [{events: [query_denied], to: {slack: '#a', mention: everyone}}]", "to.mention"},
		{"notifications: [{events: [query_denied], to: {webhook_env: 'not-an-env'}}]", "webhook_env"},
		{"notifications_language: fr", "notifications_language"},
		{"anomaly: { rows_per_hour: -1 }", "anomaly"},
		{"notifications: [{events: [query_denied], to: {slack: '#a'}}]\nslack: {bot_token_env: 'x y'}", "slack.bot_token_env"},
	} {
		if _, err := Parse([]byte(base + tt.yaml)); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.yaml, err, tt.want)
		}
	}

	// A channel ID and an unset webhook env (warning only).
	c, err = Parse([]byte(base + "notifications: [{events: [config_changed], to: {slack: C0123ABC, webhook_env: DBGW_TEST_UNSET_HOOK}}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(c.Warnings, "\n"), "DBGW_TEST_UNSET_HOOK is not set") {
		t.Errorf("warnings = %v", c.Warnings)
	}

	// No notifications: Slack is off even with a slack section.
	c, err = Parse([]byte(base + "slack: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.NotificationsEnabled() || c.SlackEnabled() {
		t.Error("enabled without routes")
	}
}
