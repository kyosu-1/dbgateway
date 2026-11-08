package notify

import (
	"slices"
	"testing"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
)

func TestRoutingAndWhen(t *testing.T) {
	cfg := testConfig(
		config.NotificationRoute{Events: []string{"approval_requested"}, To: config.NotificationTarget{Slack: "#db-approvals", Mention: "approvers"}},
		config.NotificationRoute{Events: []string{"approval_requested"}, When: `event.risk == "high"`,
			To: config.NotificationTarget{Slack: "#db-approvals", WebhookEnv: "HOOK"}},
		config.NotificationRoute{Events: []string{"query_denied"}, When: `database.labels.env == "prod"`,
			To: config.NotificationTarget{Slack: "#security-alerts", WebhookEnv: "HOOK"}},
		config.NotificationRoute{Events: []string{"query_denied", "break_glass_used"}, When: `"tier" in database.labels && database.name.startsWith("pay")`,
			To: config.NotificationTarget{Slack: config.SlackRequester, WebhookEnv: "HOOK"}},
		config.NotificationRoute{Events: []string{"config_changed"}, To: config.NotificationTarget{Slack: "C0ADMIN"}},
	)
	routes := compileRoutes(cfg, quietLogger())
	if len(routes) != 5 {
		t.Fatalf("routes = %d", len(routes))
	}
	ev := func(typ events.Type, db string, labels map[string]string, risk string) events.Event {
		return events.Event{Type: typ, Database: db, Labels: labels, Detail: map[string]string{"risk": risk}}
	}
	for _, tt := range []struct {
		name      string
		e         events.Event
		channels  []string
		mention   bool
		requester bool
		webhooks  []string
	}{
		{"approval low risk", ev(events.ApprovalRequested, "prod-main", nil, "low"), []string{"#db-approvals"}, true, false, nil},
		// Two routes to the same channel: one post, mention kept, webhook added.
		{"approval high risk", ev(events.ApprovalRequested, "prod-main", nil, "high"), []string{"#db-approvals"}, true, false, []string{"HOOK"}},
		{"denied prod", ev(events.QueryDenied, "prod-main", map[string]string{"env": "prod"}, ""), []string{"#security-alerts"}, false, false, []string{"HOOK"}},
		// Missing label: the condition fails to evaluate and does not match.
		{"denied no label", ev(events.QueryDenied, "dev", nil, ""), nil, false, false, nil},
		{"denied dev", ev(events.QueryDenied, "dev", map[string]string{"env": "dev"}, ""), nil, false, false, nil},
		{"denied pay", ev(events.QueryDenied, "payments", map[string]string{"tier": "1"}, ""), nil, false, true, []string{"HOOK"}},
		{"config", ev(events.ConfigChanged, "", nil, ""), []string{"C0ADMIN"}, false, false, nil},
		{"unrouted", ev(events.ExecutionFinished, "prod-main", nil, ""), nil, false, false, nil},
	} {
		got := resolve(routes, tt.e, quietLogger())
		if !slices.Equal(got.order, tt.channels) || got.requester != tt.requester || !slices.Equal(got.webhooks, tt.webhooks) {
			t.Errorf("%s: got channels=%v requester=%v webhooks=%v", tt.name, got.order, got.requester, got.webhooks)
		}
		if len(tt.channels) > 0 && got.channels[tt.channels[0]] != tt.mention {
			t.Errorf("%s: mention = %v", tt.name, got.channels[tt.channels[0]])
		}
	}
}

func TestCatalogParity(t *testing.T) {
	for lang, m := range catalog {
		for other, om := range catalog {
			for k := range m {
				if _, ok := om[k]; !ok {
					t.Errorf("key %q in %s but not in %s", k, lang, other)
				}
			}
		}
	}
	en := newMsgs("en")
	if got := en.requester(&events.Principal{Human: "taro@example.com", Agent: "claude-code"}); got != "claude-code on behalf of taro@example.com" {
		t.Errorf("en requester = %q", got)
	}
	if got := newMsgs("xx").t("button.reject"); got != "Reject" {
		t.Errorf("fallback = %q", got)
	}
	if got := newMsgs("ja").t("button.reject"); got != "却下" {
		t.Errorf("ja = %q", got)
	}
}
