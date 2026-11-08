package notify

import (
	"log/slog"
	"slices"

	"cel.dev/cel-go/cel"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
)

type route struct {
	index  int
	events []events.Type
	when   cel.Program // nil: always
	to     config.NotificationTarget
}

// compileRoutes compiles the configured routes. The configuration was
// validated, so failures are unexpected; a route that fails to compile is
// skipped (and logged) rather than failing startup, since notifications
// are auxiliary.
func compileRoutes(cfg *config.Config, logger *slog.Logger) []route {
	env, err := config.NotificationCELEnv()
	if err != nil {
		logger.Error("notify: CEL environment", "err", err)
		return nil
	}
	var out []route
	for i, r := range cfg.Notifications {
		rt := route{index: i, to: r.To}
		for _, e := range r.Events {
			rt.events = append(rt.events, events.Type(e))
		}
		if r.When != "" {
			prg, err := config.CompileNotificationWhen(env, r.When)
			if err != nil {
				logger.Error("notify: route skipped", "route", i, "err", err)
				continue
			}
			rt.when = prg
		}
		out = append(out, rt)
	}
	return out
}

// match reports whether the route applies to e. A condition that fails to
// evaluate (e.g. a label the database does not have) does not match.
func (r route) match(e events.Event, logger *slog.Logger) bool {
	if !slices.Contains(r.events, e.Type) {
		return false
	}
	if r.when == nil {
		return true
	}
	labels := e.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	out, _, err := r.when.Eval(map[string]any{
		"database": config.NotifyDatabase{Name: e.Database, Labels: labels},
		"event":    config.NotifyEvent{Type: string(e.Type), Status: e.Status, Risk: e.Detail["risk"]},
	})
	if err != nil {
		logger.Debug("notify: route condition did not evaluate", "route", r.index, "event", e.Type, "err", err)
		return false
	}
	b, ok := out.Value().(bool)
	return ok && b
}

// targets are the resolved destinations of one event.
type targets struct {
	// channels maps a configured Slack channel to whether approvers are
	// mentioned there. order keeps the configuration order.
	channels map[string]bool
	order    []string
	// requester: DM the requester's linked Slack user.
	requester bool
	// webhooks are environment variable names, deduplicated.
	webhooks []string
}

func (t *targets) slack() bool { return len(t.order) > 0 || t.requester }

// resolve collects the destinations of every matching route.
func resolve(routes []route, e events.Event, logger *slog.Logger) targets {
	t := targets{channels: map[string]bool{}}
	for _, r := range routes {
		if !r.match(e, logger) {
			continue
		}
		switch s := r.to.Slack; {
		case s == config.SlackRequester:
			t.requester = true
		case s != "":
			mention, seen := t.channels[s]
			if !seen {
				t.order = append(t.order, s)
			}
			t.channels[s] = mention || r.to.Mention == config.MentionApprovers
		}
		if w := r.to.WebhookEnv; w != "" && !slices.Contains(t.webhooks, w) {
			t.webhooks = append(t.webhooks, w)
		}
	}
	return t
}
