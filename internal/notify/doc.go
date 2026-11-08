// Package notify delivers dbgateway events (internal/events) to Slack and
// generic webhooks, links Slack users to dbgateway users, detects
// anomalies and reports configuration changes.
//
// Notifications are auxiliary: the approval page and get_request are the
// source of truth. Publishing never blocks or fails the caller; failures
// are logged and counted (Dispatcher.Stats).
//
// # What is sent
//
// Only the normalized SQL (literals replaced by placeholders), table
// names, the planner estimate, the requester's reason (rendered inert:
// plain text, no links or mentions), the requester, the status, the
// approval page URL and a fixed set of Detail fields (risk, rule, stage,
// rows affected, ...). Never raw SQL, literals, query results, database
// error texts or parser messages.
//
// # Routing
//
// Every route of `notifications` whose events include the event type and
// whose `when` CEL condition (over `database` {name, labels} and `event`
// {type, status, risk}) holds contributes its targets: a Slack channel
// (optionally mentioning the approvers by their linked Slack users), a DM
// to the requester (`slack: requester`) and/or a webhook (`webhook_env`).
//
// An approval_requested message posted to a channel starts a thread
// (channel and ts are stored per request). approval_decided and
// execution_finished for that request are always replied in the thread,
// and the original message's status line is updated (its reject button is
// removed once the request is no longer pending).
//
// # Wiring
//
//	d := notify.New(notify.Options{Config: cfg, Store: sqliteStore, Logger: logger})
//	an := notify.NewAnomaly(d, notify.AnomalyOptions{Config: cfg})
//	// pass `an` as the events.Publisher of the gateway and approval service
//	d.SetApprovals(approvalService)             // enables the reject button
//	d.SetPrincipalResolver(resolver)            // optional; default: store user + RBAC groups
//	go d.Run(ctx)                               // Slack Socket Mode
//	defer d.Close()
//	if changed, prev, _ := notify.ConfigChanged(ctx, sqliteStore, cfg.Version); changed {
//		an.Publish(ctx, notify.ConfigChangedEvent(prev, cfg.Version))
//	}
//
// The gateway should call Anomaly.ObserveRows after each successful read
// so that rows_per_hour can be enforced. The web account page uses
// Dispatcher.Linker() (Linked, IssueCode, Unlink) to show and issue Slack
// linking codes; users complete the link with `/dbgw link <code>`.
package notify
