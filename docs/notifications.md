# Event notifications (Slack and webhooks)

dbgateway sends notifications to Slack and generic webhooks for approval requests, approval decisions, execution results, denials, break-glass elevation, anomalies and configuration changes. In Slack, an approval request post has "Open approval page" and "Reject" buttons, and later events for the same request are posted in its thread.

Notifications are supplementary. The approval page and `get_request` are the source of truth; notifications are sent asynchronously on a best-effort basis. A failed notification never affects how a request is processed (approval, execution, denial).

## What is sent and what is not

| Sent | Not sent |
| --- | --- |
| Normalized SQL (literals replaced with `$1`, etc.) | Raw SQL, literals |
| Target tables, estimated rows, risk, approval rule name | Query results, RETURNING values |
| `reason` (the requester's justification, shown as plain text that never becomes a link or mention) | Database error messages (they can contain values; the notification says only that the execution failed and to see the approval page) |
| Requester (human, agent name), status, the person who acted, approval page URL | Decision messages such as syntax errors (they can quote parts of the SQL); only the rule name and stage are sent |

- All Slack text is escaped (`&`, `<`, `>`), and `verbatim` is used to disable automatic linking. `reason` is placed in a plain-text block, so writing `<!channel>` or `<https://…|…>` in it produces neither a notification nor a link
- Link unfurling is disabled
- Logs never contain message bodies, tokens or webhook URLs (only the event type, request ID, destination name and error)

## Configuration

```yaml
notifications:
  - events: [approval_requested]
    to: { slack: "#db-approvals", mention: approvers }   # mention the people who can approve
  - events: [approval_decided, execution_finished]
    to: { slack: requester }                              # DM the requester
  - events: [query_denied]
    when: database.labels.env == "prod"
    to: { slack: "#security-alerts" }
  - events: [break_glass_used, anomaly_detected]
    to: { slack: "#security-alerts", webhook_env: PAGERDUTY_WEBHOOK_URL }
  - events: [config_changed]
    to: { slack: "#dbgateway-admin" }

slack:                              # defaults shown below if omitted
  app_token_env: SLACK_APP_TOKEN    # xapp- (connections:write)
  bot_token_env: SLACK_BOT_TOKEN    # xoxb-

anomaly:
  denials_per_10m: 10               # more denials for one requester within 10 minutes than this
  rows_per_hour: 100000             # more rows returned to one requester within an hour than this

notifications_language: en          # en (default) or ja
notifications_webhook_secret_env: DBGW_WEBHOOK_SECRET   # optional; key for signing webhooks
```

### Routes

- `events`: any of `approval_requested`, `approval_decided`, `execution_finished`, `query_denied`, `break_glass_used`, `anomaly_detected`, `config_changed`
- `when` (optional): a CEL condition. Available variables are `database` (`name`, `labels`) and `event` (`type`, `status`, `risk`). Example: `database.labels.env == "prod" && event.risk == "high"`. A condition that fails to evaluate (for example, it references a label the database does not have) is treated as not matching. If some databases lack the label, write `"env" in database.labels && database.labels.env == "prod"`
- `to.slack`: `"#channel-name"`, a channel ID (`C0123ABC`), or `requester` (a DM to the requester's Slack user; not sent to people who have not linked their account)
- `to.mention: approvers`: mentions the people who can approve the next step, as their linked Slack users (people without a link are shown by email address). Only valid for channel destinations
- `to.webhook_env`: the name of the environment variable holding the webhook URL
- Every matching route is used (not just the first). The same channel or webhook receives a message only once

When the configuration is loaded, dbgateway checks event names, compiles the CEL conditions, and validates channel formats and environment variable names. If a token or webhook environment variable is empty, it logs a warning and skips that destination (startup continues).

### Threads

- When `approval_requested` is posted to a channel, the post (channel and `ts`) is saved in the management database, and approval, rejection, expiry and withdrawal (`approval_decided`) and the execution result (`execution_finished`) are **posted as replies in the same thread**. This happens regardless of route configuration. Even if a route targets the same channel, no separate channel post is made
- The "Status" line of the original post is also updated (for example "Rejected (alice@example.com)", "Succeeded"). Once the request is no longer pending, the "Reject" button is removed

### Anomaly detection (anomaly_detected)

- When one requester's `query_denied` events exceed `denials_per_10m` within 10 minutes (agent requests count toward the human they act for; counts are per human)
- When the rows returned to one requester within an hour exceed `rows_per_hour`
- After a notification, the same requester and kind are not notified again until the window (10 minutes, 1 hour) has passed
- Counting happens in process memory (per instance in a multi-instance deployment)

### Configuration changes (config_changed)

At startup, dbgateway compares the configuration version (the first 12 characters of the file's SHA-256) with the one from the previous startup and notifies if it changed (with the previous and current versions). The first startup does not notify.

## Slack setup

1. At https://api.slack.com/apps, choose "Create New App" → "From an app manifest", and paste [`deploy/slack/manifest.yaml`](../deploy/slack/manifest.yaml)
2. Under "Basic Information" → "App-Level Tokens", create a token with `connections:write` and put it in `SLACK_APP_TOKEN` (`xapp-…`)
3. Install the app with "Install to Workspace" and put the "Bot User OAuth Token" in `SLACK_BOT_TOKEN` (`xoxb-…`)
4. Invite the bot to the destination channels (`/invite @dbgateway`)
5. Restart dbgateway. `Slack Socket Mode connected` in the log means it is connected

Socket Mode uses only an outbound WebSocket from dbgateway to Slack; no inbound URL from Slack to dbgateway is needed. With multiple instances, each instance connects and Slack delivers each button action to one of them.

Required bot scopes: `chat:write` (post, update, ephemeral replies), `im:write` (DMs to requesters), `users:read`, `commands` (`/dbgw`).

### Linking Slack accounts

Mentions, DMs to requesters and the Reject button require a link between a Slack user and a dbgateway user.

1. On the dbgateway account page, issue a Slack linking code; a one-time code is shown (for example `7KQ2-M9XD`, valid for 10 minutes)
2. In Slack, run `/dbgw link 7KQ2-M9XD`

- Only a hash of the code is stored in the management database. Issuing a new code invalidates the previous one
- After five wrong codes from the same Slack user within 10 minutes, further attempts are refused for a while
- `/dbgw whoami` shows the linked account; `/dbgw unlink` (or the account page) removes the link
- A Slack user links to only one dbgateway user. Linking again from another account removes the previous link

### Reject button

- A rejection is accepted only if the Slack user who pressed the button is linked to a dbgateway user who is an approver for some step of the request (the same check as rejecting on the approval page; the comment records that it was rejected from Slack)
- The requester, unlinked users, non-approvers and users deactivated through SCIM get an ephemeral message explaining why, and nothing happens. The same applies to requests that are already decided
- After a rejection, the result is posted in the thread and the original post's status is updated
- **Approving is not possible in Slack.** "Open approval page" takes you to the approval page, where you approve after step-up authentication (passkey or IdP re-authentication)

## Webhooks

Events are POSTed as JSON to the URL in the `webhook_env` environment variable (for relaying to Microsoft Teams, PagerDuty and so on).

```json
{
  "type": "approval_requested",
  "time": "2026-11-08T01:02:03Z",
  "request_id": "req_…",
  "database": "prod-main",
  "labels": { "env": "prod" },
  "principal": { "kind": "agent", "human": "alice@example.com", "agent": "claude-code", "client_id": "…" },
  "sql": "UPDATE users SET plan = $1 WHERE id = $2",
  "tables": ["public.users"],
  "estimate_rows": 1,
  "reason": "Support ticket #1234",
  "status": "pending",
  "approvers": ["bob@example.com"],
  "url": "https://dbgw.example.com/approvals/req_…",
  "detail": { "risk": "high", "approval_rule": "prod-writes", "max_affected_rows": "2" },
  "text": "Approval requested · prod-main · claude-code on behalf of alice@example.com · Pending approval"
}
```

- `detail` contains only `risk`, `approval_rule`, `max_affected_rows`, `step`, `rows_affected`, `stage`, `rule`, `databases`, `expires_at`, `anomaly`, `count`, `threshold`, `window`, `previous_version` and `version`
- Headers: `Content-Type: application/json`, `User-Agent: dbgateway`, `X-Dbgw-Event: <event name>`
- The timeout is 5 seconds. On connection errors, 429 and 5xx, delivery is retried with doubling intervals (1 s, 2 s), **at most 3 attempts** in total. Other 4xx responses are not retried
- URLs are never logged (they often contain secrets)

### Verifying signatures

With `notifications_webhook_secret_env` set, an HMAC-SHA256 of the body is sent as `X-Dbgw-Signature: sha256=<hex>`. On the receiving side, compute the same value over the body exactly as received (the bytes before any re-parsing) and compare in constant time.

```python
import hmac, hashlib
expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(expected, request.headers["X-Dbgw-Signature"])
```

The body includes `time`, so discarding events that are too old protects against replay.

## Operations

- Up to 1024 pending events are queued in memory. Overflowing events are dropped and the count is logged (at most once a minute)
- On shutdown, dbgateway waits up to 10 seconds for pending events to be sent
- Slack thread positions and account links are stored in the `slack_threads`, `slack_links` and `slack_link_codes` tables of the management database (SQLite or PostgreSQL)

## Integration (for developers)

- `notify.New` returns a `*Dispatcher` that implements `events.Publisher`. When notifications are configured, the `server` package passes it (wrapped with `notify.NewAnomaly`) to the gateway and the approval service
- `Anomaly.ObserveRows(principal, database, rows)`: called by the gateway after each successful read; used for the `rows_per_hour` check
- The web account page uses `Linked(email)`, `IssueCode(email)` and `Unlink(email)` of `Dispatcher.Linker()`
- `Dispatcher.SetPrincipalResolver` replaces how the principal of the person who pressed the Reject button is built with the auth package's resolver (by default it is resolved from the management database's user and IdP groups with `RBAC.ResolveGroups`, and users deactivated through SCIM are refused)
