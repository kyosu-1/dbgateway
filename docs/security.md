# Security model

dbgateway controls two things: **what reaches the database** and **what data leaves it**. It cannot control what an agent does with data after it was legitimately returned, so this page states both what it protects against and what it does not.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What dbgateway protects against

- **Destructive writes by a mistaken or misled agent.** Writes are never auto-allowed; each one needs a human approval, can be bounded by the planner estimate, and is rolled back if it affects more rows than approved.
- **Read-only escapes.** Multiple statements, transaction control, session settings, side-effecting functions and leftover session state are blocked at parse time and again at execution time.
- **Prompt injection that writes back to the database.** A write is also an exfiltration channel, so every write goes through a human.
- **Forged or replayed approvals.** Approvals happen inside dbgateway with step-up authentication, are bound to the exact statement, and can be used once.
- **Credential exposure.** Neither people nor agents ever hold database credentials. Cloud IAM authentication can replace static passwords.
- **Sensitive data reaching an AI.** Column data classes, masking by lineage, `no_ai` columns and optional value-based PII detection.
- **Agents exceeding the person they act for.** See [Agents versus people](#agents-versus-people).

## What it does not protect against

- **Parser bypasses.** dbgateway uses the database's own parser and fails closed, but if a statement ever slipped through, the database's own GRANTs are the last line of defense. Give dbgateway a read user with `SELECT` only and a separate write user; never a superuser.
- **Functions inside views and triggers.** Function calls and conditions inside a view definition are not chosen by the caller and are not checked against the allowlist (output lineage through views is still traced for masking). Triggers fired by an approved write are invisible to analysis. Protect these with database privileges.
- **Exfiltration by a legitimate user or agent.** Data that was correctly returned can be sent elsewhere by the agent through other tools. Results are labelled as data, not instructions, but the agent environment must control its own outbound channels.
- **Split attacks.** Decisions are per request. Harmless-looking requests that add up to something harmful across requests or sessions are not detected; anomaly notifications (bursts of denials, large result volumes) only partly compensate.
- **Approvers who do not read.** The approval page shows the full statement, estimate, affected-row limit and touched columns, but cannot force careful review.
- **Malicious dbgateway administrators.** Whoever controls the configuration, the host or the management database can change behavior. The audit hash chain and external forwarding make tampering detectable, not impossible.

## Row-level security

dbgateway connects with shared database users, so by default the database cannot tell who a request is for. With `session_identity: true` on a PostgreSQL database, every transaction — reads, and approved or break-glass writes, which run for their requester — starts with these transaction-local settings:

| Setting | Value |
| --- | --- |
| `dbgateway.user` | E-mail of the person (for an agent, the person it acts for), lower case |
| `dbgateway.kind` | `human` or `agent` |
| `dbgateway.agent` | Agent name; empty for people |
| `dbgateway.groups` | Comma-separated groups |
| `dbgateway.request_id` | Request ID, as in the audit log and approvals |

Row-level security policies and triggers can use them:

```sql
ALTER TABLE tickets ENABLE ROW LEVEL SECURITY;
CREATE POLICY own_tickets ON tickets
  USING (assignee = current_setting('dbgateway.user', true));
```

Callers cannot change the settings: `SET`, `set_config` and transaction control are refused, and they are reset after every transaction. Read `current_setting(name, true)` (missing settings return `NULL`, so a policy matches nothing when the setting is absent). The planner estimate (`EXPLAIN`) runs without the settings. Requires a read and a write user that are subject to row-level security (not superusers, not `BYPASSRLS`, not the table owner unless the policy is `FORCE`d).

## Trust boundaries

| Boundary | Controls |
| --- | --- |
| Clients → dbgateway | HTTPS (terminated in front of dbgateway). Agents use OAuth access tokens bound to the MCP resource; people use browser sessions or CLI tokens. MCP tool annotations and client-side confirmations are never trusted; every decision is made on the server |
| dbgateway → databases | TLS (`sslmode: verify-full` recommended), separate read and write users, optional IAM authentication. The database firewall should admit only dbgateway |
| dbgateway → IdP | OIDC authorization code flow with PKCE and nonce |
| dbgateway → Slack, webhooks | Outbound only. Messages carry normalized SQL (no literals), table names, estimates, the reason and status; never result values or database error text |
| Configuration | Trusted input, managed in Git and reviewed through pull requests. Secrets are referenced by environment variable name only |
| Management database | Trusted. Stores only hashes of tokens and session IDs |

## Defense layers

1. **Authentication and roles.** Fixed roles (`viewer`, `querier`, `writer`, `approver`, `admin`) bound to groups or users per database, optionally with an expiry.
2. **Parse-stage rejection** with the real parser, independent of configuration.
3. **Lineage and data classes** for every referenced column.
4. **CEL policies**, deny by default. A configuration in which an `allow` rule could match a write is rejected at load time.
5. **Built-in guards** that no configuration or shadow mode can turn off (see [Policies](./policies#built-in-guards)).
6. **Execution limits**: read-only transaction (plus `default_transaction_read_only` on the PostgreSQL read pool), statement and lock timeouts, fixed search path or `sql_mode`, row and byte limits, extended query protocol (the server refuses multiple statements), and session reset after every request.
7. **Masking** at the result, by lineage. Database errors that might quote stored values are reduced to their SQLSTATE.
8. **Audit**, fail closed.
9. **Database GRANTs**, the last line of defense.

## Safe defaults

- With no policies configured, only plain reads are allowed. Writes and DDL are denied until approvals are enabled (`approvals.enabled`); after that, the default for writes is approve and DDL stays denied.
- An approve decision with no matching approval rule is denied.
- Unclassified columns are `masked` for agents on databases labelled `env: prod`.
- Shadow mode (`server.mode: shadow`) relaxes only policy denials of reads; parse-stage rejections, built-in guards and approvals stay enforced.
- `auth.dev_login` is refused unless dbgateway listens on loopback.
- SQL literals are redacted in the audit log unless `audit.log_raw_sql` is set.
- dbgateway sends no telemetry.

## Rejected statements

Rejected at parse time on every database:

- empty or unparsable SQL, and more than one statement
- transaction control (`BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, ...)
- session settings (`SET`, `RESET`, `SET ROLE`, `SET TRANSACTION`, ...) and `SHOW`
- `EXPLAIN` in any form (dbgateway runs its own estimates)
- `CALL`, `DO`, `PREPARE` / `EXECUTE` / `DEALLOCATE`, table locks
- `SELECT ... INTO`, row-locking clauses (`FOR UPDATE`, `FOR SHARE`, ...)
- parameter placeholders (`$1`, `?`); write values inline, they are redacted in the audit log
- functions outside the allowlist; the defaults contain only side-effect-free built-ins (extend with `sql.allowed_functions`)
- statement types the adapter does not recognize

PostgreSQL additionally: `ALTER SYSTEM`, `COPY` (all forms), `NOTIFY` / `LISTEN` / `UNLISTEN`, cursors (`DECLARE`, `FETCH`, `CLOSE`), `DISCARD`, `LOAD`, `CHECKPOINT`. Functions such as `pg_read_file`, `lo_import`, `dblink`, `set_config`, `pg_terminate_backend`, `nextval` and `query_to_xml` are not on the allowlist.

MySQL additionally: executable comments (`/*! */`, `/*M! */`, `/*T! */`) and optimizer hints (`/*+ */`), even inside strings, because they can make the server run something different from what was analyzed; invalid UTF-8 and control characters; `LOAD DATA`, `IMPORT INTO`, `LOCK TABLES`, `USE`, `KILL`, `FLUSH`, `SHUTDOWN` and similar utilities; `SELECT ... INTO OUTFILE / DUMPFILE / @var`, `LOCK IN SHARE MODE`, `SQL_CALC_FOUND_ROWS`; user and system variables. `LOAD_FILE`, `SLEEP`, `BENCHMARK` and `GET_LOCK` are not on the allowlist. See [MySQL](./mysql).

Classified but never executed: DDL (denied by policy; it cannot be approved) and `TRUNCATE` (not even after approval, because affected rows cannot be checked). Data-modifying CTEs and `MERGE` count as writes.

The test suites in [testdata/bypass](../testdata/bypass/) hold the known bypass attempts, including variants with comments, case changes, quoting and schema qualification.

## Agents versus people

- An agent token carries the person it acts for. The agent's roles are that person's roles, narrowed by the token's scopes (`db:read`, `db:write`) and databases. It never has `approver` or `admin`.
- Agents cannot approve, cannot use break-glass elevation, cannot export from the SQL editor, cannot use the connectRPC API and cannot manage tokens. Human CLI tokens are not accepted on the MCP endpoint.
- For agent requests, the person behind the agent counts as the requester and cannot approve them.
- `no_ai` columns are withheld from agents (people see them). Unmask grants apply only to people.
- Agents may not use non-public columns in filters, joins, grouping or ordering, since result order or row counts would reveal the values.
- Every result carries a notice that it is database content, not instructions. The `reason` an agent writes is shown on the approval page as inert text, labelled as written by the agent, so approvers are not steered by it.

## Approvals

- **Binding hash.** Each request stores a hash over database, raw SQL, requester, approval rule and configuration version. It is checked at approval and again right before execution; any change means a new request.
- **Re-evaluation.** Before running, the requester's `writer` role and the policy are evaluated again with the current configuration. If the decision is no longer approve under the same approval rule, the write does not run.
- **Affected-row limit.** The write runs in a transaction and is rolled back if it affects more rows than the limit shown to approvers (by default twice the estimate, at least one row).
- **Step-up authentication.** Approving requires a passkey or IdP re-authentication no older than `approvals.step_up_max_age` (5 minutes by default). Only people can approve; one person approves at most one step. Rejecting needs no step-up, so Slack can offer a reject button.
- **Single execution.** The request moves from approved to running with a conditional update, which consumes the approval. An audit entry is written before execution; no audit, no write. A request interrupted mid-execution is marked failed and never re-run.
- **Visibility.** Request IDs are 128-bit random values. Only the requester (and their agents) and eligible approvers can see a request; others get the same answer as for a nonexistent ID.

Details: [Approvals](./approvals).

## Audit integrity

Every request, allowed or not, is one JSON line containing the hash of the previous line, so editing, deleting or reordering lines breaks the chain. `dbgw audit verify` checks it, for files and for the PostgreSQL audit log. Retention keeps checkpoints so the remaining log still verifies. Query result values are never recorded. If an entry cannot be written, the request returns no result. Forwarding to OpenTelemetry is best effort and lets you keep a copy outside dbgateway's control. Details: [Masking and audit](./masking-and-audit).

## Web UI hardening

- `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'`: no inline scripts or styles and no third-party resources (the editor is bundled). The SQL editor (`/console`) additionally allows `<style>` elements carrying a per-response nonce, which the bundled editor needs; scripts remain `'self'` only.
- `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on pages.
- Every state-changing form carries a CSRF token bound to the session; GET requests never change state.
- Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` when the public URL is HTTPS.
- Request bodies are size-limited.
