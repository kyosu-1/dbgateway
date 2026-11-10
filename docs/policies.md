# Policies, roles and data classes

Every request goes through two checks. **Roles** decide whether a person may do this kind of thing on this database at all. **Policies** (CEL rules) then decide whether this particular statement is allowed, needs approval, or is denied. Column **data classes** feed both the policies and the masking of results.

All of this lives in the configuration file, which is meant to be kept in Git and changed through pull requests. See [configuration.md](configuration.md) for every key.

## How a request is decided

For `execute_sql` (and the same request from the SQL editor, the CLI or the API), dbgateway runs these steps in order and stops at the first denial:

1. **Role.** The caller needs `querier` on the database. Unknown databases and missing roles get the same answer, so callers cannot probe which databases exist.
2. **Reason.** An empty `reason` is denied.
3. **Parse stage.** The SQL is parsed. Multiple statements, transaction control, `SET`, `COPY`, `DO`, `EXPLAIN`, locking clauses, functions outside the allowlist and other dangerous constructs are rejected here, whatever the policies say. See [security.md](security.md).
4. **Writes:** with approvals enabled, the caller also needs `writer`, and the database needs a `write_user`.
5. **Estimate.** dbgateway runs `EXPLAIN` when a rule references `estimate`, and for every write when approvals are enabled. If `EXPLAIN` fails, the request is denied.
6. **Risk** level is computed (approvals only; see [approvals.md](approvals.md#risk-levels)).
7. **Policy rules**, top to bottom; the first match wins. No match means deny.
8. **Built-in guards** that no rule can turn off.
9. **Masking plan.** If the source of any result column cannot be traced, the request is denied before it runs.
10. Execute, mask, write the audit log, return.

Every denial comes back with the `stage` (`parse`, `role` or `policy`), the `rule`, a `reason` (why) and a `hint` (how to get through). AI agents use the hint to fix their query themselves.

## Groups and roles

### Groups

```yaml
groups:
  - { name: data-team, oidc_group: data-team }        # IdP group
  - { name: oncall, members: [alice@example.com] }    # without an IdP
```

A person belongs to a group when their IdP groups (the OIDC `groups_claim`, or SCIM-synced groups) contain `oidc_group`, or when their e-mail is listed in `members`. When SCIM is enabled and the user is synced, SCIM groups replace the groups from the ID token ([scim.md](scim.md)).

### Roles

There are five fixed roles, granted per database:

| Role | Allows |
| --- | --- |
| `viewer` | Browse and search the schema (`search_objects`) |
| `querier` | Run read queries, with masking. Implies `viewer` |
| `writer` | Submit writes for approval. Submitting also needs `querier` |
| `approver` | Act on approval requests for the database when an approval rule names the `approver` role; use break-glass elevation |
| `admin` | Use the audit log and user screens; can be named in approval rule steps. Does not imply any other role |

`approver` does not let anyone approve their own request, and does not grant read access by itself.

### Role bindings

```yaml
role_bindings:
  - group: data-team
    databases: { labels: { env: prod } }
    roles: [querier, writer]
  - group: sre
    databases: "*"
    roles: [querier, writer, approver]
  - user: bob@example.com            # a personal, time-limited grant
    databases: [staging]
    roles: [querier]
    expires_at: 2026-12-31T00:00:00Z
```

Each binding has exactly one of `group` or `user` (an e-mail address). `databases` selects databases in one of three forms: `"*"` (all), a list of names (or a single name), or `{ labels: {...} }` (every database whose labels include all the given pairs). A binding with `expires_at` stops applying at that time; this is how just-in-time access is granted.

### Agents

An AI agent acts for a person and never exceeds that person's permissions. Its roles on a database are the person's roles, narrowed by its token:

- `db:read` scope keeps `viewer` and `querier`; `db:write` keeps `writer`.
- `approver` and `admin` are never given to an agent.
- A token can also be restricted to certain databases.

See [authentication.md](authentication.md) for how agent tokens are issued.

## Data classes

Every column has one of three classes:

| Class | Agents | People |
| --- | --- | --- |
| `public` | See the value | See the value |
| `masked` | See a masked value | See a masked value, unless they have [unmask](approvals.md#unmask) |
| `no_ai` | Never receive the value (the column is withheld) | See the value |

`no_ai` is meant for things such as free text written by outsiders: useful for people, but a prompt-injection and data-leak risk when sent to a model.

```yaml
data_classes:
  - columns: ["public.users.email", "public.users.phone"]
    class: masked
    semantic_type: contact
  - column_pattern: ".*(password|token|secret).*"
    class: masked
    semantic_type: secret
  - columns: ["public.support_tickets.body"]
    class: no_ai
  - column_pattern: "public\\.[a-z_]+\\.(id|[a-z_]+_id|created_at|status)"
    class: public

semantic_types:
  contact: { method: partial }   # redact | partial | hmac
  secret: { method: redact }
```

- Each entry has either `columns` (exact `schema.table.column`, case-insensitive) or `column_pattern` (a regular expression that must match the whole `schema.table.column`).
- Exact entries win over patterns; patterns are tried in order. For MySQL, the "schema" is the database name.
- `semantic_type` picks the masking method ([masking-and-audit.md](masking-and-audit.md#masking-methods)).

### Columns without a class

Unclassified columns get a default class, separately for people and agents:

1. the database's `default_class`, then
2. the top-level `default_class`, then
3. the built-in default: **`masked` for agents on databases labelled `env: prod`**, `public` otherwise.

```yaml
default_class:
  human: public
  agent: masked
```

Combined with the guard against filtering on sensitive columns (below), this means an agent on a production database cannot even write `WHERE id = 42` until `id` is classified. That is intentional: classify the harmless columns as `public` explicitly, usually with a pattern for ids and timestamps as above.

## Policy rules

```yaml
policies:
  - name: deny-ddl
    when: stmt.kind == "ddl"
    action: deny
    message: "Schema changes are not run through dbgateway."
    hint: "Write a migration and get it reviewed."
  - name: deny-unbounded-writes
    when: stmt.kind in ["update", "delete"] && !stmt.has_where
    action: deny
  - name: agents-never-see-no-ai
    when: principal.kind == "agent" && columns.exists(c, c.class == "no_ai")
    action: deny
  - name: reads
    when: stmt.kind == "select" && !stmt.is_write
    action: allow
    require: { replica: true }
  - name: writes
    when: stmt.is_write
    action: approve
    require: { reason: true }
```

| Field | Meaning |
| --- | --- |
| `name` | Unique; recorded in the audit log and returned to the caller |
| `when` | A CEL expression that must evaluate to a boolean |
| `action` | `allow`, `approve` (writes only; see [approvals.md](approvals.md)) or `deny` |
| `require` | Extra conditions for `allow` / `approve` (below) |
| `message`, `hint` | Returned on `deny`, to explain why and how to get the query through |

Rules are evaluated top to bottom and **the first match wins**. **No match means deny** (rule `no-matching-rule`).

An `allow` rule that could ever match a write or a DDL statement is a configuration error: dbgateway partially evaluates each `allow` condition with only the statement type known and refuses to load the configuration unless the condition is definitely false for writes and DDL. Writes can only run through approval.

### Default policies

When `policies` is empty:

- with approvals disabled: plain `SELECT` is allowed, everything else denied;
- with approvals enabled: DDL is denied, plain `SELECT` is allowed, writes need approval.

### CEL variables

| Variable | Fields |
| --- | --- |
| `principal` | `kind` (`"human"` / `"agent"`), `human` (e-mail), `agent` (agent name), `client_id`, `groups` (dbgateway group names) |
| `database` | `name`, `type` (`postgres` / `mysql`), `labels` (map) |
| `stmt` | `kind` (`select`, `insert`, `update`, `delete`, `merge`, `truncate`, `ddl`, `other`), `is_write`, `has_where`, `tables`, `functions`, `unknown` |
| `stmt.tables[]` | `schema`, `name`, `fqn` (`schema.name`), `read`, `write` |
| `columns[]` | Every referenced column: `name` (`schema.table.column`), `schema`, `table`, `column`, `class`, `semantic_type`, `usage` |
| `estimate` | `rows`, `cost` from `EXPLAIN` (zero when no estimate was taken) |
| `risk` | `"low"`, `"medium"` or `"high"` (always `"low"` when approvals are disabled) |

Notes:

- `stmt.is_write` is true for `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `TRUNCATE` and for a `WITH` query containing one of them.
- `stmt.has_where` is true for an `UPDATE` / `DELETE` with a `WHERE` (or a `MERGE` with a join condition) and **always false for `INSERT`**, so write `stmt.kind in ["update", "delete"] && !stmt.has_where` rather than `stmt.is_write && !stmt.has_where`.
- `columns` covers every place a column is used, not only the output. `usage` lists where: `output` (select list, `RETURNING`), `filter` (`WHERE`, `HAVING`, `JOIN`), `group` (`GROUP BY`, `DISTINCT ON`, `PARTITION BY`), `order`, `write` (assigned by `INSERT` / `UPDATE` / `MERGE`) and `other`. Columns read through views, CTEs and subqueries are resolved to base-table columns. Conditions and functions inside a view definition are not the caller's choice, so they do not count as `filter` usage and are not checked against the function allowlist.
- CEL string extensions are available, and numbers of different types compare directly (`estimate.rows > 1000`).

### `require`

| Key | Effect |
| --- | --- |
| `reason: true` | The reason must be specific: at least 8 characters and not a generic word such as `test`, `debug` or `check` (rule `builtin:reason-too-vague`). A non-empty reason is always required, with or without this |
| `step_up: true` | On `approve` rules, satisfied by the approvers' step-up authentication, which is always required. On `allow` rules the request is denied (`builtin:step-up-not-enabled`): step-up of the requester for reads is not supported |
| `max_rows: N` | Lowers the row limit for statements matched by this rule (it never raises the database's limit). Also applies to `RETURNING` rows and exports |
| `replica: true` | Runs the read on the database's `replica`; without a replica, on the primary's read user |

### Evaluation errors

A condition can fail at run time, for example `database.labels.env` on a database without an `env` label. dbgateway fails closed:

- a **`deny`** rule whose condition fails **matches**;
- an **`allow`** or **`approve`** rule whose condition fails is **skipped**;
- a risk condition that fails counts as a match (higher risk);
- an approval rule that fails denies the request instead of falling through to a later, possibly weaker rule.

Write `"env" in database.labels && database.labels.env == "prod"` when a label may be missing.

## Built-in guards

These apply in every mode, including shadow mode, and no rule can turn them off.

| Rule | Denies |
| --- | --- |
| `builtin:reason-required` | An empty `reason` |
| `builtin:reason-too-vague` | A generic reason, when the matched rule has `require.reason` |
| `builtin:unanalyzable` | A statement dbgateway could not fully analyze (unknown table or column, constructs it cannot follow) |
| `builtin:sensitive-predicate` | An agent using a `masked` or `no_ai` column in a filter, `GROUP BY` or `ORDER BY`. Results and their order would reveal the values (`WHERE email LIKE 'a%'`). People may do this; they still see the column masked |
| `builtin:untraceable-output` | A result column whose source cannot be traced, because masking could not be guaranteed |
| `builtin:write-guard` | Anything other than a plain read that reached `allow` |
| `builtin:approval-not-enabled` | Any write while `approvals.enabled` is false |
| `builtin:approve-non-write` | An `approve` decision on a statement that is not a write. Reads cannot be approved, and DDL never runs through dbgateway |
| `builtin:truncate` | `TRUNCATE`: its affected rows cannot be checked |
| `builtin:no-approval-route` | An `approve` decision that matches no approval rule |
| `builtin:estimate-failed` | A statement whose `EXPLAIN` failed when an estimate was needed |
| `builtin:backup-protected` | A statement that references the [backup schema](./approvals#backups-and-restore), other than the exact restore statement recorded for that backup |
| `builtin:backup-unsupported` | With `backup.required`, an `UPDATE`, `DELETE` or `MERGE` that cannot be backed up |
| `builtin:pii-detected` | A result in which value-based PII detection found personal data, with `pii_detection.action: deny` |

## Shadow mode

```yaml
server:
  mode: shadow    # default: enforce
```

Shadow mode lets you roll out policies without breaking people's work. It relaxes exactly one thing: **a policy denial of a read** (a `deny` rule, or no matching rule) becomes an allow. The audit log entry records the rule that would have denied it in `shadow_denied_by`, and `explain_policy` shows it too.

Shadow mode never relaxes role checks, parse-stage rejections, the reason requirement, the built-in guards, masking, or anything about writes.

## Checking a decision

`explain_policy` evaluates a statement exactly like `execute_sql` (role, analysis, classification, risk, policy, approval rule) but never runs it; only `EXPLAIN` may run. It is available as:

- the MCP tool `explain_policy` ([mcp.md](mcp.md)),
- **Check the decision** in the SQL editor ([console.md](console.md)),
- `dbgw explain` ([cli.md](cli.md)).

It returns the decision, the stage and rule, the reason and hint of a denial, `shadow_denied_by`, the risk, the estimate, every referenced column with its class and usage, and how each result column would be returned (as is, masked or withheld). For `approve` it also returns the approval rule, its steps and expiry, who could approve the first step, the affected-rows limit, and whether an active break-glass elevation would run the write immediately. It does not need a reason, and it is audited as event `explain`.

## Policy tests

Policy tests pin down expected decisions so that a configuration change cannot silently open or close access. They need no database, so they run in CI.

```sh
dbgw policy test testdata/policy/*.yaml        # -v prints passing cases; exit status 1 on failure
```

```yaml
config: ../../examples/dbgateway.yaml   # relative to this file; --config overrides it

catalog:                                # the schema the cases run against
  search_path: [public]
  relations:
    - { name: public.users, columns: [id, name, email, plan, created_at] }
    - name: public.user_contacts
      kind: view                        # table (default) | view | materialized_view
      definition: "SELECT id, lower(email) AS email FROM users"
      columns: [id, email]

principals:
  alice-agent: { kind: agent, human: alice@example.com, agent: claude-code, groups: [data-team] }
  alice-agent-write: { kind: agent, human: alice@example.com, agent: claude-code, groups: [data-team], scopes: ["db:read", "db:write"] }
  alice: { kind: human, human: alice@example.com, groups: [data-team] }

cases:
  - name: agent reads with a public filter
    principal: alice-agent
    database: prod-main
    sql: "SELECT id, email FROM users WHERE id = 42"
    expect: { decision: allow, rule: reads, masked: [email], visible: [id] }

  - name: agent may not filter on a masked column
    principal: alice-agent
    database: prod-main
    sql: "SELECT id FROM users WHERE email LIKE 'a%'"
    expect: { decision: deny, rule: "builtin:sensitive-predicate" }

  - name: a large update is high risk
    principal: alice-agent-write
    database: prod-main
    sql: "UPDATE users SET plan = 'pro' WHERE created_at < '2020-01-01'"
    estimate: { rows: 50000 }
    expect: { decision: approve, risk: high, approval_rule: prod-high-risk }
```

- `principal` is a name from `principals` or an inline principal. Agents get the `db:read` scope unless `scopes` says otherwise; `databases` restricts the token.
- `estimate` sets the planner estimate (default zero rows).
- Every `expect` field is optional: `decision`, `rule`, `stage`, `risk`, `approval_rule`, and the output columns that must be `masked`, `withheld` or `visible`.
- The analyzer matches the database's `type`, so MySQL databases are tested with MySQL syntax.

Policy tests cover the decision and the masking plan. They do not cover the reason checks, break-glass elevation or value-based PII detection, which depend on the request or the data.
