# Quotas

Policies decide one statement at a time. A caller who is allowed to read a table can still pull all of it out through many small queries, each of which passes every rule. [Anomaly notifications](notifications.md#anomaly-detection-anomaly-detected) tell you when that happens; **quotas stop it**. A quota limits how many queries one person may run and how many rows they may receive over time, and denies reads once the limit is used up.

## Example

```yaml
quotas:
  - name: agents-prod
    when: principal.kind == "agent" && database.labels.env == "prod"
    queries_per_minute: 30
    rows_per_hour: 20000
    rows_per_day: 100000
    hint: "Ask #data-platform if you need a higher quota."
  - name: people-prod
    when: principal.kind == "human" && database.labels.env == "prod"
    rows_per_day: 500000
  - name: customers-table
    when: stmt.tables.exists(t, t.fqn == "public.customers")
    rows_per_hour: 2000
```

| Key | Description |
| --- | --- |
| `name` | Required, unique. Returned as rule `quota:<name>` and used as the key of the counters, so renaming a quota starts it from zero |
| `when` | Optional CEL condition; empty means every read. The variables are those of [policy rules](policies.md#cel-variables) except `estimate` and `risk`: `principal`, `database`, `stmt` and `columns` |
| `queries_per_minute` | Queries in the current minute |
| `queries_per_hour` | Queries in the last hour |
| `rows_per_hour` | Rows returned in the last hour |
| `rows_per_day` | Rows returned in the last 24 hours |
| `hint` | Added to the hint of a denial, for example whom to ask for a higher quota |

Each quota needs at least one limit. Unknown keys are errors, and `dbgw config validate` compiles the conditions.

## What is counted

- **Every matching quota applies.** Unlike policy rules, quotas are not first-match: a read is checked against, and counted in, every quota whose condition matches it.
- **Per person.** Counters are kept per quota and per person. An agent counts against the person it acts for, together with all of that person's other agents and tokens. Agent tokens are cheap to obtain (each consent issues a new one), so per-token counters could be reset at will; the person is the accountable party, and anomaly detection counts per person too. To limit agents more tightly than people, match on `principal.kind`: a quota whose condition only matches agents counts only the agents' reads.
- **Across databases.** A quota that matches several databases counts them together, which is what stops spreading the reads over replicas or copies. Write one quota per database (`database.name == "..."`) for separate budgets.
- **Reads that run.** A read counts once it reaches the database: one query, plus the rows returned to the caller (a read that fails in the database counts as a query with no rows). Exports from the SQL editor are reads and count the same way. Reads denied before they run, including by a quota, are not counted (anomaly detection counts denials instead). Writes go through [approval](approvals.md) and are not subject to quotas.

## Windows

Usage is stored in one-minute buckets. `queries_per_minute` covers the current minute (it resets at the start of each minute); the hourly and daily limits cover the current minute and the 59 (or 1,439) before it, so they slide forward a minute at a time instead of resetting all at once.

## Enforcement

Quotas are checked after the policies, the built-in guards and the masking plan, right before the read would run:

1. If any limit of a matching quota is used up, the read is **denied** with stage `policy` and rule `quota:<name>`. The reason says which limit (`rows_per_hour`, ...) and how much of it is used. The hint says when the quota frees up, in UTC and as a wait (`in 12m`), followed by the quota's `hint`. When several limits are used up, the one that frees up last is reported.
2. Otherwise the read runs, but **never returns more rows than the row limits have left**. If a quota allows 300 more rows in the hour, the read's row limit is lowered to 300; a larger result is truncated, like any result over the row limit, and the hint names the quota. A single query therefore cannot go past a row limit.
3. After the read, the query and its row count are added to every matching quota.

Quota denials are handled like every other denial: they are written to the audit log (with `quota_limit`, `quota_used` and `quota_max` in `extra`), published as `query_denied` [notification events](notifications.md), and count toward the `denials_per_10m` anomaly. Agents get the reason and the hint, so they can stop and wait instead of retrying.

`explain_policy` (and **Check the decision** in the SQL editor, `dbgw explain`) reports a quota that would deny the read now, with the same rule, reason and hint. It does not count as a query.

### Shadow mode

With `server.mode: shadow`, a used-up quota does not deny: the read runs without the row cap, and the audit log records `shadow_denied_by: quota:<name>`. Usage is still counted. This is a good way to choose limits: run in shadow mode for a while and look for `quota:` in `shadow_denied_by`.

### Concurrency

The check and the count are separate steps, not one transaction. Reads by the same person that run at the same moment can each pass the check, so a limit can be exceeded by the reads in flight at that time, each still bounded by its row limit (`limits.max_rows`, `require.max_rows`, and the rows the quota had left when it started).

## Storage and multiple instances

Usage lives in the management database (table `quota_usage`), so every instance sees the same counts: with the PostgreSQL store ([ha.md](ha.md)) quotas hold across all instances, and with SQLite they work for the single instance. A read that matches quotas costs one query to load the buckets and one upsert to add to them; reads that match no quota never touch the table. Buckets are deleted by the periodic cleanup once no window of their quota needs them.

### When the management database is unavailable

Quotas **fail closed**: if usage cannot be read, the read is not run, and if it cannot be recorded after the read, the result is withheld (status `error`). This matches the audit log, which withholds results it cannot record. It does not make dbgateway less available in practice: every request already needs the management database, because tokens and sessions are looked up in it.

## Quotas and anomaly notifications

They complement each other. `anomaly.rows_per_hour` is a single, global alert threshold kept in each instance's memory; quotas are enforced, selected by CEL, shared across instances, and can cover longer windows. A common setup sets the anomaly threshold below the quota, so that someone hears about unusual volume before the quota starts denying.
