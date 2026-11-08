# Masking and the audit log

Masking decides what values leave dbgateway. The audit log records who did what, without recording the values themselves.

## Masking

### Where it happens

Masking is applied to results after the database returns them and before they leave dbgateway. It applies the same way to every entry point: MCP, the API, the SQL editor, the CLI, exports, and the `RETURNING` rows of approved writes (which are stored already masked). Masked values never reach an agent's context, the browser, Slack or webhooks.

The masking plan is computed **before** the statement runs. If the source of any result column cannot be traced, the request is denied without running (`builtin:untraceable-output`). If the database returns a different number of columns than the analysis predicted, the result is withheld.

### Column lineage

Each result column is traced back to the base-table columns it is derived from, through aliases, expressions and function calls, subqueries, CTEs, views (by expanding their definition) and `SELECT *`. The **strictest source wins**: `lower(email)` is masked like `email`, and `concat(name, body)` is withheld from agents if `body` is `no_ai`.

Classes come from `data_classes` and `default_class` ([policies.md](policies.md#data-classes)).

### Who sees what

| Class | Agent | Person | Person with unmask |
| --- | --- | --- | --- |
| `public` | value | value | value |
| `masked` | masked value | masked value | value |
| `no_ai` | withheld | value | value |

- A **withheld** column stays in the result with `withheld: true`, and every value is `null`. A masked column carries `masked: true`. Both report their class.
- **Unmask** is granted per person and database, possibly with an expiry, and never to agents ([approvals.md](approvals.md#unmask)).
- Agents also may not use `masked` or `no_ai` columns in filters, `GROUP BY` or `ORDER BY` (`builtin:sensitive-predicate`), because the result or its order would reveal the values.
- Schema search marks the columns that would be masked for the caller.

### Masking methods

A column's `semantic_type` selects the method (`semantic_types: { contact: { method: partial } }`). Without a semantic type, the method is `redact`.

| Method | Result | Notes |
| --- | --- | --- |
| `redact` | `****` | The default |
| `partial` | `a***@example.com`, `0***8` | Keeps the first character and an e-mail domain, or the first and last character; values of 4 characters or fewer become `****`. Only for an unmodified single column: derived values (`lower(email)`) fall back to `redact` |
| `hmac` | `hmac:3f2a9c0e1b7d4a56` | Keyed HMAC-SHA256 (first 16 hex digits). Equal values give equal outputs, so masked values can still be compared and counted. The key comes from `masking.hmac_key_env`; keep it secret per deployment. Without a key, it falls back to `redact` |

`NULL` stays `NULL` with every method.

### Value-based PII detection

```yaml
pii_detection:
  enabled: true
  detectors: [email, phone_jp, credit_card, my_number]   # default: all
  action: mask                                           # mask (default) | deny
```

A safety net for columns nobody classified, not a replacement for `data_classes`. It scans the values of the columns that would be returned to **agents** as they are, including text inside longer strings and inside JSON values. Results for people are decided by classes only.

| Detector | Finds |
| --- | --- |
| `email` | Email addresses (`local@domain.tld`, TLD of two or more letters) |
| `phone_jp` | Japanese phone numbers: mobile and IP phones (11 digits starting with 070/080/090/050), landlines (10 digits), 0120/0800, and `+81` notation. With or without hyphens, spaces or parentheses; full-width digits are covered too |
| `credit_card` | Card numbers of 13–19 digits (spaces or hyphens allowed), starting with 2–6 and passing the Luhn check |
| `my_number` | Japanese 12-digit Individual Numbers ("My Number"; groups of four such as `1234 5678 9018` allowed), only with a valid check digit |

- Matches are found inside longer text as well. Numbers that follow letters or digits (`ORD-123456789018`), decimals, oddly grouped digits and numbers failing the check digit or Luhn check are ignored, so ordinary IDs and timestamps are not reported.
- `mask` replaces each detected span with `****` and marks the column as masked (class `pii:<detector>`). `deny` withholds the whole result (`builtin:pii-detected`).
- To keep the cost predictable, only the first 4 KiB of each string are scanned, and at most 16 KiB, 1024 elements and 8 levels per JSON value.

### Database error messages

Some database errors quote stored values (a failed type conversion, a constraint violation), which could leak masked data. dbgateway passes through the message only for errors known to mention identifiers and types: for PostgreSQL, SQLSTATE classes `42` (syntax and access), `25`, `53`, `54`, plus statement and lock timeouts. Other errors are reduced to the SQLSTATE (or the MySQL error number). Notifications never include database or parser messages.

## Audit log

Every request is recorded, whether it ran or not, including denials, approval steps and errors. Result values are never recorded: only row and byte counts, durations, and the names of masked columns.

### Events

| `event` | Recorded for |
| --- | --- |
| `query` | `execute_sql` and the same request from the SQL editor, CLI or API: allowed, denied, submitted for approval, failed, and writes run under break-glass elevation |
| `export` | A CSV or JSON export from the SQL editor (`extra.format`, row count) |
| `explain` | `explain_policy`, "Check the decision", `dbgw explain` |
| `search` | Schema searches. The table list the SQL editor shows as part of its layout is not recorded when allowed; denials are |
| `approval` | Every state change of an approval request; `extra.action` is `submitted`, `approved` (with the step and step-up method), `rejected`, `canceled`, `expired`, `running`, `succeeded`, `failed` or `integrity_failed` |
| `break_glass` | Granting a break-glass elevation (databases, expiry, reason, step-up method) |

`decision` is `allow`, `approve`, `deny` or `error`. `stage` and `rule` say what decided it.

### Entry format

One JSON object per line:

```json
{"ts":"2026-11-08T01:15:00.123456789Z","request_id":"req_k3x2q7...","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","event":"query","principal":{"kind":"agent","human":"alice@example.com","agent":"claude-code","client_id":"https://agent.example.com/client-metadata.json","client_name":"Example Agent"},"database":"prod-main","sql":"SELECT id, email FROM users WHERE id = $1","sql_sha256":"9c56cc51b374c3ba...","reason":"Support ticket #1234: check the user's plan","analysis":{"kind":"select","tables":["public.users"],"columns":["public.users.email","public.users.id"]},"decision":"allow","stage":"policy","rule":"reads","config_version":"3f9a1c2b7d10","result":{"rows":1,"bytes":48,"duration_ms":12,"truncated":false,"masked_columns":["email"],"error":null},"prev_hash":"5e884898da280471...","hash":"2c26b46b68ffc68f..."}
```

| Field | Content |
| --- | --- |
| `ts`, `request_id`, `trace_id` | Time, the request ID (shared by all entries of one request, including its approval) and the caller's trace ID |
| `principal` | `kind`, `human`, and for agents `agent`, `client_id` and the self-reported `client_name` (informational only) |
| `database`, `sql`, `sql_sha256`, `reason` | See SQL redaction below. The reason is free text, recorded as given |
| `analysis` | Statement kind, write flag, tables, columns, functions, `unknown` |
| `estimate` | The `EXPLAIN` estimate, when one was taken |
| `decision`, `stage`, `rule`, `shadow_denied_by` | The outcome; `shadow_denied_by` names the rule that would have denied the read in [shadow mode](policies.md#shadow-mode) |
| `config_version` | First 12 hex digits of the SHA-256 of the configuration file |
| `result` | Rows, bytes, duration, truncation, masked or withheld columns, error message |
| `extra` | Event-specific details (risk, approval rule, step, actor, `break_glass`, ...) |
| `prev_hash`, `hash` | The hash chain |

### SQL redaction

By default `sql` holds the **normalized** statement, with every literal replaced by a placeholder (`WHERE email = $1`). Statements that could not be normalized are recorded as `<not recorded; see sql_sha256>`. `sql_sha256` is always the hash of the raw SQL, so a known statement can still be matched.

`audit.log_raw_sql: true` records the SQL with its values. Turn it on only if access to the audit log is restricted accordingly. Notifications always use the normalized SQL. The SQL editor's per-person history is separate from the audit log and keeps the SQL as typed ([console.md](console.md)).

### Hash chain and verification

Each line contains the hash of the previous line (`prev_hash`) and its own `hash`: the SHA-256 of the line's bytes without the trailing `hash` field. The first entry chains to 64 zeros. Any edit, deletion or reordering breaks the chain.

```sh
dbgw audit verify                      # the output selected by the configuration
dbgw audit verify --dir /var/log/dbgateway/audit
# ok: 12345 entries in 30 files, chained from genesis; last hash <hash>
```

It exits with status 1 and reports where the chain breaks if anything was modified.

**Retention and checkpoints.** Entries older than `audit.retention` (default 365 days) are deleted. Before deleting, dbgateway records a checkpoint: the hash of the last deleted line. The oldest remaining line must then chain to a checkpoint instead of to genesis, so the remaining log stays verifiable. Copy checkpoints somewhere outside dbgateway's control, so that a deleted prefix cannot be passed off as retention.

### Outputs

| `audit.output` | Behavior |
| --- | --- |
| `file` (default) | Daily JSON Lines files `audit-YYYY-MM-DD.jsonl` (UTC) in `audit.dir`, private to the dbgateway user, synced to disk after every entry (unless `audit.no_fsync`). Retention deletes whole files and appends checkpoints to `checkpoints.jsonl` and the process log |
| `stdout` | One line per entry on standard output, for container log collectors. The chain restarts at every process start, so it is not verifiable history |
| `postgres` | The `audit_log` table in the PostgreSQL management database (or `audit.dsn_env`). All instances append to one chain, serialized with an advisory lock. Retention deletes the oldest rows hourly, recording checkpoints in `audit_checkpoints` |

`audit.otlp` additionally forwards every stored line as an OpenTelemetry log record, for example to a SIEM. Forwarding is best effort: it runs behind a bounded queue, drops are counted and logged, and it never decides whether a request succeeds. See [operations.md](operations.md) for OTLP and retention, and [ha.md](ha.md) for running several instances.

### Fail closed

If the audit log cannot be written, the action does not happen:

- query, export, search and explain results are withheld and an error is returned;
- an approval request whose submission cannot be audited is canceled;
- an approved write does not run unless its `running` entry is written first;
- a break-glass write is audited before it runs, and an elevation is not granted unless it is audited.

### The audit log screen

`/audit` in the web UI searches the log by period, person or agent, database, decision and table. Opening an entry shows every entry with the same request ID as a timeline, for example a write, its approvals and its execution. Approval pages link to it.

Only **auditors** and admins can use it: people listed in `auditors` (directly or through a group), and anyone with the `admin` role on any database. The same people can use the user screens (`/users`).

```yaml
auditors:
  - group: security
  - user: carol@example.com
```

The screen reads the `file` or `postgres` output; with `stdout`, search the log in your log platform instead.
