# Configuration reference

dbgateway reads one YAML file. Keep it in Git and change it through pull requests: role bindings, policies and approval rules are then reviewed like code, and every audit log entry records the version of the file that decided it.

## Example

A trimmed version of [examples/dbgateway.yaml](../examples/dbgateway.yaml):

```yaml
server:
  public_url: https://dbgateway.example.com   # TLS is terminated in front of dbgateway
  mode: enforce                               # or shadow

auth:
  oidc:
    issuer: https://idp.example.com
    client_id_env: DBGW_OIDC_CLIENT_ID        # secrets: names of environment variables only
    client_secret_env: DBGW_OIDC_CLIENT_SECRET

databases:
  - name: prod-main
    labels: { env: prod }
    primary:
      host: prod-main.db.example.com
      dbname: app
      read_user: dbgw_reader                  # SELECT only
      password_env: DBGW_PROD_READER_PASSWORD
      write_user: dbgw_writer                 # runs approved writes only
      write_password_env: DBGW_PROD_WRITER_PASSWORD

groups:
  - { name: data-team, oidc_group: data-team }
  - { name: sre, oidc_group: sre }

role_bindings:
  - { group: data-team, databases: { labels: { env: prod } }, roles: [querier, writer] }
  - { group: sre, databases: "*", roles: [querier, writer, approver] }

data_classes:
  - { columns: ["public.users.email"], class: masked, semantic_type: contact }
  - { column_pattern: "public\\.[a-z_]+\\.(id|[a-z_]+_id|created_at)", class: public }
semantic_types:
  contact: { method: partial }

approvals:
  enabled: true
approval_rules:
  - name: default
    when: "true"
    steps: [{ role: approver }]

policies:
  - { name: deny-ddl, when: 'stmt.kind == "ddl"', action: deny }
  - { name: reads, when: 'stmt.kind == "select" && !stmt.is_write', action: allow }
  - { name: writes, when: stmt.is_write, action: approve, require: { reason: true } }
```

## Loading and validating

- `--config path` (or `-c`) selects the file; the default is `$DBGW_CONFIG`, else `dbgateway.yaml`.
- `--config env:NAME` reads the YAML from an environment variable instead, for platforms where files cannot be mounted. If `DBGW_CONFIG_YAML` is set and `DBGW_CONFIG` is not, it is used automatically.
- **Secrets are never written in the file.** Keys ending in `_env` name the environment variable that holds the secret (passwords, DSNs, tokens, keys). `sslrootcert_env` does the same for a PEM CA certificate; dbgateway validates it and writes it to a private temporary file.
- Unknown keys are errors. Problems that do not stop dbgateway (an unset environment variable, a non-`verify-full` TLS mode on a `prod` database) are printed as warnings.
- `dbgw config validate` checks types, compiles every CEL expression, rejects `allow` rules that could match a write, and prints the configuration version.
- **Durations** accept Go syntax plus days: `90s`, `30m`, `12h`, `7d`, `1d12h`. **Sizes** accept `512KiB`, `1MiB`, `1MB` or a plain number of bytes.
- **Database selectors** (`databases:` in role bindings, `unmask`, `break_glass`) are `"*"`, a name or a list of names, or `{ labels: { key: value } }`.

## Sections

### server

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `listen` | string | `127.0.0.1:8443` | Listen address (plain HTTP; terminate TLS in front) |
| `public_url` | URL | `http://<listen>` | External URL. Plain `http` only for loopback hosts |
| `mode` | `enforce` \| `shadow` | `enforce` | [Shadow mode](policies.md#shadow-mode) records read denials instead of enforcing them |
| `metrics_listen` | `host:port` | (off) | Separate listener serving Prometheus metrics at `GET /metrics` ([operations.md](operations.md#6-metrics)). Must differ from `listen`; metrics are never served on `listen`. Not authenticated: a non-loopback address produces a warning |

### auth

See [authentication.md](authentication.md). One of `oidc`, `passkeys` or `dev_login` is required.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `oidc.issuer` | URL | | OIDC issuer (required with `oidc`) |
| `oidc.client_id_env`, `oidc.client_secret_env` | env name | | Client credentials |
| `oidc.groups_claim` | string | `groups` | ID token claim holding the IdP groups |
| `oidc.scopes` | list | `[openid, email, profile]` | Requested scopes |
| `passkeys` | bool | `false` | Passkey sign-in and enrollment links, for running without an IdP. `public_url` must use a host name |
| `agent_tokens.max_ttl` | duration | `1h` | Lifetime of agent access tokens (at most `24h`) |
| `agent_tokens.refresh` | bool | `false` | Issue refresh tokens to agents |
| `cli_token_ttl` | duration | `12h` | Lifetime of `dbgw login` tokens |
| `session_ttl` | duration | `1h` | Lifetime of browser sessions |
| `dev_login` | bool | `false` | Password-less login for local development; only with a loopback `listen` |
| `allow_insecure_client_metadata` | bool | `false` | Allow `http://` client metadata URLs on loopback (development) |

### store

The management database: users, sessions, tokens, approval requests, grants. Use PostgreSQL for several instances ([ha.md](ha.md)).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `driver` | `sqlite` \| `postgres` | `sqlite` | |
| `path` | path | `var/dbgateway.db` | SQLite file |
| `dsn_env` | env name | | PostgreSQL DSN (required with `postgres`) |
| `sslrootcert_env` | env name | | PEM CA of the management database, added to the DSN |

### audit

See [masking-and-audit.md](masking-and-audit.md#audit-log).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `output` | `file` \| `stdout` \| `postgres` | `file` | Primary output. `postgres` requires `store.driver: postgres` |
| `dir` | path | `var/audit` | Directory of daily files (`file`) |
| `retention` | duration | `365d` | Entries older than this are deleted, after a checkpoint |
| `log_raw_sql` | bool | `false` | Record SQL with literal values |
| `no_fsync` | bool | `false` | Skip fsync after each entry (faster, less durable) |
| `dsn_env` | env name | `store.dsn_env` | Audit database for `postgres` |
| `otlp.endpoint` | `host:port` | | Also forward entries as OpenTelemetry logs over gRPC (best effort) |
| `otlp.insecure` | bool | `false` | Plaintext gRPC |
| `otlp.headers_env` | env name | | gRPC metadata as `key=value,...` (URL-encoded values) |

### sql

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allowed_functions` | list | `[]` | Functions added to the built-in allowlist, optionally schema-qualified (`public.business_days`) |

### masking

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `hmac_key_env` | env name | | Key of the `hmac` method; without it `hmac` falls back to `redact` |

### databases

A list. MySQL specifics are in [mysql.md](mysql.md), IAM authentication in [operations.md](operations.md).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | | Unique name used by callers |
| `type` | `postgres` \| `mysql` | `postgres` | |
| `labels` | map | | Used by selectors and CEL (`database.labels.env`). `env: prod` changes the default class for agents |
| `primary` | endpoint | | Required |
| `replica` | endpoint | | Used by `require.replica` |
| `limits.max_rows` | int | `1000` | Rows returned per query |
| `limits.max_bytes` | size | `1MiB` | Bytes returned per query |
| `limits.statement_timeout` | duration | `10s` | |
| `limits.lock_timeout` | duration | `2s` | |
| `search_path` | list | `[public]` | Schemas for unqualified names. MySQL: the default database only |
| `default_class` | `{human, agent}` | | Class of unclassified columns on this database |
| `docs` | map | | Descriptions and example queries for agents and people writing SQL; see [docs](#docs) |
| `backup.schema` | string | | PostgreSQL only. Save the rows approved `UPDATE`/`DELETE` statements change into new tables in this schema; see [Backups and restore](./approvals#backups-and-restore) |
| `backup.required` | bool | `false` | Deny `UPDATE`, `DELETE` and `MERGE` statements that cannot be backed up |

Endpoint keys:

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | | Required |
| `port` | int | `5432` / `3306` | |
| `dbname` | string | `postgres` | Required for MySQL (the replica inherits it) |
| `auth` | `password` \| `aws_iam` \| `gcp_iam` | `password` | IAM methods need TLS and no password; MySQL supports `password` only |
| `region` | string | AWS SDK default | `aws_iam` only |
| `read_user` | string | | Required. Grant it read access only |
| `password_env` | env name | | Password of `read_user` |
| `write_user` | string | | Runs approved writes; without it, writes to the database are denied |
| `write_password_env` | env name | | Password of `write_user` |
| `sslmode` | string | `verify-full` | PostgreSQL modes; for MySQL `disable`, `require` or `verify-full` |
| `sslrootcert` | path | | CA file |
| `sslrootcert_env` | env name | | CA as PEM in an environment variable (exclusive with `sslrootcert`) |

#### docs

Knowledge about the schema that names alone do not tell: what the database is for, what tables and columns mean, units and allowed values, and example queries known to be right. Agents get it from `list_databases` and `search_objects` ([MCP](mcp.md#schema-docs)), people from `dbgw dbs`, `dbgw search` and the SQL editor's schema list. It lives in the configuration so that it is reviewed and versioned like everything else.

```yaml
databases:
  - name: prod-main
    docs:
      description: Core OLTP database of the shop. Amounts are in JPY, tax included.
      tables:
        public.orders:
          description: One row per checkout. status is pending, paid or refunded.
          columns:
            amount: Total in JPY, tax included.
      examples:
        - title: Daily revenue
          description: Paid orders only, by UTC day.
          sql: |
            SELECT date_trunc('day', created_at) AS day, sum(amount) AS revenue
            FROM orders WHERE status = 'paid' GROUP BY 1 ORDER BY 1
```

| Key | Type | Description |
| --- | --- | --- |
| `description` | string | About the database. Returned by `list_databases` |
| `tables` | map | Key: `schema.table` (MySQL: `database.table`), also for views. Matched case-insensitively |
| `tables.*.description` | string | About the table |
| `tables.*.columns` | map | Column name to its description |
| `examples` | list | Example queries: `title` (required, unique per database), `sql` (required), `description` |

- **Database comments are kept.** `search_objects` returns the configured text as `description` and the database's own `COMMENT` as `comment` (detail `full`, as before). Nothing is merged or overwritten, so you can see where each came from; agents are told to prefer `description` when the two disagree.
- **Examples are attached to tables.** dbgateway analyzes each example with the same SQL analyzer as `execute_sql`, against the live catalog, and returns it from `search_objects` whenever one of the tables it references (after resolving `search_path`, aliases, CTEs and views) is in the result. An example that cannot be analyzed — a typo, a table that no longer exists, a statement dbgateway refuses — is never shown, and a warning is logged once. Examples are shown, not run: they go through the usual checks when an agent executes them.
- **Same visibility as the schema.** Docs are returned only to callers with search access (`viewer`, implied by `querier`) on the database, exactly like table and column names. A database the caller cannot search, or that does not exist, looks the same.
- **Metadata only.** Descriptions do not change classification or masking: a masked column with a description is still masked. Docs are shown verbatim to everyone who can search the database, so never put data values (customer names, e-mail addresses, secrets) in them.
- Keys are validated like the rest of the file: unknown keys, unqualified table names, empty entries and duplicate example titles are errors. `dbgw config validate` does not connect to the database, so whether examples reference existing tables is checked at run time (the warning above).

### groups

| Key | Type | Description |
| --- | --- | --- |
| `name` | string | Unique group name |
| `oidc_group` | string | IdP group (OIDC claim or SCIM) that makes someone a member |
| `members` | list of e-mails | Static members, for environments without an IdP |

### role_bindings

See [policies.md](policies.md#groups-and-roles).

| Key | Type | Description |
| --- | --- | --- |
| `group` / `user` | string | Exactly one: a group name or an e-mail address |
| `databases` | selector | Required |
| `roles` | list | `viewer`, `querier`, `writer`, `approver`, `admin` |
| `expires_at` | timestamp | The binding stops applying at this time (JIT) |

### default_class

`{ human: <class>, agent: <class> }`, each `public`, `masked` or `no_ai`. Overridden per database. When neither is set: `masked` for agents on `env: prod` databases, `public` otherwise.

### data_classes

| Key | Type | Description |
| --- | --- | --- |
| `columns` | list | `schema.table.column` names (exclusive with `column_pattern`) |
| `column_pattern` | regexp | Must match the whole `schema.table.column` |
| `class` | `public` \| `masked` \| `no_ai` | |
| `semantic_type` | string | A key of `semantic_types` |

Exact columns win over patterns; patterns are tried in order.

### semantic_types

A map from name to `{ method: redact | partial | hmac }`. See [masking methods](masking-and-audit.md#masking-methods).

### policies

| Key | Type | Description |
| --- | --- | --- |
| `name` | string | Unique |
| `when` | CEL | Boolean condition |
| `action` | `allow` \| `approve` \| `deny` | |
| `require.reason` | bool | Reject generic reasons |
| `require.step_up` | bool | Satisfied by approvers' step-up on `approve`; denies reads |
| `require.max_rows` | int | Lower row limit for this rule |
| `require.replica` | bool | Run reads on the replica |
| `message`, `hint` | string | Returned on deny |

Without policies, defaults apply ([policies.md](policies.md#default-policies)).

### scim

See [scim.md](scim.md).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Serve `/scim/v2` |
| `token_env` | env name | | Bearer token the IdP presents (required when enabled; use 32+ characters) |

### pii_detection

See [masking-and-audit.md](masking-and-audit.md#value-based-pii-detection).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Scan values returned to agents |
| `detectors` | list | all | `email`, `phone_jp`, `credit_card`, `my_number` |
| `action` | `mask` \| `deny` | `mask` | Mask the detected spans, or withhold the whole result |

### approvals

See [approvals.md](approvals.md).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Without it every write is denied |
| `default_max_affected_ratio` | number | `2.0` | Affected-rows limit = estimate × ratio (at least 1) |
| `step_up_max_age` | duration | `5m` | How recent step-up must be to approve or elevate (at most `1h`) |

### risk

| Key | Type | Description |
| --- | --- | --- |
| `high`, `medium` | list of CEL | Evaluated high first; no match means `low`. Cannot reference `risk` |

### approval_rules

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | | Unique |
| `when` | CEL | | Condition; may use `risk` |
| `steps[].role` / `steps[].group` | string | | Exactly one: `approver` or `admin`, or a group name |
| `steps[].count` | int | `1` | Distinct people needed for the step |
| `expire_after` | duration | `1h` | Time to finish all steps (at most `7d`) |
| `max_affected_rows` | int | | Fixed affected-rows limit |

### unmask

| Key | Type | Description |
| --- | --- | --- |
| `user` / `group` | string | Exactly one |
| `databases` | selector | Required |
| `expires_at` | timestamp | Optional end of the grant |

Applies to people only.

### break_glass

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_duration` | duration | `1h` | Longest elevation (at most `24h`) |
| `databases` | selector | | Required. Where approvers may elevate |

Requires `approvals.enabled`.

### notifications

Routes and their settings; see [notifications.md](notifications.md). Every matching route is used.

| Key | Type | Description |
| --- | --- | --- |
| `events` | list | `approval_requested`, `approval_decided`, `execution_finished`, `query_denied`, `break_glass_used`, `anomaly_detected`, `config_changed` |
| `when` | CEL | Optional condition over `database` (`name`, `labels`) and `event` (`type`, `status`, `risk`); an evaluation error does not match |
| `to.slack` | string | `#channel`, a channel ID, or `requester` (direct message) |
| `to.mention` | `approvers` | Mention the people who can act, in a channel message |
| `to.webhook_env` | env name | Webhook URL that receives the event as JSON |

Top-level settings that go with them:

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `slack.app_token_env` | env name | `SLACK_APP_TOKEN` | App-level token (Socket Mode) |
| `slack.bot_token_env` | env name | `SLACK_BOT_TOKEN` | Bot token |
| `anomaly.denials_per_10m` | int | `10` | Denials per requester in ten minutes before `anomaly_detected` |
| `anomaly.rows_per_hour` | int | `100000` | Rows returned to one requester in an hour before `anomaly_detected` |
| `notifications_language` | `en` \| `ja` | `en` | Language of notification messages |
| `notifications_webhook_secret_env` | env name | | HMAC-SHA256 key that signs webhook bodies (`X-Dbgw-Signature`) |

### auditors

A list of `{ user: <e-mail> }` or `{ group: <name> }`. They may use the audit log and user screens, as may anyone with `admin` on any database ([masking-and-audit.md](masking-and-audit.md#the-audit-log-screen)).

### console

The SQL editor; see [console.md](console.md).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `history` | bool | `true` | Keep each person's executed SQL (as typed) |
| `history_retention` | duration | `30d` | How long history is kept |
| `export` | bool | `true` | Allow CSV and JSON export |
| `export_max_rows` | int | `10000` | Rows per export (at most 1,000,000) |
