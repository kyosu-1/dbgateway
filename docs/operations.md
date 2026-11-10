# Operations

How to run dbgateway in front of production PostgreSQL. This guide covers:

1. Connecting to databases with cloud IAM authentication (Amazon RDS / Cloud SQL)
2. Forwarding the audit log with OpenTelemetry
3. Audit log retention and tamper verification
4. The emergency bypass (direct database access without dbgateway)
5. Identity checks in the web UI (passkeys and step-up authentication) and access to audit pages
6. Prometheus metrics

For every configuration key, see the [configuration reference](configuration.md). Replace each `<...>` below with the value for your environment.

## 1. IAM authentication

Each database endpoint selects its authentication method with `auth`.

| `auth` | Used instead of a password | Where credentials come from |
| --- | --- | --- |
| `password` | The value of the environment variable named by `password_env` | — |
| `aws_iam` | An RDS authentication token (valid 15 minutes) | The standard AWS SDK chain (environment variables, profile, ECS task role, EKS Pod Identity / IRSA, EC2 instance profile) |
| `gcp_iam` | A Google OAuth 2.0 access token (valid 1 hour) | Application Default Credentials (ADC), e.g. GKE Workload Identity or a GCE service account |

IAM authentication is available for PostgreSQL databases only; MySQL supports `auth: password` (see [mysql.md](mysql.md)).

Common behavior:

- A token is fetched in `BeforeConnect` each time a new physical connection is opened and sent as the password. Tokens are reused until less than 5 minutes of validity remain (RDS: 10 minutes after issue; Google: until 5 minutes before the token expires). The database checks the token only at login, so established connections keep working after the token expires.
- If no token can be obtained, the connection fails. There is no fallback to password authentication.
- TLS is required. Set `sslmode` to `verify-full` (or `verify-ca` for a Cloud SQL per-instance CA). Configuration validation rejects `disable`, `allow` and `prefer`, which can fall back to plaintext. `require` produces a warning because it does not verify the server certificate, so the token could be intercepted.
- `password_env` and `write_password_env` cannot be set together with an IAM method.
- The write user (`write_user`) uses the same method. Grant IAM login to the write user as well.

### 1.1 Amazon RDS / Aurora (`aws_iam`)

**1. Enable IAM authentication on the instance**

```sh
aws rds modify-db-instance --db-instance-identifier <instance> \
  --enable-iam-database-authentication --apply-immediately
```

In Terraform this is `iam_database_authentication_enabled = true` (the `iam_auth` variable in [deploy/aws](../deploy/aws)).

**2. Create the database user** (connect as an administrator)

```sql
CREATE USER dbgw_iam;                -- no password
GRANT rds_iam TO dbgw_iam;           -- allow IAM login
GRANT CONNECT ON DATABASE <db> TO dbgw_iam;
GRANT USAGE ON SCHEMA public TO dbgw_iam;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dbgw_iam;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO dbgw_iam;
```

A user with `rds_iam` can no longer log in with a password. GRANTs are the last line of defense for reads, so give the read user nothing beyond SELECT.

**3. Allow `rds-db:connect` for dbgateway's runtime role**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": [
        "arn:aws:rds-db:<region>:<account-id>:dbuser:<DbiResourceId>/dbgw_iam",
        "arn:aws:rds-db:<region>:<account-id>:dbuser:<DbiResourceId>/dbgw_writer"
      ]
    }
  ]
}
```

`<DbiResourceId>` is the instance's resource ID (starts with `db-`; `aws rds describe-db-instances --query 'DBInstances[].DbiResourceId'`), not the instance name. For Aurora, use the cluster resource ID (starts with `cluster-`).

**4. Configure dbgateway**

```yaml
databases:
  - name: prod-main
    primary:
      host: <instance>.<id>.<region>.rds.amazonaws.com
      auth: aws_iam
      region: <region>            # default: the standard AWS config (AWS_REGION, etc.)
      read_user: dbgw_iam
      sslmode: verify-full
      sslrootcert: /etc/dbgateway/rds-global-bundle.pem
```

Download the CA bundle from `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`. `host` and `port` are part of the token signature, so use the RDS endpoint name itself, not a CNAME or other alias.

Notes:

- IAM authentication limits the rate of new connections (AWS does not recommend it above a few hundred new connections per second). dbgateway pools connections, so this is normally not an issue, but keep it in mind when restarting many instances at once.
- Set `rds.force_ssl=1` in the parameter group so the database also rejects plaintext connections.

### 1.2 Cloud SQL for PostgreSQL (`gcp_iam`)

**1. Enable IAM authentication and require TLS**

```sh
gcloud sql instances patch <instance> \
  --database-flags=cloudsql.iam_authentication=on \
  --ssl-mode=ENCRYPTED_ONLY
```

`--database-flags` replaces the existing flags, so include any other flags you already have. dbgateway connects directly without a client certificate, so use `ENCRYPTED_ONLY` (`TRUSTED_CLIENT_CERTIFICATE_REQUIRED` does not work).

**2. Register the IAM user in the database**

```sh
# Service account (recommended). The database user name is the email without .gserviceaccount.com
gcloud sql users create dbgw@<project>.iam --instance=<instance> --type=cloud_iam_service_account
# A person's account (for testing)
gcloud sql users create <user@example.com> --instance=<instance> --type=cloud_iam_user
```

A registered user has no privileges yet. GRANT them as an administrator (quote the user name).

```sql
GRANT CONNECT ON DATABASE <db> TO "dbgw@<project>.iam";
GRANT USAGE ON SCHEMA public TO "dbgw@<project>.iam";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "dbgw@<project>.iam";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "dbgw@<project>.iam";
```

**3. Grant IAM roles**

| Role | Purpose |
| --- | --- |
| `roles/cloudsql.instanceUser` | Login with IAM database authentication (`cloudsql.instances.login`). Required |
| `roles/cloudsql.client` | Connecting through the Cloud SQL Auth Proxy or connectors, and reading instance metadata. Not needed for dbgateway's direct connection; grant it if you use the Auth Proxy in operations |

```sh
gcloud projects add-iam-policy-binding <project> \
  --member=serviceAccount:dbgw@<project>.iam.gserviceaccount.com --role=roles/cloudsql.instanceUser
gcloud projects add-iam-policy-binding <project> \
  --member=serviceAccount:dbgw@<project>.iam.gserviceaccount.com --role=roles/cloudsql.client
```

**4. Server CA and sslmode**

The Cloud SQL server certificate depends on the CA mode.

| `server_ca_mode` | Server certificate | sslmode | `host` |
| --- | --- | --- | --- |
| `GOOGLE_MANAGED_INTERNAL_CA` (per-instance CA, default) | `CN=<project>:<instance>`. No IP SAN (a DNS name only with PSC) | `verify-ca`. The CA is dedicated to the instance, so verifying the CA also verifies the server's identity | IP address |
| `GOOGLE_MANAGED_CAS_CA` (shared CA) | SAN contains the instance DNS name (`<uid>.<project-dns-label>.<region>.sql.goog`) | `verify-full`. The CA is shared, so the host name must be verified | DNS name (create the DNS record yourself) |

```sh
# Per-instance CA
gcloud sql instances describe <instance> --format='value(serverCaCert.cert)' > server-ca.pem
# Shared CA
gcloud sql ssl server-certs list --instance=<instance> --format='value(ca_cert.cert)' > server-ca.pem
```

To rotate the CA, put both the old and new CA in one file for `sslrootcert`, and remove the old one after the switch (`gcloud sql ssl server-ca-certs list`).

**5. Configure dbgateway**

```yaml
databases:
  - name: prod-analytics
    primary:
      host: 10.20.0.5              # private IP (recommended)
      auth: gcp_iam
      read_user: dbgw@<project>.iam
      sslmode: verify-ca
      sslrootcert: /etc/dbgateway/cloudsql-server-ca.pem
```

Notes:

- Credentials come from ADC. Use Workload Identity on GKE and the VM service account on GCE; do not use service account key files. Tokens are requested with the `https://www.googleapis.com/auth/sqlservice.login` scope (the same scope as the Cloud SQL Go connector). User ADC and metadata-server tokens ignore the requested scope and return a `cloud-platform` token, which also works for login.
- When testing locally with your own ADC, rerun `gcloud auth application-default login` with the same account as the Cloud SQL IAM user. If ADC belongs to another account or is stale, login fails with `Cloud IAM user authentication failed` (SQLSTATE 28000). The gcloud login and ADC are separate credentials.
- User names are lowercase only. Writing the full service account email fails configuration validation.
- In production, connect over a private IP (Private Service Access or PSC), not a public IP.

**Why not the Cloud SQL Go connector**

dbgateway does not plug `cloud.google.com/go/cloudsqlconn` into pgx's `DialFunc`. A direct TLS connection can be verified securely (see the table above), while the connector would require the Cloud SQL Admin API, `roles/cloudsql.client`, a network path to the Admin API and extra dependencies, adding failure points outside the database. If a setup where host name verification is hard (PSC, shared CA) becomes necessary, an `instance_connection_name` setting and the connector may be added.

### 1.3 Testing in a disposable environment

`deploy/aws` (RDS) and `deploy/gcp` (Cloud SQL) contain Terraform for disposable test environments. The command printed at the end of `setup.sh` runs `TestIAMIntegration`, which logs in with IAM authentication and checks `current_user`. See the README in each directory. Always run `terraform destroy` when you are done.

## 2. Forwarding the audit log with OpenTelemetry

```yaml
audit:
  output: file                    # primary output
  dir: /var/lib/dbgateway/audit
  otlp:
    endpoint: otel-collector.internal:4317   # host:port (no scheme)
    insecure: false                          # true only for a collector on the same host
    headers_env: DBGW_OTLP_HEADERS           # optional; gRPC metadata
```

**Behavior**

- Only the primary output (file / stdout / postgres) decides whether a request succeeds. If the primary output cannot be written, no result is returned (fail closed).
- Forwarding is best effort. Each line written to the primary output is put on a bounded queue per forwarder (4096 entries), and a separate goroutine sends up to 256 entries at a time over OTLP/gRPC. When the queue is full or a send fails, the line is dropped from forwarding; drops are counted and logged at most once per minute (`audit forwarder queue full; entry dropped`, `audit forwarding failed`). On shutdown, totals for sent, dropped and failed entries are logged.
- An unreachable collector does not block startup (the connection is opened lazily). A missing `headers_env` variable does block startup.
- TLS is verified against the system CAs. For a collector with an internal CA, set `OTEL_EXPORTER_OTLP_CERTIFICATE` to the CA file (the standard OpenTelemetry environment variables apply).

The `headers_env` value is a comma-separated list of `key=value` pairs with URL-encoded values.

```sh
export DBGW_OTLP_HEADERS='authorization=Bearer%20<token>,x-tenant=<tenant>'
```

**Log records**

| Field | Content |
| --- | --- |
| Body | The audit log line itself (JSON, including `hash`). The receiver can recompute the hash |
| Attributes | Each field flattened under `dbgw.`, e.g. `dbgw.request_id`, `dbgw.principal.human`, `dbgw.principal.agent`, `dbgw.database`, `dbgw.decision`, `dbgw.rule`, `dbgw.analysis.tables` (string array), `dbgw.result.rows`, `dbgw.hash`, `dbgw.prev_hash`. The SQL text is in the body only, not in attributes |
| Timestamp | The audit log `ts` |
| Event name | `dbgateway.audit` |
| Severity | WARN for `deny` and `error`, INFO otherwise |
| Resource | `service.name=dbgateway` |

The audit log contains no result values, so neither does the forwarded data. SQL literals are redacted by default (`log_raw_sql: false`).

**Collector example** (send to a SIEM through a collector)

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        tls:
          cert_file: /etc/otelcol/tls.crt
          key_file: /etc/otelcol/tls.key
processors:
  batch: {}
exporters:
  otlphttp/siem:
    endpoint: https://<siem-endpoint>
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp/siem]
```

Forwarding is best effort, so entries can be missing. The primary output is the source of truth. In the SIEM, gaps show up as breaks in the `dbgw.prev_hash` → `dbgw.hash` chain.

## 3. Audit log retention and verification

See [masking-and-audit.md](masking-and-audit.md) for the audit log format and hash chain.

**Retention**

- With `audit.output: file`, dbgateway writes one file per UTC day (`audit-YYYY-MM-DD.jsonl`) in `audit.dir` and fsyncs every line. `no_fsync: true` disables this, but the last lines may be lost on a crash.
- Files older than `audit.retention` (default 365 days) are deleted. Before deleting a file, its last hash is recorded in `checkpoints.jsonl` and also written to the process log (`audit checkpoint`). The remaining files verify from that checkpoint.
- Files that fail verification (tampered) are not deleted.
- `audit.output: stdout` restarts the hash chain on every start. Use `file` (or `postgres`, see [ha.md](ha.md)) in production when you need a verifiable history.
- For long-term, tamper-resistant storage, copy the previous day's file every day to write-once storage (S3 Object Lock, GCS bucket lock, etc.). Also ship the process log (including checkpoints) to a separate logging system.

**Verification**

```sh
dbgw audit verify --dir /var/lib/dbgateway/audit
# ok: 12345 entries in 30 files, chained from genesis; last hash <hash>
```

- Recomputes the hash of every line and checks the `prev_hash` chain. Modified, deleted or reordered lines print `FAILED` and exit with code 1.
- Run it daily from cron or CI and alert the security channel on failure. Recording the last hash externally (in a ticket or another logging system) also detects truncation at the end.
- If verification fails, make the directory read-only to preserve it, then compare it with the external copies and the OTLP destination to find which lines changed.

**Search**

Audit log search (the `/audit` page and its API) reads entries newest first and filters by time range, principal (substring of the human or agent name), database, decision, event, table and request ID. Files are read backwards in chunks, so memory use stays constant however large the log is.

## 4. Emergency bypass (direct database access)

Connect to the database directly, bypassing dbgateway, only during an incident when dbgateway is down and you cannot wait for it to recover. If dbgateway is running, use its break-glass elevation first (an approver uses it for a limited time, with a reason and step-up authentication; see [approvals.md](approvals.md)). The bypass skips all of dbgateway's analysis, policies, masking and auditing, so it is the last resort.

### 4.1 Preparation (in normal times)

**Sealed credentials**

- Create an emergency database user (e.g. `dbgw_breakglass`) and keep it `NOLOGIN`. Do not put its credentials in dbgateway's configuration or runtime environment.
- Seal the credentials needed to enable it somewhere separate from dbgateway, using one or both of:
  - **Seal with cloud IAM (recommended)**: On RDS, grant `rds_iam` to `dbgw_breakglass` and create a dedicated IAM role allowed `rds-db:connect`. Only a few named people can assume this role, with MFA. On Cloud SQL, do not grant `roles/cloudsql.instanceUser` to a dedicated group in normal times; grant it with a time-bound condition only in an emergency.
  - **Seal a password**: Store the password in an emergency vault of your password manager, or in a secret manager that logs access (AWS Secrets Manager, Secret Manager), and limit who can retrieve it. Require two people (with approval) to retrieve it.
- Treat the administrator user's credentials (the RDS master user, Cloud SQL `postgres`) the same way.

**Alerting**

Detect use at both the database and the cloud layer so that every use triggers an alert.

- Database: set `log_connections = on`, detect logins by `dbgw_breakglass` and the administrator user in the logs, and alert the security channel and administrators (CloudWatch Logs metric filters, Cloud Logging log-based alerts). If pgaudit is available, log every operation by this user.
- Cloud: detect AssumeRole on the emergency IAM role, secret retrieval (`GetSecretValue`, `AccessSecretVersion`) and IAM grants in CloudTrail / Cloud Audit Logs, and alert.
- Send these alerts to the same destination as dbgateway's `break_glass_used` notification (see [notifications.md](notifications.md)).

**Network path**

Normally only dbgateway has a network path to the database. Decide the emergency path in advance (SSM Session Manager port forwarding, Cloud SQL Auth Proxy, a bastion host that is normally stopped, etc.), and log and alert on its use too.

**Drills**

Once a quarter, run the whole procedure in a test environment and confirm that alerts arrive, credentials can be retrieved, and they can be disabled and rotated afterwards.

### 4.2 Procedure (in an emergency)

1. **Declare**: Record an incident and post the reason for the bypass, the planned work, the operator and the witness in the security channel (a person posts first, separately from automatic alerts).
2. **Two people**: The operator and the witness are different people; the witness watches the session (e.g. by screen sharing).
3. **Retrieve credentials**: Assume the emergency IAM role with MFA, or retrieve the secret. With a password, enable the user for a limited time with `ALTER ROLE dbgw_breakglass LOGIN VALID UNTIL '<two hours from now>'`.
4. **Connect**: Connect with TLS verification and record the session.

   ```sh
   script -q breakglass-$(date -u +%Y%m%dT%H%M%SZ).log
   psql "host=<host> dbname=<db> user=dbgw_breakglass sslmode=verify-full sslrootcert=<ca>"
   ```

   ```sql
   \set ECHO all
   SET default_transaction_read_only = on;   -- read only until a write is needed
   SET statement_timeout = '30s';
   ```

5. **Do the minimum**: Run writes one at a time: `BEGIN`, check the affected row count, then `COMMIT`. Paste the SQL you ran into the incident record.
6. **Close**: Disconnect, set `ALTER ROLE dbgw_breakglass NOLOGIN`, change the password and seal it again (with IAM, remove the temporary grant). Close the emergency network path. Post in the channel that you are done.

### 4.3 Post-incident review

Hold a review within two business days of any use.

- Collect: the incident record, the `script` log, database logs (connections and pgaudit), CloudTrail / Cloud Audit Logs, alert records, and dbgateway's audit log for the same period.
- Check: whether the declaration and alerts came before the operations, whether the operations stayed within the incident's scope, whether the SQL run matches the database logs, and whether disabling and rotation are complete.
- Decide: why dbgateway (including break-glass elevation) could not handle it, and what to change so the bypass is not needed next time (redundancy, break-glass elevation scope, procedure improvements, etc.).
- Administrators and the security team approve the review result and keep it in the incident record. Fix procedural gaps (an alert did not arrive, disabling was forgotten, etc.) before the next drill.

## 5. Web UI identity checks and access

See [authentication.md](authentication.md) for sign-in methods and [approvals.md](approvals.md) for approvals and break-glass elevation.

### 5.1 Passkeys

- The passkey (WebAuthn) RP ID is the host name of `server.public_url`. IP addresses cannot be used (passkeys are then disabled, and `auth.passkeys: true` is a configuration error). Changing the host name invalidates registered passkeys.
- With an IdP, each person registers a passkey from "Add passkey" on their account page. Adding one requires re-authenticating with the IdP first.
- With `auth.passkeys: true`, people can sign in with a passkey on the login page. Use this when there is no IdP. The first passkey is registered from a one-time link (valid 24 hours) produced by running the following on the server. Give the link only to that person, over a trusted channel.

```sh
dbgw passkey enroll --config /etc/dbgateway/dbgateway.yaml --email alice@example.com
```

- When combined with an IdP, people removed from the IdP can still sign in with a passkey. Disable them through SCIM, or do not enable passkey sign-in.

### 5.2 Step-up authentication (before approvals and break-glass elevation)

Approving a request and starting break-glass elevation require an identity check within `approvals.step_up_max_age` (default 5 minutes). The check can be a passkey, IdP re-authentication (requested with `prompt=login` and `max_age=0`; the ID token's `auth_time` must be within the last 5 minutes), or the re-confirm button of the development login (loopback only). IdP re-authentication is unavailable if the IdP does not return `auth_time`.

### 5.3 Audit log and user pages

The audit log search (`/audit`) and the user pages (`/users`) are available to people and groups listed in `auditors`, and to anyone with the `admin` role on any database. Audit log search works with `audit.output: file` or `postgres`, not with `stdout`.

```yaml
auditors:
  - group: security
  - user: alice@example.com
```

## 6. Metrics

dbgateway can serve Prometheus metrics on a separate listener. It is off by default.

```yaml
server:
  listen: 0.0.0.0:8443
  metrics_listen: 127.0.0.1:9090   # GET /metrics
```

- `/metrics` is served **only** on `metrics_listen`, never on `listen`. The main listener is reachable by every user and agent, and metrics reveal operational details (database names, request rates, error rates). The metrics listener serves nothing else (`/healthz` stays on `listen`).
- `/metrics` has no authentication. Keep `metrics_listen` on loopback (with a sidecar or node agent scraping it), or bind it to a private interface and allow only Prometheus to reach it (security group, firewall, Kubernetes NetworkPolicy). Configuration validation prints a warning for non-loopback addresses.
- `metrics_listen` must not use the same port as `listen` on the same (or the wildcard) address. If the port is taken, `dbgw serve` fails at startup.
- Counters start at zero when the process starts; use `rate()` / `increase()`. With several instances, each instance is scraped separately.

**Metrics**

Labels have small, fixed sets of values. `database` is a configured database name; it is empty when a request named a database that does not exist, so names made up by callers never become labels. E-mail addresses, agent names, SQL, table names and request IDs are never labels: use the [audit log](masking-and-audit.md#audit-log) for those.

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `dbgateway_requests_total` | counter | `event`, `database`, `kind`, `decision`, `stage` | Finished requests. `event`: `query`, `export`, `search`, `explain`. `kind`: `human`, `agent`. `decision`: `allow`, `deny`, `approve` (submitted for approval, or a break-glass write), `error` (database unavailable, execution failed, or the audit log could not be written). `stage`: `parse`, `role`, `policy`, or empty |
| `dbgateway_request_duration_seconds` | histogram | `event`, `database`, `decision` | Time to handle a request, including analysis, the database and the audit write |
| `dbgateway_rows_returned` | histogram | `database`, `kind` | Rows returned by allowed reads (`query` and `export`) |
| `dbgateway_approval_transitions_total` | counter | `database`, `status` | Approval request state changes: `submitted`, `step_approved` (one step of a multi-step rule), `approved`, `rejected`, `canceled`, `expired`, `succeeded`, `failed` |
| `dbgateway_events_total` | counter | `type` | [Events](notifications.md) emitted: `approval_requested`, `approval_decided`, `execution_finished`, `query_denied`, `break_glass_used`, `anomaly_detected` (only when notifications are configured), `config_changed` |
| `dbgateway_audit_write_failures_total` | counter | | Audit entries that could not be written to the primary output. Each one failed a request closed |
| `dbgateway_audit_forwarded_records_total` | counter | `forwarder`, `result` | Audit forwarding (`forwarder="otlp"`), by `result`: `sent`, `dropped` (queue full), `failed`. Only with `audit.otlp` |
| `dbgateway_notification_events_total` | counter | `result` | Events offered to notifications: `published` (queued) or `dropped` (queue full). Only with notifications |
| `dbgateway_notification_deliveries_total` | counter | `result` | Slack posts and webhook requests: `delivered`, `failed` (after retries), `skipped` (e.g. no linked Slack user). Only with notifications |
| `dbgateway_catalog_loads_total` | counter | `database`, `result` | Catalog (schema) loads from a database: `ok` or `error` |
| `dbgateway_catalog_load_duration_seconds` | histogram | `database` | Time to load a catalog |
| `dbgateway_db_pool_connections` | gauge | `database`, `pool`, `state` | Open connections by `state` (`in_use`, `idle`). `pool`: `read`, `replica`, `write`. Reported once the database has been used since the start |
| `dbgateway_db_pool_max_connections` | gauge | `database`, `pool` | Pool size limit (0: unlimited) |
| `dbgateway_db_pool_waits_total` | counter | `database`, `pool` | Connection acquisitions that had to wait for a free connection |
| `dbgateway_db_pool_wait_seconds_total` | counter | `database`, `pool` | Total time spent waiting for a connection |
| `dbgateway_build_info` | gauge | `version`, `config_version` | Always 1. `config_version` is the version recorded in the audit log, useful to follow configuration rollouts |
| `go_*`, `process_*` | | | Go runtime and process metrics |

**Example alerts**

```yaml
groups:
  - name: dbgateway
    rules:
      - alert: DbgatewayAuditWriteFailures      # requests are failing closed
        expr: increase(dbgateway_audit_write_failures_total[5m]) > 0
      - alert: DbgatewayRequestErrors
        expr: |
          sum by (database) (rate(dbgateway_requests_total{decision="error"}[10m]))
            / sum by (database) (rate(dbgateway_requests_total[10m])) > 0.1
        for: 10m
      - alert: DbgatewayCatalogLoadErrors       # usually the database is unreachable
        expr: increase(dbgateway_catalog_loads_total{result="error"}[10m]) > 0
      - alert: DbgatewayNotificationFailures
        expr: increase(dbgateway_notification_deliveries_total{result="failed"}[30m]) > 0
      - alert: DbgatewayApprovedWritesFailing
        expr: increase(dbgateway_approval_transitions_total{status="failed"}[1h]) > 0
```
