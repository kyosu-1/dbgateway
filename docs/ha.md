# High availability (multiple instances)

How to run dbgateway on multiple instances. The default management database (SQLite) supports a single instance only, so multiple instances need a PostgreSQL management database. For the deployment topology, see [architecture.md](architecture.md); for audit log outputs, see [masking-and-audit.md](masking-and-audit.md).

## 1. Topology

```
             ┌───────────────┐
  people ──► │ load balancer │ ──► dbgateway #1 ─┐
  agents     │ (TLS)         │ ──► dbgateway #2 ─┼──► management database (PostgreSQL)
             └───────────────┘ ──► dbgateway #3 ─┘     - tokens, sessions, approval requests, SCIM
                                         │              - audit log (with audit.output: postgres)
                                         └──────────► target databases (production PostgreSQL, etc.)
```

- All instances share one management database: tokens, browser sessions, OAuth codes, approval requests, break-glass elevations, and users and groups synced by SCIM.
- Sticky sessions are not needed. Any instance returns the same result (in-progress login state is in a cookie; sessions are in the management database).
- An approved request runs exactly once across instances. Each instance's background loop looks for approved requests and tries to run them, but only the instance that moves the status from `approved` to `running` (wins the conditional update) runs it. If an instance stops mid-execution, another instance marks the request as failed with an unknown result after a timeout. It is never re-run.
- Single use of authorization codes, device codes and refresh tokens is also enforced across instances with conditional updates.
- [Quota](quotas.md) usage is counted in the management database, so a person's limits hold across all instances (anomaly detection, in contrast, counts per instance).

### 1.1 Configuration

```yaml
store:
  driver: postgres           # sqlite (default) | postgres
  dsn_env: DBGW_STORE_DSN    # name of the environment variable holding the DSN

audit:
  output: postgres           # file (default) | stdout | postgres
  # dsn_env: DBGW_AUDIT_DSN  # to write the audit log to another database or role; default: store.dsn_env
  retention: 400d
```

- The DSN contains a password, so the configuration file holds only the environment variable name. Configuration validation rejects a DSN written directly in `dsn_env`.
- Example DSN: `postgres://dbgateway:<password>@mgmt-db.internal:5432/dbgateway?sslmode=verify-full&pool_max_conns=10`
- Each instance has one connection pool for the management database and one for the audit log. Make sure `pool_max_conns` (default: the larger of the CPU count and 4) × 2 × the number of instances fits in the management database's `max_connections`.
- `audit.output: postgres` requires `store.driver: postgres`.
- All instances use the same configuration file (policies, roles, databases, `server.public_url`) and the same secrets (OIDC client, the `masking.hmac_key_env` key, database passwords). To change the configuration, roll it out to all instances one by one. During a rollout, expect instances to run different configuration versions (`config_version`).
- Detecting requests stuck in `running` uses each instance's clock, so keep all instances in sync with NTP.

### 1.2 Preparing the management database

Create a dedicated database and role. dbgateway creates its tables at startup. Migrations are versioned in `schema_migrations` and serialized with an advisory lock, so they are applied once even when several instances start at the same time.

```sql
CREATE ROLE dbgateway LOGIN PASSWORD '<password>';
CREATE DATABASE dbgateway OWNER dbgateway;
```

- PostgreSQL 13 or later is expected (tests run on 17). No extensions are used.
- Timestamps are stored in UTC (`timestamptz`) and lists as `jsonb`.
- Put the management database on a different instance from the target production databases, so that what dbgateway protects and dbgateway's own state do not fail together.
- Use your managed service's features (Multi-AZ, automatic failover to a replica) for the management database's own availability. During a failover the management database cannot be written, so logins, token verification and audit log writes fail, and dbgateway rejects queries (fail closed).

## 2. Audit log

With multiple instances, there are two places to keep the audit log.

| Option | Setting | Characteristics |
| --- | --- | --- |
| One log in the management database | `audit.output: postgres` | One hash chain for all instances. Records from all instances can be searched together. Writes are serialized across instances with an advisory lock |
| A file per instance | `audit.output: file` | An independent chain per instance. Verify each instance with `dbgw audit verify --dir` and archive the files externally. Search covers only that instance's records |

### 2.1 Writing to the management database (`audit.output: postgres`)

- Lines have the same format as the files (one JSON line with `prev_hash` and `hash`). The `line` column of the `audit_log` table stores the line as is; time, request ID, event, decision, database, principal and tables are also stored in separate columns for search.
- For each write, an instance takes an advisory lock on the management database and chains the new line to the hash of the last line. The chain therefore never forks, even with multiple instances. If the write fails, the query result is not returned (fail closed, as with files).
- Lines older than `audit.retention` are deleted oldest first. Before deleting, the hash of the last deleted line is recorded in the `audit_checkpoints` table and also written to the process log (`audit checkpoint`). Lines that fail verification are not deleted.
- With OTLP forwarding (`audit.otlp`), the lines are forwarded exactly as stored in the management database (after chaining).

Verify using the configuration file:

```sh
DBGW_STORE_DSN=... dbgw audit verify --config /etc/dbgateway/dbgateway.yaml
# ok: 12345 entries in the PostgreSQL audit log, chained from genesis; last hash <hash>
```

- The first line must chain from the zero hash (genesis) or from the latest checkpoint. Modified, deleted or reordered lines, and search columns that do not match the line, print `FAILED` and exit with code 1.
- Anyone with write access to the management database can delete lines at the end. As with files, record the last hash externally every day or forward with OTLP to a separate logging system to detect truncation.
- For stronger protection, use a dedicated audit role via `audit.dsn_env` and remove its `UPDATE` privilege on `audit_log`. The table is created on first startup, so run `REVOKE UPDATE ON audit_log FROM <role>` after that. `DELETE` is still needed for retention.

### 2.2 A file per instance

Give each instance an `audit.dir` used only by that instance (not a shared file system). Multiple instances writing to the same directory break the chain. Archive and verify each instance as described in [operations.md](operations.md#3-audit-log-retention-and-verification).

## 3. Backing up and restoring the management database

**Backup**

Enable your managed service's automated backups (point-in-time recovery). For a logical backup:

```sh
pg_dump --format=custom --file=dbgateway-$(date -u +%F).dump "$DBGW_STORE_DSN"
```

The management database does not contain raw secrets such as tokens (only SHA-256 hashes), but it does contain the user list, SQL awaiting approval and the audit log. Store backups with the same care as production data.

**Restore**

Restoring to an earlier point also erases later revocations and executions. After restoring, run the following before starting dbgateway:

```sql
BEGIN;
-- Mark approval requests that may have run after the backup as failed, so they are not run again
UPDATE approval_requests
   SET status = 'failed', finished_at = now(), version = version + 1,
       result_json = '{"rows_affected":0,"row_count":0,"duration_ms":0,"error":"The management database was restored from a backup, so the result is unknown. Check the database."}'
 WHERE status IN ('approved', 'running');
-- Revoke everything so tokens and sessions revoked after the backup do not come back
UPDATE tokens SET revoked_at = now() WHERE revoked_at IS NULL;
TRUNCATE sessions, auth_codes, device_codes;
COMMIT;
```

- After the revocation, people sign in again with `dbgw login` or the browser, and agents reconnect.
- With SCIM, run a full resync (re-run provisioning) from the IdP to apply users disabled or deleted after the backup.
- If the audit log is in the management database, lines written after the restore point are lost. Reconstruct the record from the OTLP destination and the externally recorded hashes.

## 4. Migrating from SQLite

To move from a single instance (SQLite) to PostgreSQL:

1. Prepare the PostgreSQL management database as in 1.2.
2. Stop dbgateway.
3. Change the configuration to `store.driver: postgres` and `store.dsn_env` (and `audit.output: postgres` to move the audit log too).
4. Copy the SQLite data (optional).

   ```sh
   DBGW_STORE_DSN=... dbgw store import-sqlite --from /var/lib/dbgateway/dbgateway.db --config /etc/dbgateway/dbgateway.yaml
   ```

   This copies every management table (users, tokens, sessions, OAuth clients, approval requests, break-glass elevations, SCIM users and groups, and so on; not the audit log) in one transaction. It refuses to run if the target is not empty.
5. Start dbgateway, check `dbgw audit verify` and sign-in, then add instances.

dbgateway also works without the copy. In that case:

- Tokens, sessions and OAuth clients are not carried over. People sign in again and agents reconnect (MCP clients register again). These can simply be issued again.
- Pending and approved requests are not carried over. Finish them before migrating, or submit them again afterwards. Past approvals remain in the audit log.
- Users and groups synced by SCIM need a full resync from the IdP. Records of deleted users (kept to keep rejecting their logins) are not carried over, so also disable those users in the IdP.

The audit log is not migrated. Either keep `audit.output: file`, or, after switching to `postgres`, keep archiving and verifying the old files as before (the PostgreSQL chain starts from genesis).

## 5. Checklist

- [ ] All instances use the same configuration file and the same secrets
- [ ] The total of all instances' connection pools fits in the management database's `max_connections`
- [ ] The load balancer health check uses `GET /healthz`
- [ ] All instance clocks are synced with NTP
- [ ] Automated backups of the management database are enabled and the restore procedure (section 3) has been reviewed
- [ ] `dbgw audit verify` runs daily and failures are alerted
