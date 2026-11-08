# MySQL adapter

In addition to PostgreSQL, dbgateway supports MySQL (8.0 or later; 8.4 LTS recommended). Parsing, policies, masking and the audit log are shared with PostgreSQL; database-specific differences are confined to `internal/adapter/mysql`.

- Parser: the TiDB SQL parser (`github.com/pingcap/tidb/pkg/parser`)
- Driver: `github.com/go-sql-driver/mysql`

## Configuration

```yaml
databases:
  - name: prod-mysql
    type: mysql
    labels: { env: prod }
    primary:
      host: mysql.internal
      port: 3306              # default 3306
      dbname: app             # required; the default database
      read_user: dbgw_reader
      password_env: DBGW_MYSQL_READER_PASSWORD
      sslmode: verify-full    # disable | require | verify-full (default verify-full)
      sslrootcert: /etc/dbgateway/mysql-ca.pem
    replica:                  # optional; dbname defaults to the primary's
      host: mysql-replica.internal
      read_user: dbgw_reader
      password_env: DBGW_MYSQL_READER_PASSWORD
    limits:
      max_rows: 1000
      max_bytes: 1MiB
      statement_timeout: 10s  # sets max_execution_time
      lock_timeout: 2s        # sets lock_wait_timeout / innodb_lock_wait_timeout (rounded up to seconds)
```

- **Schema = MySQL database.** Data classes (`data_classes`) and the audit log name columns as `database.table.column`, for example `app.users.email`.
- **`search_path` can only be `[dbname]`.** MySQL resolves unqualified table names only in the default database, so either omit `search_path` or set it to a single element equal to `dbname` (anything else is a configuration error). Tables in other databases can be read by qualifying them as `other_db.table` (if grants and policies allow).
- In `sql.allowed_functions`, write a function name (`my_func`) or, for a stored function, the name qualified with its database (`app.my_func`). A qualified name matches only when the call is qualified.

### TLS (`sslmode`)

| `sslmode` | Behavior |
| --- | --- |
| `disable` | No TLS (warns for non-loopback prod databases) |
| `require` | Encrypts with TLS but does not verify the server certificate |
| `verify-full` | Verifies the server certificate against `sslrootcert` (the system roots if omitted) and checks the host name |

`allow` / `prefer` / `verify-ca` are not available for MySQL (configuration error). go-sql-driver cannot cleanly express "verify the CA but not the host name", so there is no `verify-ca`. For Amazon RDS / Aurora, set `sslrootcert` to the RDS CA bundle and use `verify-full`.

### Read-only user

```sql
CREATE USER 'dbgw_reader'@'%' IDENTIFIED BY '...';
GRANT SELECT, SHOW VIEW ON app.* TO 'dbgw_reader'@'%';
```

- `SHOW VIEW` is needed to read view definitions (`information_schema.VIEWS.VIEW_DEFINITION`). dbgateway cannot trace column lineage through a view whose definition it cannot read, so queries that reference such a view are classified as unknown and are never allowed automatically.
- Do not grant administrative privileges such as `PROCESS`, `FILE` or `SUPER`, or privileges on `mysql` / `performance_schema`.

## sql_mode

dbgateway fixes `sql_mode` to the following value in every session, and the parser tokenizes in the same mode. This keeps the way strings, identifiers and comments are delimited identical between the statement that was analyzed and the statement that runs.

```
ANSI_QUOTES,NO_BACKSLASH_ESCAPES,ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,
NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION
```

What this means for users (people and AI agents):

- **`ANSI_QUOTES`: `"..."` is an identifier (as in PostgreSQL).** Always write strings as `'...'`. `WHERE name = "alice"` refers to a column named `alice`; since no such column exists, the query is classified as unknown or fails in the database. Identifiers can also be written with backquotes `` `...` ``.
- **`NO_BACKSLASH_ESCAPES`: a backslash inside a string is an ordinary character.** Escape a quote by doubling it (`'it''s'`). `'\n'` is the two characters `\` and `n`, not a newline. This closes the classic gap where the client-side parser and the server interpret escapes differently.
- The remaining flags are the MySQL 8.4 defaults.
- Applications that use a different `sql_mode` are unaffected; the mode applies only to dbgateway's sessions.

View definitions are parsed in a different mode (`ANSI_QUOTES` only), matching the format MySQL writes to `information_schema` (identifiers in backquotes, strings with backslash escapes).

## Runtime safeguards

- Reads use a dedicated connection and run in this order:
  1. `SET SESSION sql_mode = ..., time_zone = '+00:00', max_execution_time = <statement_timeout>, lock_wait_timeout = <lock_timeout>, innodb_lock_wait_timeout = <lock_timeout>`
  2. `START TRANSACTION READ ONLY`
  3. Run the statement as a server-side prepared statement (`COM_STMT_PREPARE`). Client-side interpolation (`interpolateParams`) and multiple statements (`multiStatements`) are disabled
  4. Read the result with the row and byte limits, and keep counting the total rows after the limit is reached
  5. `ROLLBACK`
- **Each connection is discarded after one use.** MySQL has no SQL statement that resets a session (like PostgreSQL's `DISCARD ALL`), and go-sql-driver does not send `COM_RESET_CONNECTION`, so connections are closed instead of returned to the pool. Reconnecting per request costs some latency (a few to tens of milliseconds with TLS), but session state never leaks into the next request.
- `LOAD DATA LOCAL INFILE` is also refused on the client side (`allowAllFiles` is disabled and no readable files are registered).
- Writes (executed after approval) open a read-write transaction as `write_user` and commit only if the affected row count is within the limit. The count is the number of matched rows: `CLIENT_FOUND_ROWS` is enabled, so rows whose values do not change are counted too. MySQL has no RETURNING, so writes return no result rows. MySQL refuses EXPLAIN of a write inside a READ ONLY transaction, so write estimates (EXPLAIN) run in a read-write transaction as `write_user` that is always rolled back.
- Estimates (`estimate`) come from `EXPLAIN FORMAT=JSON`: the row count is the maximum of `rows_produced_per_join` (or `rows_examined_per_scan` if absent) over the tables of the outer query, and the cost is `query_cost` (`estimated_rows` / `estimated_total_cost` from `explain_json_format_version=2` are also supported). Stale statistics produce inaccurate estimates; run `ANALYZE TABLE` as needed.

### Value conversion

| MySQL type | Returned value |
| --- | --- |
| Integers | Number (`BIGINT UNSIGNED` values of 2^63 or more as strings) |
| `DECIMAL` | String (to avoid losing precision) |
| `FLOAT` / `DOUBLE` | Number |
| `DATETIME` / `TIMESTAMP` | RFC 3339 string (UTC; the session `time_zone` is `+00:00`) |
| `DATE` | `YYYY-MM-DD` |
| `TIME` | `HH:MM:SS` string |
| `JSON` | Parsed JSON value |
| `BINARY` / `VARBINARY` / `BLOB` / `GEOMETRY` | `\x` + hex (same as PostgreSQL `bytea`) |
| `BIT` | Number |
| String types, `ENUM` / `SET` | String |

### Database errors

MySQL error messages can contain values (for example 1292 `Truncated incorrect DOUBLE value: '...'`). `mysql.DescribeError` returns the message only for errors known to contain nothing but identifiers (unknown column or table, syntax errors, missing privileges, and so on); for anything else it returns only the error number. Timeouts (3024) and lock wait timeouts (1205) get dedicated messages.

## Rejected at the parse stage

As with PostgreSQL, the following are rejected regardless of configuration (fail closed). `testdata/bypass/mysql.yaml` contains the bypass test corpus.

- Unparseable SQL, multiple statements, empty statements
- Executable comments `/*! ... */`, `/*!NNNNN ... */`, `/*T! ... */`, `/*M! ... */` and optimizer hints `/*+ ... */`. **These are rejected even inside string literals** (the check is a simple context-free scan, so quoting cannot fool it)
  - Why: MySQL ignores the contents of `/*!NNNNN ... */` when the version number is newer than the server, but the parser always parses them. With `SELECT /*!99999 email AS id, */ id FROM users`, the analyzed columns and the columns actually returned differ, which could bypass masking. The hints `MAX_EXECUTION_TIME` / `SET_VAR` can lift session limits
- Control characters (other than newline and tab) and invalid UTF-8 (MySQL and the parser can disagree on them, for example when detecting `--` comments)
- Transaction control (`BEGIN` / `START TRANSACTION` / `COMMIT` / `ROLLBACK` / `SAVEPOINT` / `RELEASE SAVEPOINT` / `XA`)
- `SET` (all forms: `SET @x`, `SET ROLE`, `SET PASSWORD`, `SET NAMES`, `SET TRANSACTION`, ...)
- User variables (references to `@x` and `@x := ...`) and system variables (`@@...`). Use `VERSION()` for the server version and `DATABASE()` for the default database
- Parameters (`?`)
- `LOAD DATA` / `LOAD XML` / `IMPORT INTO`, `SELECT ... INTO OUTFILE / DUMPFILE / @var`
- `FOR UPDATE` / `FOR SHARE` / `LOCK IN SHARE MODE`, `LOCK TABLES` / `UNLOCK TABLES`
- `HANDLER`, `CALL`, `DO`, `PREPARE` / `EXECUTE` / `DEALLOCATE`, `USE`, `KILL`, `FLUSH`, `SHUTDOWN` and other administrative statements
- `EXPLAIN` (with or without `ANALYZE`), `DESCRIBE`, `SHOW` (use the `search_objects` tool to look up tables and columns)
- `SQL_CALC_FOUND_ROWS`
- Functions not on the allowlist

User management (`GRANT` / `REVOKE` / `CREATE USER`, ...), `ANALYZE TABLE` / `OPTIMIZE TABLE`, and `CREATE` / `ALTER` / `DROP` / `RENAME` are classified as DDL (`stmt.kind == "ddl"`); `INSERT` / `REPLACE` / `UPDATE` / `DELETE` (including multi-table forms) as writes; and `TRUNCATE` as `truncate`. Whether an `UPDATE` / `DELETE` has a `WHERE` clause is in `stmt.has_where`.

### Function allowlist

By default only side-effect-free built-in functions are allowed (aggregate, window, string, numeric, date, JSON, hash, and information functions such as `VERSION()`). The following are not included by default:

| Function | Reason |
| --- | --- |
| `LOAD_FILE` | Reads files on the server |
| `SLEEP`, `BENCHMARK` | Stalling / load |
| `GET_LOCK`, `RELEASE_LOCK`, `RELEASE_ALL_LOCKS`, `IS_FREE_LOCK`, `IS_USED_LOCK` | Locks |
| `MASTER_POS_WAIT`, `SOURCE_POS_WAIT`, `WAIT_FOR_EXECUTED_GTID_SET`, ... | Waiting on replication |
| `group_replication_*`, `asynchronous_connection_failover_*` | Replication control |
| `LAST_INSERT_ID`, `FOUND_ROWS`, `ROW_COUNT` | Session state (`LAST_INSERT_ID(expr)` sets a value) |
| `UUID_SHORT` | Advances a server-wide counter (harmless, but excluded because it changes state) |
| `NEXTVAL` / `SETVAL` / `LASTVAL` | Sequences |
| `PASSWORD`, `ENCODE`, `DECODE`, `VALIDATE_PASSWORD_STRENGTH` | Removed or password-related |
| Stored functions, UDFs (`sys_exec` / `sys_eval`, ...) | Unknown behavior |

Spatial functions (`ST_*`) and some encryption functions are also excluded by default. Add them with `sql.allowed_functions` if needed.

## Column lineage

With the same rules as PostgreSQL, dbgateway traces each result column, and each column used in conditions, aggregation and ordering, back to the columns of the underlying tables.

- Tables, aliases, `*` / `t.*` / `db.t.*`, derived tables (including `LATERAL`), CTEs (recursive CTEs are iterated to a fixed point)
- Views: definitions from `information_schema.VIEWS` are expanded recursively. Conditions inside a view were not chosen by the user, so they are not recorded as the user's column usage
- Joins: `ON`, `USING`, `NATURAL` (in MySQL's column order: common columns, then the remaining columns of the first table, then those of the second; with `RIGHT JOIN` the right table is the first). Common columns of `USING` / `NATURAL` are compared, so they are recorded as filter
- Subqueries in expressions (scalar, `EXISTS`, `IN`, `ANY` / `ALL`), `UNION` / `INTERSECT` / `EXCEPT`, window functions, `GROUP_CONCAT(... ORDER BY ...)`
- References to aliases and positions (`ORDER BY 2`) in `GROUP BY` / `HAVING` / `ORDER BY`. MySQL prefers either the alias or the input column depending on the clause, so a name that matches both is recorded as using both columns (erring on the safe side)
- The usage categories are the same as for PostgreSQL (output / filter / group / order / other / write)

### Case sensitivity of names

- Column names are matched case-insensitively (as in MySQL).
- Table and database names may be case-sensitive in MySQL depending on `lower_case_table_names` (case-sensitive by default on Linux). dbgateway's catalog looks up tables case-insensitively, so **when two tables differ only in case (`Users` and `users`), both are dropped from the catalog** and references to them are classified as unknown. A name never resolves to the wrong table.
- Table aliases prefer an exact match; if a name matches several aliases that differ only in case, the query is classified as unknown.

## Limitations

- Syntax the TiDB parser does not support cannot be parsed and is rejected. Examples: `JSON_TABLE`, column lists on derived tables (`AS t(a, b)`), `SELECT ... INTO @var` / `INTO DUMPFILE`, `BEGIN WORK`, `HANDLER`, `XA`, `CHECKSUM TABLE`, `CREATE TRIGGER` / `CREATE EVENT`.
- TiDB-specific syntax (`AS OF TIMESTAMP`, `TABLESAMPLE`, hints, ...) is rejected.
- Queries containing `/*+` or `/*!` inside string literals are rejected (see above).
- Writes cannot return result rows (MySQL has no RETURNING).
- `sql_mode` is fixed and users cannot change it (`SET` is rejected).
- The catalog reads `information_schema.COLUMNS` / `TABLES` / `VIEWS`, limited to what the read-only user can see. Views in `mysql` / `performance_schema` / `sys` / `information_schema` are not expanded and are treated as base tables. `search_objects` hides these system schemas unless a schema is given explicitly.
- `INVISIBLE` columns (including `my_row_id` created by `sql_generate_invisible_primary_key`) are left out of the catalog. `SELECT *` does not return them, so including them would make the expansion of `*` differ from the actual result. Referencing them by name is classified as unknown.
- Because a new connection is opened for each request, per-request latency is somewhat higher than with PostgreSQL.

## Development environment and tests

```sh
docker compose -f examples/dev/mysql/compose.yaml up -d --wait   # MySQL 8.4 on 127.0.0.1:53306
go test ./internal/adapter/mysql/                                 # unit tests (parsing, bypass corpus)
go test -tags integration ./internal/adapter/mysql/               # integration tests against a real database
```

The sample schema and data (`users`, `subscriptions`, `orders`, `support_tickets`, and the view `user_contacts`) are the same as in the PostgreSQL development environment, and a read-only user `dbgw_reader` is created (password `reader`, `SELECT` and `SHOW VIEW` only). The integration tests' target can be changed with the environment variables `DBGW_TEST_MYSQL_HOST` / `DBGW_TEST_MYSQL_PORT` / `DBGW_TEST_MYSQL_PASSWORD` / `DBGW_TEST_MYSQL_ROOT_PASSWORD`.
