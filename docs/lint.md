# Migration lint

dbgateway never runs schema changes: DDL is refused, and schema changes belong in migrations that are reviewed in pull requests and applied by your migration tool (see [Design decisions](./design-decisions)). `dbgw lint` gives that review automated checks. It reads migration files, parses them with the same parsers dbgateway uses for queries (pg_query for PostgreSQL, the TiDB parser for MySQL), and reports statements that are likely to cause an outage or lose data in production: locks held for a long time, table rewrites, destructive changes and changes that break running code.

It works fully offline. It never connects to a database and does not need a dbgateway server or configuration.

```console
$ dbgw lint db/migrations/20261111_add_plan.sql
db/migrations/20261111_add_plan.sql:1:1: warning pg/lock-timeout: This statement locks an existing table, but lock_timeout is not set earlier in the file.
    hint: Begin the migration with SET lock_timeout = '5s' (SET LOCAL inside a transaction) and retry when it times out.
db/migrations/20261111_add_plan.sql:1:30: error pg/add-column-not-null-without-default: Adding NOT NULL column users.plan without a DEFAULT fails if the table has rows.
    hint: Add a constant DEFAULT (no table rewrite since PostgreSQL 11), or add the column as nullable, backfill it, then make it NOT NULL.
db/migrations/20261111_add_plan.sql:2:1: error pg/create-index-concurrently: CREATE INDEX on users without CONCURRENTLY blocks writes to the table while the index is built.
    hint: Use CREATE INDEX CONCURRENTLY, outside a transaction block. If it fails, drop the INVALID index it leaves behind and retry.
2 errors, 1 warning, 0 info in 1 file
```

## Usage

```sh
dbgw lint [--dialect postgres|mysql] [--config lint.yaml] [--format text|json|github] FILE|DIR|-...
```

- Arguments are files, directories (searched recursively for `*.sql`) or glob patterns (`'db/migrations/*.sql'`, expanded by dbgw if the shell did not). `-` reads standard input.
- A file may contain any number of statements.
- `--dialect`: `postgres` (default) or `mysql`. The configuration file can set the default.
- `--config` (`-c`): a [configuration file](#configuration).
- `--format` (`-o`): `text` (default), `json`, or `github` for [GitHub Actions annotations](#github-actions).
- `--list-rules`: print the rules of the dialect with their default severity (`-o json` for JSON).

Each finding has a position (`file:line:column`, column in characters), a rule ID, a severity, a message and a hint on how to fix it. A summary is printed to standard error (except with `json`).

| Exit status | Meaning |
| --- | --- |
| 0 | No error-level findings (warnings and info do not fail) |
| 1 | At least one error-level finding, including a file that cannot be parsed (`syntax-error`) |
| 2 | Nothing was checked: bad flags, configuration or paths |

### What counts as an existing table

Most rules are about statements that are dangerous on a table that already holds data. dbgw lint only sees the file, so it treats a table as **new** when the same file creates it earlier (`CREATE TABLE` or `CREATE TABLE ... AS`) and every other table as **existing**. Creating an index on a table created in the same migration, for example, is not reported.

### Lint new migrations only

Migrations that have already been applied cannot be changed, so lint only the files a pull request adds or modifies (see the [GitHub Actions example](#github-actions)), not the whole directory.

### JSON output

```json
{
  "findings": [
    {
      "file": "db/migrations/20261111_add_plan.sql",
      "line": 2,
      "column": 1,
      "rule": "pg/create-index-concurrently",
      "severity": "error",
      "message": "CREATE INDEX on users without CONCURRENTLY blocks writes to the table while the index is built.",
      "hint": "Use CREATE INDEX CONCURRENTLY, outside a transaction block. ..."
    }
  ],
  "summary": { "files": 1, "errors": 1, "warnings": 0, "infos": 0 }
}
```

## Suppressing a finding

When a finding is intended (a reviewed backfill, a rename of a table no code uses yet), put a comment on the line before the statement:

```sql
-- dbgw-lint-ignore pg/dml-without-where -- one-off backfill of a 2,000-row table, reviewed in #123
UPDATE plans SET tier = 'free';
```

- On a line of its own, `-- dbgw-lint-ignore RULE[, RULE...]` suppresses those rules for the **next statement** (wherever it starts) and for the line directly below the comment.
- After code on the same line, it suppresses the rules on that line, and for the statement that ends before it on that line:

  ```sql
  UPDATE plans SET tier = 'free'; -- dbgw-lint-ignore pg/dml-without-where -- reviewed in #123
  CREATE TABLE events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    happened_at timestamp NOT NULL, -- dbgw-lint-ignore pg/prefer-timestamptz -- always UTC, written by a legacy job
    payload jsonb
  );
  ```

- Without rule IDs, it suppresses every rule.
- Write the reason after `--` following the rule IDs; it is ignored.
- `/* dbgw-lint-ignore ... */` works too, and `# dbgw-lint-ignore ...` for MySQL.
- `syntax-error` cannot be suppressed.

## Configuration

An optional YAML file changes severities, turns rules off and ignores files. Unknown keys, unknown rule IDs and invalid severities are errors.

```yaml
# .dbgw-lint.yaml
dialect: postgres            # default for --dialect

rules:                       # error | warning | info | off
  pg/prefer-text: off
  pg/drop-column: error
  pg/lock-timeout: off       # our migration tool sets lock_timeout itself

ignore:
  - files: ["db/migrations/legacy/**"]          # not checked at all
  - files: ["db/migrations/2025*_*.sql"]
    rules: [pg/require-primary-key]
```

- `rules` sets the severity of a rule, or turns it off. Rules of both dialects can be listed; only the ones of the dialect being checked apply.
- `ignore` turns `rules` off for `files`; without `rules`, matching files are skipped entirely. Patterns are matched against the path as given on the command line: `*` and `?` match within one path segment, `**` matches any number of segments, and a pattern without `/` matches the file name in any directory.

## GitHub Actions

`--format github` prints [workflow commands](https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions) (`::error file=...,line=...::...`), so findings appear as annotations on the pull request's changed lines.

```yaml
# .github/workflows/migrations.yml
name: migrations
on:
  pull_request:
    paths: ["db/migrations/**"]
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-latest
    env:
      # A release that includes `dbgw lint` (0.2.0 or later), without the "v".
      DBGW_VERSION: "0.2.0"
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # to diff against the base branch
      - name: Install dbgw
        run: |
          name="dbgw_${DBGW_VERSION}_linux_amd64"
          base="https://github.com/kyosu-1/dbgateway/releases/download/v${DBGW_VERSION}"
          curl -fsSLO "$base/$name.tar.gz"
          curl -fsSLO "$base/checksums.txt"
          sha256sum --check --ignore-missing checksums.txt
          tar -xzf "$name.tar.gz"
          sudo install "$name/dbgw" /usr/local/bin/dbgw
      - name: Lint new and changed migrations
        run: |
          git diff --name-only --diff-filter=AM -z "origin/${GITHUB_BASE_REF}...HEAD" -- 'db/migrations/*.sql' \
            | xargs -0 --no-run-if-empty dbgw lint --config .dbgw-lint.yaml --format github
```

Release archives are named `dbgw_<version>_<os>_<arch>.tar.gz` (`linux_amd64`, `linux_arm64`, `darwin_arm64`) and contain a directory of the same name with the `dbgw` binary; `checksums.txt` holds their SHA-256 sums. See the [releases page](https://github.com/kyosu-1/dbgateway/releases).

Instead of downloading a release, you can build dbgw in the job. cgo is required (the PostgreSQL parser is C), which works on GitHub's Ubuntu runners:

```yaml
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - run: go install github.com/kyosu-1/dbgateway/cmd/dbgw@v0.2.0
```

Run the same command locally before pushing, or from a pre-commit hook:

```sh
git diff --name-only --diff-filter=AM -z origin/main...HEAD -- 'db/migrations/*.sql' | xargs -0 dbgw lint
```

## PostgreSQL rules

| Rule | Severity | Reported when |
| --- | --- | --- |
| [`pg/create-index-concurrently`](#pg-create-index-concurrently) | error | `CREATE INDEX` without `CONCURRENTLY` on an existing table |
| [`pg/drop-index-concurrently`](#pg-drop-index-concurrently) | warning | `DROP INDEX` without `CONCURRENTLY` |
| [`pg/concurrently-in-transaction`](#pg-concurrently-in-transaction) | error | `CONCURRENTLY` after `BEGIN` in the same file |
| [`pg/add-column-not-null-without-default`](#pg-add-column-not-null-without-default) | error | `ADD COLUMN ... NOT NULL` without `DEFAULT` |
| [`pg/add-column-volatile-default`](#pg-add-column-volatile-default) | error | `ADD COLUMN` that rewrites the table |
| [`pg/alter-column-type`](#pg-alter-column-type) | error | `ALTER COLUMN ... TYPE` |
| [`pg/set-not-null`](#pg-set-not-null) | error | `ALTER COLUMN ... SET NOT NULL` without a validated `CHECK` |
| [`pg/add-constraint-not-valid`](#pg-add-constraint-not-valid) | error | `FOREIGN KEY` or `CHECK` added without `NOT VALID` |
| [`pg/constraint-using-index`](#pg-constraint-using-index) | error | `PRIMARY KEY` or `UNIQUE` added without `USING INDEX` |
| [`pg/lock-timeout`](#pg-lock-timeout) | warning | Locking DDL without `lock_timeout` set before it |
| [`pg/dml-without-where`](#pg-dml-without-where) | error | `UPDATE` or `DELETE` without `WHERE` |
| [`pg/drop-table`](#pg-drop-table) | warning | `DROP TABLE` |
| [`pg/drop-column`](#pg-drop-column) | warning | `ALTER TABLE ... DROP COLUMN` |
| [`pg/rename-table`](#pg-rename-table) | warning | Renaming a table, view or materialized view |
| [`pg/rename-column`](#pg-rename-column) | warning | Renaming a column |
| [`pg/truncate`](#pg-truncate) | warning | `TRUNCATE` |
| [`pg/require-primary-key`](#pg-require-primary-key) | warning | `CREATE TABLE` without a primary key |
| [`pg/prefer-identity`](#pg-prefer-identity) | warning | `serial`, `bigserial`, `smallserial` |
| [`pg/prefer-timestamptz`](#pg-prefer-timestamptz) | warning | `timestamp` without time zone |
| [`pg/prefer-text`](#pg-prefer-text) | info | `varchar(n)`, `char(n)` |

Severities follow one principle: **error** for statements that block reads or writes on a busy table for an unbounded time, fail on real data, or silently change every row; **warning** for changes that are destructive or break running code but are often intended, and for conventions that prevent later outages; **info** for style.

### pg/create-index-concurrently

A plain `CREATE INDEX` takes a `SHARE` lock: reads continue, but every `INSERT`, `UPDATE` and `DELETE` waits until the whole table has been read and the index built, which can take minutes to hours. `CREATE INDEX CONCURRENTLY` builds the index without blocking writes. It cannot run in a transaction block, and if it fails it leaves an `INVALID` index that must be dropped before retrying.

```sql
CREATE INDEX users_email ON users (email);               -- reported
CREATE INDEX CONCURRENTLY users_email ON users (email);  -- ok
```

### pg/drop-index-concurrently

`DROP INDEX` takes an `ACCESS EXCLUSIVE` lock on the index's table, blocking reads and writes while it waits for running queries. Use `DROP INDEX CONCURRENTLY` (outside a transaction block). Indexes created in the same file are not reported.

### pg/concurrently-in-transaction

`CREATE INDEX CONCURRENTLY`, `DROP INDEX CONCURRENTLY`, `REINDEX ... CONCURRENTLY` and `DETACH PARTITION ... CONCURRENTLY` fail with "cannot run inside a transaction block". The rule reports them after an explicit `BEGIN` / `START TRANSACTION` in the same file. Many migration tools also wrap each file in a transaction, or send the whole file as one multi-statement query (which PostgreSQL runs as a single transaction); dbgw lint cannot see that, so put concurrent statements in a migration of their own and mark it as non-transactional in your tool.

### pg/add-column-not-null-without-default

Adding a `NOT NULL` (or `PRIMARY KEY`) column without a default fails as soon as the table has a row. Since PostgreSQL 11, a column with a constant default is added without rewriting the table, so add `DEFAULT <constant>`; otherwise add the column as nullable, backfill it and add `NOT NULL` later (see [pg/set-not-null](#pg-set-not-null)).

```sql
ALTER TABLE users ADD COLUMN plan text NOT NULL;                 -- reported
ALTER TABLE users ADD COLUMN plan text NOT NULL DEFAULT 'free';  -- ok
```

### pg/add-column-volatile-default

A constant default is stored in the catalog, but a column whose value differs per row forces PostgreSQL to rewrite the entire table under an `ACCESS EXCLUSIVE` lock: a volatile default (`gen_random_uuid()`, `random()`, `clock_timestamp()`, `nextval()`, `uuid_generate_v4()` and similar), a `serial` type, an identity column, or a stored generated column. Stable functions such as `now()` are fine. Add the column without the default, backfill it in batches, then set the default for new rows.

```sql
ALTER TABLE users ADD COLUMN token uuid DEFAULT gen_random_uuid();  -- reported
ALTER TABLE users ADD COLUMN created_at timestamptz DEFAULT now();  -- ok
```

### pg/alter-column-type

Changing a column's type rewrites the table and rebuilds its indexes under an `ACCESS EXCLUSIVE` lock, unless the old and new types are binary coercible (for example `varchar(n)` to `text` or to a longer `varchar`). dbgw lint does not know the old type, so it reports every type change on an existing table; suppress the finding when you know no rewrite happens. Otherwise add a new column, backfill it and move the code over.

### pg/set-not-null

`SET NOT NULL` scans the whole table while holding an `ACCESS EXCLUSIVE` lock. Since PostgreSQL 12 the scan is skipped when a valid `CHECK (col IS NOT NULL)` constraint exists, and that constraint can be validated without blocking writes:

```sql
ALTER TABLE users ADD CONSTRAINT users_email_not_null CHECK (email IS NOT NULL) NOT VALID;
ALTER TABLE users VALIDATE CONSTRAINT users_email_not_null;   -- does not block writes
ALTER TABLE users ALTER COLUMN email SET NOT NULL;            -- no scan; not reported
ALTER TABLE users DROP CONSTRAINT users_email_not_null;
```

The rule is not reported when the same file adds such a constraint (valid, or `NOT VALID` followed by `VALIDATE CONSTRAINT`). When validation happens in an earlier migration, suppress the finding.

### pg/add-constraint-not-valid

Adding a `FOREIGN KEY` or `CHECK` constraint checks every existing row while holding a lock that blocks writes (for a foreign key, on both tables; for a `CHECK`, reads are blocked too). With `NOT VALID` the constraint is added instantly and enforced for new rows; `VALIDATE CONSTRAINT` then checks the existing rows while allowing reads and writes.

```sql
ALTER TABLE orders ADD CONSTRAINT orders_user_fk FOREIGN KEY (user_id) REFERENCES users (id) NOT VALID;
ALTER TABLE orders VALIDATE CONSTRAINT orders_user_fk;
```

### pg/constraint-using-index

Adding a `PRIMARY KEY` or `UNIQUE` constraint (including a new column declared `UNIQUE` or `PRIMARY KEY`) builds the index while holding an `ACCESS EXCLUSIVE` lock. Build the index concurrently first, then attach it:

```sql
CREATE UNIQUE INDEX CONCURRENTLY users_email_key ON users (email);
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE USING INDEX users_email_key;
```

### pg/lock-timeout

Most DDL needs an `ACCESS EXCLUSIVE` (or other strong) lock. If a long-running query holds a conflicting lock, the DDL waits, and every query that arrives after it queues behind it: a quick `ALTER TABLE` becomes an outage. With `lock_timeout` the migration fails fast instead, and can be retried. The rule reports the first statement that locks an existing table (`ALTER TABLE` other than `VALIDATE CONSTRAINT` alone, non-concurrent `CREATE INDEX` / `DROP INDEX`, `DROP TABLE`, renames, `TRUNCATE`, `CREATE TRIGGER`) when no non-zero `SET lock_timeout` comes before it in the file; `SET LOCAL` counts only inside the transaction that sets it. It is reported once per file. Turn it off if your migration tool or database role already sets `lock_timeout`.

```sql
SET lock_timeout = '5s';
ALTER TABLE users ADD COLUMN plan text;
```

### pg/dml-without-where

An `UPDATE` or `DELETE` without `WHERE` changes every row: usually a mistake, and on a large table a long transaction that holds row locks and bloats the table. Tables created in the same file are not reported. For an intended backfill of a large table, update in batches and suppress the finding.

### pg/drop-table

`DROP TABLE` deletes the data and breaks every deployed version of the code that still uses the table. Make sure nothing uses it and that the data is backed up or no longer needed.

### pg/drop-column

Dropping a column deletes its data, and code that still reads or writes it fails (including ORMs that list every column). Deploy code that no longer uses the column first, then drop it in a later migration.

### pg/rename-table

During a deployment, old and new code run side by side; renaming a table (or view) breaks the old code immediately. Expand and contract instead: add the new name (for example a new table, or a view with the old name), move the code over, then remove the old name.

### pg/rename-column

Same as [pg/rename-table](#pg-rename-table) for columns: add a new column, write to both, backfill, move reads over, then drop the old column.

### pg/truncate

`TRUNCATE` deletes every row and takes an `ACCESS EXCLUSIVE` lock. It is rarely what a migration should do on a table in use.

### pg/require-primary-key

Tables without a primary key cannot be replicated with logical replication (`UPDATE` and `DELETE` fail without a replica identity), are hard to deduplicate and are not supported by many tools and ORMs. Not reported for temporary tables, partitions (`PARTITION OF`), typed tables (`OF type`), `CREATE TABLE ... (LIKE ...)`, or when the same file adds the primary key with `ALTER TABLE`.

### pg/prefer-identity

`serial` types create a sequence with separate ownership and permissions and are not standard SQL. Identity columns (`GENERATED ALWAYS AS IDENTITY` or `GENERATED BY DEFAULT AS IDENTITY`) are recommended since PostgreSQL 10.

### pg/prefer-timestamptz

`timestamp` (without time zone) stores the wall-clock time without the zone, so the same value means different instants for clients in different time zones, and daylight-saving changes produce ambiguous values. `timestamptz` stores an instant and costs the same 8 bytes.

### pg/prefer-text

In PostgreSQL, `varchar(n)` is not faster than `text`, and changing `n` later can require a migration on a large table; `char(n)` pads values with spaces. Use `text`, with a `CHECK (char_length(col) <= n)` constraint when a limit is a real requirement. This is a style rule (info).

## MySQL rules

| Rule | Severity | Reported when |
| --- | --- | --- |
| `mysql/alter-algorithm` | warning | `ALTER TABLE` on an existing table without `ALGORITHM=INSTANT` or `INPLACE`, with `ALGORITHM=COPY`, or with `LOCK=SHARED` / `EXCLUSIVE` |
| `mysql/dml-without-where` | error | `UPDATE` or `DELETE` without `WHERE` |
| `mysql/drop-table` | warning | `DROP TABLE` (not temporary tables or views) |
| `mysql/drop-column` | warning | `ALTER TABLE ... DROP COLUMN` |
| `mysql/rename-table` | warning | `RENAME TABLE`, `ALTER TABLE ... RENAME TO` |
| `mysql/rename-column` | warning | `RENAME COLUMN`, or `CHANGE` with a different column name |
| `mysql/truncate` | warning | `TRUNCATE TABLE` |
| `mysql/require-primary-key` | warning | `CREATE TABLE` without a primary key (not temporary tables, `LIKE` or `... AS SELECT`) |

`mysql/alter-algorithm`: whether MySQL can change a table in place or instantly depends on the operation and the server version, and when it cannot, it silently falls back to copying the table while blocking writes. Stating `ALGORITHM=INSTANT` (or `ALGORITHM=INPLACE, LOCK=NONE`) makes MySQL refuse such a change with an error instead, so you can switch to an online schema change tool. The other MySQL rules have the same rationale as their PostgreSQL counterparts above.

MySQL files are parsed with the default MySQL 8 `sql_mode` (`"..."` is a string, backslash escapes are on). Positions are reported at the start of the statement.

## Limitations

- The check is static. It does not know table sizes, the server version or the old type of a column, so some findings may not matter for a small table; suppress them with a reason.
- Only top-level statements are checked. SQL inside `DO` blocks and function bodies is not.
- A file that cannot be parsed is reported as a single `syntax-error` and not checked otherwise. PostgreSQL syntax follows PostgreSQL 17. Client commands are not SQL and do not parse: psql meta-commands (`\set`, `\connect`) and the MySQL client's `DELIMITER`.
