# Design decisions

The choices that shape dbgateway, and why. Details live in the linked pages.

## Analyze SQL with the database's own parser

PostgreSQL statements are parsed with pg_query (the PostgreSQL parser itself) and MySQL statements with the TiDB parser. Decisions are made on the parse tree — statement kind, tables, columns, functions — never on keywords. Anything that cannot be fully analyzed is refused rather than guessed at. See [Security model](./security).

## Deny by default; never auto-allow writes

If no rule matches, the request is denied. A configuration in which an `allow` rule could match a write or DDL fails to load. Writes are only ever executed after human approval (or during an explicit, audited break-glass elevation). See [Policies and roles](./policies).

## Agents act for a person

Every agent token is issued by a signed-in person and carries that person's identity. An agent never has more rights than its person, can be narrowed further at consent, and can never approve. The audit log always says on whose behalf an agent acted. See [Authentication](./authentication).

## Approval binds the exact statement

An approval covers one statement, pinned by hash. It is re-evaluated against the current roles and policies right before it runs, executes once across all instances, and rolls back if it affects more rows than allowed. Approving requires re-authentication. See [Approvals](./approvals).

## Mask at the result, by lineage

Masking happens on the results, after tracing each output column back to its source columns through views, CTEs, expressions and `SELECT *`. If a column's origin cannot be traced, no result is returned. Columns classified `no_ai` never reach an agent, and agents may not use masked columns in conditions. See [Masking and audit](./masking-and-audit).

## Fail closed on audit

Every request, including denials, is written to a hash-chained audit log before a result is returned. If the entry cannot be written, the caller gets an error instead of data.

## Configuration as code

Roles, data classes, policies and approval rules live in one YAML file kept in Git and reviewed in pull requests. Policies have their own test format for CI. The web UI never edits permissions; it proposes the YAML change instead.

## No DDL, no client proxy

Schema changes are refused; they belong in migrations reviewed and applied by your existing tooling. `dbgw lint` checks those migrations in CI with the same parsers (see [Migration lint](./lint)). People run SQL in the web [SQL editor](./console) and the [CLI](./cli). There is no wire-protocol endpoint for desktop clients, because results saved or exported there would be outside dbgateway's control and audit.

## The database stays the last line of defense

dbgateway assumes it can be wrong. Reads run as a read-only database user inside a read-only transaction; writes use a separate user. Database GRANTs and row-level security keep working underneath.

## Simple to run

One Go binary with SQLite by default; PostgreSQL for multiple instances. MCP uses stateless Streamable HTTP. APIs other than MCP and OAuth are defined in Protocol Buffers and served with connectRPC.

## Known limitations

- Policies and risk are assessed per statement. [Quotas](./quotas) cap how many queries and rows a person (with all their agents) gets over time, and anomaly notifications flag bursts, but a split attack that stays within the quotas — or combines harmless-looking results outside dbgateway — is not detected.
- The person's identity reaches the database only as transaction settings (`session_identity`, PostgreSQL), not as a database role; MySQL databases do not receive it.
- Pending writes are returned as `status: pending` with `get_request` for polling; the MCP Tasks extension is not used yet.
- PostgreSQL syntax follows PostgreSQL 17.
