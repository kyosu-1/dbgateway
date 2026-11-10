# dbgateway

[![ci](https://github.com/kyosu-1/dbgateway/actions/workflows/ci.yml/badge.svg)](https://github.com/kyosu-1/dbgateway/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**An SQL-aware gateway that lets AI agents and people use production databases safely.**

dbgateway sits between your PostgreSQL or MySQL databases and everyone who queries them. Each statement is parsed with the database's own parser, checked against roles and policies, then **allowed, sent for human approval, or denied**. Results are masked by data class, and every request is written to a tamper-evident audit log.

AI agents connect over [MCP](https://modelcontextprotocol.io) with OAuth; people use the web SQL editor and the CLI. Everyone goes through the same checks.

📖 **Documentation: <https://kyosu-1.github.io/dbgateway/>** · [日本語](README.ja.md)

## Features

- **Understands SQL** — pg_query for PostgreSQL and the TiDB parser for MySQL. Multiple statements, transaction control, side-effect functions and anything that cannot be fully analyzed are refused.
- **Policy as code** — groups, five roles, data classes and CEL rules in one YAML file. Default deny, shadow mode and `dbgw policy test` for CI.
- **Human approval for writes** — risk levels, multi-step approval rules, passkey or IdP step-up, statement pinning, re-evaluation before execution and affected-row limits.
- **Masking by lineage** — through views, CTEs, expressions and `SELECT *`; `no_ai` columns never reach an agent; optional value-based PII detection.
- **Agents act for a person** — OAuth 2.1 with consent and short-lived agent tokens; an agent never has more rights than its person.
- **Web UI** (English and Japanese) — SQL editor with completion, history and audited export; approvals, requests, audit log and users.
- **Tamper-evident audit log** — hash chain, `dbgw audit verify`, fail closed; files, PostgreSQL or OpenTelemetry.
- **Built for production** — IAM database authentication on AWS and Google Cloud, read replicas, multi-instance mode, Slack and webhook notifications, SCIM.

## Quickstart

Requires Docker, and Linux or macOS (Apple silicon) for the release binary — or Go with cgo to build it (`make run-dev`).

```sh
git clone --depth 1 https://github.com/kyosu-1/dbgateway.git && cd dbgateway
make download         # bin/dbgw from the latest release
make serve-dev        # sample PostgreSQL + dbgateway on http://127.0.0.1:8443
claude mcp add --transport http dbgateway http://127.0.0.1:8443/mcp
```

Then ask your agent about the `dev-main` database, or open <http://127.0.0.1:8443/console>. The development configuration uses a password-less dev login that only works on loopback. Full walkthrough: [Quickstart](https://kyosu-1.github.io/dbgateway/quickstart).

## Example policy

```yaml
policies:                       # top to bottom, first match wins; no match = deny
  - name: deny-unbounded-writes
    when: stmt.kind in ["update", "delete"] && !stmt.has_where
    action: deny
    hint: "There is no WHERE clause. Narrow down the target rows and run it again."
  - name: agents-never-see-no-ai
    when: principal.kind == "agent" && columns.exists(c, c.class == "no_ai")
    action: deny
  - name: reads
    when: stmt.kind == "select" && !stmt.is_write
    action: allow
  - name: writes
    when: stmt.is_write
    action: approve
    require: { reason: true, step_up: true }
```

A complete configuration: [examples/dbgateway.yaml](examples/dbgateway.yaml).

## Status

dbgateway is early software: the configuration format, APIs and MCP tools may change before 1.0. It does not replace least-privilege database users — keep them as the last line of defense.

## Contributing and security

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
