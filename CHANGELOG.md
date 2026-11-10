# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

## [Unreleased]

### Added

- Prometheus metrics on a separate, optional listener (`server.metrics_listen`, `GET /metrics`): requests by database, principal kind, decision and stage, request durations, rows returned, approval state changes, audit write and forwarding failures, notification deliveries, catalog loads, connection pools, and Go runtime and process metrics. Labels never contain identities, SQL or table names.
- Schema docs (`databases[].docs`): database, table and column descriptions and example queries kept in the configuration, returned by `list_databases` and `search_objects` (MCP and API), `dbgw dbs` / `dbgw search` and the SQL editor's schema list, alongside database comments. Examples are attached to the tables they reference using the SQL analyzer.
- Backups of approved writes (PostgreSQL, `databases[].backup`): the rows an `UPDATE` or `DELETE` changes are copied into a table in the database, in the same transaction, and the request offers a restore statement that goes through approval like any other write.
- `dbgw lint`: offline review of SQL migration files with the PostgreSQL and MySQL parsers. 20 PostgreSQL rules (locks, table rewrites, unsafe constraints, destructive and breaking changes, type conventions) and 8 MySQL rules; text, JSON and GitHub Actions annotation output; YAML configuration and `-- dbgw-lint-ignore` comments.

## [0.1.0] - 2026-11-11

First public release.

### Added

- MCP server (Streamable HTTP) with `list_databases`, `search_objects`, `execute_sql`, `get_request` and `explain_policy`; stdio relay `dbgw mcp stdio`.
- SQL analysis with the PostgreSQL parser (pg_query) and the TiDB parser for MySQL; refusal of anything that cannot be fully analyzed.
- Roles, groups, data classes and CEL policies with default deny, shadow mode and `dbgw policy test`.
- Column masking by lineage, `no_ai` columns and value-based PII detection.
- Approval workflow for writes: risk levels, multi-step approval rules, passkey or IdP step-up, statement pinning, re-evaluation and affected-row limits; time-limited roles, unmask and break-glass elevation.
- Web UI (English and Japanese): approvals, requests, SQL editor with completion, history, saved queries and audited export, audit log, users.
- OAuth 2.1 authorization server for agents, OIDC and passkey sign-in, CLI device flow, SCIM 2.0.
- Hash-chained audit log (files, PostgreSQL, OpenTelemetry) with `dbgw audit verify`.
- Slack and webhook notifications, anomaly alerts.
- IAM database authentication for Amazon RDS and Cloud SQL, read replicas, multi-instance mode with PostgreSQL.
- Terraform examples for ECS Fargate and Cloud Run.

[Unreleased]: https://github.com/kyosu-1/dbgateway/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kyosu-1/dbgateway/releases/tag/v0.1.0
