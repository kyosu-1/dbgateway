# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

## [Unreleased]

## [0.3.0] - 2026-11-11

### Added

- `backup.retention`: backup tables older than the retention are dropped hourly, with an audit entry (`backup_expired`) for each.
- `databases[].session_identity` (PostgreSQL): every transaction carries the requester as `dbgateway.user`, `dbgateway.kind`, `dbgateway.agent`, `dbgateway.groups` and `dbgateway.request_id` settings, so row-level security policies and triggers can tell who a request is for.
- Quotas (`quotas`): limits on the queries and rows one person, together with all their agents, may get per minute, hour or day, selected by CEL conditions. A used-up quota denies reads with rule `quota:<name>` and a hint saying when it frees up, a read never returns more rows than the quota has left, and `explain_policy` reports a quota that would deny. Usage is kept in the management database, so it is shared by all instances with the PostgreSQL store; store errors fail closed. Shadow mode records quota denials instead of enforcing them.
- Helm chart (`deploy/helm/dbgateway`) for Kubernetes: the configuration from values (or an existing ConfigMap) with a rollout on change, secrets from existing Secrets through `envFrom` / `env`, a single instance with SQLite and audit files on a persistent volume or several replicas with the PostgreSQL store, a hardened pod (non-root, read-only root file system, no capabilities, no API token), an optional Ingress, metrics Service, ServiceMonitor, PodDisruptionBudget and NetworkPolicy, and checks that refuse values dbgateway would reject or that would lose data.

## [0.2.0] - 2026-11-11

### Added

- Prometheus metrics on a separate, optional listener (`server.metrics_listen`, `GET /metrics`): requests by database, principal kind, decision and stage, request durations, rows returned, approval state changes, audit write and forwarding failures, notification deliveries, catalog loads, connection pools, and Go runtime and process metrics. Labels never contain identities, SQL or table names.
- Schema docs (`databases[].docs`): database, table and column descriptions and example queries kept in the configuration, returned by `list_databases` and `search_objects` (MCP and API), `dbgw dbs` / `dbgw search` and the SQL editor's schema list, alongside database comments. Examples are attached to the tables they reference using the SQL analyzer.
- Backups of approved writes (PostgreSQL, `databases[].backup`): the rows an `UPDATE` or `DELETE` changes are copied into a table in the database, in the same transaction, and the request offers a restore statement that goes through approval like any other write.
- `dbgw lint`: offline review of SQL migration files with the PostgreSQL and MySQL parsers. 20 PostgreSQL rules (locks, table rewrites, unsafe constraints, destructive and breaking changes, type conventions) and 8 MySQL rules; text, JSON and GitHub Actions annotation output; YAML configuration and `-- dbgw-lint-ignore` comments.

### Changed

- The quickstart uses the release binary: `make download` fetches and verifies `bin/dbgw`, and `make serve-dev` runs it; building needs Go with cgo only on other platforms.

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

[Unreleased]: https://github.com/kyosu-1/dbgateway/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kyosu-1/dbgateway/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kyosu-1/dbgateway/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kyosu-1/dbgateway/releases/tag/v0.1.0
