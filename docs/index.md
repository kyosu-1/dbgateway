---
layout: home

hero:
  name: dbgateway
  text: A gateway that understands SQL
  tagline: Let AI agents and people use production databases — every statement parsed, checked against policy, masked and audited.
  actions:
    - theme: brand
      text: What is dbgateway?
      link: /introduction
    - theme: alt
      text: Quickstart
      link: /quickstart
    - theme: alt
      text: GitHub
      link: https://github.com/kyosu-1/dbgateway

features:
  - title: Parses every statement
    details: SQL is analyzed with the database's own parser (pg_query for PostgreSQL, the TiDB parser for MySQL). Anything that cannot be fully analyzed is refused.
  - title: Policy as code
    details: Roles, data classes and CEL rules live in one YAML file reviewed in Git. Default deny, shadow mode for rollout, and policy tests for CI.
  - title: Human approval for writes
    details: Writes become approval requests. Approvers re-authenticate with a passkey or the IdP; the statement is pinned, re-evaluated and capped by affected rows.
  - title: Masking by lineage
    details: Sensitive columns are masked in results — through views, CTEs, expressions and SELECT * — and columns marked no_ai never reach an agent.
  - title: One path for agents and people
    details: AI agents connect over MCP with OAuth; people use the web SQL editor and the CLI. Everyone goes through the same checks.
  - title: Tamper-evident audit log
    details: Every request, including denials, is recorded in a hash chain. If the audit log cannot be written, no result is returned.
---
