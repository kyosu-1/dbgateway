# Deploying dbgateway

dbgateway is a single binary (`dbgw serve`) configured by one YAML file. Run it close to the databases, on the same private network, and put HTTPS in front of it.

## Choose a topology

| | Single instance | Multiple instances |
| --- | --- | --- |
| Management database | SQLite file (`store.driver: sqlite`) | PostgreSQL (`store.driver: postgres`) |
| Audit log | JSON Lines files (`audit.output: file`) | PostgreSQL (`audit.output: postgres`), optionally also OTLP |
| Good for | a VM, a small team | container platforms, high availability |

With PostgreSQL, approvals execute exactly once across instances and the audit log stays a single hash chain. See [High availability](./ha).

## Container platforms

The image is built from the repository's [Dockerfile](../Dockerfile). On platforms where you cannot mount files:

- pass the whole configuration in an environment variable: `dbgw serve --config env:DBGW_CONFIG_YAML`
- pass CA certificates the same way with `sslrootcert_env` (databases) and `store.sslrootcert_env` (management database)
- keep secrets in the platform's secret store and reference them with `*_env` keys

Platform notes:

- **AWS ECS Fargate** — run tasks in private subnets behind an ALB; give the task role `rds-db:connect` and use `auth: aws_iam` for RDS.
- **Google Cloud Run** — approvals and expirations run outside requests, so set **CPU always allocated** and **at least one instance**; connect to Cloud SQL over Direct VPC egress and use `auth: gcp_iam`. Cloud Run reserves paths ending in `z`, so use `/health` (not `/healthz`) for external health checks.

Both setups have complete Terraform examples, including the database, IAM authentication and a cloud end-to-end test:

- [deploy/aws-ecs](../deploy/aws-ecs/) — ECS Fargate, ALB, RDS for PostgreSQL with IAM authentication
- [deploy/gcp-cloudrun](../deploy/gcp-cloudrun/) — Cloud Run, Cloud SQL for PostgreSQL with IAM authentication

Smaller examples that only create a database for trying IAM authentication: [deploy/aws](../deploy/aws/), [deploy/gcp](../deploy/gcp/).

## Checklist

- [ ] HTTPS in front of dbgateway, and `server.public_url` set to the external URL
- [ ] OIDC sign-in configured; `auth.dev_login` off
- [ ] Least-privilege database users: a read-only user for reads, a separate user for approved writes
- [ ] Data classes for sensitive columns; production databases labelled so unclassified columns are masked for agents
- [ ] Policies tested with `dbgw policy test` in CI; consider starting in shadow mode
- [ ] Audit log stored durably and verified with `dbgw audit verify`
- [ ] Notifications for approvals and anomalies

For day-to-day operation (IAM authentication, OpenTelemetry, the emergency bypass) see [Operations](./operations).
