# AWS test environment (Amazon RDS for PostgreSQL)

A disposable RDS for PostgreSQL 17 instance to run dbgateway's integration
tests against a managed database over TLS (`sslmode=verify-full`, with
`rds.force_ssl=1`). It is **not** a production deployment.

Nothing account-specific is stored in this directory: pass your own values
with variables and environment, and keep state locally (it is git-ignored).

```sh
cd deploy/aws
export AWS_PROFILE=<your-profile>          # or any other credential source
terraform init
terraform apply -var "allowed_cidr=$(curl -fsSL https://checkip.amazonaws.com)/32"
./setup.sh                                 # loads the sample schema, prints test env
# ... run the printed commands from the repository root ...
terraform destroy -var "allowed_cidr=$(curl -fsSL https://checkip.amazonaws.com)/32"
```

Variables: `region` (default `ap-northeast-1`), `name`, `allowed_cidr`
(required, never `0.0.0.0/0`), `engine_version`, `instance_class`
(default `db.t4g.micro`).

The instance is publicly addressable but only reachable from
`allowed_cidr`. Destroy it when you are done; it has no final snapshot and no
backups.
