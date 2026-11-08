# Google Cloud test environment (Cloud SQL for PostgreSQL)

A disposable Cloud SQL for PostgreSQL 17 instance to run dbgateway's
integration tests against a managed database over TLS, including Cloud SQL
IAM database authentication (`auth: gcp_iam`). It is **not** a production
deployment.

Nothing account-specific is stored in this directory: pass your own values
with variables, and keep state locally (it is git-ignored).

```sh
cd deploy/gcp
gcloud auth application-default login      # credentials for Terraform and the IAM test
terraform init
terraform apply \
  -var "project=<your-project-id>" \
  -var "allowed_cidr=$(curl -fsSL https://checkip.amazonaws.com)/32" \
  -var "iam_principal=$(gcloud config get account)"
./setup.sh                                 # loads the sample schema, grants, prints test env
# ... run the printed commands from the repository root ...
terraform destroy -var "project=<your-project-id>" \
  -var "allowed_cidr=$(curl -fsSL https://checkip.amazonaws.com)/32" \
  -var "iam_principal=$(gcloud config get account)"
```

Variables: `project` (required), `region` (default `asia-northeast1`),
`name`, `allowed_cidr` (required, never `0.0.0.0/0`), `iam_principal`
(required: the Google account or service account email dbgateway logs in
as), `grant_iam_roles` (default `true`), `tier` (default `db-f1-micro`).

What it creates:

- The instance with a public IP restricted to `allowed_cidr` (authorized
  networks), TLS required (`ssl_mode = ENCRYPTED_ONLY`), a per-instance
  server CA, and `cloudsql.iam_authentication=on`. No backups, no deletion
  protection.
- Database `app`, the built-in user `dbgw_admin` (only for `setup.sh`),
  and the IAM database user for `iam_principal` (for a service account the
  user name is the email without `.gserviceaccount.com`).
- With `grant_iam_roles`, the project roles `roles/cloudsql.instanceUser`
  (needed to log in) and `roles/cloudsql.client` for `iam_principal`.

`setup.sh` loads `examples/dev/initdb/01-schema.sql` (which creates the
`dbgw_reader` password user) with `docker run postgres:17 psql` over TLS,
and grants the IAM user read access.

## TLS: why `verify-ca`

The server certificate of an instance with a per-instance CA
(`GOOGLE_MANAGED_INTERNAL_CA`) has `CN=<project>:<instance>` and no subject
alternative name for its IP address, so `verify-full` against the IP fails.
Because the CA is unique to the instance, `sslmode=verify-ca` with the
instance's server CA as `sslrootcert` verifies the server's identity. (With
a shared CA, `GOOGLE_MANAGED_CAS_CA`, the certificate carries the instance
DNS name and you must use `verify-full` with that name instead.)

dbgateway configuration for this instance:

```yaml
primary:
  host: <terraform output public_ip>
  auth: gcp_iam
  read_user: <terraform output iam_db_user>
  sslmode: verify-ca
  sslrootcert: deploy/gcp/cloudsql-server-ca.pem
```

The instance is publicly addressable but only reachable from
`allowed_cidr`. Destroy it when you are done.
