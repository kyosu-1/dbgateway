#!/usr/bin/env bash
# Loads the sample schema into the Cloud SQL instance created by this
# Terraform configuration, grants read access to the IAM database user and
# prints the environment for the integration tests.
# Requires: terraform (already applied), docker.
set -euo pipefail
cd "$(dirname "$0")"

ip=$(terraform output -raw public_ip)
admin_pw=$(terraform output -raw admin_password)
reader_pw=$(terraform output -raw reader_password)
iam_user=$(terraform output -raw iam_db_user)
ca="$PWD/cloudsql-server-ca.pem"

# The instance's own server CA. Its server certificate has no SAN for the
# public IP (only CN=<project>:<instance>), so clients verify the CA
# (sslmode=verify-ca); with a per-instance CA that also verifies identity.
terraform output -raw server_ca_cert > "$ca"

psql_admin() {
  docker run --rm -i \
    -v "$PWD/../../examples/dev/initdb:/initdb:ro" \
    -v "$ca:/ca.pem:ro" \
    -e PGPASSWORD="$admin_pw" \
    postgres:17 \
    psql "host=$ip dbname=app user=dbgw_admin sslmode=verify-ca sslrootcert=/ca.pem" \
      -v ON_ERROR_STOP=1 -q "$@"
}

# The sample schema creates its tables once; skip it on a re-run.
if [ "$(psql_admin -tA -c "SELECT to_regclass('public.users') IS NOT NULL")" != "t" ]; then
  psql_admin -f /initdb/01-schema.sql
fi
psql_admin -c "ALTER ROLE dbgw_reader PASSWORD '$reader_pw'"

# The IAM user exists (created by Terraform) but has no privileges yet.
psql_admin -v iam_user="$iam_user" <<'SQL'
GRANT CONNECT ON DATABASE app TO :"iam_user";
GRANT USAGE ON SCHEMA public TO :"iam_user";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO :"iam_user";
SQL

cat <<EOF
# Run the integration tests against Cloud SQL (TLS verify-ca, password user):
export DBGW_TEST_PG_HOST=$ip
export DBGW_TEST_PG_PORT=5432
export DBGW_TEST_PG_SSLMODE=verify-ca
export DBGW_TEST_PG_SSLROOTCERT=$ca
export DBGW_TEST_PG_PASSWORD=\$(terraform -chdir=deploy/gcp output -raw reader_password)
go test -tags integration -count=1 ./internal/gateway/

# IAM database authentication (auth: gcp_iam) with your Application Default
# Credentials (gcloud auth application-default login, as $iam_user):
export DBGW_TEST_IAM_HOST=$ip
export DBGW_TEST_IAM_AUTH=gcp_iam
export DBGW_TEST_IAM_USER=$iam_user
export DBGW_TEST_IAM_SSLMODE=verify-ca
export DBGW_TEST_IAM_SSLROOTCERT=$ca
go test -tags integration -count=1 -v -run TestIAMIntegration ./internal/adapter/postgres/
EOF
