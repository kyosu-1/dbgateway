#!/usr/bin/env bash
# Loads the sample schema into the RDS instance created by this Terraform
# configuration, creates the IAM database user (when iam_auth is enabled)
# and prints the environment for the integration tests.
# Requires: terraform (already applied), docker, curl.
set -euo pipefail
cd "$(dirname "$0")"

host=$(terraform output -raw host)
region=$(terraform output -raw region)
admin_pw=$(terraform output -raw admin_password)
reader_pw=$(terraform output -raw reader_password)
iam_auth=$(terraform output -raw iam_auth)
ca="$PWD/rds-global-bundle.pem"

if [ ! -f "$ca" ]; then
  curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem -o "$ca"
fi

psql_admin() {
  docker run --rm -i \
    -v "$PWD/../../examples/dev/initdb:/initdb:ro" \
    -v "$ca:/ca.pem:ro" \
    -e PGPASSWORD="$admin_pw" \
    postgres:17 \
    psql "host=$host dbname=app user=dbgw_admin sslmode=verify-full sslrootcert=/ca.pem" \
      -v ON_ERROR_STOP=1 -q "$@"
}

# The sample schema creates its tables once; skip it on a re-run.
if [ "$(psql_admin -tA -c "SELECT to_regclass('public.users') IS NOT NULL")" != "t" ]; then
  psql_admin -f /initdb/01-schema.sql
fi
psql_admin -c "ALTER ROLE dbgw_reader PASSWORD '$reader_pw'"

if [ "$iam_auth" = "true" ]; then
  # IAM user: no password; logins use RDS authentication tokens (rds_iam).
  psql_admin <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dbgw_iam') THEN
    CREATE USER dbgw_iam;
  END IF;
END
$$;
GRANT rds_iam TO dbgw_iam;
GRANT CONNECT ON DATABASE app TO dbgw_iam;
GRANT USAGE ON SCHEMA public TO dbgw_iam;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dbgw_iam;
SQL
fi

cat <<EOF
# Run the integration tests against RDS (TLS verify-full):
export DBGW_TEST_PG_HOST=$host
export DBGW_TEST_PG_PORT=5432
export DBGW_TEST_PG_SSLMODE=verify-full
export DBGW_TEST_PG_SSLROOTCERT=$ca
export DBGW_TEST_PG_PASSWORD=\$(terraform -chdir=deploy/aws output -raw reader_password)
go test -tags integration -count=1 ./internal/gateway/
EOF

if [ "$iam_auth" = "true" ]; then
  cat <<EOF

# IAM database authentication (auth: aws_iam) with your current AWS
# credentials (they need rds-db:connect; see 'terraform output iam_connect_policy'):
export DBGW_TEST_IAM_HOST=$host
export DBGW_TEST_IAM_AUTH=aws_iam
export DBGW_TEST_IAM_USER=dbgw_iam
export DBGW_TEST_IAM_REGION=$region
export DBGW_TEST_IAM_SSLMODE=verify-full
export DBGW_TEST_IAM_SSLROOTCERT=$ca
go test -tags integration -count=1 -v -run TestIAMIntegration ./internal/adapter/postgres/
EOF
fi
