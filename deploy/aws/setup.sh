#!/usr/bin/env bash
# Loads the sample schema into the RDS instance created by this Terraform
# configuration and prints the environment for the integration tests.
# Requires: terraform (already applied), docker, curl.
set -euo pipefail
cd "$(dirname "$0")"

host=$(terraform output -raw host)
admin_pw=$(terraform output -raw admin_password)
reader_pw=$(terraform output -raw reader_password)
ca="$PWD/rds-global-bundle.pem"

if [ ! -f "$ca" ]; then
  curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem -o "$ca"
fi

docker run --rm \
  -v "$PWD/../../examples/dev/initdb:/initdb:ro" \
  -v "$ca:/ca.pem:ro" \
  -e PGPASSWORD="$admin_pw" \
  postgres:17 \
  psql "host=$host dbname=app user=dbgw_admin sslmode=verify-full sslrootcert=/ca.pem" \
    -v ON_ERROR_STOP=1 -q \
    -f /initdb/01-schema.sql \
    -c "ALTER ROLE dbgw_reader PASSWORD '$reader_pw'"

cat <<EOF
# Run the integration tests against RDS (TLS verify-full):
export DBGW_TEST_PG_HOST=$host
export DBGW_TEST_PG_PORT=5432
export DBGW_TEST_PG_SSLMODE=verify-full
export DBGW_TEST_PG_SSLROOTCERT=$ca
export DBGW_TEST_PG_PASSWORD=\$(terraform -chdir=deploy/aws output -raw reader_password)
go test -tags integration -count=1 ./internal/gateway/
EOF
