#!/usr/bin/env bash
# Prepares the Cloud SQL instance created by this Terraform configuration:
# loads the sample schema into `app`, grants the Cloud Run service account's
# IAM database user read and write access to it, and gives dbgw_store the
# management database `dbgateway`. Safe to re-run.
# Requires: terraform (applied), docker, and a client inside allowed_cidr.
set -euo pipefail
cd "$(dirname "$0")"

ip=$(terraform output -raw sql_public_ip)
admin_pw=$(terraform output -raw admin_password)
iam_user=$(terraform output -raw iam_db_user)
ca="$PWD/cloudsql-server-ca.pem"

# The instance's own server CA. Its server certificate has no SAN for the
# IP, so clients verify the CA (sslmode=verify-ca); with a per-instance CA
# that also verifies the server's identity.
terraform output -raw server_ca_cert > "$ca"

psql_admin() {
  local db=$1
  shift
  docker run --rm -i \
    -v "$PWD/../../examples/dev/initdb:/initdb:ro" \
    -v "$ca:/ca.pem:ro" \
    -e PGPASSWORD="$admin_pw" \
    postgres:17 \
    psql "host=$ip dbname=$db user=dbgw_admin sslmode=verify-ca sslrootcert=/ca.pem" \
      -v ON_ERROR_STOP=1 -q "$@"
}

# Target database: the sample schema, created once.
if [ "$(psql_admin app -tA -c "SELECT to_regclass('public.users') IS NOT NULL")" != "t" ]; then
  psql_admin app -f /initdb/01-schema.sql
  # The schema creates dbgw_reader with a well-known password for local
  # development; it is not used here.
  psql_admin app -c "ALTER ROLE dbgw_reader NOLOGIN"
fi

# The IAM user (created by Terraform) is both dbgateway's read_user and
# write_user. Reads stay read-only through READ ONLY transactions and
# default_transaction_read_only on the read connections.
psql_admin app -v iam_user="$iam_user" <<'SQL'
GRANT CONNECT ON DATABASE app TO :"iam_user";
GRANT USAGE ON SCHEMA public TO :"iam_user";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"iam_user";
SQL

# Management database: dbgateway creates its tables on start-up as
# dbgw_store (the public schema belongs to pg_database_owner, i.e. the
# database owner). Databases created through the Cloud SQL API are owned by
# cloudsqlsuperuser; changing the owner needs membership in the new owner,
# hence the GRANT first. If Cloud SQL refuses that, fall back to privileges
# that are enough for dbgateway's migrations.
if ! psql_admin dbgateway <<'SQL'
GRANT dbgw_store TO dbgw_admin;
ALTER DATABASE dbgateway OWNER TO dbgw_store;
SQL
then
  echo "setup.sh: could not make dbgw_store own dbgateway; granting privileges instead" >&2
  psql_admin dbgateway <<'SQL'
GRANT CONNECT, CREATE, TEMPORARY ON DATABASE dbgateway TO dbgw_store;
GRANT USAGE, CREATE ON SCHEMA public TO dbgw_store;
SQL
fi

echo "setup.sh: done (CA written to $ca)"
