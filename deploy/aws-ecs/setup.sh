#!/usr/bin/env bash
# Prepares the RDS instance created by this Terraform configuration:
#   - database app: the sample schema (examples/dev/initdb/01-schema.sql)
#     and the IAM database users dbgw_iam (read) and dbgw_iam_writer (write)
#   - database dbgateway: the management database, owned by dbgw_store
# Idempotent: safe to run again. Runs psql in docker over TLS (verify-full).
# Requires: terraform (already applied), docker, curl.
set -euo pipefail
cd "$(dirname "$0")"

for cmd in terraform docker curl; do
  command -v "$cmd" >/dev/null || { echo "setup.sh: $cmd is required" >&2; exit 1; }
done

host=$(terraform output -raw rds_host)
ca="$PWD/rds-global-bundle.pem"

if [ ! -s "$ca" ]; then
  curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem -o "$ca"
fi

# Passwords are passed through the environment, never on a command line.
PGPASSWORD=$(terraform output -raw admin_password)
DBGW_STORE_PASSWORD=$(terraform output -raw store_password)
export PGPASSWORD DBGW_STORE_PASSWORD

# psql_admin DBNAME [psql args...]: psql as the master user.
psql_admin() {
  local db=$1
  shift
  docker run --rm -i \
    -v "$PWD/../../examples/dev/initdb:/initdb:ro" \
    -v "$ca:/ca.pem:ro" \
    -e PGPASSWORD -e DBGW_STORE_PASSWORD \
    postgres:17 \
    psql "host=$host dbname=$db user=dbgw_admin sslmode=verify-full sslrootcert=/ca.pem" \
      -v ON_ERROR_STOP=1 -q "$@"
}

# --- Target database: sample schema and IAM users -------------------------

# The sample schema creates its tables once; skip it on a re-run.
if [ "$(psql_admin app -tA -c "SELECT to_regclass('public.users') IS NOT NULL")" != "t" ]; then
  echo "Loading the sample schema into app ..." >&2
  psql_admin app -1 -f /initdb/01-schema.sql
fi

echo "Creating the IAM database users ..." >&2
psql_admin app <<'SQL'
SET client_min_messages = warning; -- quiet "already a member" on re-runs
-- The sample schema's password user is not used here; its well-known
-- password must not open a login on a publicly addressable instance.
ALTER ROLE dbgw_reader NOLOGIN;

-- IAM users: no password; logins use RDS authentication tokens (rds_iam).
SELECT 'CREATE ROLE dbgw_iam LOGIN'
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dbgw_iam') \gexec
SELECT 'CREATE ROLE dbgw_iam_writer LOGIN'
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dbgw_iam_writer') \gexec
GRANT rds_iam TO dbgw_iam, dbgw_iam_writer;
GRANT CONNECT ON DATABASE app TO dbgw_iam, dbgw_iam_writer;
GRANT USAGE ON SCHEMA public TO dbgw_iam, dbgw_iam_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dbgw_iam;
-- Approved writes; no DDL: schema changes never go through dbgateway.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dbgw_iam_writer;
SQL

# --- Management database ---------------------------------------------------

echo "Creating the management database ..." >&2
psql_admin postgres <<'SQL'
SET client_min_messages = warning;
SELECT 'CREATE ROLE dbgw_store LOGIN'
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dbgw_store') \gexec
\getenv store_pw DBGW_STORE_PASSWORD
ALTER ROLE dbgw_store WITH LOGIN PASSWORD :'store_pw';
-- PostgreSQL 16+: creating a database owned by another role requires being
-- able to SET ROLE to it.
GRANT dbgw_store TO dbgw_admin;
-- CREATE DATABASE cannot run inside a transaction block (or DO).
SELECT 'CREATE DATABASE dbgateway OWNER dbgw_store'
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'dbgateway') \gexec
REVOKE CONNECT, TEMPORARY ON DATABASE dbgateway FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE dbgateway TO dbgw_store;
SQL

echo "Done. dbgateway creates its tables in the dbgateway database when a task (or 'dbgw passkey enroll') first connects." >&2
