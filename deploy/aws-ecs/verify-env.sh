#!/usr/bin/env bash
# Prints the environment for the cloud verification test (test/cloud) as
# KEY=VALUE lines on stdout, and creates two one-time passkey enrollment
# links (valid 24h) in the shared management database:
#
#   set -a; eval "$(deploy/aws-ecs/verify-env.sh)"; set +a
#   go test -tags cloud -count=1 ./test/cloud/
#
# Run after setup.sh. Writes the ALB certificate to alb-cert.pem here.
# Requires: terraform (already applied), go, curl; PostgreSQL reachable
# from allowed_cidr.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

for cmd in terraform go curl; do
  command -v "$cmd" >/dev/null || { echo "verify-env.sh: $cmd is required" >&2; exit 1; }
done

tf() { terraform -chdir="$here" output -raw "$1"; }

hostname=$(tf hostname)
alb=$(tf alb_dns_name)
public_url=$(tf public_url)
requester=$(tf requester_email)
approver=$(tf approver_email)

ca_file="$here/alb-cert.pem"
tf tls_cert_pem >"$ca_file"

db_ca="$here/rds-global-bundle.pem"
if [ ! -s "$db_ca" ]; then
  curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem -o "$db_ca"
fi

# `dbgw passkey enroll` loads the configuration (the IAM endpoints need no
# secrets; sslrootcert_env needs DBGW_DB_CA) and writes the link to the
# management database through the store DSN.
DBGW_CONFIG_YAML=$(tf dbgateway_config)
DBGW_STORE_DSN=$(tf store_dsn)
DBGW_DB_CA=$(cat "$db_ca")
export DBGW_CONFIG_YAML DBGW_STORE_DSN DBGW_DB_CA

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
(cd "$root" && go build -o "$bin/dbgw" ./cmd/dbgw)

# enroll EMAIL: prints the one-time enrollment link for EMAIL.
enroll() {
  local link
  link=$("$bin/dbgw" passkey enroll --config env:DBGW_CONFIG_YAML --email "$1" | grep -m1 -F "$public_url/passkeys/enroll/" || true)
  if [ -z "$link" ]; then
    echo "verify-env.sh: dbgw passkey enroll printed no link for $1" >&2
    exit 1
  fi
  printf '%s\n' "$link"
}

enroll_requester=$(enroll "$requester")
enroll_approver=$(enroll "$approver")

cat <<EOF
DBGW_CLOUD_URL=https://$hostname
DBGW_CLOUD_CONNECT_ADDR=$alb:443
DBGW_CLOUD_CA_FILE=$ca_file
DBGW_CLOUD_DB=cloud-main
DBGW_CLOUD_ENROLL_REQUESTER=$enroll_requester
DBGW_CLOUD_ENROLL_APPROVER=$enroll_approver
EOF
