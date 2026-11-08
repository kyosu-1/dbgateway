#!/usr/bin/env bash
# Prints the environment for the end-to-end tests against this Cloud Run
# deployment (go test -tags cloud ./test/cloud/), including one-time passkey
# enrollment links for the requester and the approver.
#
# Usage: eval "$(deploy/gcp-cloudrun/verify-env.sh)"   (or copy the output)
# Requires: terraform (applied with an image), setup.sh already run (it
# writes cloudsql-server-ca.pem), go, gcloud, and a client inside
# allowed_cidr (the links are written to the management database over the
# Cloud SQL public IP).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
tf() { terraform -chdir="$here" "$@"; }

ca="$here/cloudsql-server-ca.pem"
if [ ! -s "$ca" ]; then
  echo "verify-env.sh: $ca is missing; run setup.sh first" >&2
  exit 1
fi

# dbgateway's issuer, OAuth redirect URIs and WebAuthn origin are built from
# server.public_url (Cloud Run's deterministic URL), so the tests must use
# that URL; the service's other URL (service_uri) reaches the same service
# but does not match the configuration.
url=$(tf output -raw public_url)
if ! tf output -json service_urls | grep -qF "\"$url\""; then
  echo "verify-env.sh: warning: Cloud Run did not report $url among the service's URLs (terraform output service_urls)" >&2
fi

requester=$(tf output -raw requester_email)
approver=$(tf output -raw approver_email)
config=$(tf output -raw dbgateway_config)
store_dsn=$(tf output -raw store_dsn_public)
db_ca=$(cat "$ca")

# `dbgw passkey enroll` prints the link on stdout and a note on stderr
# (left on the terminal).
# The link is built from server.public_url; the store is reached over the
# public IP with the same CA.
enroll() {
  (cd "$root" && DBGW_CONFIG_YAML="$config" DBGW_STORE_DSN="$store_dsn" DBGW_DB_CA="$db_ca" \
    go run ./cmd/dbgw passkey enroll --config env:DBGW_CONFIG_YAML --email "$1") |
    grep -Eo 'https://[^[:space:]]+/passkeys/enroll/[^[:space:]]+' | head -n1 || true
}
enroll_requester=$(enroll "$requester")
enroll_approver=$(enroll "$approver")
if [ -z "$enroll_requester" ] || [ -z "$enroll_approver" ]; then
  echo "verify-env.sh: dbgw passkey enroll failed (is your IP in allowed_cidr and setup.sh done?)" >&2
  exit 1
fi

# Cloud Run accepts the invoker's ID token in X-Serverless-Authorization
# (when both headers are sent, only that one is checked, and its signature is
# removed before the request reaches the container), so Authorization is
# passed through for dbgateway's own OAuth tokens. The header value is expanded by the test
# process's shell or by the tester; it is printed unexpanded on purpose.
cat <<EOF
DBGW_CLOUD_URL=$url
DBGW_CLOUD_HEADER="X-Serverless-Authorization: Bearer \$(gcloud auth print-identity-token)"
DBGW_CLOUD_DB=cloud-main
DBGW_CLOUD_ENROLL_REQUESTER=$enroll_requester
DBGW_CLOUD_ENROLL_APPROVER=$enroll_approver
EOF
