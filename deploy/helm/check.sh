#!/bin/sh
# Checks the Helm chart without a cluster:
#   - helm lint --strict and helm template with each value set in ci/
#   - the rendered manifests against the Kubernetes schemas (kubeconform)
#   - the rendered dbgateway configuration with `dbgw config validate`
#   - invalid combinations of values are refused
#
# Usage: deploy/helm/check.sh   (from anywhere; needs helm, bin/dbgw and,
# optionally, kubeconform on PATH or in $KUBECONFORM)
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
chart="$root/deploy/helm/dbgateway"
dbgw=${DBGW:-$root/bin/dbgw}
kubeconform=${KUBECONFORM:-kubeconform}
k8s_version=${KUBERNETES_VERSION:-1.31.0}
# JSON schemas of CRDs (ServiceMonitor), pinned to a commit.
crd_schemas='https://raw.githubusercontent.com/datreeio/CRDs-catalog/49729e49e8f062933e3716a26540d41b0cd0856c/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

if ! command -v "$kubeconform" >/dev/null 2>&1; then
  echo "kubeconform not found: skipping schema validation" >&2
  kubeconform=
fi
if [ ! -x "$dbgw" ]; then
  echo "$dbgw not found: run 'make build' first" >&2
  exit 1
fi

for values in "$chart"/ci/*-values.yaml; do
  name=$(basename "$values" -values.yaml)
  echo "--- $name"
  helm lint --strict "$chart" -f "$values"
  helm template dbgateway "$chart" --namespace dbgateway -f "$values" > "$out/$name.yaml"
  if [ -n "$kubeconform" ]; then
    "$kubeconform" -strict -summary -kubernetes-version "$k8s_version" \
      -schema-location default -schema-location "$crd_schemas" "$out/$name.yaml"
  fi
  # The configuration rendered into the ConfigMap (absent with existingConfigMap).
  awk 'f && /^    /{print substr($0, 5); next} f{f=0} /^  dbgateway.yaml: \|$/{f=1}' \
    "$out/$name.yaml" > "$out/$name.dbgateway.yaml"
  if [ -s "$out/$name.dbgateway.yaml" ]; then
    "$dbgw" config validate --config "$out/$name.dbgateway.yaml"
  fi
done

# Each of these must be refused by the chart with the given message.
expect_failure() {
  message=$1
  shift
  if helm template dbgateway "$chart" "$@" > "$out/fail.log" 2>&1; then
    echo "expected failure ($message) but rendering succeeded: $*" >&2
    exit 1
  fi
  if ! grep -q -- "$message" "$out/fail.log"; then
    echo "expected '$message', got:" >&2
    cat "$out/fail.log" >&2
    exit 1
  fi
  echo "refused as expected: $message"
}

single="$chart/ci/single-instance-values.yaml"
multi="$chart/ci/multi-instance-values.yaml"

echo "--- invalid values"
expect_failure "config.auth is required"
expect_failure "requires the PostgreSQL store" -f "$single" --set replicaCount=2
expect_failure "requires config.audit.output: postgres" -f "$multi" --set config.audit.output=file
expect_failure "requires persistence.enabled: false" -f "$multi" --set persistence.enabled=true
expect_failure "is a loopback address" -f "$single" --set config.server.listen=127.0.0.1:8443
expect_failure "must equal ports.http" -f "$single" --set config.server.listen=0.0.0.0:8080
expect_failure "set config.server.public_url" -f "$single" --set config.server.public_url=null
expect_failure "must use https" -f "$single" --set config.server.public_url=http://dbgateway.example.com
expect_failure "is not one of ingress.hosts" -f "$multi" --set config.server.public_url=https://other.example.com
expect_failure "must equal ports.metrics" -f "$multi" --set config.server.metrics_listen=0.0.0.0:9100
expect_failure "requires metrics.enabled" -f "$single" --set metrics.serviceMonitor.enabled=true
echo "ok"
