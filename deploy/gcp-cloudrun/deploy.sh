#!/usr/bin/env bash
# Pushes a locally built dbgateway image to this environment's Artifact
# Registry repository and prints the Terraform commands that deploy it.
# It does not apply anything.
#
# Usage: deploy.sh <local image tag>
#   Build the image for Cloud Run's architecture first, at the repository
#   root, e.g.:
#     docker build --platform linux/amd64 -t dbgateway:test .
# Requires: terraform (applied, at least with image=""), docker, gcloud.
set -euo pipefail
cd "$(dirname "$0")"

if [ $# -ne 1 ]; then
  echo "usage: $0 <local image tag built for linux/amd64>" >&2
  exit 2
fi
local_tag=$1

arch=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$local_tag")
if [ "$arch" != "linux/amd64" ]; then
  echo "$local_tag is $arch; Cloud Run needs linux/amd64 (docker build --platform linux/amd64 ...)" >&2
  exit 1
fi

repo=$(terraform output -raw artifact_repository)
registry=${repo%%/*}
# A unique tag per push, so that Terraform sees a new image and rolls out a
# new revision.
remote="$repo/dbgateway:$(date -u +%Y%m%d-%H%M%S)"

gcloud auth configure-docker "$registry" --quiet
docker tag "$local_tag" "$remote"
docker push "$remote"

# Pin the digest so the revision runs exactly the pushed image.
digest=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$remote" | grep -F "$repo/dbgateway@" | head -n1)
image=${digest:-$remote}

cat <<EOF

Pushed $remote
Deploy it (review the plan before applying), with the same variables as before:

  terraform plan -out=tfplan -var image=$image <your other -var options>
  terraform apply tfplan
EOF
