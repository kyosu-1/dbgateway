#!/usr/bin/env bash
# Pushes an already built local dbgateway image (linux/arm64) to the ECR
# repository created by this Terraform configuration, then prints the
# terraform command that rolls it out. Builds nothing and applies nothing.
#
#   ./deploy.sh dbgateway:abc123-arm64
#
# Build the image beforehand from the repository root, e.g.
#   docker buildx build --platform linux/arm64 -t dbgateway:$(git rev-parse --short HEAD)-arm64 --load .
# Requires: terraform (already applied), docker, aws.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 LOCAL_IMAGE:TAG" >&2
  exit 2
fi
src=$1
cd "$(dirname "$0")"

for cmd in terraform docker aws; do
  command -v "$cmd" >/dev/null || { echo "deploy.sh: $cmd is required" >&2; exit 1; }
done

# The tag is what follows the last ':' after the last '/'.
last=${src##*/}
case "$last" in
  *:*) tag=${last##*:} ;;
  *) echo "deploy.sh: give the image with an explicit tag (e.g. dbgateway:abc123-arm64)" >&2; exit 2 ;;
esac

arch=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$src")
if [ "$arch" != "linux/arm64" ]; then
  echo "deploy.sh: $src is $arch; the Fargate tasks run linux/arm64" >&2
  exit 1
fi

repo=$(terraform output -raw ecr_repository_url)
region=$(terraform output -raw region)
registry=${repo%%/*}
dest="$repo:$tag"

aws ecr get-login-password --region "$region" |
  docker login --username AWS --password-stdin "$registry"
docker tag "$src" "$dest"
docker push "$dest"

# Prefer the digest, so that re-pushing a tag always rolls out the image
# that was pushed here.
image=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$dest" | grep -m1 -F "$repo@" || true)
image=${image:-$dest}

cat <<EOF

Pushed $dest
Roll it out (review the plan before applying):

  cd $(pwd)
  terraform plan -var 'image=$image' -out tfplan
  terraform apply tfplan
EOF
