#!/bin/sh
# Download dbgw from a GitHub release into bin/dbgw, verifying its checksum.
# Usage: scripts/download.sh [vX.Y.Z]   (default: the latest release)
# Release binaries exist for linux/amd64, linux/arm64 and darwin/arm64;
# elsewhere, build with `make build` (Go with cgo).
set -eu

repo=kyosu-1/dbgateway
dest=bin
work=bin/.download

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
x86_64) arch=amd64 ;;
aarch64) arch=arm64 ;;
esac

tag=${1:-}
if [ -z "$tag" ]; then
	tag=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
fi
[ -n "$tag" ] || { echo "download: no release found" >&2; exit 1; }

name="dbgw_${tag#v}_${os}_${arch}"
base="https://github.com/$repo/releases/download/$tag"
mkdir -p "$work"
echo "download: $name.tar.gz ($tag)"
if ! curl -fsSL -o "$work/$name.tar.gz" "$base/$name.tar.gz"; then
	echo "download: no release binary for $os/$arch; build it with 'make build' (Go with cgo)" >&2
	exit 1
fi
curl -fsSL -o "$work/checksums.txt" "$base/checksums.txt"
(
	cd "$work"
	grep " $name.tar.gz\$" checksums.txt >"$name.sha256"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -c "$name.sha256"
	else
		shasum -a 256 -c "$name.sha256"
	fi
)
tar -xzf "$work/$name.tar.gz" -C "$work"
mv "$work/$name/dbgw" "$dest/dbgw"
"$dest/dbgw" --version
