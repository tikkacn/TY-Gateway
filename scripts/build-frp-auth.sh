#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
goos="${GOOS:-linux}"
goarch="${GOARCH:-amd64}"
out_dir="${1:-${repo_root}/work/frp-auth-dist}"

if [[ "$goos" != linux || ( "$goarch" != amd64 && "$goarch" != arm64 ) ]]; then
  echo "Supported targets: linux/amd64 and linux/arm64" >&2
  exit 2
fi

mkdir -p "$out_dir"
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required to write the artifact checksum" >&2
  exit 1
fi

binary="${out_dir%/}/ty-frp-auth-${goos}-${goarch}"
CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
  go build -trimpath -buildvcs=false -ldflags='-s -w' \
  -o "$binary" "$repo_root/cmd/ty-frp-auth"

(cd "$out_dir" && sha256sum "$(basename "$binary")" > "$(basename "$binary").sha256")

echo "Built $binary"
echo "Checksum: $binary.sha256"
