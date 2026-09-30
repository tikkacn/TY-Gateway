#!/usr/bin/env bash
set -Eeuo pipefail

out_dir="${1:-work/oec-dist}"
version="${TY_AGENT_VERSION:-0.8.5}"
release_github_repo="${TY_RELEASE_GITHUB_REPO:-tikkacn/TY-Gateway}"
if [[ -n "$release_github_repo" && ! "$release_github_repo" =~ ^[A-Za-z0-9-]{1,39}/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}$ ]]; then
  echo "TY_RELEASE_GITHUB_REPO must be an owner/repository name" >&2
  exit 2
fi
mkdir -p "$out_dir"

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w -X main.version=${version}" \
  -o "${out_dir}/gateway-agent-linux-arm64" ./cmd/gateway-agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" \
  -o "${out_dir}/dae-config-helper-linux-arm64" ./cmd/dae-config-helper
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" \
  -o "${out_dir}/gateway-local-linux-arm64" ./cmd/gateway-local
release_fetch_ldflags="-s -w"
if [[ -n "$release_github_repo" ]]; then
  release_fetch_ldflags+=" -X main.githubRepo=${release_github_repo}"
fi
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="$release_fetch_ldflags" \
  -o "${out_dir}/ty-release-fetch-linux-arm64" ./cmd/ty-release-fetch

sha256sum "${out_dir}/gateway-agent-linux-arm64" "${out_dir}/dae-config-helper-linux-arm64" "${out_dir}/gateway-local-linux-arm64" "${out_dir}/ty-release-fetch-linux-arm64" > "${out_dir}/SHA256SUMS"
echo "Built ${out_dir}/gateway-agent-linux-arm64"
echo "Built ${out_dir}/dae-config-helper-linux-arm64"
echo "Built ${out_dir}/gateway-local-linux-arm64"
echo "Built ${out_dir}/ty-release-fetch-linux-arm64"
