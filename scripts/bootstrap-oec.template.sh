#!/usr/bin/env bash
# Generated only by prepare-oec-bootstrap.py. This is for a FRESH ARM64 device;
# installed devices use the local update page or ty-gateway-update instead.
set -Eeuo pipefail

release_version='@RELEASE_VERSION@'
fetch_sha256='@FETCH_SHA256@'
public_key_base64='@PUBLIC_KEY_BASE64@'
github_fetch_url='https://github.com/tikkacn/TY-Gateway/releases/download/v@RELEASE_VERSION@/ty-release-fetch-linux-arm64'
r2_fetch_url='https://oec.uutec.net/bootstrap/@RELEASE_VERSION@/ty-release-fetch-linux-arm64'
channel=stable
offline_dir=''

usage() {
  echo 'usage: bootstrap-oec.sh [--channel stable|pilot] [--offline-dir DIRECTORY]' >&2
  exit 2
}
while (($#)); do
  case "$1" in
    --channel) (($# >= 2)) || usage; channel="$2"; shift 2 ;;
    --offline-dir) (($# >= 2)) || usage; offline_dir="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$channel" == stable || "$channel" == pilot ]] || usage
[[ "$(id -u)" == 0 ]] || { echo 'Run as root.' >&2; exit 2; }
[[ "$(uname -m)" == aarch64 || "$(uname -m)" == arm64 ]] || { echo 'ARM64 Linux is required.' >&2; exit 2; }
[[ -d /run/systemd/system ]] || { echo 'systemd is required.' >&2; exit 2; }
for command_name in sha256sum base64 python3 mktemp realpath cp; do
  command -v "$command_name" >/dev/null || { echo "Missing prerequisite: $command_name" >&2; exit 2; }
done
python3 -c 'import dbus' >/dev/null 2>&1 || { echo 'Install python3-dbus first.' >&2; exit 2; }
[[ -x /usr/sbin/dnsmasq ]] || { echo 'Install dnsmasq-base first.' >&2; exit 2; }
[[ -e /usr/bin/nmcli || -e /bin/nmcli ]] || { echo 'NetworkManager is required.' >&2; exit 2; }
[[ ! -e /usr/local/bin/ty-gateway-agent && ! -e /var/lib/ty-gateway/credentials.json ]] || {
  echo 'Device is already installed; use the signed software updater, not bootstrap.' >&2; exit 2;
}

work_dir="$(mktemp -d /var/tmp/ty-gateway-bootstrap.XXXXXXXX)"
chmod 0700 "$work_dir"
trap 'rm -rf -- "$work_dir"' EXIT
printf '%s' "$public_key_base64" | base64 -d > "$work_dir/release-public.pem"
chmod 0600 "$work_dir/release-public.pem"
fetch="$work_dir/ty-release-fetch-linux-arm64"
if [[ -n "$offline_dir" ]]; then
  offline_dir="$(realpath -- "$offline_dir")"
  [[ -d "$offline_dir" && ! -L "$offline_dir" ]] || { echo 'Invalid offline package directory.' >&2; exit 2; }
  cp -- "$offline_dir/ty-release-fetch-linux-arm64" "$fetch"
else
  command -v curl >/dev/null || { echo 'curl is required for online bootstrap.' >&2; exit 2; }
  if ! curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
       --connect-timeout 10 --max-time 180 "$github_fetch_url" -o "$fetch"; then
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --connect-timeout 10 --max-time 180 "$r2_fetch_url" -o "$fetch"
  fi
fi
printf '%s  %s\n' "$fetch_sha256" "$fetch" | sha256sum --check --status || {
  echo 'Bootstrap verifier hash mismatch; no code was executed.' >&2; exit 2;
}
chmod 0700 "$fetch"
mkdir -m 0700 "$work_dir/cache"
if [[ -n "$offline_dir" ]]; then
  "$fetch" stage-local -json -channel "$channel" -public-key "$work_dir/release-public.pem" \
    -output-dir "$work_dir/cache" -bundle "$offline_dir/release.json" \
    -artifact "$offline_dir/ty-gateway-oec-overlay.tar.gz" > "$work_dir/result.json"
else
  "$fetch" stage -json -channel "$channel" -public-key "$work_dir/release-public.pem" \
    -output-dir "$work_dir/cache" > "$work_dir/result.json"
fi
staged="$(python3 - "$work_dir/result.json" "$release_version" <<'PY'
import json
import pathlib
import sys

result = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
if result.get('version') != sys.argv[2] or not isinstance(result.get('staged'), str):
    raise SystemExit('signed release is not the bootstrap-approved version')
print(result['staged'])
PY
)"
[[ -d "$staged" && ! -L "$staged" && "$staged" == "$work_dir/cache/"* ]] || {
  echo 'Invalid verified staging directory.' >&2; exit 2;
}
[[ -f "$staged/install-oec-overlay.sh" && ! -L "$staged/install-oec-overlay.sh" ]] || {
  echo 'Verified overlay is missing its installer.' >&2; exit 2;
}
echo "Installing signed TY Gateway $release_version ($channel) on this fresh device."
/bin/bash "$staged/install-oec-overlay.sh"
echo 'Installation completed. Check local management and Cloud enrollment status before enabling DHCP, DNS or proxying.'
