#!/usr/bin/env bash
# Generated only by prepare-oec-bootstrap.py. Intended for a fresh Debian-based
# ARM64 Armbian device. Existing installs must use the signed updater.
set -Eeuo pipefail

release_version='@RELEASE_VERSION@'
channel='@RELEASE_CHANNEL@'
fetch_sha256='@FETCH_SHA256@'
public_key_base64='@PUBLIC_KEY_BASE64@'
public_key_sha256='78756e159ec392b52b146b049db79b0d94848ee10359841f58877aad192f1a3f'
github_release_url="https://github.com/tikkacn/TY-Gateway/releases/download/v${release_version}"
r2_release_url="https://oec.uutec.net/releases/${release_version}"
r2_fetch_url="https://oec.uutec.net/bootstrap/${release_version}/ty-release-fetch-linux-arm64"
dae_version='2.1.1'
dae_sha256='e7ecc9600df20163e90b9cab018f522e090996993c971ad0c271fb5b33c3a387'
dae_url="https://github.com/daeuniverse/dae/releases/download/v${dae_version}/dae-linux-arm64.deb"

[[ "$channel" == stable || "$channel" == pilot ]] || { echo 'Invalid embedded release channel.' >&2; exit 2; }
[[ "$(id -u)" == 0 ]] || { echo 'Run as root.' >&2; exit 2; }
[[ "$(uname -m)" == aarch64 || "$(uname -m)" == arm64 ]] || { echo 'ARM64 Linux is required.' >&2; exit 2; }
[[ -d /run/systemd/system ]] || { echo 'systemd is required.' >&2; exit 2; }
[[ -e /usr/bin/nmcli || -e /bin/nmcli ]] || { echo 'Use an Armbian image with NetworkManager installed.' >&2; exit 2; }
[[ -x /usr/bin/apt-get && -x /usr/bin/dpkg-deb ]] || { echo 'This installer supports Debian/Ubuntu based Armbian only.' >&2; exit 2; }
[[ -r /etc/os-release ]] && grep -Eq '^(ID=(debian|ubuntu)|ID_LIKE=.*(debian|ubuntu))' /etc/os-release || {
  echo 'This installer supports Debian/Ubuntu based Armbian only.' >&2; exit 2;
}
command -v ip >/dev/null 2>&1 || { echo 'iproute2 is required by Armbian.' >&2; exit 2; }
nmcli -t -f RUNNING general status | grep -qx running || { echo 'NetworkManager is not running; fix the base network before installing.' >&2; exit 2; }
ip -4 route show default | grep -q . || { echo 'No IPv4 default route; connect the OEC to the existing router first.' >&2; exit 2; }
[[ ! -e /usr/local/bin/ty-gateway-agent && ! -e /var/lib/ty-gateway/credentials.json ]] || {
  echo 'TY Gateway is already installed; use the signed software updater.' >&2; exit 2;
}
if command -v dae >/dev/null 2>&1 || [[ -e /usr/bin/dae || -e /usr/lib/systemd/system/dae.service || -e /lib/systemd/system/dae.service ]]; then
  echo 'A DAE installation already exists; bootstrap will not replace it.' >&2; exit 2
fi

kernel_version="$(uname -r)"
kernel_version_number="${kernel_version%%-*}"
IFS=. read -r kernel_major kernel_minor _ <<<"$kernel_version_number"
if [[ "$kernel_major" =~ ^[0-9]+$ && "$kernel_minor" =~ ^[0-9]+$ ]] &&
   (( kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 17) )); then
  kernel_version_ok=1
else
  echo "DAE requires Linux 5.17 or newer; found $kernel_version. No TY Gateway files have been installed." >&2
  exit 2
fi

work_dir="$(mktemp -d /var/tmp/ty-gateway-bootstrap.XXXXXXXX)"
chmod 0700 "$work_dir"
trap 'rm -rf -- "$work_dir"' EXIT

# Check upstream dae's required kernel options when Armbian exposes its config.
# A passing config check is necessary, but live eBPF attachment still needs a
# device test. An unavailable config is reported as unknown rather than guessed.
kernel_config=''
for candidate in "/boot/config-${kernel_version}" /boot/config; do
  if [[ -r "$candidate" ]]; then kernel_config="$candidate"; break; fi
done
if [[ -z "$kernel_config" && -r /proc/config.gz ]] && command -v zcat >/dev/null 2>&1; then
  kernel_config='/proc/config.gz'
fi
kernel_missing=()
kernel_runtime_missing=()
if [[ -n "$kernel_config" ]]; then
  config_tmp="$work_dir/kernel.config"
  if [[ "$kernel_config" == /proc/config.gz ]]; then zcat /proc/config.gz >"$config_tmp"; else cp -- "$kernel_config" "$config_tmp"; fi
  for option in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_CGROUPS CONFIG_KPROBES CONFIG_NET_INGRESS CONFIG_NET_EGRESS CONFIG_NET_CLS_ACT CONFIG_BPF_STREAM_PARSER CONFIG_DEBUG_INFO CONFIG_DEBUG_INFO_BTF CONFIG_KPROBE_EVENTS CONFIG_BPF_EVENTS; do
    grep -qx "${option}=y" "$config_tmp" || kernel_missing+=("$option")
  done
  for option in CONFIG_NET_SCH_INGRESS CONFIG_NET_CLS_BPF; do
    grep -Eq "^${option}=(y|m)$" "$config_tmp" || kernel_missing+=("$option")
  done
  grep -qx '# CONFIG_DEBUG_INFO_REDUCED is not set' "$config_tmp" || kernel_missing+=(CONFIG_DEBUG_INFO_REDUCED)
  rm -f -- "$config_tmp"
fi
[[ -r /sys/kernel/btf/vmlinux ]] || kernel_runtime_missing+=(BTF)
if command -v mountpoint >/dev/null 2>&1 && mountpoint -q /sys/fs/bpf; then
  :
else
  kernel_runtime_missing+=(bpffs-mount)
fi

# Install only the small runtime dependencies. This does not run apt upgrade,
# install a network manager, change addresses, or enable DHCP/DNS/proxying.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl dnsmasq-base python3 python3-dbus
python3 -c 'import dbus' >/dev/null
[[ -x /usr/sbin/dnsmasq ]] || { echo 'dnsmasq-base installation did not provide /usr/sbin/dnsmasq.' >&2; exit 2; }
[[ -e /usr/bin/nmcli || -e /bin/nmcli ]] || { echo 'NetworkManager disappeared during dependency installation.' >&2; exit 2; }
ip -4 route show default | grep -q . || { echo 'No IPv4 default route; connect the OEC to the existing router first.' >&2; exit 2; }

printf '%s' "$public_key_base64" | base64 -d > "$work_dir/release-public.pem"
chmod 0600 "$work_dir/release-public.pem"
printf '%s  %s\n' "$public_key_sha256" "$work_dir/release-public.pem" | sha256sum --check --status || {
  echo 'Embedded TY Gateway public key does not match the pinned key.' >&2; exit 2;
}
fetch="$work_dir/ty-release-fetch-linux-arm64"
dae_deb="$work_dir/dae-linux-arm64.deb"

download_exact() {
  local primary="$1" backup="$2" target="$3"
  if curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
       --connect-timeout 10 --max-time 240 "$primary" -o "$target"; then
    return 0
  fi
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 240 "$backup" -o "$target"
}

download_exact "$github_release_url/ty-release-fetch-linux-arm64" "$r2_fetch_url" "$fetch"
printf '%s  %s\n' "$fetch_sha256" "$fetch" | sha256sum --check --status || {
  echo 'TY Gateway verifier hash mismatch; no downloaded code was executed.' >&2; exit 2;
}
chmod 0700 "$fetch"

bundle="$work_dir/release.json"
artifact="$work_dir/ty-gateway-oec-overlay.tar.gz"
download_exact "$github_release_url/release.json" "$r2_release_url/$channel/release.json" "$bundle"
download_exact "$github_release_url/ty-gateway-oec-overlay.tar.gz" "$r2_release_url/ty-gateway-oec-overlay.tar.gz" "$artifact"
mkdir -m 0700 "$work_dir/cache"
"$fetch" stage-local -json -channel "$channel" -public-key "$work_dir/release-public.pem" \
  -output-dir "$work_dir/cache" -bundle "$bundle" -artifact "$artifact" > "$work_dir/result.json"
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

# DAE is fetched directly from its official release and pinned by SHA-256.
# Extract its files without running the upstream post-install script, which may
# restart a service. The TY Gateway proxy switch remains off after a fresh install.
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 240 "$dae_url" -o "$dae_deb"
printf '%s  %s\n' "$dae_sha256" "$dae_deb" | sha256sum --check --status || {
  echo 'Official DAE package hash mismatch; refusing installation.' >&2; exit 2;
}
[[ "$(dpkg-deb -f "$dae_deb" Architecture)" == arm64 && "$(dpkg-deb -f "$dae_deb" Version)" == "$dae_version" ]] || {
  echo 'Official DAE package metadata did not match the pinned ARM64 release.' >&2; exit 2;
}
mkdir -m 0700 "$work_dir/dae"
dpkg-deb -x "$dae_deb" "$work_dir/dae"
dae_source="$work_dir/dae/usr/bin/dae"
dae_unit="$work_dir/dae/usr/lib/systemd/system/dae.service"
[[ -f "$dae_unit" ]] || dae_unit="$work_dir/dae/lib/systemd/system/dae.service"
[[ -f "$dae_source" && -f "$dae_unit" && -f "$work_dir/dae/usr/share/dae/geoip.dat" && -f "$work_dir/dae/usr/share/dae/geosite.dat" ]] || {
  echo 'Pinned DAE package is missing required runtime files.' >&2; exit 2;
}

install -D -o root -g root -m 0755 "$dae_source" /usr/bin/dae
install -D -o root -g root -m 0644 "$dae_unit" /usr/lib/systemd/system/dae.service
install -D -o root -g root -m 0644 "$work_dir/dae/usr/share/dae/geoip.dat" /usr/share/dae/geoip.dat
install -D -o root -g root -m 0644 "$work_dir/dae/usr/share/dae/geosite.dat" /usr/share/dae/geosite.dat
install -d -o root -g root -m 0755 /etc/dae/ty-gateway
if [[ ! -e /etc/dae/config.dae ]]; then
  cat > /etc/dae/config.dae <<'DAE_CONFIG'
include {
  /etc/dae/ty-gateway/managed.dae
}
DAE_CONFIG
  chown root:root /etc/dae/config.dae
  chmod 0600 /etc/dae/config.dae
fi
if [[ ! -e /etc/dae/ty-gateway/managed.dae ]]; then
  cat > /etc/dae/ty-gateway/managed.dae <<'DAE_MANAGED'
# Managed by TY Gateway. Initial policy is direct.
routing {
  dip(geoip:private, 224.0.0.0/3, 'ff00::/8') -> direct
  fallback: direct
}
DAE_MANAGED
  chown root:root /etc/dae/ty-gateway/managed.dae
  chmod 0600 /etc/dae/ty-gateway/managed.dae
fi
systemctl daemon-reload
systemctl disable dae >/dev/null 2>&1 || true
if systemctl is-active --quiet dae; then
  echo 'DAE unexpectedly became active during installation; stopping it to preserve the default-off proxy state.' >&2
  systemctl stop dae
fi

echo "Installing signed TY Gateway $release_version ($channel) and DAE $dae_version."
/bin/bash "$staged/install-oec-overlay.sh"

echo 'Installation completed. DHCP, LAN DNS, and DAE proxy routing remain off by default.'
if [[ -z "$kernel_config" ]]; then
  echo "DAE kernel configuration: unknown (no readable kernel config for $kernel_version); BTF/BPF filesystem checks alone are not conclusive."
elif ((${#kernel_missing[@]})); then
  echo "DAE kernel configuration: missing ${kernel_missing[*]}. Software is installed, but the proxy switch may not work until a compatible kernel is used."
else
  echo 'DAE kernel configuration: upstream-required options are present; actual eBPF attachment still needs on-device validation.'
fi
if ((${#kernel_runtime_missing[@]})); then
  echo "DAE runtime prerequisites not detected: ${kernel_runtime_missing[*]}. The proxy switch must remain off until these are resolved."
fi
echo 'Next: open http://<OEC-LAN-IP>:8088, set the local password, and confirm Cloud enrollment before changing network settings.'
