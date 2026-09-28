#!/usr/bin/env bash
# Generated only by prepare-oec-bootstrap.py. Intended for a fresh Debian-based
# ARM64 Armbian device. Existing installs must use the signed updater.
set -Eeuo pipefail
umask 077

release_version='@RELEASE_VERSION@'
channel='@RELEASE_CHANNEL@'
fetch_sha256='@FETCH_SHA256@'
public_key_base64='@PUBLIC_KEY_BASE64@'
public_key_sha256='78756e159ec392b52b146b049db79b0d94848ee10359841f58877aad192f1a3f'
github_release_url="https://github.com/tikkacn/TY-Gateway/releases/download/v${release_version}"
r2_release_url='@R2_RELEASE_URL@'
r2_fetch_url='@R2_FETCH_URL@'
dae_version='2.1.1'
dae_sha256='e7ecc9600df20163e90b9cab018f522e090996993c971ad0c271fb5b33c3a387'
dae_url="https://github.com/daeuniverse/dae/releases/download/v${dae_version}/dae-linux-arm64.deb"
package_dir=''

usage() {
  echo 'usage: bootstrap-oec.sh [--package-dir DIRECTORY]' >&2
  exit 2
}
while (($#)); do
  case "$1" in
    --package-dir) (($# >= 2)) || usage; package_dir="$2"; shift 2 ;;
    *) usage ;;
  esac
done

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
command -v flock >/dev/null 2>&1 || { echo 'flock is required to prevent concurrent installations.' >&2; exit 2; }
nmcli -t -f RUNNING general status | grep -qx running || { echo 'NetworkManager is not running; fix the base network before installing.' >&2; exit 2; }
ip -4 route show default | grep -q . || { echo 'No IPv4 default route; connect the OEC to the existing router first.' >&2; exit 2; }
exec 9>/run/ty-gateway-bootstrap.lock
flock -n 9 || { echo 'Another TY Gateway installation is running.' >&2; exit 2; }

bootstrap_state_dir=/var/lib/ty-gateway-bootstrap
bootstrap_state_file="$bootstrap_state_dir/state"
report_onboarding_status() {
  if [[ -f /var/lib/ty-gateway/credentials.json ]]; then
    echo 'Cloud enrollment: device credentials are saved.'
  else
    echo 'Cloud enrollment: pending. The Agent will retry; verify that this device MAC is pre-registered.'
  fi
  if [[ -f /var/lib/ty-gateway/frpc-auto.toml ]]; then
    echo 'Automatic FRP: device configuration received. Verify real SSH reachability in the administrator console.'
  else
    echo 'Automatic FRP: not provisioned yet. A reserved port or completed software install is not a working tunnel.'
  fi
}
if [[ -e "$bootstrap_state_dir" || -L "$bootstrap_state_dir" ]]; then
  [[ -d "$bootstrap_state_dir" && ! -L "$bootstrap_state_dir" ]] || {
    echo 'Bootstrap state directory is unsafe.' >&2; exit 2;
  }
fi
bootstrap_state=''
if [[ -e "$bootstrap_state_file" || -L "$bootstrap_state_file" ]]; then
  [[ -f "$bootstrap_state_file" && ! -L "$bootstrap_state_file" && "$(stat -c %u "$bootstrap_state_file")" == 0 ]] || {
    echo 'Bootstrap state file is unsafe.' >&2; exit 2;
  }
  bootstrap_state="$(<"$bootstrap_state_file")"
  [[ "$bootstrap_state" == in-progress || "$bootstrap_state" == complete ]] || {
    echo 'Bootstrap state is invalid; no installation changes were made.' >&2; exit 2;
  }
fi
if [[ "$bootstrap_state" == complete ]]; then
  [[ -x /usr/local/bin/ty-gateway-agent ]] || {
    echo 'Bootstrap was marked complete but its Agent is missing; use the signed software repair process.' >&2; exit 2;
  }
  echo 'TY Gateway software installation already completed; no files or services were changed.'
  report_onboarding_status
  exit 0
fi
if [[ -z "$bootstrap_state" ]] && { [[ -e /usr/local/bin/ty-gateway-agent ]] || [[ -e /var/lib/ty-gateway/credentials.json ]]; }; then
  echo 'An older TY Gateway installation exists; use the signed software updater, not first-install bootstrap.' >&2
  exit 2
fi
mark_bootstrap_state() {
  local next_state="$1" temporary
  install -d -o root -g root -m 0700 "$bootstrap_state_dir"
  temporary="$(mktemp "$bootstrap_state_dir/.state.XXXXXXXX")"
  printf '%s\n' "$next_state" > "$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$bootstrap_state_file"
  bootstrap_state="$next_state"
}
# A previous bootstrap may have installed the pinned DAE files before its TY
# Gateway overlay failed. Defer the decision until the signed package and the
# official DAE package have been checked; never overwrite an unrelated DAE.
existing_dae=0
if command -v dae >/dev/null 2>&1 || [[ -e /usr/bin/dae || -e /usr/lib/systemd/system/dae.service || -e /lib/systemd/system/dae.service ]]; then
  existing_dae=1
fi
legacy_retry=0
if [[ -z "$bootstrap_state" ]] && (( existing_dae )); then
  legacy_retry=1
fi
if (( legacy_retry )) && {
  [[ ! -f /etc/dae/config.dae || -L /etc/dae/config.dae || ! -f /etc/dae/ty-gateway/managed.dae || -L /etc/dae/ty-gateway/managed.dae ]] ||
  ! grep -Fxq '# Managed by TY Gateway. Initial policy is direct.' /etc/dae/ty-gateway/managed.dae ||
  systemctl is-active --quiet dae || systemctl is-enabled --quiet dae
}; then
  echo 'An unrelated or active DAE installation is present; bootstrap will not modify it.' >&2
  exit 2
fi
if [[ "$bootstrap_state" == in-progress ]] && systemctl is-active --quiet dae; then
  echo 'DAE is active during an incomplete first installation; refusing to replace a running proxy.' >&2
  exit 2
fi
if [[ -z "$bootstrap_state" ]] && (( ! legacy_retry )); then
  mark_bootstrap_state in-progress
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
  if [[ -z "$backup" ]]; then
    echo 'GitHub download failed; this bootstrap has no fallback source configured.' >&2
    return 1
  fi
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 240 "$backup" -o "$target"
}

bundle="$work_dir/release.json"
artifact="$work_dir/ty-gateway-oec-overlay.tar.gz"
if [[ -n "$package_dir" ]]; then
  [[ -d "$package_dir" && ! -L "$package_dir" ]] || { echo 'Invalid local package directory.' >&2; exit 2; }
  package_dir="$(realpath -- "$package_dir")"
  for name in ty-release-fetch-linux-arm64 release.json ty-gateway-oec-overlay.tar.gz dae-linux-arm64-v2.1.1.deb; do
    [[ -f "$package_dir/$name" && ! -L "$package_dir/$name" ]] || {
      echo "Local package directory is missing a regular $name file." >&2; exit 2;
    }
  done
  cp -- "$package_dir/ty-release-fetch-linux-arm64" "$fetch"
  cp -- "$package_dir/release.json" "$bundle"
  cp -- "$package_dir/ty-gateway-oec-overlay.tar.gz" "$artifact"
  cp -- "$package_dir/dae-linux-arm64-v2.1.1.deb" "$dae_deb"
else
  download_exact "$github_release_url/ty-release-fetch-linux-arm64" "$r2_fetch_url" "$fetch"
  download_exact "$github_release_url/release.json" "$r2_release_url/$channel/release.json" "$bundle"
  download_exact "$github_release_url/ty-gateway-oec-overlay.tar.gz" "$r2_release_url/ty-gateway-oec-overlay.tar.gz" "$artifact"
fi
printf '%s  %s\n' "$fetch_sha256" "$fetch" | sha256sum --check --status || {
  echo 'TY Gateway verifier hash mismatch; no downloaded code was executed.' >&2; exit 2;
}
chmod 0700 "$fetch"

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

# DAE is bundled from its official release or fetched directly, then pinned by SHA-256.
# Extract its files without running the upstream post-install script, which may
# restart a service. The TY Gateway proxy switch remains off after a fresh install.
if [[ -z "$package_dir" ]]; then
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 240 "$dae_url" -o "$dae_deb"
fi
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

cat > "$work_dir/initial-config.dae" <<'DAE_CONFIG'
include {
  /etc/dae/ty-gateway/managed.dae
}
global {
}
DAE_CONFIG
cat > "$work_dir/initial-managed.dae" <<'DAE_MANAGED'
# Managed by TY Gateway. Initial policy is direct.
routing {
  dip(geoip:private, 224.0.0.0/3, 'ff00::/8') -> direct
  fallback: direct
}
DAE_MANAGED

dae_command="$(command -v dae 2>/dev/null || true)"
if (( existing_dae )) && [[ -n "$dae_command" && "$dae_command" != /usr/bin/dae ]]; then
  echo 'DAE resolves outside /usr/bin/dae; bootstrap will not replace it.' >&2
  exit 2
fi

if [[ "$bootstrap_state" == in-progress ]] && (( existing_dae )); then
  # A marker alone must not authorize overwriting an independently installed
  # or subsequently changed DAE. Partial writes are fine, but each existing
  # file has to match the pinned release or our initial default-off policy.
  for pair in \
    "/usr/bin/dae:$dae_source" \
    "/usr/lib/systemd/system/dae.service:$dae_unit" \
    "/usr/share/dae/geoip.dat:$work_dir/dae/usr/share/dae/geoip.dat" \
    "/usr/share/dae/geosite.dat:$work_dir/dae/usr/share/dae/geosite.dat" \
    "/etc/dae/config.dae:$work_dir/initial-config.dae" \
    "/etc/dae/ty-gateway/managed.dae:$work_dir/initial-managed.dae"; do
    destination="${pair%%:*}"
    expected="${pair#*:}"
    if [[ -e "$destination" || -L "$destination" ]] &&
       { [[ ! -f "$destination" || -L "$destination" ]] || ! cmp -s -- "$destination" "$expected"; }; then
      echo "Interrupted installation has a changed DAE file: $destination; no DAE files were replaced." >&2
      exit 2
    fi
  done
  if [[ -e /lib/systemd/system/dae.service && ! -e /usr/lib/systemd/system/dae.service ]] ||
     systemctl is-enabled --quiet dae; then
    echo 'A different or enabled DAE service exists; no DAE files were replaced.' >&2
    exit 2
  fi
fi

if (( legacy_retry )); then
  # Only reuse the exact files and default-off configuration written by the
  # interrupted bootstrap. Any modification or active service is left alone.
  dae_command="$(command -v dae 2>/dev/null || true)"
  if [[ "$dae_command" != /usr/bin/dae ]] ||
     [[ ! -f /usr/bin/dae || -L /usr/bin/dae || ! -f /usr/lib/systemd/system/dae.service || -L /usr/lib/systemd/system/dae.service ]] ||
     [[ ! -f /usr/share/dae/geoip.dat || -L /usr/share/dae/geoip.dat || ! -f /usr/share/dae/geosite.dat || -L /usr/share/dae/geosite.dat ]] ||
     [[ ! -f /etc/dae/config.dae || -L /etc/dae/config.dae || ! -f /etc/dae/ty-gateway/managed.dae || -L /etc/dae/ty-gateway/managed.dae ]] ||
     ! cmp -s -- /usr/bin/dae "$dae_source" ||
     ! cmp -s -- /usr/lib/systemd/system/dae.service "$dae_unit" ||
     ! cmp -s -- /usr/share/dae/geoip.dat "$work_dir/dae/usr/share/dae/geoip.dat" ||
     ! cmp -s -- /usr/share/dae/geosite.dat "$work_dir/dae/usr/share/dae/geosite.dat" ||
     ! cmp -s -- /etc/dae/config.dae "$work_dir/initial-config.dae" ||
     ! cmp -s -- /etc/dae/ty-gateway/managed.dae "$work_dir/initial-managed.dae" ||
     systemctl is-active --quiet dae || systemctl is-enabled --quiet dae; then
    echo 'DAE is already installed but does not match an inactive, unchanged TY Gateway bootstrap. No DAE files were replaced.' >&2
    exit 2
  fi
  echo 'Reusing unchanged DAE files from the interrupted TY Gateway bootstrap.'
  mark_bootstrap_state in-progress
else
  install -D -o root -g root -m 0755 "$dae_source" /usr/bin/dae
  install -D -o root -g root -m 0644 "$dae_unit" /usr/lib/systemd/system/dae.service
  install -D -o root -g root -m 0644 "$work_dir/dae/usr/share/dae/geoip.dat" /usr/share/dae/geoip.dat
  install -D -o root -g root -m 0644 "$work_dir/dae/usr/share/dae/geosite.dat" /usr/share/dae/geosite.dat
  install -d -o root -g root -m 0755 /etc/dae/ty-gateway
  if [[ ! -e /etc/dae/config.dae ]]; then
    install -D -o root -g root -m 0600 "$work_dir/initial-config.dae" /etc/dae/config.dae
  fi
  if [[ ! -e /etc/dae/ty-gateway/managed.dae ]]; then
    install -D -o root -g root -m 0600 "$work_dir/initial-managed.dae" /etc/dae/ty-gateway/managed.dae
  fi
  systemctl daemon-reload
  if systemctl is-active --quiet dae; then
    echo 'DAE became active during first installation; refusing to stop a running proxy.' >&2
    exit 2
  fi
  systemctl disable dae >/dev/null 2>&1 || true
fi

# The direct-only bootstrap config must pass the same DAE parser gate as later
# cloud policies. A missing required section must not be marked installed.
if ! /usr/bin/dae validate -c /etc/dae/config.dae; then
  echo 'Initial DAE configuration failed validation; keeping bootstrap in-progress.' >&2
  exit 2
fi

echo "Installing signed TY Gateway $release_version ($channel) and DAE $dae_version."
TY_OVERLAY_REPAIR_INITIAL_INSTALL=1 /bin/bash "$staged/install-oec-overlay.sh"

# Keep the marker in-progress if the installation stopped before every
# required service was available. A later invocation will reapply the signed
# files and reconcile only the first-install service defaults.
[[ -x /usr/local/bin/ty-gateway-agent && -x /usr/local/bin/ty-gateway-local && -f /var/lib/ty-gateway/.initialized ]] || {
  echo 'TY Gateway files or firstboot initialization are incomplete; retry the same bootstrap.' >&2; exit 2;
}
for required_unit in ty-gateway-firstboot.service ty-gateway-dae-helper.service ty-gateway-agent.service ty-gateway-local.service ty-gateway-network.service ty-gateway-update-recover.service ty-gateway-update-service.service; do
  systemctl is-enabled --quiet "$required_unit" || {
    echo "Required service is not enabled: $required_unit; retry the same bootstrap." >&2; exit 2;
  }
done
for required_unit in ty-gateway-dae-helper.service ty-gateway-agent.service ty-gateway-local.service ty-gateway-network.service ty-gateway-update-service.service; do
  systemctl is-active --quiet "$required_unit" || {
    echo "Required service is not running: $required_unit; retry the same bootstrap." >&2; exit 2;
  }
done
if systemctl is-active --quiet dae || systemctl is-enabled --quiet dae; then
  echo 'DAE proxy was unexpectedly enabled during installation; inspect it before retrying.' >&2
  exit 2
fi
mark_bootstrap_state complete

echo 'Software installation completed. DHCP, LAN DNS, and DAE proxy routing remain off by default.'
report_onboarding_status
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
