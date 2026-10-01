#!/usr/bin/env bash
# Restore only package-managed software from an installer snapshot. The device
# identity, subscription, local password, network plan and FRP credentials stay.
set -Eeuo pipefail

backup_dir="${1:?usage: restore-oec-overlay.sh BACKUP_DIRECTORY}"
[[ $# == 1 && "$backup_dir" == /* ]] || { echo "Expected one absolute backup directory" >&2; exit 2; }

test_root="${TY_OVERLAY_TEST_ROOT:-}"
if [[ "${TY_OVERLAY_TEST_MODE:-0}" == 1 ]]; then
  [[ -n "$test_root" ]] || { echo "Missing isolated test root" >&2; exit 2; }
  case "$test_root" in
    "${TMPDIR:-/tmp}"/ty-oec-overlay-test.*) ;;
    *) echo "Unsafe test root" >&2; exit 2 ;;
  esac
  target_root="$(CDPATH= cd -- "$test_root" && pwd -P)"
  test_bin="${TY_OVERLAY_TEST_BIN:-}"
  [[ -n "$test_bin" && "$test_bin" == "$(dirname -- "$target_root")/fake-bin" ]] || { echo "Missing mocked system tools" >&2; exit 2; }
  [[ "$(command -v systemctl)" == "$test_bin/systemctl" ]] || { echo "Mock systemctl required" >&2; exit 2; }
else
  [[ -z "$test_root" && "$(id -u)" == 0 ]] || { echo "Root privileges required" >&2; exit 2; }
  target_root=""
fi

target() { printf '%s%s' "$target_root" "$1"; }
backup_root="$(target /var/lib/ty-gateway-update/backups)"
[[ -d "$backup_root" && ! -L "$backup_root" && -d "$backup_dir" && ! -L "$backup_dir" ]] || {
  echo "Backup directories must be real directories" >&2; exit 2;
}
[[ "$(dirname -- "$backup_dir")" == "$backup_root" && "$(basename -- "$backup_dir")" == ty-gateway-overlay.* ]] || {
  echo "Backup is outside the TY Gateway rollback directory" >&2; exit 2;
}
if [[ "${TY_OVERLAY_TEST_MODE:-0}" != 1 ]]; then
  [[ "$(stat -c %a "$backup_root")" == 700 && "$(stat -c %a "$backup_dir")" == 700 ]] || {
    echo "Backup directory permissions are unsafe" >&2; exit 2;
  }
fi
[[ -f "$backup_dir/files.tsv" && ! -L "$backup_dir/files.tsv" && -f "$backup_dir/units.tsv" && ! -L "$backup_dir/units.tsv" ]] || {
  echo "Backup metadata is missing or unsafe" >&2; exit 2;
}

# Keep this list in step with the installer's package-managed software paths.
software_paths=(
  /usr/local/bin/ty-gateway-agent
  /usr/local/bin/ty-gateway-local
  /usr/local/bin/ty-release-fetch
  /usr/local/bin/frpc
  /usr/local/libexec/ty-gateway-update
  /usr/local/libexec/ty-gateway-update-service
  /usr/local/libexec/ty-gateway-dae-helper
  /usr/local/libexec/ty-gateway-dae-preflight
  /usr/local/libexec/ty_gateway_dae_compat.py
  /etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding
  /usr/local/libexec/ty-gateway-firstboot
  /usr/local/libexec/ty-gateway-network
  /usr/local/libexec/ty_gateway_lan.py
  /etc/tmpfiles.d/ty-gateway-lan.conf
  /etc/systemd/system/ty-gateway-firstboot.service
  /etc/systemd/system/ty-gateway-agent.service
  /etc/systemd/system/ty-gateway-local.service
  /etc/systemd/system/ty-gateway-network.service
  /etc/systemd/system/ty-gateway-lan.service
  /etc/systemd/system/ty-gateway-dae-helper.service
  /etc/systemd/system/ty-gateway-update-recover.service
  /etc/systemd/system/ty-gateway-update-service.service
  /etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf
  /etc/ty-gateway/agent.env.example
  /etc/ty-gateway/local.env.example
  /etc/ty-gateway/frpc.toml.example
  /etc/ty-gateway/release-public.pem
  /etc/systemd/system/ty-frpc-rescue.service
)
units=(
  ty-gateway-firstboot.service ty-gateway-dae-helper.service
  ty-gateway-agent.service ty-gateway-local.service
  ty-gateway-network.service ty-gateway-lan.service
  ty-gateway-update-recover.service
  ty-gateway-update-service.service
  ty-frpc-rescue.service
)
declare -A expected_path=() existed=() seen=() prior_load=() prior_enabled=() prior_active=() prior_masked=()
for relative in "${software_paths[@]}"; do expected_path["$relative"]=1; done
while IFS=$'\t' read -r kind present relative extra; do
  [[ -z "${extra:-}" && "$present" =~ ^[01]$ && "$relative" == /* ]] || { echo "Invalid backup file metadata" >&2; exit 2; }
  [[ "$kind" == state ]] && continue
  [[ "$kind" == software && -v "expected_path[$relative]" && ! -v "seen[$relative]" ]] || { echo "Unexpected software path in backup" >&2; exit 2; }
  seen["$relative"]=1
  existed["$relative"]="$present"
  saved="$backup_dir$relative"
  if [[ "$present" == 1 ]]; then
    [[ -f "$saved" || -L "$saved" ]] || { echo "A saved software file is missing" >&2; exit 2; }
  else
    [[ ! -e "$saved" && ! -L "$saved" ]] || { echo "Unexpected saved software file" >&2; exit 2; }
  fi
done < "$backup_dir/files.tsv"
for relative in "${software_paths[@]}"; do
  [[ -v "seen[$relative]" ]] || { echo "Backup is incomplete" >&2; exit 2; }
done

declare -A expected_unit=() seen_unit=()
for unit in "${units[@]}"; do expected_unit["$unit"]=1; done
while IFS=$'\t' read -r unit load enabled active masked extra; do
  [[ -z "${extra:-}" && -v "expected_unit[$unit]" && ! -v "seen_unit[$unit]" && "$masked" =~ ^[01]$ ]] || {
    echo "Invalid backup service metadata" >&2; exit 2;
  }
  case "$load:$enabled:$active" in
    *[!A-Za-z0-9.:-]*) echo "Invalid backup service state" >&2; exit 2 ;;
  esac
  seen_unit["$unit"]=1
  prior_load["$unit"]="$load"
  prior_enabled["$unit"]="$enabled"
  prior_active["$unit"]="$active"
  prior_masked["$unit"]="$masked"
done < "$backup_dir/units.tsv"
for unit in "${units[@]}"; do
  [[ -v "seen_unit[$unit]" ]] || { echo "Backup service list is incomplete" >&2; exit 2; }
done

# Remove newly introduced units before replacing files. Never touch the rescue
# service process; it may be the only way to recover a remote device.
for unit in "${units[@]}"; do
  [[ "$unit" == ty-frpc-rescue.service || "${prior_masked[$unit]}" == 1 || "${prior_load[$unit]}" != not-found ]] && continue
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
done
# Compatibility handoff before replacing a newer network helper with an older
# one. This preserves today's LAN plan, but removes an upstream indirection
# which the old helper cannot update when the proxy is later switched off.
dns_helper="$(target /usr/local/libexec/ty_gateway_lan.py)"
if [[ "${TY_OVERLAY_TEST_MODE:-0}" != 1 && -f "$dns_helper" && ! -L "$dns_helper" ]] && \
   grep -q '^def legacy_dns_config():' "$dns_helper"; then
  /usr/bin/python3 "$dns_helper" dns-legacy
fi
for relative in "${software_paths[@]}"; do
  destination="$(target "$relative")"
  rm -f -- "$destination"
  if [[ "${existed[$relative]}" == 1 ]]; then
    mkdir -p -- "$(dirname -- "$destination")"
    cp -a -- "$backup_dir$relative" "$destination"
  fi
done
systemctl daemon-reload
for unit in "${units[@]}"; do
  [[ "$unit" == ty-frpc-rescue.service || "${prior_masked[$unit]}" == 1 || "${prior_load[$unit]}" == not-found ]] && continue
  case "${prior_enabled[$unit]}" in
    enabled) systemctl enable "$unit" >/dev/null ;;
    disabled) systemctl disable "$unit" >/dev/null ;;
  esac
  current="$(systemctl is-active "$unit" 2>/dev/null || true)"
  if [[ "${prior_active[$unit]}" == active && "$unit" != ty-gateway-firstboot.service ]]; then
    if [[ "$current" == active ]]; then systemctl restart "$unit"; else systemctl start "$unit"; fi
  elif [[ "${prior_active[$unit]}" != active && "$current" == active ]]; then
    systemctl stop "$unit"
  fi
done
printf 'restored\n' > "$backup_dir/result"
chmod 0600 "$backup_dir/result"
echo "TY Gateway software files restored. Device identity, local settings and rescue session were retained."
