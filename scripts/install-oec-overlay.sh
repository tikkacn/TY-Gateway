#!/usr/bin/env bash
set -Eeuo pipefail

package_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
payload_dir="$package_dir/payload"
test_root="${TY_OVERLAY_TEST_ROOT:-}"
if [[ "${TY_OVERLAY_TEST_MODE:-0}" == 1 ]]; then
  [[ -n "$test_root" ]] || { echo "Test mode requires an isolated temporary root" >&2; exit 2; }
  case "$test_root" in
    "${TMPDIR:-/tmp}"/ty-oec-overlay-test.*) ;;
    *) echo "Refusing test root outside the temporary test directory" >&2; exit 2 ;;
  esac
  target_root="$(CDPATH= cd -- "$test_root" && pwd -P)"
  [[ "$target_root" != / ]] || { echo "Refusing test root /" >&2; exit 2; }
  test_bin="${TY_OVERLAY_TEST_BIN:-}"
  [[ -n "$test_bin" && "$test_bin" == "$(dirname -- "$target_root")/fake-bin" ]] || {
    echo "Test mode requires fake system tools beside the temporary root" >&2
    exit 2
  }
  for command_name in systemctl getent groupadd useradd install chown; do
    command_path="$(command -v "$command_name" 2>/dev/null || true)"
    [[ "$command_path" == "$test_bin/"* ]] || {
      echo "Test mode requires a mocked $command_name command" >&2
      exit 2
    }
  done
else
  [[ -z "$test_root" ]] || { echo "TY_OVERLAY_TEST_ROOT is only valid in explicit test mode" >&2; exit 2; }
  target_root=""
  [[ "$(id -u)" == 0 ]] || { echo "Run this installer as root" >&2; exit 2; }
  case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "Refusing installation on $(uname -m); this overlay is for the ARM64 OEC" >&2; exit 2 ;;
  esac
  [[ -d /run/systemd/system ]] || { echo "systemd is required" >&2; exit 2; }
  python3 -c 'import dbus' >/dev/null 2>&1 || { echo "python3-dbus is required" >&2; exit 2; }
  [[ -x /usr/sbin/dnsmasq ]] || { echo "Install dnsmasq-base before this overlay" >&2; exit 2; }
fi

target() {
  if [[ -n "$target_root" ]]; then
    printf '%s%s' "$target_root" "$1"
  else
    printf '%s' "$1"
  fi
}

activation_source="${TY_ACTIVATION_SOURCE:-}"
activation_target="$(target /var/lib/ty-gateway/activation.json)"
if [[ -n "$activation_source" ]]; then
  [[ -f "$activation_source" && ! -L "$activation_source" ]] || {
    echo "TY_ACTIVATION_SOURCE must name a regular activation JSON file" >&2
    exit 2
  }
  [[ ! -e "$activation_target" && ! -L "$activation_target" &&
     ! -e "$(target /var/lib/ty-gateway/credentials.json)" &&
     ! -L "$(target /var/lib/ty-gateway/credentials.json)" ]] || {
    echo "Refusing to overwrite existing device identity or activation" >&2
    exit 2
  }
fi

# Check the package before touching the target. Trim a trailing CR so packages
# copied through Windows still receive full verification; do not skip failures.
sum_file="$package_dir/SHA256SUMS"
[[ -f "$sum_file" ]] || { echo "SHA256SUMS is missing" >&2; exit 2; }
declare -A checksum_seen=()
checksum_count=0
normalized_sums=""
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^([[:xdigit:]]{64})[[:space:]]+[*]?(.+)$ ]] || {
    echo "Invalid line in SHA256SUMS" >&2; exit 2;
  }
  expected="${BASH_REMATCH[1],,}"
  relative="${BASH_REMATCH[2]}"
  relative="${relative#./}"
  case "$relative" in
    ""|/*|../*|*/../*|*/..|./*|*/./*|*/.) echo "Unsafe path in SHA256SUMS: $relative" >&2; exit 2 ;;
  esac
  [[ "$relative" =~ ^[-A-Za-z0-9_./]+$ ]] || { echo "Invalid path in SHA256SUMS" >&2; exit 2; }
  [[ -n "$relative" && ! -v "checksum_seen[$relative]" ]] || {
    echo "Duplicate or empty path in SHA256SUMS" >&2; exit 2;
  }
  checksum_seen["$relative"]=1
  file="$package_dir/$relative"
  [[ -f "$file" && ! -L "$file" ]] || { echo "Package file is missing or unsafe: $relative" >&2; exit 2; }
  normalized_sums+="$expected  $relative"$'\n'
  ((checksum_count+=1))
done < "$sum_file"
(( checksum_count > 0 )) || { echo "SHA256SUMS is empty" >&2; exit 2; }
if ! printf '%s' "$normalized_sums" | (cd "$package_dir" && sha256sum --check --status); then
  echo "Package checksum verification failed" >&2
  exit 2
fi

required_files=(
  install-oec-overlay.sh restore-oec-overlay.sh README.md target.json overlay-manifest.json
  payload/usr/local/bin/ty-gateway-agent
  payload/usr/local/bin/ty-gateway-local
  payload/usr/local/bin/ty-release-fetch
  payload/usr/local/bin/frpc
  payload/usr/local/libexec/ty-gateway-update
  payload/usr/local/libexec/ty-gateway-update-service
  payload/usr/local/libexec/ty-gateway-dae-helper
  payload/usr/local/libexec/ty-gateway-dae-preflight
  payload/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding
  payload/usr/local/libexec/ty-gateway-firstboot
  payload/usr/local/libexec/ty-gateway-network
  payload/usr/local/libexec/ty_gateway_lan.py
  payload/etc/tmpfiles.d/ty-gateway-lan.conf
  payload/etc/systemd/system/ty-gateway-firstboot.service
  payload/etc/systemd/system/ty-gateway-agent.service
  payload/etc/systemd/system/ty-gateway-local.service
  payload/etc/systemd/system/ty-gateway-network.service
  payload/etc/systemd/system/ty-gateway-lan.service
  payload/etc/systemd/system/ty-gateway-dae-helper.service
  payload/etc/systemd/system/ty-gateway-update-recover.service
  payload/etc/systemd/system/ty-gateway-update-service.service
  payload/etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf
  payload/etc/systemd/system/ty-frpc-rescue.service
  payload/etc/ty-gateway/agent.env.example
  payload/etc/ty-gateway/local.env.example
  payload/etc/ty-gateway/frpc.toml.example
  payload/etc/ty-gateway/release-public.pem
)
for relative in "${required_files[@]}"; do
  [[ -v "checksum_seen[$relative]" ]] || { echo "Required package file is not checksummed: $relative" >&2; exit 2; }
done

# Some archive publishers/transfer paths normalize executable mode bits. The
# signed archive and every file hash have already been verified above, so now
# restore executable modes only for the fixed allowlist of package programs.
# Reject symlinks and non-regular files before chmod to keep this safe for local
# package installs as well as online updates.
payload_executables=(
  payload/usr/local/bin/ty-gateway-agent
  payload/usr/local/bin/ty-gateway-local
  payload/usr/local/bin/ty-release-fetch
  payload/usr/local/bin/frpc
  payload/usr/local/libexec/ty-gateway-network
  payload/usr/local/libexec/ty-gateway-update
  payload/usr/local/libexec/ty-gateway-update-service
  payload/usr/local/libexec/ty-gateway-dae-helper
  payload/usr/local/libexec/ty-gateway-dae-preflight
  payload/usr/local/libexec/ty-gateway-firstboot
  payload/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding
)
for relative in "${payload_executables[@]}"; do
  file="$package_dir/$relative"
  [[ -f "$file" && ! -L "$file" ]] || { echo "Executable payload file is missing or unsafe: $relative" >&2; exit 2; }
  chmod 0755 -- "$file"
done

[[ -x "$payload_dir/usr/local/bin/ty-gateway-agent" && \
   -x "$payload_dir/usr/local/bin/ty-gateway-local" && \
   -x "$payload_dir/usr/local/bin/ty-release-fetch" && \
   -x "$payload_dir/usr/local/libexec/ty-gateway-network" && \
   -x "$payload_dir/usr/local/libexec/ty-gateway-update" && \
   -x "$payload_dir/usr/local/libexec/ty-gateway-update-service" && \
   -x "$payload_dir/usr/local/bin/frpc" && \
   -x "$payload_dir/usr/local/libexec/ty-gateway-dae-helper" && \
   -x "$payload_dir/usr/local/libexec/ty-gateway-dae-preflight" && \
   -x "$payload_dir/usr/local/libexec/ty-gateway-firstboot" ]] || {
  echo "Incomplete overlay payload" >&2
  exit 2
}

systemd_dir="$(target /etc/systemd/system)"
config_dir="$(target /etc/ty-gateway)"
release_public_target="$(target /etc/ty-gateway/release-public.pem)"
if [[ -e "$release_public_target" || -L "$release_public_target" ]]; then
  [[ -f "$release_public_target" && ! -L "$release_public_target" ]] &&
    cmp -s "$payload_dir/etc/ty-gateway/release-public.pem" "$release_public_target" || {
      echo "Existing release trust key differs from the packaged key; refusing implicit key rotation" >&2
      exit 2
    }
fi

# Capture unit states before replacing unit files. Existing service enablement
# is user state: upgrades may refresh active services, but never enable, disable,
# start, or stop a previously installed unit just because it is in this bundle.
repair_initial_install="${TY_OVERLAY_REPAIR_INITIAL_INSTALL:-0}"
[[ "$repair_initial_install" == 0 || "$repair_initial_install" == 1 ]] || {
  echo "TY_OVERLAY_REPAIR_INITIAL_INSTALL must be 0 or 1" >&2; exit 2;
}
units=(
  ty-gateway-firstboot.service
  ty-gateway-dae-helper.service
  ty-gateway-agent.service
  ty-gateway-local.service
  ty-gateway-network.service
  ty-gateway-lan.service
  ty-gateway-update-recover.service
  ty-gateway-update-service.service
  ty-frpc-rescue.service
)
declare -A unit_load=() unit_enabled=() unit_active=() unit_masked=() unit_new=() unit_touched=()
for unit in "${units[@]}"; do
  load_line="$(systemctl show -p LoadState "$unit" 2>/dev/null || true)"
  unit_load["$unit"]="${load_line#LoadState=}"
  [[ -n "${unit_load[$unit]}" ]] || unit_load["$unit"]="not-found"
  unit_enabled["$unit"]="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  unit_active["$unit"]="$(systemctl is-active "$unit" 2>/dev/null || true)"
  unit_new["$unit"]=0
  [[ "${unit_load[$unit]}" == not-found ]] && unit_new["$unit"]=1
  unit_masked["$unit"]=0
  unit_touched["$unit"]=0
  case "${unit_enabled[$unit]}:${unit_load[$unit]}" in
    masked:*|masked-runtime:*|*:masked) unit_masked["$unit"]=1 ;;
  esac
done

frpc_config="$(target /etc/ty-gateway/frpc.toml)"
frpc_binary="$payload_dir/usr/local/bin/frpc"
if ! "$frpc_binary" --version >/dev/null 2>&1; then
  echo "Packaged FRPC executable failed its version check" >&2
  exit 2
fi
if [[ -f "$frpc_config" ]]; then
  # frpc verify is local-only. Suppress diagnostics because config parsers can
  # include credential-bearing values in error output.
  if ! "$frpc_binary" verify -c "$frpc_config" >/dev/null 2>&1; then
    echo "Existing FRPC configuration is invalid for the packaged client; no files were changed" >&2
    exit 2
  fi
fi

declare -a managed_targets=(
  /usr/local/bin/ty-gateway-agent
  /usr/local/bin/ty-gateway-local
  /usr/local/bin/ty-release-fetch
  /usr/local/bin/frpc
  /usr/local/libexec/ty-gateway-update
  /usr/local/libexec/ty-gateway-update-service
  /usr/local/libexec/ty-gateway-dae-helper
  /usr/local/libexec/ty-gateway-dae-preflight
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
  /etc/ty-gateway/agent.env
  /etc/ty-gateway/local.env
  /var/lib/ty-gateway/activation.json
  /var/lib/ty-gateway/pending-enrollment.json
  /var/lib/ty-gateway/.initialized
  /etc/systemd/system/multi-user.target.wants/ty-gateway-firstboot.service
  /etc/systemd/system/multi-user.target.wants/ty-gateway-dae-helper.service
  /etc/systemd/system/multi-user.target.wants/ty-gateway-local.service
  /etc/systemd/system/multi-user.target.wants/ty-gateway-network.service
  /etc/systemd/system/multi-user.target.wants/ty-gateway-agent.service
  /etc/systemd/system/multi-user.target.wants/ty-gateway-update-recover.service
  /etc/systemd/system/multi-user.target.wants/ty-gateway-update-service.service
)
if [[ "${unit_masked[ty-frpc-rescue.service]}" != 1 ]]; then
  managed_targets+=(/etc/systemd/system/ty-frpc-rescue.service)
fi

keep_backup="${TY_OVERLAY_KEEP_BACKUP:-0}"
[[ "$keep_backup" == 0 || "$keep_backup" == 1 ]] || { echo "TY_OVERLAY_KEEP_BACKUP must be 0 or 1" >&2; exit 2; }
backup_report="${TY_OVERLAY_BACKUP_REPORT:-}"
if [[ -n "$backup_report" ]]; then
  [[ "$keep_backup" == 1 && "$backup_report" == /* && -f "$backup_report" && ! -L "$backup_report" ]] || {
    echo "Backup report must be an existing regular file when durable backups are enabled" >&2; exit 2;
  }
fi
if [[ "$keep_backup" == 1 ]]; then
  backup_parent="$(target /var/lib/ty-gateway-update/backups)"
  mkdir -p -- "$backup_parent"
  [[ -d "$backup_parent" && ! -L "$backup_parent" ]] || { echo "Backup directory must be a real directory" >&2; exit 2; }
  chmod 0700 "$backup_parent"
else
  backup_parent="$(target /var/tmp)"
  mkdir -p -- "$backup_parent"
fi
backup_dir="$(mktemp -d "$backup_parent/ty-gateway-overlay.XXXXXX")"
chmod 0700 "$backup_dir"
if [[ "$keep_backup" == 1 ]]; then
  install -m 0700 "$package_dir/restore-oec-overlay.sh" "$backup_dir/restore.sh"
fi
declare -A target_existed=()
snapshot_files="$backup_dir/files.tsv"
for relative in "${managed_targets[@]}"; do
  destination="$(target "$relative")"
  if [[ -e "$destination" || -L "$destination" ]]; then
    target_existed["$relative"]=1
    saved="$backup_dir$relative"
    mkdir -p -- "$(dirname -- "$saved")"
    cp -a -- "$destination" "$saved"
  else
    target_existed["$relative"]=0
  fi
  if [[ "$keep_backup" == 1 ]]; then
    case "$relative" in
      /etc/ty-gateway/agent.env|/etc/ty-gateway/local.env|/var/lib/ty-gateway/*|/etc/systemd/system/multi-user.target.wants/*)
        snapshot_kind=state ;;
      *) snapshot_kind=software ;;
    esac
    printf '%s\t%s\t%s\n' "$snapshot_kind" "${target_existed[$relative]}" "$relative" >> "$snapshot_files"
  fi
done
if [[ "$keep_backup" == 1 ]]; then
  chmod 0600 "$snapshot_files"
  for unit in "${units[@]}"; do
    printf '%s\t%s\t%s\t%s\t%s\n' "$unit" "${unit_load[$unit]}" "${unit_enabled[$unit]}" "${unit_active[$unit]}" "${unit_masked[$unit]}" >> "$backup_dir/units.tsv"
  done
  chmod 0600 "$backup_dir/units.tsv"
fi
if [[ -n "$backup_report" ]]; then
  # The updater records this path before any package file changes. A boot-time
  # recovery can therefore locate the snapshot after an interrupted install.
  printf '%s\n' "$backup_dir" > "$backup_report"
  chmod 0600 "$backup_report"
fi

transaction_active=1
restore_files() {
  local relative destination saved
  for relative in "${managed_targets[@]}"; do
    if [[ "$relative" == /var/lib/ty-gateway/activation.json && -f "$(target /var/lib/ty-gateway/credentials.json)" ]]; then
      # If enrollment completed while the installer was finishing, never
      # resurrect a spent activation code or remove durable credentials.
      continue
    fi
    destination="$(target "$relative")"
    rm -f -- "$destination" || return 1
    if [[ "${target_existed[$relative]}" == 1 ]]; then
      saved="$backup_dir$relative"
      mkdir -p -- "$(dirname -- "$destination")" || return 1
      cp -a -- "$saved" "$destination" || return 1
    fi
  done
}

restore_units() {
  local unit now_active
  for unit in "${units[@]}"; do
    [[ "${unit_masked[$unit]}" == 1 ]] && continue
    # The rescue tunnel is never changed, even while rolling back another unit.
    [[ "$unit" == ty-frpc-rescue.service ]] && continue
    if [[ "${unit_new[$unit]}" == 1 ]]; then
      if [[ "${unit_touched[$unit]}" == 1 ]]; then
        now_active="$(systemctl is-active "$unit" 2>/dev/null || true)"
        [[ "$now_active" != active ]] || systemctl stop "$unit" >/dev/null || return 1
      fi
      continue
    fi
    if [[ "${unit_touched[$unit]}" == 1 && "${unit_active[$unit]}" == active && "$unit" != ty-gateway-firstboot.service ]]; then
      systemctl restart "$unit" >/dev/null 2>&1 || systemctl start "$unit" >/dev/null 2>&1 || return 1
    else
      now_active="$(systemctl is-active "$unit" 2>/dev/null || true)"
      if [[ "${unit_touched[$unit]}" == 1 && "$now_active" == active && "${unit_active[$unit]}" != active ]]; then
        systemctl stop "$unit" >/dev/null || return 1
      fi
    fi
  done
}

stop_new_units() {
  local unit now_active
  for unit in "${units[@]}"; do
    [[ "${unit_new[$unit]}" == 1 && "${unit_touched[$unit]}" == 1 ]] || continue
    [[ "${unit_masked[$unit]}" != 1 && "$unit" != ty-frpc-rescue.service ]] || continue
    now_active="$(systemctl is-active "$unit" 2>/dev/null || true)"
    [[ "$now_active" != active ]] || systemctl stop "$unit" >/dev/null || return 1
  done
}

finish_install() {
  local status=$?
  trap - EXIT
  if (( status != 0 )) && [[ "${transaction_active:-0}" == 1 ]]; then
    set +e
    rollback_ok=1
    stop_new_units || rollback_ok=0
    restore_files || rollback_ok=0
    systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=0
    restore_units || rollback_ok=0
    if [[ "$rollback_ok" == 1 ]]; then
      rm -rf -- "$backup_dir"
      if [[ -n "$backup_report" ]]; then
        printf 'rolled_back\n' > "$backup_report"
      fi
      echo "Installation failed; package-managed files and touched service states were restored. Newly created accounts or directories may remain." >&2
    else
      echo "Installation failed and automatic rollback was incomplete; backup retained at $backup_dir for manual recovery." >&2
    fi
  elif (( status == 0 )) && [[ "${transaction_active:-0}" == 1 ]]; then
    if [[ "$keep_backup" == 1 ]]; then
      printf 'installed\n' > "$backup_dir/result"
      chmod 0600 "$backup_dir/result"
      echo "Software rollback snapshot retained at $backup_dir"
    else
      rm -rf -- "$backup_dir"
    fi
  fi
  exit "$status"
}
trap finish_install EXIT

ensure_directory() {
  local destination="$1" mode="$2" owner="$3" group="$4"
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -d "$destination" && ! -L "$destination" ]] || {
      echo "Expected a real directory at $destination" >&2
      return 1
    }
    return 0
  fi
  install -d -m "$mode" -o "$owner" -g "$group" "$destination"
}

ensure_directory "$(target /etc/systemd/system)" 0755 root root
ensure_directory "$(target /etc/systemd/system/dae.service.d)" 0755 root root
ensure_directory "$(target /etc/NetworkManager/dispatcher.d)" 0755 root root
ensure_directory "$(target /usr/local/bin)" 0755 root root
ensure_directory "$(target /usr/local/libexec)" 0755 root root
mkdir -p -- "$(target /var/tmp)"

if ! getent group tygateway >/dev/null 2>&1; then
  groupadd --system tygateway
fi
if ! getent group typroxy >/dev/null 2>&1; then
  groupadd --system typroxy
fi
if ! getent passwd tygateway >/dev/null 2>&1; then
  useradd --system --gid tygateway --home-dir /var/lib/ty-gateway --shell /usr/sbin/nologin tygateway
fi
if ! getent group tylocal >/dev/null 2>&1; then
  groupadd --system tylocal
fi
if ! getent passwd tylocal >/dev/null 2>&1; then
  useradd --system --gid tylocal --home-dir /var/lib/ty-gateway-local --shell /usr/sbin/nologin tylocal
fi
ensure_directory "$(target /etc/ty-gateway)" 0750 root tygateway
ensure_directory "$(target /var/lib/ty-gateway)" 0700 tygateway tygateway
ensure_directory "$(target /var/lib/ty-gateway-local)" 0700 tylocal tylocal
if [[ -n "$activation_source" ]]; then
  install -o tygateway -g tygateway -m 0600 "$activation_source" "$activation_target"
fi

install -m 0755 "$payload_dir/usr/local/bin/ty-gateway-agent" "$(target /usr/local/bin/ty-gateway-agent)"
install -m 0755 "$payload_dir/usr/local/bin/ty-gateway-local" "$(target /usr/local/bin/ty-gateway-local)"
install -m 0755 "$payload_dir/usr/local/bin/ty-release-fetch" "$(target /usr/local/bin/ty-release-fetch)"
install -m 0755 "$payload_dir/usr/local/bin/frpc" "$(target /usr/local/bin/frpc)"
install -m 0755 "$payload_dir/usr/local/libexec/ty-gateway-update" "$(target /usr/local/libexec/ty-gateway-update)"
install -m 0755 "$payload_dir/usr/local/libexec/ty-gateway-update-service" "$(target /usr/local/libexec/ty-gateway-update-service)"
install -m 0755 "$payload_dir/usr/local/libexec/ty-gateway-dae-helper" "$(target /usr/local/libexec/ty-gateway-dae-helper)"
install -m 0755 "$payload_dir/usr/local/libexec/ty-gateway-dae-preflight" "$(target /usr/local/libexec/ty-gateway-dae-preflight)"
install -m 0755 "$payload_dir/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding" "$(target /etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding)"
install -m 0755 "$payload_dir/usr/local/libexec/ty-gateway-firstboot" "$(target /usr/local/libexec/ty-gateway-firstboot)"
install -m 0755 "$payload_dir/usr/local/libexec/ty-gateway-network" "$(target /usr/local/libexec/ty-gateway-network)"
install -m 0644 "$payload_dir/usr/local/libexec/ty_gateway_lan.py" "$(target /usr/local/libexec/ty_gateway_lan.py)"
ensure_directory "$(target /etc/tmpfiles.d)" 0755 root root
install -m 0644 "$payload_dir/etc/tmpfiles.d/ty-gateway-lan.conf" "$(target /etc/tmpfiles.d/ty-gateway-lan.conf)"
if [[ "${TY_OVERLAY_TEST_MODE:-0}" != 1 ]]; then
  systemd-tmpfiles --create /etc/tmpfiles.d/ty-gateway-lan.conf
fi

install_unit() {
  local unit="$1" source="$2"
  if [[ "${unit_masked[$unit]}" == 1 ]]; then
    echo "Preserving masked service: $unit"
    return
  fi
  install -m 0644 "$payload_dir/etc/systemd/system/$source" "$(target "/etc/systemd/system/$unit")"
}
install_unit ty-gateway-firstboot.service ty-gateway-firstboot.service
install_unit ty-gateway-agent.service ty-gateway-agent.service
install_unit ty-gateway-local.service ty-gateway-local.service
install_unit ty-gateway-network.service ty-gateway-network.service
install_unit ty-gateway-lan.service ty-gateway-lan.service
install_unit ty-gateway-dae-helper.service ty-gateway-dae-helper.service
install_unit ty-gateway-update-recover.service ty-gateway-update-recover.service
install_unit ty-gateway-update-service.service ty-gateway-update-service.service
install -m 0644 "$payload_dir/etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf" "$(target /etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf)"
install_unit ty-frpc-rescue.service ty-frpc-rescue.service

install -m 0640 "$payload_dir/etc/ty-gateway/agent.env.example" "$(target /etc/ty-gateway/agent.env.example)"
install -m 0640 "$payload_dir/etc/ty-gateway/local.env.example" "$(target /etc/ty-gateway/local.env.example)"
install -m 0640 "$payload_dir/etc/ty-gateway/frpc.toml.example" "$(target /etc/ty-gateway/frpc.toml.example)"
install -m 0644 "$payload_dir/etc/ty-gateway/release-public.pem" "$release_public_target"

if [[ ! -e "$(target /etc/ty-gateway/agent.env)" ]]; then
  install -o root -g tygateway -m 0640 "$payload_dir/etc/ty-gateway/agent.env.example" "$(target /etc/ty-gateway/agent.env)"
fi
if [[ ! -e "$(target /etc/ty-gateway/local.env)" ]]; then
  install -o root -g tylocal -m 0640 "$payload_dir/etc/ty-gateway/local.env.example" "$(target /etc/ty-gateway/local.env)"
fi

# The local manager deliberately runs without access to privileged hardware
# metadata. Seed the public device identifier while the installer still runs
# as root; upgrades preserve an operator-provided value.
seed_local_device_code() {
  local local_env="$(target /etc/ty-gateway/local.env)"
  grep -q '^TY_LOCAL_DEVICE_CODE=' "$local_env" 2>/dev/null && return 0
  local interface_name
  interface_name="$(sed -n 's/^TY_LOCAL_INTERFACE=//p' "$local_env" | head -n 1 | tr -d '\r' | xargs)"
  [[ "$interface_name" =~ ^[A-Za-z0-9_.:-]+$ ]] || return 0
  local mac_file="$(target "/sys/class/net/${interface_name}/address")"
  [[ -r "$mac_file" ]] || return 0
  local mac
  mac="$(tr -d ':\r\n' < "$mac_file" | tr '[:lower:]' '[:upper:]')"
  [[ "$mac" =~ ^[0-9A-F]{12}$ ]] || return 0
  printf 'TY_LOCAL_DEVICE_CODE=%s\n' "$mac" >> "$local_env"
}
seed_local_device_code

systemctl daemon-reload

activate_managed_unit() {
  local unit="$1" should_start="$2" should_restart="$3"
  if [[ "$repair_initial_install" == 1 ]]; then
    [[ "${unit_masked[$unit]}" != 1 ]] || {
      echo "Cannot complete first installation while $unit is masked" >&2
      return 1
    }
    # A power loss can leave a unit file installed but not enabled or started.
    # Reconcile the first-install defaults without restarting an active service.
    if [[ "${unit_enabled[$unit]}" != enabled ]]; then
      systemctl enable "$unit" >/dev/null
    fi
    if [[ "$should_start" == yes && "${unit_active[$unit]}" != active ]]; then
      unit_touched["$unit"]=1
      systemctl start "$unit"
    fi
    return 0
  fi
  [[ "${unit_masked[$unit]}" != 1 ]] || return 0
  if [[ "${unit_new[$unit]}" == 1 ]]; then
    systemctl enable "$unit" >/dev/null
    if [[ "$should_start" == yes ]]; then
      unit_touched["$unit"]=1
      systemctl start "$unit"
    fi
  elif [[ "${unit_active[$unit]}" == active && "$should_restart" == yes ]]; then
    if [[ "$unit" == ty-gateway-agent.service && "${TY_OVERLAY_PRESERVE_AGENT_PROCESS:-0}" == 1 ]]; then
      echo "Preserving the running agent process; the updated binary will be used after an operator-approved restart."
      return 0
    fi
    unit_touched["$unit"]=1
    systemctl restart "$unit"
  fi
}

# First installs receive the documented defaults. Upgrades preserve each
# existing unit's enabled/stopped/masked state; active services are refreshed
# in place except FRPC, which is the only remote rescue path in some installs.
activate_managed_unit ty-gateway-dae-helper.service yes yes
activate_managed_unit ty-gateway-network.service yes yes
activate_managed_unit ty-gateway-local.service yes yes
activate_managed_unit ty-gateway-firstboot.service yes no
activate_managed_unit ty-gateway-update-recover.service no no
activate_managed_unit ty-gateway-update-service.service yes yes
credentials="$(target /var/lib/ty-gateway/credentials.json)"
if [[ "$repair_initial_install" == 1 || -f "$credentials" || "${unit_new[ty-gateway-agent.service]}" == 1 ]]; then
  activate_managed_unit ty-gateway-agent.service yes yes
fi
if [[ -n "$activation_source" && "${unit_new[ty-gateway-agent.service]}" != 1 && "${unit_masked[ty-gateway-agent.service]}" != 1 && "${unit_active[ty-gateway-agent.service]}" != active ]]; then
  unit_touched[ty-gateway-agent.service]=1
  systemctl enable ty-gateway-agent.service >/dev/null
  systemctl start ty-gateway-agent.service
fi

echo "TY Gateway overlay installed and package checksums verified."
echo "Existing service enablement and masked states were preserved."
echo "Existing agent.env, local.env, credentials.json and FRPC configuration were retained."
if [[ -f "$frpc_config" ]]; then
  echo "FRPC configuration validated and retained; the rescue service state was not changed."
  echo "A running FRPC process was not restarted; the updated binary and unit take effect on a later operator-approved safe restart."
else
  echo "FRPC is not configured; the rescue service remains untouched and is not enabled by a fresh install."
fi
if [[ -f "$(target /var/lib/ty-gateway/credentials.json)" ]]; then
  echo "Existing enrollment credentials were retained."
else
  if [[ -f "$activation_target" ]]; then
    echo "One-time activation file is ready; first network enrollment will claim it."
  else
    echo "Generic first-boot enrollment is enabled; the device will claim only a MAC pre-registered in the administrator console."
  fi
fi
echo "Local manager URL (until feiliu.local/mDNS is verified): http://<OEC-LAN-IP>:8088"
