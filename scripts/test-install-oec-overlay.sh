#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
installer_source="$repo_dir/scripts/install-oec-overlay.sh"
restore_source="$repo_dir/scripts/restore-oec-overlay.sh"
temp_root="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
test_base="$(mktemp -d "$temp_root/ty-oec-overlay-test.XXXXXX")"
test_base="$(CDPATH= cd -- "$test_base" && pwd -P)"
case "$test_base" in
  "$temp_root"/ty-oec-overlay-test.*) ;;
  *) echo "Unexpected test directory; refusing cleanup" >&2; exit 2 ;;
esac
[[ "$test_base" != / && "$test_base" != "$temp_root" ]] || { echo "Unsafe test directory" >&2; exit 2; }
trap 'rm -rf -- "$test_base"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "$3 (expected '$2', got '$1')"; }
assert_file_eq() {
  local file="$1" expected="$2" actual
  actual="$(<"$file")"
  assert_eq "$actual" "$expected" "$file content"
}

new_fixture() {
  fixture="$test_base/$1"
  package="$fixture/package"
  install_root="$fixture/install"
  fakebin="$fixture/fake-bin"
  mkdir -p "$package/payload/usr/local/bin" "$package/payload/usr/local/libexec" \
    "$package/payload/etc/systemd/system/dae.service.d" "$package/payload/etc/ty-gateway" "$package/payload/etc/tmpfiles.d" \
    "$package/payload/etc/NetworkManager/dispatcher.d" \
    "$install_root" "$fakebin" "$install_root/.service-state"

  cp "$installer_source" "$package/install-oec-overlay.sh"
  cp "$restore_source" "$package/restore-oec-overlay.sh"
  printf 'fixture readme\n' > "$package/README.md"
  printf '{"fixture":true}\n' > "$package/target.json"
  printf '{"fixture":true}\n' > "$package/overlay-manifest.json"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$package/payload/usr/local/bin/ty-gateway-agent"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$package/payload/usr/local/bin/ty-gateway-local"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$package/payload/usr/local/bin/ty-release-fetch"
  printf '#!/usr/bin/python3\n' > "$package/payload/usr/local/libexec/ty-gateway-update"
  printf '#!/usr/bin/python3\n' > "$package/payload/usr/local/libexec/ty-gateway-update-service"
  printf '#!/usr/bin/env bash\nif [[ "${1:-}" == --version ]]; then exit 0; fi\nif [[ "${1:-}" == verify ]]; then grep -q "^invalid$" "${3:-}" && exit 1; exit 0; fi\nexit 2\n' > "$package/payload/usr/local/bin/frpc"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$package/payload/usr/local/libexec/ty-gateway-dae-helper"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$package/payload/usr/local/libexec/ty-gateway-dae-preflight"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$package/payload/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$package/payload/usr/local/libexec/ty-gateway-firstboot"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$package/payload/usr/local/libexec/ty-gateway-network"
  printf '# fixture module\n' > "$package/payload/usr/local/libexec/ty_gateway_lan.py"
  printf 'f /run/xtables.lock 0600 root root -\n' > "$package/payload/etc/tmpfiles.d/ty-gateway-lan.conf"
  chmod 0755 "$package/payload/usr/local/bin/"* "$package/payload/usr/local/libexec/"*
  chmod 0755 "$package/payload/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding"

  for unit in ty-gateway-firstboot ty-gateway-agent ty-gateway-local ty-gateway-network ty-gateway-lan ty-gateway-dae-helper ty-gateway-update-recover ty-gateway-update-service ty-frpc-rescue; do
    printf '[Unit]\nDescription=fixture %s\n' "$unit" > "$package/payload/etc/systemd/system/$unit.service"
  done
  printf '[Service]\nExecStartPre=/usr/local/libexec/ty-gateway-dae-preflight\nExecReload=\nExecReload=/usr/local/libexec/ty-gateway-dae-preflight\nExecReload=/usr/bin/dae reload $MAINPID\n' > "$package/payload/etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf"
  printf 'TY_SERVER_URL=https://example.invalid\n' > "$package/payload/etc/ty-gateway/agent.env.example"
  printf 'TY_LOCAL_INTERFACE=eth0\n' > "$package/payload/etc/ty-gateway/local.env.example"
  printf 'serverAddr="example.invalid"\n' > "$package/payload/etc/ty-gateway/frpc.toml.example"
  printf '%s\n' '-----BEGIN PUBLIC KEY-----' 'fixture' '-----END PUBLIC KEY-----' > "$package/payload/etc/ty-gateway/release-public.pem"

  cat > "$fakebin/systemctl" <<'MOCK_SYSTEMCTL'
#!/usr/bin/env bash
set -eu
action="${1:-}"
shift || true
state_dir="$TY_OVERLAY_TEST_ROOT/.service-state"
log="$TY_OVERLAY_TEST_ROOT/.systemctl.log"
printf '%s %s\n' "$action" "$*" >> "$log"
unit="${*: -1}"
file="$state_dir/$unit"
load=not-found; enabled=disabled; active=inactive
if [[ -f "$file" ]]; then read -r load enabled active < "$file"; fi
save() { printf '%s %s %s\n' "$load" "$enabled" "$active" > "$file"; }
case "$action" in
  show) printf 'LoadState=%s\n' "$load" ;;
  is-enabled) printf '%s\n' "$enabled"; [[ "$enabled" != disabled && "$enabled" != not-found ]] ;;
  is-active) printf '%s\n' "$active"; [[ "$active" == active ]] ;;
  daemon-reload)
    for candidate in ty-gateway-firstboot ty-gateway-agent ty-gateway-local ty-gateway-network ty-gateway-lan ty-gateway-dae-helper ty-gateway-update-recover ty-gateway-update-service ty-frpc-rescue; do
      candidate_file="$state_dir/$candidate.service"
      if [[ ! -f "$candidate_file" && -f "$TY_OVERLAY_TEST_ROOT/etc/systemd/system/$candidate.service" ]]; then
        printf 'loaded disabled inactive\n' > "$candidate_file"
      fi
    done
    ;;
  enable)
    if [[ "${TY_FAKE_FAIL_ENABLE:-}" == "$unit" ]]; then exit 1; fi
    load=loaded; enabled=enabled; save
    ;;
  disable)
    [[ "${1:-}" == --now ]] && shift
    unit="${1:-$unit}"; file="$state_dir/$unit"
    [[ -f "$file" ]] && read -r load enabled active < "$file" || { load=loaded; enabled=disabled; active=inactive; }
    enabled=disabled
    if [[ "${TY_FAKE_DISABLE_NOW:-}" == "$unit" ]]; then active=inactive; fi
    save
    ;;
  start|restart|try-restart)
    if [[ "${TY_FAKE_FAIL_INSTALL_TARGET:-}" == "action:$action:$unit" ]]; then
      marker="$TY_OVERLAY_TEST_ROOT/.fail-once-$action-$unit"
      if [[ ! -e "$marker" ]]; then : > "$marker"; exit 1; fi
    fi
    load=loaded; active=active; save
    ;;
  stop)
    active=inactive; save
    ;;
  *) echo "unexpected mocked systemctl action: $action" >&2; exit 2 ;;
esac
MOCK_SYSTEMCTL

  cat > "$fakebin/getent" <<'MOCK_GETENT'
#!/usr/bin/env bash
exit 2
MOCK_GETENT
  cat > "$fakebin/groupadd" <<'MOCK_NOOP'
#!/usr/bin/env bash
exit 0
MOCK_NOOP
  cp "$fakebin/groupadd" "$fakebin/useradd"
  cp "$fakebin/groupadd" "$fakebin/chown"

  cat > "$fakebin/install" <<'MOCK_INSTALL'
#!/usr/bin/env bash
set -eu
directory=0; mode=""; args=()
while (($#)); do
  case "$1" in
    -d) directory=1; shift ;;
    -m) mode="$2"; shift 2 ;;
    -o|-g) shift 2 ;;
    --) shift; break ;;
    -*) echo "unknown install option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
args+=("$@")
target="${args[-1]}"
if [[ -n "${TY_FAKE_FAIL_INSTALL_TARGET:-}" && "$target" == *"$TY_FAKE_FAIL_INSTALL_TARGET"* ]]; then exit 1; fi
if ((directory)); then
  mkdir -p -- "$target"
  [[ -z "$mode" ]] || chmod "$mode" "$target"
else
  source="${args[-2]}"
  mkdir -p -- "$(dirname -- "$target")"
  cp -- "$source" "$target"
  [[ -z "$mode" ]] || chmod "$mode" "$target"
fi
MOCK_INSTALL

  chmod 0755 "$fakebin"/*
  (
    cd "$package"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  )
}

run_installer() {
  ( PATH="$fakebin:$PATH" TY_OVERLAY_TEST_MODE=1 TY_OVERLAY_TEST_ROOT="$install_root" TY_OVERLAY_TEST_BIN="$fakebin" \
    bash "$package/install-oec-overlay.sh" )
}
run_installer_preserve_agent() {
  ( PATH="$fakebin:$PATH" TY_OVERLAY_TEST_MODE=1 TY_OVERLAY_TEST_ROOT="$install_root" TY_OVERLAY_TEST_BIN="$fakebin" \
    TY_OVERLAY_PRESERVE_AGENT_PROCESS=1 bash "$package/install-oec-overlay.sh" )
}
run_installer_keep_backup() {
  ( PATH="$fakebin:$PATH" TY_OVERLAY_TEST_MODE=1 TY_OVERLAY_TEST_ROOT="$install_root" TY_OVERLAY_TEST_BIN="$fakebin" \
    TY_OVERLAY_KEEP_BACKUP=1 bash "$package/install-oec-overlay.sh" )
}

set_state() { printf '%s\n' "$2" > "$install_root/.service-state/$1"; }
state_of() { local x; x="$(<"$install_root/.service-state/$1")"; printf '%s' "$x"; }
assert_no_frpc_mutation() {
  if [[ -f "$install_root/.systemctl.log" ]] && grep -E '^(enable|disable|start|stop|restart|try-restart) .*ty-frpc-rescue\.service' "$install_root/.systemctl.log" >/dev/null; then
    fail "installer mutated FRPC service state"
  fi
}

# First installation without FRPC configuration: TY defaults apply, but the
# rescue service remains untouched and disabled.
new_fixture fresh
fresh_output="$(run_installer)"
grep -Fq 'FRPC is not configured' <<< "$fresh_output" || fail "fresh-install FRPC status was not reported"
assert_eq "$(state_of ty-frpc-rescue.service)" "loaded disabled inactive" "fresh FRPC state"
assert_eq "$(state_of ty-gateway-local.service)" "loaded enabled active" "fresh local manager state"
assert_eq "$(state_of ty-gateway-agent.service)" "loaded enabled active" "fresh MAC auto-enrollment Agent state"
assert_file_eq "$install_root/usr/local/libexec/ty-gateway-dae-preflight" $'#!/usr/bin/env bash\nexit 0' "installed dae preflight"
assert_file_eq "$install_root/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding" $'#!/usr/bin/env bash\nexit 0' "installed dae NetworkManager dispatcher"
assert_file_eq "$install_root/etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf" $'[Service]\nExecStartPre=/usr/local/libexec/ty-gateway-dae-preflight\nExecReload=\nExecReload=/usr/local/libexec/ty-gateway-dae-preflight\nExecReload=/usr/bin/dae reload $MAINPID' "installed dae preflight drop-in"
assert_no_frpc_mutation
run_installer >/dev/null
assert_eq "$(state_of ty-frpc-rescue.service)" "loaded disabled inactive" "repeat install FRPC state"
assert_eq "$(state_of ty-gateway-local.service)" "loaded enabled active" "repeat install local manager state"
assert_no_frpc_mutation

# A successful update retains a private snapshot. Restoring it only reverts
# package software and service states; device configuration and rescue access
# must survive.
new_fixture durable-rollback
set_state ty-gateway-local.service "loaded enabled active"
set_state ty-frpc-rescue.service "loaded enabled active"
mkdir -p "$install_root/usr/local/bin" "$install_root/etc/ty-gateway"
printf 'old local binary\n' > "$install_root/usr/local/bin/ty-gateway-local"
printf 'old frpc binary\n' > "$install_root/usr/local/bin/frpc"
printf 'operator settings\n' > "$install_root/etc/ty-gateway/local.env"
run_installer_keep_backup >/dev/null
backup_count="$(find "$install_root/var/lib/ty-gateway-update/backups" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
assert_eq "$backup_count" 1 "durable rollback snapshot count"
backup_dir="$(find "$install_root/var/lib/ty-gateway-update/backups" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -x "$backup_dir/restore.sh" ]] || fail "durable rollback helper missing"
( PATH="$fakebin:$PATH" TY_OVERLAY_TEST_MODE=1 TY_OVERLAY_TEST_ROOT="$install_root" TY_OVERLAY_TEST_BIN="$fakebin" \
  bash "$backup_dir/restore.sh" "$backup_dir" ) >/dev/null
assert_file_eq "$install_root/usr/local/bin/ty-gateway-local" "old local binary" "durable rollback local binary"
assert_file_eq "$install_root/usr/local/bin/frpc" "old frpc binary" "durable rollback FRPC binary"
assert_file_eq "$install_root/etc/ty-gateway/local.env" "operator settings" "durable rollback local settings"
assert_eq "$(state_of ty-gateway-local.service)" "loaded enabled active" "durable rollback local service"
assert_no_frpc_mutation

# A fresh device starts the Agent immediately and awaits a pre-registered MAC;
# the package contains neither a per-device activation file nor shared secrets.
new_fixture fresh-activation
printf '{"mac":"020000008801","activation_code":"fixture"}\n' > "$fixture/activation.json"
TY_ACTIVATION_SOURCE="$fixture/activation.json" run_installer >/dev/null
assert_eq "$(state_of ty-gateway-agent.service)" "loaded enabled active" "fresh activated Agent state"
assert_file_eq "$install_root/var/lib/ty-gateway/activation.json" '{"mac":"020000008801","activation_code":"fixture"}' "installed activation file"
assert_no_frpc_mutation

# An explicit activation source is also permission to start a previously
# installed but inactive Agent. No FRPC state is changed.
new_fixture later-activation
set_state ty-gateway-agent.service "loaded disabled inactive"
printf '{"mac":"020000008802","activation_code":"fixture"}\n' > "$fixture/activation.json"
TY_ACTIVATION_SOURCE="$fixture/activation.json" run_installer >/dev/null
assert_eq "$(state_of ty-gateway-agent.service)" "loaded enabled active" "later activated Agent state"
assert_no_frpc_mutation

# A failed installation must remove a newly staged activation file, allowing
# a safe retry with the same source file.
new_fixture activation-rollback
printf '{"mac":"020000008803","activation_code":"fixture"}\n' > "$fixture/activation.json"
if TY_ACTIVATION_SOURCE="$fixture/activation.json" TY_FAKE_FAIL_INSTALL_TARGET=ty-gateway-local.service run_installer >/dev/null 2>&1; then fail "activation install failure was ignored"; fi
[[ ! -e "$install_root/var/lib/ty-gateway/activation.json" ]] || fail "failed install left activation file behind"

# Existing agent and local environment files keep their content on upgrade.
new_fixture preserve-env
mkdir -p "$install_root/etc/ty-gateway"
printf 'operator agent settings\n' > "$install_root/etc/ty-gateway/agent.env"
printf 'operator local settings\n' > "$install_root/etc/ty-gateway/local.env"
run_installer >/dev/null
assert_file_eq "$install_root/etc/ty-gateway/agent.env" "operator agent settings" "existing agent.env content"
assert_file_eq "$install_root/etc/ty-gateway/local.env" "operator local settings" "existing local.env content"

# A deliberate safe upgrade updates the Agent binary/unit without restarting
# the live Agent, avoiding a subscription refresh before the operator is ready.
new_fixture preserve-agent-process
set_state ty-gateway-agent.service "loaded enabled active"
mkdir -p "$install_root/var/lib/ty-gateway"
touch "$install_root/var/lib/ty-gateway/credentials.json"
preserved_output="$(run_installer_preserve_agent)"
grep -Fq 'Preserving the running agent process' <<< "$preserved_output" || fail "agent process preservation was not reported"
assert_eq "$(state_of ty-gateway-agent.service)" "loaded enabled active" "preserved active agent state"
if grep -E '^restart .*ty-gateway-agent\.service' "$install_root/.systemctl.log" >/dev/null; then
  fail "installer restarted the Agent despite the preserve-process option"
fi
grep -q 'fixture ty-gateway-agent' "$install_root/etc/systemd/system/ty-gateway-agent.service" || fail "agent unit was not refreshed while preserving process"

# Existing FRPC active/enabled: file and binary update, service does not restart.
new_fixture frpc-active
set_state ty-frpc-rescue.service "loaded enabled active"
mkdir -p "$install_root/etc/ty-gateway" "$install_root/etc/systemd/system" "$install_root/usr/local/bin"
printf 'serverAddr="example.invalid"\n' > "$install_root/etc/ty-gateway/frpc.toml"
printf 'old frpc service unit\n' > "$install_root/etc/systemd/system/ty-frpc-rescue.service"
printf 'old binary\n' > "$install_root/usr/local/bin/frpc"
active_output="$(run_installer)"
grep -Fq 'FRPC configuration validated and retained' <<< "$active_output" || fail "FRPC config preservation was not reported"
grep -Fq 'later operator-approved safe restart' <<< "$active_output" || fail "safe FRPC restart guidance was not reported"
assert_eq "$(state_of ty-frpc-rescue.service)" "loaded enabled active" "active FRPC state"
assert_no_frpc_mutation
grep -q 'fixture ty-frpc-rescue' "$install_root/etc/systemd/system/ty-frpc-rescue.service" || fail "FRPC unit was not refreshed"

# FRPC enabled but stopped and FRPC disabled both remain unchanged.
new_fixture frpc-enabled-stopped
set_state ty-frpc-rescue.service "loaded enabled inactive"
run_installer >/dev/null
assert_eq "$(state_of ty-frpc-rescue.service)" "loaded enabled inactive" "enabled stopped FRPC state"
assert_no_frpc_mutation

new_fixture frpc-disabled
set_state ty-frpc-rescue.service "loaded disabled inactive"
run_installer >/dev/null
assert_eq "$(state_of ty-frpc-rescue.service)" "loaded disabled inactive" "disabled FRPC state"
assert_no_frpc_mutation

# Masked units are never overwritten, including a regular-file test stand-in
# for systemd's /dev/null symlink (which is unavailable on some Windows hosts).
new_fixture frpc-masked
set_state ty-frpc-rescue.service "masked masked inactive"
mkdir -p "$install_root/etc/systemd/system"
printf 'mask sentinel\n' > "$install_root/etc/systemd/system/ty-frpc-rescue.service"
run_installer >/dev/null
assert_file_eq "$install_root/etc/systemd/system/ty-frpc-rescue.service" "mask sentinel"
assert_eq "$(state_of ty-frpc-rescue.service)" "masked masked inactive" "masked FRPC state"
assert_no_frpc_mutation

# Existing disabled TY services are preserved during upgrades too.
new_fixture core-disabled
set_state ty-gateway-local.service "loaded disabled inactive"
set_state ty-gateway-dae-helper.service "loaded disabled inactive"
set_state ty-gateway-agent.service "loaded disabled inactive"
set_state ty-gateway-firstboot.service "loaded disabled inactive"
run_installer >/dev/null
assert_eq "$(state_of ty-gateway-local.service)" "loaded disabled inactive" "disabled local manager state"
assert_eq "$(state_of ty-gateway-dae-helper.service)" "loaded disabled inactive" "disabled helper state"
assert_eq "$(state_of ty-gateway-agent.service)" "loaded disabled inactive" "disabled agent state"
assert_eq "$(state_of ty-gateway-firstboot.service)" "loaded disabled inactive" "disabled firstboot state"

# Invalid FRPC config must abort before any managed file is touched.
new_fixture invalid-config
mkdir -p "$install_root/etc/ty-gateway" "$install_root/usr/local/bin"
printf 'invalid\n' > "$install_root/etc/ty-gateway/frpc.toml"
printf 'old binary\n' > "$install_root/usr/local/bin/frpc"
if run_installer >/dev/null 2>&1; then fail "invalid FRPC config was accepted"; fi
assert_file_eq "$install_root/usr/local/bin/frpc" "old binary" "config preflight changed target binary"

# A digest mismatch is rejected before any target file changes.
new_fixture invalid-sum
mkdir -p "$install_root"
printf 'old binary\n' > "$install_root/old-sentinel"
printf 'tampered payload\n' >> "$package/payload/usr/local/bin/ty-gateway-local"
if run_installer >/dev/null 2>&1; then fail "checksum mismatch was accepted"; fi
assert_file_eq "$install_root/old-sentinel" "old binary" "checksum preflight sentinel"

# CRLF checksum lists are accepted only after every listed digest matches.
new_fixture crlf-sums
sed 's/$/\r/' "$package/SHA256SUMS" > "$package/SHA256SUMS.crlf"
mv "$package/SHA256SUMS.crlf" "$package/SHA256SUMS"
run_installer >/dev/null
assert_eq "$(state_of ty-frpc-rescue.service)" "loaded disabled inactive" "CRLF checksum FRPC state"

# A write failure restores package files and the old active service binary.
new_fixture rollback
set_state ty-gateway-local.service "loaded enabled active"
set_state ty-gateway-dae-helper.service "loaded enabled active"
mkdir -p "$install_root/usr/local/bin" "$install_root/etc/systemd/system"
printf 'old local binary\n' > "$install_root/usr/local/bin/ty-gateway-local"
printf 'old helper binary\n' > "$install_root/usr/local/bin/ty-gateway-dae-helper"
printf 'old local unit\n' > "$install_root/etc/systemd/system/ty-gateway-local.service"
if TY_FAKE_FAIL_INSTALL_TARGET=ty-gateway-local.service run_installer >/dev/null 2>&1; then fail "simulated install failure was ignored"; fi
assert_file_eq "$install_root/usr/local/bin/ty-gateway-local" "old local binary" "rollback local binary"
assert_file_eq "$install_root/etc/systemd/system/ty-gateway-local.service" "old local unit" "rollback local unit"
assert_eq "$(state_of ty-gateway-local.service)" "loaded enabled active" "rollback active service state"
assert_no_frpc_mutation

# A failed restart also restores old files and the previous active state.
new_fixture restart-rollback
set_state ty-gateway-local.service "loaded enabled active"
set_state ty-gateway-dae-helper.service "loaded enabled active"
mkdir -p "$install_root/usr/local/bin"
printf 'old local binary\n' > "$install_root/usr/local/bin/ty-gateway-local"
printf 'old helper binary\n' > "$install_root/usr/local/bin/ty-gateway-dae-helper"
if TY_FAKE_FAIL_INSTALL_TARGET=action:restart:ty-gateway-local.service run_installer >/dev/null 2>&1; then fail "simulated restart failure was ignored"; fi
assert_file_eq "$install_root/usr/local/bin/ty-gateway-local" "old local binary" "restart rollback local binary"
assert_eq "$(state_of ty-gateway-local.service)" "loaded enabled active" "restart rollback local service state"
assert_no_frpc_mutation

echo "OEC overlay installer tests passed (fresh MAC auto-enrollment/repeat/legacy activation installs, activation rollback, preserved live Agent, FRPC active/stopped/disabled/masked, existing disabled units, checksum/config rejection, CRLF sums, file/restart rollback)."
