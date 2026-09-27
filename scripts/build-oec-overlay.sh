#!/usr/bin/env bash
set -Eeuo pipefail

out_dir="${1:-work/oec-overlay}"
agent="${2:-work/oec-dist/gateway-agent-linux-arm64}"
frpc="${3:-work/frpc-linux-arm64}"
dae_helper="${4:-work/oec-dist/dae-config-helper-linux-arm64}"
local_manager="${5:-work/oec-dist/gateway-local-linux-arm64}"
release_fetch="${6:-work/oec-dist/ty-release-fetch-linux-arm64}"
python3="${PYTHON3:-python3}"

[[ -f "$agent" && -f "$frpc" && -f "$dae_helper" && -f "$local_manager" && -f "$release_fetch" ]] || { echo "Agent, local manager, dae helper, release fetch and FRPC binaries must exist" >&2; exit 2; }
[[ -f keys/ty-release-public.pem && -f scripts/ty-gateway-update.py ]] || { echo "Release key or update helper is missing" >&2; exit 2; }
[[ -f firmware/oec/rootfs/etc/systemd/system/ty-gateway-agent.service ]] || { echo "OEC rootfs payload is missing" >&2; exit 2; }
[[ -f firmware/oec/rootfs/etc/systemd/system/ty-gateway-local.service ]] || { echo "local manager service unit is missing" >&2; exit 2; }
[[ -f firmware/oec/rootfs/etc/systemd/system/ty-gateway-network.service && -f firmware/oec/rootfs/usr/local/libexec/ty-gateway-network ]] || { echo "network helper payload is missing" >&2; exit 2; }
[[ -f firmware/oec/rootfs/etc/systemd/system/ty-gateway-dae-helper.service ]] || { echo "dae helper service unit is missing" >&2; exit 2; }
[[ -f firmware/oec/rootfs/etc/systemd/system/ty-gateway-update-recover.service ]] || { echo "update recovery unit is missing" >&2; exit 2; }
[[ -f firmware/oec/rootfs/etc/systemd/system/ty-gateway-update-service.service && -f scripts/ty-gateway-update-service.py ]] || { echo "update service payload is missing" >&2; exit 2; }
[[ -f firmware/oec/rootfs/etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf && -f firmware/oec/rootfs/usr/local/libexec/ty-gateway-dae-preflight ]] || { echo "dae forwarding preflight is missing" >&2; exit 2; }
[[ -f firmware/oec/rootfs/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding ]] || { echo "dae forwarding NetworkManager dispatcher is missing" >&2; exit 2; }
[[ -f scripts/install-oec-overlay.sh ]] || { echo "overlay installer is missing" >&2; exit 2; }
[[ -f scripts/restore-oec-overlay.sh ]] || { echo "overlay restore helper is missing" >&2; exit 2; }
[[ ! -e "$out_dir" ]] || { echo "Refusing to overwrite existing output directory: $out_dir" >&2; exit 2; }
[[ ! -e "${out_dir}.tar.gz" ]] || { echo "Refusing to overwrite existing archive: ${out_dir}.tar.gz" >&2; exit 2; }

mkdir -p -- "$out_dir/payload/usr/local/bin" "$out_dir/payload/usr/local/libexec" "$out_dir/payload/etc/systemd/system" "$out_dir/payload/etc/ty-gateway"
mkdir -p -- "$out_dir/payload/etc/systemd/system/dae.service.d"
mkdir -p -- "$out_dir/payload/etc/NetworkManager/dispatcher.d"
install -m 0755 -- "$agent" "$out_dir/payload/usr/local/bin/ty-gateway-agent"
install -m 0755 -- "$local_manager" "$out_dir/payload/usr/local/bin/ty-gateway-local"
install -m 0755 -- "$release_fetch" "$out_dir/payload/usr/local/bin/ty-release-fetch"
install -m 0755 -- "$frpc" "$out_dir/payload/usr/local/bin/frpc"
install -m 0755 -- "$dae_helper" "$out_dir/payload/usr/local/libexec/ty-gateway-dae-helper"
install -m 0755 -- firmware/oec/rootfs/usr/local/libexec/ty-gateway-dae-preflight "$out_dir/payload/usr/local/libexec/ty-gateway-dae-preflight"
install -m 0755 -- firmware/oec/rootfs/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding "$out_dir/payload/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding"
install -m 0755 -- firmware/oec/rootfs/usr/local/libexec/ty-gateway-firstboot "$out_dir/payload/usr/local/libexec/ty-gateway-firstboot"
install -m 0755 -- firmware/oec/rootfs/usr/local/libexec/ty-gateway-network "$out_dir/payload/usr/local/libexec/ty-gateway-network"
install -m 0755 -- scripts/ty-gateway-update.py "$out_dir/payload/usr/local/libexec/ty-gateway-update"
install -m 0755 -- scripts/ty-gateway-update-service.py "$out_dir/payload/usr/local/libexec/ty-gateway-update-service"
install -m 0644 -- firmware/oec/rootfs/usr/local/libexec/ty_gateway_lan.py "$out_dir/payload/usr/local/libexec/ty_gateway_lan.py"
mkdir -p -- "$out_dir/payload/etc/tmpfiles.d"
install -m 0644 -- firmware/oec/rootfs/etc/tmpfiles.d/ty-gateway-lan.conf "$out_dir/payload/etc/tmpfiles.d/ty-gateway-lan.conf"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/ty-gateway-firstboot.service "$out_dir/payload/etc/systemd/system/ty-gateway-firstboot.service"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/ty-gateway-agent.service "$out_dir/payload/etc/systemd/system/ty-gateway-agent.service"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/ty-gateway-local.service "$out_dir/payload/etc/systemd/system/ty-gateway-local.service"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/ty-gateway-network.service "$out_dir/payload/etc/systemd/system/ty-gateway-network.service"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/ty-gateway-lan.service "$out_dir/payload/etc/systemd/system/ty-gateway-lan.service"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/ty-gateway-dae-helper.service "$out_dir/payload/etc/systemd/system/ty-gateway-dae-helper.service"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/ty-gateway-update-recover.service "$out_dir/payload/etc/systemd/system/ty-gateway-update-recover.service"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/ty-gateway-update-service.service "$out_dir/payload/etc/systemd/system/ty-gateway-update-service.service"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf "$out_dir/payload/etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf"
install -m 0644 -- firmware/oec/rootfs/etc/systemd/system/ty-frpc-rescue.service "$out_dir/payload/etc/systemd/system/ty-frpc-rescue.service"
install -m 0640 -- firmware/oec/rootfs/etc/ty-gateway/agent.env.example "$out_dir/payload/etc/ty-gateway/agent.env.example"
install -m 0640 -- firmware/oec/rootfs/etc/ty-gateway/local.env.example "$out_dir/payload/etc/ty-gateway/local.env.example"
install -m 0640 -- firmware/oec/rootfs/etc/ty-gateway/frpc.toml.example "$out_dir/payload/etc/ty-gateway/frpc.toml.example"
install -m 0644 -- keys/ty-release-public.pem "$out_dir/payload/etc/ty-gateway/release-public.pem"
install -m 0755 -- scripts/install-oec-overlay.sh "$out_dir/install-oec-overlay.sh"
install -m 0755 -- scripts/restore-oec-overlay.sh "$out_dir/restore-oec-overlay.sh"
install -m 0644 -- firmware/oec/README.md "$out_dir/README.md"
install -m 0644 -- firmware/oec/target.json "$out_dir/target.json"

"$python3" - "$out_dir" "$agent" "$frpc" "$dae_helper" "$local_manager" "$release_fetch" <<'PY'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()
manifest = {
    'format_version': 1,
    'package': 'ty-gateway-oec-overlay',
    'status': 'boot-preserving-installable-overlay',
    'target': 'ordinary OnethingCloud OEC; base image must be validated separately',
    'changes': ['install ARM64 Agent with local default-off dae proxy gate', 'install local password-protected OEC management UI as a separate low-privilege user', 'apply DHCP/DNS and MAC/IP settings through a dedicated dnsmasq service on explicit local save', 'apply static OEC IPv4 through a restricted root helper with automatic NetworkManager rollback until new-address login confirmation', 'install root-scoped dae config helper', 'install optional FRPC client', 'install systemd units', 'create low-privilege service users'],
    'never_changes': ['/boot', 'Loader', 'DTB', 'partition table', 'existing agent.env', 'existing credentials.json', 'unrelated applications'],
    'defaults': {'auto_enroll': True, 'frpc_enabled': False, 'dae_included': False, 'dae_proxy_routing': False, 'dhcp_active': False, 'lan_dns_active': False},
    'source_sha256': {'agent': sha(sys.argv[2]), 'frpc': sha(sys.argv[3]), 'dae_helper': sha(sys.argv[4]), 'local_manager': sha(sys.argv[5]), 'release_fetch': sha(sys.argv[6])},
}
(out / 'overlay-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
PY

(
  cd "$out_dir"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
tar -C "$(dirname "$out_dir")" -czf "${out_dir}.tar.gz" "$(basename "$out_dir")"
echo "Created boot-preserving OEC overlay: $out_dir"
echo "Created archive: ${out_dir}.tar.gz"
