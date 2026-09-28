# FRP per-device authorization: server-side requirements

This document describes the FRPS-side prerequisite for automatic OEC tunnels. It is not an FRPS deployment script and does not change any server. Do not enable Cloud automatic FRP until this listener has been configured and verified.

The OEC one-click package does not install or configure the FRPS-side component. Build `cmd/ty-frp-auth` separately for the FRPS host; this intentionally produces an artifact outside `work/oec-dist` and is not part of the OEC overlay or bootstrap. From the repository root:

```powershell
.\scripts\build-frp-auth.ps1                 # Linux amd64 (default)
.\scripts\build-frp-auth.ps1 -GoArch arm64  # Linux ARM64
```

On Linux/macOS with Go installed:

```sh
GOOS=linux GOARCH=amd64 ./scripts/build-frp-auth.sh
GOOS=linux GOARCH=arm64 ./scripts/build-frp-auth.sh
```

The output is `work/frp-auth-dist/ty-frp-auth-linux-<arch>` with a separate `.sha256` checksum. Verify it before installing, then install the binary as `/usr/local/bin/ty-frp-auth`. Do not upload this server-only binary as an OEC package. Example environment and systemd unit templates are in [`deploy/frp`](../deploy/frp); adapt the service account to the existing FRPS service before use.

## Security model

- Each enrolled device authenticates to the TY Gateway plugin using its own roster-backed credential. MAC is an enrollment lookup, not a cryptographic secret.
- A separate random FRPS token (at least 32 characters) stays only on the FRPS host. It must never be placed in Cloud configuration, OEC images, generated FRPC configuration, release assets, or logs.
- `ty-frp-auth` checks the per-device roster credential, then rewrites only the FRP Login `privilege_key` to the signature expected by the native FRPS token verifier. The token signature follows FRP 0.71.0's `MD5(token || decimal_timestamp)` protocol.
- This makes plugin configuration fail closed: if the plugin is not configured on the public listener, the FRPC client (which does not possess the server token) cannot pass FRPS native token verification. If the plugin is configured but unavailable or has no fresh roster, FRP rejects the operation.
- The plugin listener must remain loopback-only (`127.0.0.1:9081`). Never expose its HTTP handler publicly.

This relies on FRP's documented “modify content” plugin response for `Login`; the native server then verifies `privilege_key`. See the [FRP v0.71.0 plugin protocol](https://github.com/fatedier/frp/blob/v0.71.0/doc/server_plugin.md), [server login flow and verifier call](https://github.com/fatedier/frp/blob/v0.71.0/server/service.go), and [token signature implementation](https://github.com/fatedier/frp/blob/v0.71.0/pkg/util/util/util.go).

## FRPS listener settings

Merge the following settings into the intended FRPS instance's configuration. Preserve unrelated existing settings only after reviewing them. The public FRPC control port is **TCP 7001**; device SSH mappings are **TCP 22000–22999**.

`auth.tokenSource` is mutually exclusive with the old `auth.token`: replace the legacy shared token setting instead of keeping both. Existing shared-token FRPC clients will not be admitted by this per-device roster; migrate them before switching the listener. Configure FRPS TLS certificate/key with the CA that Cloud sends to devices. Permit TCP 7001 and 22000–22999 through the server firewall/NAT, but never expose 9081.

```toml
bindAddr = "0.0.0.0"
bindPort = 7001
proxyBindAddr = "0.0.0.0"
transport.tls.force = true

auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = "/etc/frp/ty-server-auth.token"

allowPorts = [{ start = 22000, end = 22999 }]
maxPortsPerClient = 1

[[httpPlugins]]
name = "ty-gateway-per-device-auth"
addr = "127.0.0.1:9081"
path = "/handler"
ops = ["Login", "NewProxy", "Ping", "NewWorkConn", "NewUserConn", "CloseProxy"]
```

The FRP token is deliberately not reproduced here. Generate it on the FRPS host, store the exact token bytes (no surrounding whitespace or newline) in the path above with mode `0600`, and make FRPS and `ty-frp-auth` run under the same service account so both can read it without broadening file permissions. The plugin process must receive:

```text
TY_FRP_SERVER_AUTH_TOKEN_FILE=/etc/frp/ty-server-auth.token
TY_FRP_ROSTER_URL=https://<cloud-host>/api/v1/frp/roster
TY_FRP_ROSTER_TOKEN_FILE=<private-file-containing-the-separate-roster-API-token>
TY_FRP_ROSTER_CACHE=/var/lib/ty-frp-auth/roster.json
```

The roster API token is distinct from the FRPS token. Keep both files private. The service must start only when the FRPS token is present and strong, and when it can load a fresh roster.

Copy `deploy/frp/ty-frp-auth.env.example` to `/etc/ty-frp-auth/ty-frp-auth.env`; put only secret-file paths there. Place the roster API token in the referenced private file, and use `deploy/frp/ty-frp-auth.service.example` as a starting point. Set the unit's `User` and `Group` to the same account as FRPS, then ensure the unit's state directory and both token files are readable/writable only by that account. The service template is illustrative, not yet verified with the production FRPS host's systemd layout.

Do not enable FRP `auth.additionalScopes` yet. The current OEC client intentionally never receives the FRPS token; the plugin validates heartbeat and work-connection operations itself. Enabling native token checks on those additional scopes would require extending the plugin to rewrite their auth fields too.

## Activation and verification gate

1. Confirm the exact FRPS instance serving public TCP 7001 is the one configured above. Ensure no alternate public FRPS listener bypasses this authorization path.
2. Start `ty-frp-auth` and confirm its local `/healthz` is healthy. Confirm the FRPS listener is configured with all six operations, especially `Login` and `NewProxy`.
3. Verify the FRPS config with the matching FRP binary, restart the listener in a planned window, then run the localhost integration test. It must prove both that a client is rejected when the plugin is omitted and that a roster-authorized client succeeds through the plugin.
4. Only after server-side checks pass, enable `TY_FRP_AUTO_ENABLED=1` in Cloud and test a pre-registered OEC. The end-to-end test is not complete until SSH through its assigned 22000–22999 mapping succeeds.

Changing an existing shared FRPS listener can interrupt existing clients. Migrate or explicitly account for them before changing port 7001. A port assignment, FRPC process, or healthy local plugin alone does not prove the public tunnel works.
