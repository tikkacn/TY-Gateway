# OEC2 FRP authorization test

## What the local integration test proves

The Go integration test launches official FRP 0.71.0 `frps` and `frpc` only on loopback. It exercises the native OIDC client-credentials exchange, confirms an invalid device credential is rejected, confirms the authorization plugin rejects a mismatched rescue key/port, and verifies an authorized client forwards an SSH greeting through its assigned port. It does not connect to or alter the public FRPS listener.

The test has passed on the Linux FRPS host with the official FRP 0.71.0 binaries. The ARM64 test kit can also be built locally from the verified upstream archive:

```powershell
.\scripts\build-frp-auth-oec2-test.ps1
```

On OEC2, run the test command shown in the generated `work/frp-auth-oec2-test-v0.71.0/README.md`. Test-only OIDC keys, tokens, ports, and credentials are generated locally and must not be reused in production.

## Current server-side pilot state (2026-09-29)

- Cloud OIDC discovery and JWKS are publicly reachable over HTTPS. Invalid clients receive HTTP 401. The signing private key stays on the Cloud host.
- FRPS 0.71.0 on TCP 7001 validates OIDC tokens and loads the per-device authorization plugin. The allowed mapping pool is 22000–22999; the plugin listens only on loopback.
- The plugin fetches a fresh Cloud roster. OEC2 device #105 currently has the first free mapping, TCP 22000, and appears in the roster.
- The original FRPS config, Cloud binary/environment, and previous plugin binary are backed up on their respective servers.

## What still requires the OEC2 device

No production OEC2 FRPC connection has authenticated yet. The FRPS listener, OIDC endpoint, and roster health do not prove that OEC2 obtained the new OIDC metadata, started FRPC, or exposed SSH. After installing the signed GitHub pilot on the existing registered OEC2, verify the Agent log, FRPC process, FRPS connection, and the administrator-side SSH probe. Do not report an FRP tunnel as working until the SSH banner is reachable through TCP 22000.

Device #105's MAC has already been claimed. A future full reflash that deletes `/var/lib/ty-gateway/credentials.json` will generate a new device secret and cannot reclaim that already-claimed MAC automatically. Preserve the current credentials for this pilot. A destructive re-enrollment needs a deliberate administrator-side identity re-arm first; MAC alone is not sufficient authority to take over an existing device.
