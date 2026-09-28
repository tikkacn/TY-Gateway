# Automatic FRP authentication

This describes the server-side prerequisite for an OEC first-boot tunnel. It is not a deployment script and does not change a server. Do not enable Cloud automatic FRP until FRPS, the Cloud OIDC endpoints, and the authorization plugin are configured and tested together.

The OEC one-click package does not install or configure FRPS. Build `cmd/ty-frp-auth` separately for the FRPS host; keep it outside the OEC package and public release assets. Build instructions are in [`deploy/frp`](../deploy/frp) and the repository scripts.

## Authentication model

- The device creates a unique FRP client secret by deriving it from its device secret, device ID, and assigned port. It is not a shared FRPS token and is never placed in the public repository or release package.
- FRPC uses FRP 0.71.0's native OIDC client-credentials mode. It sends the per-device credential to the HTTPS Cloud token endpoint; Cloud issues a signed five-minute JWT only when the device is MAC-claimed, enabled, has an assigned port in 22000–22999, and the supplied per-device credential matches.
- FRPS validates JWT signatures through Cloud's issuer discovery/JWKS endpoints. The issuer signing key is stored only on the Cloud host in a private file; FRPS receives only the public JWKS. Protect and back up that private key. Replacing it invalidates outstanding tokens and requires FRPS to refresh its issuer metadata.
- The plugin checks the fresh Cloud roster and verifies the device-specific credential and exact assigned SSH mapping. It leaves the OIDC login token unchanged so FRPS's native verifier can validate it.
- A device credential is still present in the root-only FRPC configuration on its own OEC. MAC is an enrollment lookup, not a cryptographic secret. The configuration is not returned through the customer portal.

Native OIDC rejects devices without a valid device-specific credential even if the plugin is missing. The plugin remains required to enforce the per-device port/name restrictions: if it is omitted, an already authorized device could try to claim another free port in the allowed pool. Restrict `allowPorts` and `maxPortsPerClient`, keep the plugin configured for every listed operation, and verify the running FRPS configuration.

## FRPS settings

Use the same FRP 0.71.0 release for the server and OEC client. The public FRPC control port is TCP **7001**; assigned SSH mappings are TCP **22000–22999**. Preserve unrelated server settings after review. Configure the FRPS TLS server certificate/key and expose the HTTPS Cloud issuer to FRPS for discovery/JWKS.

```toml
bindAddr = "0.0.0.0"
bindPort = 7001
proxyBindAddr = "0.0.0.0"
transport.tls.force = true

auth.method = "oidc"
auth.oidc.issuer = "https://oec.188811.xyz/api/v1/frp/oidc"
auth.oidc.audience = "ty-gateway-frp"
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]

allowPorts = [{ start = 22000, end = 22999 }]
maxPortsPerClient = 1

[[httpPlugins]]
name = "ty-gateway-per-device-auth"
addr = "127.0.0.1:9081"
path = "/handler"
ops = ["Login", "NewProxy", "Ping", "NewWorkConn", "NewUserConn", "CloseProxy"]
```

The Cloud service needs:

```text
TY_FRP_AUTO_ENABLED=1
TY_FRPS_HOST=<public-FRPS-host>
TY_FRP_AUTO_CA_FILE=<private-path-to-FRPS-server-CA-PEM>
TY_FRP_OIDC_ISSUER=https://oec.188811.xyz/api/v1/frp/oidc
TY_FRP_OIDC_AUDIENCE=ty-gateway-frp
TY_FRP_OIDC_SIGNING_KEY_FILE=/var/lib/tygateway/frp-oidc-signing-key.pem
```

Cloud creates the ECDSA signing key on first start with owner-only permissions if it does not exist. The service account must be able to create/read that file. Back it up securely; do not put it in GitHub, R2, an OEC image, or an FRPS host. The Cloud OIDC routes are `/api/v1/frp/oidc/.well-known/openid-configuration`, `/jwks`, and `/token`. Ensure the existing HTTPS reverse proxy forwards `/api/` to TY Cloud.

The authorization plugin reads only the dedicated roster API token file and uses its own cached roster:

```text
TY_FRP_ROSTER_URL=https://oec.188811.xyz/api/v1/frp/roster
TY_FRP_ROSTER_TOKEN_FILE=<private-file-containing-the-roster-API-token>
TY_FRP_ROSTER_CACHE=/var/lib/ty-frp-auth/roster.json
TY_FRP_AUTH_LISTEN=127.0.0.1:9081
TY_FRP_PORT_START=22000
TY_FRP_PORT_END=22999
```

The plugin listener must remain loopback-only; never expose port 9081 publicly. The FRP control channel and mapping pool must be allowed by firewall/NAT as needed.

## Verification gate

1. Confirm Cloud's HTTPS issuer discovery and JWKS return successfully; verify no private key or device secret is exposed there.
2. Confirm FRPS configuration verifies with the installed FRP version and uses OIDC plus the complete plugin operation list.
3. Run the localhost FRP 0.71.0 integration test. It must prove the native OIDC verifier rejects a wrong device credential, the plugin rejects an incorrect per-device SSH mapping, and an authorized device reaches the local SSH greeting through its assigned port.
4. Only after those pass, enable the Cloud feature and verify one MAC-pre-registered OEC automatically enrolls, obtains FRP config, stays connected on port 7001, and exposes only its assigned 22000–22999 SSH port.

A Cloud-assigned port, a running FRPC process, or a healthy local plugin does not by itself prove the remote SSH tunnel works. Do not change a production FRPS listener while existing clients may depend on it without checking current connections and scheduling a migration window.
