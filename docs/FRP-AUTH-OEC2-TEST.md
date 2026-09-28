# OEC2 local FRP authorization integration test

This test kit runs the FRP 0.71.0 client and server only on OEC2 loopback. It does not contact or modify the production FRPS listener, Cloud API, or systemd services. The Go test starts temporary FRPS/FRPC processes and binds randomly selected localhost ports, then checks plugin-required login rejection, roster authorization, proxy creation, and an SSH banner forwarding through the tunnel.

## Build the test kit on Windows

From the repository root, with the local Go toolchain prepared:

```powershell
.\scripts\build-frp-auth-oec2-test.ps1
```

The script downloads the official FRP `v0.71.0` Linux ARM64 release and validates its SHA-256 before extracting `frps` and `frpc`. It cross-compiles the Go integration test for Linux ARM64. The output directory is `work/frp-auth-oec2-test-v0.71.0`; it is ignored by Git and contains no credentials. Transfer only `ty-frp-auth-oec2-test-v0.71.0.zip` from that directory; the source archive and extraction staging are not needed on the device.

## Run on OEC2

Copy the ZIP to OEC2 over SSH/SCP, then extract it and enter the extracted directory. Run:

```sh
sha256sum -c SHA256SUMS
cd payload
chmod 755 frps frpc frpauth.test
TY_FRP_TEST_FRPS="$PWD/frps" \
TY_FRP_TEST_FRPC="$PWD/frpc" \
./frpauth.test -test.run '^TestFRP071RealSSHForwarding$' -test.v
```

Success requires `PASS` for `TestFRP071RealSSHForwarding`. A skip means the FRPS/FRPC paths were not passed. A failure is useful evidence and should be returned in full. The test's test-only tokens and generated credentials are ephemeral; do not reuse them in production.

The test uses no public listening address and does not verify OEC-to-production FRP connectivity. Production activation still requires a separate server-side migration and an end-to-end SSH test through the assigned `22000–22999` mapping.
