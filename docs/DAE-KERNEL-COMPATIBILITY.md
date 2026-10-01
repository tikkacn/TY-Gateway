# DAE transparent ingress compatibility

DAE process readiness, successful node health checks and configuration validation
do not prove that LAN traffic can enter its transparent listener. On OEC2 with
Linux 6.1.157-rk35xx-ophub and DAE 2.1.1, actual LAN TCP connections timed out
despite all those checks passing.

Linux TC `bpf_sk_assign` rejects listeners with `SO_REUSEPORT` before 6.6.
DAE 2.0.0 and 2.1.1 enable that flag in `TproxyControl`. The historical OEC1
handover records kernel 6.6.25 and DAE 2.0.0, explaining why that older TY setup
could work while the fresh OEC2 system failed. This is a kernel/core combination,
not a claim that every previous TY release or every Armbian image behaves alike.

The root-owned, one-shot `ty_gateway_dae_compat.py` is included in installation,
upgrade, package checksums, both builders, publication audit and software restore.
The DAE unit invokes it after startup and after a completed configuration reload:

- Kernel below 6.6: verify the installed root-owned DAE process, obtain stable
  process descriptors via `pidfd_open`/`pidfd_getfd`, and identify exactly one
  coherent transparent TCP4/TCP6/UDP listener triplet. Clear and verify only
  those listeners' `SO_REUSEPORT`, preserving outgoing node sockets and DNS.
- Kernel 6.6 and newer: no adjustment or cross-process socket inspection.
- Incomplete, ambiguous or inaccessible listeners: fail the service operation
  visibly instead of reporting successful compatibility. No arbitrary PID/FD,
  fixed cookie, node label or customer port is embedded in the helper.
- No daemon polling, kernel/DAE binary replacement, network reactivation, changes
  to customer configuration, identity or FRP. The check is idempotent. A vendor
  backport to an older kernel may not need it; clearing the flag is conservative
  for DAE's single ingress listener per protocol.

The packaged DAE unit already runs as root with `CAP_SYS_PTRACE` available.
Do not silently extend permissions if a future hardened unit blocks pidfd access;
revisit this compatibility path and its targeted verification then. The tested
syscall architectures are ARM64 and x86-64; others are refused on legacy kernels.

Focused mocks: `python3 tests/dae-ingress-compat-test.py`. On a legacy-kernel
appliance, a read-only post-start check is:

```sh
sudo python3 /usr/local/libexec/ty_gateway_dae_compat.py "$(systemctl show -p MainPID --value dae.service)" --check
```

Source evidence: [DAE 2.1.1 socket options](https://github.com/daeuniverse/dae/blob/v2.1.1/component/outbound/dialer/sockopt.go),
[Linux 6.5 rejection](https://github.com/torvalds/linux/blob/v6.5/net/core/filter.c),
[Linux 6.6 assignment](https://github.com/torvalds/linux/blob/v6.6/net/core/filter.c).

Acceptance must separately cover a real client connection after DAE restart,
configuration reload, and eventually appliance reboot. A successful mock test
or socket flag check is not a replacement for that real-client evidence.

2026-10-01 candidate acceptance: installed on the 6.1.157 appliance, restarted
DAE, and observed its start hook automatically adjust three newly created
listeners. The user confirmed Windows YouTube access still worked. A subsequent
configuration reload also passed the read-only listener check. Customer settings
and device identity remained byte-identical. Full appliance reboot, UDP traffic
and other kernels have not yet been physically tested. This fix is included in
v0.8.9; the historical v0.8.8 package does not contain it.
