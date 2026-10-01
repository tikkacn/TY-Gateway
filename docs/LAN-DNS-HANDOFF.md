# LAN DNS handoff (v0.8.9)

The LAN-only DAE hook deliberately excludes the appliance's own management
sockets. LAN dnsmasq must therefore explicitly forward to the active DAE DNS
listener; forwarding only to the router bypasses DAE's DNS domain observation.

`ty_gateway_lan.py` generates a dnsmasq `servers-file` pointing to a root-private
upstream file. The existing boot-enabled network helper reconciles that file
every five seconds, independently of Agent/cloud connectivity:

- Saved DAE proxy policy enabled, service active and DNS listener responsive:
  forward only to the appliance IPv4 address on port 5353.
- Otherwise: use the customer's existing router/custom direct upstreams.
- DAE stop hook: immediately choose direct upstreams, without probing the proxy.
- Send dnsmasq HUP only for changed upstreams or a pending failed signal;
  preserve DHCP leases, addresses, reservations and customer settings.

The readiness query uses the immutable cloud management name, whose DAE DNS
route is direct. It tests DNS listener responsiveness, not node health or a
successful client YouTube connection. Router IPv6 advertisements/private client
DNS can still bypass the intended IPv4 path and require separate diagnosis.

The installer snapshots dynamic DNS files for failed-update recovery. The
software restore script materializes the customer's current direct upstreams
before replacing a newer helper with an older helper lacking this mechanism.

Focused check: `python3 tests/lan-dns-handoff-test.py` (temporary files and mocks,
no live interfaces). Real phone browsing and actual administrator downgrade
remain separate acceptance tests.

dnsmasq's documented `servers-file` is re-read on HUP; its ordinary configuration
file is not: [official manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).
