# IPv6 protection

A dual-stack full tunnel needs an IPv6 interface address and an IPv6 default
route in AllowedIPs, plus server-side forwarding and return routing. Verify a
real IPv6 packet through the tunnel in an isolated environment. A configured
route alone gives no proof the remote endpoint forwards the packet.

An IPv4-only full tunnel places an IPv6 default route on the WireGuard device.
Without an IPv6 peer for that route, WireGuard drops those packets. This policy
is scoped to the active NetworkManager connection. Routing observations cover
the checked destination and default route. Other policy rules, specific routes,
new interfaces and forwarded traffic need separate validation. The Linux
kill switch can block ordinary host IPv6 outside the selected tunnel when its
helper installs a block. Check the dashboard and the [kill switch guide](KILL_SWITCH.md).

Use `ip -6 route get <test-address>` to inspect routing. Test with an IPv6
peer sentinel, a physical-interface capture and a positive control before
enabling protection. Repeat after daemon restart, network changes and suspend.
See [TEST_PLAN.md](../testing/TEST_PLAN.md).
