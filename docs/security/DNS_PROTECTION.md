# DNS protection

Linux applies NetworkManager's exclusive DNS priority to supported full-tunnel
profiles. Include a DNS resolver reachable through the tunnel. The dashboard
checks the resolver configuration and route selection independently of peer
handshake, tunnel link state and DNS reachability. On systemd-resolved it
checks the default DNS route and the servers actually attached to the tunnel.
With a plain resolv.conf it checks the listed resolvers against the profile.

Local split-DNS domains can use other links. Browser DNS-over-HTTPS and
applications implementing their own DNS follow their own settings and IP
routes. Aegis does not configure those applications. WireGuard encrypts traffic
between peers. The resolver's upstream connection is outside that guarantee.

Settings can disable the connected-tunnel probes. Aegis binds them to the
WireGuard device and a tunnel source address. A DNS reply shows the resolver
answered. The DNS egress address belongs to the recursive resolver and cannot
establish the client's public VPN address or geography.

Use `resolvectl status` to inspect the selected links and DNS servers. Check
`ip route get <resolver>` for the expected device. A meaningful leak test checks
physical-interface captures with a known positive control, then repeats
before, during and after tunnel activation and failure. Use the VM plan for
disruptive tests. See [TEST_PLAN.md](../testing/TEST_PLAN.md).
