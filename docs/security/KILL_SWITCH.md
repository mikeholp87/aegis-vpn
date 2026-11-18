# Kill switch

**Standard** leaves ordinary operating-system networking available when the
tunnel is down. Sequential switching can briefly use the ordinary uplink.

**Protected** uses a session-scoped nftables block on Linux through the Aegis
helper and Polkit. Install the helper and its matching policy from a trusted
build. Enabling it in Settings requires IP-literal WireGuard endpoints and
administrator authorization before connection. Unsupported or failed setup
blocks activation. Aegis checks the installed block again during activation and
while monitoring a connected session. It stops the tunnel when it detects that
required protection is absent or cannot be confirmed.

The helper owns only `inet aegis_vpn`. Loopback, the selected tunnel, UDP to its
configured endpoints, DHCP and necessary IPv6 control traffic have exceptions.
**Allow local network** grants additional private and link-local access.
Endpoint exceptions match address/port rather than process identity. Forwarded
packets are outside the helper's output/input policy. An independent
administrator firewall rewrite can remove enforcement before the monitor
detects it.

The block normally survives app crashes and tunnel drops. **Disconnect** or
**Stop blocking** authorizes removal. Protected server switching remains
refused. **Always On** across reboot and Windows WFP protection are pending.
See [recovery](RECOVERY.md) and [test evidence](../testing/TEST_RESULTS.md).
