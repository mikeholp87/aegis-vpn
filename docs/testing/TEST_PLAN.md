# Test plan

## Automated (every change)
`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`,
`pnpm lint && pnpm typecheck && pnpm test`, cargo-deny, cargo audit,
pnpm audit (CI). Run Gitleaks only when explicitly requested.

## Live Linux, non-disruptive (developer host)
1. `sudo scripts/test-netns-peer.sh up` (or `pkexec <abs path> up` without a terminal; isolated namespace, split route 10.99.0.0/24)
2. `cargo run -p aegis-linux --example nm_live -- /run/aegis-test/aegis-netns-test.conf`
3. Expect PASS for: import, connect, ping 10.99.0.1, server response confirmed,
   disconnect, delete, no leftover interface/route/NM connection
4. `sudo scripts/test-netns-peer.sh down`

## VM only (disruptive): `scripts/vm/run-vm-tests.sh`
Runs as your normal user (needs `/dev/kvm`), never touches host networking.
Boots the SHA512-verified Debian 13 cloud image with `-snapshot` under QEMU
user-mode networking, provisions it with cloud-init (NetworkManager,
systemd-resolved, wireguard-tools, dnsmasq, tcpdump), copies a static musl
`vm_suite` and the peer script in, and runs `vm_suite full` and
`vm_suite full4`. Each mode checks:

- connect + server response confirmed
- IPv4 internet route via the tunnel; endpoint route stays outside it
- ping an IPv4 sentinel that exists only behind the tunnel
- `full`: IPv6 route via the tunnel + IPv6 sentinel ping; `full4`: IPv6
  bypasses the tunnel and the app reports IPv6 protection as Failed
- DNS protection reported as Configured
- DNS leak: positive control (lookups visible on the uplink before connecting),
  then both resolved and libc lookups answered by the tunnel's DNS (sentinel
  answer) with 0 port-53 packets on the uplink
- reconnect after `nmcli connection down` behind the app's back
- recovery after `systemctl restart NetworkManager`
- after disconnect, IPv4/IPv6 rules, routes and resolved DNS/domains identical
  to the pre-connect baseline; no leftover NM connection

`KEEP_VM=1` leaves the VM running and prints the SSH command.
The extended suite also checks the optional Linux helper block; see current test
results for its environment and scope. Still pending: protected country switching,
suspend/resume, reboot with the tunnel active, Wi-Fi/uplink changes.

## Release matrix
Windows 11 x64 · Ubuntu LTS GNOME · Debian stable KDE · Fedora Workstation ×
scenarios 1–20 from the master prompt (§22): fresh install, valid/invalid
import, reachable/unreachable server, disconnect, switch profiles, Wi-Fi
off/on, network change, suspend/resume, UI restart, NM restart, reboot,
full-tunnel, split, DNS/IPv6, kill switch, uninstall, reinstall.

Release criteria: all automated checks green, live Linux test green, matrix
rows run with results recorded, no open critical security issues.

## Locations regression and acceptance

Core tests cover additive migration without credential copies, ISO validation,
server CRUD/reference checks, duplicate names/endpoints, favorite persistence,
peer-evidence-only recent success, destination preflight, failed switching,
concurrent connect/Quick Connect rejection, cancellation during preflight and
activation, disabled/pending registration, Quick Connect preferences/country/
cooldown, and expired/future health samples. Frontend tests cover directory
navigation/search/filtering/grouping/sorting, empty/error/loading states,
import assignment, favorites, delete confirmation, cancellation and active
Dashboard synchronization. Test fixtures use simulated metadata/documentation
endpoints; they are never shipped as configured production servers.

The VM suite now switches between two country-labelled profiles of one
controlled peer, confirms responses and sentinel traffic, switches back and
deletes the destination. It preserves the existing full/full4 route/DNS/IPv6/
reconnect/NM-restart/restoration checks. These labels do not prove geographic
location or independent remote-server deployment. Run on a KVM-capable Linux
host via `scripts/vm/run-vm-tests.sh`, or dispatch the separate
`.github/workflows/vpn-integration.yml` workflow. Record all failures, including
known NM restart/firewall behavior, without broad expected-failure exemptions.

Remaining live acceptance: two independently operated country servers, invalid
remote credentials/no handshake, failure during switching/authorization/DNS/
firewall cleanup, suspend/resume, uplink changes, crash/restart and reboot.
Windows CI compilation/portable tests do not substitute for an implemented
Windows service, authenticated IPC/DPAPI tests and a Windows 11 real tunnel.
No protected-switch success can be accepted until continuous protection across
transitions and helper failure paths is implemented and tested. Update TEST_RESULTS with environment and actual evidence.
