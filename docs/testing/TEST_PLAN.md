# Test plan

## Automated (every change)
`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`,
`pnpm lint && pnpm typecheck && pnpm test`, cargo-deny, cargo audit,
pnpm audit, gitleaks (CI).

## Live Linux, non-disruptive (developer host)
1. `sudo scripts/test-netns-peer.sh up` (or `pkexec <abs path> up` without a terminal; isolated namespace, split route 10.99.0.0/24)
2. `cargo run -p aegis-linux --example nm_live -- /run/aegis-test/aegis-netns-test.conf`
3. Expect PASS for: import, connect, ping 10.99.0.1, server response confirmed,
   disconnect, delete, no leftover interface/route/NM connection
4. `sudo scripts/test-netns-peer.sh down`

## VM only (disruptive)
Full-tunnel routing, DNS leak, IPv6 leak, kill switch, network change,
suspend/resume, reboot with tunnel active, NM restart.

## Release matrix
Windows 11 x64 · Ubuntu LTS GNOME · Debian stable KDE · Fedora Workstation ×
scenarios 1–20 from the master prompt (§22): fresh install, valid/invalid
import, reachable/unreachable server, disconnect, switch profiles, Wi-Fi
off/on, network change, suspend/resume, UI restart, NM restart, reboot,
full-tunnel, split, DNS/IPv6, kill switch, uninstall, reinstall.

Release criteria: all automated checks green, live Linux test green, matrix
rows run with results recorded, no open critical security issues.
