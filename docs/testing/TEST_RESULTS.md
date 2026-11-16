# Test results

Only what was actually executed. Newest first.

## 2026-11-16 — VM harness pre-push checks

- `shellcheck scripts/test-netns-peer.sh scripts/vm/run-vm-tests.sh`: pass.
- `shfmt -d scripts/test-netns-peer.sh scripts/vm/run-vm-tests.sh`: pass.
- `cargo fmt --all --check`: pass.
- `cargo test -p aegis-linux`: 8 tests passed.
- `cargo clippy -p aegis-linux --all-targets -- -D warnings`: pass.

Not run in this check: the disruptive VM suite. These checks do not establish
full-tunnel, DNS/IPv6 leak, reconnect or NetworkManager-restart results.

## 2026-11-16 — LIVE edit + export through NetworkManager

Same host and isolated netns peer as the split-route run below (peer re-created
with fresh keys). Test: `target/debug/examples/nm_edit_live
/run/aegis-test/aegis-netns-test.conf`, unprivileged user.

| Step | Result |
|---|---|
| Editor draft loads (NM `GetSecrets`) | PASS |
| Draft shows correct derived public key | PASS |
| Draft JSON (UI payload) contains no private key | PASS (384 B) |
| Update: rename, MTU 1380, keepalive 15, add search domain (NM `Update2`) | PASS |
| Reloaded config has the edits and the original private/peer keys | PASS |
| Connect edited profile | PASS |
| Kernel interface `aegis-43bc7148` MTU is 1380 | PASS |
| Ping 10.99.0.1 through edited tunnel; server response confirmed | PASS |
| Export; file mode 0600; parses equal to edited config | PASS |
| Aegis NM keyfile exists and is not readable by the user | PASS |
| Delete; no leftover NM connection or interface | PASS |

First attempt had 1 FAIL: the test asserted the keyfile **directory** was not
listable, but Debian's `network-manager` package ships
`/etc/NetworkManager/system-connections` as 0755 (files 0600). That was a wrong
assertion, not a leak: no keyfile was readable. The test now checks the
real property (our keyfile unreadable). Consequence recorded in the threat
model: other local users can see profile *names* via the directory listing.

## 2026-11-16 — LIVE split-route tunnel through NetworkManager (first real tunnel)

Host: Debian forky/sid, KDE Plasma Wayland, kernel 7.2.15, NetworkManager 1.58.1,
Tailscale active. Peer: `scripts/test-netns-peer.sh up` run via `pkexec`
(isolated namespace `aegis-peer`, WireGuard server 10.99.0.1, endpoint
10.200.0.2:51820 over veth). Test: `target/debug/examples/nm_live
/run/aegis-test/aegis-netns-test.conf`, run as the normal (unprivileged) user.

| Step | Result |
|---|---|
| Import profile | PASS: route kind Split |
| Connect (NM AddConnection2 + ActivateConnection via Polkit, no root) | PASS in 282 ms |
| `ping -c 3 10.99.0.1` through the tunnel | PASS: 3/3 received |
| Engine reports server response confirmed | PASS: `Connected { peer: Confirmed }`, interface `aegis-874e8416`, rx 476 B / tx 564 B |
| Disconnect | PASS: state Disconnected |
| Delete profile | PASS |
| No leftover `aegis-*` interface | PASS |
| No leftover 10.99.0.0/24 route | PASS |
| No leftover Aegis NetworkManager connection | PASS: 0 |

Host state before vs after (`ip route/rule show table all` v4+v6, `resolvectl dns`,
`nmcli connection show`): policy rules **identical**, DNS **identical**, NM
connection list **identical**. Routes differ only by the test peer's own
`aegis-veth0` link routes (created by the script, removed by `down`).
After `test-netns-peer.sh down`: routes and policy rules (v4+v6, all tables)
**identical** to the pre-test snapshot.

Not covered by this run: full-tunnel routing, DNS/IPv6 leak behaviour, kill
switch, reconnect after a real drop, NM restart, suspend/resume, reboot, and
the desktop UI driving the connection (the test drives the same `Engine` the
UI uses). Verification of the NM keyfile permissions was not done.

## 2026-11-16 (later) — tauri-plugin-notification → notify-rust 4.19

| Check | Command | Result |
|---|---|---|
| Format / clippy | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| Tests | `cargo test --workspace` | 51 passed |
| zbus 5 dependents | `cargo tree -i zbus@5.19.0` | only tauri-plugin-single-instance 2.5.5 remains |
| Rust advisories | `cargo audit` | 0 vulnerabilities; same 5 warnings (zbus 5 crates now via single-instance only; proc-macro-error; glib 0.18) |
| Windows type-check | `cargo check -p aegis-desktop --target x86_64-pc-windows-msvc` | not possible here: tauri-build needs `llvm-rc` (not installed). The `cfg(not(unix))` notification branch is unverified until the Windows CI job runs |

Not run: an actual notification popup on KDE/GNOME/Windows.

## 2026-11-16 (later) — zbus 5.19 → 6.3 migration, same host

| Check | Command | Result |
|---|---|---|
| Format / clippy | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| Tests | `cargo test --workspace` | 51 passed (21 config, 22 core, 8 linux) |
| NM read-only probe on zbus 6 | `cargo run -p aegis-linux --example nm_probe` | pass: NM 1.58.1, 0 Aegis profiles, no active tunnel |
| Rust advisories | `cargo audit` | 0 vulnerabilities; same 5 warnings. zvariant/zvariant_derive/zbus_names 5.x now come only from tauri-plugin-notification 2.8.1 and tauri-plugin-single-instance 2.5.5 (`cargo tree -i zbus@5.19.0`); aegis-linux no longer depends on them |

Not run: live tunnel test (still needs root for the netns peer).

## 2026-11-16 — Debian forky/sid, KDE Plasma (Wayland), kernel 7.2, NM 1.58.1, rustc 1.99.1, Node 24

| Check | Command | Result |
|---|---|---|
| Rust format | `cargo fmt --all --check` | pass |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| aegis-config | `cargo test -p aegis-config` | 21 passed (incl. 2000-case proptests, RFC 7748 key vector) |
| aegis-core | `cargo test -p aegis-core` | 22 passed (connect/cancel/reconnect/fail-closed/recovery/no-secret-leak) |
| aegis-linux | `cargo test -p aegis-linux` | 8 passed (NM settings mapping, ownership, DNS byte order) |
| Windows stub | `cargo check -p aegis-windows --target x86_64-pc-windows-msvc` | pass (type-check only, not linked or run) |
| Frontend lint/types | `pnpm lint`, `pnpm typecheck` | pass |
| Frontend tests | `pnpm test` | 9 passed |
| Frontend build | `pnpm build` | pass, 265 KB JS (83 KB gzip) |
| Desktop build | `cargo build -p aegis-desktop` | pass |
| App launch (mock) | `AEGIS_BACKEND=mock pnpm tauri dev` | launched, no errors in log; UI not visually reviewed |
| NM read-only probe | `cargo run -p aegis-linux --example nm_probe` | pass: connected, NM 1.58.1, 0 Aegis profiles, no active tunnel |
| Shell scripts | `shellcheck`, `shfmt -d` on `scripts/test-netns-peer.sh` | pass |
| Workflow syntax | `yq` parse of `.github/workflows/*.yml` | parses; actionlint not installed |
| Rust advisories | `cargo audit` | 0 vulnerabilities; 5 warnings: zvariant/zvariant_derive/zbus_names 5.x unmaintained (RUSTSEC-2026-0370/0371/0372, via zbus 5.19), proc-macro-error unmaintained (RUSTSEC-2024-0370), glib 0.18.5 unsound (RUSTSEC-2024-0429, via Tauri GTK3 stack) |
| npm advisories | `pnpm audit --prod` | no known vulnerabilities |

### Not run
- **Live tunnel test** (`nm_live` against netns peer): needs root for the namespace. Not run.
- CI on GitHub: repository has no remote.
- Windows build/run: no Windows host; CI job written but not run.
- Tray on GNOME/KDE, notifications, autostart, packaging (deb/rpm/nsis).
- Any DNS/IPv6 leak, kill-switch, suspend, reboot or network-change test.
- cargo-deny (not installed locally).
