# Test results

Only what was actually executed. Newest first.

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
