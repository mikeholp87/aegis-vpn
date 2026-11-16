# Research notes (2026-11-16)

Versions checked against crates.io / npm on 2026-11-16.

| Component | Version | Notes |
|---|---|---|
| Tauri | 2.12.5 (`@tauri-apps/cli` 2.12.4) | capabilities + app manifest permissions; tray-icon feature |
| tauri-plugin-dialog / single-instance / autostart / notification | 2.8.4 / 2.5.5 / 2.7.0 / 2.8.1 | used from Rust only |
| zbus | 5.19 used; 6.3.0 current | see DECISIONS D7 and RustSec warnings |
| ipnet, base64, zeroize, x25519-dalek, getrandom | 2.12, 0.23, 1.9, 3.0, 0.4 | key derivation tested with RFC 7748 §6.1 vector |
| React / Vite / Tailwind / TypeScript / Vitest | 19.3 / 8.3 / 4.3 / 7.0 / 5.1 | |
| NetworkManager (dev host) | 1.58.1 | WireGuard since 1.16 |

## NetworkManager WireGuard (settings-wireguard)
`wireguard.private-key` (+`-flags`), `peers` = `aa{sv}` with `public-key`,
`allowed-ips` (as), `endpoint`, `preshared-key` (+`-flags`),
`persistent-keepalive`; `mtu`, `listen-port`, `fwmark`, `peer-routes`
(default true), `ip4/ip6-auto-default-route` (auto when a peer routes /0;
NM then adds policy rules like `wg-quick Table=auto`). `connection.interface-name`
is required. DNS isolation: `ipv4/6.dns-priority` negative + `dns-search ~.`.
Secrets via `Settings.Connection.GetSecrets("wireguard")`. Device statistics:
we read `/sys/class/net/<if>/statistics` instead of the NM Statistics
interface (which needs `RefreshRateMs` set).

## WireGuard for Windows embeddable-dll-service
From upstream README: service `WireGuardTunnel$<name>`, own-process,
auto start, depends on `Nsi` and `TcpIp`, **SID type
SERVICE_SID_TYPE_UNRESTRICTED** (required); executable invoked with
`/service <config path>`; load `tunnel.dll` and call
`WireGuardTunnelService(LPCWSTR)` (cdecl, BOOL). Requires `wireguard.dll`
(WireGuardNT) next to it. Build via `build.bat` (Go). Not yet confirmed from
upstream docs (must verify in Phase D): `.conf.dpapi` handling, UAPI named
pipe path for stats, prebuilt wireguard.dll redistribution licence.

## Open questions
- Is Polkit `settings.modify.own` granted for SSH/non-graphical sessions on
  each target distro? (Affects error messaging only.)
- GNOME without the AppIndicator extension shows no tray; closing then
  hides the window. Mitigation: re-launch focuses the window (single-instance).
