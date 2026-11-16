# Aegis VPN

A lightweight, open-source WireGuard® client for Linux and Windows 11, built with
Rust, Tauri 2 and React. Working name.

> **Status: pre-alpha.** The Linux NetworkManager backend is implemented but has
> not yet passed a live tunnel test. The Windows backend is not implemented.
> There is no kill switch yet. Do not rely on this for protection. See
> [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/testing/TEST_RESULTS.md](docs/testing/TEST_RESULTS.md).

## What it does

- Imports standard WireGuard `.conf` files (file picker or drag and drop),
  rejecting `PostUp`-style scripts and directives it cannot honour
- Creates and edits profiles without ever showing or accepting raw keys in the UI
- Connects through NetworkManager on Linux; tunnels keep running when the app closes
- Shows what is actually confirmed: tunnel up, server responded, protection
  configured or not, instead of a single "secure" badge
- Automatic reconnect with bounded backoff, diagnostics, sanitized export
- Light and dark themes, keyboard navigation, tray menu
- No account, no telemetry, no network requests of its own

## Supported platforms

| Platform | Status |
|---|---|
| Linux with NetworkManager ≥ 1.16 (Ubuntu, Debian, Fedora; GNOME/KDE) | Implemented, live test pending |
| Linux without NetworkManager | Not supported yet (shown as unavailable) |
| Windows 11 x64 | Not implemented |

## Build from source

See [docs/development/LINUX.md](docs/development/LINUX.md) and
[docs/development/WINDOWS.md](docs/development/WINDOWS.md).

```sh
cd apps/desktop && pnpm install && pnpm tauri dev
# UI only, no real tunnels:
AEGIS_BACKEND=mock pnpm tauri dev
```

## Limitations

- No kill switch; with it enabled in Settings the app refuses to connect.
- DNS and IPv6 protection for full-tunnel profiles is configured through
  NetworkManager but not independently verified.
- Handshake times are not readable without root on Linux; the app infers a
  server response from received data.
- Not independently security-audited.

## License

MIT OR Apache-2.0. WireGuard is a registered trademark of Jason A. Donenfeld;
this project is not affiliated with the WireGuard project.
