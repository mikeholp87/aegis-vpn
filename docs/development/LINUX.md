# Linux development

Packages (Debian/Ubuntu names):
```sh
sudo apt install build-essential pkg-config libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev librsvg2-dev libssl-dev network-manager
# for live tests only:
sudo apt install wireguard-tools
```
Fedora: `webkit2gtk4.1-devel libayatana-appindicator-gtk3-devel librsvg2-devel openssl-devel NetworkManager`.

Toolchain: Rust stable (rustup), Node 24, pnpm 12.

```sh
cd apps/desktop
pnpm install
pnpm tauri dev                     # real NetworkManager backend
AEGIS_BACKEND=mock pnpm tauri dev  # simulated backend
AEGIS_LOG=debug pnpm tauri dev     # verbose logs (never include keys)
```

Read-only backend check: `cargo run -p aegis-linux --example nm_probe`.
Live split-route test: see `docs/testing/TEST_PLAN.md`.

Profiles you create appear in NetworkManager as "Aegis: <name>" with
interface `aegis-xxxxxxxx`. Remove leftovers with
`nmcli connection delete "Aegis: <name>"`.
