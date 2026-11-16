# Windows development

**The Windows backend is not implemented.** The app builds and runs, but
reports that no VPN backend is available.

Prerequisites: Visual Studio Build Tools (C++ workload), WebView2 runtime
(preinstalled on Windows 11), Rust stable MSVC, Node 24, pnpm 12.

```powershell
cd apps\desktop
pnpm install
$env:AEGIS_BACKEND="mock"; pnpm tauri dev
```

Planned design (Phase D) is in `docs/architecture/RESEARCH.md` and
`crates/aegis-windows/src/lib.rs`: LocalSystem service, official
embeddable-dll-service (`tunnel.dll`, `wireguard.dll`), DPAPI-protected
configs, ACL-restricted named pipe. Do not install test-signed drivers.
