# Roadmap and status

Legend: [x] done and verified · [~] implemented, not fully verified · [ ] not started · [!] blocked

## Phase A: foundation
- [x] Cargo workspace, toolchain, lints
- [x] `aegis-config` parser/validator/serializer + 21 tests incl. proptest
- [x] `aegis-core` engine, store, drafts, diagnostics, mock + 22 tests
- [x] Architecture, decisions, research, threat model docs
- [~] CI workflows (`ci.yml`, `release.yml`) written; **never run** (local git only, no remote)

## Phase B: desktop UI
- [x] Dashboard, Profiles (search/import/drag-drop/editor/duplicate/export/delete/preferred), Activity & diagnostics, Settings, About
- [x] Light/dark/system theme, keyboard focus, reduced motion, native dialogs/radios
- [x] 9 Vitest UI tests
- [~] Tray menu: implemented; not tested on GNOME/KDE/Windows
- [~] Notifications (notify-rust), autostart: implemented; not tested
- [ ] Visual review of the running app by a human (agent did not screenshot)

## Phase C: Linux backend
- [x] NetworkManager detection (read-only probe passed on NM 1.58.1)
- [x] WgConfig ↔ NM settings mapping + 8 tests
- [x] install/activate/deactivate/status via D-Bus: **live split-route test passed** 2026-11-16 (import, connect, ping, confirm, disconnect, delete, no leftovers)
- [x] Edit/export of an NM-stored profile (GetSecrets + Update2): **live test passed** 2026-11-16
- [x] Migrate our code to zbus 6 (zbus 5 remains only via two Tauri plugins; see DECISIONS D7)
- [ ] Non-NM fallback via root helper (shown as unavailable meanwhile)
- [ ] React to NM signals instead of 2 s polling

## Phase D: Windows
- [!] No Windows 11 machine available; stub backend reports "not implemented"
- [ ] `services/windows-service`, named pipe IPC, DPAPI, tunnel.dll build in CI, NSIS hooks

## Phase E: security
- [ ] `aegis-helper` (Polkit, SO_PEERCRED) with nftables `inet aegis_vpn` kill switch
- [ ] DNS/IPv6 leak verification (VM)
- [ ] QEMU VM harness (`scripts/vm/`) for full-tunnel and kill-switch tests

## Phase F: distribution
- [~] Tauri bundle config for deb/rpm/nsis; never built
- [ ] Signed releases, updater, packaging scripts, test matrix runs

## Later (v1.1+)
Per-app split tunnelling, advanced DNS, profile groups, backups, provisioning.
