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
- [~] Windows 11 dev machine now available (unelevated; Hyper-V VM for disruptive tests not yet usable, needs admin rights). Handoff: docs/development/WINDOWS_HANDOFF.md
- [x] Pipe protocol (`aegis-windows::proto`) and tunnel naming (`names`): unit-tested on Linux and Windows
- [~] The Windows client and service have pipe round-trip tests. Desktop selection remains disabled while server authentication is pending.
- [x] `services/windows-service` pipe server: explicit DACL, first-instance flag, bounded connections, tested unelevated (8 tests). Handler is a `Skeleton` that reports everything `Unsupported`
- [ ] Run the service as LocalSystem under the SCM (`aegis-service service`) and re-test the pipe as SYSTEM; per-connection client check
- [x] DPAPI config store in the `tunnel.dll` format (`<name>.conf.dpapi`), directory ACL verified, service-side re-validation: tested unelevated; not yet as SYSTEM or read by `tunnel.dll`
- [~] `tunnel.dll` built locally from upstream source and `wireguard.dll` fetched (hashes in TEST_RESULTS); not yet loaded; CI build and pinning still to do
- [x] `aegis-tunnel.exe` host: argument rules, safe absolute-path load of the real `tunnel.dll` (not called yet)
- [ ] Install `WireGuardTunnel$aegis-…` via SCM (needs elevation), run `tunnel.dll` as SYSTEM on our `.conf.dpapi`, status/handshake
- [ ] tunnel.dll + wireguard.dll build in CI, NSIS install/uninstall hooks
- [ ] Windows kill switch (WFP, own provider/sublayer), DNS/IPv6 verification, sleep/resume, network change

## Phase E: security
- [~] `aegis-helper` (pkexec + Polkit) with nftables `inet aegis_vpn` kill switch (DECISIONS D14); VM results in TEST_RESULTS
- [~] Helper hardening verified in the Debian VM with a test Polkit rule (2026-11-18). Desktop administrator prompts remain untested.
- [~] Include the helper and Polkit policy in DEB/RPM bundles. Native package lifecycle verification remains pending.
- [ ] Kill switch: forward chain for containers/VMs, hostname endpoints
- [ ] Helper: detect leaked NetworkManager anti-spoofing rules for the active tunnel address and warn in Diagnostics/Dashboard; never remove them (DECISIONS D11)
- [ ] Report the NM rule leak upstream (check whether NM ≥1.52.2 / 1.58 still has it)
- [x] DNS/IPv6 leak protection: IPv6 blocked on IPv4-only full tunnels, runtime `Verified`/`Failed` checks, VM-tested (122/122, Debian 13, 2026-11-16; DECISIONS D12)
- [x] Internet reachability: tunnel-DNS lookup on connect and every 60 s, VM-tested positive and negative (DECISIONS D13)
- [ ] DNS/IPv6 verification on Ubuntu/Fedora (resolved and plain resolv.conf setups)
- [x] QEMU VM harness (`scripts/vm/`): full-tunnel, DNS/IPv6 leak, reconnect, NM-restart and restore checks; **89/89 pass** on Debian 13 (2026-11-16)
- [x] Network switch (real NM primary-connection change) and silent-server handling, VM-tested; resume logic unit-tested (DECISIONS D15)
- [ ] Real suspend/resume and Wi-Fi roaming on hardware; re-activate the tunnel when NoResponse follows a network change if NM keeps a stale endpoint route
- [ ] Extend VM suite: reboot with tunnel up; Ubuntu and Fedora images

## Phase F: distribution
- [~] Tauri bundle config for deb/rpm/nsis; never built
- [ ] Signed releases, updater, packaging scripts, test matrix runs

## Later (v1.1+)
Per-app split tunnelling, advanced DNS, profile groups, backups, provisioning.

## Locations (2026-11-16)
- [x] Secret-free server metadata on existing ProfileId, ISO catalog, additive store defaults
- [x] Locations navigation, country/server selection, search, favorites/recent/available filters
- [x] Import assignment, existing-profile assignment and manual generated-key registration gate
- [x] Country favorites, preferred country/profile, documented Quick Connect eligibility/ranking
- [x] Dashboard synchronization, response-age expiry, unknown RTT, cancellation regression tests
- [~] Real Linux switching reuses NM, with destination preflight, ID/link confirmation and cleanup;
  unit/interface checks pass, extended VM switching test not run here (no /dev/kvm)
- [~] Isolated Linux VPN CI workflow added; manually triggered, not executed this session
- [ ] Windows privileged service and real Windows integration acceptance
- [ ] Protected country switching with continuous transition protection; suspend/resume/reboot/uplink-change matrix
- [ ] Supported RTT sampler, public multi-country controlled-server matrix, independent security audit

See `docs/features/LOCATIONS.md`; the full cross-platform acceptance criteria
remain incomplete until those platform/protection checks exist and pass.

- Audit/remediation and current release evidence: [FULL_GAP_AUDIT](audits/FULL_GAP_AUDIT.md), [REMAINING_GAPS](audits/REMAINING_GAPS.md).
