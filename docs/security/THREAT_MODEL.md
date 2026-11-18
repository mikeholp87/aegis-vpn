# Threat model (v0.1, not independently reviewed)

Assets: WireGuard private/preshared keys; the user's traffic and DNS;
integrity of system network configuration.

| Threat | Mitigation | Status |
|---|---|---|
| Malicious imported `.conf` (scripts, routing tricks) | Parser rejects Pre/PostUp/Down, SaveConfig, Table, FwMark, unknown keys; size cap 64 KiB; proptest fuzzing | Done, tested |
| Wrong file imported, contents echoed in UI | Errors name key + entry index only, never values | Done, tested |
| Compromised webview content | No keys or paths cross IPC; per-command allow-list; CSP; no shell/fs/http plugins; exports need native dialog | Done; CSP/permissions not penetration-tested |
| Path traversal on import/export | Native/OS paths only; bounded reads from one regular-file descriptor; Unix imports also reject symlinks | Done, tested |
| Key exposure in logs/diagnostics/crash output | `SecretKey` redacted Debug, no Display/Serialize; tests scan UI payloads and bundle | Done, tested |
| Other local users | NM `permissions=user:<me>`; app files 0600 in 0700 dir; NM keyfile root 0600 | Done; keyfile unreadable verified live. Residual: on Debian the keyfile directory is 0755, so connection names ("Aegis: <profile name>") are visible to other local users |
| Untrusted callers of the root helper | Administrator authentication for machine-wide firewall changes. Read-only queries scoped by first argument. Strict validation, fixed command paths and clean environment. Mutations are limited to `inet aegis_vpn`. Root-owned runtime directory, no-follow/single-link checks and kernel lock (D14). Windows plans call for a pipe DACL and SID check. | Hardened helper ran in the VM with a test Polkit rule. Desktop authentication prompts remain untested. |
| DLL search-path attacks (Windows) | Planned: load tunnel.dll by absolute path from install dir, `SetDefaultDllDirectories` | Planned |
| DNS leaks | Full tunnel: NM exclusive DNS (priority -50, `~.`); runtime check of DNS server routes and systemd-resolved routing ⇒ Verified/Failed (DECISIONS D12) | Verified in VM (Debian 13): tunnel DNS answers, 0 packets on uplink, with positive control |
| IPv6 leaks | Full tunnel routes ::/0; IPv4-only full tunnels get an unreachable ::/0 route; runtime route-lookup check ⇒ Verified/Failed (D12) | Verified in VM (Debian 13): ::/0 via tunnel; IPv4-only correctly reported as leaking |
| Traffic outside tunnel during failures | Kill switch (D14): nftables block from Connect until Disconnect, kept through drops, failed reconnects and app crashes; unavailable ⇒ connecting refused. Not covered: forwarded (container/VM) traffic, hostname endpoints (refused) | See TEST_RESULTS (VM) |
| Stale status or failed teardown misreported as safe/inactive | Uncertain state invalidates protection, keeps Disconnect available and blocks edits; failed teardown aborts switching | Regression tests; normal reconnect/restart/cleanup verified in VM |
| Interrupted helper operation or failed firewall inspection | Query kernel state. Preserve inspection errors through backend wrappers. Keep unknown state and failed cleanup retryable. Stop uninstall on cleanup failure. | Unit and stub failure tests passed. Live VM tests verified startup recovery of a retained block and confirmed its removal. |
| Stale "connected" status after sleep, a network switch or a dead server | Proof from before a resume/switch is discarded; a server that stops answering while we send is shown as NoResponse; kill switch stays on throughout (D15) | Unit-tested; network switch and silent server VM-tested; real suspend not tested |
| Stale routes/interfaces | NM owns and removes them; engine rolls back failed activation; recovery removes orphan profiles | Implemented; live test pending |
| Touching other VPNs/connections | Ownership check (uuid + type + `aegis-` iface) before any change | Done, tested (unit) |
| Dependency compromise | Pinned versions, lockfiles, cargo-deny/audit + pnpm audit in CI, actions pinned by SHA | CI written, not run (no remote) |
| Leaked NM anti-spoofing rules after NM restart (DECISIONS D11) | Detect and warn via helper; never removed by Aegis | Found in VM; detection planned with helper |
| Unsafe updates | Updater disabled until signing + rollback tested | By design |

Known dependency warnings: see `docs/testing/TEST_RESULTS.md` (four unmaintained
transitive crates). GLib 0.18 uses a pinned, reviewed two-line backport of its
iterator fix; its branch remains EOL. See `docs/security/GLIB_BACKPORT.md`.
Borrowed key decoding avoids additional owned secret strings, but zbus
serialization buffers cannot be guaranteed zeroized.


### Audit boundary updates

Windows opens no production pipe until an authenticated service exists. Pipe
name and protocol version cannot establish server identity. Linux Firewall
Verified is a periodic observation. An administrator can change a rule
between observations. Verify the actual capture requirements before making a
fail-closed claim for reboot, independently modified firewall rules or
protected transitions. Desktop mock mode uses in-memory keys and temporary
metadata, with a persistent simulation banner.
