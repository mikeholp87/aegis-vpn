# Threat model (v0.1, not independently reviewed)

Assets: WireGuard private/preshared keys; the user's traffic and DNS;
integrity of system network configuration.

| Threat | Mitigation | Status |
|---|---|---|
| Malicious imported `.conf` (scripts, routing tricks) | Parser rejects Pre/PostUp/Down, SaveConfig, Table, FwMark, unknown keys; size cap 64 KiB; proptest fuzzing | Done, tested |
| Wrong file imported, contents echoed in UI | Errors name key + entry index only, never values | Done, tested |
| Compromised webview content | No keys or paths cross IPC; per-command allow-list; CSP; no shell/fs/http plugins; exports need native dialog | Done; CSP/permissions not penetration-tested |
| Path traversal on import/export | Paths only from native dialogs / OS drop events; import requires regular file | Done |
| Key exposure in logs/diagnostics/crash output | `SecretKey` redacted Debug, no Display/Serialize; tests scan UI payloads and bundle | Done, tested |
| Other local users | NM `permissions=user:<me>`; app files 0600 in 0700 dir; NM keyfile root 0600 | Done; live check pending |
| Untrusted IPC clients / helper impersonation | No helper yet. Planned: SO_PEERCRED + Polkit check (Linux), pipe DACL + SID check (Windows) | Planned |
| DLL search-path attacks (Windows) | Planned: load tunnel.dll by absolute path from install dir, `SetDefaultDllDirectories` | Planned |
| DNS leaks | Full tunnel: NM exclusive DNS (priority -50, `~.`); reported as Configured, not Verified | Configured, unverified |
| IPv6 leaks | Full tunnel routes ::/0; IPv4-only full tunnels reported as Failed for IPv6 | Configured, unverified |
| Traffic outside tunnel during failures | No kill switch yet; requesting it blocks connecting (fail closed) | Partial |
| Stale routes/interfaces | NM owns and removes them; engine rolls back failed activation; recovery removes orphan profiles | Implemented; live test pending |
| Touching other VPNs/connections | Ownership check (uuid + type + `aegis-` iface) before any change | Done, tested (unit) |
| Dependency compromise | Pinned versions, lockfiles, cargo-deny/audit + pnpm audit in CI, actions pinned by SHA | CI written, not run (no remote) |
| Unsafe updates | Updater disabled until signing + rollback tested | By design |

Known dependency warnings: see `docs/testing/TEST_RESULTS.md` (zbus 5 crates
unmaintained; glib 0.18 unsound via Tauri's GTK3 stack).
