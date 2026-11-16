# Architecture

## Components

```
┌──────────── Webview (unprivileged, no secrets) ────────────┐
│ React UI: Dashboard · Profiles · Activity · Settings ·    │
│ About. Talks only through typed Tauri commands/events.    │
└──────────────┬──────────────────────────────▲─────────────┘
       invoke (allow-listed)            "engine" events
┌──────────────▼──────────────────────────────┴─────────────┐
│ Tauri shell (apps/desktop/src-tauri): commands, native     │
│ dialogs, drag-drop, tray, notifications, autostart.        │
│ AnyBackend picks the backend at start-up.                  │
├────────────────────────────────────────────────────────────┤
│ aegis-core Engine<B: VpnBackend>                           │
│  · ConnectionState machine, op lock, cancel, timeouts      │
│  · monitor (2 s poll) → PeerState, rates, drop detection   │
│  · bounded reconnect (1 s → 60 s, N attempts)              │
│  · crash recovery: adopt live tunnel, remove orphans       │
│  · Store: profiles.json + settings.json (no secrets, 0600) │
│  · diagnostics + sanitized bundle                          │
├──────────────┬──────────────────┬──────────────────────────┤
│ MockBackend  │ NmBackend (Linux)│ ServiceBackend (Windows) │
│ opt-in only  │ D-Bus → NM       │ STUB: reports unavailable│
└──────────────┴────────┬─────────┴──────────────────────────┘
                        │ system D-Bus + Polkit
               ┌────────▼────────┐
               │ NetworkManager  │ root: creates wg iface, routes,
               │ (system)        │ DNS; stores keys root-only
               └─────────────────┘
```

## Key data flows

**Import.** User picks a file in a native dialog (or drops it) → Rust reads
≤64 KiB → `aegis_config::parse` (rejects scripts/unknown keys; errors never
echo values) → `backend.install(id, name, cfg)` (NM `AddConnection2` with
secrets) → metadata + `ProfileSummary` saved to `profiles.json`. If saving
metadata fails the backend profile is removed again.

**Connect.** `Engine::connect` takes the op lock → checks requested
protection is available (fail closed) → `Preparing` → `Connecting` →
`backend.activate` (NM `ActivateConnection`, waits for state ACTIVATED,
30 s timeout, cancellable) → `Connected{peer: Pending}` → monitor reads
status every 2 s; `rx_bytes > 0` or a handshake time ⇒ `Confirmed`; sent
data with no reply for 20 s ⇒ `NoResponse`. Link gone ⇒ reconnect loop.

**Edit.** UI receives a `ProfileDraft` (no keys) → returns it with
`KeyAction`s → core loads the full config from the backend, applies, validates,
reinstalls (NM `Update2`).

**Close/quit.** Closing the window hides it (tray present) or quits the UI.
The engine never deactivates on exit: NM owns the tunnel, so it persists.
On next start, `recover()` adopts it.

## Secret handling

| Where | Linux | Windows (planned) |
|---|---|---|
| At rest | NM keyfile, root 0600, `private-key-flags=0` | DPAPI-encrypted config in ProgramData |
| App storage | none | none |
| In memory | `SecretKey` zeroized on drop | same |
| To UI | never | never |
| Export | explicit, warned, native save dialog, 0600 | same |

## Not built yet

Root helper (kill switch, non-NM fallback, exact handshake time), Windows
service, updater, packaging scripts. See `docs/ROADMAP.md`.
