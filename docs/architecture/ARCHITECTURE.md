# Architecture

## Components

```
┌──────────── Webview (unprivileged, no secrets) ────────────┐
│ React UI: Dashboard · Locations · Profiles · Activity ·    │
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

Non-NM fallback, exact handshake time, Windows service, updater and packaging
verification. Linux kill-switch work now uses the separately installed
`aegis-helper` through Polkit/pkexec (see decision D14); protected switching
remains refused. See `docs/ROADMAP.md`.

## Locations and registry

`aegis-core::registry` adds secret-free `ServerMetadata` to the existing
`ProfileMeta`; the profile ID is the server ID. It deliberately adds no second
credential store, endpoint record or connection engine. Old `profiles.json`
records deserialize with default metadata (enabled, unassigned, no history),
then the existing atomic writer includes it on the next mutation. Missing
settings fields also default; favorites and preferred-country selection use
`settings.json`. No destructive migration or rewrite occurs at startup.

The bundled ISO country catalog is separate from per-profile metadata and
credentials. `ServerUpdate` accepts only editable fields; clients cannot forge
connection timestamps or health. Configuration updates invalidate old response
samples and newly generated keys mark registration pending.

Tauri adds five explicitly permissioned commands: `country_catalog`,
`update_server`, `server_health`, `refresh_server_health`, `quick_connect`.
Listing, add/import/edit/delete, connect/disconnect/switch and preferred-server
operations reuse the existing profile commands. Filtering/grouping are pure UI
projections; Rust alone validates metadata and chooses Quick Connect candidates.
`Snapshot.health` shares the engine event stream, with no second connection
state store or background scanner. Listeners register before the initial fetch
so startup snapshots cannot overwrite a newer event.

Connect and Quick Connect take the existing operation lock with immediate Busy
rejection. A cancellable load/validate preflight runs before old-tunnel teardown.
Activation and backend ID/link confirmation share a bounded cancellable timeout.
The existing Preparing/Connecting/Disconnecting/Connected/Failed/Uncertain states
express each sequential switch step. Cleanup uncertainty blocks unsafe edits;
requested kill-switch protection blocks unsupported connection/switching.

Successful history requires fresh received data or a recent runtime handshake;
activation alone does not enter recents. Failed connection/reconnect attempts
cool down Quick Connect candidates. Recent response evidence expires after
five minutes; RTT remains absent because no supported sampler is implemented.
See [Locations](../features/LOCATIONS.md) for operational limits and pending
Windows/protected-switch acceptance.
