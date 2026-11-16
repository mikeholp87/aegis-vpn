# Changelog

## Unreleased
- Locations directory with ISO country metadata and bundled licensed flags
- Persistent server/country favorites, recent peer-confirmed history and Quick Connect
- Import/manual profile workflows with country assignment and key-registration gating
- Validated, cancellable server switching through the existing Linux engine
- Dashboard location synchronization, honest unknown health and explicit failure states
- Isolated VM switching checks and manually triggered Linux networking CI (not run here)
- Windows tunnel service, RTT sampling and protected switching remain unavailable
- WireGuard config parser/validator with script and unknown-key rejection
- Connection engine with explicit states, cancel, reconnect, crash recovery
- Desktop app: dashboard, profiles, diagnostics, settings, about, tray
- Linux NetworkManager backend (live test pending)
- Windows backend stub (reports not implemented)

## Locations and server switching

Country assignments are user metadata, not geographic verification. The registry
contains no private or preshared keys; diagnostic bundles may include endpoints,
location labels and connection timestamps, so review them before sharing.
No server directory probes or geolocation requests run automatically. Read the
Settings disclosure for optional connected-tunnel connectivity checks.

There is no kill switch in this build. Switching is disconnect-then-connect;
requested fail-closed protection blocks connection rather than silently falling
back. Destination validation precedes teardown, and failed cleanup produces an
explicit Uncertain state. Windows service support and full live cross-platform
acceptance are pending; see `docs/features/LOCATIONS.md` and the test results.
