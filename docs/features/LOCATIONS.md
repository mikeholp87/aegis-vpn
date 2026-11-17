# VPN Locations

Locations is a directory of **your configured WireGuard profiles**. Aegis does
not sell VPN access or include public servers. A country assignment describes
what you entered; it does not verify the server's physical location.

## First real server

1. Ask your provider or server operator for a working client `.conf`. The
   remote server must already recognize that client's public key and tunnel
   address. Importing a file does not configure a remote machine.
2. Open **Locations → Add server → Import WireGuard Configuration**. The native
   file picker passes the configuration directly to Rust. Choose a country,
   optionally a city, region and descriptive time zone, and save. If you import
   several files, metadata dialogs appear in order. Skipping a dialog leaves
   its profile under **Unassigned location**; it does not delete the import.
3. Select the country, choose a server and click **Connect**. On Linux the
   existing NetworkManager/Polkit backend authorizes activation. A backend
   unavailable error means this build cannot establish a tunnel on that system.
4. Wait for **Server answered**. A tunnel interface being up does not prove
   that the remote peer answered. Exact handshake times are unavailable with
   the unprivileged Linux backend; authenticated received data provides evidence
   instead. Check ordinary traffic separately.
5. **Dashboard → Change location** returns to the directory. Select another
   configured country/server and choose **Switch server**. **Disconnect** stops
   the owned tunnel. Closing the GUI keeps the NM tunnel running; reopening
   adopts it.

Profiles imported in Profiles or through drag-and-drop remain supported. Use
**Locations → Add server → Assign an existing profile** to assign their country.
Multiple peers remain one profile/server entry, with every endpoint and all
original AllowedIPs preserved. Duplicate endpoints are allowed; duplicate names
receive the existing numbered suffix. No endpoint-derived country inference is
performed.

## Manual setup and keys

**Configure manually** opens the existing profile editor: server name, client
addresses, server public key, endpoint (`host:port`, or `[IPv6]:port`), AllowedIPs,
DNS, keepalive and MTU. It generates a client key inside Rust. Save, assign a
country, then copy the **public** client key and tunnel addresses from server
details to your operator. Only confirm registration after the operator has
registered them. Until then, connection attempts and Quick Connect are blocked.
The configuration is locally valid, but remote availability is unknown.

The webview never accepts client private or preshared keys. To use existing
keys, import a `.conf`. For a generated preshared key, explicitly export the
profile from Profiles and deliver that secret securely to the operator; export
shows a warning and uses a native save dialog. Do not transmit configurations
through chat, analytics, diagnostics or public issue reports.

Keys are still stored by NetworkManager in its protected backend store. The
server registry stores only a profile ID, location, preferences and history.
Editing configuration uses the existing validator. Changing generated keys
requires remote registration again; neither generation nor a registration
checkbox proves that a remote server is ready.

## Browsing and preferences

- Search country names/codes, city, region, server names or endpoints.
- Expand/collapse a country to inspect its servers. Bundled SVG flags render
  consistently without depending on OS emoji support. Names remain available
  to screen readers.
- Star a server or country; the **Favorites** filter includes both.
- **Recently used** lists only connections with observed peer evidence, never
  unsuccessful attempts. Sort by country, recent success or favorites.
- **Manage** edits location, opens configuration, sets the preferred profile,
  or deletes the server and its stored keys after confirmation. Active tunnels
  must be disconnected before disabling, deleting, renaming or editing config.
- **Quick Connect country** optionally limits automatic selection. Disabled
  servers are excluded. The existing preferred profile setting is reused.

Country metadata uses the maintained Debian `iso-codes` ISO 3166-1 alpha-2
catalog (249 codes in the bundled snapshot). Updating the catalog data adds
countries without application logic changes. City, region and time zone are
optional user text; a country has no single assumed time zone. Catalog and flag
licenses/provenance accompany their respective data directories.

## Quick Connect and health

Quick Connect does not claim to select the highest-throughput or lowest-latency
server. It never creates temporary tunnels or contacts idle endpoints to test
speed. It selects only enabled, configured, registration-ready profiles in the
preferred country (if set), excluding recent failures for five minutes and a
currently nonresponding peer. Ranking is: authenticated response within five
minutes, preferred profile, server/country favorite, most recent success, then
stable name/ID order. The reason is recorded in Activity. A failed attempt is
not retried across the whole directory automatically.

**Available servers** means an authenticated response was observed within five
minutes, not a promise of present availability. Unknown and expired results
remain unknown. A missing reply is not proof that the WireGuard service is
unreachable. Latency is **Not measured**: no supported RTT sampler exists in
this release. Tunnel activation duration, a DNS lookup, ping failures and
handshake age are not substituted for WireGuard RTT. There are no load figures.

**Refresh status** reads the active backend tunnel and protection state. Idle
servers are never probed. Passive observations use the existing two-second
monitor; no new scan service or automatic remote probes are started. History
is persisted once per successful session/attempt/failure, rather than writing
on every transfer-counter poll. More recent in-memory observations may be lost
on a crash; this conservatively expires old health after restart.

Settings controls optional connectivity checks, separately from peer response
and DNS/IPv6 policy verification. Read its privacy disclosure before enabling
it. DNS resolver responses and DNS-based address observations report the recursive resolver’s egress IPv4, not
a verified client VPN exit address. They have narrower meaning than general
internet access, throughput or geographic verification.

## Switching and security limits

One engine and its operation lock own all changes. Conflicting connect and
Quick Connect requests return Busy. Destination configuration is loaded and
validated **before** the working tunnel is removed; cancel during preflight
keeps that tunnel. Cancel during activation invokes cleanup. The selected
backend must confirm the destination ID and link state before Connected.

Switching is sequential: disconnect old, activate new. If destination startup
fails, cleanup runs and the state is Failed; cleanup uncertainty is explicitly
Uncertain. There is no automatic fallback to another server or to an unprotected
mode, and no automatic rollback activation that could obscure the failure.
A later connection requires an explicit user action or existing bounded
reconnect for the selected profile.

Linux now has an optional nftables kill switch through the installed
`aegis-helper`/Polkit integration. The backend reports whether it is available;
requesting it on an unsupported installation blocks connection. It requires
literal IP endpoints and keeps blocking after a failed attempt/drop until
**Disconnect/Stop blocking**. See the helper documentation and current test
results before enabling it.

**Protected switching remains refused**, even when the helper is installed.
Continuous transition protection and helper failure semantics need their own
implementation and live acceptance. A refused switch keeps the current tunnel
and block. Do not turn protection off merely to force a switch. With protection
off, ordinary traffic may use the uplink between tunnels. DNS/IPv6 checks
report backend observations; local resolver domains and non-full-tunnel routing
retain their documented limitations. See architecture decision D11 for NM
firewall leftovers after a daemon restart; Aegis never flushes global state.

Windows remains an unavailable backend: a LocalSystem service, authenticated
ACL-restricted IPC, DPAPI storage, official embeddable tunnel DLL integration,
installer/reboot/restart cleanup and Windows runtime testing are still required.
The Windows CI job verifies builds and portable tests, not a real tunnel.

## Operator preparation

Use the [official WireGuard quick start](https://www.wireguard.com/quickstart/)
and your OS networking documentation. An operator needs to:

1. Install an official WireGuard implementation on the intended server, keep
   its private key private and give the client the server's **public** key.
2. Add a peer for the client's public key, assigning unique tunnel addresses
   and server-side AllowedIPs for those addresses; provision a matching
   preshared key on both ends if used.
3. Listen on the advertised UDP port; permit it in the host/cloud firewall.
   Ensure the client endpoint is reachable outside the tunnel.
4. For internet VPN service, deliberately configure IPv4/IPv6 forwarding,
   suitable routed address space or NAT, return routes and a tunnel-reachable
   DNS resolver. Aegis cannot turn a private-network peer into an internet exit.
5. Deliver the matching client `.conf` securely. Its client AllowedIPs select
   intended routes; provide addresses for every default-route address family.
   Test from a controlled client, including DNS and IPv6, before production use.

Aegis does not SSH into servers or provision VPS instances. A future provisioning
feature must first inspect state, show proposed changes and rollback, obtain
explicit permission, verify SSH host keys, protect SSH/config secrets, and
preserve unrelated networking. Cloud credentials are never discovered
implicitly and fetched arbitrary installer scripts are not acceptable.

## Troubleshooting and verification

- **Unavailable backend:** install/start supported NetworkManager on Linux.
  Windows service support is pending; mock mode never creates a real tunnel.
- **Registration pending:** register the displayed public identity with the
  operator, then confirm in server details. Existing keys require import.
- **No response:** check public-key roles, preshared key matching, endpoint,
  UDP firewall and the remote client peer. Internet reachability is separate.
- **Busy:** wait, Cancel, or Disconnect; operations are not queued as conflicting
  connects. **Uncertain:** retry Disconnect or resolve the backend failure.
- **No Quick Connect candidate:** clear country restrictions, enable/register a
  profile, wait for a recent failure's cooldown, or import a server.
- **Wrong location:** edit user metadata; the hostname is not geographic proof.
- **Validation failure:** unsupported scripts/directives are rejected, never
  silently executed or discarded. Preserve original files for recovery.

Automated coverage and missing live-platform checks are recorded in
[TEST_RESULTS](../testing/TEST_RESULTS.md). The manually triggered
`vpn-integration.yml` runs the VM-only suite, including switching between two
country-labelled profiles of one controlled peer. That validates switching
mechanics, not actual servers located in different countries. Public multi-country,
Windows, suspend/resume, reboot and protected-switch acceptance remain
unverified by this feature’s checks. Separately recorded helper VM checks do
not establish protected-switch success.

## Implementation files

- `crates/aegis-core/src/registry.rs`, `types.rs`, `engine.rs`: metadata,
  migration defaults, validation, history/health, selection and connection flow.
- `apps/desktop/src/screens/Locations.tsx`, `lib/locations.ts`, `App.tsx`,
  `Dashboard.tsx`, `Profiles.tsx`, `lib/store.ts`: directory, editing, navigation,
  shared editor, events and active location presentation.
- `apps/desktop/src/lib/api.ts`, `lib/types.ts`, Tauri `commands.rs`, `lib.rs`,
  `backend.rs`, `build.rs`, `capabilities/default.json`: typed commands and
  explicit permissions, with existing backend operation forwarding.
- `crates/aegis-core/data/`, `apps/desktop/public/flags/`: country catalog,
  flags and licenses. No new runtime library dependency was introduced.
- `engine_tests.rs`, `registry.rs` unit tests, `App.test.tsx`,
  `lib/locations.test.ts`, Linux `examples/vm_suite.rs`: regressions and isolated
  live-test coverage. `.github/workflows/vpn-integration.yml`: manual VM CI.
- README, AGENTS, architecture/decisions/security, roadmap, changelog and test
  docs: usage and exact limitations. CLAUDE continues to import AGENTS as the
  repository's single instruction source.
