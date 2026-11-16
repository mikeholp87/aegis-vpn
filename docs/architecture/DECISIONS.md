# Decisions

Each entry: decision, why, alternatives, revisit when.

### D1. Linux tunnels through NetworkManager, no root helper (2026-11-16)
NM ≥1.16 has native WireGuard connections and Polkit already authorizes the
active desktop user. The app stays unprivileged; NM does routes/DNS and
cleans up its own interface. *Alternatives:* own root helper with netlink +
nftables (more attack surface, duplicate of NM). *Revisit:* systems without NM
need a helper-based fallback (planned).

### D2. Secrets live with the privileged backend
Linux: NM system-owned secret (root-only keyfile, survives GUI exit, same as
Wi-Fi passwords). Windows: service + DPAPI. The app's own files hold only
metadata. *Alternative:* Secret Service/libsecret agent-owned secrets. Rejected
for v1: tunnel and reconnect would depend on the GUI running and on a
keyring being unlocked. *Trade-off:* root on the machine can read keys
(true of any VPN client).

### D3. Webview never handles keys or file paths
Editor offers Keep/Generate/Remove for keys; pasting keys is replaced by
importing a `.conf`. Dialogs run in Rust. Limits damage from compromised
web content to "use the commands the UI already has".

### D4. Explicit per-command Tauri permissions
`build.rs` declares the command list, so each command needs an `allow-*`
entry. No shell/fs/http/dialog JS plugins. Strict CSP, `freezePrototype`.

### D5. "Connected" is not "confirmed"
Unprivileged code cannot read WireGuard handshake times on Linux. We treat
authenticated data received (`rx_bytes > 0`) as proof the server answered,
show `Pending` until then and `NoResponse` after 20 s of unanswered traffic.

### D6. Fail closed on unavailable protection
If the kill switch is on in Settings but unsupported, `connect` refuses with a
fix-it message instead of connecting unprotected.

### D7. zbus 6 for the NetworkManager backend
First shipped on zbus 5.19; migrated to 6.3 on 2026-11-16 after RustSec
flagged zbus 5's zvariant, zvariant_derive and zbus_names as unmaintained
(RUSTSEC-2026-0370/71/72; zbus 6 merged them in). Our code uses
`zbus::{Variant, OwnedVariant, OwnedObjectPath, Proxy}` with features
`tokio` + `proxy`. tauri-plugin-notification was replaced by `notify-rust`
4.19 (`z-with-tokio`, zbus 6) called from Rust. **Remaining:** zbus 5 is still
pulled in by tauri-plugin-single-instance 2.5.5 (latest release), which we keep
because re-launching is how users get the window back on desktops without a
tray. *Revisit:* bump it when it moves to zbus 6.

### D8. Fewer crates than the original outline
Storage and diagnostics live in `aegis-core`; IPC crate deferred until the
helper/service exist. Split again when a module grows or gets a second user.

### D9. System UI font
No bundled or remote fonts: native look on KDE/GNOME/Windows, zero network
requests, strict CSP.

### D10. Mock only on explicit request
`AEGIS_BACKEND=mock`; never a silent fallback. Banner always visible.

### D11. Leaked NetworkManager anti-spoofing rules: detect and warn, never remove (2026-11-16)
Found in the VM suite: NetworkManager 1.52.1 (Debian 13) adds a raw-table rule
per full tunnel (`ip daddr <tunnel addr> iifname != "<iface>" … drop`). If NM
restarts while the tunnel is up, it re-adds the rule and on disconnect removes
only one copy; the leftover silently drops replies for any later tunnel with
the same address on another interface, while the app still sees encrypted
data arriving ("server responded"). Reproduced with a plain
`nmcli connection import` profile, so it is not Aegis-specific.
*Decision (user, 2026-11-16):* Aegis will **detect** such leftovers and show a
warning (reboot, or reload the firewall), and will **not remove** them, because
they belong to NetworkManager. Reading the ruleset needs CAP_NET_ADMIN, so the
check ships with the root helper (Phase E); there is no unprivileged
equivalent. *Also:* report upstream after checking current NM releases.
