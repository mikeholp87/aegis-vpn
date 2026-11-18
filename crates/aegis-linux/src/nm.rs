//! NetworkManager backend over the system D-Bus.
//!
//! Runs unprivileged: NetworkManager performs interface, route and DNS changes
//! and Polkit authorizes the logged-in user (`settings.modify.own`,
//! `network-control`). This code only ever touches connections whose
//! settings identify them as ours (see [`settings::owned_profile`]).

use std::collections::HashMap;
use std::time::Duration;

use aegis_config::{RouteKind, WgConfig};
use aegis_core::{
    BackendKind, Capabilities, CoreError, Feature, LinkState, ProfileId, ProfileSummary,
    Protection, Result, Settings as AppSettings, Support, TunnelStatus, VpnBackend,
};
use zbus::{Connection, Proxy};
use zbus::{OwnedObjectPath, OwnedVariant};

use crate::settings::{self, Settings};
use crate::verify::{self, Resolver};

const NM: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const IF_SETTINGS: &str = "org.freedesktop.NetworkManager.Settings";
const IF_CONN: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const IF_ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const IF_DEVICE: &str = "org.freedesktop.NetworkManager.Device";

/// NMActiveConnectionState
const ACTIVATING: u32 = 1;
const ACTIVATED: u32 = 2;
const DEACTIVATING: u32 = 3;

/// Settings.AddConnection2 flags: persist to disk, keep it from autoconnecting.
const ADD_TO_DISK: u32 = 0x1;
const ADD_BLOCK_AUTOCONNECT: u32 = 0x20;
const MIN_VERSION: (u32, u32) = (1, 16);

pub struct NmBackend {
    conn: Connection,
    user: String,
    version: String,
    handshake: std::sync::Mutex<HandshakeCache>,
    /// OS events (resume, network switch), handed to the engine once.
    events: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<aegis_core::SystemEvent>>>,
}

/// Handshake reads go through pkexec, so they are cached and, after a
/// failure, not retried for a while (no repeated Polkit prompts).
#[derive(Default)]
struct HandshakeCache {
    activation: String,
    interface: String,
    value_ms: Option<u64>,
    next_read: Option<std::time::Instant>,
}

impl HandshakeCache {
    fn cached(
        &self,
        activation: &str,
        iface: &str,
        now: std::time::Instant,
    ) -> Option<Option<u64>> {
        (self.activation == activation
            && self.interface == iface
            && self.next_read.is_some_and(|t| now < t))
        .then_some(self.value_ms)
    }
}

const HANDSHAKE_EVERY: Duration = Duration::from_secs(10);
const HANDSHAKE_RETRY_AFTER_ERROR: Duration = Duration::from_secs(300);

fn map_err(e: zbus::Error) -> CoreError {
    if let zbus::Error::MethodError(name, msg, _) = &e {
        let msg = msg.clone().unwrap_or_default();
        if name.as_str().ends_with("PermissionDenied") || name.as_str().ends_with(".AccessDenied") {
            return CoreError::PermissionDenied {
                message: format!(
                    "NetworkManager refused the request ({msg}). Polkit normally allows the user of the active \
                     desktop session; remote or non-graphical sessions may need an administrator."
                ),
            };
        }
        return CoreError::backend(format!("NetworkManager: {msg} ({name})"));
    }
    CoreError::backend(format!("D-Bus: {e}"))
}

fn parse_version(v: &str) -> Option<(u32, u32)> {
    let mut it = v.split('.').map(|p| p.parse::<u32>().ok());
    Some((it.next()??, it.next()??))
}

impl NmBackend {
    /// Connect to NetworkManager and check it can manage WireGuard.
    pub async fn connect() -> Result<Self> {
        let conn = Connection::system()
            .await
            .map_err(|e| CoreError::unsupported(format!("cannot reach the system D-Bus: {e}")))?;
        let nm = Proxy::new(&conn, NM, NM_PATH, NM).await.map_err(map_err)?;
        let version: String = nm.get_property("Version").await.map_err(|_| {
            CoreError::unsupported(
                "NetworkManager is not running. Start it, or use a system that has it",
            )
        })?;
        if parse_version(&version).is_none_or(|v| v < MIN_VERSION) {
            return Err(CoreError::unsupported(format!(
                "NetworkManager {version} is too old; WireGuard support needs 1.16 or newer"
            )));
        }
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .map_err(|_| CoreError::unsupported("cannot determine the current user name"))?;
        let conn_for_events = conn.clone();
        Ok(Self {
            conn,
            user,
            version,
            handshake: std::sync::Mutex::default(),
            events: std::sync::Mutex::new(Some(crate::events::spawn(&conn_for_events))),
        })
    }

    /// Newest peer handshake (unix ms) via the root helper, `None` when it
    /// cannot be read. Never invented: absent means unknown.
    async fn last_handshake(&self, activation: &str, iface: Option<&str>) -> Option<u64> {
        let iface = iface?;
        if !matches!(crate::killswitch::handshake_support(), Support::Supported) {
            return None;
        }
        {
            let c = self.handshake.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(value) = c.cached(activation, iface, std::time::Instant::now()) {
                return value;
            }
        }
        let read = crate::killswitch::run_capture(vec!["handshake".into(), iface.to_owned()]).await;
        let mut c = self.handshake.lock().unwrap_or_else(|p| p.into_inner());
        c.activation = activation.to_owned();
        c.interface = iface.to_owned();
        match read.ok().and_then(|t| t.trim().parse::<u64>().ok()) {
            Some(secs) => {
                c.value_ms = (secs > 0).then_some(secs * 1000);
                c.next_read = Some(std::time::Instant::now() + HANDSHAKE_EVERY);
            }
            None => {
                c.value_ms = None;
                c.next_read = Some(std::time::Instant::now() + HANDSHAKE_RETRY_AFTER_ERROR);
            }
        }
        c.value_ms
    }

    async fn proxy(&self, path: &str, iface: &'static str) -> Result<Proxy<'static>> {
        Proxy::new(&self.conn, NM, path.to_owned(), iface)
            .await
            .map_err(map_err)
    }

    async fn find_connection(&self, id: ProfileId) -> Result<Option<OwnedObjectPath>> {
        let s = self.proxy(SETTINGS_PATH, IF_SETTINGS).await?;
        match s
            .call::<_, _, OwnedObjectPath>("GetConnectionByUuid", &(id.0.to_string(),))
            .await
        {
            Ok(p) => {
                // Same UUID but not created by us (extremely unlikely): refuse to touch it.
                let settings = self.get_settings(p.as_str()).await?;
                if settings::owned_profile(&settings) == Some(id) {
                    Ok(Some(p))
                } else {
                    Err(CoreError::backend(
                        "a NetworkManager connection with this id exists but is not managed by Aegis",
                    ))
                }
            }
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str().ends_with("InvalidConnection") =>
            {
                Ok(None)
            }
            Err(e) => Err(map_err(e)),
        }
    }

    async fn get_settings(&self, path: &str) -> Result<Settings> {
        let c = self.proxy(path, IF_CONN).await?;
        c.call("GetSettings", &()).await.map_err(map_err)
    }

    /// Read one authoritative property snapshot; absent objects are confirmed gone.
    async fn active(&self) -> Result<Vec<(OwnedObjectPath, ProfileId, u32, Vec<OwnedObjectPath>)>> {
        let nm = self.proxy(NM_PATH, NM).await?;
        let paths: Vec<OwnedObjectPath> = nm
            .get_property("ActiveConnections")
            .await
            .map_err(map_err)?;
        let manager = self
            .proxy("/org/freedesktop", "org.freedesktop.DBus.ObjectManager")
            .await?;
        let objects: HashMap<OwnedObjectPath, Settings> = manager
            .call("GetManagedObjects", &())
            .await
            .map_err(map_err)?;
        let mut out = Vec::new();
        for p in paths {
            let Some(properties) = objects.get(&p).and_then(|o| o.get(IF_ACTIVE)) else {
                continue;
            };
            let Some((conn_path, state, devices)) = parse_active(properties)? else {
                continue;
            };
            let settings = self.get_settings(conn_path.as_str()).await?;
            if let Some(id) = settings::owned_profile(&settings) {
                out.push((p, id, state, devices));
            }
        }
        Ok(out)
    }

    async fn wait_active_state(&self, id: ProfileId, want_gone: bool) -> Result<()> {
        loop {
            let ours = self.active().await?;
            let me = ours.iter().find(|a| a.1 == id);
            match (me, want_gone) {
                (None, true) => return Ok(()),
                (None, false) => {
                    return Err(CoreError::backend(
                        "NetworkManager stopped activating the tunnel. Check the endpoint and that the profile is valid; \
                         `journalctl -u NetworkManager` has details.",
                    ));
                }
                (Some(a), false) if a.2 == ACTIVATED => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(250)).await,
            }
        }
    }
}

/// Read interface counters from sysfs (no privileges needed).
fn read_counters(iface: &str) -> (u64, u64) {
    let read = |f: &str| {
        std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{f}"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    (read("rx_bytes"), read("tx_bytes"))
}

impl VpnBackend for NmBackend {
    async fn capabilities(&self) -> Result<Capabilities> {
        Ok(Capabilities {
            backend: BackendKind::NetworkManager,
            simulated: false,
            backend_version: Some(self.version.clone()),
            available: Support::Supported,
            kill_switch: crate::killswitch::support(),
            dns_protection: Support::Supported,
            ipv6_protection: Support::Supported,
            exact_handshake_time: crate::killswitch::handshake_support(),
            notes: vec![
                "Tunnels are NetworkManager connections named \"Aegis: …\"; they keep running if the app is closed."
                    .into(),
                "Private keys are stored by NetworkManager in a root-only file under /etc/NetworkManager/system-connections."
                    .into(),
            ],
        })
    }

    async fn install(&self, id: ProfileId, name: &str, cfg: &WgConfig) -> Result<()> {
        let new = settings::to_settings(id, name, &self.user, cfg);
        if let Some(path) = self.find_connection(id).await? {
            let c = self.proxy(path.as_str(), IF_CONN).await?;
            let args: HashMap<String, OwnedVariant> = HashMap::new();
            // Update2 flags: 0x1 = persist to disk.
            c.call::<_, _, HashMap<String, OwnedVariant>>("Update2", &(new, ADD_TO_DISK, args))
                .await
                .map_err(map_err)?;
        } else {
            let s = self.proxy(SETTINGS_PATH, IF_SETTINGS).await?;
            let args: HashMap<String, OwnedVariant> = HashMap::new();
            s.call::<_, _, (OwnedObjectPath, HashMap<String, OwnedVariant>)>(
                "AddConnection2",
                &(new, ADD_TO_DISK | ADD_BLOCK_AUTOCONNECT, args),
            )
            .await
            .map_err(map_err)?;
        }
        Ok(())
    }

    async fn uninstall(&self, id: ProfileId) -> Result<()> {
        if let Some(path) = self.find_connection(id).await? {
            let c = self.proxy(path.as_str(), IF_CONN).await?;
            c.call::<_, _, ()>("Delete", &()).await.map_err(map_err)?;
        }
        Ok(())
    }

    async fn load(&self, id: ProfileId) -> Result<WgConfig> {
        let path = self.find_connection(id).await?.ok_or(CoreError::NotFound)?;
        let mut s = self.get_settings(path.as_str()).await?;
        let c = self.proxy(path.as_str(), IF_CONN).await?;
        let secrets: Settings = c
            .call("GetSecrets", &("wireguard",))
            .await
            .map_err(map_err)?;
        settings::merge_secrets(&mut s, secrets);
        settings::from_settings(&s)
    }

    async fn installed(&self) -> Result<Vec<ProfileId>> {
        let s = self.proxy(SETTINGS_PATH, IF_SETTINGS).await?;
        let paths: Vec<OwnedObjectPath> = s.call("ListConnections", &()).await.map_err(map_err)?;
        let mut out = Vec::new();
        for p in paths {
            // Connections of other users are not visible to us; errors mean "not ours".
            if let Ok(settings) = self.get_settings(p.as_str()).await
                && let Some(id) = settings::owned_profile(&settings)
            {
                out.push(id);
            }
        }
        Ok(out)
    }

    async fn activate(&self, id: ProfileId) -> Result<()> {
        let mut path = self.find_connection(id).await?.ok_or(CoreError::NotFound)?;
        let current = self.get_settings(path.as_str()).await?;
        if settings::lacks_ipv6_block(&current) {
            // Installed by an older version: re-install so IPv6 gets blocked.
            let name = settings::profile_name(&current);
            let cfg = self.load(id).await?;
            self.install(id, &name, &cfg).await?;
            path = self.find_connection(id).await?.ok_or(CoreError::NotFound)?;
        }
        let nm = self.proxy(NM_PATH, NM).await?;
        let root = OwnedObjectPath::try_from("/").expect("static path");
        nm.call::<_, _, OwnedObjectPath>("ActivateConnection", &(path, root.clone(), root))
            .await
            .map_err(map_err)?;
        self.wait_active_state(id, false).await
    }

    async fn deactivate(&self, id: ProfileId) -> Result<()> {
        let Some((active, ..)) = self.active().await?.into_iter().find(|a| a.1 == id) else {
            return Ok(());
        };
        let nm = self.proxy(NM_PATH, NM).await?;
        match nm
            .call::<_, _, ()>("DeactivateConnection", &(active,))
            .await
        {
            Ok(()) => {}
            // Already going away.
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str().ends_with("ConnectionNotActive") => {}
            Err(e) => return Err(map_err(e)),
        }
        tokio::time::timeout(Duration::from_secs(15), self.wait_active_state(id, true))
            .await
            .map_err(|_| CoreError::Timeout {
                what: "the tunnel did not go down".into(),
                seconds: 15,
            })?
    }

    async fn status(&self) -> Result<Option<TunnelStatus>> {
        let Some((activation, id, state, devices)) = self.active().await?.into_iter().next() else {
            return Ok(None);
        };
        let mut interface = None;
        if let Some(dev) = devices.first() {
            let d = self.proxy(dev.as_str(), IF_DEVICE).await?;
            interface = Some(
                d.get_property::<String>("Interface")
                    .await
                    .map_err(map_err)?,
            );
        }
        let (rx_bytes, tx_bytes) = interface.as_deref().map(read_counters).unwrap_or((0, 0));
        let last_handshake_ms = if state == ACTIVATED {
            self.last_handshake(activation.as_str(), interface.as_deref())
                .await
        } else {
            None
        };
        let link = match state {
            ACTIVATING => LinkState::Activating,
            ACTIVATED => LinkState::Up,
            DEACTIVATING => LinkState::Deactivating,
            _ => LinkState::Down,
        };
        Ok(Some(TunnelStatus {
            id,
            link,
            interface,
            rx_bytes,
            tx_bytes,
            last_handshake_ms,
        }))
    }

    fn protection(&self, profile: &ProfileSummary, settings: &AppSettings) -> Protection {
        profile_protection(profile, settings)
    }

    fn system_events(&self) -> Option<tokio::sync::mpsc::Receiver<aegis_core::SystemEvent>> {
        self.events.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    async fn apply_kill_switch(
        &self,
        id: ProfileId,
        endpoints: &[std::net::SocketAddr],
        allow_lan: bool,
    ) -> Result<()> {
        let mut args = vec!["apply".to_owned(), settings::iface_name(id)];
        if allow_lan {
            args.push("--allow-lan".into());
        }
        args.extend(endpoints.iter().map(ToString::to_string));
        crate::killswitch::run(args).await
    }

    async fn remove_kill_switch(&self) -> Result<()> {
        crate::killswitch::run(vec!["remove".into()]).await
    }

    async fn kill_switch_active(&self) -> Result<bool> {
        crate::killswitch::active().await
    }

    async fn check_reachability(&self, profile: &ProfileSummary, status: &TunnelStatus) -> Feature {
        let Some((server, iface, source)) = tunnel_dns(profile, status) else {
            return Feature::Unsupported("the profile has no DNS server inside the tunnel".into());
        };
        let rcode = tokio::task::spawn_blocking(move || verify::lookup(server, &iface, source))
            .await
            .unwrap_or(None);
        verify::judge_reachability(rcode)
    }

    async fn check_public_ip(&self, profile: &ProfileSummary, status: &TunnelStatus) -> Feature {
        let Some((server, iface, source)) = tunnel_dns(profile, status) else {
            return Feature::Unsupported("the profile has no DNS server inside the tunnel".into());
        };
        let addrs =
            tokio::task::spawn_blocking(move || verify::lookup_public_ip(server, &iface, source))
                .await
                .unwrap_or(None);
        verify::judge_public_ip(addrs)
    }

    async fn verify_protection(
        &self,
        profile: &ProfileSummary,
        settings: &AppSettings,
        status: &TunnelStatus,
    ) -> Protection {
        let mut p = profile_protection(profile, settings);
        let addrs: Vec<std::net::IpAddr> = profile
            .addresses
            .iter()
            .filter_map(|a| a.parse::<ipnet::IpNet>().ok())
            .map(|a| a.addr())
            .collect();
        // Only upgrade what is configured; Off/Failed from the profile itself stay.
        if matches!(p.ipv6, Feature::Configured(_)) {
            let default = std::fs::read_to_string("/proc/net/ipv6_route")
                .ok()
                .and_then(|t| verify::ipv6_default_route(&t));
            p.ipv6 = verify::judge_ipv6(
                profile.route_kind,
                verify::probe(verify::PUBLIC_V6, &addrs),
                default.as_ref(),
                status.interface.as_deref(),
            );
        }
        if matches!(p.dns, Feature::Configured(_)) {
            let servers: Vec<_> = profile
                .dns
                .iter()
                .filter_map(|d| d.parse::<std::net::IpAddr>().ok())
                .map(|d| (d, verify::probe(d, &addrs)))
                .collect();
            let ifindex = status.interface.as_deref().and_then(|i| {
                std::fs::read_to_string(format!("/sys/class/net/{i}/ifindex"))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()
            });
            p.dns = verify::judge_dns(&servers, &self.resolver().await, ifindex);
        }
        p
    }
}

impl NmBackend {
    /// Read the resolver configuration (no privileges needed).
    async fn resolver(&self) -> Resolver {
        let text = match std::fs::read_to_string("/etc/resolv.conf") {
            Ok(t) => t,
            Err(e) => return Resolver::Unknown(format!("cannot read /etc/resolv.conf: {e}")),
        };
        if let Some(ns) = verify::parse_resolv_conf(&text) {
            return Resolver::Plain(ns);
        }
        let resolver = async {
            let proxy = Proxy::new(
                &self.conn,
                "org.freedesktop.resolve1",
                "/org/freedesktop/resolve1",
                "org.freedesktop.resolve1.Manager",
            )
            .await?;
            let (domains, dns) = tokio::try_join!(
                proxy.get_property::<Vec<(i32, String, bool)>>("Domains"),
                proxy.get_property::<Vec<(i32, i32, Vec<u8>)>>("DNS"),
            )?;
            Ok::<_, zbus::Error>(Resolver::Resolved { domains, dns })
        };
        match tokio::time::timeout(Duration::from_secs(2), resolver).await {
            Ok(Ok(resolver)) => resolver,
            Ok(Err(e)) => Resolver::Unknown(format!("systemd-resolved did not answer: {e}")),
            Err(_) => Resolver::Unknown("systemd-resolved did not answer in time".into()),
        }
    }
}

/// IPv4-only full tunnels route `::/0` into the tunnel, which drops it (see `settings::to_settings`).
const BLOCKED_V6: &str = "the profile has no IPv6, so IPv6 is sent into the tunnel and dropped while connected; not yet verified";

fn parse_active(
    p: &settings::Section,
) -> Result<Option<(OwnedObjectPath, u32, Vec<OwnedObjectPath>)>> {
    let invalid =
        || CoreError::backend("NetworkManager returned incomplete active-connection properties");
    let field = |key: &str| p.get(key).ok_or_else(invalid);
    let kind = <&str>::try_from(field("Type")?).map_err(|_| invalid())?;
    if kind != "wireguard" {
        return Ok(None);
    }
    let path = OwnedObjectPath::try_from(field("Connection")?.try_clone().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let state = u32::try_from(field("State")?).map_err(|_| invalid())?;
    let devices =
        Vec::<OwnedObjectPath>::try_from(field("Devices")?.try_clone().map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    Ok(Some((path, state, devices)))
}

/// DNS server that the kernel would reach through this tunnel's addresses.
fn tunnel_dns(
    profile: &ProfileSummary,
    status: &TunnelStatus,
) -> Option<(std::net::IpAddr, String, std::net::IpAddr)> {
    let iface = status.interface.as_ref()?;
    if iface != &settings::iface_name(status.id) {
        return None;
    }
    let addrs: Vec<std::net::IpAddr> = profile
        .addresses
        .iter()
        .filter_map(|a| a.parse::<ipnet::IpNet>().ok())
        .map(|a| a.addr())
        .collect();
    profile
        .dns
        .iter()
        .filter_map(|d| d.parse::<std::net::IpAddr>().ok())
        .find_map(|d| {
            if verify::probe(d, &addrs) != verify::RouteProbe::Tunnel {
                return None;
            }
            let source = addrs.iter().copied().find(|a| a.is_ipv6() == d.is_ipv6())?;
            Some((d, iface.clone(), source))
        })
}

fn profile_protection(profile: &ProfileSummary, settings: &AppSettings) -> Protection {
    let has_family = |v6| {
        profile
            .addresses
            .iter()
            .filter_map(|a| a.parse::<ipnet::IpNet>().ok())
            .any(|a| a.addr().is_ipv6() == v6)
    };
    let has_dns = profile
        .dns
        .iter()
        .filter_map(|d| d.parse::<std::net::IpAddr>().ok())
        .any(|d| {
            has_family(d.is_ipv6())
                && if d.is_ipv6() {
                    matches!(
                        profile.route_kind,
                        RouteKind::Full | RouteKind::FullIpv6Only
                    )
                } else {
                    matches!(
                        profile.route_kind,
                        RouteKind::Full | RouteKind::FullIpv4Only
                    )
                }
        });
    // The engine reports the kill switch from what is actually installed.
    let _ = settings;
    let kill_switch = Feature::Off;
    let (dns, ipv6) = match profile.route_kind {
        RouteKind::Full => (
            if has_dns {
                Feature::Configured(
                    "Tunnel DNS configured with priority -50 and ~.; resolver selection not independently verified"
                        .into(),
                )
            } else {
                Feature::Failed(
                    "the profile has no DNS servers, so lookups use your local network".into(),
                )
            },
            if has_family(true) {
                Feature::Configured(
                    "IPv6 default route configured on the tunnel; not independently verified"
                        .into(),
                )
            } else {
                Feature::Configured(BLOCKED_V6.into())
            },
        ),
        RouteKind::FullIpv4Only => (
            if has_dns {
                Feature::Configured("IPv4 tunnel DNS configured with priority -50 and ~.; resolver selection not independently verified".into())
            } else {
                Feature::Failed("the profile has no DNS servers".into())
            },
            Feature::Configured(BLOCKED_V6.into()),
        ),
        RouteKind::FullIpv6Only | RouteKind::Split => (Feature::Off, Feature::Off),
    };
    Protection {
        kill_switch,
        dns,
        ipv6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_cache_is_scoped_to_one_activation() {
        let now = std::time::Instant::now();
        let cache = HandshakeCache {
            activation: "/ActiveConnection/1".into(),
            interface: "aegis-11111111".into(),
            value_ms: Some(1000),
            next_read: Some(now + HANDSHAKE_EVERY),
        };
        assert_eq!(
            cache.cached("/ActiveConnection/1", "aegis-11111111", now),
            Some(Some(1000))
        );
        assert_eq!(
            cache.cached("/ActiveConnection/2", "aegis-11111111", now),
            None
        );
        assert_eq!(
            cache.cached(
                "/ActiveConnection/1",
                "aegis-11111111",
                now + HANDSHAKE_EVERY
            ),
            None
        );
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("1.58.1"), Some((1, 58)));
        assert!(parse_version("1.14.0").unwrap() < MIN_VERSION);
        assert_eq!(parse_version("garbage"), None);
    }

    #[test]
    fn incomplete_active_properties_are_errors_not_absence() {
        let mut p = settings::Section::new();
        p.insert(
            "Type".into(),
            OwnedVariant::try_from(zbus::Variant::from("wireguard")).unwrap(),
        );
        assert!(parse_active(&p).is_err());
        p.insert(
            "Type".into(),
            OwnedVariant::try_from(zbus::Variant::from("ethernet")).unwrap(),
        );
        assert!(parse_active(&p).unwrap().is_none());
        p.insert("Type".into(), OwnedVariant::from(17_u32));
        assert!(parse_active(&p).is_err());
    }

    #[test]
    fn protection_requires_enabled_address_family_and_dns_servers() {
        let mut cfg = aegis_config::parse(include_str!(
            "../../../tests/fixtures/valid/full-tunnel.conf"
        ))
        .unwrap();
        cfg.interface.addresses.retain(|a| a.addr().is_ipv4());
        cfg.interface.dns = vec!["fd99::1".parse().unwrap()];
        let p = profile_protection(&ProfileSummary::from_config(&cfg), &AppSettings::default());
        assert!(
            matches!(p.ipv6, Feature::Configured(ref d) if d == BLOCKED_V6),
            "{p:?}"
        );
        assert!(matches!(p.dns, Feature::Failed(_)), "{p:?}");

        cfg.interface.dns.clear();
        cfg.interface.dns_search = vec!["corp.example".into()];
        let p = profile_protection(&ProfileSummary::from_config(&cfg), &AppSettings::default());
        assert!(matches!(p.dns, Feature::Failed(_)), "{p:?}");

        cfg.interface.dns = vec!["10.0.0.1".parse().unwrap()];
        let p = profile_protection(&ProfileSummary::from_config(&cfg), &AppSettings::default());
        assert!(matches!(p.dns, Feature::Configured(_)), "{p:?}");
    }

    #[test]
    fn ipv6_dns_is_not_exclusive_when_only_ipv4_has_a_default_route() {
        let mut cfg = aegis_config::parse(include_str!(
            "../../../tests/fixtures/valid/full-tunnel.conf"
        ))
        .unwrap();
        cfg.peers[0].allowed_ips.retain(|a| a.addr().is_ipv4());
        cfg.interface.dns.retain(|d| d.is_ipv6());
        let p = profile_protection(&ProfileSummary::from_config(&cfg), &AppSettings::default());
        assert!(matches!(p.dns, Feature::Failed(_)), "{p:?}");
    }
}
