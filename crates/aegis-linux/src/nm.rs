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
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{Connection, Proxy};

use crate::settings::{self, Settings};

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
}

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
        Ok(Self {
            conn,
            user,
            version,
        })
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

    /// Active connections that are ours: (active path, profile, state, device paths).
    async fn active(&self) -> Result<Vec<(OwnedObjectPath, ProfileId, u32, Vec<OwnedObjectPath>)>> {
        let nm = self.proxy(NM_PATH, NM).await?;
        let paths: Vec<OwnedObjectPath> = nm
            .get_property("ActiveConnections")
            .await
            .map_err(map_err)?;
        let mut out = Vec::new();
        for p in paths {
            let Ok(a) = self.proxy(p.as_str(), IF_ACTIVE).await else {
                continue;
            };
            // Objects can vanish between listing and reading; skip those.
            let Ok(kind) = a.get_property::<String>("Type").await else {
                continue;
            };
            if kind != "wireguard" {
                continue;
            }
            let Ok(conn_path) = a.get_property::<OwnedObjectPath>("Connection").await else {
                continue;
            };
            let Ok(s) = self.get_settings(conn_path.as_str()).await else {
                continue;
            };
            let Some(id) = settings::owned_profile(&s) else {
                continue;
            };
            let state: u32 = a.get_property("State").await.unwrap_or(0);
            let devices: Vec<OwnedObjectPath> = a.get_property("Devices").await.unwrap_or_default();
            out.push((p, id, state, devices));
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
            kill_switch: Support::Unsupported(
                "needs the Aegis firewall helper, which is not installed in this version".into(),
            ),
            dns_protection: Support::Supported,
            ipv6_protection: Support::Supported,
            exact_handshake_time: Support::Unsupported(
                "reading WireGuard handshake times requires root; Aegis infers a server response from received data"
                    .into(),
            ),
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
            let args: HashMap<String, OwnedValue> = HashMap::new();
            // Update2 flags: 0x1 = persist to disk.
            c.call::<_, _, HashMap<String, OwnedValue>>("Update2", &(new, ADD_TO_DISK, args))
                .await
                .map_err(map_err)?;
        } else {
            let s = self.proxy(SETTINGS_PATH, IF_SETTINGS).await?;
            let args: HashMap<String, OwnedValue> = HashMap::new();
            s.call::<_, _, (OwnedObjectPath, HashMap<String, OwnedValue>)>(
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
        let path = self.find_connection(id).await?.ok_or(CoreError::NotFound)?;
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
        let Some((_, id, state, devices)) = self.active().await?.into_iter().next() else {
            return Ok(None);
        };
        let mut interface = None;
        if let Some(dev) = devices.first()
            && let Ok(d) = self.proxy(dev.as_str(), IF_DEVICE).await
        {
            interface = d.get_property::<String>("Interface").await.ok();
        }
        let (rx_bytes, tx_bytes) = interface.as_deref().map(read_counters).unwrap_or((0, 0));
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
            last_handshake_ms: None,
        }))
    }

    fn protection(&self, profile: &ProfileSummary, settings: &AppSettings) -> Protection {
        let has_dns = !profile.dns.is_empty();
        let kill_switch = if settings.kill_switch {
            Feature::Unsupported("the firewall helper is not installed".into())
        } else {
            Feature::Off
        };
        let (dns, ipv6) = match profile.route_kind {
            RouteKind::Full => {
                (
                    if has_dns {
                        Feature::Configured("NetworkManager sends all DNS to this tunnel's servers (priority -50, ~.)".into())
                    } else {
                        Feature::Failed(
                            "the profile has no DNS servers, so lookups use your local network"
                                .into(),
                        )
                    },
                    Feature::Configured("IPv6 default route goes through the tunnel".into()),
                )
            }
            RouteKind::FullIpv4Only => (
                if has_dns {
                    Feature::Configured(
                        "NetworkManager sends all DNS to this tunnel's servers".into(),
                    )
                } else {
                    Feature::Failed("the profile has no DNS servers".into())
                },
                Feature::Failed(
                    "the profile does not route IPv6; IPv6 traffic bypasses the tunnel".into(),
                ),
            ),
            RouteKind::FullIpv6Only | RouteKind::Split => (Feature::Off, Feature::Off),
        };
        Protection {
            kill_switch,
            dns,
            ipv6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("1.58.1"), Some((1, 58)));
        assert!(parse_version("1.14.0").unwrap() < MIN_VERSION);
        assert_eq!(parse_version("garbage"), None);
    }
}
