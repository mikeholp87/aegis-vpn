//! Pure conversion between [`WgConfig`] and NetworkManager connection
//! settings (`a{sa{sv}}`). No D-Bus I/O here, so it is fully unit-tested.
//!
//! Reference: NetworkManager "settings-wireguard", "settings-ipv4/ipv6",
//! "settings-connection" documentation (NM >= 1.16). D-Bus types come from zbus 6 (`Variant`, `OwnedVariant`; the former zvariant crate).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aegis_config::{Endpoint, Interface, Peer, RouteKind, WgConfig};
use aegis_core::{CoreError, ProfileId, Result};
use ipnet::IpNet;
use zbus::{OwnedVariant, Variant};

pub type Section = HashMap<String, OwnedVariant>;
pub type Settings = HashMap<String, Section>;

/// Interface names of tunnels we own start with this; it is also how
/// `installed()` recognises our connections. Max interface name length is 15.
pub const IFACE_PREFIX: &str = "aegis-";
/// NetworkManager secret flag: secret stored by NM itself (root-only keyfile).
const SECRET_FLAG_NONE: u32 = 0;
/// Negative priority: only this connection's DNS servers are used while it is
/// active (prevents DNS queries leaking to other interfaces' resolvers).
pub const EXCLUSIVE_DNS_PRIORITY: i32 = -50;
/// Metric of the unreachable `::/0` route that blocks IPv6 on IPv4-only full
/// tunnels. Lower than any uplink default route (NM uses 100+), so it wins.
pub const IPV6_BLOCK_METRIC: u32 = 1;

pub fn iface_name(id: ProfileId) -> String {
    format!("{IFACE_PREFIX}{}", &id.0.simple().to_string()[..8])
}

fn ov<'a>(v: impl Into<Variant<'a>>) -> OwnedVariant {
    OwnedVariant::try_from(v.into()).expect("values without file descriptors always convert")
}

fn section(items: Vec<(&str, OwnedVariant)>) -> Section {
    items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

fn address_data(nets: &[&IpNet]) -> Vec<HashMap<String, OwnedVariant>> {
    nets.iter()
        .map(|n| {
            HashMap::from([
                ("address".to_owned(), ov(n.addr().to_string())),
                ("prefix".to_owned(), ov(u32::from(n.prefix_len()))),
            ])
        })
        .collect()
}

/// `unreachable ::/0` with a metric below any uplink default route.
fn ipv6_block_route() -> OwnedVariant {
    ov(vec![HashMap::from([
        ("dest".to_owned(), ov("::")),
        ("prefix".to_owned(), ov(0u32)),
        ("metric".to_owned(), ov(IPV6_BLOCK_METRIC)),
        ("type".to_owned(), ov("unreachable")),
    ])])
}

/// Profile name stored in `connection.id` ("Aegis: <name>").
pub fn profile_name(s: &Settings) -> String {
    let id = get_str(s, "connection", "id").unwrap_or_default();
    id.strip_prefix("Aegis: ").unwrap_or(&id).to_owned()
}

/// Build NetworkManager settings, including secrets, for a profile.
// shortcut: zbus serialization buffers cannot be wiped here; revisit when it supports secret-aware storage.
pub fn to_settings(id: ProfileId, name: &str, user: &str, cfg: &WgConfig) -> Settings {
    let i = &cfg.interface;
    let route = cfg.route_kind();
    let full_v4 = matches!(route, RouteKind::Full | RouteKind::FullIpv4Only);
    let full_v6 = matches!(route, RouteKind::Full | RouteKind::FullIpv6Only);

    let mut conn = section(vec![
        ("id", ov(format!("Aegis: {name}"))),
        ("uuid", ov(id.0.to_string())),
        ("type", ov("wireguard")),
        ("interface-name", ov(iface_name(id))),
        // The app decides when to connect; NM must not bring it up on its own.
        ("autoconnect", ov(false)),
        // Private to this user: other local users cannot see or use it.
        ("permissions", ov(vec![format!("user:{user}")])),
    ]);
    conn.insert("zone".into(), ov("")); // leave firewalld zone untouched

    let peers: Vec<HashMap<String, OwnedVariant>> = cfg
        .peers
        .iter()
        .map(|p| {
            let mut m = HashMap::from([
                ("public-key".to_owned(), ov(p.public_key.to_string())),
                (
                    "allowed-ips".to_owned(),
                    ov(p.allowed_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()),
                ),
            ]);
            if let Some(e) = &p.endpoint {
                m.insert("endpoint".into(), ov(e.to_string()));
            }
            if let Some(k) = p.persistent_keepalive {
                m.insert("persistent-keepalive".into(), ov(u32::from(k)));
            }
            if let Some(psk) = &p.preshared_key {
                m.insert(
                    "preshared-key".into(),
                    ov(psk.expose_base64().as_str().to_owned()),
                );
                m.insert("preshared-key-flags".into(), ov(SECRET_FLAG_NONE));
            }
            m
        })
        .collect();
    let mut wg = section(vec![
        (
            "private-key",
            ov(i.private_key.expose_base64().as_str().to_owned()),
        ),
        ("private-key-flags", ov(SECRET_FLAG_NONE)),
        ("peers", ov(peers)),
    ]);
    if let Some(m) = i.mtu {
        wg.insert("mtu".into(), ov(u32::from(m)));
    }
    if let Some(p) = i.listen_port {
        wg.insert("listen-port".into(), ov(u32::from(p)));
    }

    let v4: Vec<&IpNet> = i
        .addresses
        .iter()
        .filter(|a| matches!(a, IpNet::V4(_)))
        .collect();
    let v6: Vec<&IpNet> = i
        .addresses
        .iter()
        .filter(|a| matches!(a, IpNet::V6(_)))
        .collect();
    let dns4: Vec<u32> = i
        .dns
        .iter()
        .filter_map(|d| match d {
            // NM wants IPv4 DNS as u32 in network byte order.
            IpAddr::V4(a) => Some(u32::from_ne_bytes(a.octets())),
            IpAddr::V6(_) => None,
        })
        .collect();
    let dns6: Vec<Vec<u8>> = i
        .dns
        .iter()
        .filter_map(|d| match d {
            IpAddr::V6(a) => Some(a.octets().to_vec()),
            IpAddr::V4(_) => None,
        })
        .collect();

    let ip_section = |nets: &[&IpNet], full: bool, has_dns: bool, dns: OwnedVariant| -> Section {
        if nets.is_empty() {
            // Without an address of this family NM must not configure it. For a
            // full tunnel this would leak, which the profile warnings report.
            return section(vec![("method", ov("disabled"))]);
        }
        let mut s = section(vec![
            ("method", ov("manual")),
            ("address-data", ov(address_data(nets))),
        ]);
        if has_dns {
            s.insert("dns".into(), dns);
            s.insert("ignore-auto-dns".into(), ov(true));
        }
        let mut search = i.dns_search.clone();
        if full && has_dns {
            // Route every DNS domain to this tunnel (systemd-resolved) and
            // make its servers exclusive.
            search.push("~.".into());
            s.insert("dns-priority".into(), ov(EXCLUSIVE_DNS_PRIORITY));
        }
        if !search.is_empty() {
            s.insert("dns-search".into(), ov(search));
        }
        s
    };
    let ipv4 = ip_section(&v4, full_v4, !dns4.is_empty(), ov(dns4.clone()));
    // IPv6 is blocked whenever IPv4 is a full tunnel and IPv6 is not carried.
    let block_v6 = full_v4 && (!full_v6 || v6.is_empty());
    let ipv6 = if !block_v6 {
        ip_section(&v6, full_v6, !dns6.is_empty(), ov(dns6))
    } else {
        // IPv4 full tunnel that does not carry IPv6: block IPv6 with an
        // unreachable default route instead of letting it leave through the
        // local network. NM removes the route on disconnect. Verified on
        // NM 1.52: `manual` with no address accepts a routes-only section.
        // IPv6 DNS servers are kept so export stays faithful; queries to them
        // cannot leave while the block is in place.
        let has_dns = !dns6.is_empty();
        let mut s = if v6.is_empty() {
            let mut s = section(vec![("method", ov("manual"))]);
            if has_dns {
                s.insert("dns".into(), ov(dns6));
                s.insert("ignore-auto-dns".into(), ov(true));
            }
            s
        } else {
            ip_section(&v6, false, has_dns, ov(dns6))
        };
        s.insert("route-data".into(), ipv6_block_route());
        s
    };

    HashMap::from([
        ("connection".to_owned(), conn),
        ("wireguard".to_owned(), wg),
        ("ipv4".to_owned(), ipv4),
        ("ipv6".to_owned(), ipv6),
    ])
}

fn get<'a>(s: &'a Settings, sec: &str, key: &str) -> Option<&'a OwnedVariant> {
    s.get(sec)?.get(key)
}

fn get_str(s: &Settings, sec: &str, key: &str) -> Option<String> {
    get(s, sec, key).and_then(|v| String::try_from(v.try_clone().ok()?).ok())
}

fn bad(what: &str) -> CoreError {
    CoreError::backend(format!(
        "NetworkManager returned an unexpected value for {what}"
    ))
}

fn str_of(m: &HashMap<String, OwnedVariant>, key: &str) -> Option<String> {
    m.get(key)
        .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
}

fn u32_of(m: &HashMap<String, OwnedVariant>, key: &str) -> Option<u32> {
    m.get(key).and_then(|v| u32::try_from(v).ok())
}

fn maps(v: &OwnedVariant) -> Option<Vec<HashMap<String, OwnedVariant>>> {
    Vec::<HashMap<String, OwnedVariant>>::try_from(v.try_clone().ok()?).ok()
}

/// Rebuild a [`WgConfig`] from NM settings merged with secrets.
pub fn from_settings(s: &Settings) -> Result<WgConfig> {
    let private_key = get(s, "wireguard", "private-key").and_then(|v| <&str>::try_from(v).ok())
        .ok_or_else(|| {
            CoreError::backend("the private key is missing from NetworkManager (secret not readable); re-import the profile")
        })?
        .parse()
        .map_err(|_| bad("wireguard.private-key"))?;

    let mut addresses = Vec::new();
    let mut dns: Vec<IpAddr> = Vec::new();
    let mut dns_search: Vec<String> = Vec::new();
    for fam in ["ipv4", "ipv6"] {
        if let Some(list) = get(s, fam, "address-data").and_then(maps) {
            for m in list {
                let a: IpAddr = str_of(&m, "address")
                    .and_then(|a| a.parse().ok())
                    .ok_or_else(|| bad("address"))?;
                let p = u32_of(&m, "prefix").ok_or_else(|| bad("prefix"))? as u8;
                addresses.push(IpNet::new(a, p).map_err(|_| bad("prefix"))?);
            }
        }
        if let Some(search) = get(s, fam, "dns-search")
            .and_then(|v| Vec::<String>::try_from(v.try_clone().ok()?).ok())
        {
            for d in search.into_iter().filter(|d| d != "~.") {
                if !dns_search.contains(&d) {
                    dns_search.push(d);
                }
            }
        }
    }
    if let Some(v) =
        get(s, "ipv4", "dns").and_then(|v| Vec::<u32>::try_from(v.try_clone().ok()?).ok())
    {
        dns.extend(
            v.into_iter()
                .map(|n| IpAddr::V4(Ipv4Addr::from(n.to_ne_bytes()))),
        );
    }
    if let Some(v) =
        get(s, "ipv6", "dns").and_then(|v| Vec::<Vec<u8>>::try_from(v.try_clone().ok()?).ok())
    {
        for b in v {
            let arr: [u8; 16] = b.try_into().map_err(|_| bad("ipv6.dns"))?;
            dns.push(IpAddr::V6(Ipv6Addr::from(arr)));
        }
    }

    let mut peers = Vec::new();
    for m in get(s, "wireguard", "peers")
        .and_then(maps)
        .unwrap_or_default()
    {
        let public_key = str_of(&m, "public-key")
            .and_then(|k| k.parse().ok())
            .ok_or_else(|| bad("peer public-key"))?;
        let allowed_ips = m
            .get("allowed-ips")
            .and_then(|v| Vec::<String>::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default()
            .iter()
            .map(|a| a.parse::<IpNet>().map_err(|_| bad("allowed-ips")))
            .collect::<Result<Vec<_>>>()?;
        let endpoint = match str_of(&m, "endpoint") {
            Some(e) => Some(e.parse::<Endpoint>().map_err(|_| bad("endpoint"))?),
            None => None,
        };
        let preshared_key = match m
            .get("preshared-key")
            .and_then(|v| <&str>::try_from(v).ok())
        {
            Some(k) if !k.is_empty() => Some(k.parse().map_err(|_| bad("preshared-key"))?),
            _ => None,
        };
        peers.push(Peer {
            public_key,
            preshared_key,
            endpoint,
            allowed_ips,
            persistent_keepalive: u32_of(&m, "persistent-keepalive")
                .filter(|k| *k > 0)
                .map(|k| k as u16),
        });
    }

    let num = |key: &str| {
        get(s, "wireguard", key)
            .and_then(|v| u32::try_from(v).ok())
            .filter(|n| *n > 0)
    };
    Ok(WgConfig {
        interface: Interface {
            private_key,
            addresses,
            dns,
            dns_search,
            mtu: num("mtu").map(|n| n as u16),
            listen_port: num("listen-port").map(|n| n as u16),
        },
        peers,
    })
}

/// Merge a `GetSecrets("wireguard")` reply into settings from `GetSettings()`.
/// Peers in the secrets reply are matched by public key.
pub fn merge_secrets(settings: &mut Settings, secrets: Settings) {
    let Some(sec_wg) = secrets.get("wireguard") else {
        return;
    };
    let Some(wg) = settings.get_mut("wireguard") else {
        return;
    };
    if let Some(k) = sec_wg.get("private-key").and_then(|v| v.try_clone().ok()) {
        wg.insert("private-key".into(), k);
    }
    let (Some(sec_peers), Some(peers)) = (
        sec_wg.get("peers").and_then(maps),
        wg.get("peers").and_then(maps),
    ) else {
        return;
    };
    let merged: Vec<HashMap<String, OwnedVariant>> = peers
        .into_iter()
        .map(|mut p| {
            let pk = str_of(&p, "public-key");
            if let Some(sp) = sec_peers.iter().find(|sp| str_of(sp, "public-key") == pk)
                && let Some(psk) = sp.get("preshared-key").and_then(|v| v.try_clone().ok())
            {
                p.insert("preshared-key".into(), psk);
            }
            p
        })
        .collect();
    wg.insert("peers".into(), ov(merged));
}

/// True for connections installed before IPv6 blocking existed: an IPv4 full
/// tunnel whose IPv6 is simply disabled (so it leaks). Re-installing fixes it.
pub fn lacks_ipv6_block(s: &Settings) -> bool {
    let routes = |net: &str| {
        get(s, "wireguard", "peers")
            .and_then(maps)
            .unwrap_or_default()
            .iter()
            .any(|p| {
                p.get("allowed-ips")
                    .and_then(|v| Vec::<String>::try_from(v.try_clone().ok()?).ok())
                    .is_some_and(|a| a.iter().any(|x| x == net))
            })
    };
    let has_v6_addr = get(s, "ipv6", "address-data")
        .and_then(maps)
        .is_some_and(|a| !a.is_empty());
    let blocked = get(s, "ipv6", "route-data")
        .and_then(maps)
        .is_some_and(|r| {
            r.iter().any(|m| {
                str_of(m, "type").as_deref() == Some("unreachable")
                    && u32_of(m, "prefix") == Some(0)
            })
        });
    routes("0.0.0.0/0") && !(routes("::/0") && has_v6_addr) && !blocked
}

/// Our profile id if these settings describe a tunnel this app manages.
pub fn owned_profile(s: &Settings) -> Option<ProfileId> {
    if get_str(s, "connection", "type").as_deref() != Some("wireguard") {
        return None;
    }
    let id = ProfileId(get_str(s, "connection", "uuid")?.parse().ok()?);
    (get_str(s, "connection", "interface-name")? == iface_name(id)).then_some(id)
}

/// Remove secrets, for comparing or logging settings.
pub fn without_secrets(mut s: Settings) -> Settings {
    if let Some(wg) = s.get_mut("wireguard") {
        wg.remove("private-key");
        if let Some(peers) = wg.get("peers").and_then(maps) {
            let cleaned: Vec<_> = peers
                .into_iter()
                .map(|mut p| {
                    p.remove("preshared-key");
                    p
                })
                .collect();
            wg.insert("peers".into(), ov(cleaned));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = include_str!("../../../tests/fixtures/valid/full-tunnel.conf");
    const SPLIT: &str = include_str!("../../../tests/fixtures/valid/split.conf");

    fn id() -> ProfileId {
        ProfileId("0b1e8a3c-1111-4222-8333-944455556666".parse().unwrap())
    }

    #[test]
    fn roundtrips_full_and_split() {
        for text in [FULL, SPLIT] {
            let cfg = aegis_config::parse(text).unwrap();
            let s = to_settings(id(), "Work", "alice", &cfg);
            assert_eq!(from_settings(&s).unwrap(), cfg);
        }
    }

    #[test]
    fn owned_by_us_private_and_manual_start() {
        let cfg = aegis_config::parse(FULL).unwrap();
        let s = to_settings(id(), "Work", "alice", &cfg);
        assert_eq!(owned_profile(&s), Some(id()));
        assert_eq!(
            get_str(&s, "connection", "interface-name").unwrap(),
            "aegis-0b1e8a3c"
        );
        assert!(iface_name(id()).len() <= 15);
        let perms = Vec::<String>::try_from(
            get(&s, "connection", "permissions")
                .unwrap()
                .try_clone()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(perms, vec!["user:alice"]);
        assert!(!bool::try_from(get(&s, "connection", "autoconnect").unwrap()).unwrap());
    }

    #[test]
    fn full_tunnel_gets_exclusive_dns() {
        let s = to_settings(id(), "Work", "alice", &aegis_config::parse(FULL).unwrap());
        for fam in ["ipv4", "ipv6"] {
            assert_eq!(
                i32::try_from(get(&s, fam, "dns-priority").unwrap()).unwrap(),
                EXCLUSIVE_DNS_PRIORITY
            );
            let search =
                Vec::<String>::try_from(get(&s, fam, "dns-search").unwrap().try_clone().unwrap())
                    .unwrap();
            assert!(search.contains(&"~.".to_string()), "{fam}");
        }
    }

    #[test]
    fn split_tunnel_does_not_hijack_dns_or_ipv6() {
        let s = to_settings(id(), "Lab", "alice", &aegis_config::parse(SPLIT).unwrap());
        assert!(get(&s, "ipv4", "dns-priority").is_none());
        let search =
            Vec::<String>::try_from(get(&s, "ipv4", "dns-search").unwrap().try_clone().unwrap())
                .unwrap();
        assert_eq!(search, vec!["corp.example"]);
        assert_eq!(get_str(&s, "ipv6", "method").unwrap(), "disabled");
    }

    #[test]
    fn ipv4_only_full_tunnel_blocks_ipv6() {
        let mut cfg = aegis_config::parse(FULL).unwrap();
        cfg.peers[0].allowed_ips.retain(|a| a.addr().is_ipv4());
        for keep_v6_addr in [true, false] {
            if !keep_v6_addr {
                cfg.interface.addresses.retain(|a| a.addr().is_ipv4());
            }
            let s = to_settings(id(), "Work", "alice", &cfg);
            let routes = get(&s, "ipv6", "route-data").and_then(maps).unwrap();
            assert_eq!(str_of(&routes[0], "type").as_deref(), Some("unreachable"));
            assert_eq!(str_of(&routes[0], "dest").as_deref(), Some("::"));
            assert_eq!(u32_of(&routes[0], "prefix"), Some(0));
            assert_eq!(get_str(&s, "ipv6", "method").unwrap(), "manual");
            assert!(!lacks_ipv6_block(&s));
            // The block is ours, not the profile's: it never shows up on export.
            assert_eq!(from_settings(&s).unwrap(), cfg);
        }
        // An install from before blocking existed is detected for refresh.
        let mut old = to_settings(id(), "Work", "alice", &cfg);
        old.insert("ipv6".into(), section(vec![("method", ov("disabled"))]));
        assert!(lacks_ipv6_block(&old));
        // Full dual-stack and split profiles are left alone.
        let full = to_settings(id(), "Work", "alice", &aegis_config::parse(FULL).unwrap());
        assert!(get(&full, "ipv6", "route-data").is_none() && !lacks_ipv6_block(&full));
        let split = to_settings(id(), "Lab", "alice", &aegis_config::parse(SPLIT).unwrap());
        assert!(!lacks_ipv6_block(&split));
    }

    #[test]
    fn dns_byte_order_matches_networkmanager() {
        let s = to_settings(id(), "Lab", "alice", &aegis_config::parse(SPLIT).unwrap());
        let dns =
            Vec::<u32>::try_from(get(&s, "ipv4", "dns").unwrap().try_clone().unwrap()).unwrap();
        // 10.99.0.1 in network byte order, as `nmcli` writes it.
        assert_eq!(dns[0].to_ne_bytes(), [10, 99, 0, 1]);
    }

    #[test]
    fn secrets_merge_and_strip() {
        let cfg = aegis_config::parse(FULL).unwrap();
        let full = to_settings(id(), "Work", "alice", &cfg);
        let mut public = without_secrets(full.try_clone_settings());
        assert!(
            from_settings(&public).is_err(),
            "private key must be required"
        );
        merge_secrets(&mut public, full.try_clone_settings());
        assert_eq!(from_settings(&public).unwrap(), cfg);
    }

    #[test]
    fn foreign_connections_are_not_ours() {
        let cfg = aegis_config::parse(FULL).unwrap();
        let mut s = to_settings(id(), "Work", "alice", &cfg);
        s.get_mut("connection")
            .unwrap()
            .insert("interface-name".into(), ov("wg0"));
        assert_eq!(owned_profile(&s), None);
    }

    trait CloneSettings {
        fn try_clone_settings(&self) -> Settings;
    }
    impl CloneSettings for Settings {
        fn try_clone_settings(&self) -> Settings {
            self.iter()
                .map(|(k, sec)| {
                    (
                        k.clone(),
                        sec.iter()
                            .map(|(k, v)| (k.clone(), v.try_clone().unwrap()))
                            .collect(),
                    )
                })
                .collect()
        }
    }
}
