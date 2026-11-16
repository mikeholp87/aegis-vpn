use std::collections::HashSet;

use ipnet::IpNet;

use crate::{Issue, RouteKind, WgConfig};

/// Semantic validation. Returns blocking errors (empty = valid).
/// Used both after parsing and after in-app edits.
pub fn validate(cfg: &WgConfig) -> Vec<Issue> {
    let mut out = Vec::new();
    let i = &cfg.interface;
    let mut e = |field: &str, msg: String| out.push(Issue::error(None, Some(field), msg));

    if i.addresses.is_empty() {
        e("Address", "at least one tunnel address is required".into());
    }
    if let Some(m) = i.mtu {
        let has_v6 = i.addresses.iter().any(|a| matches!(a, IpNet::V6(_)));
        let min = if has_v6 { 1280 } else { 576 };
        if !(min..=9000).contains(&m) {
            e("MTU", format!("must be between {min} and 9000"));
        }
    }
    if i.dns_search.iter().any(|d| !crate::parse::is_hostname(d)) {
        e("DNS", "contains an invalid search domain".into());
    }
    if cfg.peers.is_empty() {
        e("Peer", "at least one [Peer] is required".into());
    }
    if !cfg.peers.is_empty() && cfg.peers.iter().all(|p| p.endpoint.is_none()) {
        e(
            "Endpoint",
            "no peer has an Endpoint, so this client could never start a connection".into(),
        );
    }

    let own = i.private_key.public_key();
    let mut keys = HashSet::new();
    let mut nets: HashSet<IpNet> = HashSet::new();
    for (n, p) in cfg.peers.iter().enumerate() {
        let n = n + 1;
        if p.public_key == own {
            e(
                "PublicKey",
                format!("peer {n} uses this interface's own public key"),
            );
        }
        if !keys.insert(p.public_key) {
            e(
                "PublicKey",
                format!("peer {n} duplicates another peer's public key"),
            );
        }
        if p.allowed_ips.is_empty() {
            e(
                "AllowedIPs",
                format!("peer {n} has no AllowedIPs, so no traffic would use it"),
            );
        }
        for net in &p.allowed_ips {
            if !nets.insert(net.trunc()) {
                e(
                    "AllowedIPs",
                    format!(
                        "peer {n} repeats network {} already routed elsewhere",
                        net.trunc()
                    ),
                );
            }
        }
        if let Some(ep) = &p.endpoint
            && ep.port == 0
        {
            e(
                "Endpoint",
                format!("peer {n} endpoint port must be 1-65535"),
            );
        }
    }
    out
}

/// Non-blocking concerns shown to the user next to the profile.
pub fn warnings(cfg: &WgConfig) -> Vec<Issue> {
    let mut out = Vec::new();
    let kind = cfg.route_kind();
    if kind == RouteKind::FullIpv4Only {
        out.push(Issue::warning(
            Some("AllowedIPs"),
            "routes all IPv4 but not IPv6; IPv6 traffic may bypass the tunnel unless IPv6 protection is enabled",
        ));
    }
    if matches!(kind, RouteKind::Full | RouteKind::FullIpv4Only) && cfg.interface.dns.is_empty() {
        out.push(Issue::warning(
            Some("DNS"),
            "full-tunnel profile without DNS servers; DNS queries may go to your local network's resolver",
        ));
    }
    out
}
