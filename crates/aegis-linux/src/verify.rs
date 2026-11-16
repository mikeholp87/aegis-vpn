//! Unprivileged runtime checks of DNS and IPv6 protection for the running
//! tunnel. They read what the kernel and resolver will actually do; they do
//! not send packets. A UDP `connect()` only performs the kernel's route
//! lookup and picks a source address, which is enough to tell whether
//! traffic to a destination would use the tunnel.
//!
//! The decision functions (`judge_*`) are pure so they are unit-tested; the
//! I/O helpers around them are thin.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use aegis_config::RouteKind;
use aegis_core::Feature;

/// Any global unicast IPv6 address works: only the route lookup matters and
/// nothing is sent. (Google public DNS, chosen because it is always routed.)
pub const PUBLIC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));

/// Where the kernel would send traffic to one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteProbe {
    /// Source address is one of the tunnel's own addresses.
    Tunnel,
    /// Routed, but with a source address outside the tunnel.
    Outside,
    /// No route (unreachable, blackholed, prohibited, or no source address).
    Unreachable,
}

pub fn probe(dest: IpAddr, tunnel_addrs: &[IpAddr]) -> RouteProbe {
    let bind = if dest.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(sock) = UdpSocket::bind(bind) else {
        // IPv6 disabled system-wide: nothing can leave over it.
        return RouteProbe::Unreachable;
    };
    if sock.connect(SocketAddr::new(dest, 53)).is_err() {
        return RouteProbe::Unreachable;
    }
    match sock.local_addr() {
        Ok(a) if tunnel_addrs.contains(&a.ip()) => RouteProbe::Tunnel,
        Ok(_) => RouteProbe::Outside,
        Err(_) => RouteProbe::Unreachable,
    }
}

/// How this system resolves names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolver {
    /// systemd-resolved: its `Domains` property, as (ifindex, domain, routing-only).
    Resolved(Vec<(i32, String, bool)>),
    /// `/etc/resolv.conf` with these nameservers (NetworkManager writes it directly).
    Plain(Vec<IpAddr>),
    /// Could not be determined; the reason is shown to the user.
    Unknown(String),
}

/// Nameservers from resolv.conf text. `None` means it points at the
/// systemd-resolved stub, whose real configuration must be read over D-Bus.
pub fn parse_resolv_conf(text: &str) -> Option<Vec<IpAddr>> {
    let servers: Vec<IpAddr> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|v| v.trim().split('%').next()?.parse().ok())
        .collect();
    let stub = ["127.0.0.53", "127.0.0.54"].map(|s| s.parse::<IpAddr>().expect("literal"));
    if !servers.is_empty() && servers.iter().all(|s| stub.contains(s)) {
        None
    } else {
        Some(servers)
    }
}

pub fn judge_dns(
    servers: &[(IpAddr, RouteProbe)],
    resolver: &Resolver,
    tunnel_ifindex: Option<i32>,
) -> Feature {
    if servers.is_empty() {
        return Feature::Failed(
            "the profile has no DNS servers, so lookups use your local network".into(),
        );
    }
    if servers.iter().any(|(_, p)| *p == RouteProbe::Outside) {
        return Feature::Failed(
            "a DNS server of this profile is reached outside the tunnel, so lookups are not encrypted. \
             Use a DNS server inside the tunnel's address range."
                .into(),
        );
    }
    if servers.iter().all(|(_, p)| *p == RouteProbe::Unreachable) {
        return Feature::Failed("the profile's DNS servers have no route".into());
    }
    match resolver {
        Resolver::Resolved(domains) => {
            let Some(tun) = tunnel_ifindex else {
                return Feature::Configured(
                    "could not identify the tunnel interface to check systemd-resolved".into(),
                );
            };
            let catch_all: Vec<i32> = domains
                .iter()
                .filter(|(_, d, route_only)| *route_only && d.trim_end_matches('.').is_empty())
                .map(|(i, ..)| *i)
                .collect();
            if !catch_all.contains(&tun) {
                return Feature::Failed(
                    "systemd-resolved is not sending lookups to the tunnel; reconnect, or check \
                     `resolvectl status`"
                        .into(),
                );
            }
            if catch_all.iter().any(|i| *i != tun) {
                return Feature::Failed(
                    "another network also receives all DNS lookups (see `resolvectl status`)"
                        .into(),
                );
            }
            let mut local: Vec<&str> = domains
                .iter()
                .filter(|(i, d, _)| *i != tun && !d.trim_end_matches('.').is_empty())
                .map(|(_, d, _)| d.as_str())
                .collect();
            local.sort_unstable();
            local.dedup();
            let base = "systemd-resolved sends all lookups to the tunnel's DNS servers, which are routed \
                        through the tunnel";
            Feature::Verified(if local.is_empty() {
                base.into()
            } else {
                let shown: Vec<&str> = local.iter().take(3).copied().collect();
                format!(
                    "{base}. Names under {} still go to that network's own DNS server",
                    shown.join(", ")
                )
            })
        }
        Resolver::Plain(ns) => {
            let ours: Vec<IpAddr> = servers.iter().map(|(a, _)| *a).collect();
            if !ns.is_empty() && ns.iter().all(|n| ours.contains(n)) {
                Feature::Verified(
                    "/etc/resolv.conf lists only the tunnel's DNS servers, which are routed through the tunnel"
                        .into(),
                )
            } else {
                Feature::Failed(
                    "/etc/resolv.conf lists DNS servers outside the tunnel, so some lookups can leak".into(),
                )
            }
        }
        Resolver::Unknown(why) => Feature::Configured(format!(
            "tunnel DNS configured as exclusive; resolver state could not be checked ({why})"
        )),
    }
}

pub fn judge_ipv6(route: RouteKind, probe: RouteProbe) -> Feature {
    match (route, probe) {
        (RouteKind::Full, RouteProbe::Tunnel) => {
            Feature::Verified("IPv6 internet traffic is routed through the tunnel".into())
        }
        (RouteKind::Full | RouteKind::FullIpv4Only, RouteProbe::Unreachable) => Feature::Verified(
            "IPv6 is blocked while connected: there is no IPv6 route outside the tunnel".into(),
        ),
        (RouteKind::Full | RouteKind::FullIpv4Only, _) => Feature::Failed(
            "IPv6 traffic leaves outside the tunnel. Reconnect so Aegis can block it, or add IPv6 to the profile."
                .into(),
        ),
        (RouteKind::FullIpv6Only | RouteKind::Split, _) => Feature::Off,
    }
}

/// Name looked up by the reachability check. Reserved by RFC 2606 and run by
/// IANA, so the lookup reveals nothing about the user.
pub const REACH_NAME: &str = "example.com";

/// Name whose authoritative response is the querier's public IPv4. Queried
/// only through the tunnel's own DNS server (same path as reachability).
pub const WHOAMI_NAME: &str = "whoami.akamai.net";

/// A standard recursive DNS query (A record) for `name`.
pub fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(17 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD; 1 question
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // root, type A, class IN
    q
}

/// RCODE of a reply to query `id`, or `None` if it is not that reply.
pub fn dns_rcode(id: u16, reply: &[u8]) -> Option<u8> {
    let head = reply.get(..4)?;
    let is_reply = head[2] & 0x80 != 0;
    (u16::from_be_bytes([head[0], head[1]]) == id && is_reply).then_some(head[3] & 0x0f)
}

fn skip_name(buf: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *buf.get(i)?;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(i + 2);
        }
        i = i.checked_add(1 + usize::from(len))?;
        if i > buf.len() {
            return None;
        }
    }
}

/// IPv4 addresses from A answers in a reply to query `id`.
pub fn dns_a_records(id: u16, reply: &[u8]) -> Option<Vec<Ipv4Addr>> {
    let rcode = dns_rcode(id, reply)?;
    if rcode != 0 {
        return Some(vec![]);
    }
    let ancount = u16::from_be_bytes([*reply.get(6)?, *reply.get(7)?]);
    let mut i = skip_name(reply, 12)?;
    i = i.checked_add(4)?; // qtype + qclass
    let mut out = Vec::new();
    for _ in 0..ancount {
        i = skip_name(reply, i)?;
        let rtype = u16::from_be_bytes([*reply.get(i)?, *reply.get(i + 1)?]);
        let rdlen = u16::from_be_bytes([*reply.get(i + 8)?, *reply.get(i + 9)?]) as usize;
        i = i.checked_add(10)?;
        let end = i.checked_add(rdlen)?;
        let rdata = reply.get(i..end)?;
        if rtype == 1 && rdata.len() == 4 {
            out.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
        i = end;
    }
    Some(out)
}

/// `rcode` is `None` when no matching reply arrived in time.
pub fn judge_reachability(rcode: Option<u8>) -> Feature {
    match rcode {
        // NOERROR or NXDOMAIN: the server resolved the name.
        Some(0 | 3) => Feature::Verified(format!(
            "the tunnel's DNS server answered a lookup for {REACH_NAME}"
        )),
        Some(code) => Feature::Failed(format!(
            "the tunnel's DNS server could not resolve names (DNS error {code}); the VPN server may have no internet access"
        )),
        None => Feature::Failed(
            "no answer from the tunnel's DNS server within 3 seconds; the VPN server may be down or have no internet access"
                .into(),
        ),
    }
}

pub fn judge_public_ip(addrs: Option<Vec<Ipv4Addr>>) -> Feature {
    match addrs {
        Some(list) if !list.is_empty() => Feature::Verified(list[0].to_string()),
        Some(_) => {
            Feature::Failed("the tunnel DNS answered whoami but returned no IPv4 address".into())
        }
        None => {
            Feature::Failed("no whoami answer from the tunnel's DNS server within 3 seconds".into())
        }
    }
}

fn dns_exchange(server: IpAddr, name: &str) -> Option<(u16, Vec<u8>)> {
    let bind = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(SocketAddr::new(server, 53)).ok()?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .ok()?;
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x5a5a);
    sock.send(&dns_query(id, name)).ok()?;
    let mut buf = [0u8; 512];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        let n = sock.recv(&mut buf).ok()?;
        if dns_rcode(id, &buf[..n]).is_some() {
            return Some((id, buf[..n].to_vec()));
        }
    }
    None
}

/// Send one query to `server` and wait up to 3 s for its reply. Blocking.
pub fn lookup(server: IpAddr) -> Option<u8> {
    let (id, reply) = dns_exchange(server, REACH_NAME)?;
    dns_rcode(id, &reply)
}

/// Ask `server` for [`WHOAMI_NAME`] and return the A records. Blocking.
pub fn lookup_public_ip(server: IpAddr) -> Option<Vec<Ipv4Addr>> {
    let (id, reply) = dns_exchange(server, WHOAMI_NAME)?;
    dns_a_records(id, &reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn resolv_conf_stub_and_plain() {
        assert_eq!(
            parse_resolv_conf("# x\nnameserver 127.0.0.53\noptions edns0\n"),
            None
        );
        assert_eq!(
            parse_resolv_conf("nameserver 10.0.0.1\nnameserver fe80::1%eth0\n"),
            Some(vec![ip("10.0.0.1"), ip("fe80::1")])
        );
        assert_eq!(parse_resolv_conf(""), Some(vec![]));
    }

    #[test]
    fn dns_needs_tunnel_route_and_exclusive_resolver() {
        let via_tunnel = [(ip("10.0.0.1"), RouteProbe::Tunnel)];
        let tun = Some(7);
        let only_tunnel = Resolver::Resolved(vec![(7, ".".into(), true), (2, "lan".into(), false)]);
        let f = judge_dns(&via_tunnel, &only_tunnel, tun);
        assert!(
            matches!(&f, Feature::Verified(d) if d.contains("lan")),
            "{f:?}"
        );

        assert!(matches!(
            judge_dns(
                &[(ip("192.168.1.1"), RouteProbe::Outside)],
                &only_tunnel,
                tun
            ),
            Feature::Failed(_)
        ));
        let shared = Resolver::Resolved(vec![(7, ".".into(), true), (2, ".".into(), true)]);
        assert!(matches!(
            judge_dns(&via_tunnel, &shared, tun),
            Feature::Failed(_)
        ));
        let missing = Resolver::Resolved(vec![(2, ".".into(), true)]);
        assert!(matches!(
            judge_dns(&via_tunnel, &missing, tun),
            Feature::Failed(_)
        ));
        // Domain "." without the routing-only flag is a search domain, not a catch-all.
        let search_only = Resolver::Resolved(vec![(7, ".".into(), false)]);
        assert!(matches!(
            judge_dns(&via_tunnel, &search_only, tun),
            Feature::Failed(_)
        ));
        assert!(matches!(
            judge_dns(&[], &only_tunnel, tun),
            Feature::Failed(_)
        ));
        assert!(matches!(
            judge_dns(&via_tunnel, &Resolver::Unknown("no D-Bus".into()), tun),
            Feature::Configured(_)
        ));
    }

    #[test]
    fn dns_plain_resolv_conf_must_list_only_tunnel_servers() {
        let s = [(ip("10.0.0.1"), RouteProbe::Tunnel)];
        assert!(matches!(
            judge_dns(&s, &Resolver::Plain(vec![ip("10.0.0.1")]), None),
            Feature::Verified(_)
        ));
        assert!(matches!(
            judge_dns(
                &s,
                &Resolver::Plain(vec![ip("10.0.0.1"), ip("192.168.1.1")]),
                None
            ),
            Feature::Failed(_)
        ));
    }

    #[test]
    fn ipv6_verified_only_through_tunnel_or_blocked() {
        use RouteKind::*;
        assert!(matches!(
            judge_ipv6(Full, RouteProbe::Tunnel),
            Feature::Verified(_)
        ));
        assert!(matches!(
            judge_ipv6(Full, RouteProbe::Outside),
            Feature::Failed(_)
        ));
        assert!(matches!(
            judge_ipv6(FullIpv4Only, RouteProbe::Unreachable),
            Feature::Verified(_)
        ));
        assert!(matches!(
            judge_ipv6(FullIpv4Only, RouteProbe::Outside),
            Feature::Failed(_)
        ));
        assert_eq!(judge_ipv6(Split, RouteProbe::Outside), Feature::Off);
    }

    #[test]
    fn dns_query_wire_format_and_reply_matching() {
        let q = dns_query(0xabcd, "example.com");
        assert_eq!(
            q,
            [
                &[0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0][..],
                b"\x07example\x03com\x00",
                &[0, 1, 0, 1]
            ]
            .concat()
        );
        let mut reply = q.clone();
        reply[2] |= 0x80; // QR
        reply[3] = 0x83; // RA + NXDOMAIN
        assert_eq!(dns_rcode(0xabcd, &reply), Some(3));
        assert_eq!(dns_rcode(0xabce, &reply), None, "other query id");
        assert_eq!(dns_rcode(0xabcd, &q), None, "our own query is not a reply");
        assert_eq!(dns_rcode(0xabcd, &[0xab]), None, "truncated");
        assert!(matches!(judge_reachability(Some(0)), Feature::Verified(_)));
        assert!(matches!(judge_reachability(Some(3)), Feature::Verified(_)));
        assert!(matches!(judge_reachability(Some(2)), Feature::Failed(_)));
        assert!(matches!(judge_reachability(None), Feature::Failed(_)));
    }

    #[test]
    fn dns_a_records_parse_pointer_answer() {
        // Compact reply: question for whoami.akamai.net + one A via name pointer.
        let mut reply = dns_query(0x1111, "whoami.akamai.net");
        reply[2] |= 0x80; // QR
        reply[3] = 0x80; // RA + NOERROR
        reply[7] = 1; // ANCOUNT = 1
        reply.extend_from_slice(&[
            0xc0, 0x0c, // pointer to question name
            0, 1, // type A
            0, 1, // class IN
            0, 0, 0, 60, // TTL
            0, 4, // rdlength
            203, 0, 113, 50,
        ]);
        assert_eq!(
            dns_a_records(0x1111, &reply),
            Some(vec![Ipv4Addr::new(203, 0, 113, 50)])
        );
        assert!(matches!(
            judge_public_ip(Some(vec![Ipv4Addr::new(203, 0, 113, 50)])),
            Feature::Verified(s) if s == "203.0.113.50"
        ));
        assert!(matches!(judge_public_ip(Some(vec![])), Feature::Failed(_)));
        assert!(matches!(judge_public_ip(None), Feature::Failed(_)));
    }

    #[test]
    fn probe_reports_outside_for_loopback_source() {
        // 127.0.0.1 routes via lo with source 127.0.0.1, which is not a tunnel address.
        assert_eq!(
            probe(ip("127.0.0.1"), &[ip("10.0.0.2")]),
            RouteProbe::Outside
        );
        assert_eq!(
            probe(ip("127.0.0.1"), &[ip("127.0.0.1")]),
            RouteProbe::Tunnel
        );
    }
}
