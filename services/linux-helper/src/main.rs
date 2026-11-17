//! `aegis-helper`: the only Aegis code that runs as root (via pkexec).
//!
//! It manages one dedicated nftables table, `inet aegis_vpn`, and never
//! touches other tables or global state. Usage:
//!
//! ```text
//! aegis-helper apply <iface> [--allow-lan] <ip:port>...   install or replace the kill switch
//! aegis-helper remove                                     delete the table (idempotent)
//! aegis-helper handshake <iface>                          newest handshake time, read-only
//! ```
//!
//! While applied, everything is blocked except loopback, the tunnel
//! interface, UDP to the WireGuard endpoints, DHCP and IPv6 neighbour
//! discovery (plus private/link-local ranges with `--allow-lan`). Rules live in
//! the kernel, so they keep blocking if the app crashes; a marker file in
//! /run (cleared on reboot, like the rules) lets the unprivileged app see that.
//!
//! Every argument is validated before anything runs; the environment from
//! pkexec is ignored and `nft` is called by absolute path with a clean env.

use std::io::Write as _;
use std::net::SocketAddr;
use std::process::{Command, ExitCode, Stdio};

const TABLE: &str = "aegis_vpn";
const NFT: &str = "/usr/sbin/nft";
const WG: &str = "/usr/bin/wg";
const MARKER_DIR: &str = "/run/aegis-vpn";
const MARKER: &str = "/run/aegis-vpn/kill-switch";
const MAX_ENDPOINTS: usize = 16;

const LAN4: &str =
    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255";
const LAN6: &str = "fc00::/7, fe80::/10, ff00::/8";

#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    Apply {
        iface: String,
        allow_lan: bool,
        endpoints: Vec<SocketAddr>,
    },
    Remove,
    /// Print the newest peer handshake time (unix seconds, 0 = none yet).
    Handshake {
        iface: String,
    },
}

fn parse(args: &[String]) -> Result<Cmd, String> {
    match args.first().map(String::as_str) {
        Some("remove") if args.len() == 1 => Ok(Cmd::Remove),
        Some("handshake") if args.len() == 2 && valid_iface(&args[1]) => Ok(Cmd::Handshake {
            iface: args[1].clone(),
        }),
        Some("handshake") => Err("usage: aegis-helper handshake <aegis-iface>".into()),
        Some("apply") => {
            let iface = args.get(1).ok_or("missing interface")?;
            if !valid_iface(iface) {
                return Err("interface must be an Aegis tunnel (aegis-<8 hex digits>)".into());
            }
            let mut allow_lan = false;
            let mut endpoints = Vec::new();
            for a in &args[2..] {
                if a == "--allow-lan" {
                    allow_lan = true;
                    continue;
                }
                let ep: SocketAddr = a
                    .parse()
                    .map_err(|_| "endpoints must be IP:port literals".to_string())?;
                if ep.port() == 0 || ep.ip().is_unspecified() || ep.ip().is_multicast() {
                    return Err("endpoint address or port is not usable".into());
                }
                endpoints.push(ep);
            }
            if endpoints.is_empty() || endpoints.len() > MAX_ENDPOINTS {
                return Err(format!("give 1 to {MAX_ENDPOINTS} endpoints"));
            }
            Ok(Cmd::Apply {
                iface: iface.clone(),
                allow_lan,
                endpoints,
            })
        }
        _ => Err("usage: aegis-helper apply <iface> [--allow-lan] <ip:port>... | remove".into()),
    }
}

/// Exactly what `aegis_linux::settings::iface_name` produces.
fn valid_iface(s: &str) -> bool {
    s.strip_prefix("aegis-").is_some_and(|h| {
        h.len() == 8
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// One atomic transaction: creating then deleting the table first makes the
/// script work whether or not it exists, and nft applies it all or nothing.
fn ruleset(iface: &str, allow_lan: bool, endpoints: &[SocketAddr]) -> String {
    let mut ep = String::new();
    for e in endpoints {
        let fam = if e.is_ipv4() { "ip" } else { "ip6" };
        ep += &format!("\t\t{fam} daddr {} udp dport {} accept\n", e.ip(), e.port());
    }
    let (lan_out, lan_in) = if allow_lan {
        (
            format!("\t\tip daddr {{ {LAN4} }} accept\n\t\tip6 daddr {{ {LAN6} }} accept\n"),
            format!("\t\tip saddr {{ {LAN4} }} accept\n\t\tip6 saddr {{ {LAN6} }} accept\n"),
        )
    } else {
        (String::new(), String::new())
    };
    format!(
        "table inet {TABLE} {{}}
delete table inet {TABLE}
table inet {TABLE} {{
\tchain output {{
\t\ttype filter hook output priority filter - 10; policy drop;
\t\toifname \"lo\" accept
\t\toifname \"{iface}\" accept
{ep}\t\tudp sport 68 udp dport 67 accept
\t\tudp sport 546 udp dport 547 accept
\t\ticmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report }} accept
{lan_out}\t\treject with icmpx type admin-prohibited
\t}}
\tchain input {{
\t\ttype filter hook input priority filter - 10; policy drop;
\t\tiifname \"lo\" accept
\t\tiifname \"{iface}\" accept
\t\tct state established,related accept
\t\tudp sport 67 udp dport 68 accept
\t\tudp sport 547 udp dport 546 accept
\t\ticmpv6 type {{ nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect }} accept
{lan_in}\t}}
}}
"
    )
}

fn nft(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    let mut child = Command::new(NFT)
        .args(args)
        .env_clear()
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {NFT}: {e}; install nftables"))?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(text.as_bytes())
            .map_err(|e| format!("writing to nft: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("waiting for nft: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// Newest handshake in `wg show <iface> latest-handshakes` output
/// (`<public key>\t<unix seconds>` per peer). Only the number leaves the helper.
fn newest_handshake(text: &str) -> u64 {
    text.lines()
        .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        .max()
        .unwrap_or(0)
}

fn wg_latest_handshakes(iface: &str) -> Result<String, String> {
    let out = Command::new(WG)
        .args(["show", iface, "latest-handshakes"])
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {WG}: {e}; install wireguard-tools"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

fn is_root() -> bool {
    // Effective uid is the second field of the Uid line.
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|v| v.split_whitespace().nth(1).map(|u| u == "0"))
            .unwrap_or(false)
    })
}

fn run(cmd: Cmd) -> Result<(), String> {
    match cmd {
        Cmd::Apply {
            iface,
            allow_lan,
            endpoints,
        } => {
            nft(&["-f", "-"], Some(&ruleset(&iface, allow_lan, &endpoints)))?;
            // Read back: report success only for rules the kernel actually holds.
            let listed = nft(&["list", "table", "inet", TABLE], None)?;
            let want = format!("oifname \"{iface}\" accept");
            if !(listed.contains(&want) && listed.matches("policy drop").count() == 2) {
                let _ = nft(&["delete", "table", "inet", TABLE], None);
                return Err("rules did not read back as installed; removed them".into());
            }
            // The app learns about a block (e.g. after a crash) only from the
            // marker, so a block without one must not be left behind.
            let marked = std::fs::create_dir_all(MARKER_DIR)
                .and_then(|()| std::fs::write(MARKER, format!("{iface}\n")))
                .map_err(|e| format!("{MARKER}: {e}"));
            if marked.is_err() {
                let _ = nft(&["delete", "table", "inet", TABLE], None);
            }
            marked
        }
        Cmd::Handshake { iface } => {
            println!("{}", newest_handshake(&wg_latest_handshakes(&iface)?));
            Ok(())
        }
        Cmd::Remove => {
            match nft(&["delete", "table", "inet", TABLE], None) {
                Ok(_) => {}
                // Already gone is success: remove is idempotent.
                Err(e) if e.contains("No such file") => {}
                Err(e) => return Err(e),
            }
            match std::fs::remove_file(MARKER) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("{MARKER}: {e}")),
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = parse(&args).and_then(|cmd| {
        if !is_root() {
            return Err("must run as root (through pkexec)".into());
        }
        run(cmd)
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegis-helper: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses_only_strict_input() {
        assert_eq!(
            parse(&args(
                "apply aegis-0b1e8a3c --allow-lan 203.0.113.5:51820 [2001:db8::1]:51820"
            )),
            Ok(Cmd::Apply {
                iface: "aegis-0b1e8a3c".into(),
                allow_lan: true,
                endpoints: vec![
                    "203.0.113.5:51820".parse().unwrap(),
                    "[2001:db8::1]:51820".parse().unwrap()
                ],
            })
        );
        assert_eq!(parse(&args("remove")), Ok(Cmd::Remove));
        for bad in [
            "",
            "remove extra",
            "apply",
            "apply eth0 1.2.3.4:51820",
            "apply aegis-0B1E8A3C 1.2.3.4:51820",
            "apply aegis-0b1e8a3c\" 1.2.3.4:51820",
            "apply aegis-0b1e8a3c",
            "apply aegis-0b1e8a3c vpn.example.com:51820",
            "apply aegis-0b1e8a3c 1.2.3.4:0",
            "apply aegis-0b1e8a3c 0.0.0.0:51820",
            "apply aegis-0b1e8a3c 1.2.3.4:51820;flush ruleset",
            "flush",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?} must be rejected");
        }
        let many = format!(
            "apply aegis-0b1e8a3c {}",
            "1.2.3.4:1 ".repeat(MAX_ENDPOINTS + 1)
        );
        assert!(parse(&args(&many)).is_err());
    }

    #[test]
    fn handshake_command_is_strict_and_output_is_only_a_number() {
        assert_eq!(
            parse(&args("handshake aegis-0b1e8a3c")),
            Ok(Cmd::Handshake {
                iface: "aegis-0b1e8a3c".into()
            })
        );
        for bad in [
            "handshake",
            "handshake wg0",
            "handshake aegis-0b1e8a3c extra",
            "handshake aegis-0b1e8a3c;id",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
        let text = "AAAA=\t1700000100\nBBBB=\t1700000300\nCCCC=\t0\n";
        assert_eq!(newest_handshake(text), 1_700_000_300);
        assert_eq!(newest_handshake(""), 0);
        assert_eq!(newest_handshake("garbage\nline two\n"), 0);
    }

    #[test]
    fn ruleset_touches_only_our_table_and_blocks_by_default() {
        let eps = [
            "203.0.113.5:51820".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ];
        let r = ruleset("aegis-0b1e8a3c", false, &eps);
        for line in r
            .lines()
            .filter(|l| l.starts_with("table") || l.starts_with("delete"))
        {
            assert!(line.contains("inet aegis_vpn"), "{line}");
        }
        assert!(!r.contains("flush"));
        assert_eq!(r.matches("policy drop").count(), 2);
        assert!(r.contains("oifname \"aegis-0b1e8a3c\" accept"));
        assert!(r.contains("ip daddr 203.0.113.5 udp dport 51820 accept"));
        assert!(r.contains("ip6 daddr 2001:db8::1 udp dport 443 accept"));
        assert!(!r.contains("192.168.0.0/16"), "LAN blocked unless asked");
        assert!(ruleset("aegis-0b1e8a3c", true, &eps).contains("192.168.0.0/16"));
    }
}
