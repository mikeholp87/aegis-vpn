//! Disruptive live tests: run ONLY inside the disposable test VM
//! (`scripts/vm/run-vm-tests.sh` copies and runs this as the `aegis` user).
//!
//!   vm_suite <full|full4> <path to test-netns-peer.sh>
//!
//! Covers full-tunnel routing, endpoint exclusion, DNS leak (resolver answer +
//! packet capture on the uplink), IPv6 routing/leak reporting, reconnect after
//! an external drop, NetworkManager restart, and restoration of routes, rules
//! and DNS after disconnect. Root steps use `sudo -n` (passwordless in the VM).

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use checks::*;
    use std::time::{Duration, Instant};

    use aegis_core::{ConnectionState, Engine, Feature, PeerState, VpnBackend as _};

    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .expect("usage: vm_suite <full|full4> <peer script>");
    let peer_script = args
        .next()
        .expect("usage: vm_suite <full|full4> <peer script>");
    assert!(
        mode == "full" || mode == "full4",
        "mode must be full or full4"
    );
    assert!(
        std::path::Path::new("/etc/aegis-test-vm").exists(),
        "refusing to run: /etc/aegis-test-vm marker missing (this is not the test VM)"
    );
    let full_v6 = mode == "full";

    let mut failures = 0;
    let mut step = |name: &str, ok: bool, detail: &str| {
        let d = detail.trim().replace('\n', " | ");
        println!(
            "{} [{mode}] {name}: {}",
            if ok { "PASS" } else { "FAIL" },
            &d[..d.len().min(300)]
        );
        if !ok {
            failures += 1;
        }
    };

    // Everything below changes the default route; the marker check above and
    // AEGIS_VM_TEST keep it inside the VM.
    let _ = root(&[&peer_script, "down"]);
    let (ok, out) = root(&["env", "AEGIS_VM_TEST=1", &peer_script, "up", &mode]);
    step("peer up", ok, &out);
    if !ok {
        std::process::exit(1);
    }
    let conf = out.lines().last().unwrap_or_default().trim().to_owned();
    let uplink = run(&["ip", "-4", "route", "show", "default"])
        .1
        .split_whitespace()
        .skip_while(|w| *w != "dev")
        .nth(1)
        .unwrap_or("eth0")
        .to_owned();
    // Let the peer's veth finish IPv6 link-local setup (DAD) so the baseline
    // is not taken mid-change.
    for _ in 0..50 {
        let a = run(&[
            "ip",
            "-6",
            "addr",
            "show",
            "dev",
            "aegis-veth0",
            "scope",
            "link",
        ])
        .1;
        if a.contains("inet6") && !a.contains("tentative") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (nft_ok, nft_out) = root(&["nft", "list", "ruleset"]);
    step(
        "nftables snapshot available",
        nft_ok,
        nft_out.lines().next().unwrap_or("(empty ruleset)"),
    );
    let baseline = net_state();
    // Positive control: without the tunnel, lookups must be visible on the
    // uplink, otherwise a "0 packets" result later would prove nothing.
    let (_, _, control) = dns_probe(&uplink, &format!("control-{}", std::process::id())).await;
    step(
        &format!("control: DNS visible on uplink {uplink} before connecting"),
        control > 0,
        &format!("{control} packets"),
    );

    let data = std::env::temp_dir().join(format!("aegis-vm-{}", std::process::id()));
    let engine = Engine::start(aegis_linux::NmBackend::connect().await.expect("NM"), &data)
        .await
        .expect("engine");
    let p = engine
        .import_file(std::path::Path::new(&conf))
        .await
        .expect("import");
    let id = p.meta.id;
    step(
        "profile route kind",
        true,
        &format!("{:?}", p.meta.summary.route_kind),
    );

    let wait_confirmed = |secs: u64| {
        let engine = &engine;
        async move {
            let deadline = Instant::now() + Duration::from_secs(secs);
            while Instant::now() < deadline {
                let _ = run(&["ping", "-c", "1", "-W", "1", "198.51.100.1"]);
                if matches!(
                    engine.snapshot().state,
                    ConnectionState::Connected {
                        peer: PeerState::Confirmed,
                        ..
                    }
                ) {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            false
        }
    };

    if !full_v6 {
        // Simulate an install from before IPv6 blocking existed: connecting
        // must refresh it rather than leak.
        let (ok, out) = root(&[
            "nmcli",
            "connection",
            "modify",
            &id.to_string(),
            "ipv6.method",
            "disabled",
            "ipv6.routes",
            "",
        ]);
        step("downgrade to pre-blocking NM settings", ok, &out);
    }
    let r = engine.connect(id).await;
    step("connect", r.is_ok(), &format!("{r:?}"));
    step(
        "server response confirmed",
        wait_confirmed(15).await,
        &format!("{:?}", engine.snapshot().state),
    );

    // Routing.
    let r4 = run(&["ip", "-4", "route", "get", "1.1.1.1"]).1;
    step(
        "IPv4 internet route goes through tunnel",
        r4.contains("dev aegis-"),
        &r4,
    );
    let ep = run(&["ip", "-4", "route", "get", "10.200.0.2"]).1;
    step(
        "endpoint route stays outside tunnel",
        ep.contains("dev aegis-veth0"),
        &ep,
    );
    let (ok, out) = run(&["ping", "-c", "2", "-W", "2", "198.51.100.1"]);
    step(
        "ping IPv4 sentinel behind tunnel",
        ok,
        out.lines().rev().nth(1).unwrap_or(""),
    );
    let r6 = run(&["ip", "-6", "route", "get", "2001:db8:ffff::1"]).1;
    if full_v6 {
        step(
            "IPv6 internet route goes through tunnel",
            r6.contains("dev aegis-"),
            &r6,
        );
        let (ok, out) = run(&["ping", "-6", "-c", "2", "-W", "2", "2001:db8:99::1"]);
        step(
            "ping IPv6 sentinel behind tunnel",
            ok,
            out.lines().rev().nth(1).unwrap_or(""),
        );
    } else {
        step(
            "IPv6 blocked on an IPv4-only full tunnel (no route outside it)",
            r6.contains("No route to host") || r6.contains("unreachable"),
            &r6,
        );
        let (ok, out) = run(&["ping", "-6", "-c", "1", "-W", "2", "2001:db8:ffff::1"]);
        step(
            "IPv6 ping to the internet fails",
            !ok,
            out.lines().last().unwrap_or(""),
        );
    }
    // The engine runs the active check on each status poll; give it one.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let prot = engine.snapshot().protection;
    step(
        "DNS protection verified at runtime",
        matches!(prot.dns, Feature::Verified(_)),
        &format!("{:?}", prot.dns),
    );
    step(
        "IPv6 protection verified at runtime",
        matches!(prot.ipv6, Feature::Verified(_)),
        &format!("{:?}", prot.ipv6),
    );
    let reach = engine.snapshot().reachability;
    step(
        "reachability: tunnel DNS answered",
        matches!(reach, Feature::Verified(_)),
        &format!("{reach:?}"),
    );

    // DNS leak: capture on the uplink while resolving unique names.
    let tag = std::process::id();
    let (q1, q2, leaked_count) = dns_probe(&uplink, &format!("leak-{tag}")).await;
    step(
        "resolvectl answer came from tunnel DNS",
        q1.contains("198.51.100.1"),
        &q1,
    );
    step(
        "libc (getent) answer came from tunnel DNS",
        q2.contains("198.51.100.1"),
        &q2,
    );
    step(
        &format!("no DNS packets on uplink {uplink}"),
        leaked_count == 0,
        &format!("{leaked_count} packets"),
    );

    // Two country-labelled profiles use the same isolated peer. This proves
    // profile switching, not the physical geography of public remote servers.
    let assign = |code: &str| aegis_core::registry::ServerUpdate {
        location: Some(aegis_core::registry::Location {
            country_code: code.into(),
            city: Some("Isolated test fixture".into()),
            region: None,
            time_zone: None,
        }),
        favorite: true,
        enabled: true,
        registration_pending: false,
    };
    let r = engine.update_server(id, assign("SG")).await;
    step(
        "assign first country metadata",
        r.is_ok(),
        "user-assigned SG fixture",
    );
    let second = engine.duplicate(id).await.expect("second test profile");
    let second_id = second.meta.id;
    let r = engine.update_server(second_id, assign("DE")).await;
    step(
        "assign destination country metadata",
        r.is_ok(),
        "user-assigned DE fixture",
    );
    let r = engine.connect(second_id).await;
    step(
        "switch to second country profile",
        r.is_ok(),
        &format!("{r:?}"),
    );
    step(
        "destination peer answered",
        wait_confirmed(15).await,
        &format!("{:?}", engine.snapshot().state),
    );
    let (ok, out) = run(&["ping", "-c", "2", "-W", "2", "198.51.100.1"]);
    step(
        "traffic works after country switch",
        ok,
        out.lines().rev().nth(1).unwrap_or(""),
    );
    step(
        "active destination metadata synchronized",
        engine.snapshot().profile.is_some_and(|p| {
            p.meta.id == second_id
                && p.meta
                    .server
                    .location
                    .is_some_and(|l| l.country_code == "DE")
        }),
        "expected DE test profile",
    );
    let r = engine.connect(id).await;
    step("switch back to first profile", r.is_ok(), &format!("{r:?}"));
    step(
        "original peer answered again",
        wait_confirmed(15).await,
        &format!("{:?}", engine.snapshot().state),
    );
    let r = engine.delete(second_id).await;
    step("delete inactive destination", r.is_ok(), &format!("{r:?}"));

    // Reconnect after the tunnel is taken down behind the app's back.
    let (ok, out) = root(&["nmcli", "connection", "down", "uuid", &id.to_string()]);
    step("external drop (nmcli down)", ok, &out);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_reconnecting = false;
    while Instant::now() < deadline && !saw_reconnecting {
        saw_reconnecting = matches!(
            engine.snapshot().state,
            ConnectionState::Reconnecting { .. }
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    step(
        "engine noticed drop and is reconnecting",
        saw_reconnecting,
        &format!("{:?}", engine.snapshot().state),
    );
    step(
        "reconnected and confirmed",
        wait_confirmed(30).await,
        &format!("{:?}", engine.snapshot().state),
    );

    // Normal disconnect must restore everything exactly (incl. nftables).
    let r = engine.disconnect().await;
    step("disconnect", r.is_ok(), &format!("{r:?}"));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let diff = diff_lines(&baseline, &net_state());
    step(
        "routes, rules, DNS and nftables restored exactly",
        diff.is_empty(),
        &diff.join(" | "),
    );

    // NetworkManager restart while connected, in separate cycles. The NM rule
    // leak (DECISIONS D11) is intermittent, so try several times.
    for cycle in 1..=3 {
        if cycle > 1 {
            let r = engine.disconnect().await;
            step(
                &format!("cycle {cycle}: disconnect"),
                r.is_ok(),
                &format!("{r:?}"),
            );
        }
        let r = engine.connect(id).await;
        step(
            &format!("cycle {cycle}: connect"),
            r.is_ok(),
            &format!("{r:?}"),
        );
        step(
            &format!("cycle {cycle}: confirmed before NM restart"),
            wait_confirmed(15).await,
            &format!("{:?}", engine.snapshot().state),
        );
        let (ok, out) = root(&["systemctl", "restart", "NetworkManager"]);
        step(&format!("cycle {cycle}: restart NetworkManager"), ok, &out);
        tokio::time::sleep(Duration::from_secs(5)).await;
        step(
            &format!("cycle {cycle}: confirmed after NM restart"),
            wait_confirmed(60).await,
            &format!("{:?}", engine.snapshot().state),
        );
        let r4 = run(&["ip", "-4", "route", "get", "1.1.1.1"]).1;
        step(
            &format!("cycle {cycle}: still routed through tunnel"),
            r4.contains("dev aegis-"),
            &r4,
        );
        let (ok, out) = run(&["ping", "-c", "2", "-W", "2", "198.51.100.1"]);
        step(
            &format!("cycle {cycle}: ping sentinel"),
            ok,
            out.lines().rev().nth(1).unwrap_or(""),
        );
    }
    let r = engine.disconnect().await;
    step("disconnect after NM restart", r.is_ok(), &format!("{r:?}"));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let diff = diff_lines(&baseline, &net_state());
    step(
        "nothing left after NM restart cycle",
        diff.is_empty(),
        &diff.join(" | "),
    );
    // Reachability must fail honestly when the server side cannot resolve:
    // stop the tunnel's DNS server, reconnect, expect Failed (never Verified).
    let (ok, out) = root(&["pkill", "-F", "/run/aegis-test/dnsmasq.pid"]);
    step("stop tunnel DNS server", ok, &out);
    let r = engine.connect(id).await;
    step("reconnect without tunnel DNS", r.is_ok(), &format!("{r:?}"));
    wait_confirmed(15).await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let reach = engine.snapshot().reachability;
    step(
        "reachability fails when tunnel DNS does not answer",
        matches!(reach, Feature::Failed(_)),
        &format!("{reach:?}"),
    );
    let r = engine.disconnect().await;
    step(
        "disconnect after reachability check",
        r.is_ok(),
        &format!("{r:?}"),
    );

    let r = engine.delete(id).await;
    step("delete", r.is_ok(), &format!("{r:?}"));
    let left = engine
        .backend()
        .installed()
        .await
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    step(
        "no leftover NetworkManager connection",
        left == 0,
        &left.to_string(),
    );
    let (ok, out) = root(&[&peer_script, "down"]);
    step("peer down", ok, &out);
    let _ = std::fs::remove_dir_all(&data);

    println!(
        "{} [{mode}]",
        if failures == 0 {
            "ALL PASSED"
        } else {
            "FAILURES"
        }
    );
    std::process::exit(if failures == 0 { 0 } else { 1 });
}

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
mod checks {
    use std::process::Command;
    use std::time::Duration;
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn snapshots_detect_duplicate_rules_and_reordering() {
            assert!(!diff_lines("rule a\n", "rule a\nrule a\n").is_empty());
            assert!(!diff_lines("rule a\nrule b\n", "rule b\nrule a\n").is_empty());
            assert!(diff_lines("rule a\n", "rule a\n").is_empty());
        }

        #[test]
        #[should_panic(expected = "capture read failed")]
        fn failed_capture_is_not_a_zero_packet_result() {
            packet_count((false, "tcpdump: cannot read capture".into()));
        }
    }

    fn packet_count(result: (bool, String)) -> usize {
        assert!(result.0, "capture read failed: {}", result.1);
        result
            .1
            .lines()
            .filter(|l| l.contains(".53:") || l.contains(".53 "))
            .count()
    }
    pub(super) fn run(cmd: &[&str]) -> (bool, String) {
        match Command::new(cmd[0]).args(&cmd[1..]).output() {
            Ok(o) => (
                o.status.success(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
            ),
            Err(e) => (false, e.to_string()),
        }
    }
    pub(super) fn root(cmd: &[&str]) -> (bool, String) {
        let mut v = vec!["sudo", "-n"];
        v.extend_from_slice(cmd);
        run(&v)
    }
    pub(super) fn net_state() -> String {
        let mut s = String::new();
        for c in [
            &["ip", "-4", "rule"][..],
            &["ip", "-6", "rule"],
            &["ip", "-4", "route", "show", "table", "all"],
            &["ip", "-6", "route", "show", "table", "all"],
            &["resolvectl", "dns"],
            &["resolvectl", "domain"],
            &["sudo", "-n", "nft", "list", "ruleset"],
        ] {
            let (ok, out) = run(c);
            assert!(ok, "snapshot command failed: {}: {out}", c.join(" "));
            s += &format!("$ {}\n{}\n", c.join(" "), out);
        }
        // Drop values that change by themselves between snapshots: RA route
        // lifetimes, nexthop ids and firewall packet counters.
        s.lines()
            .map(|l| {
                let mut out = Vec::new();
                let mut skip = false;
                for w in l.split_whitespace() {
                    if skip {
                        skip = false;
                        continue;
                    }
                    if matches!(w, "expires" | "nhid" | "packets" | "bytes") {
                        skip = true;
                        continue;
                    }
                    out.push(w);
                }
                out.join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    pub(super) fn diff_lines(before: &str, after: &str) -> Vec<String> {
        if before == after {
            return vec![];
        }
        // Show only the differing middle, so the step output names the leftover.
        let (b, a): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
        let pre = b.iter().zip(&a).take_while(|(x, y)| x == y).count();
        let suf = b[pre..]
            .iter()
            .rev()
            .zip(a[pre..].iter().rev())
            .take_while(|(x, y)| x == y)
            .count();
        let removed = b[pre..b.len() - suf].iter().map(|l| format!("- {l}"));
        let added = a[pre..a.len() - suf].iter().map(|l| format!("+ {l}"));
        let out: Vec<String> = removed.chain(added).collect();
        if out.is_empty() {
            vec!["(whitespace-only difference)".into()]
        } else {
            out
        }
    }

    /// Resolve two unique names (systemd-resolved and libc paths) while
    /// capturing port 53 on `iface`. Returns both answers and the packet count.
    pub(super) async fn dns_probe(iface: &str, label: &str) -> (String, String, usize) {
        let pcap = format!("/tmp/aegis-dns-{label}.pcap");
        let mut cap = Command::new("sudo")
            .args([
                "-n", "tcpdump", "-n", "-i", iface, "-U", "-w", &pcap, "port", "53",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("tcpdump");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            cap.try_wait().expect("capture status").is_none(),
            "capture exited before DNS probe"
        );
        let q1 = run(&[
            "resolvectl",
            "query",
            "-4",
            &format!("{label}-a.aegis.test"),
        ])
        .1;
        let q2 = run(&["getent", "ahostsv4", &format!("{label}-b.aegis.test")]).1;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let pattern = format!("^tcpdump .* -w {pcap} ");
        let (ok, out) = root(&["pkill", "-INT", "-f", &pattern]);
        assert!(ok, "capture stop failed: {out}");
        assert!(
            cap.wait().expect("capture exit").success(),
            "capture failed"
        );
        let count = packet_count(root(&["tcpdump", "-n", "-r", &pcap]));
        let _ = root(&["rm", "-f", &pcap]);
        (q1, q2, count)
    }
}
