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
    use std::process::Command;
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

    fn run(cmd: &[&str]) -> (bool, String) {
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
    fn root(cmd: &[&str]) -> (bool, String) {
        let mut v = vec!["sudo", "-n"];
        v.extend_from_slice(cmd);
        run(&v)
    }
    fn net_state() -> String {
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
            s += &format!("$ {}\n{}\n", c.join(" "), run(c).1);
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
    fn diff_lines(before: &str, after: &str) -> Vec<String> {
        let b: Vec<&str> = before.lines().collect();
        let a: Vec<&str> = after.lines().collect();
        let added = a
            .iter()
            .filter(|l| !b.contains(l))
            .map(|l| format!("+ {l}"));
        let removed = b
            .iter()
            .filter(|l| !a.contains(l))
            .map(|l| format!("- {l}"));
        added.chain(removed).collect()
    }

    /// Resolve two unique names (systemd-resolved and libc paths) while
    /// capturing port 53 on `iface`. Returns both answers and the packet count.
    async fn dns_probe(iface: &str, label: &str) -> (String, String, usize) {
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
        let q1 = run(&[
            "resolvectl",
            "query",
            "-4",
            &format!("{label}-a.aegis.test"),
        ])
        .1;
        let q2 = run(&["getent", "ahostsv4", &format!("{label}-b.aegis.test")]).1;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = root(&["pkill", "-INT", "-f", &pcap]);
        let _ = cap.wait();
        let count = root(&["tcpdump", "-n", "-r", &pcap])
            .1
            .lines()
            .filter(|l| l.contains(".53:") || l.contains(".53 "))
            .count();
        let _ = root(&["rm", "-f", &pcap]);
        (q1, q2, count)
    }

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
            "IPv6 bypasses an IPv4-only full tunnel (expected leak)",
            !r6.contains("dev aegis-"),
            &r6,
        );
    }
    let prot = engine.snapshot().protection;
    step(
        "DNS protection reported Configured",
        matches!(prot.dns, Feature::Configured(_)),
        &format!("{:?}", prot.dns),
    );
    let ipv6_ok = if full_v6 {
        matches!(prot.ipv6, Feature::Configured(_))
    } else {
        matches!(prot.ipv6, Feature::Failed(_))
    };
    step(
        "IPv6 protection reported honestly",
        ipv6_ok,
        &format!("{:?}", prot.ipv6),
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
    // Known NetworkManager issue (seen with 1.52.1): restarting NM while a
    // full tunnel is up duplicates its anti-spoofing raw-table rule and only
    // one copy is removed on disconnect. Reported as XFAIL so it is visible
    // but does not fail the suite; anything else left behind is a FAIL.
    let diff = diff_lines(&baseline, &net_state());
    let nm_leak = |l: &&String| {
        l.starts_with("+ ")
            && ((l.contains("iifname != \"aegis-") && l.contains("drop"))
                || l.contains("ct mark set mark")
                || l.contains("meta mark set ct mark")
                || l.starts_with("+ table ")
                || l.starts_with("+ chain ")
                || l.starts_with("+ type filter hook")
                || l.trim() == "+ }"
                || l.starts_with("+ # Warning: table"))
    };
    let (known, other): (Vec<&String>, Vec<&String>) = diff.iter().partition(nm_leak);
    if other.is_empty() && known.is_empty() {
        println!(
            "XPASS [{mode}] NM rule leak not reproduced in this run (it is intermittent; see DECISIONS D11)"
        );
    } else if other.is_empty() {
        println!(
            "XFAIL [{mode}] known NetworkManager leak after restart: {}",
            known
                .iter()
                .map(|l| l.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        );
    } else {
        step(
            "nothing unexpected left after NM restart cycle",
            false,
            &other
                .iter()
                .map(|l| l.as_str())
                .collect::<Vec<_>>()
                .join(" | "),
        );
    }
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
