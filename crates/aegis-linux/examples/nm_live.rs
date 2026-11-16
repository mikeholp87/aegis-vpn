//! Live split-route test through the real engine + NetworkManager.
//!
//! Prerequisite (root, isolated, split-route only):
//!   sudo scripts/test-netns-peer.sh up
//! Then, as your normal user:
//!   cargo run -p aegis-linux --example nm_live -- /run/aegis-test/aegis-netns-test.conf
//!
//! Steps: import → connect → wait for confirmed server response → ping the
//! peer through the tunnel → disconnect → delete → verify nothing is left.

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use aegis_core::{ConnectionState, Engine, PeerState};

    let conf = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: nm_live <profile.conf>"),
    );
    let mut failures = 0;
    let mut step = |name: &str, ok: bool, detail: String| {
        println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };

    let data = std::env::temp_dir().join(format!("aegis-live-{}", std::process::id()));
    let backend = aegis_linux::NmBackend::connect()
        .await
        .expect("NetworkManager");
    let engine = Engine::start(backend, &data).await.expect("engine");

    let profile = engine.import_file(&conf).await;
    step(
        "import",
        profile.is_ok(),
        format!("{:?}", profile.as_ref().map(|p| &p.meta.summary.route_kind)),
    );
    let Ok(profile) = profile else {
        std::process::exit(1)
    };
    let id = profile.meta.id;

    let t0 = Instant::now();
    let r = engine.connect(id).await;
    step("connect", r.is_ok(), format!("{r:?} in {:?}", t0.elapsed()));

    // Generate traffic so the server answers, then wait for confirmation.
    let ping = std::process::Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.99.0.1"])
        .output();
    let ping_ok = ping.as_ref().is_ok_and(|o| o.status.success());
    step(
        "ping 10.99.0.1 through tunnel",
        ping_ok,
        ping.map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .rev()
                .nth(1)
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_else(|e| e.to_string()),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut confirmed = false;
    while Instant::now() < deadline {
        if matches!(
            engine.snapshot().state,
            ConnectionState::Connected {
                peer: PeerState::Confirmed,
                ..
            }
        ) {
            confirmed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let snap = engine.snapshot();
    step(
        "server response confirmed",
        confirmed,
        format!(
            "{:?} stats={:?}",
            snap.state,
            snap.stats.map(|s| (s.interface, s.rx_bytes, s.tx_bytes))
        ),
    );

    let r = engine.disconnect().await;
    step(
        "disconnect",
        r.is_ok() && engine.snapshot().state == ConnectionState::Disconnected,
        format!("{r:?}"),
    );
    let r = engine.delete(id).await;
    step("delete profile", r.is_ok(), format!("{r:?}"));

    let leftover_links: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("aegis-") && n != "aegis-veth0")
                .collect()
        })
        .unwrap_or_default();
    step(
        "no leftover aegis interfaces",
        leftover_links.is_empty(),
        format!("{leftover_links:?}"),
    );
    let routes = std::process::Command::new("ip")
        .args(["route", "show", "10.99.0.0/24"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    step(
        "no leftover 10.99.0.0/24 route",
        routes.trim().is_empty(),
        format!("{:?}", routes.trim()),
    );
    use aegis_core::VpnBackend as _;
    let b = aegis_linux::NmBackend::connect()
        .await
        .expect("NetworkManager");
    let left = b.installed().await.map(|v| v.len()).unwrap_or(usize::MAX);
    step(
        "no leftover NetworkManager connection",
        left == 0,
        format!("{left} Aegis connections"),
    );

    let _ = std::fs::remove_dir_all(&data);
    println!(
        "{}",
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
