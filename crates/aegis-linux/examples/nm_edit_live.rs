//! Live edit + export test through the real engine + NetworkManager.
//!
//! Prerequisite: `sudo scripts/test-netns-peer.sh up` (isolated split-route peer).
//!   cargo run -p aegis-linux --example nm_edit_live -- /run/aegis-test/aegis-netns-test.conf
//!
//! Exercises `load` (NM GetSecrets) via the editor draft, `update` (NM Update2),
//! proves the edit reached the kernel (MTU on the live interface), checks keys
//! survive the edit and never appear in UI data, exports and compares, then
//! cleans up.

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use std::time::{Duration, Instant};

    use aegis_core::{ConnectionState, Engine, PeerState, VpnBackend as _};

    let conf_path = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: nm_edit_live <profile.conf>"),
    );
    let original_text = std::fs::read_to_string(&conf_path).expect("read profile");
    let original = aegis_config::parse(&original_text).expect("parse profile");
    let priv_b64 = original.interface.private_key.expose_base64();

    let mut failures = 0;
    let mut step = |name: &str, ok: bool, detail: String| {
        println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };

    let data = std::env::temp_dir().join(format!("aegis-edit-live-{}", std::process::id()));
    let engine = Engine::start(aegis_linux::NmBackend::connect().await.expect("NM"), &data)
        .await
        .expect("engine");
    let id = engine
        .import_file(&conf_path)
        .await
        .expect("import")
        .meta
        .id;

    // 1. Editor draft: requires reading secrets back from NM (GetSecrets).
    let draft = engine.draft(id).await;
    step(
        "load draft (NM GetSecrets)",
        draft.is_ok(),
        format!("{:?}", draft.as_ref().err()),
    );
    let Ok(mut draft) = draft else {
        std::process::exit(1)
    };
    let expected_pub = original.interface.private_key.public_key().to_string();
    step(
        "draft shows derived public key",
        draft.public_key.as_deref() == Some(expected_pub.as_str()),
        format!("{:?}", draft.public_key),
    );
    let draft_json = serde_json::to_string(&draft).expect("json");
    step(
        "draft (UI payload) contains no private key",
        !draft_json.contains(priv_b64.as_str()),
        format!("{} bytes", draft_json.len()),
    );

    // 2. Edit: rename, set MTU, change keepalive, add a search domain; keep keys.
    draft.name = "Edited test".into();
    draft.mtu = Some(1380);
    draft.peers[0].persistent_keepalive = Some(15);
    draft.dns.push("edit.test".into());
    let r = engine.update(id, &draft).await;
    step(
        "update (NM Update2)",
        r.is_ok(),
        format!("{:?}", r.as_ref().map(|p| &p.meta.name)),
    );

    let after = engine.backend().load(id).await;
    let after_ok = after.as_ref().is_ok_and(|c| {
        c.interface.private_key == original.interface.private_key
            && c.interface.mtu == Some(1380)
            && c.peers[0].persistent_keepalive == Some(15)
            && c.peers[0].public_key == original.peers[0].public_key
            && c.interface.dns_search == vec!["edit.test".to_string()]
    });
    step(
        "reloaded config has edits and original keys",
        after_ok,
        format!(
            "{:?}",
            after
                .as_ref()
                .map(|c| (c.interface.mtu, c.peers[0].persistent_keepalive))
                .map_err(ToString::to_string)
        ),
    );

    // 3. The edit reaches the kernel and the tunnel still works.
    let r = engine.connect(id).await;
    step("connect edited profile", r.is_ok(), format!("{r:?}"));
    let iface = engine
        .backend()
        .status()
        .await
        .ok()
        .flatten()
        .and_then(|s| s.interface);
    let mtu = iface
        .as_deref()
        .and_then(|i| std::fs::read_to_string(format!("/sys/class/net/{i}/mtu")).ok())
        .map(|s| s.trim().to_owned());
    step(
        "kernel interface MTU is 1380",
        mtu.as_deref() == Some("1380"),
        format!("{iface:?} mtu={mtu:?}"),
    );
    let ping = std::process::Command::new("ping")
        .args(["-c", "2", "-W", "2", "10.99.0.1"])
        .output();
    step(
        "ping through edited tunnel",
        ping.is_ok_and(|o| o.status.success()),
        String::new(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline
        && !matches!(
            engine.snapshot().state,
            ConnectionState::Connected {
                peer: PeerState::Confirmed,
                ..
            }
        )
    {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    step(
        "server response confirmed",
        matches!(
            engine.snapshot().state,
            ConnectionState::Connected {
                peer: PeerState::Confirmed,
                ..
            }
        ),
        format!("{:?}", engine.snapshot().state),
    );
    let _ = engine.disconnect().await;

    // 4. Export (what the UI does after its warning + native save dialog).
    let out = data.join("export.conf");
    let r = engine.export(id, &out).await;
    step("export", r.is_ok(), format!("{r:?}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        step(
            "export file is mode 0600",
            mode == 0o600,
            format!("{mode:o}"),
        );
    }
    let exported = std::fs::read_to_string(&out)
        .ok()
        .and_then(|t| aegis_config::parse(&t).ok());
    step(
        "export parses and equals the edited config",
        exported
            .as_ref()
            .is_some_and(|e| after.as_ref().is_ok_and(|a| a == e)),
        String::new(),
    );

    // 5. Secrets are not readable by unprivileged users on disk.
    let nm_dir = std::fs::read_dir("/etc/NetworkManager/system-connections");
    step(
        "NM keyfile directory not listable by this user",
        nm_dir
            .as_ref()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
        format!("{:?}", nm_dir.as_ref().err().map(|e| e.kind())),
    );

    // 6. Clean up.
    let r = engine.delete(id).await;
    step("delete", r.is_ok(), format!("{r:?}"));
    let left = engine
        .backend()
        .installed()
        .await
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    step(
        "no leftover NetworkManager connection",
        left == 0,
        format!("{left}"),
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
