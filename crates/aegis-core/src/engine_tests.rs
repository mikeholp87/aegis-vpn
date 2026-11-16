use std::sync::Arc;
use std::time::Duration;

use crate::mock::MockBackend;
use crate::{CoreError, Engine, VpnBackend, types::*};

const CONF: &str = include_str!("../../../tests/fixtures/valid/full-tunnel.conf");
const SPLIT: &str = include_str!("../../../tests/fixtures/valid/split.conf");
const PRIV: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
const PSK: &str = "MFujEGz6ut24WLYNi1ay+2fdQM2dc66lyn8CjB3arsM=";

async fn engine() -> (Arc<Engine<MockBackend>>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    (
        Engine::start(MockBackend::instant(), dir.path())
            .await
            .unwrap(),
        dir,
    )
}

async fn wait_for(e: &Engine<MockBackend>, what: &str, pred: impl Fn(&ConnectionState) -> bool) {
    for _ in 0..600 {
        if pred(&e.snapshot().state) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "timed out waiting for {what}; state = {:?}",
        e.snapshot().state
    );
}

fn is_connected(s: &ConnectionState) -> bool {
    matches!(s, ConnectionState::Connected { .. })
}

#[tokio::test(start_paused = true)]
async fn import_connect_disconnect() {
    let (e, _d) = engine().await;
    let p = e.import_text("Work", CONF).await.unwrap();
    assert_eq!(e.profiles().len(), 1);
    e.connect(p.meta.id).await.unwrap();
    assert!(is_connected(&e.snapshot().state));
    assert!(e.snapshot().simulated);
    // Mock reports a handshake, so the monitor confirms the peer.
    wait_for(&e, "peer confirmed", |s| {
        matches!(
            s,
            ConnectionState::Connected {
                peer: PeerState::Confirmed,
                ..
            }
        )
    })
    .await;
    // Simulated protection is never reported as active.
    let prot = e.snapshot().protection;
    assert!(
        matches!(prot.kill_switch, Feature::Unsupported(_)),
        "{prot:?}"
    );
    e.disconnect().await.unwrap();
    assert_eq!(e.snapshot().state, ConnectionState::Disconnected);
    assert!(e.backend().status().await.unwrap().is_none());
}

#[tokio::test]
async fn invalid_import_installs_nothing() {
    let (e, _d) = engine().await;
    let err = e
        .import_text("bad", "[Interface]\nPostUp = rm -rf /\n")
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::Config(_)));
    assert!(e.profiles().is_empty());
    assert!(e.backend().installed().await.unwrap().is_empty());
}

#[tokio::test]
async fn failed_activation_reports_failure_and_rolls_back() {
    let (e, _d) = engine().await;
    let p = e.import_text("Work", CONF).await.unwrap();
    e.backend().fail_next_activate("endpoint unreachable");
    assert!(e.connect(p.meta.id).await.is_err());
    assert!(matches!(e.snapshot().state, ConnectionState::Failed { .. }));
    assert!(e.backend().status().await.unwrap().is_none());
}

#[tokio::test]
async fn kill_switch_request_fails_closed_when_unsupported() {
    let (e, _d) = engine().await;
    let p = e.import_text("Work", CONF).await.unwrap();
    let mut s = e.settings();
    s.kill_switch = true;
    e.set_settings(s).unwrap();
    let err = e.connect(p.meta.id).await.unwrap_err();
    assert!(matches!(err, CoreError::Unsupported { .. }), "{err:?}");
    assert!(err.to_string().contains("Disable the kill switch"));
    assert!(
        e.backend().status().await.unwrap().is_none(),
        "must not connect without requested protection"
    );
}

#[tokio::test]
async fn unsupported_protection_cannot_be_enabled_during_a_session() {
    let (e, _d) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    e.connect(id).await.unwrap();
    let mut s = e.settings();
    s.kill_switch = true;
    assert!(e.set_settings(s).is_err());
    assert!(!e.settings().kill_switch);
    e.disconnect().await.unwrap();
}

#[tokio::test]
async fn disconnect_failure_is_retryable_and_aborts_profile_switch() {
    let (e, _d) = engine().await;
    let a = e.import_text("A", CONF).await.unwrap().meta.id;
    let b = e.import_text("B", SPLIT).await.unwrap().meta.id;
    e.connect(a).await.unwrap();
    e.backend().fail_deactivate(true);
    assert!(e.disconnect().await.is_err());
    assert!(!e.snapshot().state.is_idle());
    assert!(e.disconnect().await.is_err());
    assert!(e.connect(b).await.is_err());
    assert_eq!(e.backend().status().await.unwrap().unwrap().id, a);
    assert!(e.delete(a).await.is_err());
    e.backend().fail_deactivate(false);
    e.disconnect().await.unwrap();
    assert_eq!(e.snapshot().state, ConnectionState::Disconnected);
    assert!(e.backend().status().await.unwrap().is_none());
}

#[tokio::test(start_paused = true)]
async fn status_failure_invalidates_protection_and_recovers_without_activation() {
    let (e, _d) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    e.connect(id).await.unwrap();
    e.backend().fail_status(true);
    wait_for(&e, "status uncertainty", |s| !is_connected(s)).await;
    assert!(!e.snapshot().state.is_idle());
    assert!(matches!(e.snapshot().protection.dns, Feature::Failed(_)));
    assert!(e.delete(id).await.is_err());
    e.backend().fail_status(false);
    wait_for(&e, "status recovery", is_connected).await;
    e.disconnect().await.unwrap();
}

#[tokio::test]
async fn recovery_surfaces_unmet_protection_without_dropping_live_tunnel() {
    let (e, dir) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    let mut s = e.settings();
    s.kill_switch = true;
    e.set_settings(s).unwrap();
    drop(e);
    let b = MockBackend::instant();
    b.install(id, "Work", &aegis_config::parse(CONF).unwrap())
        .await
        .unwrap();
    b.activate(id).await.unwrap();
    let e = Engine::start(b, dir.path()).await.unwrap();
    assert!(!is_connected(&e.snapshot().state));
    assert!(!e.snapshot().state.is_idle());
    assert!(e.backend().status().await.unwrap().is_some());
    assert!(e.connect(id).await.is_err());
    e.disconnect().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn startup_status_failure_stays_unknown_until_reconciled() {
    let (e, dir) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    drop(e);
    let b = MockBackend::instant();
    b.install(id, "Work", &aegis_config::parse(CONF).unwrap())
        .await
        .unwrap();
    b.activate(id).await.unwrap();
    b.fail_status(true);
    let e = Engine::start(b, dir.path()).await.unwrap();
    assert!(!e.snapshot().state.is_idle());
    assert!(!is_connected(&e.snapshot().state));
    assert!(e.disconnect().await.is_err());
    assert!(e.delete(id).await.is_err());
    assert!(e.connect(id).await.is_err());
    assert!(!e.snapshot().state.is_idle());
    e.backend()
        .fail_next_activate("reconciliation must not activate");
    e.backend().fail_status(false);
    wait_for(&e, "startup reconciliation", is_connected).await;
    e.disconnect().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn recovered_protection_request_blocks_reactivation_after_drop() {
    let (e, dir) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    let mut s = e.settings();
    s.kill_switch = true;
    s.reconnect_max_attempts = 1;
    e.set_settings(s).unwrap();
    drop(e);
    let b = MockBackend::instant();
    b.install(id, "Work", &aegis_config::parse(CONF).unwrap())
        .await
        .unwrap();
    b.activate(id).await.unwrap();
    let e = Engine::start(b, dir.path()).await.unwrap();
    e.backend().drop_tunnel();
    wait_for(&e, "unsupported retry stopped", |s| {
        matches!(s, ConnectionState::Failed { .. })
    })
    .await;
    assert!(e.backend().status().await.unwrap().is_none());
    assert!(e.settings().kill_switch);
}

#[tokio::test]
async fn failed_activation_and_rollback_remain_retryable() {
    let (e, _dir) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    e.backend().fail_next_activate("activation failed");
    e.backend().fail_deactivate(true);
    assert!(e.connect(id).await.is_err());
    assert!(!e.snapshot().state.is_idle());
    e.backend().fail_deactivate(false);
    e.disconnect().await.unwrap();
    assert_eq!(e.snapshot().state, ConnectionState::Disconnected);
}

#[tokio::test(start_paused = true)]
async fn cancel_reconnect_cleans_up_and_stops_retrying() {
    let (e, _dir) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    e.connect(id).await.unwrap();
    e.backend().drop_tunnel();
    wait_for(&e, "retry scheduled", |s| {
        matches!(s, ConnectionState::Reconnecting { .. })
    })
    .await;
    e.cancel();
    wait_for(&e, "retry cancelled", |s| {
        *s == ConnectionState::Disconnected
    })
    .await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(e.snapshot().state, ConnectionState::Disconnected);
    assert!(e.backend().status().await.unwrap().is_none());
}

#[tokio::test]
async fn cancel_during_connect() {
    let dir = tempfile::tempdir().unwrap();
    let mock = MockBackend::with_delay(Duration::from_secs(10));
    let e = Engine::start(mock, dir.path()).await.unwrap();
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    let e2 = Arc::clone(&e);
    let task = tokio::spawn(async move { e2.connect(id).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        e.snapshot().state,
        ConnectionState::Connecting { .. }
    ));
    e.cancel();
    assert!(matches!(task.await.unwrap(), Err(CoreError::Cancelled)));
    assert_eq!(e.snapshot().state, ConnectionState::Disconnected);
}

#[tokio::test(start_paused = true)]
async fn reconnects_after_unexpected_drop() {
    let (e, _d) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    e.connect(id).await.unwrap();
    e.backend().drop_tunnel();
    wait_for(&e, "reconnecting", |s| {
        matches!(s, ConnectionState::Reconnecting { .. })
    })
    .await;
    wait_for(&e, "reconnected", is_connected).await;
    assert!(
        e.events()
            .iter()
            .any(|l| l.message.contains("went down unexpectedly"))
    );
    e.disconnect().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn recovered_session_with_kill_switch_does_not_reactivate_after_drop() {
    let (e, dir) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    let mut s = e.settings();
    s.kill_switch = true;
    s.reconnect_max_attempts = 2;
    e.set_settings(s).unwrap();
    drop(e);
    let b = MockBackend::instant();
    b.install(id, "Work", &aegis_config::parse(CONF).unwrap())
        .await
        .unwrap();
    b.activate(id).await.unwrap();
    let e = Engine::start(b, dir.path()).await.unwrap();
    assert!(!is_connected(&e.snapshot().state));
    assert!(!e.snapshot().state.is_idle());
    e.backend().drop_tunnel();
    wait_for(&e, "failed without reactivation", |s| {
        matches!(s, ConnectionState::Failed { .. })
    })
    .await;
    assert!(
        e.backend().status().await.unwrap().is_none(),
        "must not reactivate when requested kill switch is unavailable"
    );
    assert!(
        e.events().iter().any(|l| {
            l.message.contains("kill switch")
                || l.message.contains("Reconnect attempt")
                || l.message.contains("went down unexpectedly")
        }),
        "expected reconnect refusal evidence in events: {:?}",
        e.events()
    );
}

#[tokio::test]
async fn activation_failure_with_failed_cleanup_stays_uncertain_and_retryable() {
    let (e, _d) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    e.backend().fail_next_activate("endpoint unreachable");
    e.backend().fail_deactivate(true);
    assert!(e.connect(id).await.is_err());
    assert!(
        matches!(e.snapshot().state, ConnectionState::Uncertain { .. }),
        "{:?}",
        e.snapshot().state
    );
    assert!(!e.snapshot().state.is_idle());
    e.backend().fail_deactivate(false);
    e.disconnect().await.unwrap();
    assert_eq!(e.snapshot().state, ConnectionState::Disconnected);
}

#[tokio::test(start_paused = true)]
async fn drop_without_auto_reconnect_fails() {
    let (e, _d) = engine().await;
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    let mut s = e.settings();
    s.auto_reconnect = false;
    e.set_settings(s).unwrap();
    e.connect(id).await.unwrap();
    e.backend().drop_tunnel();
    wait_for(&e, "failed", |s| {
        matches!(s, ConnectionState::Failed { .. })
    })
    .await;
}

#[tokio::test]
async fn switching_profiles_keeps_one_tunnel() {
    let (e, _d) = engine().await;
    let a = e.import_text("A", CONF).await.unwrap().meta.id;
    let b = e.import_text("B", SPLIT).await.unwrap().meta.id;
    e.connect(a).await.unwrap();
    e.connect(b).await.unwrap();
    assert_eq!(e.snapshot().state.profile(), Some(b));
    assert_eq!(e.backend().status().await.unwrap().unwrap().id, b);
}

#[tokio::test]
async fn active_profile_cannot_be_deleted_or_edited() {
    let (e, _d) = engine().await;
    let id = e.import_text("A", CONF).await.unwrap().meta.id;
    e.connect(id).await.unwrap();
    assert!(e.delete(id).await.is_err());
    let d = e.draft(id).await.unwrap();
    assert!(e.update(id, &d).await.is_err());
    e.disconnect().await.unwrap();
    e.delete(id).await.unwrap();
    assert!(e.backend().installed().await.unwrap().is_empty());
}

#[tokio::test]
async fn duplicate_rename_and_unique_names() {
    let (e, _d) = engine().await;
    let id = e.import_text("Home", CONF).await.unwrap().meta.id;
    let again = e.import_text("home", CONF).await.unwrap();
    assert_eq!(again.meta.name, "home (2)");
    let dup = e.duplicate(id).await.unwrap();
    assert_eq!(dup.meta.name, "Home copy");
    e.rename(id, "Office").await.unwrap();
    assert!(e.profiles().iter().any(|p| p.meta.name == "Office"));
    // Duplicates keep the same secrets.
    assert_eq!(
        e.backend().load(dup.meta.id).await.unwrap(),
        e.backend().load(id).await.unwrap()
    );
}

#[tokio::test]
async fn recovery_removes_orphans_and_adopts_active_tunnel() {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::start(MockBackend::instant(), dir.path())
        .await
        .unwrap();
    let id = e.import_text("A", CONF).await.unwrap().meta.id;
    drop(e);

    // A fresh UI process finds the tunnel still up plus an orphan profile.
    let mock = MockBackend::instant();
    let cfg = aegis_config::parse(CONF).unwrap();
    let orphan = ProfileId::new();
    mock.install(id, "A", &cfg).await.unwrap();
    mock.install(orphan, "orphan", &cfg).await.unwrap();
    mock.activate(id).await.unwrap();
    let e = Engine::start(mock, dir.path()).await.unwrap();
    assert!(is_connected(&e.snapshot().state));
    assert_eq!(e.backend().installed().await.unwrap(), vec![id]);
}

#[tokio::test]
async fn ui_facing_data_never_contains_secrets() {
    let (e, _d) = engine().await;
    let id = e.import_text("A", CONF).await.unwrap().meta.id;
    e.connect(id).await.unwrap();
    let blobs = [
        serde_json::to_string(&e.profiles()).unwrap(),
        serde_json::to_string(&e.snapshot()).unwrap(),
        serde_json::to_string(&e.draft(id).await.unwrap()).unwrap(),
        serde_json::to_string(&e.events()).unwrap(),
        crate::diagnostics::bundle(&e, "test").await,
    ];
    for b in blobs {
        assert!(!b.contains(PRIV) && !b.contains(PSK), "secret leaked: {b}");
    }
}

#[tokio::test]
async fn export_is_private_and_complete() {
    let (e, d) = engine().await;
    let id = e.import_text("A", CONF).await.unwrap().meta.id;
    let out = d.path().join("export.conf");
    e.export(id, &out).await.unwrap();
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains(PRIV));
    assert_eq!(
        aegis_config::parse(&text).unwrap(),
        aegis_config::parse(CONF).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn import_file_rejects_non_files_and_large_files() {
    let (e, d) = engine().await;
    assert!(e.import_file(d.path()).await.is_err());
    let big = d.path().join("big.conf");
    std::fs::write(&big, vec![b'#'; aegis_config::MAX_CONFIG_BYTES + 10]).unwrap();
    assert!(e.import_file(&big).await.is_err());
    let ok = d.path().join("Office VPN.conf");
    std::fs::write(&ok, CONF).unwrap();
    assert_eq!(e.import_file(&ok).await.unwrap().meta.name, "Office VPN");
    #[cfg(unix)]
    {
        let link = d.path().join("link.conf");
        std::os::unix::fs::symlink(&ok, &link).unwrap();
        assert!(e.import_file(&link).await.is_err());
        let fifo = d.path().join("fifo.conf");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(e.import_file(&fifo).await.is_err());
    }
}

fn server_update(code: &str) -> crate::registry::ServerUpdate {
    crate::registry::ServerUpdate {
        location: Some(crate::registry::Location {
            country_code: code.into(),
            city: Some("Test fixture".into()),
            region: None,
            time_zone: None,
        }),
        favorite: true,
        enabled: true,
        registration_pending: false,
    }
}

#[tokio::test]
async fn server_metadata_migrates_and_persists_without_credentials() {
    let (e, dir) = engine().await;
    let a = e.import_text("Same name", CONF).await.unwrap().meta.id;
    let b = e.import_text("Same name", CONF).await.unwrap().meta.id;
    assert_ne!(e.profiles()[0].meta.name, e.profiles()[1].meta.name);
    // Duplicate endpoints are allowed: two client identities may use one server.
    assert_eq!(
        e.profiles()[0].meta.summary.endpoints,
        e.profiles()[1].meta.summary.endpoints
    );
    e.update_server(a, server_update("sg")).await.unwrap();
    assert!(e.update_server(b, server_update("ZZ")).await.is_err());
    assert!(
        e.update_server(ProfileId::new(), server_update("SG"))
            .await
            .is_err()
    );
    let saved = crate::store::Store::open(dir.path())
        .unwrap()
        .profiles()
        .unwrap();
    assert_eq!(
        saved[0].server.location.as_ref().unwrap().country_code,
        "SG"
    );
    assert!(saved[0].server.favorite);
    let json = std::fs::read_to_string(dir.path().join("profiles.json")).unwrap();
    assert!(!json.contains(PRIV) && !json.contains(PSK));
    let mut legacy: serde_json::Value = serde_json::from_str(&json).unwrap();
    for p in legacy.as_array_mut().unwrap() {
        p.as_object_mut().unwrap().remove("server");
    }
    std::fs::write(
        dir.path().join("profiles.json"),
        serde_json::to_vec(&legacy).unwrap(),
    )
    .unwrap();
    let migrated = crate::store::Store::open(dir.path())
        .unwrap()
        .profiles()
        .unwrap();
    assert_eq!(migrated.len(), 2);
    assert!(
        migrated
            .iter()
            .all(|p| p.server.location.is_none() && p.server.enabled)
    );
    e.delete(a).await.unwrap();
    assert_eq!(e.profiles().len(), 1);
}

#[tokio::test]
async fn switch_preflight_keeps_working_tunnel_when_destination_is_invalid() {
    let (e, _dir) = engine().await;
    let a = e
        .import_text("Singapore simulated", CONF)
        .await
        .unwrap()
        .meta
        .id;
    let b = e
        .import_text("Germany simulated", SPLIT)
        .await
        .unwrap()
        .meta
        .id;
    e.update_server(a, server_update("SG")).await.unwrap();
    e.update_server(b, server_update("DE")).await.unwrap();
    e.connect(a).await.unwrap();
    e.backend().uninstall(b).await.unwrap();
    assert!(e.connect(b).await.is_err());
    assert_eq!(e.backend().status().await.unwrap().unwrap().id, a);
    assert!(e.snapshot().profile.unwrap().active);
    let mut disabled = server_update("SG");
    disabled.enabled = false;
    assert!(e.update_server(a, disabled).await.is_err());
    e.disconnect().await.unwrap();
}

#[tokio::test]
async fn country_switch_uses_same_engine_and_failure_stays_explicit() {
    let (e, _dir) = engine().await;
    let a = e
        .import_text("Singapore simulated", CONF)
        .await
        .unwrap()
        .meta
        .id;
    let b = e
        .import_text("Germany simulated", SPLIT)
        .await
        .unwrap()
        .meta
        .id;
    e.update_server(a, server_update("SG")).await.unwrap();
    e.update_server(b, server_update("DE")).await.unwrap();
    e.connect(a).await.unwrap();
    e.connect(b).await.unwrap();
    assert_eq!(
        e.snapshot()
            .profile
            .unwrap()
            .meta
            .server
            .location
            .unwrap()
            .country_code,
        "DE"
    );
    assert_eq!(e.backend().status().await.unwrap().unwrap().id, b);
    e.backend()
        .fail_next_activate("simulated unreachable destination");
    assert!(e.connect(a).await.is_err());
    assert!(
        matches!(e.snapshot().state, ConnectionState::Failed { profile: Some(id), .. } if id == a)
    );
    assert!(e.backend().status().await.unwrap().is_none());
    let profiles = e.profiles();
    assert!(
        profiles
            .iter()
            .find(|p| p.meta.id == a)
            .unwrap()
            .meta
            .server
            .last_connected_ms
            .is_none()
    );
    let choice = crate::registry::quick_connect(
        &profiles.iter().map(|p| p.meta.clone()).collect::<Vec<_>>(),
        &e.settings(),
        now_ms(),
    )
    .unwrap();
    assert_eq!(choice.id, b, "failed destination must be in cooldown");
}

#[tokio::test(start_paused = true)]
async fn successful_history_requires_peer_evidence_and_survives_reopening() {
    let (e, dir) = engine().await;
    let id = e.import_text("Simulated", CONF).await.unwrap().meta.id;
    e.connect(id).await.unwrap();
    assert!(e.profiles()[0].meta.server.last_connected_ms.is_none());
    wait_for(&e, "confirmed", |s| {
        matches!(
            s,
            ConnectionState::Connected {
                peer: PeerState::Confirmed,
                ..
            }
        )
    })
    .await;
    assert!(e.profiles()[0].meta.server.last_connected_ms.is_some());
    assert!(e.server_health()[0].measured_rtt_ms.is_none());
    e.disconnect().await.unwrap();
    let restored = Engine::start(MockBackend::instant(), dir.path())
        .await
        .unwrap();
    assert!(
        restored.profiles()[0]
            .meta
            .server
            .last_connected_ms
            .is_some()
    );
    assert!(!restored.profiles()[0].active);
}

#[tokio::test(start_paused = true)]
async fn competing_connection_requests_return_busy_and_can_be_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::start(MockBackend::with_delay(Duration::from_secs(10)), dir.path())
        .await
        .unwrap();
    let a = e.import_text("A", CONF).await.unwrap().meta.id;
    let b = e.import_text("B", SPLIT).await.unwrap().meta.id;
    let connecting = {
        let e = e.clone();
        tokio::spawn(async move { e.connect(a).await })
    };
    tokio::task::yield_now().await;
    assert!(matches!(e.connect(b).await, Err(CoreError::Busy)));
    assert!(matches!(e.quick_connect().await, Err(CoreError::Busy)));
    e.cancel();
    assert!(matches!(
        connecting.await.unwrap(),
        Err(CoreError::Cancelled)
    ));
    assert_eq!(e.snapshot().state, ConnectionState::Disconnected);
}

#[tokio::test]
async fn generated_identity_is_pending_until_registered_and_disabled_servers_stay_disabled() {
    let (e, _dir) = engine().await;
    let cfg = aegis_config::parse(CONF).unwrap();
    let mut draft = crate::draft::ProfileDraft::from_config("Manual simulated", &cfg);
    draft.private_key = crate::draft::KeyAction::Generate;
    let p = e.create(&draft).await.unwrap();
    assert!(p.meta.server.registration_pending);
    assert!(e.connect(p.meta.id).await.is_err());
    assert!(e.quick_connect().await.is_err());
    let mut update = server_update("TH");
    update.enabled = false;
    e.update_server(p.meta.id, update).await.unwrap();
    assert!(e.connect(p.meta.id).await.is_err());
    e.update_server(p.meta.id, server_update("TH"))
        .await
        .unwrap();
    e.connect(p.meta.id).await.unwrap();
    e.disconnect().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancel_during_destination_preflight_preserves_current_tunnel() {
    let dir = tempfile::tempdir().unwrap();
    let mut backend = MockBackend::instant();
    backend.load_delay = Duration::from_secs(10);
    let e = Engine::start(backend, dir.path()).await.unwrap();
    let a = e.import_text("A simulated", CONF).await.unwrap().meta.id;
    let b = e.import_text("B simulated", SPLIT).await.unwrap().meta.id;
    e.connect(a).await.unwrap();
    let switching = {
        let e = e.clone();
        tokio::spawn(async move { e.connect(b).await })
    };
    tokio::task::yield_now().await;
    e.cancel();
    assert!(matches!(
        switching.await.unwrap(),
        Err(CoreError::Cancelled)
    ));
    assert_eq!(e.backend().status().await.unwrap().unwrap().id, a);
    e.disconnect().await.unwrap();
}

/// Regression: the reachability probe ran during the WireGuard handshake and
/// reported a healthy server as "no answer within 3 seconds". It must wait for
/// the peer to be confirmed.
#[tokio::test(start_paused = true)]
async fn connectivity_checks_wait_for_peer_confirmation() {
    let (e, _d) = engine().await;
    let mut s = e.settings();
    s.connectivity_check = true;
    e.set_settings(s).unwrap();
    let id = e.import_text("Work", CONF).await.unwrap().meta.id;
    e.backend().silent_peer(true);
    e.connect(id).await.unwrap();
    tokio::time::sleep(Duration::from_secs(10)).await; // several monitor polls
    assert_eq!(
        e.backend().reachability_checks(),
        0,
        "probed before the server answered"
    );

    e.backend().silent_peer(false);
    wait_for(&e, "peer confirmed", |s| {
        matches!(
            s,
            ConnectionState::Connected {
                peer: PeerState::Confirmed,
                ..
            }
        )
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        e.backend().reachability_checks() >= 1,
        "never probed after confirmation"
    );
    e.disconnect().await.unwrap();
}
