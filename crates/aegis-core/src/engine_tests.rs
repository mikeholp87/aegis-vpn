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
}
