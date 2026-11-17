//! OS events that matter to a running tunnel, from the system D-Bus:
//!
//! * `org.freedesktop.login1` `PrepareForSleep(false)`: the computer woke up.
//! * NetworkManager's `PrimaryConnection` changing: another Wi-Fi network, a
//!   cable plugged in or removed, a different uplink.
//!
//! Both are best effort. If logind or NetworkManager do not answer, the
//! watcher ends and the engine simply gets no events, which is the same as
//! before: the monitor still notices a dead tunnel on its own.

use aegis_core::SystemEvent;
use futures_util::StreamExt;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use zbus::{Connection, OwnedObjectPath, Proxy};

const LOGIND: &str = "org.freedesktop.login1";
const LOGIND_PATH: &str = "/org/freedesktop/login1";
const LOGIND_IFACE: &str = "org.freedesktop.login1.Manager";
const NM: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";

/// Start the watchers on `conn`. Must be called inside a Tokio runtime.
pub fn spawn(conn: &Connection) -> Receiver<SystemEvent> {
    let (tx, rx) = channel(16);
    tokio::spawn(watch_sleep(conn.clone(), tx.clone()));
    tokio::spawn(watch_network(conn.clone(), tx));
    rx
}

async fn watch_sleep(conn: Connection, tx: Sender<SystemEvent>) {
    let Ok(proxy) = Proxy::new(&conn, LOGIND, LOGIND_PATH, LOGIND_IFACE).await else {
        tracing::debug!("logind not reachable; no resume events");
        return;
    };
    let Ok(mut signals) = proxy.receive_signal("PrepareForSleep").await else {
        tracing::debug!("cannot subscribe to PrepareForSleep; no resume events");
        return;
    };
    while let Some(msg) = signals.next().await {
        // The argument is true when going to sleep and false when waking up.
        if msg.body().deserialize::<bool>().is_ok_and(|going| !going)
            && tx.send(SystemEvent::Resumed).await.is_err()
        {
            return;
        }
    }
}

async fn watch_network(conn: Connection, tx: Sender<SystemEvent>) {
    let Ok(proxy) = Proxy::new(&conn, NM, NM_PATH, NM).await else {
        return;
    };
    let mut changes = proxy
        .receive_property_changed::<OwnedObjectPath>("PrimaryConnection")
        .await;
    while changes.next().await.is_some() {
        if tx.send(SystemEvent::NetworkChanged).await.is_err() {
            return;
        }
    }
}
