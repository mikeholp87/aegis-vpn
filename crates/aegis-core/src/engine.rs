//! Connection lifecycle and profile management on top of a [`VpnBackend`].
//!
//! Concurrency model: every mutating operation takes `op_lock` (one at a time,
//! so system state cannot be corrupted by interleaving). `cancel()` and
//! snapshots do not take it. A background monitor polls the backend while a
//! tunnel is active and drives reconnection.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_config::{MAX_CONFIG_BYTES, WgConfig};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::backend::VpnBackend;
use crate::draft::{ProfileDraft, clean_name};
use crate::error::{CoreError, Result};
use crate::retry::RetryPolicy;
use crate::store::{Store, write_private_atomic};
use crate::types::*;

const MAX_EVENTS: usize = 200;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Sent traffic with no reply for this long ⇒ `PeerState::NoResponse`.
const NO_RESPONSE_AFTER: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_secs(2);

struct Live {
    state: ConnectionState,
    stats: Option<Stats>,
    events: VecDeque<LogEntry>,
    profiles: Vec<ProfileMeta>,
    settings: Settings,
    /// Cancels the in-flight connect / reconnect loop.
    op_cancel: CancellationToken,
    /// Stops the monitor for the current session.
    monitor_cancel: CancellationToken,
}

pub struct Engine<B: VpnBackend> {
    backend: Arc<B>,
    store: Store,
    live: Mutex<Live>,
    op_lock: tokio::sync::Mutex<()>,
    tx: broadcast::Sender<EngineEvent>,
    caps: Capabilities,
}

impl<B: VpnBackend> Engine<B> {
    /// Open the store, query the backend, and reconcile state left by a
    /// previous run (crash recovery).
    pub async fn start(backend: B, data_dir: &Path) -> Result<Arc<Self>> {
        let store = Store::open(data_dir)?;
        let profiles = store.profiles()?;
        let settings = store.settings()?;
        let caps = backend.capabilities().await?;
        let (tx, _) = broadcast::channel(64);
        let engine = Arc::new(Self {
            backend: Arc::new(backend),
            store,
            live: Mutex::new(Live {
                state: ConnectionState::Disconnected,
                stats: None,
                events: VecDeque::new(),
                profiles,
                settings,
                op_cancel: CancellationToken::new(),
                monitor_cancel: CancellationToken::new(),
            }),
            op_lock: tokio::sync::Mutex::new(()),
            tx,
            caps,
        });
        engine.recover().await;
        Ok(engine)
    }

    fn live(&self) -> std::sync::MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.tx.subscribe()
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    fn log(&self, level: Level, message: impl Into<String>) {
        let entry = LogEntry {
            at_ms: now_ms(),
            level,
            message: message.into(),
        };
        match level {
            Level::Info => tracing::info!(target: "aegis", "{}", entry.message),
            Level::Warn => tracing::warn!(target: "aegis", "{}", entry.message),
            Level::Error => tracing::error!(target: "aegis", "{}", entry.message),
        }
        {
            let mut l = self.live();
            if l.events.len() == MAX_EVENTS {
                l.events.pop_front();
            }
            l.events.push_back(entry.clone());
        }
        let _ = self.tx.send(EngineEvent::Log(entry));
    }

    fn set_state(&self, state: ConnectionState) {
        {
            let mut l = self.live();
            if l.state == state {
                return;
            }
            if state.is_idle() {
                l.stats = None;
            }
            l.state = state;
        }
        self.publish();
    }

    fn publish(&self) {
        let _ = self
            .tx
            .send(EngineEvent::Snapshot(Box::new(self.snapshot())));
    }

    pub fn snapshot(&self) -> Snapshot {
        let l = self.live();
        let active = l.state.profile();
        let profile = active
            .and_then(|id| l.profiles.iter().find(|p| p.id == id))
            .map(|m| ProfileView {
                meta: m.clone(),
                preferred: l.settings.preferred_profile == Some(m.id),
                active: true,
            });
        let protection = match (&l.state, &profile) {
            (ConnectionState::Connected { .. }, Some(p)) => {
                self.backend.protection(&p.meta.summary, &l.settings)
            }
            _ => Protection::off(),
        };
        Snapshot {
            state: l.state.clone(),
            protection,
            stats: l.stats.clone(),
            profile,
            simulated: self.caps.simulated,
        }
    }

    pub fn events(&self) -> Vec<LogEntry> {
        self.live().events.iter().cloned().collect()
    }

    // ---------- profiles ----------

    pub fn profiles(&self) -> Vec<ProfileView> {
        let l = self.live();
        let active = l.state.profile();
        l.profiles
            .iter()
            .map(|m| ProfileView {
                meta: m.clone(),
                preferred: l.settings.preferred_profile == Some(m.id),
                active: active == Some(m.id),
            })
            .collect()
    }

    fn meta(&self, id: ProfileId) -> Result<ProfileMeta> {
        self.live()
            .profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    fn save_profiles(&self, f: impl FnOnce(&mut Vec<ProfileMeta>)) -> Result<()> {
        let mut next = self.live().profiles.clone();
        f(&mut next);
        self.store.save_profiles(&next)?;
        self.live().profiles = next;
        let _ = self.tx.send(EngineEvent::ProfilesChanged);
        Ok(())
    }

    fn unique_name(&self, wanted: &str) -> String {
        let l = self.live();
        let taken = |n: &str| l.profiles.iter().any(|p| p.name.eq_ignore_ascii_case(n));
        if !taken(wanted) {
            return wanted.to_owned();
        }
        (2..)
            .map(|i| format!("{wanted} ({i})"))
            .find(|n| !taken(n))
            .expect("unbounded")
    }

    async fn add(&self, name: &str, cfg: &WgConfig) -> Result<ProfileView> {
        let name = self.unique_name(&clean_name(name).map_err(CoreError::invalid)?);
        let id = ProfileId::new();
        self.backend.install(id, &name, cfg).await?;
        let meta = ProfileMeta {
            id,
            name: name.clone(),
            created_ms: now_ms(),
            updated_ms: now_ms(),
            summary: ProfileSummary::from_config(cfg),
        };
        if let Err(e) = self.save_profiles(|v| v.push(meta.clone())) {
            // Roll back so the secret store holds nothing we do not track.
            let _ = self.backend.uninstall(id).await;
            return Err(e);
        }
        self.log(Level::Info, format!("Profile \"{name}\" added"));
        Ok(ProfileView {
            meta,
            preferred: false,
            active: false,
        })
    }

    pub async fn import_text(&self, name: &str, text: &str) -> Result<ProfileView> {
        let _g = self.op_lock.lock().await;
        let cfg = aegis_config::parse(text)?;
        self.add(name, &cfg).await
    }

    /// Import a user-selected file. The path must come from a native file
    /// dialog or drag-and-drop, never from web content.
    pub async fn import_file(&self, path: &Path) -> Result<ProfileView> {
        let meta = std::fs::metadata(path).map_err(CoreError::storage)?;
        if !meta.is_file() {
            return Err(CoreError::invalid("not a regular file"));
        }
        if meta.len() > MAX_CONFIG_BYTES as u64 {
            return Err(CoreError::invalid(
                "file is too large to be a WireGuard profile",
            ));
        }
        let text = zeroize::Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|_| CoreError::invalid("file is not readable UTF-8 text"))?,
        );
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Imported".into());
        self.import_text(&name, &text).await
    }

    pub async fn create(&self, draft: &ProfileDraft) -> Result<ProfileView> {
        let _g = self.op_lock.lock().await;
        let cfg = draft.apply(None)?;
        self.add(&draft.name, &cfg).await
    }

    pub async fn draft(&self, id: ProfileId) -> Result<ProfileDraft> {
        let meta = self.meta(id)?;
        let cfg = self.backend.load(id).await?;
        Ok(ProfileDraft::from_config(&meta.name, &cfg))
    }

    pub async fn update(&self, id: ProfileId, draft: &ProfileDraft) -> Result<ProfileView> {
        let _g = self.op_lock.lock().await;
        if self.live().state.profile() == Some(id) && !self.live().state.is_idle() {
            return Err(CoreError::invalid(
                "disconnect before editing the active profile",
            ));
        }
        let mut meta = self.meta(id)?;
        let existing = self.backend.load(id).await?;
        let cfg = draft.apply(Some(&existing))?;
        let name = clean_name(&draft.name).map_err(CoreError::invalid)?;
        let name = if name.eq_ignore_ascii_case(&meta.name) {
            name
        } else {
            self.unique_name(&name)
        };
        self.backend.install(id, &name, &cfg).await?;
        meta.name = name;
        meta.summary = ProfileSummary::from_config(&cfg);
        meta.updated_ms = now_ms();
        let m = meta.clone();
        self.save_profiles(|v| {
            if let Some(slot) = v.iter_mut().find(|p| p.id == id) {
                *slot = m;
            }
        })?;
        self.log(Level::Info, format!("Profile \"{}\" updated", meta.name));
        Ok(ProfileView {
            meta,
            preferred: false,
            active: false,
        })
    }

    pub async fn rename(&self, id: ProfileId, name: &str) -> Result<()> {
        let mut d = self.draft(id).await?;
        d.name = name.to_owned();
        self.update(id, &d).await.map(|_| ())
    }

    pub async fn duplicate(&self, id: ProfileId) -> Result<ProfileView> {
        let _g = self.op_lock.lock().await;
        let meta = self.meta(id)?;
        let cfg = self.backend.load(id).await?;
        self.add(&format!("{} copy", meta.name), &cfg).await
    }

    pub async fn delete(&self, id: ProfileId) -> Result<()> {
        let _g = self.op_lock.lock().await;
        let meta = self.meta(id)?;
        if self.live().state.profile() == Some(id) && !self.live().state.is_idle() {
            return Err(CoreError::invalid(
                "disconnect before deleting the active profile",
            ));
        }
        // Metadata first: if uninstall then fails, recovery removes the orphan on next start.
        self.save_profiles(|v| v.retain(|p| p.id != id))?;
        if self.live().settings.preferred_profile == Some(id) {
            let mut s = self.settings();
            s.preferred_profile = None;
            self.store.save_settings(&s)?;
            self.live().settings = s;
        }
        self.backend.uninstall(id).await?;
        self.log(Level::Info, format!("Profile \"{}\" deleted", meta.name));
        Ok(())
    }

    /// Write the full configuration, including private keys, to `path`.
    /// The UI must show an explicit warning first; the path must come from a
    /// native save dialog.
    pub async fn export(&self, id: ProfileId, path: &Path) -> Result<()> {
        let meta = self.meta(id)?;
        let cfg = self.backend.load(id).await?;
        write_private_atomic(path, cfg.to_wg_quick().as_bytes())?;
        self.log(
            Level::Warn,
            format!("Profile \"{}\" exported with its private key", meta.name),
        );
        Ok(())
    }

    // ---------- settings ----------

    pub fn settings(&self) -> Settings {
        self.live().settings.clone()
    }

    pub fn set_settings(&self, mut s: Settings) -> Result<Settings> {
        if let Some(p) = s.preferred_profile
            && self.meta(p).is_err()
        {
            s.preferred_profile = None;
        }
        s.reconnect_max_attempts = s.reconnect_max_attempts.clamp(1, 50);
        self.store.save_settings(&s)?;
        self.live().settings = s.clone();
        self.publish();
        Ok(s)
    }

    // ---------- connection ----------

    /// Fail closed: a requested protection that the backend cannot provide
    /// blocks the connection instead of being silently downgraded.
    fn check_requested_protection(&self) -> Result<()> {
        if self.live().settings.kill_switch && !self.caps.kill_switch.is_supported() {
            let why = match &self.caps.kill_switch {
                Support::Unsupported(m) => m.clone(),
                Support::Supported => String::new(),
            };
            return Err(CoreError::unsupported(format!(
                "the kill switch is enabled in Settings but is not available on this system ({why}). \
                 Not connecting, to avoid running without the protection you asked for. \
                 Disable the kill switch in Settings to connect without it."
            )));
        }
        Ok(())
    }

    pub async fn connect(self: &Arc<Self>, id: ProfileId) -> Result<()> {
        let _g = self.op_lock.lock().await;
        let meta = self.meta(id)?;
        let current = self.live().state.clone();
        if let ConnectionState::Connected { profile, .. } = current
            && profile == id
        {
            return Ok(());
        }
        if !self.caps.available.is_supported() {
            return Err(CoreError::unsupported(
                "no usable VPN backend; see Diagnostics",
            ));
        }
        self.check_requested_protection()?;

        // Switch profiles: v1 supports one active tunnel.
        if let Some(prev) = current.profile()
            && !current.is_idle()
            && prev != id
        {
            self.teardown(prev).await;
        }

        let cancel = CancellationToken::new();
        self.live().op_cancel = cancel.clone();
        self.set_state(ConnectionState::Preparing { profile: id });
        self.log(Level::Info, format!("Connecting to \"{}\"", meta.name));
        self.set_state(ConnectionState::Connecting { profile: id });

        match self.activate_once(id, &cancel).await {
            Ok(()) => {
                self.on_connected(id);
                Ok(())
            }
            Err(e) => {
                let _ = self.backend.deactivate(id).await; // roll back partial activation
                if matches!(e, CoreError::Cancelled) {
                    self.log(Level::Info, "Connection cancelled");
                    self.set_state(ConnectionState::Disconnected);
                } else {
                    self.log(
                        Level::Error,
                        format!("Connection to \"{}\" failed: {e}", meta.name),
                    );
                    self.set_state(ConnectionState::Failed {
                        profile: Some(id),
                        reason: e.to_string(),
                    });
                }
                Err(e)
            }
        }
    }

    async fn activate_once(&self, id: ProfileId, cancel: &CancellationToken) -> Result<()> {
        tokio::select! {
            _ = cancel.cancelled() => Err(CoreError::Cancelled),
            r = tokio::time::timeout(CONNECT_TIMEOUT, self.backend.activate(id)) => match r {
                Ok(r) => r,
                Err(_) => Err(CoreError::Timeout { what: "the tunnel did not come up".into(), seconds: CONNECT_TIMEOUT.as_secs() }),
            },
        }
    }

    fn on_connected(self: &Arc<Self>, id: ProfileId) {
        self.set_state(ConnectionState::Connected {
            profile: id,
            since_ms: now_ms(),
            peer: PeerState::Pending,
        });
        self.log(
            Level::Info,
            "Tunnel is up; waiting for the server to respond",
        );
        let token = CancellationToken::new();
        self.live().monitor_cancel = token.clone();
        let me = Arc::clone(self);
        tokio::spawn(async move { me.monitor(id, token).await });
    }

    /// Cancel an in-flight connect or reconnect loop.
    pub fn cancel(&self) {
        self.live().op_cancel.cancel();
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.cancel(); // stop a pending connect/reconnect first
        let _g = self.op_lock.lock().await;
        let Some(id) = self.live().state.profile() else {
            return Ok(());
        };
        if self.live().state.is_idle() {
            self.set_state(ConnectionState::Disconnected);
            return Ok(());
        }
        self.teardown(id).await;
        Ok(())
    }

    async fn teardown(&self, id: ProfileId) {
        self.live().monitor_cancel.cancel();
        self.set_state(ConnectionState::Disconnecting { profile: id });
        match self.backend.deactivate(id).await {
            Ok(()) => {
                self.log(Level::Info, "Disconnected");
                self.set_state(ConnectionState::Disconnected);
            }
            Err(e) => {
                self.log(Level::Error, format!("Disconnect failed: {e}"));
                self.set_state(ConnectionState::Failed {
                    profile: Some(id),
                    reason: format!("disconnect failed: {e}"),
                });
            }
        }
    }

    async fn monitor(self: Arc<Self>, id: ProfileId, stop: CancellationToken) {
        let mut prev: Option<(u64, u64, u64)> = None; // rx, tx, at_ms
        let mut first_tx_ms: Option<u64> = None;
        loop {
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(POLL) => {}
            }
            let status = self.backend.status().await;
            if stop.is_cancelled() {
                return;
            }
            match status {
                Ok(Some(s)) if s.id == id && s.link == LinkState::Up => {
                    let now = now_ms();
                    let (rx_rate, tx_rate) = match prev {
                        Some((rx, tx, at)) if now > at => {
                            let dt = (now - at) as f64 / 1000.0;
                            (
                                s.rx_bytes.saturating_sub(rx) as f64 / dt,
                                s.tx_bytes.saturating_sub(tx) as f64 / dt,
                            )
                        }
                        _ => (0.0, 0.0),
                    };
                    prev = Some((s.rx_bytes, s.tx_bytes, now));
                    if s.tx_bytes > 0 && first_tx_ms.is_none() {
                        first_tx_ms = Some(now);
                    }
                    let confirmed = s.last_handshake_ms.is_some() || s.rx_bytes > 0;
                    let peer = if confirmed {
                        PeerState::Confirmed
                    } else if first_tx_ms
                        .is_some_and(|t| now - t > NO_RESPONSE_AFTER.as_millis() as u64)
                    {
                        PeerState::NoResponse
                    } else {
                        PeerState::Pending
                    };
                    let mut changed = None;
                    {
                        let mut l = self.live();
                        l.stats = Some(Stats {
                            rx_bytes: s.rx_bytes,
                            tx_bytes: s.tx_bytes,
                            rx_rate_bps: rx_rate,
                            tx_rate_bps: tx_rate,
                            last_handshake_ms: s.last_handshake_ms,
                            interface: s.interface.clone(),
                            sampled_ms: now,
                        });
                        if let ConnectionState::Connected { peer: old, .. } = &mut l.state
                            && *old != peer
                        {
                            *old = peer;
                            changed = Some(peer);
                        }
                    }
                    match changed {
                        Some(PeerState::Confirmed) => self.log(Level::Info, "Server responded; tunnel confirmed"),
                        Some(PeerState::NoResponse) => self.log(
                            Level::Warn,
                            "No response from the server yet. Check the endpoint, keys, and that UDP is not blocked.",
                        ),
                        _ => {}
                    }
                    self.publish();
                }
                Ok(_) => {
                    self.log(Level::Warn, "Tunnel went down unexpectedly");
                    self.reconnect_loop(id, stop).await;
                    return;
                }
                Err(e) => self.log(Level::Warn, format!("Could not read tunnel status: {e}")),
            }
        }
    }

    async fn reconnect_loop(self: Arc<Self>, id: ProfileId, stop: CancellationToken) {
        let settings = self.settings();
        if !settings.auto_reconnect {
            self.set_state(ConnectionState::Failed {
                profile: Some(id),
                reason: "tunnel went down and automatic reconnection is off".into(),
            });
            return;
        }
        let cancel = CancellationToken::new();
        self.live().op_cancel = cancel.clone();
        let policy = RetryPolicy::new(settings.reconnect_max_attempts);
        let mut attempt = 1;
        while let Some(delay) = policy.delay(attempt) {
            self.set_state(ConnectionState::Reconnecting {
                profile: id,
                attempt,
                next_retry_ms: now_ms() + delay.as_millis() as u64,
            });
            self.log(
                Level::Info,
                format!("Reconnecting (attempt {attempt}) in {}s", delay.as_secs()),
            );
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(delay) => {}
            }
            let _g = self.op_lock.lock().await;
            if cancel.is_cancelled() || stop.is_cancelled() {
                return;
            }
            match self.activate_once(id, &cancel).await {
                Ok(()) => {
                    drop(_g);
                    self.on_connected(id);
                    return;
                }
                Err(CoreError::Cancelled) => return,
                Err(e) => self.log(
                    Level::Warn,
                    format!("Reconnect attempt {attempt} failed: {e}"),
                ),
            }
            attempt += 1;
        }
        let _ = self.backend.deactivate(id).await;
        self.log(Level::Error, "Giving up after repeated reconnect failures");
        self.set_state(ConnectionState::Failed {
            profile: Some(id),
            reason: "reconnect attempts exhausted".into(),
        });
    }

    /// Reconcile with the backend after start-up: adopt a tunnel that is
    /// still up (the UI may have restarted while the tunnel persisted) and
    /// remove backend profiles we no longer track.
    async fn recover(self: &Arc<Self>) {
        if !self.caps.available.is_supported() {
            return;
        }
        let known: Vec<ProfileId> = self.live().profiles.iter().map(|p| p.id).collect();
        match self.backend.installed().await {
            Ok(installed) => {
                for orphan in installed.into_iter().filter(|id| !known.contains(id)) {
                    self.log(Level::Warn, format!("Removing leftover tunnel profile {orphan} from an interrupted operation"));
                    let _ = self.backend.uninstall(orphan).await;
                }
            }
            Err(e) => self.log(Level::Warn, format!("Could not list backend profiles: {e}")),
        }
        if let Ok(Some(s)) = self.backend.status().await
            && known.contains(&s.id)
            && s.link == LinkState::Up
        {
            self.log(
                Level::Info,
                "Found an active tunnel from a previous session",
            );
            self.on_connected(s.id);
        }
    }

    // ---------- diagnostics ----------

    pub async fn diagnostics(&self) -> Vec<crate::diagnostics::Check> {
        crate::diagnostics::run(self).await
    }

    /// The underlying backend (read access for diagnostics and integration tests).
    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub(crate) fn profiles_meta(&self) -> Vec<ProfileMeta> {
        self.live().profiles.clone()
    }
}
