//! In-memory simulated backend for UI development and deterministic tests.
//!
//! It never touches the network. Every capability it reports says
//! `simulated: true`, and protection is always `Unsupported`, so the UI can
//! never present a mock connection as real protection.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use aegis_config::WgConfig;

use crate::backend::VpnBackend;
use crate::error::{CoreError, Result};
use crate::types::*;

#[derive(Default)]
struct Inner {
    profiles: HashMap<ProfileId, WgConfig>,
    active: Option<(ProfileId, u64)>,
    fail_next_activate: Option<String>,
    drop_active: bool,
    fail_deactivate: bool,
    fail_status: bool,
    silent_peer: bool,
    reachability_checks: usize,
}

pub struct MockBackend {
    inner: Mutex<Inner>,
    pub activate_delay: Duration,
    pub load_delay: Duration,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            inner: Mutex::default(),
            activate_delay: Duration::from_millis(700),
            load_delay: Duration::ZERO,
        }
    }
}

impl MockBackend {
    pub fn instant() -> Self {
        Self::with_delay(Duration::ZERO)
    }
    pub fn with_delay(activate_delay: Duration) -> Self {
        Self {
            activate_delay,
            ..Default::default()
        }
    }
    /// Test hook: make the next `activate` fail with this message.
    pub fn fail_next_activate(&self, msg: &str) {
        self.lock().fail_next_activate = Some(msg.into());
    }
    /// Test hook: simulate the tunnel disappearing underneath us.
    pub fn drop_tunnel(&self) {
        let mut g = self.lock();
        g.active = None;
        g.drop_active = true;
    }
    pub fn fail_deactivate(&self, fail: bool) {
        self.lock().fail_deactivate = fail;
    }
    pub fn fail_status(&self, fail: bool) {
        self.lock().fail_status = fail;
    }
    /// Test hook: the link is up but the server has not answered (no rx, no handshake).
    pub fn silent_peer(&self, silent: bool) {
        self.lock().silent_peer = silent;
    }
    /// How many times the engine ran the reachability check.
    pub fn reachability_checks(&self) -> usize {
        self.lock().reachability_checks
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

const SIM: &str = "simulated backend: no real tunnel exists";

impl VpnBackend for MockBackend {
    async fn capabilities(&self) -> Result<Capabilities> {
        let u = || Support::Unsupported(SIM.into());
        Ok(Capabilities {
            backend: BackendKind::Mock,
            simulated: true,
            backend_version: None,
            available: Support::Supported,
            kill_switch: u(),
            dns_protection: u(),
            ipv6_protection: u(),
            exact_handshake_time: u(),
            notes: vec!["Running with the simulated backend (AEGIS_BACKEND=mock). Traffic is NOT protected.".into()],
        })
    }

    async fn install(&self, id: ProfileId, _name: &str, cfg: &WgConfig) -> Result<()> {
        self.lock().profiles.insert(id, cfg.clone());
        Ok(())
    }

    async fn uninstall(&self, id: ProfileId) -> Result<()> {
        let mut g = self.lock();
        g.profiles.remove(&id);
        if g.active.map(|a| a.0) == Some(id) {
            g.active = None;
        }
        Ok(())
    }

    async fn load(&self, id: ProfileId) -> Result<WgConfig> {
        tokio::time::sleep(self.load_delay).await;
        self.lock()
            .profiles
            .get(&id)
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn installed(&self) -> Result<Vec<ProfileId>> {
        Ok(self.lock().profiles.keys().copied().collect())
    }

    async fn activate(&self, id: ProfileId) -> Result<()> {
        if !self.lock().profiles.contains_key(&id) {
            return Err(CoreError::NotFound);
        }
        tokio::time::sleep(self.activate_delay).await;
        let mut g = self.lock();
        if let Some(msg) = g.fail_next_activate.take() {
            return Err(CoreError::backend(msg));
        }
        g.active = Some((id, now_ms()));
        g.drop_active = false;
        Ok(())
    }

    async fn deactivate(&self, id: ProfileId) -> Result<()> {
        let mut g = self.lock();
        if g.fail_deactivate {
            return Err(CoreError::backend("simulated deactivation failure"));
        }
        if g.active.map(|a| a.0) == Some(id) {
            g.active = None;
        }
        Ok(())
    }

    async fn status(&self) -> Result<Option<TunnelStatus>> {
        let g = self.lock();
        if g.fail_status {
            return Err(CoreError::backend("simulated status failure"));
        }
        Ok(g.active.map(|(id, since)| {
            // Deterministic synthetic counters so the UI has something to render.
            let secs = now_ms().saturating_sub(since) / 1000;
            TunnelStatus {
                id,
                link: LinkState::Up,
                interface: Some("sim0".into()),
                rx_bytes: if g.silent_peer { 0 } else { secs * 48_000 },
                tx_bytes: secs * 9_000,
                last_handshake_ms: (!g.silent_peer).then_some(since),
            }
        }))
    }

    fn protection(&self, _profile: &ProfileSummary, _settings: &Settings) -> Protection {
        let u = || Feature::Unsupported(SIM.into());
        Protection {
            kill_switch: u(),
            dns: u(),
            ipv6: u(),
        }
    }

    async fn check_reachability(
        &self,
        _profile: &ProfileSummary,
        _status: &TunnelStatus,
    ) -> Feature {
        self.lock().reachability_checks += 1;
        Feature::Unsupported(SIM.into())
    }

    async fn check_public_ip(&self, _profile: &ProfileSummary, _status: &TunnelStatus) -> Feature {
        Feature::Unsupported(SIM.into())
    }
}
