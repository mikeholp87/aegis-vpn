//! Runtime backend selection. The simulated backend is only ever used when
//! explicitly requested with `AEGIS_BACKEND=mock`; if no real backend works we
//! report that instead of silently pretending.

use aegis_config::{RouteKind, WgConfig};
use aegis_core::mock::MockBackend;
use aegis_core::{
    BackendKind, Capabilities, CoreError, ProfileId, Protection, Result, Settings, Support,
    TunnelStatus, VpnBackend,
};

pub enum AnyBackend {
    Mock(MockBackend),
    #[cfg(target_os = "linux")]
    Nm(aegis_linux::NmBackend),
    #[cfg(windows)]
    Win(aegis_windows::ServiceBackend),
    Unavailable(String),
}

pub async fn select() -> AnyBackend {
    if std::env::var("AEGIS_BACKEND").as_deref() == Ok("mock") {
        tracing::warn!("using the simulated backend (AEGIS_BACKEND=mock)");
        return AnyBackend::Mock(MockBackend::default());
    }
    #[cfg(target_os = "linux")]
    {
        match aegis_linux::NmBackend::connect().await {
            Ok(b) => AnyBackend::Nm(b),
            Err(e) => AnyBackend::Unavailable(e.to_string()),
        }
    }
    #[cfg(windows)]
    {
        match aegis_windows::ServiceBackend::connect().await {
            Ok(b) => AnyBackend::Win(b),
            Err(e) => AnyBackend::Unavailable(e.to_string()),
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        AnyBackend::Unavailable("this operating system is not supported".into())
    }
}

fn unavailable(reason: &str) -> CoreError {
    CoreError::unsupported(format!("no VPN backend is available: {reason}"))
}

macro_rules! delegate {
    ($self:ident, $b:ident => $call:expr) => {
        match $self {
            AnyBackend::Mock($b) => $call,
            #[cfg(target_os = "linux")]
            AnyBackend::Nm($b) => $call,
            #[cfg(windows)]
            AnyBackend::Win($b) => $call,
            AnyBackend::Unavailable(r) => Err(unavailable(r)),
        }
    };
}

impl VpnBackend for AnyBackend {
    async fn capabilities(&self) -> Result<Capabilities> {
        if let AnyBackend::Unavailable(reason) = self {
            let u = || Support::Unsupported("no backend".into());
            return Ok(Capabilities {
                backend: BackendKind::None,
                simulated: false,
                backend_version: None,
                available: Support::Unsupported(reason.clone()),
                kill_switch: u(),
                dns_protection: u(),
                ipv6_protection: u(),
                exact_handshake_time: u(),
                notes: vec![],
            });
        }
        delegate!(self, b => b.capabilities().await)
    }
    async fn install(&self, id: ProfileId, name: &str, cfg: &WgConfig) -> Result<()> {
        delegate!(self, b => b.install(id, name, cfg).await)
    }
    async fn uninstall(&self, id: ProfileId) -> Result<()> {
        delegate!(self, b => b.uninstall(id).await)
    }
    async fn load(&self, id: ProfileId) -> Result<WgConfig> {
        delegate!(self, b => b.load(id).await)
    }
    async fn installed(&self) -> Result<Vec<ProfileId>> {
        if matches!(self, AnyBackend::Unavailable(_)) {
            return Ok(vec![]);
        }
        delegate!(self, b => b.installed().await)
    }
    async fn activate(&self, id: ProfileId) -> Result<()> {
        delegate!(self, b => b.activate(id).await)
    }
    async fn deactivate(&self, id: ProfileId) -> Result<()> {
        delegate!(self, b => b.deactivate(id).await)
    }
    async fn status(&self) -> Result<Option<TunnelStatus>> {
        if matches!(self, AnyBackend::Unavailable(_)) {
            return Ok(None);
        }
        delegate!(self, b => b.status().await)
    }
    fn protection(&self, route: RouteKind, settings: &Settings) -> Protection {
        match self {
            AnyBackend::Mock(b) => b.protection(route, settings),
            #[cfg(target_os = "linux")]
            AnyBackend::Nm(b) => b.protection(route, settings),
            #[cfg(windows)]
            AnyBackend::Win(b) => b.protection(route, settings),
            AnyBackend::Unavailable(_) => Protection::off(),
        }
    }
}
