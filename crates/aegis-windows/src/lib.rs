//! Windows backend (Phase D, not implemented yet).
//!
//! Planned design: a LocalSystem service (`services/windows-service`) that
//! installs per-tunnel `WireGuardTunnel$<name>` services using the official
//! WireGuard embeddable-dll-service (tunnel.dll + wireguard.dll), stores
//! configs DPAPI-encrypted, and talks to this crate over an ACL-restricted
//! named pipe. Until then `connect()` reports the backend as unavailable so
//! the UI shows that honestly instead of pretending to work.

#[cfg(windows)]
mod imp {
    use aegis_config::WgConfig;
    use aegis_core::{
        Capabilities, CoreError, ProfileId, ProfileSummary, Protection, Result, Settings,
        TunnelStatus, VpnBackend,
    };

    pub struct ServiceBackend(());

    fn not_yet() -> CoreError {
        CoreError::unsupported("the Windows tunnel service is not implemented in this build")
    }

    impl ServiceBackend {
        pub async fn connect() -> Result<Self> {
            Err(not_yet())
        }
    }

    // Unreachable: `connect()` never returns a value. Kept so the desktop app
    // compiles on Windows with the same backend enum.
    impl VpnBackend for ServiceBackend {
        async fn capabilities(&self) -> Result<Capabilities> {
            Err(not_yet())
        }
        async fn install(&self, _: ProfileId, _: &str, _: &WgConfig) -> Result<()> {
            Err(not_yet())
        }
        async fn uninstall(&self, _: ProfileId) -> Result<()> {
            Err(not_yet())
        }
        async fn load(&self, _: ProfileId) -> Result<WgConfig> {
            Err(not_yet())
        }
        async fn installed(&self) -> Result<Vec<ProfileId>> {
            Err(not_yet())
        }
        async fn activate(&self, _: ProfileId) -> Result<()> {
            Err(not_yet())
        }
        async fn deactivate(&self, _: ProfileId) -> Result<()> {
            Err(not_yet())
        }
        async fn status(&self) -> Result<Option<TunnelStatus>> {
            Err(not_yet())
        }
        fn protection(&self, _: &ProfileSummary, _: &Settings) -> Protection {
            Protection::off()
        }
    }
}

#[cfg(windows)]
pub use imp::ServiceBackend;
