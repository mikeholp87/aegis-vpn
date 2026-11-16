use std::future::Future;

use aegis_config::WgConfig;

use crate::error::Result;
use crate::types::{
    Capabilities, Feature, ProfileId, ProfileSummary, Protection, Settings, TunnelStatus,
};

/// A platform networking backend.
///
/// Backends own the secret material: `install` hands the full configuration
/// to the privileged store (NetworkManager, the Windows service, or memory for
/// the mock) and `load` is the only way to get it back. Implementations must
/// only ever touch tunnels they created.
pub trait VpnBackend: Send + Sync + 'static {
    fn capabilities(&self) -> impl Future<Output = Result<Capabilities>> + Send;

    /// Create or replace a managed profile, including its secrets.
    fn install(
        &self,
        id: ProfileId,
        name: &str,
        cfg: &WgConfig,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Remove a managed profile. Removing a missing profile is not an error.
    fn uninstall(&self, id: ProfileId) -> impl Future<Output = Result<()>> + Send;

    /// Read back a managed profile, including secrets (for edit/export).
    fn load(&self, id: ProfileId) -> impl Future<Output = Result<WgConfig>> + Send;

    /// Ids of all profiles this backend manages (used for crash recovery).
    fn installed(&self) -> impl Future<Output = Result<Vec<ProfileId>>> + Send;

    /// Bring the tunnel up. Resolves once the backend reports the link up,
    /// or with an error. Callers apply their own timeout and cancellation.
    fn activate(&self, id: ProfileId) -> impl Future<Output = Result<()>> + Send;

    /// Bring the tunnel down. Deactivating an inactive profile is not an error.
    fn deactivate(&self, id: ProfileId) -> impl Future<Output = Result<()>> + Send;

    /// Status of the currently active managed tunnel, if any.
    fn status(&self) -> impl Future<Output = Result<Option<TunnelStatus>>> + Send;

    /// Protection actually in effect for an active tunnel. Must never report
    /// more than is really established.
    fn protection(&self, profile: &ProfileSummary, settings: &Settings) -> Protection;

    /// Active check of the running tunnel (route lookups, resolver state).
    /// The engine calls it on every status poll while connected and shows
    /// its result instead of [`Self::protection`]. Default: no active check.
    /// Light check that the server side can reach the internet, run when the
    /// tunnel comes up and then once a minute. Default: not tested (`Off`).
    fn check_reachability(
        &self,
        profile: &ProfileSummary,
        status: &TunnelStatus,
    ) -> impl Future<Output = Feature> + Send {
        let _ = (profile, status);
        async { Feature::Off }
    }

    /// Observe the tunnel's egress IPv4 via the profile DNS (whoami). Run once
    /// when connected. Default: not tested (`Off`).
    fn check_public_ip(
        &self,
        profile: &ProfileSummary,
        status: &TunnelStatus,
    ) -> impl Future<Output = Feature> + Send {
        let _ = (profile, status);
        async { Feature::Off }
    }

    fn verify_protection(
        &self,
        profile: &ProfileSummary,
        settings: &Settings,
        status: &TunnelStatus,
    ) -> impl Future<Output = Protection> + Send {
        let _ = status;
        let p = self.protection(profile, settings);
        async move { p }
    }
}
