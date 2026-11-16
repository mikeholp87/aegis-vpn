use aegis_config::{RouteKind, WgConfig};
use aegis_core::*;
pub struct NmBackend;
impl NmBackend {
    pub async fn connect() -> Result<Self> {
        Err(CoreError::unsupported(
            "NetworkManager backend not built yet",
        ))
    }
}
impl VpnBackend for NmBackend {
    async fn capabilities(&self) -> Result<Capabilities> {
        unimplemented!()
    }
    async fn install(&self, _: ProfileId, _: &str, _: &WgConfig) -> Result<()> {
        unimplemented!()
    }
    async fn uninstall(&self, _: ProfileId) -> Result<()> {
        unimplemented!()
    }
    async fn load(&self, _: ProfileId) -> Result<WgConfig> {
        unimplemented!()
    }
    async fn installed(&self) -> Result<Vec<ProfileId>> {
        unimplemented!()
    }
    async fn activate(&self, _: ProfileId) -> Result<()> {
        unimplemented!()
    }
    async fn deactivate(&self, _: ProfileId) -> Result<()> {
        unimplemented!()
    }
    async fn status(&self) -> Result<Option<TunnelStatus>> {
        unimplemented!()
    }
    fn protection(&self, _: RouteKind, _: &Settings) -> Protection {
        Protection::off()
    }
}
