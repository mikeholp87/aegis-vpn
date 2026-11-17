//! Windows backend. The app never touches the network stack itself: it talks
//! to the LocalSystem service (`services/windows-service`) over a named pipe
//! (`proto`). The service stores configs DPAPI-encrypted, installs one
//! official `WireGuardTunnel$aegis-…` service per tunnel (tunnel.dll) and
//! owns the kill switch. See DECISIONS D16 for the design and its status.
//!
//! `proto` and `names` are portable and unit-tested everywhere. `ServiceBackend`
//! is Windows-only and has been compiled but not run (no Windows machine yet).

pub mod names;
pub mod proto;

#[cfg(windows)]
mod imp {
    use std::net::SocketAddr;
    use std::time::Duration;

    use aegis_config::WgConfig;
    use aegis_core::{
        Capabilities, CoreError, ProfileId, ProfileSummary, Protection, Result, Settings,
        TunnelStatus, VpnBackend,
    };
    use tokio::net::windows::named_pipe::ClientOptions;

    use crate::proto::{self, PIPE_NAME, Request, Response, SecretText};

    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PIPE_BUSY: i32 = 231;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const CALL_TIMEOUT: Duration = Duration::from_secs(60);

    pub struct ServiceBackend(());

    fn unavailable() -> CoreError {
        CoreError::unsupported(
            "the Aegis Windows service is not running. Reinstall Aegis VPN, or start the \
             \"Aegis VPN\" service from services.msc as an administrator",
        )
    }

    fn pipe_error(e: std::io::Error) -> CoreError {
        match e.raw_os_error() {
            Some(ERROR_FILE_NOT_FOUND) => unavailable(),
            Some(ERROR_ACCESS_DENIED) => CoreError::PermissionDenied {
                message: "the Aegis service refused this user. Only members of the local \
                          Users group of an interactive session may control it"
                    .into(),
            },
            _ => CoreError::backend(format!("cannot reach the Aegis service: {e}")),
        }
    }

    async fn call(req: Request) -> Result<Response> {
        tokio::time::timeout(CALL_TIMEOUT, async {
            // Every busy pipe instance is retried briefly; the service keeps a free instance.
            let mut pipe = None;
            for _ in 0..20 {
                match ClientOptions::new().open(PIPE_NAME) {
                    Ok(p) => {
                        pipe = Some(p);
                        break;
                    }
                    Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => return Err(pipe_error(e)),
                }
            }
            let mut pipe = pipe.ok_or_else(|| CoreError::backend("the Aegis service is busy"))?;
            proto::write_frame(&mut pipe, &req)
                .await
                .map_err(CoreError::backend)?;
            let reply = proto::read_frame::<_, Response>(&mut pipe)
                .await
                .map_err(CoreError::backend)?
                .ok_or_else(|| CoreError::backend("the Aegis service closed the connection"))?;
            reply.into_result()
        })
        .await
        .map_err(|_| CoreError::Timeout {
            what: "the Aegis service".into(),
            seconds: CALL_TIMEOUT.as_secs(),
        })?
    }

    async fn expect_ok(req: Request) -> Result<()> {
        match call(req).await? {
            Response::Ok => Ok(()),
            _ => Err(CoreError::backend(
                "unexpected reply from the Aegis service",
            )),
        }
    }

    impl ServiceBackend {
        /// Reaches the service and checks the protocol version. Errors say how to fix it.
        pub async fn connect() -> Result<Self> {
            expect_ok(Request::Hello {
                version: proto::VERSION,
            })
            .await?;
            Ok(Self(()))
        }
    }

    impl VpnBackend for ServiceBackend {
        async fn capabilities(&self) -> Result<Capabilities> {
            match call(Request::Capabilities).await? {
                Response::Capabilities { capabilities } => Ok(capabilities),
                _ => Err(CoreError::backend(
                    "unexpected reply from the Aegis service",
                )),
            }
        }
        async fn install(&self, id: ProfileId, name: &str, cfg: &WgConfig) -> Result<()> {
            let config = SecretText::new(cfg.to_wg_quick().to_string());
            expect_ok(Request::Install {
                id,
                name: name.to_owned(),
                config,
            })
            .await
        }
        async fn uninstall(&self, id: ProfileId) -> Result<()> {
            expect_ok(Request::Uninstall { id }).await
        }
        async fn load(&self, id: ProfileId) -> Result<WgConfig> {
            match call(Request::Load { id }).await? {
                Response::Config { config } => {
                    aegis_config::parse(config.expose()).map_err(CoreError::Config)
                }
                _ => Err(CoreError::backend(
                    "unexpected reply from the Aegis service",
                )),
            }
        }
        async fn installed(&self) -> Result<Vec<ProfileId>> {
            match call(Request::Installed).await? {
                Response::Installed { ids } => Ok(ids),
                _ => Err(CoreError::backend(
                    "unexpected reply from the Aegis service",
                )),
            }
        }
        async fn activate(&self, id: ProfileId) -> Result<()> {
            expect_ok(Request::Activate { id }).await
        }
        async fn deactivate(&self, id: ProfileId) -> Result<()> {
            expect_ok(Request::Deactivate { id }).await
        }
        async fn status(&self) -> Result<Option<TunnelStatus>> {
            match call(Request::Status).await? {
                Response::Status { status } => Ok(status),
                _ => Err(CoreError::backend(
                    "unexpected reply from the Aegis service",
                )),
            }
        }
        /// Nothing is reported as protected until the service verifies it
        /// (`verify_protection` is not implemented for Windows yet).
        fn protection(&self, _: &ProfileSummary, _: &Settings) -> Protection {
            Protection::off()
        }
        async fn apply_kill_switch(
            &self,
            id: ProfileId,
            endpoints: &[SocketAddr],
            allow_lan: bool,
        ) -> Result<()> {
            expect_ok(Request::ApplyKillSwitch {
                id,
                endpoints: endpoints.to_vec(),
                allow_lan,
            })
            .await
        }
        async fn remove_kill_switch(&self) -> Result<()> {
            expect_ok(Request::RemoveKillSwitch).await
        }
        async fn kill_switch_active(&self) -> bool {
            matches!(
                call(Request::KillSwitchActive).await,
                Ok(Response::Active { active: true })
            )
        }
    }
}

#[cfg(windows)]
pub use imp::ServiceBackend;
