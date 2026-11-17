//! `aegis-service service`  run under the Service Control Manager (LocalSystem)
//! `aegis-service console`  run in the foreground for development (Ctrl-C stops)

#[cfg(not(windows))]
fn main() {
    eprintln!("aegis-service only runs on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    app::main();
}

#[cfg(windows)]
mod app {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use aegis_service::server::PipeServer;
    use aegis_service::store::{ConfigStore, DirPolicy};
    use aegis_service::{Service, Skeleton, serve};
    use aegis_windows::proto::PIPE_NAME;
    use tokio_util::sync::CancellationToken;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    /// Must match the name the installer registers with the SCM.
    const SERVICE_NAME: &str = "AegisVpnService";

    define_windows_service!(ffi_service_main, service_main);

    pub fn main() {
        match std::env::args().nth(1).as_deref() {
            Some("service") => {
                if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
                    eprintln!("not started by the Service Control Manager: {e}");
                    std::process::exit(1);
                }
            }
            Some("console") => console(),
            _ => {
                eprintln!("usage: aegis-service service | console");
                std::process::exit(2);
            }
        }
    }

    fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
    }

    fn console() {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "aegis_service=debug".into()),
            )
            .init();
        let result = runtime().and_then(|rt| {
            rt.block_on(async {
                let shutdown = CancellationToken::new();
                let stop = shutdown.clone();
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    stop.cancel();
                });
                serve(PIPE_NAME, Arc::new(Skeleton), shutdown).await
            })
        });
        if let Err(e) = result {
            eprintln!("service failed: {e}");
            std::process::exit(1);
        }
    }

    fn service_main(_args: Vec<OsString>) {
        // No stderr under the SCM; file logging arrives with the config store.
        let _ = run_service();
    }

    fn status(state: ServiceState, exit: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }

    /// `%ProgramData%\Aegis VPN`. The service runs as LocalSystem, whose
    /// environment is set by Windows, not by a user.
    fn config_dir() -> std::io::Result<PathBuf> {
        let base = std::env::var_os("ProgramData")
            .ok_or_else(|| std::io::Error::other("ProgramData is not set"))?;
        Ok(PathBuf::from(base).join("Aegis VPN"))
    }

    fn run_service() -> windows_service::Result<()> {
        let shutdown = CancellationToken::new();
        let on_stop = shutdown.clone();
        let handle =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    on_stop.cancel();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;

        // Report Running only once the config directory is verified and the pipe
        // is really ours.
        let outcome = runtime().and_then(|rt| {
            rt.block_on(async {
                let store = ConfigStore::open(config_dir()?, &DirPolicy::production())
                    .map_err(std::io::Error::other)?;
                let server = PipeServer::bind(PIPE_NAME)?;
                handle
                    .set_service_status(status(ServiceState::Running, 0))
                    .map_err(std::io::Error::other)?;
                server.run(Arc::new(Service::new(store)), shutdown).await
            })
        });
        handle.set_service_status(status(
            ServiceState::Stopped,
            if outcome.is_ok() { 0 } else { 1 },
        ))?;
        Ok(())
    }
}
