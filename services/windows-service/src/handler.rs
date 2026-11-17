//! Request handling. [`Handler`] is the seam the pipe server dispatches to, so
//! the server is tested with a fake and the real tunnel code plugs in later.

use std::future::Future;

use aegis_core::{BackendKind, Capabilities, Support};
use aegis_windows::proto::{self, ErrorKind, Request, Response};

pub trait Handler: Send + Sync + 'static {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send;
}

/// What the service can honestly do today: speak the protocol and report that it
/// cannot bring up tunnels. Every capability is `Unsupported` with the reason, so
/// the app blocks connecting instead of pretending (AGENTS.md rule 5). Replaced
/// piece by piece as the real implementation lands.
pub struct Skeleton;

const NOT_YET: &str = "this build of the Aegis service cannot manage tunnels yet";

impl Handler for Skeleton {
    async fn handle(&self, req: Request) -> Response {
        match req {
            Request::Hello { version } if version == proto::VERSION => Response::Ok,
            Request::Hello { version } => Response::Error {
                kind: ErrorKind::Unsupported,
                message: format!(
                    "protocol version {version} is not supported (service speaks {}); \
                     reinstall Aegis VPN so the app and service match",
                    proto::VERSION
                ),
            },
            Request::Capabilities => Response::Capabilities {
                capabilities: Capabilities {
                    backend: BackendKind::WindowsService,
                    simulated: false,
                    backend_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                    available: Support::Unsupported(NOT_YET.into()),
                    kill_switch: Support::Unsupported(NOT_YET.into()),
                    dns_protection: Support::Unsupported(NOT_YET.into()),
                    ipv6_protection: Support::Unsupported(NOT_YET.into()),
                    exact_handshake_time: Support::Unsupported(NOT_YET.into()),
                    notes: Vec::new(),
                },
            },
            // True statements about an empty service.
            Request::Installed => Response::Installed { ids: Vec::new() },
            Request::Status => Response::Status { status: None },
            Request::KillSwitchActive => Response::Active { active: false },
            Request::RemoveKillSwitch | Request::Deactivate { .. } | Request::Uninstall { .. } => {
                Response::Ok
            }
            Request::Load { .. } => Response::Error {
                kind: ErrorKind::NotFound,
                message: "no such profile in the service".into(),
            },
            Request::Install { .. }
            | Request::Activate { .. }
            | Request::ApplyKillSwitch { .. } => Response::Error {
                kind: ErrorKind::Unsupported,
                message: NOT_YET.into(),
            },
        }
    }
}
