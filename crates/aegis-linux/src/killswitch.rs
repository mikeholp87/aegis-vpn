//! Kill switch through the root helper (`services/linux-helper`), started
//! with pkexec. The app itself never gains privileges: it passes validated
//! arguments and reads an unprivileged marker file the helper maintains.

use std::path::Path;
use std::process::{Command, Stdio};

use aegis_core::{CoreError, Result, Support};

pub const HELPER: &str = "/usr/libexec/aegis-vpn/aegis-helper";
pub const POLICY: &str = "/usr/share/polkit-1/actions/org.aegisvpn.helper.policy";
const PKEXEC: &str = "/usr/bin/pkexec";
const NFT: &str = "/usr/sbin/nft";
const WG: &str = "/usr/bin/wg";
/// Written by the helper while blocking; /run is cleared on reboot, like the rules.
const MARKER: &str = "/run/aegis-vpn/kill-switch";

pub fn support() -> Support {
    let missing: Vec<&str> = [
        (HELPER, "the Aegis helper"),
        (POLICY, "its Polkit policy"),
        (PKEXEC, "pkexec"),
        (NFT, "nftables (nft)"),
    ]
    .into_iter()
    .filter(|(path, _)| !Path::new(path).is_file())
    .map(|(_, what)| what)
    .collect();
    if missing.is_empty() {
        Support::Supported
    } else {
        Support::Unsupported(format!(
            "missing {}. Packages install the helper; from source run \
             `cargo build --release -p aegis-helper && sudo scripts/install-helper.sh install target/release/aegis-helper`",
            missing.join(", ")
        ))
    }
}

pub fn active() -> bool {
    Path::new(MARKER).is_file()
}

/// Handshake times need the helper (root) and `wg`.
pub fn handshake_support() -> Support {
    if !matches!(support(), Support::Supported) {
        return Support::Unsupported(
            "reading WireGuard handshake times needs the Aegis helper (see the kill switch note)"
                .into(),
        );
    }
    if Path::new(WG).is_file() {
        Support::Supported
    } else {
        Support::Unsupported(
            "reading WireGuard handshake times needs wireguard-tools (`wg`); Aegis infers a server response from received data"
                .into(),
        )
    }
}

pub async fn run(args: Vec<String>) -> Result<()> {
    run_capture(args).await.map(|_| ())
}

/// Run the helper through pkexec and return its stdout. Blocking work happens
/// off the async runtime.
pub async fn run_capture(args: Vec<String>) -> Result<String> {
    let out = tokio::task::spawn_blocking(move || {
        Command::new(PKEXEC)
            .arg(HELPER)
            .args(&args)
            .stdin(Stdio::null())
            .output()
    })
    .await
    .map_err(|e| CoreError::backend(format!("kill-switch helper task failed: {e}")))?
    .map_err(|e| CoreError::unsupported(format!("cannot run pkexec: {e}")))?;
    match out.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        // pkexec: 126 = not authorized or dialog dismissed, 127 = authentication failed.
        Some(126 | 127) => Err(CoreError::PermissionDenied {
            message: "permission to change the kill switch was refused. Polkit allows the user of the \
                      active desktop session; remote or non-graphical sessions need an administrator."
                .into(),
        }),
        _ => {
            let err = String::from_utf8_lossy(&out.stderr);
            let msg = err.trim().trim_start_matches("aegis-helper: ");
            Err(CoreError::backend(format!("the kill-switch helper failed: {msg}")))
        }
    }
}
