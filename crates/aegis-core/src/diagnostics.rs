//! Diagnostic checks and a sanitized, exportable bundle.
//!
//! The bundle is assembled only from secret-free types (`ProfileMeta`,
//! `Settings`, `Capabilities`, events), so key material cannot appear in it
//! by construction; a test below also scans the output.

use serde::Serialize;

use crate::backend::VpnBackend;
use crate::engine::Engine;
use crate::types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

fn check(
    id: &'static str,
    title: &'static str,
    status: CheckStatus,
    detail: impl Into<String>,
) -> Check {
    Check {
        id,
        title,
        status,
        detail: detail.into(),
    }
}

pub(crate) async fn run<B: VpnBackend>(e: &Engine<B>) -> Vec<Check> {
    use CheckStatus::*;
    let caps = e.capabilities();
    let mut out = vec![match &caps.available {
        Support::Supported if caps.simulated => check(
            "backend",
            "VPN backend",
            Warn,
            "simulated backend: no real tunnels are created",
        ),
        Support::Supported => check(
            "backend",
            "VPN backend",
            Pass,
            format!(
                "{:?} {}",
                caps.backend,
                caps.backend_version.clone().unwrap_or_default()
            ),
        ),
        Support::Unsupported(m) => check("backend", "VPN backend", Fail, m.clone()),
    }];

    let profiles = e.profiles_meta();
    let with_warnings = profiles
        .iter()
        .filter(|p| !p.summary.warnings.is_empty())
        .count();
    out.push(check(
        "profiles",
        "Profiles",
        if profiles.is_empty() {
            Skipped
        } else if with_warnings > 0 {
            Warn
        } else {
            Pass
        },
        if profiles.is_empty() {
            "no profiles imported".to_string()
        } else {
            format!(
                "{} profile(s), {} with warnings",
                profiles.len(),
                with_warnings
            )
        },
    ));

    match e.backend().installed().await {
        Ok(ids) => {
            let missing: Vec<_> = profiles
                .iter()
                .filter(|p| !ids.contains(&p.id))
                .map(|p| p.name.clone())
                .collect();
            out.push(if missing.is_empty() {
                check(
                    "store",
                    "Secret storage",
                    Pass,
                    "every profile has its configuration in the backend store",
                )
            } else {
                check(
                    "store",
                    "Secret storage",
                    Fail,
                    format!(
                        "missing from backend store (re-import needed): {}",
                        missing.join(", ")
                    ),
                )
            });
        }
        Err(err) => out.push(check("store", "Secret storage", Fail, err.to_string())),
    }

    let snap = e.snapshot();
    match (&snap.state, &snap.stats) {
        (ConnectionState::Connected { peer, .. }, stats) => {
            out.push(check(
                "tunnel",
                "Tunnel interface",
                Pass,
                stats
                    .as_ref()
                    .and_then(|s| s.interface.clone())
                    .unwrap_or_else(|| "up".into()),
            ));
            let (st, d) = match peer {
                PeerState::Confirmed => (
                    Pass,
                    "server responded (handshake or authenticated data received)",
                ),
                PeerState::Pending => (Warn, "no data received from the server yet"),
                PeerState::NoResponse => (
                    Fail,
                    "data sent but nothing received: check endpoint, keys, firewall",
                ),
            };
            out.push(check("handshake", "Server response", st, d));
            if let Some(s) = stats {
                let hs = match s.last_handshake_ms {
                    Some(t) => format!("last handshake {}s ago", now_ms().saturating_sub(t) / 1000),
                    None => match &caps.exact_handshake_time {
                        Support::Supported => "no handshake yet".into(),
                        Support::Unsupported(m) => format!("handshake time unavailable: {m}"),
                    },
                };
                out.push(check(
                    "counters",
                    "Transfer counters",
                    Pass,
                    format!("rx {} B, tx {} B; {hs}", s.rx_bytes, s.tx_bytes),
                ));
            }
        }
        (state, _) => {
            let d = format!(
                "not connected ({})",
                serde_json::to_value(state)
                    .ok()
                    .and_then(|v| v["state"].as_str().map(str::to_owned))
                    .unwrap_or_default()
            );
            out.push(check("tunnel", "Tunnel interface", Skipped, d));
        }
    }

    for (id, title, s) in [
        ("kill_switch", "Kill switch", &snap.protection.kill_switch),
        ("dns", "DNS leak protection", &snap.protection.dns),
        ("ipv6", "IPv6 protection", &snap.protection.ipv6),
    ] {
        let (st, d) = match s {
            Feature::Off => (Skipped, "off or not connected".to_string()),
            Feature::Unsupported(m) => (Warn, format!("unsupported: {m}")),
            Feature::Configured(m) => {
                (Warn, format!("configured, not independently verified: {m}"))
            }
            Feature::Verified(m) => (Pass, m.clone()),
            Feature::Failed(m) => (Fail, m.clone()),
        };
        out.push(check(id, title, st, d));
    }
    out.push(check(
        "reachability",
        "Internet reachability",
        Skipped,
        "not tested: Aegis makes no external requests unless you enable a check",
    ));
    out
}

#[derive(Serialize)]
struct Bundle<'a> {
    generated_ms: u64,
    app_version: &'a str,
    os: &'static str,
    arch: &'static str,
    capabilities: &'a Capabilities,
    settings: Settings,
    profiles: Vec<ProfileMeta>,
    snapshot: Snapshot,
    checks: Vec<Check>,
    events: Vec<LogEntry>,
}

/// JSON diagnostic bundle. Contains public keys and endpoints (useful for
/// support) but never private or preshared keys.
pub async fn bundle<B: VpnBackend>(e: &Engine<B>, app_version: &str) -> String {
    let b = Bundle {
        generated_ms: now_ms(),
        app_version,
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        capabilities: e.capabilities(),
        settings: e.settings(),
        profiles: e.profiles_meta(),
        snapshot: e.snapshot(),
        checks: run(e).await,
        events: e.events(),
    };
    serde_json::to_string_pretty(&b).unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"))
}
