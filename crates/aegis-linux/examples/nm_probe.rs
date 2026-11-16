//! Read-only smoke test against the running NetworkManager. Changes nothing.
//! `cargo run -p aegis-linux --example nm_probe`

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    use aegis_core::VpnBackend;
    let b = match aegis_linux::NmBackend::connect().await {
        Ok(b) => b,
        Err(e) => {
            println!("connect: FAIL {e}");
            std::process::exit(1);
        }
    };
    let caps = b.capabilities().await.expect("capabilities");
    println!(
        "connect: OK, NetworkManager {}",
        caps.backend_version.unwrap_or_default()
    );
    println!(
        "installed Aegis profiles: {:?}",
        b.installed().await.map(|v| v.len())
    );
    println!(
        "active Aegis tunnel: {:?}",
        b.status().await.map(|s| s.map(|s| (s.link, s.interface)))
    );
}

#[cfg(not(target_os = "linux"))]
fn main() {}
