//! Prints OS events (resume, network switch) as the Linux backend sees them.
//! Read-only. Usage: events_probe [seconds]  (default 30)
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use aegis_core::VpnBackend as _;
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let backend = aegis_linux::NmBackend::connect()
        .await
        .expect("NetworkManager");
    let mut rx = backend.system_events().expect("events available once");
    let start = std::time::Instant::now();
    println!("listening for {secs}s");
    let end = tokio::time::sleep(std::time::Duration::from_secs(secs));
    tokio::pin!(end);
    loop {
        tokio::select! {
            _ = &mut end => break,
            ev = rx.recv() => match ev {
                Some(e) => println!("{:>5.1}s {e:?}", start.elapsed().as_secs_f32()),
                None => break,
            },
        }
    }
    println!("done");
}
#[cfg(not(target_os = "linux"))]
fn main() {}
