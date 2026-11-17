//! `aegis-tunnel.exe /service <config.conf.dpapi>`: the process each
//! `WireGuardTunnel$aegis-…` Windows service runs. Loads `tunnel.dll` from its own
//! directory and runs the official WireGuard tunnel service on the config.

#[cfg(not(windows))]
fn main() {
    eprintln!("aegis-tunnel only runs on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use aegis_service::tunnel_dll::{TunnelDll, restrict_dll_search};
    use aegis_service::tunnel_host::parse_args;

    let code = (|| -> Result<bool, String> {
        restrict_dll_search().map_err(|e| format!("cannot restrict DLL search: {e}"))?;
        let programdata = std::env::var_os("ProgramData").ok_or("ProgramData is not set")?;
        let config_dir = PathBuf::from(programdata).join("Aegis VPN");
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        let config = parse_args(&args, &config_dir).map_err(|e| e.to_string())?;

        let exe = std::env::current_exe().map_err(|e| format!("cannot find own path: {e}"))?;
        let dll = exe
            .parent()
            .ok_or("own path has no directory")?
            .join("tunnel.dll");
        let tunnel = TunnelDll::load(&dll).map_err(|e| format!("cannot load tunnel.dll: {e}"))?;
        Ok(tunnel.run(&config))
    })();
    match code {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(message) => {
            // No config text or key can be in these messages.
            eprintln!("aegis-tunnel: {message}");
            std::process::exit(2);
        }
    }
}
