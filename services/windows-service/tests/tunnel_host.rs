//! `aegis-tunnel` argument validation and `tunnel.dll` loading.
#![cfg(windows)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use aegis_core::ProfileId;
use aegis_service::tunnel_dll::TunnelDll;
use aegis_service::tunnel_host::{ArgError, parse_args};
use aegis_windows::names;

const DIR: &str = r"C:\ProgramData\Aegis VPN";

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

fn good_file() -> String {
    format!(r"{DIR}\{}.conf.dpapi", names::tunnel_name(ProfileId::new()))
}

#[test]
fn accepts_exactly_one_of_our_configs() {
    let file = good_file();
    let got = parse_args(&args(&["/service", &file]), Path::new(DIR)).expect("valid");
    assert_eq!(got, PathBuf::from(&file));
    // Directories are case-insensitive on Windows; the file name stays exact.
    let shouting = file.replacen(DIR, &DIR.to_uppercase(), 1);
    assert_ne!(shouting, file);
    parse_args(&args(&["/service", &shouting]), Path::new(DIR)).expect("case-insensitive dir");
    // An upper-case tunnel name is not one of ours.
    let name = names::tunnel_name(ProfileId::new()).to_uppercase();
    let loud = format!(r"{DIR}\{name}.conf.dpapi");
    assert_eq!(
        parse_args(&args(&["/service", &loud]), Path::new(DIR)),
        Err(ArgError::WrongName)
    );
}

#[test]
fn refuses_everything_else() {
    let dir = Path::new(DIR);
    let name = names::tunnel_name(ProfileId::new());
    let cases: Vec<(Vec<OsString>, ArgError)> = vec![
        (args(&[]), ArgError::Usage),
        (args(&["/service"]), ArgError::Usage),
        (args(&["/run", &good_file()]), ArgError::Usage),
        (args(&["/service", &good_file(), "extra"]), ArgError::Usage),
        (
            args(&["/service", &format!(r"{name}.conf.dpapi")]),
            ArgError::NotAbsolute,
        ),
        (
            args(&["/service", &format!(r"{DIR}\..\{name}.conf.dpapi")]),
            ArgError::SpecialComponent,
        ),
        (
            args(&["/service", &format!(r"C:\Users\Public\{name}.conf.dpapi")]),
            ArgError::WrongDirectory,
        ),
        (
            args(&["/service", &format!(r"{DIR}\sub\{name}.conf.dpapi")]),
            ArgError::WrongDirectory,
        ),
        (
            args(&["/service", &format!(r"{DIR}\{name}.conf")]), // plaintext
            ArgError::WrongName,
        ),
        (
            args(&["/service", &format!(r"{DIR}\wg0.conf.dpapi")]), // not ours
            ArgError::WrongName,
        ),
        (
            args(&["/service", &format!(r"{DIR}\{name}.conf.dpapi.exe")]),
            ArgError::WrongName,
        ),
        (
            args(&["/service", &format!(r"{DIR}\.conf.dpapi")]),
            ArgError::WrongName,
        ),
    ];
    for (input, expected) in cases {
        let got = parse_args(&input, dir);
        assert_eq!(got, Err(expected), "{input:?}");
    }
}

#[test]
fn loading_refuses_relative_missing_and_wrong_dlls() {
    // Relative path: never searched for.
    assert!(TunnelDll::load(Path::new("tunnel.dll")).is_err());
    // Does not exist.
    assert!(TunnelDll::load(Path::new(r"C:\no\such\dir\tunnel.dll")).is_err());
    // A real DLL without our export is refused with a clear message, not called.
    let e = TunnelDll::load(Path::new(r"C:\Windows\System32\kernel32.dll"))
        .err()
        .expect("kernel32 has no WireGuardTunnelService");
    assert!(e.to_string().contains("WireGuardTunnelService"), "{e}");
}

/// Loads the real tunnel.dll (a Go runtime starts inside this process) but does
/// NOT call it: outside the SCM it would try to run as a service. Point
/// `AEGIS_TUNNEL_DLL` at an absolute path and run with `-- --ignored`.
#[test]
#[ignore = "needs AEGIS_TUNNEL_DLL=<absolute path to tunnel.dll>"]
fn the_real_tunnel_dll_loads_and_exports_the_entry_point() {
    let path = std::env::var_os("AEGIS_TUNNEL_DLL").expect("set AEGIS_TUNNEL_DLL");
    TunnelDll::load(Path::new(&path)).expect("real tunnel.dll loads and exports the entry point");
}
