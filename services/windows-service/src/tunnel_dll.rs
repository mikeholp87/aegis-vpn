//! Loading `tunnel.dll` safely and calling its one entry point.
//!
//! THREAT_MODEL lists DLL search-path attacks. The defences here:
//! - [`restrict_dll_search`] drops the current directory and `PATH` from the
//!   search order for the whole process (`SetDefaultDllDirectories`);
//! - the DLL is loaded by **absolute path** beside this exe, with
//!   `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`, so its own
//!   dependency (`wireguard.dll`) resolves from that directory or System32 only.
//!
//! Whether the install directory itself is writable only by administrators is
//! the installer's job (Step 6).

#![allow(unsafe_code)]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW, SetDefaultDllDirectories,
};
use windows::core::{HSTRING, PCWSTR, s};

pub fn restrict_dll_search() -> io::Result<()> {
    // SAFETY: plain flag argument.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) }
        .map_err(|e| crate::security::io_error(&e))
}

/// `WireGuardTunnelService(LPCWSTR conf_file) -> bool`, from tunnel.dll.
type TunnelServiceFn = unsafe extern "C" fn(*const u16) -> u8;

pub struct TunnelDll {
    entry: TunnelServiceFn,
}

impl TunnelDll {
    /// `path` must be absolute.
    pub fn load(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::other("tunnel.dll path must be absolute"));
        }
        let wide = HSTRING::from(
            path.to_str()
                .ok_or_else(|| io::Error::other("path is not valid UTF-8"))?,
        );
        // SAFETY: NUL-terminated absolute path; flags as documented above.
        let module = unsafe {
            LoadLibraryExW(
                PCWSTR(wide.as_ptr()),
                None,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }
        .map_err(|e| crate::security::io_error(&e))?;
        // SAFETY: `module` is a valid loaded module.
        let Some(proc) = (unsafe { GetProcAddress(module, s!("WireGuardTunnelService")) }) else {
            // Not unloaded, for the same reason as above (it may be a Go DLL).
            return Err(io::Error::other(
                "tunnel.dll does not export WireGuardTunnelService",
            ));
        };
        // SAFETY: the export has this signature (tunnel.h from the same build).
        let entry = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, TunnelServiceFn>(proc)
        };
        Ok(Self { entry })
    }

    /// Run the tunnel service for `config`. Blocks until the service stops.
    /// Returns what the DLL returns: true when it ran and stopped cleanly.
    pub fn run(&self, config: &Path) -> bool {
        let wide: Vec<u16> = config
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        unsafe { (self.entry)(wide.as_ptr()) != 0 }
    }
}

// Deliberately no `Drop` that calls `FreeLibrary`. tunnel.dll is a Go c-shared
// library, and a Go runtime cannot be unloaded: its threads keep running code
// inside the DLL. Measured: unloading it crashed the process with
// STATUS_ACCESS_VIOLATION (0xC0000005) at exit. The module stays loaded until
// the process ends, which is what this short-lived host process wants anyway.
