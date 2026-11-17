//! Security descriptors for the pipe and the config directory. Raw Win32 security
//! calls live here (DPAPI is in `dpapi`).
//!
//! Production DACL, in order:
//! - deny network logons (belt and braces; the pipe also rejects remote clients),
//! - SYSTEM and Administrators: full control,
//! - interactive users: [`IU_ACE`], i.e. `FILE_GENERIC_READ | FILE_GENERIC_WRITE`
//!   minus `FILE_CREATE_PIPE_INSTANCE` (`0x12019b`).
//!
//! `P` blocks inheritance, so nothing is added from a parent object.
//!
//! What the missing bit does (measured on Windows 11, see TEST_RESULTS): Windows
//! checks `FILE_CREATE_PIPE_INSTANCE` when a process calls `CreateNamedPipe` to
//! add an instance of an existing pipe name, not when a client opens the pipe.
//! So a local user can talk to the service but cannot stand up a second server
//! instance of the same name, which would let them impersonate the service and
//! read the configs other clients send. Combined with
//! `FILE_FLAG_FIRST_PIPE_INSTANCE` at startup (nobody can pre-create the name)
//! this closes pipe squatting.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::path::Path;

use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::core::{HSTRING, PCWSTR, PWSTR};

/// Map a `windows` error to `io::Error`, keeping the Win32 code when there is one.
pub fn io_error(e: &windows::core::Error) -> io::Error {
    let hr = e.code().0 as u32;
    if hr >> 16 == 0x8007 {
        io::Error::from_raw_os_error((hr & 0xFFFF) as i32)
    } else {
        io::Error::other(e.message())
    }
}

/// Render `psd` as SDDL for the requested parts, then free the string.
fn descriptor_string(
    psd: PSECURITY_DESCRIPTOR,
    info: OBJECT_SECURITY_INFORMATION,
) -> io::Result<String> {
    let mut out = PWSTR::null();
    // SAFETY: `psd` is a valid descriptor; `out` receives a LocalAlloc'd string.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            info,
            &mut out,
            None,
        )
    }
    .map_err(|e| io_error(&e))?;
    // SAFETY: NUL-terminated string just produced by Windows, freed right after.
    let text = unsafe { out.to_string() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.0.cast::<c_void>())));
    }
    text.map_err(|_| io::Error::other("descriptor text is not valid UTF-16"))
}

/// Create a directory whose DACL (and so its inherited children's) is `sd`.
/// Fails if it already exists.
pub fn create_dir_with(path: &Path, sd: &SecurityDescriptor) -> io::Result<()> {
    let wide = HSTRING::from(
        path.to_str()
            .ok_or_else(|| io::Error::other("path is not valid UTF-8"))?,
    );
    let attrs = sd.attributes();
    // SAFETY: `wide` is NUL-terminated and `attrs` points at a descriptor that
    // outlives the call.
    unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&attrs)) }.map_err(|e| io_error(&e))
}

/// `O:<owner>D:<dacl>` of an existing file or directory, as Windows prints it.
pub fn path_security(path: &Path) -> io::Result<String> {
    let wide = HSTRING::from(
        path.to_str()
            .ok_or_else(|| io::Error::other("path is not valid UTF-8"))?,
    );
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: valid path string and out pointer; the descriptor is freed below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            info,
            None,
            None,
            None,
            None,
            &mut psd,
        )
    };
    if rc.0 != 0 {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    let text = descriptor_string(psd, info);
    // SAFETY: allocated by GetNamedSecurityInfoW with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    text
}

impl SecurityDescriptor {
    /// The DACL as Windows normalizes it (`D:...`), for comparisons.
    pub fn dacl_string(&self) -> io::Result<String> {
        descriptor_string(self.descriptor, DACL_SECURITY_INFORMATION)
    }
}

/// Interactive users: read and write, but not create further pipe instances.
pub const IU_ACE: &str = "(A;;0x12019b;;;IU)";

/// The DACL the service runs with.
pub const PRODUCTION_SDDL: &str = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";

/// Owns the security descriptor allocated by Windows and frees it on drop.
pub struct SecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
}

// The descriptor is immutable after creation and only read by the kernel.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    /// The production DACL.
    pub fn production() -> io::Result<Self> {
        Self::from_sddl(PRODUCTION_SDDL)
    }

    /// Any SDDL string. The service only uses [`PRODUCTION_SDDL`]; tests use
    /// variants so they can run without SYSTEM or administrator rights.
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide = HSTRING::from(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 string and `descriptor`
        // a valid out pointer. On success Windows allocates the descriptor with
        // LocalAlloc; `Drop` frees it.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|e| io::Error::other(format!("invalid pipe security descriptor: {e}")))?;
        Ok(Self { descriptor })
    }

    /// Attributes to pass to `CreateNamedPipe`. Valid while `self` lives.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: false.into(),
        }
    }
}

/// Create one server instance of the pipe with our DACL. `first` sets
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`, which fails if anything else already owns
/// the name, so the service never silently joins a squatter's pipe.
pub fn create_server(
    name: &str,
    security: &SecurityDescriptor,
    first: bool,
    max_instances: usize,
) -> io::Result<NamedPipeServer> {
    let mut attrs = security.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte)
        .max_instances(max_instances);
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES whose descriptor outlives
    // the call; CreateNamedPipe copies the descriptor.
    unsafe { options.create_with_security_attributes_raw(name, (&raw mut attrs).cast::<c_void>()) }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        // via LocalAlloc and not freed elsewhere.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}
