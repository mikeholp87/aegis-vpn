//! The named pipe's security descriptor. The only `unsafe` code in the crate.
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

use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::core::{HSTRING, PCWSTR};

/// Interactive users: read and write, but not create further pipe instances.
pub const IU_ACE: &str = "(A;;0x12019b;;;IU)";

/// The DACL the service runs with.
pub const PRODUCTION_SDDL: &str = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";

/// Owns the security descriptor allocated by Windows and frees it on drop.
pub struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
}

// The descriptor is immutable after creation and only read by the kernel.
unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

impl PipeSecurity {
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
    security: &PipeSecurity,
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

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        // via LocalAlloc and not freed elsewhere.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}
