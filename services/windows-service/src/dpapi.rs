//! DPAPI, compatible with what `tunnel.dll` reads: `CryptProtectData` with the
//! tunnel name as the description, `CRYPTPROTECT_UI_FORBIDDEN`, no extra entropy,
//! user scope of the calling account. The tunnel service and this service both
//! run as LocalSystem, so what we protect it can unprotect. It rejects a blob
//! whose stored description differs from the name, and so do we.
//!
//! Plaintext lives only in zeroizing buffers.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use zeroize::{Zeroize, Zeroizing};

fn blob(bytes: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len())
            .map_err(|_| io::Error::other("data too large for DPAPI"))?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

/// Copy a LocalAlloc'd output blob into a Vec, wipe the original, free it.
///
/// # Safety
/// `out` must be an output blob filled in by a successful DPAPI call.
unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
    if out.pbData.is_null() {
        return Zeroizing::new(Vec::new());
    }
    // SAFETY: per the contract, pbData points to cbData bytes we now own.
    let src = unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) };
    let copy = Zeroizing::new(src.to_vec());
    src.zeroize();
    // SAFETY: the buffer was allocated by DPAPI with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.pbData.cast::<c_void>())));
    }
    copy
}

pub fn protect(data: &[u8], description: &str) -> io::Result<Vec<u8>> {
    let input = blob(data)?;
    let descr = HSTRING::from(description);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` borrows `data` for the call; `descr` is NUL-terminated;
    // `out` is a valid out parameter that `take` consumes.
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR(descr.as_ptr()),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    }
    .map_err(|e| io::Error::other(format!("DPAPI protect failed: {e}")))?;
    // SAFETY: filled in by the successful call above. The ciphertext is not
    // secret, but `take` hands back a Zeroizing buffer; copy it out.
    Ok(unsafe { take(out) }.to_vec())
}

/// Decrypt, requiring the stored description to equal `expected_description`.
pub fn unprotect(encrypted: &[u8], expected_description: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    let input = blob(encrypted)?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    let mut descr = PWSTR::null();
    // SAFETY: as above; `descr` receives a LocalAlloc'd string freed below.
    unsafe {
        CryptUnprotectData(
            &input,
            Some(&mut descr),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    }
    .map_err(|e| io::Error::other(format!("DPAPI unprotect failed: {e}")))?;
    // SAFETY: filled in by the successful call above.
    let plain = unsafe { take(out) };

    let stored = if descr.is_null() {
        None
    } else {
        // SAFETY: NUL-terminated string allocated by DPAPI, freed right after.
        let s = unsafe { descr.to_string() }.ok();
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descr.0.cast::<c_void>())));
        }
        s
    };
    if stored.as_deref() != Some(expected_description) {
        return Err(io::Error::other(
            "stored config belongs to a different tunnel name",
        ));
    }
    Ok(plain)
}
