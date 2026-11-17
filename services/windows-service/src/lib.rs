//! The Aegis Windows service: the only privileged Windows code (DECISIONS D16).
//!
//! The desktop app talks to it over a local named pipe using the frame protocol
//! in `aegis_windows::proto`. This crate owns the pipe (with an explicit DACL),
//! decodes requests with bounded input and dispatches them to a [`Handler`].
//!
//! Windows only; other hosts compile an empty crate.

#![cfg_attr(not(windows), allow(unused))]

#[cfg(windows)]
pub mod handler;
#[cfg(windows)]
pub mod security;
#[cfg(windows)]
pub mod server;

#[cfg(windows)]
pub use handler::{Handler, Skeleton};
#[cfg(windows)]
pub use server::serve;
