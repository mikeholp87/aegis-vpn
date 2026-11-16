//! Linux backend: WireGuard tunnels managed through NetworkManager.

#[cfg(target_os = "linux")]
mod nm;
#[cfg(target_os = "linux")]
pub mod settings;
#[cfg(target_os = "linux")]
pub mod verify;

#[cfg(target_os = "linux")]
pub use nm::NmBackend;
