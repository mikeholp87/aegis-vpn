//! Argument rules for `aegis-tunnel`, the exe the official-style tunnel service
//! runs as `aegis-tunnel.exe /service <config>` (DECISIONS D16). It loads
//! `tunnel.dll` and hands it the config path; see [`crate::tunnel_dll`].
//!
//! The service is started by the SCM with a command line we registered, but the
//! exe still refuses anything that is not exactly one of our own encrypted
//! configs in our own directory, so it cannot be pointed at another file.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use aegis_windows::names;

const SUFFIX: &str = ".conf.dpapi";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArgError {
    #[error("usage: aegis-tunnel /service <config path>")]
    Usage,
    #[error("the config path must be absolute")]
    NotAbsolute,
    #[error("the config path must not contain `..` or other special components")]
    SpecialComponent,
    #[error("the config is not in the Aegis config directory")]
    WrongDirectory,
    #[error("the config file name is not one Aegis creates")]
    WrongName,
}

/// Validate `args` (without the program name) and return the config path.
pub fn parse_args(args: &[OsString], config_dir: &Path) -> Result<PathBuf, ArgError> {
    let [flag, path] = args else {
        return Err(ArgError::Usage);
    };
    if flag != "/service" {
        return Err(ArgError::Usage);
    }
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(ArgError::NotAbsolute);
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(ArgError::SpecialComponent);
    }
    // Windows paths are case-insensitive.
    let parent = path.parent().ok_or(ArgError::WrongDirectory)?;
    if !same_path(parent, config_dir) {
        return Err(ArgError::WrongDirectory);
    }
    let owned = path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(SUFFIX))
        .is_some_and(names::is_owned_tunnel_name);
    if !owned {
        return Err(ArgError::WrongName);
    }
    Ok(path)
}

fn same_path(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    norm(a) == norm(b)
}
