//! Non-secret app storage: profile metadata and settings as JSON files in the
//! per-user config directory. Secrets never go here (see `VpnBackend`).

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Serialize, de::DeserializeOwned};

use crate::error::{CoreError, Result};
use crate::types::{ProfileMeta, Settings};

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(CoreError::storage)?;
        restrict_dir(&dir);
        Ok(Self { dir })
    }

    pub fn profiles(&self) -> Result<Vec<ProfileMeta>> {
        self.read("profiles.json")
    }

    pub fn save_profiles(&self, p: &[ProfileMeta]) -> Result<()> {
        self.write("profiles.json", &p)
    }

    pub fn settings(&self) -> Result<Settings> {
        self.read("settings.json")
    }

    pub fn save_settings(&self, s: &Settings) -> Result<()> {
        self.write("settings.json", s)
    }

    fn read<T: DeserializeOwned + Default>(&self, name: &str) -> Result<T> {
        match fs::read(self.dir.join(name)) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                CoreError::storage(format!("{name} is corrupt ({e}); move it aside to reset"))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
            Err(e) => Err(CoreError::storage(e)),
        }
    }

    fn write<T: Serialize + ?Sized>(&self, name: &str, v: &T) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(v).map_err(CoreError::storage)?;
        write_private_atomic(&self.dir.join(name), &bytes)
    }
}

/// Write a file readable only by the current user, atomically (temp + rename),
/// so a crash never leaves a half-written file behind.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| CoreError::storage("path has no parent directory"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| CoreError::storage("path has no file name"))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let res = (|| -> std::io::Result<()> {
        let mut f = open_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.map_err(CoreError::storage)
}

#[cfg(unix)]
fn open_private(p: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)
}

#[cfg(not(unix))]
fn open_private(p: &Path) -> std::io::Result<fs::File> {
    // Per-user %APPDATA% inherits a user-only ACL by default.
    fs::OpenOptions::new().write(true).create_new(true).open(p)
}

#[cfg(unix)]
fn restrict_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        assert!(s.profiles().unwrap().is_empty());
        assert_eq!(s.settings().unwrap(), Settings::default());
        let st = Settings {
            kill_switch: true,
            ..Default::default()
        };
        s.save_settings(&st).unwrap();
        assert!(s.settings().unwrap().kill_switch);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.json");
        write_private_atomic(&p, b"{}").unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn corrupt_file_reports_how_to_fix() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("settings.json"), "{nope").unwrap();
        let err = Store::open(d.path())
            .unwrap()
            .settings()
            .unwrap_err()
            .to_string();
        assert!(err.contains("move it aside"), "{err}");
    }
}
