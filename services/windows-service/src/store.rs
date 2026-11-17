//! Encrypted config store: one `<tunnel name>.conf.dpapi` per profile, in the
//! exact format `tunnel.dll` loads (see `dpapi` and DECISIONS D16).
//!
//! A tunnel name carries only 24 of a profile id's 32 hex digits, so the full id
//! is kept as a leading `# aegis-profile-id = <uuid>` comment inside the encrypted
//! payload. WireGuard's parser ignores comments; `load` strips it again.
//!
//! The directory is created with a protected DACL and, when it already exists,
//! is checked before use: `C:\ProgramData` lets any user create a folder, and a
//! pre-created or loosely-permissioned one would let them swap a profile's config.

use std::io::Write;
use std::path::{Path, PathBuf};

use aegis_core::ProfileId;
use aegis_windows::names;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::dpapi;
use crate::security::{self, SecurityDescriptor};

const SUFFIX: &str = ".conf.dpapi";
const ID_HEADER: &str = "# aegis-profile-id = ";
const ERROR_ALREADY_EXISTS: i32 = 183;

/// What the config directory must look like.
pub struct DirPolicy {
    /// DACL to create the directory with, and to require on an existing one.
    pub sddl: String,
    /// Acceptable owners, as Windows prints them (`SY`, `BA` or a SID string).
    /// The owner can always rewrite the DACL, so a foreign owner is refused.
    pub owners: Vec<String>,
}

impl DirPolicy {
    /// SYSTEM and Administrators only, inherited by the files inside.
    pub fn production() -> Self {
        Self {
            sddl: "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".into(),
            owners: vec!["SY".into(), "BA".into()],
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("no such profile in the service")]
    NotFound,
    #[error(
        "the Aegis config directory is not protected as expected ({0}); remove it as an \
         administrator and restart the service"
    )]
    UnsafeDirectory(&'static str),
    #[error("a different profile already uses this tunnel name")]
    NameCollision,
    #[error("the stored config for this profile is damaged")]
    Corrupt,
    #[error("config storage failed: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ConfigStore {
    dir: PathBuf,
}

impl ConfigStore {
    /// Create or verify `dir` (its parent must exist).
    pub fn open(dir: PathBuf, policy: &DirPolicy) -> Result<Self, StoreError> {
        let wanted = SecurityDescriptor::from_sddl(&policy.sddl)?;
        match security::create_dir_with(&dir, &wanted) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS) => {}
            Err(e) => return Err(e.into()),
        }
        // Always verify, including right after creating it.
        let actual = security::path_security(&dir)?;
        let (owner, dacl) = split_owner_dacl(&actual)
            .ok_or(StoreError::UnsafeDirectory("unreadable permissions"))?;
        if !policy.owners.iter().any(|o| o == owner) {
            return Err(StoreError::UnsafeDirectory("unexpected owner"));
        }
        if dacl != wanted.dacl_string()? {
            return Err(StoreError::UnsafeDirectory("unexpected permissions"));
        }
        Ok(Self { dir })
    }

    /// Where the tunnel service reads this profile's config from.
    pub fn path_for(&self, id: ProfileId) -> PathBuf {
        self.file(&names::tunnel_name(id))
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}{SUFFIX}"))
    }

    pub fn save(&self, id: ProfileId, config: &str) -> Result<(), StoreError> {
        let name = names::tunnel_name(id);
        let path = self.file(&name);
        match self.read(&name) {
            Ok((existing, _)) if existing != id => return Err(StoreError::NameCollision),
            // Missing or unreadable: overwriting is the repair.
            Ok(_) | Err(StoreError::NotFound | StoreError::Corrupt | StoreError::Io(_)) => {}
            Err(e) => return Err(e),
        }
        let payload = Zeroizing::new(format!("{ID_HEADER}{}\n{config}", id.0));
        let blob = dpapi::protect(payload.as_bytes(), &name)?;

        let tmp = self.dir.join(format!("{name}.tmp"));
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&blob)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;
        Ok(())
    }

    pub fn load(&self, id: ProfileId) -> Result<Zeroizing<String>, StoreError> {
        let (found, config) = self.read(&names::tunnel_name(id))?;
        if found != id {
            return Err(StoreError::NameCollision);
        }
        Ok(config)
    }

    /// Idempotent.
    pub fn remove(&self, id: ProfileId) -> Result<(), StoreError> {
        match std::fs::remove_file(self.path_for(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Ids of every readable profile we stored. Files that are not ours, are
    /// damaged, or whose name does not match their content are skipped.
    pub fn list(&self) -> Result<Vec<ProfileId>, StoreError> {
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(stem) = file_name
                .to_str()
                .and_then(|n| n.strip_suffix(SUFFIX))
                .filter(|s| names::is_owned_tunnel_name(s))
            else {
                continue;
            };
            if let Ok((id, _)) = self.read(stem)
                && names::tunnel_name(id) == stem
            {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Decrypt `<name>.conf.dpapi`; returns the embedded id and the config text.
    fn read(&self, name: &str) -> Result<(ProfileId, Zeroizing<String>), StoreError> {
        let blob = match std::fs::read(self.file(name)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let plain = dpapi::unprotect(&blob, name).map_err(|_| StoreError::Corrupt)?;
        let text =
            Zeroizing::new(String::from_utf8(plain.to_vec()).map_err(|_| StoreError::Corrupt)?);
        let (first, rest) = text.split_once('\n').ok_or(StoreError::Corrupt)?;
        let uuid = first
            .strip_prefix(ID_HEADER)
            .and_then(|u| Uuid::parse_str(u.trim()).ok())
            .ok_or(StoreError::Corrupt)?;
        Ok((ProfileId(uuid), Zeroizing::new(rest.to_owned())))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// `O:<owner>D:<dacl>` into its two parts.
fn split_owner_dacl(sddl: &str) -> Option<(&str, &str)> {
    let rest = sddl.strip_prefix("O:")?;
    let at = rest.find("D:")?;
    Some((&rest[..at], &rest[at..]))
}
