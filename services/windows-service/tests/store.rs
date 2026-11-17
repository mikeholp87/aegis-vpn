//! The encrypted config store against real DPAPI and real directory ACLs.
//! Runs unelevated as the current user, so the directory policy adds an owner
//! ACE and names the test user as the accepted owner. The production policy
//! (SYSTEM/Administrators owner) can only be satisfied when running as SYSTEM
//! and is not exercised here.
#![cfg(windows)]
#![allow(clippy::unwrap_used)] // test helpers; the repo only exempts #[test] bodies

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use aegis_core::ProfileId;
use aegis_service::security::path_security;
use aegis_service::store::{ConfigStore, DirPolicy, StoreError};
use aegis_windows::names;
use uuid::Uuid;

/// The WireGuard documentation example keys. Public, not secrets.
const PRIVATE_KEY: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const CONFIG: &str = "[Interface]\n\
PrivateKey = YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\
Address = 10.0.0.2/32\n\
DNS = 10.0.0.1\n\n\
[Peer]\n\
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
Endpoint = 192.0.2.1:51820\n\
AllowedIPs = 0.0.0.0/0\n";

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "aegis-store-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Owner string Windows prints for a directory this user creates.
fn my_owner() -> String {
    let probe = Scratch::new();
    std::fs::create_dir(&probe.0).unwrap();
    let sddl = path_security(&probe.0).unwrap();
    sddl.strip_prefix("O:")
        .and_then(|r| r.find("D:").map(|i| r[..i].to_owned()))
        .expect("owner in descriptor")
}

fn test_policy() -> DirPolicy {
    DirPolicy {
        sddl: "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)".into(),
        owners: vec![my_owner()],
    }
}

fn open() -> (Scratch, ConfigStore) {
    let dir = Scratch::new();
    let store = ConfigStore::open(dir.0.clone(), &test_policy()).expect("open store");
    (dir, store)
}

#[test]
fn round_trip_is_encrypted_on_disk_and_listed() {
    let (_dir, store) = open();
    let id = ProfileId::new();
    store.save(id, CONFIG).unwrap();

    // Exactly the file name tunnel.dll expects.
    let path = store.path_for(id);
    assert_eq!(
        path.file_name().unwrap().to_str().unwrap(),
        format!("{}.conf.dpapi", names::tunnel_name(id))
    );

    // Nothing readable on disk: no key, no section names, no address.
    let raw = std::fs::read(&path).unwrap();
    let as_text = String::from_utf8_lossy(&raw);
    for needle in [PRIVATE_KEY, "PrivateKey", "[Interface]", "192.0.2.1"] {
        assert!(
            !as_text.contains(needle),
            "{needle} found in the stored file"
        );
    }

    assert_eq!(&*store.load(id).unwrap(), CONFIG);
    assert_eq!(store.list().unwrap(), vec![id]);
    // What comes back parses as an ordinary config.
    aegis_config::parse(&store.load(id).unwrap()).expect("stored config still parses");
}

#[test]
fn saving_again_replaces_and_leaves_no_temp_file() {
    let (dir, store) = open();
    let id = ProfileId::new();
    store.save(id, CONFIG).unwrap();
    let updated = CONFIG.replace("10.0.0.2/32", "10.0.0.9/32");
    store.save(id, &updated).unwrap();
    assert_eq!(*store.load(id).unwrap(), updated);
    let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn remove_is_idempotent_and_load_then_reports_not_found() {
    let (_dir, store) = open();
    let id = ProfileId::new();
    store.save(id, CONFIG).unwrap();
    store.remove(id).unwrap();
    store.remove(id).unwrap();
    assert!(matches!(store.load(id), Err(StoreError::NotFound)));
    assert!(store.list().unwrap().is_empty());
}

/// tunnel.dll insists the DPAPI description equals the tunnel name, and so do
/// we: a blob copied under another profile's name is refused.
#[test]
fn a_blob_under_the_wrong_name_is_refused() {
    let (_dir, store) = open();
    let (a, b) = (ProfileId::new(), ProfileId::new());
    store.save(a, CONFIG).unwrap();
    std::fs::copy(store.path_for(a), store.path_for(b)).unwrap();

    assert!(matches!(store.load(b), Err(StoreError::Corrupt)));
    assert_eq!(store.list().unwrap(), vec![a]);
}

#[test]
fn two_profiles_sharing_a_tunnel_name_prefix_cannot_clobber_each_other() {
    let (_dir, store) = open();
    let x = 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef_u128;
    let a = ProfileId(Uuid::from_u128(x));
    let b = ProfileId(Uuid::from_u128(x ^ 1)); // differs only in the last digit
    assert_eq!(names::tunnel_name(a), names::tunnel_name(b));

    store.save(a, CONFIG).unwrap();
    assert!(matches!(
        store.save(b, &CONFIG.replace("10.0.0.2", "10.0.0.7")),
        Err(StoreError::NameCollision)
    ));
    assert_eq!(&*store.load(a).unwrap(), CONFIG);
    assert!(matches!(store.load(b), Err(StoreError::NameCollision)));
}

#[test]
fn foreign_and_damaged_files_are_ignored_not_trusted() {
    let (dir, store) = open();
    let id = ProfileId::new();
    store.save(id, CONFIG).unwrap();

    std::fs::write(dir.0.join("notes.txt"), b"hello").unwrap();
    std::fs::write(dir.0.join("wg0.conf.dpapi"), b"not ours").unwrap();
    let damaged = ProfileId::new();
    std::fs::write(store.path_for(damaged), b"garbage, not a DPAPI blob").unwrap();

    assert_eq!(store.list().unwrap(), vec![id]);
    assert!(matches!(store.load(damaged), Err(StoreError::Corrupt)));
    // Saving over a damaged file repairs it.
    store.save(damaged, CONFIG).unwrap();
    assert_eq!(&*store.load(damaged).unwrap(), CONFIG);
}

#[test]
fn directory_gets_the_protected_dacl_and_is_reused_on_restart() {
    let dir = Scratch::new();
    let policy = test_policy();
    let first = ConfigStore::open(dir.0.clone(), &policy).unwrap();
    let id = ProfileId::new();
    first.save(id, CONFIG).unwrap();

    let sddl = path_security(&dir.0).unwrap();
    assert!(
        sddl.contains("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"),
        "{sddl}"
    );

    // A second open (service restart) accepts the directory and sees the data.
    let second = ConfigStore::open(dir.0.clone(), &policy).unwrap();
    assert_eq!(second.list().unwrap(), vec![id]);
}

/// The pre-creation attack: someone makes the directory first, with inherited
/// (loose) permissions. The service must refuse it rather than use it.
#[test]
fn a_directory_someone_else_created_is_refused() {
    let dir = Scratch::new();
    std::fs::create_dir(&dir.0).unwrap(); // default, inherited DACL

    // Owner not accepted (as for any non-SYSTEM/Administrators owner).
    let strict = DirPolicy {
        owners: vec!["SY".into(), "BA".into()],
        ..test_policy()
    };
    let e = ConfigStore::open(dir.0.clone(), &strict)
        .err()
        .expect("refused");
    assert!(
        matches!(e, StoreError::UnsafeDirectory("unexpected owner")),
        "{e}"
    );

    // Owner accepted but the permissions are the inherited ones, not ours.
    let e = ConfigStore::open(dir.0.clone(), &test_policy())
        .err()
        .expect("refused");
    assert!(
        matches!(e, StoreError::UnsafeDirectory("unexpected permissions")),
        "{e}"
    );
}
