//! The real handler (validation + encrypted store) behind the real pipe, driven
//! by the real client code. Unelevated: test DACLs and a scratch directory.
#![cfg(windows)]
#![allow(clippy::unwrap_used)] // test helpers; the repo only exempts #[test] bodies

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use aegis_core::{ProfileId, Support};
use aegis_service::Service;
use aegis_service::security::{IU_ACE, SecurityDescriptor, path_security};
use aegis_service::server::PipeServer;
use aegis_service::store::{ConfigStore, DirPolicy};
use aegis_windows::call_pipe;
use aegis_windows::proto::{Request, Response, SecretText};
use tokio_util::sync::CancellationToken;

/// WireGuard documentation example keys: public, not secrets.
const PRIVATE_KEY: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const GOOD: &str = "[Interface]\n\
PrivateKey = YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\
Address = 10.0.0.2/32\n\
DNS = 10.0.0.1\n\n\
[Peer]\n\
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
Endpoint = 192.0.2.1:51820\n\
AllowedIPs = 0.0.0.0/0\n";

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Harness {
    name: String,
    _dir: Scratch,
    stop: CancellationToken,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn my_owner() -> String {
    let p = std::env::temp_dir().join(format!("aegis-svc-owner-{}", std::process::id()));
    let _ = std::fs::create_dir(&p);
    let sddl = path_security(&p).unwrap();
    let _ = std::fs::remove_dir(&p);
    sddl.strip_prefix("O:")
        .and_then(|r| r.find("D:").map(|i| r[..i].to_owned()))
        .unwrap()
}

fn start() -> Harness {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir =
        Scratch(std::env::temp_dir().join(format!("aegis-svc-test-{}-{n}", std::process::id())));
    let policy = DirPolicy {
        sddl: "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)".into(),
        owners: vec![my_owner()],
    };
    let store = ConfigStore::open(dir.0.clone(), &policy).expect("store");
    let name = format!(r"\\.\pipe\aegis-svc-test-{}-{n}", std::process::id());
    let sd = SecurityDescriptor::from_sddl(&format!(
        "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA){IU_ACE}(A;;GA;;;OW)"
    ))
    .unwrap();
    let server = PipeServer::bind_with(&name, sd).expect("bind");
    let stop = CancellationToken::new();
    tokio::spawn(server.run(Arc::new(Service::new(store)), stop.clone()));
    Harness {
        name,
        _dir: dir,
        stop,
    }
}

async fn install(
    h: &Harness,
    id: ProfileId,
    text: &str,
) -> Result<Response, aegis_core::CoreError> {
    call_pipe(
        &h.name,
        Request::Install {
            id,
            name: "x".into(),
            config: SecretText::new(text.to_owned()),
        },
    )
    .await
}

#[tokio::test]
async fn install_load_list_uninstall_through_the_pipe() {
    let h = start();
    let id = ProfileId::new();

    assert!(matches!(install(&h, id, GOOD).await.unwrap(), Response::Ok));

    let Response::Installed { ids } = call_pipe(&h.name, Request::Installed).await.unwrap() else {
        panic!("installed")
    };
    assert_eq!(ids, vec![id]);

    let Response::Config { config } = call_pipe(&h.name, Request::Load { id }).await.unwrap()
    else {
        panic!("config")
    };
    let loaded = aegis_config::parse(config.expose()).expect("loads as a valid config");
    let original = aegis_config::parse(GOOD).unwrap();
    assert_eq!(
        loaded.to_wg_quick().as_str(),
        original.to_wg_quick().as_str()
    );

    assert!(matches!(
        call_pipe(&h.name, Request::Uninstall { id }).await.unwrap(),
        Response::Ok
    ));
    let gone = call_pipe(&h.name, Request::Load { id }).await;
    assert!(
        matches!(gone, Err(aegis_core::CoreError::NotFound)),
        "{gone:?}"
    );
    // Uninstalling again is fine.
    assert!(matches!(
        call_pipe(&h.name, Request::Uninstall { id }).await.unwrap(),
        Response::Ok
    ));
}

/// The service does not trust the app. These all reach it directly and must be
/// refused, and the refusal must never echo a value from the config.
#[tokio::test]
async fn the_service_revalidates_and_never_echoes_config_values() {
    let h = start();
    let with_script = GOOD.replace(
        "Address = 10.0.0.2/32",
        "Address = 10.0.0.2/32\nPostUp = calc.exe",
    );
    let with_table = GOOD.replace("DNS = 10.0.0.1", "DNS = 10.0.0.1\nTable = off");
    let no_address = GOOD.replace("Address = 10.0.0.2/32\n", "");
    let too_big = format!("{GOOD}{}", "# padding\n".repeat(10_000));

    for (label, text) in [
        ("PostUp script", with_script),
        ("Table", with_table),
        ("missing Address", no_address),
        ("not a config", "hello world".into()),
        ("oversized", too_big),
    ] {
        let id = ProfileId::new();
        let r = install(&h, id, &text).await;
        let err = r.expect_err(label);
        let shown = err.to_string();
        assert!(!shown.contains(PRIVATE_KEY), "{label}: leaked key: {shown}");
        assert!(
            !shown.contains("calc.exe"),
            "{label}: echoed a value: {shown}"
        );
        // Nothing was stored.
        assert!(
            matches!(
                call_pipe(&h.name, Request::Load { id }).await,
                Err(aegis_core::CoreError::NotFound)
            ),
            "{label}: stored despite being refused"
        );
    }
}

#[tokio::test]
async fn a_tunnel_name_collision_is_refused_over_the_pipe() {
    let h = start();
    let x = 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef_u128;
    let a = ProfileId(uuid::Uuid::from_u128(x));
    let b = ProfileId(uuid::Uuid::from_u128(x ^ 1));
    assert!(matches!(install(&h, a, GOOD).await.unwrap(), Response::Ok));
    let e = install(&h, b, &GOOD.replace("10.0.0.2", "10.0.0.8")).await;
    assert!(e.is_err(), "second profile must not overwrite the first");
    let Response::Config { config } = call_pipe(&h.name, Request::Load { id: a }).await.unwrap()
    else {
        panic!("config")
    };
    assert!(config.expose().contains("10.0.0.2"));
}

#[tokio::test]
async fn tunnels_are_still_reported_unsupported() {
    let h = start();
    let Response::Capabilities { capabilities: c } =
        call_pipe(&h.name, Request::Capabilities).await.unwrap()
    else {
        panic!("caps")
    };
    assert!(matches!(c.available, Support::Unsupported(_)));
    let id = ProfileId::new();
    install(&h, id, GOOD).await.unwrap();
    // Storing a config must not make activation pretend to work.
    assert!(call_pipe(&h.name, Request::Activate { id }).await.is_err());
}
