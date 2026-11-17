//! Real named pipes, real DACLs, real client code. Runs unelevated: it serves
//! on a unique test pipe name, never on the production name.
//!
//! The server's DACL is production's plus an owner ACE, because creating the
//! second pipe instance needs rights that production gives only to SYSTEM and
//! Administrators. `production_dacl_is_applied_as_written` and
//! `users_cannot_add_a_pipe_instance` cover the real DACL's properties.
#![cfg(windows)]
#![allow(unsafe_code)]

use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use aegis_core::{BackendKind, ProfileId, Support};
use aegis_service::security::{IU_ACE, PRODUCTION_SDDL, PipeSecurity, create_server};
use aegis_service::server::PipeServer;
use aegis_service::{Handler, Skeleton};
use aegis_windows::proto::{self, ErrorKind, Request, Response, SecretText};
use aegis_windows::{call_pipe, open_client};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

const ERROR_ACCESS_DENIED: i32 = 5;

static NEXT: AtomicU32 = AtomicU32::new(0);

fn unique_name() -> String {
    format!(
        r"\\.\pipe\aegis-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Production's ACEs, plus full control for the owner so an unelevated test
/// process can create the follow-up pipe instances.
fn test_security() -> PipeSecurity {
    PipeSecurity::from_sddl(&format!(
        "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA){IU_ACE}(A;;GA;;;OW)"
    ))
    .expect("test descriptor")
}

struct Running {
    name: String,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Running {
    fn start<H: Handler>(handler: H) -> Self {
        let name = unique_name();
        let server = PipeServer::bind_with(&name, test_security()).expect("bind test pipe");
        let stop = CancellationToken::new();
        let task = tokio::spawn(server.run(Arc::new(handler), stop.clone()));
        Self { name, stop, task }
    }

    async fn shutdown(self) {
        self.stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("server stops promptly")
            .expect("server task")
            .expect("server result");
    }
}

#[tokio::test]
async fn hello_and_honest_capabilities_through_the_real_client() {
    let s = Running::start(Skeleton);

    let reply = call_pipe(
        &s.name,
        Request::Hello {
            version: proto::VERSION,
        },
    )
    .await
    .expect("hello");
    assert!(matches!(reply, Response::Ok));

    let Response::Capabilities { capabilities: c } = call_pipe(&s.name, Request::Capabilities)
        .await
        .expect("caps")
    else {
        panic!("expected capabilities");
    };
    assert_eq!(c.backend, BackendKind::WindowsService);
    assert!(!c.simulated);
    // The skeleton must not claim anything it cannot do.
    for support in [
        &c.available,
        &c.kill_switch,
        &c.dns_protection,
        &c.ipv6_protection,
        &c.exact_handshake_time,
    ] {
        assert!(matches!(support, Support::Unsupported(_)), "{support:?}");
    }

    s.shutdown().await;
}

#[tokio::test]
async fn wrong_protocol_version_is_refused_with_a_fixable_message() {
    let s = Running::start(Skeleton);
    let err = call_pipe(&s.name, Request::Hello { version: 999 })
        .await
        .expect_err("version mismatch");
    let text = err.to_string();
    assert!(text.contains("999") && text.contains("reinstall"), "{text}");
    s.shutdown().await;
}

#[tokio::test]
async fn unimplemented_operations_fail_closed_not_silently() {
    let s = Running::start(Skeleton);
    let install = call_pipe(
        &s.name,
        Request::Install {
            id: ProfileId::new(),
            name: "x".into(),
            config: SecretText::new("[Interface]".into()),
        },
    )
    .await;
    assert!(install.is_err(), "install must not pretend to work");
    let activate = call_pipe(
        &s.name,
        Request::Activate {
            id: ProfileId::new(),
        },
    )
    .await;
    assert!(activate.is_err(), "activate must not pretend to work");
    let kill_switch = call_pipe(
        &s.name,
        Request::ApplyKillSwitch {
            id: ProfileId::new(),
            endpoints: vec![],
            allow_lan: false,
        },
    )
    .await;
    assert!(kill_switch.is_err(), "kill switch must not pretend to work");
    s.shutdown().await;
}

#[tokio::test]
async fn a_second_server_cannot_take_an_owned_pipe_name() {
    let s = Running::start(Skeleton);
    // FILE_FLAG_FIRST_PIPE_INSTANCE: the name is taken, so binding must fail.
    let e = PipeServer::bind_with(&s.name, test_security())
        .err()
        .expect("second bind must fail");
    assert_eq!(e.raw_os_error(), Some(ERROR_ACCESS_DENIED), "{e}");
    s.shutdown().await;
}

#[tokio::test]
async fn oversized_and_garbage_frames_do_not_hurt_the_server() {
    let s = Running::start(Skeleton);

    // Length prefix far over MAX_FRAME: refused without reading or allocating it.
    let mut c = open_client(&s.name).unwrap();
    c.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
    let reply = proto::read_frame::<_, Response>(&mut c).await;
    assert!(
        matches!(
            reply,
            Ok(Some(Response::Error {
                kind: ErrorKind::Invalid,
                ..
            })) | Ok(None)
                | Err(_)
        ),
        "{reply:?}"
    );

    // Well-formed length, not JSON.
    let mut c = open_client(&s.name).unwrap();
    c.write_all(&5u32.to_le_bytes()).await.unwrap();
    c.write_all(b"nope!").await.unwrap();
    let reply = proto::read_frame::<_, Response>(&mut c).await.unwrap();
    assert!(matches!(
        reply,
        Some(Response::Error {
            kind: ErrorKind::Invalid,
            ..
        })
    ));

    // A client that connects and vanishes.
    drop(open_client(&s.name).unwrap());

    // The server is still healthy.
    let ok = call_pipe(
        &s.name,
        Request::Hello {
            version: proto::VERSION,
        },
    )
    .await
    .expect("still serving");
    assert!(matches!(ok, Response::Ok));
    s.shutdown().await;
}

#[tokio::test]
async fn many_requests_on_one_connection_and_in_parallel() {
    let s = Running::start(Skeleton);

    let mut c = open_client(&s.name).unwrap();
    for _ in 0..20 {
        proto::write_frame(&mut c, &Request::Status).await.unwrap();
        let r = proto::read_frame::<_, Response>(&mut c)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(r, Response::Status { status: None }));
    }
    drop(c);

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let name = s.name.clone();
        tasks.push(tokio::spawn(async move {
            call_pipe(&name, Request::KillSwitchActive).await
        }));
    }
    for t in tasks {
        let r = t.await.unwrap().expect("parallel call");
        assert!(matches!(r, Response::Active { active: false }));
    }
    s.shutdown().await;
}

/// Read back the DACL Windows attached to a pipe handle.
fn applied_sddl(handle: HANDLE) -> String {
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: valid handle, valid out pointer; the descriptor is only read
    // and the test process exits soon after, so it is not freed.
    unsafe {
        let rc = GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut psd),
        );
        assert_eq!(rc.0, 0, "GetSecurityInfo failed");
        let mut out = windows::core::PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut out,
            None,
        )
        .expect("convert descriptor");
        out.to_string().expect("utf-16")
    }
}

/// Guards against the pipe silently getting a default DACL (which would give
/// the creator full control and everyone read access).
#[tokio::test]
async fn production_dacl_is_applied_as_written() {
    let name = unique_name();
    let security = PipeSecurity::from_sddl(PRODUCTION_SDDL).unwrap();
    let server = create_server(&name, &security, true, 4).unwrap();
    let sddl = applied_sddl(HANDLE(server.as_raw_handle()));
    // GA is expanded to FA (file all access) by Windows; the rest is verbatim.
    assert_eq!(
        sddl,
        "D:P(D;;FA;;;NU)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;IU)"
    );
    // The point of the IU mask: no FILE_APPEND_DATA / FILE_CREATE_PIPE_INSTANCE (0x4).
    assert_eq!(0x0012_019b_u32 & 0x4, 0);
}

/// A user holding only the interactive-user ACE cannot add a pipe instance, so
/// cannot stand up a fake server for the service's name. No SYSTEM/Administrators
/// ACE in this DACL, so the result is the same elevated or not.
#[tokio::test]
async fn users_cannot_add_a_pipe_instance() {
    let name = unique_name();
    let security = PipeSecurity::from_sddl(&format!("D:P{IU_ACE}")).unwrap();
    // The first instance sets the DACL; creating it needs no rights on it.
    let _first = create_server(&name, &security, true, 4).unwrap();
    let second = create_server(&name, &security, false, 4);
    let e = second.expect_err("a second instance must be refused");
    assert_eq!(e.raw_os_error(), Some(ERROR_ACCESS_DENIED), "{e}");
}
