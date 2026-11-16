mod backend;
mod commands;
mod tray;

use std::sync::Arc;

use aegis_core::{ConnectionState, Engine, EngineEvent, PeerState};
use commands::AppState;
use tauri::{DragDropEvent, Emitter, Manager, WindowEvent};

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("AEGIS_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main(app)
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let engine = tauri::async_runtime::block_on(async {
                let backend = backend::select().await;
                Engine::start(backend, &dir).await
            })
            .map_err(|e| format!("failed to start: {e}"))?;

            let tray_available = match tray::create(app.handle(), &engine) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!("system tray unavailable: {e}");
                    false
                }
            };
            app.manage(AppState {
                engine: Arc::clone(&engine),
                tray_available,
            });
            forward_events(app.handle().clone(), Arc::clone(&engine));

            let s = engine.settings();
            if s.connect_on_launch
                && let Some(id) = s.preferred_profile
                && engine.snapshot().state.is_idle()
            {
                let e = Arc::clone(&engine);
                tauri::async_runtime::spawn(async move {
                    let _ = e.connect(id).await; // failures surface as state + events
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                let st = window.state::<AppState>();
                // Closing the UI never touches the tunnel; with a tray we just hide.
                if st.tray_available && st.engine.settings().close_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
            WindowEvent::DragDrop(DragDropEvent::Drop { paths, .. }) => {
                let engine = Arc::clone(&window.state::<AppState>().engine);
                let app = window.app_handle().clone();
                let paths = paths.clone();
                tauri::async_runtime::spawn(commands::import_dropped(app, engine, paths));
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::capabilities,
            commands::snapshot,
            commands::events,
            commands::profiles,
            commands::settings,
            commands::set_settings,
            commands::connect,
            commands::disconnect,
            commands::cancel,
            commands::import_dialog,
            commands::new_draft,
            commands::profile_draft,
            commands::create_profile,
            commands::update_profile,
            commands::duplicate_profile,
            commands::delete_profile,
            commands::export_profile,
            commands::diagnostics,
            commands::export_diagnostics,
        ])
        .run(tauri::generate_context!());
    if let Err(e) = result {
        tracing::error!("Aegis VPN exited with an error: {e}");
        std::process::exit(1);
    }
}

pub(crate) fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn forward_events(app: tauri::AppHandle, engine: Arc<Engine<backend::AnyBackend>>) {
    let mut rx = engine.subscribe();
    tauri::async_runtime::spawn(async move {
        let mut last: Option<ConnectionState> = None;
        loop {
            let ev = match rx.recv().await {
                Ok(ev) => ev,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            if let EngineEvent::Snapshot(s) = &ev
                && last.as_ref() != Some(&s.state)
            {
                notify_transition(&app, &engine, last.as_ref(), &s.state);
                last = Some(s.state.clone());
                tray::refresh(&app, &engine);
            }
            if matches!(ev, EngineEvent::ProfilesChanged) {
                tray::refresh(&app, &engine);
            }
            let _ = app.emit("engine", &ev);
        }
    });
}

fn notify_transition(
    app: &tauri::AppHandle,
    engine: &Engine<backend::AnyBackend>,
    prev: Option<&ConnectionState>,
    next: &ConnectionState,
) {
    let visible = app
        .get_webview_window("main")
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false);
    if visible || !engine.settings().notifications {
        return;
    }
    let body = match next {
        ConnectionState::Connected {
            peer: PeerState::Confirmed,
            ..
        } if !matches!(
            prev,
            Some(ConnectionState::Connected {
                peer: PeerState::Confirmed,
                ..
            })
        ) =>
        {
            "VPN connected"
        }
        ConnectionState::Reconnecting { attempt: 1, .. } => "VPN connection lost. Reconnecting.",
        ConnectionState::Failed { .. } => "VPN connection failed. Open Aegis VPN for details.",
        _ => return,
    };
    show_notification(body);
}

/// Desktop notification via notify-rust: freedesktop D-Bus on Linux (zbus 6 on
/// our tokio runtime), WinRT toasts on Windows. Failures are logged, never fatal.
fn show_notification(body: &'static str) {
    let mut n = notify_rust::Notification::new();
    n.appname("Aegis VPN").summary("Aegis VPN").body(body);
    #[cfg(all(unix, not(target_os = "macos")))]
    tauri::async_runtime::spawn(async move {
        if let Err(e) = n.show_async().await {
            tracing::warn!("could not show notification: {e}");
        }
    });
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    tauri::async_runtime::spawn_blocking(move || {
        if let Err(e) = n.show() {
            tracing::warn!("could not show notification: {e}");
        }
    });
}
