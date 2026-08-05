use std::time::Duration;

use envault::client::{self, ClientError};
use envault_protocol::{Operation, Reply, ServiceState};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};

use crate::state::AppState;

const TRAY_ID: &str = "envault-status";
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const AVAILABLE_ICON: &[u8] = include_bytes!("../icons/tray-available.png");
const SESSION_LOCKED_ICON: &[u8] = include_bytes!("../icons/tray-session-locked.png");
const VAULT_LOCKED_ICON: &[u8] = include_bytes!("../icons/tray-vault-locked.png");
const NOT_RUNNING_ICON: &[u8] = include_bytes!("../icons/tray-not-running.png");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrayStatus {
    Available,
    DesktopSessionLocked,
    Locked,
    NotRunning,
}

#[derive(Clone, Copy, Debug)]
struct TrayPresentation {
    status: TrayStatus,
    lock_enabled: bool,
}

impl TrayPresentation {
    fn from_reply(reply: Result<Reply, ClientError>) -> Self {
        match reply {
            Ok(Reply::Status(status)) => match status.service {
                ServiceState::Unlocked => Self {
                    status: TrayStatus::Available,
                    lock_enabled: status.admin_lease_active,
                },
                ServiceState::Locked => Self {
                    status: TrayStatus::Locked,
                    lock_enabled: false,
                },
            },
            Ok(_) | Err(_) => Self {
                status: TrayStatus::NotRunning,
                lock_enabled: false,
            },
        }
    }
}

impl TrayStatus {
    fn menu_label(self) -> &'static str {
        match self {
            Self::Available => "Status: vault available",
            Self::DesktopSessionLocked => "Status: desktop session locked",
            Self::Locked => "Status: vault locked",
            Self::NotRunning => "Status: daemon not running",
        }
    }

    fn tooltip(self) -> &'static str {
        match self {
            Self::Available => "EnVault - vault available",
            Self::DesktopSessionLocked => "EnVault - desktop session locked",
            Self::Locked => "EnVault - vault locked",
            Self::NotRunning => "EnVault - daemon not running",
        }
    }

    fn icon(self) -> Image<'static> {
        let bytes = match self {
            Self::Available => AVAILABLE_ICON,
            Self::DesktopSessionLocked => SESSION_LOCKED_ICON,
            Self::Locked => VAULT_LOCKED_ICON,
            Self::NotRunning => NOT_RUNNING_ICON,
        };
        Image::from_bytes(bytes).expect("generated EnVault tray icon is a valid PNG")
    }
}

pub fn install(app: &AppHandle) -> tauri::Result<()> {
    if app.state::<AppState>().tray_installed() {
        return Ok(());
    }
    let presentation = current_status(app);
    let status_item = MenuItem::with_id(
        app,
        "status",
        presentation.status.menu_label(),
        false,
        None::<&str>,
    )?;
    let open_item = MenuItem::with_id(app, "open", "Open EnVault", true, None::<&str>)?;
    let lock_item = MenuItem::with_id(
        app,
        "lock",
        "Lock desktop session",
        presentation.lock_enabled,
        None::<&str>,
    )?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit EnVault", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status_item, &open_item, &lock_item, &quit_item])?;
    app.state::<AppState>().set_tray_status_item(status_item);
    app.state::<AppState>().set_tray_lock_item(lock_item);

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(presentation.status.icon())
        .tooltip(presentation.status.tooltip())
        .icon_as_template(false)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main_window(app),
            "lock" => lock_desktop_session(app),
            "quit" => exit_after_stopping_daemon(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    app.state::<AppState>().set_tray_installed();

    let app_handle = app.clone();
    std::thread::Builder::new()
        .name("envault-tray-status".to_string())
        .spawn(move || {
            loop {
                std::thread::sleep(POLL_INTERVAL);
                refresh(&app_handle);
            }
        })?;
    Ok(())
}

pub fn refresh(app: &AppHandle) {
    let presentation = current_status(app);
    if let Err(error) = apply_status(app, presentation) {
        eprintln!("failed to refresh EnVault tray status: {error}");
    }
}

pub fn stop_daemon(app: &AppHandle) -> Result<(), String> {
    match client::request(Operation::Stop) {
        Ok(Reply::Acknowledged { .. }) | Err(ClientError::NotRunning) => {
            let state = app.state::<AppState>();
            state.set_reveal_token(None);
            state.set_desktop_session_locked(true);
            Ok(())
        }
        Ok(_) => Err("The vault returned an unexpected response while stopping.".to_string()),
        Err(error) => Err(format!("Unable to stop EnVault: {error}")),
    }
}

fn current_status(app: &AppHandle) -> TrayPresentation {
    let mut presentation = TrayPresentation::from_reply(client::request(Operation::Status));
    if presentation.status == TrayStatus::Available
        && app.state::<AppState>().desktop_session_locked()
    {
        presentation.status = TrayStatus::DesktopSessionLocked;
        presentation.lock_enabled = false;
    }
    presentation
}

fn apply_status(app: &AppHandle, presentation: TrayPresentation) -> tauri::Result<()> {
    let tray = app
        .tray_by_id(TRAY_ID)
        .expect("EnVault tray is installed before status refresh");
    tray.set_icon(Some(presentation.status.icon()))?;
    tray.set_icon_as_template(false)?;
    tray.set_tooltip(Some(presentation.status.tooltip()))?;
    let state = app.state::<AppState>();
    state.set_tray_status_text(presentation.status.menu_label())?;
    state.set_tray_lock_enabled(presentation.lock_enabled)
}

fn lock_desktop_session(app: &AppHandle) {
    if !current_status(app).lock_enabled {
        return;
    }
    match client::request(Operation::AdminLock) {
        Ok(Reply::Acknowledged { .. }) => complete_desktop_lock(app),
        Ok(_) => emit_session_error(
            app,
            "The vault returned an unexpected response while locking.",
        ),
        Err(error) => {
            emit_session_error(app, &format!("Unable to lock the desktop session: {error}"));
        }
    }
}

fn complete_desktop_lock(app: &AppHandle) {
    let state = app.state::<AppState>();
    state.set_reveal_token(None);
    state.set_desktop_session_locked(true);
    if let Err(error) = app.emit("envault://locked", ()) {
        eprintln!("failed to notify window about locked desktop session: {error}");
    }
    refresh(app);
}

fn emit_session_error(app: &AppHandle, message: &str) {
    if let Err(error) = app.emit("envault://session-error", message) {
        eprintln!("failed to notify window about tray session error: {error}");
    }
}

fn exit_after_stopping_daemon(app: &AppHandle) {
    match stop_daemon(app) {
        Ok(()) => app.exit(0),
        Err(message) => {
            show_main_window(app);
            emit_session_error(app, &message);
        }
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if let Err(error) = window.show() {
            eprintln!("failed to show EnVault window: {error}");
        }
        if let Err(error) = window.set_focus() {
            eprintln!("failed to focus EnVault window: {error}");
        }
    }
}
