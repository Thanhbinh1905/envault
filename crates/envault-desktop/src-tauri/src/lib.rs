#![forbid(unsafe_code)]

mod commands;
mod state;
mod tray;

use tauri::{Emitter, Manager, WindowEvent};

use state::AppState;

/// # Panics
///
/// Panics if the Tauri event loop itself fails to start (a fatal
/// misconfiguration, not a runtime condition this app can recover from).
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::Builder::new().build())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
        .setup(|app| {
            let handle = app.handle().clone();
            commands::configure_default_autostart(&handle)
                .map_err(Box::<dyn std::error::Error>::from)?;
            commands::ensure_daemon_started(&handle).map_err(Box::<dyn std::error::Error>::from)?;
            tray::install(&handle)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::start_daemon,
            commands::stop_daemon,
            commands::auto_start_enabled,
            commands::set_auto_start_enabled,
            commands::admin_status,
            commands::login,
            commands::logout,
            commands::has_reveal_token,
            commands::list_profiles,
            commands::list_workspaces,
            commands::show_workspace,
            commands::create_workspace,
            commands::load_workspace,
            commands::bind_profile_to_workspace,
            commands::unbind_profile_from_workspace,
            commands::list_secrets,
            commands::reveal_secret_value,
            commands::create_profile,
            commands::update_profile,
            commands::rename_profile,
            commands::delete_profile,
            commands::activate_profile,
            commands::deactivate_profile,
            commands::create_secret,
            commands::create_generated_secret,
            commands::update_secret_description,
            commands::set_secret_value,
            commands::rename_secret,
            commands::delete_secret,
            commands::generate_secret_value,
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event
                && window.state::<AppState>().tray_installed()
            {
                api.prevent_close();
                if let Err(error) = window.hide()
                    && let Err(emit_error) =
                        window.emit("envault://session-error", error.to_string())
                {
                    eprintln!("failed to notify window about hide error: {emit_error}");
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running envault-desktop");
}
