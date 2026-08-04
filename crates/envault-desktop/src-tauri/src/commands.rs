//! Thin, literal mirror of `envault::tui::app::RealClient`: each command is
//! one `client::request(Operation::X)` matched against the expected `Reply`
//! variant. `RealClient` itself is a private type inside the `envault`
//! crate's `tui` module, so this duplicates its ~20 bodies rather than
//! importing them.

use envault::client::{self, ClientError};
use envault_core::{GeneratorSpec, ProfileView, SecretVersionView, SecretView, WorkspaceView};
use envault_protocol::{AdminLeaseStatus, DaemonStatus, Operation, Reply, SensitiveBytes};
use tauri::State;
#[cfg(not(debug_assertions))]
use tauri::{Manager, path::BaseDirectory};
use tauri_plugin_autostart::ManagerExt;

use crate::state::AppState;

/// Mirrors the TUI's `describe_error` (`tui/app.rs`): `ClientError::Remote`'s
/// `Display` impl only prints a generic "daemon returned an error" string, so
/// the structured message/code must be pulled out explicitly or the real
/// reason (e.g. "description exceeds 240 characters") never reaches the user.
#[allow(clippy::needless_pass_by_value)]
fn describe(error: ClientError) -> String {
    match error {
        ClientError::Remote(structured) => format!("{} ({})", structured.message, structured.code),
        other => other.to_string(),
    }
}

fn unexpected() -> String {
    "the daemon returned an unexpected response".to_string()
}

fn installed_cli_daemon() -> Option<std::path::PathBuf> {
    let default_location = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|home| home.join(".local/bin/envaultd"));
    if let Some(daemon) = default_location.filter(|path| path.is_file()) {
        return Some(daemon);
    }

    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("envaultd"))
        .find(|daemon| daemon.is_file())
}

#[cfg(debug_assertions)]
fn bundled_daemon_executable(_app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not resolve the desktop executable: {error}"))?;
    Ok(executable.with_file_name("envaultd"))
}

#[cfg(debug_assertions)]
fn daemon_executable(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    if let Some(daemon) = installed_cli_daemon() {
        return Ok(daemon);
    }
    bundled_daemon_executable(app)
}

#[cfg(not(debug_assertions))]
fn bundled_daemon_executable(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .resolve("bin/envaultd", BaseDirectory::Resource)
        .map_err(|error| format!("could not resolve the bundled EnVault daemon: {error}"))
}

#[cfg(not(debug_assertions))]
fn daemon_executable(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    if let Some(daemon) = installed_cli_daemon() {
        return Ok(daemon);
    }
    bundled_daemon_executable(app)
}

const AUTOSTART_PREFERENCE_FILE: &str = "desktop-autostart.json";

fn autostart_preference_path() -> Result<std::path::PathBuf, String> {
    envault_platform::data_directory()
        .map(|directory| directory.join(AUTOSTART_PREFERENCE_FILE))
        .map_err(|error| format!("could not resolve the EnVault data directory: {error}"))
}

fn read_autostart_preference() -> Result<Option<bool>, String> {
    let path = autostart_preference_path()?;
    match std::fs::read_to_string(path) {
        Ok(value) => serde_json::from_str(&value)
            .map(Some)
            .map_err(|error| format!("could not read the EnVault startup preference: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "could not read the EnVault startup preference: {error}"
        )),
    }
}

fn write_autostart_preference(enabled: bool) -> Result<(), String> {
    let path = autostart_preference_path()?;
    write_autostart_preference_at(&path, enabled)
}

fn write_autostart_preference_at(path: &std::path::Path, enabled: bool) -> Result<(), String> {
    let value = serde_json::to_string(&enabled)
        .map_err(|error| format!("could not encode the EnVault startup preference: {error}"))?;
    let directory = path
        .parent()
        .ok_or_else(|| "could not resolve the EnVault data directory".to_owned())?;
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("could not create the EnVault data directory: {error}"))?;
    std::fs::write(path, value)
        .map_err(|error| format!("could not save the EnVault startup preference: {error}"))
}

#[cfg(target_os = "linux")]
fn ensure_linux_autostart_directory() -> Result<(), String> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "could not resolve the home directory for EnVault auto-start".to_owned())?;
    ensure_linux_autostart_directory_at(&home)
}

#[cfg(target_os = "linux")]
fn ensure_linux_autostart_directory_at(home: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(home.join(".config/autostart"))
        .map_err(|error| format!("could not create the EnVault auto-start directory: {error}"))
}

fn enable_autostart(app: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    ensure_linux_autostart_directory()?;

    app.autolaunch()
        .enable()
        .map_err(|error| format!("could not enable EnVault auto-start: {error}"))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::ensure_linux_autostart_directory_at;
    use super::write_autostart_preference_at;

    #[test]
    fn autostart_preference_write_creates_missing_data_directory() {
        let directory = std::env::temp_dir().join(format!(
            "envault-desktop-autostart-preference-{}",
            std::process::id()
        ));
        let path = directory.join("data/desktop-autostart.json");
        let _ = std::fs::remove_dir_all(&directory);

        write_autostart_preference_at(&path, true).expect("write should create the data directory");

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "true");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_autostart_directory_creates_missing_config_parent() {
        let directory = std::env::temp_dir().join(format!(
            "envault-desktop-autostart-directory-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);

        ensure_linux_autostart_directory_at(&directory)
            .expect("auto-start directory should create the config parent");

        assert!(directory.join(".config/autostart").is_dir());
        std::fs::remove_dir_all(directory).unwrap();
    }
}

pub fn configure_default_autostart(app: &tauri::AppHandle) -> Result<(), String> {
    let preference = read_autostart_preference()?;
    let enabled = preference.unwrap_or(true);
    if enabled {
        enable_autostart(app)?;
    } else {
        app.autolaunch()
            .disable()
            .map_err(|error| format!("could not disable EnVault auto-start: {error}"))?;
    }
    if preference.is_none() {
        write_autostart_preference(true)?;
    }
    Ok(())
}

pub fn ensure_daemon_started(app: &tauri::AppHandle) -> Result<DaemonStatus, String> {
    let daemon = bundled_daemon_executable(app)?;
    client::start_locked_with_daemon_executable(daemon).map_err(describe)
}

#[tauri::command]
pub fn status() -> Result<DaemonStatus, String> {
    match client::request(Operation::Status).map_err(describe)? {
        Reply::Status(status) => Ok(status),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn start_daemon(app: tauri::AppHandle) -> Result<DaemonStatus, String> {
    let status = ensure_daemon_started(&app)?;
    crate::tray::refresh(&app);
    Ok(status)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn stop_daemon(state: State<'_, AppState>, app: tauri::AppHandle) -> Result<(), String> {
    crate::tray::stop_daemon(&app)?;
    state.set_reveal_token(None);
    state.set_desktop_session_locked(true);
    crate::tray::refresh(&app);
    Ok(())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn auto_start_enabled(app: tauri::AppHandle) -> Result<bool, String> {
    app.autolaunch()
        .is_enabled()
        .map_err(|error| format!("could not read the EnVault auto-start preference: {error}"))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn set_auto_start_enabled(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    if enabled {
        enable_autostart(&app)?;
    } else {
        app.autolaunch()
            .disable()
            .map_err(|error| format!("could not disable EnVault auto-start: {error}"))?;
    }
    write_autostart_preference(enabled)
}

#[tauri::command]
pub fn admin_status() -> Result<AdminLeaseStatus, String> {
    match client::request(Operation::AdminStatus).map_err(describe)? {
        Reply::AdminStatus(status) => Ok(status),
        _ => Err(unexpected()),
    }
}

#[derive(Debug, serde::Serialize)]
pub struct LoginResult {
    pub admin: AdminLeaseStatus,
    pub reveal_ready: bool,
}

/// Mirrors the TUI's `AdminUnlock` branch (`tui/app.rs:1226-1248`): unlocks
/// admin, then immediately mints a reveal token with the same password.
/// Holding the lease alone never enables reveal - see ADR 0016.
// `State<'_, AppState>` must be taken by value in every command below - the
// `#[tauri::command]` macro only recognizes and injects its extractor types
// (State among them) by value, so `clippy::needless_pass_by_value` is a
// false positive here.

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn login(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    password: String,
    ttl_minutes: u8,
) -> Result<LoginResult, String> {
    let password_bytes = SensitiveBytes::new(password.into_bytes());
    let daemon = daemon_executable(&app)?;
    client::start_with_daemon_executable(password_bytes.clone(), daemon).map_err(describe)?;
    let Reply::AdminStatus(admin) = client::request(Operation::AdminUnlock {
        password: password_bytes.clone(),
        ttl_minutes: Some(ttl_minutes),
    })
    .map_err(describe)?
    else {
        return Err(unexpected());
    };
    let reveal_ready = if let Ok(Reply::RevealToken(token)) =
        client::request(Operation::IssueRevealToken {
            password: password_bytes,
        }) {
        state.set_reveal_token(Some(token));
        true
    } else {
        state.set_reveal_token(None);
        false
    };
    state.set_desktop_session_locked(false);
    crate::tray::install(&app).map_err(|error| error.to_string())?;
    crate::tray::refresh(&app);
    Ok(LoginResult {
        admin,
        reveal_ready,
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn logout(state: State<'_, AppState>, app: tauri::AppHandle) -> Result<(), String> {
    match client::request(Operation::AdminLock).map_err(describe)? {
        Reply::Acknowledged { .. } => {
            state.set_reveal_token(None);
            state.set_desktop_session_locked(true);
            crate::tray::refresh(&app);
            Ok(())
        }
        _ => Err(unexpected()),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn has_reveal_token(state: State<'_, AppState>) -> bool {
    state.has_reveal_token()
}

#[tauri::command]
pub fn list_profiles() -> Result<Vec<ProfileView>, String> {
    match client::request(Operation::ListProfiles).map_err(describe)? {
        Reply::Profiles(profiles) => Ok(profiles),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn list_workspaces() -> Result<Vec<WorkspaceView>, String> {
    match client::request(Operation::ListWorkspaces).map_err(describe)? {
        Reply::Workspaces(workspaces) => Ok(workspaces),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn show_workspace(name: String) -> Result<Vec<ProfileView>, String> {
    match client::request(Operation::ShowWorkspace { name }).map_err(describe)? {
        Reply::WorkspaceProfiles(profiles) => Ok(profiles),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn create_workspace(name: String) -> Result<WorkspaceView, String> {
    match client::request(Operation::CreateWorkspace { name }).map_err(describe)? {
        Reply::Workspace(workspace) => Ok(workspace),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn load_workspace(name: String) -> Result<Vec<ProfileView>, String> {
    match client::request(Operation::LoadWorkspace { name }).map_err(describe)? {
        Reply::WorkspaceProfiles(profiles) => Ok(profiles),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn bind_profile_to_workspace(workspace: String, profile: String) -> Result<(), String> {
    match client::request(Operation::BindProfileToWorkspace { workspace, profile })
        .map_err(describe)?
    {
        Reply::Acknowledged { .. } => Ok(()),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn unbind_profile_from_workspace(workspace: String, profile: String) -> Result<(), String> {
    match client::request(Operation::UnbindProfileFromWorkspace { workspace, profile })
        .map_err(describe)?
    {
        Reply::Acknowledged { .. } => Ok(()),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn list_secrets() -> Result<Vec<SecretView>, String> {
    match client::request(Operation::ListSecrets).map_err(describe)? {
        Reply::Secrets(secrets) => Ok(secrets),
        _ => Err(unexpected()),
    }
}

/// Requires an in-memory reveal token (see `login`); an active admin lease
/// alone is not sufficient, matching the TUI and ADR 0016.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn reveal_secret_value(
    state: State<'_, AppState>,
    profile: String,
    name: String,
) -> Result<String, String> {
    let Some(token) = state.reveal_token() else {
        return Err("admin lease required: log in again to reveal a value".to_string());
    };
    match client::request(Operation::RevealSecretValue {
        profile,
        name,
        token,
    })
    .map_err(describe)?
    {
        Reply::SecretPlaintext(value) => Ok(String::from_utf8_lossy(value.as_slice()).into_owned()),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn create_profile(name: String, description: Option<String>) -> Result<ProfileView, String> {
    match client::request(Operation::CreateProfile {
        name,
        description,
        workspace: None,
    })
    .map_err(describe)?
    {
        Reply::Profile(profile) => Ok(profile),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn rename_profile(old_name: String, new_name: String) -> Result<ProfileView, String> {
    match client::request(Operation::RenameProfile { old_name, new_name }).map_err(describe)? {
        Reply::Profile(profile) => Ok(profile),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn update_profile(
    name: String,
    description: Option<String>,
    activate_on_start: Option<bool>,
) -> Result<ProfileView, String> {
    match client::request(Operation::UpdateProfile {
        name,
        description,
        activate_on_start,
    })
    .map_err(describe)?
    {
        Reply::Profile(profile) => Ok(profile),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn delete_profile(name: String) -> Result<(), String> {
    match client::request(Operation::DeleteProfile { name }).map_err(describe)? {
        Reply::Acknowledged { .. } => Ok(()),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn activate_profile(name: String) -> Result<ProfileView, String> {
    match client::request(Operation::LoadProfile { name }).map_err(describe)? {
        Reply::Profile(profile) => Ok(profile),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn deactivate_profile(name: String) -> Result<ProfileView, String> {
    match client::request(Operation::UnloadProfile { name }).map_err(describe)? {
        Reply::Profile(profile) => Ok(profile),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn create_generated_secret(
    profile: String,
    name: String,
    description: Option<String>,
) -> Result<SecretView, String> {
    match client::request(Operation::CreateGeneratedSecret {
        profile,
        name,
        description,
        generator: GeneratorSpec::default(),
    })
    .map_err(describe)?
    {
        Reply::Secret(secret) => Ok(secret),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn update_secret_description(
    profile: String,
    name: String,
    description: Option<String>,
) -> Result<SecretView, String> {
    match client::request(Operation::UpdateSecret {
        profile,
        name,
        description,
    })
    .map_err(describe)?
    {
        Reply::Secret(secret) => Ok(secret),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn set_secret_value(
    profile: String,
    name: String,
    value: String,
) -> Result<SecretVersionView, String> {
    match client::request(Operation::SetSecretValue {
        profile,
        name,
        value: SensitiveBytes::new(value.into_bytes()),
    })
    .map_err(describe)?
    {
        Reply::SecretValueSet(version) => Ok(version),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn rename_secret(
    profile: String,
    old_name: String,
    new_name: String,
) -> Result<SecretView, String> {
    match client::request(Operation::RenameSecret {
        profile,
        old_name,
        new_name,
    })
    .map_err(describe)?
    {
        Reply::Secret(secret) => Ok(secret),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn delete_secret(profile: String, name: String) -> Result<(), String> {
    match client::request(Operation::DeleteSecret { profile, name }).map_err(describe)? {
        Reply::Acknowledged { .. } => Ok(()),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
pub fn generate_secret_value(profile: String, name: String) -> Result<SecretVersionView, String> {
    match client::request(Operation::GenerateSecretValue {
        profile,
        name,
        generator: GeneratorSpec::default(),
    })
    .map_err(describe)?
    {
        Reply::SecretValueSet(version) => Ok(version),
        _ => Err(unexpected()),
    }
}
