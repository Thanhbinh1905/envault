use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use envault_protocol::SensitiveBytes;
use tauri::menu::MenuItem;

/// The only sensitive value this process keeps in memory: a reveal token
/// minted by `IssueRevealToken`, proving a fresh password check. Holding an
/// admin lease alone is never enough to reveal a value - see ADR 0016.
pub struct AppState {
    pub reveal_token: Mutex<Option<SensitiveBytes>>,
    desktop_session_locked: AtomicBool,
    tray_installed: AtomicBool,
    tray_status: Mutex<Option<MenuItem<tauri::Wry>>>,
    tray_lock: Mutex<Option<MenuItem<tauri::Wry>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            reveal_token: Mutex::new(None),
            desktop_session_locked: AtomicBool::new(true),
            tray_installed: AtomicBool::new(false),
            tray_status: Mutex::new(None),
            tray_lock: Mutex::new(None),
        }
    }
}

impl AppState {
    pub fn has_reveal_token(&self) -> bool {
        self.reveal_token.lock().expect("state lock").is_some()
    }

    pub fn set_reveal_token(&self, token: Option<SensitiveBytes>) {
        *self.reveal_token.lock().expect("state lock") = token;
    }

    pub fn desktop_session_locked(&self) -> bool {
        self.desktop_session_locked.load(Ordering::Relaxed)
    }

    pub fn set_desktop_session_locked(&self, locked: bool) {
        self.desktop_session_locked.store(locked, Ordering::Relaxed);
    }

    pub fn tray_installed(&self) -> bool {
        self.tray_installed.load(Ordering::Relaxed)
    }

    pub fn set_tray_installed(&self) {
        self.tray_installed.store(true, Ordering::Relaxed);
    }

    pub fn reveal_token(&self) -> Option<SensitiveBytes> {
        self.reveal_token.lock().expect("state lock").clone()
    }

    pub fn set_tray_status_item(&self, item: MenuItem<tauri::Wry>) {
        *self.tray_status.lock().expect("state lock") = Some(item);
    }

    pub fn set_tray_status_text(&self, text: &str) -> tauri::Result<()> {
        if let Some(item) = self.tray_status.lock().expect("state lock").as_ref() {
            item.set_text(text)?;
        }
        Ok(())
    }

    pub fn set_tray_lock_item(&self, item: MenuItem<tauri::Wry>) {
        *self.tray_lock.lock().expect("state lock") = Some(item);
    }

    pub fn set_tray_lock_enabled(&self, enabled: bool) -> tauri::Result<()> {
        if let Some(item) = self.tray_lock.lock().expect("state lock").as_ref() {
            item.set_enabled(enabled)?;
        }
        Ok(())
    }
}
