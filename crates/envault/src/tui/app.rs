use envault_core::{ProfileView, SecretVersionView, SecretView};
use envault_protocol::{AdminLeaseStatus, DaemonStatus, Operation, Reply};

use crate::client::{self, ClientError};

/// Abstraction over the daemon IPC calls the read surface needs, so the
/// application logic can be exercised against a fake in a later test suite
/// without a real daemon or terminal.
pub trait DaemonClient {
    fn status(&self) -> Result<DaemonStatus, ClientError>;
    fn admin_status(&self) -> Result<AdminLeaseStatus, ClientError>;
    fn list_profiles(&self) -> Result<Vec<ProfileView>, ClientError>;
    fn list_secrets(&self) -> Result<Vec<SecretView>, ClientError>;
    fn list_secret_versions(&self, name: &str) -> Result<Vec<SecretVersionView>, ClientError>;
}

/// Issues every call through the real daemon socket via [`crate::client`].
#[derive(Debug, Default)]
pub struct RealClient;

impl DaemonClient for RealClient {
    fn status(&self) -> Result<DaemonStatus, ClientError> {
        match client::request(Operation::Status)? {
            Reply::Status(status) => Ok(status),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn admin_status(&self) -> Result<AdminLeaseStatus, ClientError> {
        match client::request(Operation::AdminStatus)? {
            Reply::AdminStatus(status) => Ok(status),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn list_profiles(&self) -> Result<Vec<ProfileView>, ClientError> {
        match client::request(Operation::ListProfiles)? {
            Reply::Profiles(profiles) => Ok(profiles),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn list_secrets(&self) -> Result<Vec<SecretView>, ClientError> {
        match client::request(Operation::ListSecrets)? {
            Reply::Secrets(secrets) => Ok(secrets),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn list_secret_versions(&self, name: &str) -> Result<Vec<SecretVersionView>, ClientError> {
        match client::request(Operation::ListSecretVersions {
            name: name.to_string(),
        })? {
            Reply::SecretVersions(versions) => Ok(versions),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }
}

/// The screen currently in focus. Each screen owns its own selection state so
/// switching screens never loses the human's place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    Dashboard,
    Profiles,
    Secrets,
    Versions,
}

/// Bounded status text shown to the human. Only ever built from a
/// [`ClientError`]'s structured fields, never from a raw protocol dump.
fn describe_error(error: &ClientError) -> String {
    match error {
        ClientError::Remote(structured) => format!("{} ({})", structured.message, structured.code),
        other => other.to_string(),
    }
}

/// In-memory application state for the terminal UI read surface. Holds no
/// secret value and persists nothing across process exit.
#[derive(Debug)]
pub struct App<C: DaemonClient> {
    client: C,
    should_quit: bool,
    screen: Screen,
    status: Option<DaemonStatus>,
    admin_status: Option<AdminLeaseStatus>,
    profiles: Vec<ProfileView>,
    profile_selected: usize,
    secrets: Vec<SecretView>,
    secret_selected: usize,
    versions: Vec<SecretVersionView>,
    version_selected: usize,
    status_message: Option<String>,
}

impl<C: DaemonClient> App<C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            should_quit: false,
            screen: Screen::Dashboard,
            status: None,
            admin_status: None,
            profiles: Vec::new(),
            profile_selected: 0,
            secrets: Vec::new(),
            secret_selected: 0,
            versions: Vec::new(),
            version_selected: 0,
            status_message: None,
        }
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn screen(&self) -> Screen {
        self.screen
    }

    pub fn status(&self) -> Option<&DaemonStatus> {
        self.status.as_ref()
    }

    pub fn admin_status(&self) -> Option<&AdminLeaseStatus> {
        self.admin_status.as_ref()
    }

    pub fn profiles(&self) -> &[ProfileView] {
        &self.profiles
    }

    pub fn profile_selected(&self) -> usize {
        self.profile_selected
    }

    pub fn secrets(&self) -> &[SecretView] {
        &self.secrets
    }

    pub fn secret_selected(&self) -> usize {
        self.secret_selected
    }

    pub fn versions(&self) -> &[SecretVersionView] {
        &self.versions
    }

    pub fn version_selected(&self) -> usize {
        self.version_selected
    }

    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// Loads every panel the dashboard shows. Called once on startup and again
    /// on an explicit refresh.
    pub fn refresh_dashboard(&mut self) {
        match self.client.status() {
            Ok(status) => self.status = Some(status),
            Err(error) => self.status_message = Some(describe_error(&error)),
        }
        match self.client.admin_status() {
            Ok(status) => self.admin_status = Some(status),
            Err(error) => self.status_message = Some(describe_error(&error)),
        }
    }

    fn refresh_profiles(&mut self) {
        match self.client.list_profiles() {
            Ok(profiles) => {
                self.profiles = profiles;
                self.profile_selected = self
                    .profile_selected
                    .min(self.profiles.len().saturating_sub(1));
            }
            Err(error) => self.status_message = Some(describe_error(&error)),
        }
    }

    fn refresh_secrets(&mut self) {
        match self.client.list_secrets() {
            Ok(secrets) => {
                self.secrets = secrets;
                self.secret_selected = self
                    .secret_selected
                    .min(self.secrets.len().saturating_sub(1));
            }
            Err(error) => self.status_message = Some(describe_error(&error)),
        }
    }

    fn refresh_versions(&mut self) {
        let Some(secret) = self.secrets.get(self.secret_selected) else {
            self.versions.clear();
            return;
        };
        let name = secret.name.clone();
        match self.client.list_secret_versions(&name) {
            Ok(versions) => {
                self.versions = versions;
                self.version_selected = self
                    .version_selected
                    .min(self.versions.len().saturating_sub(1));
            }
            Err(error) => self.status_message = Some(describe_error(&error)),
        }
    }

    fn go_to(&mut self, screen: Screen) {
        self.status_message = None;
        self.screen = screen;
        match screen {
            Screen::Dashboard => self.refresh_dashboard(),
            Screen::Profiles => self.refresh_profiles(),
            Screen::Secrets => self.refresh_secrets(),
            Screen::Versions => self.refresh_versions(),
        }
    }

    fn move_selection_up(list_len: usize, selected: usize) -> usize {
        if list_len == 0 {
            0
        } else {
            selected.saturating_sub(1)
        }
    }

    fn move_selection_down(list_len: usize, selected: usize) -> usize {
        if list_len == 0 {
            0
        } else {
            selected.saturating_add(1).min(list_len - 1)
        }
    }

    /// Handles one key press. Returns nothing; all effects are applied to
    /// `self`.
    pub fn on_key(&mut self, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;
        match code {
            KeyCode::Esc if self.screen == Screen::Versions => self.go_to(Screen::Secrets),
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('d') => self.go_to(Screen::Dashboard),
            KeyCode::Char('p') => self.go_to(Screen::Profiles),
            KeyCode::Char('s') => self.go_to(Screen::Secrets),
            KeyCode::Char('r') => self.go_to(self.screen),
            KeyCode::Up | KeyCode::Char('k') => self.move_up(),
            KeyCode::Down | KeyCode::Char('j') => self.move_down(),
            KeyCode::Enter => self.select(),
            _ => {}
        }
    }

    fn move_up(&mut self) {
        match self.screen {
            Screen::Profiles => {
                self.profile_selected =
                    Self::move_selection_up(self.profiles.len(), self.profile_selected);
            }
            Screen::Secrets => {
                self.secret_selected =
                    Self::move_selection_up(self.secrets.len(), self.secret_selected);
            }
            Screen::Versions => {
                self.version_selected =
                    Self::move_selection_up(self.versions.len(), self.version_selected);
            }
            Screen::Dashboard => {}
        }
    }

    fn move_down(&mut self) {
        match self.screen {
            Screen::Profiles => {
                self.profile_selected =
                    Self::move_selection_down(self.profiles.len(), self.profile_selected);
            }
            Screen::Secrets => {
                self.secret_selected =
                    Self::move_selection_down(self.secrets.len(), self.secret_selected);
            }
            Screen::Versions => {
                self.version_selected =
                    Self::move_selection_down(self.versions.len(), self.version_selected);
            }
            Screen::Dashboard => {}
        }
    }

    fn select(&mut self) {
        if self.screen == Screen::Secrets && !self.secrets.is_empty() {
            self.go_to(Screen::Versions);
        }
    }
}
