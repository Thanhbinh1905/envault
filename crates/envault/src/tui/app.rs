use envault_core::{
    DEFAULT_ADMIN_LEASE_MINUTES, GeneratorSpec, ProfileView, SecretVersionView, SecretView,
};
use envault_protocol::{AdminLeaseStatus, DaemonStatus, Operation, Reply, SensitiveBytes};
use zeroize::Zeroizing;

use crate::client::{self, ClientError};

/// Abstraction over the daemon IPC calls the terminal UI needs, so the
/// application logic can be exercised against a fake in a later test suite
/// without a real daemon or terminal.
pub trait DaemonClient {
    fn status(&self) -> Result<DaemonStatus, ClientError>;
    fn admin_status(&self) -> Result<AdminLeaseStatus, ClientError>;
    fn list_profiles(&self) -> Result<Vec<ProfileView>, ClientError>;
    fn list_secrets(&self) -> Result<Vec<SecretView>, ClientError>;
    fn list_secret_versions(&self, name: &str) -> Result<Vec<SecretVersionView>, ClientError>;

    fn admin_unlock(
        &self,
        password: SensitiveBytes,
        ttl_minutes: u8,
    ) -> Result<AdminLeaseStatus, ClientError>;
    fn admin_lock(&self) -> Result<(), ClientError>;
    fn create_profile(
        &self,
        name: String,
        description: Option<String>,
    ) -> Result<ProfileView, ClientError>;
    fn rename_profile(
        &self,
        old_name: String,
        new_name: String,
    ) -> Result<ProfileView, ClientError>;
    fn delete_profile(&self, name: String) -> Result<(), ClientError>;
    fn activate_profile(&self, name: String) -> Result<ProfileView, ClientError>;
    fn create_generated_secret(
        &self,
        name: String,
        description: Option<String>,
        generator: GeneratorSpec,
    ) -> Result<SecretView, ClientError>;
    fn update_secret_description(
        &self,
        name: String,
        description: Option<String>,
    ) -> Result<SecretView, ClientError>;
    fn rename_secret(&self, old_name: String, new_name: String) -> Result<SecretView, ClientError>;
    fn delete_secret(&self, name: String) -> Result<(), ClientError>;
    fn generate_secret_value(
        &self,
        name: String,
        generator: GeneratorSpec,
    ) -> Result<SecretVersionView, ClientError>;
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

    fn admin_unlock(
        &self,
        password: SensitiveBytes,
        ttl_minutes: u8,
    ) -> Result<AdminLeaseStatus, ClientError> {
        match client::request(Operation::AdminUnlock {
            password,
            ttl_minutes,
        })? {
            Reply::AdminStatus(status) => Ok(status),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn admin_lock(&self) -> Result<(), ClientError> {
        match client::request(Operation::AdminLock)? {
            Reply::Acknowledged => Ok(()),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn create_profile(
        &self,
        name: String,
        description: Option<String>,
    ) -> Result<ProfileView, ClientError> {
        match client::request(Operation::CreateProfile { name, description })? {
            Reply::Profile(profile) => Ok(profile),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn rename_profile(
        &self,
        old_name: String,
        new_name: String,
    ) -> Result<ProfileView, ClientError> {
        match client::request(Operation::RenameProfile { old_name, new_name })? {
            Reply::Profile(profile) => Ok(profile),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn delete_profile(&self, name: String) -> Result<(), ClientError> {
        match client::request(Operation::DeleteProfile { name })? {
            Reply::Acknowledged => Ok(()),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn activate_profile(&self, name: String) -> Result<ProfileView, ClientError> {
        match client::request(Operation::ActivateProfile { name })? {
            Reply::Profile(profile) => Ok(profile),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn create_generated_secret(
        &self,
        name: String,
        description: Option<String>,
        generator: GeneratorSpec,
    ) -> Result<SecretView, ClientError> {
        match client::request(Operation::CreateGeneratedSecret {
            name,
            description,
            generator,
        })? {
            Reply::Secret(secret) => Ok(secret),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn update_secret_description(
        &self,
        name: String,
        description: Option<String>,
    ) -> Result<SecretView, ClientError> {
        match client::request(Operation::UpdateSecret { name, description })? {
            Reply::Secret(secret) => Ok(secret),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn rename_secret(&self, old_name: String, new_name: String) -> Result<SecretView, ClientError> {
        match client::request(Operation::RenameSecret { old_name, new_name })? {
            Reply::Secret(secret) => Ok(secret),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn delete_secret(&self, name: String) -> Result<(), ClientError> {
        match client::request(Operation::DeleteSecret { name })? {
            Reply::Acknowledged => Ok(()),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn generate_secret_value(
        &self,
        name: String,
        generator: GeneratorSpec,
    ) -> Result<SecretVersionView, ClientError> {
        match client::request(Operation::GenerateSecretValue { name, generator })? {
            Reply::SecretVersion(version) => Ok(version),
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

/// Which text field a [`Mode::TextInput`] step is collecting, and what to do
/// once the human presses Enter on it. Holds only profile/secret names and
/// descriptions, never a secret value.
#[derive(Clone, Debug)]
pub enum InputKind {
    CreateProfileName,
    CreateProfileDescription { name: String },
    RenameProfileNewName { old_name: String },
    CreateSecretName,
    CreateSecretDescription { name: String },
    UpdateSecretDescription { name: String },
    RenameSecretNewName { old_name: String },
}

impl InputKind {
    pub fn prompt(&self) -> &'static str {
        match self {
            InputKind::CreateProfileName | InputKind::RenameProfileNewName { .. } => {
                "New profile name:"
            }
            InputKind::CreateProfileDescription { .. } => {
                "Profile description (optional, Enter to skip):"
            }
            InputKind::CreateSecretName | InputKind::RenameSecretNewName { .. } => {
                "New secret name:"
            }
            InputKind::CreateSecretDescription { .. } => {
                "Secret description (optional, Enter to skip):"
            }
            InputKind::UpdateSecretDescription { .. } => "New secret description:",
        }
    }
}

/// A mutating action awaiting explicit confirmation before it is sent. No
/// keypress that selects a target can also be the keypress that commits it.
#[derive(Clone, Debug)]
pub enum PendingAction {
    LockAdmin,
    CreateProfile {
        name: String,
        description: Option<String>,
    },
    RenameProfile {
        old_name: String,
        new_name: String,
    },
    DeleteProfile {
        name: String,
    },
    ActivateProfile {
        name: String,
    },
    CreateSecret {
        name: String,
        description: Option<String>,
    },
    UpdateSecretDescription {
        name: String,
        description: Option<String>,
    },
    RenameSecret {
        old_name: String,
        new_name: String,
    },
    DeleteSecret {
        name: String,
    },
    GenerateSecretValue {
        name: String,
    },
}

impl PendingAction {
    pub fn describe(&self) -> String {
        match self {
            PendingAction::LockAdmin => "lock the admin lease".to_string(),
            PendingAction::CreateProfile { name, .. } => format!("create profile '{name}'"),
            PendingAction::RenameProfile { old_name, new_name } => {
                format!("rename profile '{old_name}' to '{new_name}'")
            }
            PendingAction::DeleteProfile { name } => format!("delete profile '{name}'"),
            PendingAction::ActivateProfile { name } => format!("activate profile '{name}'"),
            PendingAction::CreateSecret { name, .. } => {
                format!("create generated secret '{name}'")
            }
            PendingAction::UpdateSecretDescription { name, .. } => {
                format!("update the description of secret '{name}'")
            }
            PendingAction::RenameSecret { old_name, new_name } => {
                format!("rename secret '{old_name}' to '{new_name}'")
            }
            PendingAction::DeleteSecret { name } => format!("delete secret '{name}'"),
            PendingAction::GenerateSecretValue { name } => {
                format!("rotate the value of secret '{name}'")
            }
        }
    }
}

/// Input focus for the terminal UI. Only [`Mode::Normal`] responds to the
/// navigation keys; every other mode owns the keyboard until it submits or
/// cancels, so a single keypress can never both select and commit an action.
pub enum Mode {
    Normal,
    PasswordInput(Zeroizing<String>),
    TextInput(InputKind, String),
    Confirm(PendingAction),
}

impl std::fmt::Debug for Mode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Normal => write!(formatter, "Normal"),
            Mode::PasswordInput(buffer) => {
                write!(formatter, "PasswordInput(<redacted len={}>)", buffer.len())
            }
            Mode::TextInput(kind, _) => write!(formatter, "TextInput({kind:?}, <input>)"),
            Mode::Confirm(action) => write!(formatter, "Confirm({action:?})"),
        }
    }
}

/// Bounded status text shown to the human. Only ever built from a
/// [`ClientError`]'s structured fields, never from a raw protocol dump.
fn describe_error(error: &ClientError) -> String {
    match error {
        ClientError::Remote(structured) => format!("{} ({})", structured.message, structured.code),
        other => other.to_string(),
    }
}

fn normalize_optional(text: String) -> Option<String> {
    if text.is_empty() { None } else { Some(text) }
}

/// In-memory application state for the terminal UI. Holds no secret value and
/// persists nothing across process exit. The admin lease flag reflects only
/// what the daemon has most recently reported; it is never assumed to remain
/// true across a failed request.
#[derive(Debug)]
pub struct App<C: DaemonClient> {
    client: C,
    should_quit: bool,
    screen: Screen,
    mode: Mode,
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
            mode: Mode::Normal,
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

    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    pub fn status(&self) -> Option<&DaemonStatus> {
        self.status.as_ref()
    }

    pub fn admin_status(&self) -> Option<&AdminLeaseStatus> {
        self.admin_status.as_ref()
    }

    pub fn admin_lease_active(&self) -> bool {
        self.admin_status
            .as_ref()
            .is_some_and(|status| status.active)
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
    /// on an explicit refresh, and after every admin lease transition so the
    /// lease-gated keybindings reflect current daemon state immediately.
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
    /// `self`. Every mode but [`Mode::Normal`] owns the keyboard exclusively
    /// until it submits or cancels.
    pub fn on_key(&mut self, code: crossterm::event::KeyCode) {
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Normal => self.on_key_normal(code),
            Mode::PasswordInput(buffer) => self.on_key_password(code, buffer),
            Mode::TextInput(kind, buffer) => self.on_key_text(code, kind, buffer),
            Mode::Confirm(action) => self.on_key_confirm(code, action),
        }
    }

    fn on_key_normal(&mut self, code: crossterm::event::KeyCode) {
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
            KeyCode::Char('u') if !self.admin_lease_active() => {
                self.status_message = None;
                self.mode = Mode::PasswordInput(Zeroizing::new(String::new()));
            }
            KeyCode::Char('L') if self.admin_lease_active() => {
                self.mode = Mode::Confirm(PendingAction::LockAdmin);
            }
            KeyCode::Char(other) => self.on_admin_key(other),
            _ => {}
        }
    }

    /// Dispatches an admin-lease-gated action key. Every path here only ever
    /// arms a [`Mode::TextInput`] wizard or a [`Mode::Confirm`] step; nothing
    /// sends a request directly from this function.
    fn on_admin_key(&mut self, key: char) {
        if !self.admin_lease_active() {
            self.status_message = Some("admin lease required; press 'u' to unlock".to_string());
            return;
        }
        match (self.screen, key) {
            (Screen::Profiles, 'c') => {
                self.mode = Mode::TextInput(InputKind::CreateProfileName, String::new());
            }
            (Screen::Profiles, 'n') => {
                if let Some(profile) = self.profiles.get(self.profile_selected).cloned() {
                    self.mode = Mode::TextInput(
                        InputKind::RenameProfileNewName {
                            old_name: profile.name,
                        },
                        String::new(),
                    );
                }
            }
            (Screen::Profiles, 'x') => {
                if let Some(profile) = self.profiles.get(self.profile_selected) {
                    self.mode = Mode::Confirm(PendingAction::DeleteProfile {
                        name: profile.name.clone(),
                    });
                }
            }
            (Screen::Profiles, 'a') => {
                if let Some(profile) = self.profiles.get(self.profile_selected) {
                    self.mode = Mode::Confirm(PendingAction::ActivateProfile {
                        name: profile.name.clone(),
                    });
                }
            }
            (Screen::Secrets, 'c') => {
                self.mode = Mode::TextInput(InputKind::CreateSecretName, String::new());
            }
            (Screen::Secrets, 'e') => {
                if let Some(secret) = self.secrets.get(self.secret_selected).cloned() {
                    self.mode = Mode::TextInput(
                        InputKind::UpdateSecretDescription { name: secret.name },
                        String::new(),
                    );
                }
            }
            (Screen::Secrets, 'n') => {
                if let Some(secret) = self.secrets.get(self.secret_selected).cloned() {
                    self.mode = Mode::TextInput(
                        InputKind::RenameSecretNewName {
                            old_name: secret.name,
                        },
                        String::new(),
                    );
                }
            }
            (Screen::Secrets, 'x') => {
                if let Some(secret) = self.secrets.get(self.secret_selected) {
                    self.mode = Mode::Confirm(PendingAction::DeleteSecret {
                        name: secret.name.clone(),
                    });
                }
            }
            (Screen::Secrets, 'g') => {
                if let Some(secret) = self.secrets.get(self.secret_selected) {
                    self.mode = Mode::Confirm(PendingAction::GenerateSecretValue {
                        name: secret.name.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    fn on_key_password(&mut self, code: crossterm::event::KeyCode, mut buffer: Zeroizing<String>) {
        use crossterm::event::KeyCode;
        match code {
            KeyCode::Enter => {
                let password = SensitiveBytes::new(std::mem::take(&mut *buffer).into_bytes());
                match self
                    .client
                    .admin_unlock(password, DEFAULT_ADMIN_LEASE_MINUTES)
                {
                    Ok(status) => {
                        self.admin_status = Some(status);
                        self.status_message = Some("admin lease unlocked".to_string());
                    }
                    Err(error) => self.status_message = Some(describe_error(&error)),
                }
                self.mode = Mode::Normal;
            }
            KeyCode::Esc => {
                self.status_message = Some("admin unlock cancelled".to_string());
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.mode = Mode::PasswordInput(buffer);
            }
            KeyCode::Char(character) => {
                if !character.is_control() {
                    buffer.push(character);
                }
                self.mode = Mode::PasswordInput(buffer);
            }
            _ => self.mode = Mode::PasswordInput(buffer),
        }
    }

    fn on_key_text(
        &mut self,
        code: crossterm::event::KeyCode,
        kind: InputKind,
        mut buffer: String,
    ) {
        use crossterm::event::KeyCode;
        match code {
            KeyCode::Enter => self.submit_text_input(kind, buffer),
            KeyCode::Esc => {
                self.status_message = Some("cancelled".to_string());
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.mode = Mode::TextInput(kind, buffer);
            }
            KeyCode::Char(character) => {
                if !character.is_control() {
                    buffer.push(character);
                }
                self.mode = Mode::TextInput(kind, buffer);
            }
            _ => self.mode = Mode::TextInput(kind, buffer),
        }
    }

    /// Advances a text-input wizard: either arms the next field or, once every
    /// field for the action is collected, arms the confirmation step. Never
    /// sends a request itself.
    fn submit_text_input(&mut self, kind: InputKind, buffer: String) {
        match kind {
            InputKind::CreateProfileName => {
                if buffer.is_empty() {
                    self.status_message = Some("profile name cannot be empty".to_string());
                    self.mode = Mode::TextInput(InputKind::CreateProfileName, buffer);
                    return;
                }
                self.mode = Mode::TextInput(
                    InputKind::CreateProfileDescription { name: buffer },
                    String::new(),
                );
            }
            InputKind::CreateProfileDescription { name } => {
                self.mode = Mode::Confirm(PendingAction::CreateProfile {
                    name,
                    description: normalize_optional(buffer),
                });
            }
            InputKind::RenameProfileNewName { old_name } => {
                if buffer.is_empty() {
                    self.status_message = Some("new profile name cannot be empty".to_string());
                    self.mode =
                        Mode::TextInput(InputKind::RenameProfileNewName { old_name }, buffer);
                    return;
                }
                self.mode = Mode::Confirm(PendingAction::RenameProfile {
                    old_name,
                    new_name: buffer,
                });
            }
            InputKind::CreateSecretName => {
                if buffer.is_empty() {
                    self.status_message = Some("secret name cannot be empty".to_string());
                    self.mode = Mode::TextInput(InputKind::CreateSecretName, buffer);
                    return;
                }
                self.mode = Mode::TextInput(
                    InputKind::CreateSecretDescription { name: buffer },
                    String::new(),
                );
            }
            InputKind::CreateSecretDescription { name } => {
                self.mode = Mode::Confirm(PendingAction::CreateSecret {
                    name,
                    description: normalize_optional(buffer),
                });
            }
            InputKind::UpdateSecretDescription { name } => {
                self.mode = Mode::Confirm(PendingAction::UpdateSecretDescription {
                    name,
                    description: normalize_optional(buffer),
                });
            }
            InputKind::RenameSecretNewName { old_name } => {
                if buffer.is_empty() {
                    self.status_message = Some("new secret name cannot be empty".to_string());
                    self.mode =
                        Mode::TextInput(InputKind::RenameSecretNewName { old_name }, buffer);
                    return;
                }
                self.mode = Mode::Confirm(PendingAction::RenameSecret {
                    old_name,
                    new_name: buffer,
                });
            }
        }
    }

    fn on_key_confirm(&mut self, code: crossterm::event::KeyCode, action: PendingAction) {
        use crossterm::event::KeyCode;
        match code {
            KeyCode::Char('y' | 'Y') | KeyCode::Enter => self.execute_pending(action),
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                self.status_message = Some("cancelled".to_string());
                self.mode = Mode::Normal;
            }
            _ => self.mode = Mode::Confirm(action),
        }
    }

    /// Sends the confirmed action's request and refreshes whatever list it
    /// affected. This is the only place in `App` that issues a mutating
    /// daemon call.
    fn execute_pending(&mut self, action: PendingAction) {
        self.mode = Mode::Normal;
        match action {
            PendingAction::LockAdmin => match self.client.admin_lock() {
                Ok(()) => {
                    self.status_message = Some("admin lease locked".to_string());
                    self.refresh_dashboard();
                }
                Err(error) => self.status_message = Some(describe_error(&error)),
            },
            PendingAction::CreateProfile { .. }
            | PendingAction::RenameProfile { .. }
            | PendingAction::DeleteProfile { .. }
            | PendingAction::ActivateProfile { .. } => self.execute_profile_action(action),
            PendingAction::CreateSecret { .. }
            | PendingAction::UpdateSecretDescription { .. }
            | PendingAction::RenameSecret { .. }
            | PendingAction::DeleteSecret { .. }
            | PendingAction::GenerateSecretValue { .. } => self.execute_secret_action(action),
        }
    }

    fn execute_profile_action(&mut self, action: PendingAction) {
        match action {
            PendingAction::CreateProfile { name, description } => {
                match self.client.create_profile(name, description) {
                    Ok(profile) => {
                        self.status_message = Some(format!("created profile '{}'", profile.name));
                        self.refresh_profiles();
                    }
                    Err(error) => self.status_message = Some(describe_error(&error)),
                }
            }
            PendingAction::RenameProfile { old_name, new_name } => {
                match self.client.rename_profile(old_name, new_name) {
                    Ok(profile) => {
                        self.status_message =
                            Some(format!("renamed profile to '{}'", profile.name));
                        self.refresh_profiles();
                    }
                    Err(error) => self.status_message = Some(describe_error(&error)),
                }
            }
            PendingAction::DeleteProfile { name } => match self.client.delete_profile(name) {
                Ok(()) => {
                    self.status_message = Some("profile deleted".to_string());
                    self.refresh_profiles();
                }
                Err(error) => self.status_message = Some(describe_error(&error)),
            },
            PendingAction::ActivateProfile { name } => match self.client.activate_profile(name) {
                Ok(profile) => {
                    self.status_message = Some(format!("activated profile '{}'", profile.name));
                    self.refresh_dashboard();
                    self.refresh_profiles();
                }
                Err(error) => self.status_message = Some(describe_error(&error)),
            },
            PendingAction::LockAdmin
            | PendingAction::CreateSecret { .. }
            | PendingAction::UpdateSecretDescription { .. }
            | PendingAction::RenameSecret { .. }
            | PendingAction::DeleteSecret { .. }
            | PendingAction::GenerateSecretValue { .. } => {
                unreachable!("execute_pending only routes profile actions here")
            }
        }
    }

    fn execute_secret_action(&mut self, action: PendingAction) {
        match action {
            PendingAction::CreateSecret { name, description } => {
                match self.client.create_generated_secret(
                    name,
                    description,
                    GeneratorSpec::default(),
                ) {
                    Ok(secret) => {
                        self.status_message = Some(format!("created secret '{}'", secret.name));
                        self.refresh_secrets();
                    }
                    Err(error) => self.status_message = Some(describe_error(&error)),
                }
            }
            PendingAction::UpdateSecretDescription { name, description } => {
                match self.client.update_secret_description(name, description) {
                    Ok(secret) => {
                        self.status_message =
                            Some(format!("updated description of secret '{}'", secret.name));
                        self.refresh_secrets();
                    }
                    Err(error) => self.status_message = Some(describe_error(&error)),
                }
            }
            PendingAction::RenameSecret { old_name, new_name } => {
                match self.client.rename_secret(old_name, new_name) {
                    Ok(secret) => {
                        self.status_message = Some(format!("renamed secret to '{}'", secret.name));
                        self.refresh_secrets();
                    }
                    Err(error) => self.status_message = Some(describe_error(&error)),
                }
            }
            PendingAction::DeleteSecret { name } => match self.client.delete_secret(name) {
                Ok(()) => {
                    self.status_message = Some("secret deleted".to_string());
                    self.refresh_secrets();
                }
                Err(error) => self.status_message = Some(describe_error(&error)),
            },
            PendingAction::GenerateSecretValue { name } => {
                match self
                    .client
                    .generate_secret_value(name, GeneratorSpec::default())
                {
                    Ok(version) => {
                        self.status_message = Some(format!(
                            "rotated secret value to version {}",
                            version.version
                        ));
                        self.refresh_secrets();
                        if self.screen == Screen::Versions {
                            self.refresh_versions();
                        }
                    }
                    Err(error) => self.status_message = Some(describe_error(&error)),
                }
            }
            PendingAction::LockAdmin
            | PendingAction::CreateProfile { .. }
            | PendingAction::RenameProfile { .. }
            | PendingAction::DeleteProfile { .. }
            | PendingAction::ActivateProfile { .. } => {
                unreachable!("execute_pending only routes secret actions here")
            }
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
