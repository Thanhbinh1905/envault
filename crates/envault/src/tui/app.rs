use envault_core::{
    DEFAULT_ADMIN_LEASE_MINUTES, EnvImportPreview, GeneratorSpec, ImportConflictStrategy,
    PackageKind, PortabilityExportSummary, PortabilityImportSummary, PortabilityPreview,
    ProfileView, SecretVersionView, SecretView,
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
    fn reveal_secret_value(
        &self,
        name: &str,
        version: Option<u64>,
        token: &SensitiveBytes,
    ) -> Result<SensitiveBytes, ClientError>;
    /// Re-proves the vault password to mint a token bound to the current
    /// admin lease; only a connection holding this token may call
    /// `reveal_secret_value`, so an active lease alone never suffices.
    fn issue_reveal_token(&self, password: SensitiveBytes) -> Result<SensitiveBytes, ClientError>;

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

    fn preview_package_import(
        &self,
        expected_kind: PackageKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
        strategy: ImportConflictStrategy,
        rename_to: Option<String>,
    ) -> Result<PortabilityPreview, ClientError>;
    #[allow(clippy::too_many_arguments)]
    fn commit_package_import(
        &self,
        expected_kind: PackageKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
        strategy: ImportConflictStrategy,
        rename_to: Option<String>,
        expected_plan_hash: String,
    ) -> Result<PortabilityImportSummary, ClientError>;
    fn preview_env_import(
        &self,
        profile_name: String,
        input_path: String,
        strategy: ImportConflictStrategy,
    ) -> Result<EnvImportPreview, ClientError>;
    fn commit_env_import(
        &self,
        profile_name: String,
        input_path: String,
        strategy: ImportConflictStrategy,
        expected_plan_hash: String,
    ) -> Result<PortabilityImportSummary, ClientError>;
    fn export_package(
        &self,
        kind: PackageKind,
        profile_name: Option<String>,
        output_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_recipients: Vec<String>,
    ) -> Result<PortabilityExportSummary, ClientError>;
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
            profile: "base".to_string(),
            name: name.to_string(),
        })? {
            Reply::SecretVersions(versions) => Ok(versions),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn reveal_secret_value(
        &self,
        name: &str,
        version: Option<u64>,
        token: &SensitiveBytes,
    ) -> Result<SensitiveBytes, ClientError> {
        match client::request(Operation::RevealSecretValue {
            profile: "base".to_string(),
            name: name.to_string(),
            version,
            token: token.clone(),
        })? {
            Reply::SecretPlaintext(value) => Ok(value),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn issue_reveal_token(&self, password: SensitiveBytes) -> Result<SensitiveBytes, ClientError> {
        match client::request(Operation::IssueRevealToken { password })? {
            Reply::RevealToken(token) => Ok(token),
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
            ttl_minutes: Some(ttl_minutes),
        })? {
            Reply::AdminStatus(status) => Ok(status),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn admin_lock(&self) -> Result<(), ClientError> {
        match client::request(Operation::AdminLock)? {
            Reply::Acknowledged { .. } => Ok(()),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn create_profile(
        &self,
        name: String,
        description: Option<String>,
    ) -> Result<ProfileView, ClientError> {
        match client::request(Operation::CreateProfile {
            name,
            description,
            workspace: None,
        })? {
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
            Reply::Acknowledged { .. } => Ok(()),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn activate_profile(&self, name: String) -> Result<ProfileView, ClientError> {
        match client::request(Operation::LoadProfile { name })? {
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
            profile: "base".to_string(),
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
        match client::request(Operation::UpdateSecret {
            profile: "base".to_string(),
            name,
            description,
        })? {
            Reply::Secret(secret) => Ok(secret),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn rename_secret(&self, old_name: String, new_name: String) -> Result<SecretView, ClientError> {
        match client::request(Operation::RenameSecret {
            profile: "base".to_string(),
            old_name,
            new_name,
        })? {
            Reply::Secret(secret) => Ok(secret),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn delete_secret(&self, name: String) -> Result<(), ClientError> {
        match client::request(Operation::DeleteSecret {
            profile: "base".to_string(),
            name,
        })? {
            Reply::Acknowledged { .. } => Ok(()),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn generate_secret_value(
        &self,
        name: String,
        generator: GeneratorSpec,
    ) -> Result<SecretVersionView, ClientError> {
        match client::request(Operation::GenerateSecretValue {
            profile: "base".to_string(),
            name,
            generator,
        })? {
            Reply::SecretVersion(version) => Ok(version),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn preview_package_import(
        &self,
        expected_kind: PackageKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
        strategy: ImportConflictStrategy,
        rename_to: Option<String>,
    ) -> Result<PortabilityPreview, ClientError> {
        match client::request(Operation::PreviewPackageImport {
            expected_kind,
            input_path,
            transfer_password,
            age_identity_path,
            strategy,
            rename_to,
        })? {
            Reply::PortabilityPreview(preview) => Ok(preview),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_package_import(
        &self,
        expected_kind: PackageKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
        strategy: ImportConflictStrategy,
        rename_to: Option<String>,
        expected_plan_hash: String,
    ) -> Result<PortabilityImportSummary, ClientError> {
        match client::request(Operation::CommitPackageImport {
            expected_kind,
            input_path,
            transfer_password,
            age_identity_path,
            strategy,
            rename_to,
            expected_plan_hash,
        })? {
            Reply::PortabilityImport(summary) => Ok(summary),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn preview_env_import(
        &self,
        profile_name: String,
        input_path: String,
        strategy: ImportConflictStrategy,
    ) -> Result<EnvImportPreview, ClientError> {
        match client::request(Operation::PreviewEnvImport {
            profile_name,
            input_path,
            strategy,
        })? {
            Reply::EnvImportPreview(preview) => Ok(preview),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn commit_env_import(
        &self,
        profile_name: String,
        input_path: String,
        strategy: ImportConflictStrategy,
        expected_plan_hash: String,
    ) -> Result<PortabilityImportSummary, ClientError> {
        match client::request(Operation::CommitEnvImport {
            profile_name,
            input_path,
            strategy,
            expected_plan_hash,
        })? {
            Reply::PortabilityImport(summary) => Ok(summary),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn export_package(
        &self,
        kind: PackageKind,
        profile_name: Option<String>,
        output_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_recipients: Vec<String>,
    ) -> Result<PortabilityExportSummary, ClientError> {
        match client::request(Operation::ExportPackage {
            kind,
            profile_name,
            output_path,
            transfer_password,
            age_recipients,
        })? {
            Reply::PortabilityExport(summary) => Ok(summary),
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
    Portability,
}

/// Which package or file kind a portability import/export wizard is acting
/// on. Drives which conflict strategies are offered, matching exactly what
/// each daemon operation accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortabilityKind {
    Profile,
    Workspace,
    Env,
}

impl PortabilityKind {
    fn next(self) -> Self {
        match self {
            PortabilityKind::Profile => PortabilityKind::Workspace,
            PortabilityKind::Workspace => PortabilityKind::Env,
            PortabilityKind::Env => PortabilityKind::Profile,
        }
    }

    fn package_kind(self) -> Option<PackageKind> {
        match self {
            PortabilityKind::Profile => Some(PackageKind::Profile),
            PortabilityKind::Workspace => Some(PackageKind::Workspace),
            PortabilityKind::Env => None,
        }
    }

    /// The exact conflict strategy set each daemon operation accepts; the TUI
    /// never offers a strategy an operation would reject.
    fn allowed_strategies(self) -> &'static [ImportConflictStrategy] {
        use ImportConflictStrategy::{Abort, Rename, Replace, Skip};
        match self {
            PortabilityKind::Profile => &[Abort, Skip, Replace, Rename],
            PortabilityKind::Workspace => &[Abort, Replace],
            PortabilityKind::Env => &[Abort, Skip, Replace],
        }
    }

    fn label(self) -> &'static str {
        match self {
            PortabilityKind::Profile => "profile package",
            PortabilityKind::Workspace => "workspace package",
            PortabilityKind::Env => ".env file",
        }
    }
}

fn strategy_label(strategy: ImportConflictStrategy) -> &'static str {
    match strategy {
        ImportConflictStrategy::Abort => "abort",
        ImportConflictStrategy::Skip => "skip",
        ImportConflictStrategy::Replace => "replace",
        ImportConflictStrategy::Rename => "rename",
    }
}

/// The most recently displayed, not-yet-committed import preview. Holding the
/// exact request parameters alongside the returned plan hash means commit can
/// only ever be issued against the state the human actually reviewed.
#[derive(Clone, Debug)]
pub enum PortabilityPreviewState {
    Package {
        expected_kind: PackageKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
        strategy: ImportConflictStrategy,
        rename_to: Option<String>,
        preview: PortabilityPreview,
    },
    Env {
        profile_name: String,
        input_path: String,
        strategy: ImportConflictStrategy,
        preview: EnvImportPreview,
    },
}

impl PortabilityPreviewState {
    fn plan_hash(&self) -> &str {
        match self {
            PortabilityPreviewState::Package { preview, .. } => &preview.plan_hash,
            PortabilityPreviewState::Env { preview, .. } => &preview.plan_hash,
        }
    }
}

/// Which text field a [`Mode::TextInput`] step is collecting, and what to do
/// once the human presses Enter on it. Holds only names, descriptions, and
/// paths, never a secret value.
#[derive(Clone, Debug)]
pub enum InputKind {
    CreateProfileName,
    CreateProfileDescription {
        name: String,
    },
    RenameProfileNewName {
        old_name: String,
    },
    CreateSecretName,
    CreateSecretDescription {
        name: String,
    },
    UpdateSecretDescription {
        name: String,
    },
    RenameSecretNewName {
        old_name: String,
    },
    PortabilityInputPath {
        kind: PortabilityKind,
    },
    PortabilityEnvProfileName {
        input_path: String,
    },
    PortabilityAgeIdentityPath {
        kind: PortabilityKind,
        input_path: String,
    },
    PortabilityRenameTo {
        kind: PortabilityKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
    },
    ExportOutputPath {
        kind: PortabilityKind,
    },
    ExportProfileName {
        kind: PortabilityKind,
        output_path: String,
    },
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
            InputKind::PortabilityInputPath { .. } => "Source file path:",
            InputKind::PortabilityEnvProfileName { .. } => "Destination profile name:",
            InputKind::PortabilityAgeIdentityPath { .. } => {
                "Age identity file path (required when no transfer password was given):"
            }
            InputKind::PortabilityRenameTo { .. } => "Destination profile name for rename:",
            InputKind::ExportOutputPath { .. } => "Destination file path:",
            InputKind::ExportProfileName { .. } => "Profile name to export:",
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
    CommitPortability {
        plan_hash: String,
    },
    ExportPackage {
        kind: PackageKind,
        profile_name: Option<String>,
        output_path: String,
        transfer_password: SensitiveBytes,
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
            PendingAction::CommitPortability { plan_hash } => {
                format!("commit the import with plan hash {plan_hash}")
            }
            PendingAction::ExportPackage {
                kind, output_path, ..
            } => format!(
                "export {} to '{output_path}'",
                PortabilityKind::from(*kind).label()
            ),
        }
    }
}

impl From<PackageKind> for PortabilityKind {
    fn from(kind: PackageKind) -> Self {
        match kind {
            PackageKind::Profile => PortabilityKind::Profile,
            PackageKind::Workspace => PortabilityKind::Workspace,
        }
    }
}

/// Which password a [`Mode::PasswordInput`] step is collecting, and what to
/// do with it once submitted. Distinct from [`InputKind`] because a password
/// buffer must never be handled by the generic text-input path.
#[derive(Clone, Debug)]
pub enum PasswordPurpose {
    AdminUnlock,
    PackageImportTransfer {
        kind: PortabilityKind,
        input_path: String,
    },
    PackageExportTransfer {
        kind: PortabilityKind,
        profile_name: Option<String>,
        output_path: String,
    },
}

/// Input focus for the terminal UI. Only [`Mode::Normal`] responds to the
/// navigation keys; every other mode owns the keyboard until it submits or
/// cancels, so a single keypress can never both select and commit an action.
pub enum Mode {
    Normal,
    PasswordInput(PasswordPurpose, Zeroizing<String>),
    TextInput(InputKind, String),
    Confirm(PendingAction),
    /// A transient plaintext popup opened by `Reveal`. Any key closes it; the
    /// value is never written anywhere but this in-memory buffer, which
    /// zeroizes on drop.
    Reveal(String, Zeroizing<String>),
}

impl std::fmt::Debug for Mode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Normal => write!(formatter, "Normal"),
            Mode::PasswordInput(purpose, buffer) => write!(
                formatter,
                "PasswordInput({purpose:?}, <redacted len={}>)",
                buffer.len()
            ),
            Mode::TextInput(kind, _) => write!(formatter, "TextInput({kind:?}, <input>)"),
            Mode::Confirm(action) => write!(formatter, "Confirm({action:?})"),
            Mode::Reveal(label, buffer) => {
                write!(
                    formatter,
                    "Reveal({label}, <redacted len={}>)",
                    buffer.len()
                )
            }
        }
    }
}

/// Bounded status text shown to the human. Only ever built from a
/// [`ClientError`]'s structured fields, never from a raw protocol dump.
fn describe_error(error: &ClientError) -> String {
    match error {
        ClientError::Remote(structured) => format!("{} ({})", structured.message, structured.code),
        ClientError::PortabilityTimeout => format!(
            "{error} - preview current state before retrying because an atomic commit may have completed"
        ),
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
    portability_kind: PortabilityKind,
    portability_strategy: ImportConflictStrategy,
    portability_preview: Option<PortabilityPreviewState>,
    status_message: Option<String>,
    /// Held only for this process's lifetime; minted by re-proving the vault
    /// password (`IssueRevealToken`), never persisted or logged. Cleared
    /// whenever the admin lease is locked.
    reveal_token: Option<SensitiveBytes>,
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
            portability_kind: PortabilityKind::Profile,
            portability_strategy: ImportConflictStrategy::Abort,
            portability_preview: None,
            status_message: None,
            reveal_token: None,
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

    pub fn portability_kind(&self) -> PortabilityKind {
        self.portability_kind
    }

    pub fn portability_kind_label(&self) -> &'static str {
        self.portability_kind.label()
    }

    pub fn portability_strategy_label(&self) -> &'static str {
        strategy_label(self.portability_strategy)
    }

    pub fn portability_preview(&self) -> Option<&PortabilityPreviewState> {
        self.portability_preview.as_ref()
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

    /// Opens the admin-unlock prompt immediately unless this process already
    /// holds a reveal token, so the TUI - the only place a human can view
    /// plaintext - always re-proves the password itself before the Dashboard
    /// is usable, even if some other same-uid connection already holds an
    /// admin lease. An active lease alone is never treated as sufficient.
    pub fn require_admin_on_entry(&mut self) {
        if self.reveal_token.is_none() {
            self.mode =
                Mode::PasswordInput(PasswordPurpose::AdminUnlock, Zeroizing::new(String::new()));
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
            Screen::Portability => {}
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
            Mode::PasswordInput(purpose, buffer) => self.on_key_password(code, purpose, buffer),
            Mode::TextInput(kind, buffer) => self.on_key_text(code, kind, buffer),
            Mode::Confirm(action) => self.on_key_confirm(code, action),
            Mode::Reveal(..) => self.mode = Mode::Normal,
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
            KeyCode::Char('o') => self.go_to(Screen::Portability),
            KeyCode::Char('r') => self.go_to(self.screen),
            KeyCode::Up | KeyCode::Char('k') => self.move_up(),
            KeyCode::Down | KeyCode::Char('j') => self.move_down(),
            KeyCode::Enter => self.select(),
            KeyCode::Char('u') if self.reveal_token.is_none() => {
                self.status_message = None;
                self.mode = Mode::PasswordInput(
                    PasswordPurpose::AdminUnlock,
                    Zeroizing::new(String::new()),
                );
            }
            KeyCode::Char('L') if self.admin_lease_active() => {
                self.mode = Mode::Confirm(PendingAction::LockAdmin);
            }
            KeyCode::Char(other) if self.screen == Screen::Portability => {
                self.on_portability_key(other);
            }
            KeyCode::Char(other) => self.on_admin_key(other),
            _ => {}
        }
    }

    fn require_admin_lease(&mut self) -> bool {
        if self.admin_lease_active() {
            true
        } else {
            self.status_message = Some("admin lease required; press 'u' to unlock".to_string());
            false
        }
    }

    /// Dispatches a key press scoped to the Portability screen. Kind and
    /// strategy selection never touch the daemon, so they work even before an
    /// admin lease is active; every action that would issue a request is
    /// gated behind [`Self::require_admin_lease`].
    fn on_portability_key(&mut self, key: char) {
        match key {
            'v' => {
                self.portability_kind = self.portability_kind.next();
                self.portability_strategy = ImportConflictStrategy::Abort;
                self.portability_preview = None;
            }
            't' => {
                let allowed = self.portability_kind.allowed_strategies();
                let current = allowed
                    .iter()
                    .position(|candidate| *candidate == self.portability_strategy)
                    .unwrap_or(0);
                self.portability_strategy = allowed[(current + 1) % allowed.len()];
                self.portability_preview = None;
            }
            'i' => {
                if !self.require_admin_lease() {
                    return;
                }
                self.mode = Mode::TextInput(
                    InputKind::PortabilityInputPath {
                        kind: self.portability_kind,
                    },
                    String::new(),
                );
            }
            'x' => {
                if self.portability_kind == PortabilityKind::Env {
                    self.status_message = Some(
                        "export is only available for profile or workspace packages".to_string(),
                    );
                    return;
                }
                if !self.require_admin_lease() {
                    return;
                }
                self.mode = Mode::TextInput(
                    InputKind::ExportOutputPath {
                        kind: self.portability_kind,
                    },
                    String::new(),
                );
            }
            'c' => {
                if !self.require_admin_lease() {
                    return;
                }
                let Some(preview) = self.portability_preview.as_ref() else {
                    self.status_message =
                        Some("no preview to commit; press 'i' to preview first".to_string());
                    return;
                };
                self.mode = Mode::Confirm(PendingAction::CommitPortability {
                    plan_hash: preview.plan_hash().to_string(),
                });
            }
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
            (Screen::Secrets, 'v') => {
                if let Some(secret) = self.secrets.get(self.secret_selected).cloned() {
                    self.reveal_secret(secret.name, None);
                }
            }
            (Screen::Versions, 'v') => {
                if let (Some(secret), Some(version)) = (
                    self.secrets.get(self.secret_selected).cloned(),
                    self.versions.get(self.version_selected),
                ) {
                    let version = version.version;
                    self.reveal_secret(secret.name, Some(version));
                }
            }
            _ => {}
        }
    }

    /// Decrypts and shows a secret's plaintext in a transient popup. The
    /// daemon re-checks both the admin lease and this process's reveal token
    /// at the exact moment of reveal rather than trusting any cached flag,
    /// since either can expire or be revoked between key presses.
    fn reveal_secret(&mut self, name: String, version: Option<u64>) {
        let Some(token) = self.reveal_token.clone() else {
            self.status_message = Some("admin lease required; press 'u' to unlock".to_string());
            return;
        };
        match self.client.reveal_secret_value(&name, version, &token) {
            Ok(value) => {
                let text = String::from_utf8_lossy(value.as_slice()).into_owned();
                self.mode = Mode::Reveal(name, Zeroizing::new(text));
            }
            Err(error) => self.status_message = Some(describe_error(&error)),
        }
    }

    fn on_key_password(
        &mut self,
        code: crossterm::event::KeyCode,
        purpose: PasswordPurpose,
        mut buffer: Zeroizing<String>,
    ) {
        use crossterm::event::KeyCode;
        match code {
            KeyCode::Enter => {
                let password = SensitiveBytes::new(std::mem::take(&mut *buffer).into_bytes());
                match purpose {
                    PasswordPurpose::AdminUnlock => {
                        match self
                            .client
                            .admin_unlock(password.clone(), DEFAULT_ADMIN_LEASE_MINUTES)
                        {
                            Ok(status) => {
                                self.admin_status = Some(status);
                                match self.client.issue_reveal_token(password) {
                                    Ok(token) => {
                                        self.reveal_token = Some(token);
                                        self.status_message =
                                            Some("admin lease unlocked".to_string());
                                    }
                                    Err(error) => {
                                        self.reveal_token = None;
                                        self.status_message = Some(describe_error(&error));
                                    }
                                }
                            }
                            Err(error) => self.status_message = Some(describe_error(&error)),
                        }
                        self.mode = Mode::Normal;
                    }
                    PasswordPurpose::PackageImportTransfer { kind, input_path } => {
                        self.submit_import_transfer_password(kind, input_path, password);
                    }
                    PasswordPurpose::PackageExportTransfer {
                        kind,
                        profile_name,
                        output_path,
                    } => {
                        self.submit_export_transfer_password(
                            kind,
                            profile_name,
                            output_path,
                            password,
                        );
                    }
                }
            }
            KeyCode::Esc => {
                self.status_message = Some("cancelled".to_string());
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.mode = Mode::PasswordInput(purpose, buffer);
            }
            KeyCode::Char(character) => {
                if !character.is_control() {
                    buffer.push(character);
                }
                self.mode = Mode::PasswordInput(purpose, buffer);
            }
            _ => self.mode = Mode::PasswordInput(purpose, buffer),
        }
    }

    /// An empty password is a valid signal to fall back to an age identity
    /// file, matching the CLI's "password or age identity" credential choice.
    fn submit_import_transfer_password(
        &mut self,
        kind: PortabilityKind,
        input_path: String,
        password: SensitiveBytes,
    ) {
        if password.is_empty() {
            self.mode = Mode::TextInput(
                InputKind::PortabilityAgeIdentityPath { kind, input_path },
                String::new(),
            );
        } else {
            self.continue_package_import(kind, input_path, Some(password), None);
        }
    }

    fn submit_export_transfer_password(
        &mut self,
        kind: PortabilityKind,
        profile_name: Option<String>,
        output_path: String,
        password: SensitiveBytes,
    ) {
        if password.is_empty() {
            self.status_message = Some(
                "choose a transfer password to export this package; age recipients are not yet supported from the terminal UI"
                    .to_string(),
            );
            self.mode = Mode::Normal;
            return;
        }
        let Some(package_kind) = kind.package_kind() else {
            self.status_message =
                Some("export is only available for profile or workspace packages".to_string());
            self.mode = Mode::Normal;
            return;
        };
        self.mode = Mode::Confirm(PendingAction::ExportPackage {
            kind: package_kind,
            profile_name,
            output_path,
            transfer_password: password,
        });
    }

    /// Continues a package import wizard after credentials are known: collects
    /// a rename target when the current strategy requires one, otherwise
    /// issues the preview request immediately.
    fn continue_package_import(
        &mut self,
        kind: PortabilityKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
    ) {
        if self.portability_strategy == ImportConflictStrategy::Rename {
            self.mode = Mode::TextInput(
                InputKind::PortabilityRenameTo {
                    kind,
                    input_path,
                    transfer_password,
                    age_identity_path,
                },
                String::new(),
            );
        } else {
            self.mode = Mode::Normal;
            self.request_package_preview(
                kind,
                input_path,
                transfer_password,
                age_identity_path,
                None,
            );
        }
    }

    /// Issues a package import preview. Clears any previously displayed plan
    /// hash before the request is sent, not just when the response arrives,
    /// so there is never a window where a stale hash could be committed.
    fn request_package_preview(
        &mut self,
        kind: PortabilityKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
        rename_to: Option<String>,
    ) {
        self.portability_preview = None;
        let Some(expected_kind) = kind.package_kind() else {
            self.status_message =
                Some("package preview requires a profile or workspace kind".to_string());
            return;
        };
        let strategy = self.portability_strategy;
        match self.client.preview_package_import(
            expected_kind,
            input_path.clone(),
            transfer_password.clone(),
            age_identity_path.clone(),
            strategy,
            rename_to.clone(),
        ) {
            Ok(preview) => {
                self.status_message =
                    Some(format!("preview ready: plan hash {}", preview.plan_hash));
                self.portability_preview = Some(PortabilityPreviewState::Package {
                    expected_kind,
                    input_path,
                    transfer_password,
                    age_identity_path,
                    strategy,
                    rename_to,
                    preview,
                });
            }
            Err(error) => self.status_message = Some(describe_error(&error)),
        }
    }

    /// Issues an `.env` import preview. Like [`Self::request_package_preview`],
    /// invalidates any prior plan hash before the request is sent.
    fn request_env_preview(&mut self, profile_name: String, input_path: String) {
        self.portability_preview = None;
        let strategy = self.portability_strategy;
        match self
            .client
            .preview_env_import(profile_name.clone(), input_path.clone(), strategy)
        {
            Ok(preview) => {
                self.status_message =
                    Some(format!("preview ready: plan hash {}", preview.plan_hash));
                self.portability_preview = Some(PortabilityPreviewState::Env {
                    profile_name,
                    input_path,
                    strategy,
                    preview,
                });
            }
            Err(error) => self.status_message = Some(describe_error(&error)),
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
    /// field for the action is collected, arms the confirmation step or issues
    /// the request. Never sends a mutating request itself; only preview
    /// requests (which are non-mutating) are issued directly from here.
    fn submit_text_input(&mut self, kind: InputKind, buffer: String) {
        match kind {
            InputKind::PortabilityInputPath { .. }
            | InputKind::PortabilityEnvProfileName { .. }
            | InputKind::PortabilityAgeIdentityPath { .. }
            | InputKind::PortabilityRenameTo { .. }
            | InputKind::ExportOutputPath { .. }
            | InputKind::ExportProfileName { .. } => {
                self.submit_portability_text_input(kind, buffer);
            }
            _ => self.submit_profile_or_secret_text_input(kind, buffer),
        }
    }

    fn submit_profile_or_secret_text_input(&mut self, kind: InputKind, buffer: String) {
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
            InputKind::PortabilityInputPath { .. }
            | InputKind::PortabilityEnvProfileName { .. }
            | InputKind::PortabilityAgeIdentityPath { .. }
            | InputKind::PortabilityRenameTo { .. }
            | InputKind::ExportOutputPath { .. }
            | InputKind::ExportProfileName { .. } => {
                unreachable!("submit_text_input routes portability inputs elsewhere")
            }
        }
    }

    /// Advances a portability import or export wizard. Preview requests are
    /// non-mutating and are issued directly once every required field is
    /// collected; export and rename-target collection instead arm the next
    /// input step or the confirmation step.
    fn submit_portability_text_input(&mut self, kind: InputKind, buffer: String) {
        match kind {
            InputKind::PortabilityInputPath { .. }
            | InputKind::PortabilityEnvProfileName { .. }
            | InputKind::PortabilityAgeIdentityPath { .. }
            | InputKind::PortabilityRenameTo { .. } => {
                self.submit_portability_import_input(kind, buffer);
            }
            InputKind::ExportOutputPath { .. } | InputKind::ExportProfileName { .. } => {
                self.submit_portability_export_input(kind, buffer);
            }
            InputKind::CreateProfileName
            | InputKind::CreateProfileDescription { .. }
            | InputKind::RenameProfileNewName { .. }
            | InputKind::CreateSecretName
            | InputKind::CreateSecretDescription { .. }
            | InputKind::UpdateSecretDescription { .. }
            | InputKind::RenameSecretNewName { .. } => {
                unreachable!("submit_text_input routes profile/secret inputs elsewhere")
            }
        }
    }

    fn submit_portability_import_input(&mut self, kind: InputKind, buffer: String) {
        match kind {
            InputKind::PortabilityInputPath { kind } => {
                if buffer.is_empty() {
                    self.status_message = Some("source file path cannot be empty".to_string());
                    self.mode = Mode::TextInput(InputKind::PortabilityInputPath { kind }, buffer);
                    return;
                }
                match kind {
                    PortabilityKind::Env => {
                        self.mode = Mode::TextInput(
                            InputKind::PortabilityEnvProfileName { input_path: buffer },
                            String::new(),
                        );
                    }
                    PortabilityKind::Profile | PortabilityKind::Workspace => {
                        self.mode = Mode::PasswordInput(
                            PasswordPurpose::PackageImportTransfer {
                                kind,
                                input_path: buffer,
                            },
                            Zeroizing::new(String::new()),
                        );
                    }
                }
            }
            InputKind::PortabilityEnvProfileName { input_path } => {
                if buffer.is_empty() {
                    self.status_message =
                        Some("destination profile name cannot be empty".to_string());
                    self.mode = Mode::TextInput(
                        InputKind::PortabilityEnvProfileName { input_path },
                        buffer,
                    );
                    return;
                }
                self.mode = Mode::Normal;
                self.request_env_preview(buffer, input_path);
            }
            InputKind::PortabilityAgeIdentityPath { kind, input_path } => {
                if buffer.is_empty() {
                    self.status_message =
                        Some("choose a transfer password or an age identity file".to_string());
                    self.mode = Mode::TextInput(
                        InputKind::PortabilityAgeIdentityPath { kind, input_path },
                        buffer,
                    );
                    return;
                }
                self.continue_package_import(kind, input_path, None, Some(buffer));
            }
            InputKind::PortabilityRenameTo {
                kind,
                input_path,
                transfer_password,
                age_identity_path,
            } => {
                if buffer.is_empty() {
                    self.status_message =
                        Some("destination profile name cannot be empty".to_string());
                    self.mode = Mode::TextInput(
                        InputKind::PortabilityRenameTo {
                            kind,
                            input_path,
                            transfer_password,
                            age_identity_path,
                        },
                        buffer,
                    );
                    return;
                }
                self.mode = Mode::Normal;
                self.request_package_preview(
                    kind,
                    input_path,
                    transfer_password,
                    age_identity_path,
                    Some(buffer),
                );
            }
            InputKind::ExportOutputPath { .. }
            | InputKind::ExportProfileName { .. }
            | InputKind::CreateProfileName
            | InputKind::CreateProfileDescription { .. }
            | InputKind::RenameProfileNewName { .. }
            | InputKind::CreateSecretName
            | InputKind::CreateSecretDescription { .. }
            | InputKind::UpdateSecretDescription { .. }
            | InputKind::RenameSecretNewName { .. } => {
                unreachable!("submit_portability_text_input routes this input elsewhere")
            }
        }
    }

    fn submit_portability_export_input(&mut self, kind: InputKind, buffer: String) {
        match kind {
            InputKind::ExportOutputPath { kind } => {
                if buffer.is_empty() {
                    self.status_message = Some("destination file path cannot be empty".to_string());
                    self.mode = Mode::TextInput(InputKind::ExportOutputPath { kind }, buffer);
                    return;
                }
                match kind {
                    PortabilityKind::Profile => {
                        self.mode = Mode::TextInput(
                            InputKind::ExportProfileName {
                                kind,
                                output_path: buffer,
                            },
                            String::new(),
                        );
                    }
                    PortabilityKind::Workspace => {
                        self.mode = Mode::PasswordInput(
                            PasswordPurpose::PackageExportTransfer {
                                kind,
                                profile_name: None,
                                output_path: buffer,
                            },
                            Zeroizing::new(String::new()),
                        );
                    }
                    PortabilityKind::Env => {
                        self.status_message = Some(
                            "export is only available for profile or workspace packages"
                                .to_string(),
                        );
                        self.mode = Mode::Normal;
                    }
                }
            }
            InputKind::ExportProfileName { kind, output_path } => {
                if buffer.is_empty() {
                    self.status_message = Some("profile name cannot be empty".to_string());
                    self.mode =
                        Mode::TextInput(InputKind::ExportProfileName { kind, output_path }, buffer);
                    return;
                }
                self.mode = Mode::PasswordInput(
                    PasswordPurpose::PackageExportTransfer {
                        kind,
                        profile_name: Some(buffer),
                        output_path,
                    },
                    Zeroizing::new(String::new()),
                );
            }
            InputKind::PortabilityInputPath { .. }
            | InputKind::PortabilityEnvProfileName { .. }
            | InputKind::PortabilityAgeIdentityPath { .. }
            | InputKind::PortabilityRenameTo { .. }
            | InputKind::CreateProfileName
            | InputKind::CreateProfileDescription { .. }
            | InputKind::RenameProfileNewName { .. }
            | InputKind::CreateSecretName
            | InputKind::CreateSecretDescription { .. }
            | InputKind::UpdateSecretDescription { .. }
            | InputKind::RenameSecretNewName { .. } => {
                unreachable!("submit_portability_export_input routes this input elsewhere")
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
                    self.reveal_token = None;
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
            PendingAction::CommitPortability { .. } => self.execute_portability_commit(),
            PendingAction::ExportPackage {
                kind,
                profile_name,
                output_path,
                transfer_password,
            } => self.execute_export_package(kind, profile_name, output_path, transfer_password),
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
            | PendingAction::GenerateSecretValue { .. }
            | PendingAction::CommitPortability { .. }
            | PendingAction::ExportPackage { .. } => {
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
            | PendingAction::ActivateProfile { .. }
            | PendingAction::CommitPortability { .. }
            | PendingAction::ExportPackage { .. } => {
                unreachable!("execute_pending only routes secret actions here")
            }
        }
    }

    /// Commits the currently held preview and consumes it, whether the commit
    /// succeeds or fails. A stale or repeated commit is impossible: after this
    /// call there is no plan hash left in state until a fresh preview is
    /// requested.
    fn execute_portability_commit(&mut self) {
        let Some(preview_state) = self.portability_preview.take() else {
            self.status_message = Some("no preview to commit".to_string());
            return;
        };
        match preview_state {
            PortabilityPreviewState::Package {
                expected_kind,
                input_path,
                transfer_password,
                age_identity_path,
                strategy,
                rename_to,
                preview,
            } => match self.client.commit_package_import(
                expected_kind,
                input_path,
                transfer_password,
                age_identity_path,
                strategy,
                rename_to,
                preview.plan_hash,
            ) {
                Ok(summary) => {
                    self.status_message = Some(describe_import_summary(&summary));
                    self.refresh_dashboard();
                    self.refresh_profiles();
                }
                Err(error) => self.status_message = Some(describe_error(&error)),
            },
            PortabilityPreviewState::Env {
                profile_name,
                input_path,
                strategy,
                preview,
            } => match self.client.commit_env_import(
                profile_name,
                input_path,
                strategy,
                preview.plan_hash,
            ) {
                Ok(summary) => {
                    self.status_message = Some(describe_import_summary(&summary));
                    self.refresh_secrets();
                }
                Err(error) => self.status_message = Some(describe_error(&error)),
            },
        }
    }

    fn execute_export_package(
        &mut self,
        kind: PackageKind,
        profile_name: Option<String>,
        output_path: String,
        transfer_password: SensitiveBytes,
    ) {
        match self.client.export_package(
            kind,
            profile_name,
            output_path,
            Some(transfer_password),
            Vec::new(),
        ) {
            Ok(summary) => {
                self.status_message = Some(format!(
                    "exported package {} to '{}'",
                    summary.package_id, summary.output_path
                ));
            }
            Err(error) => self.status_message = Some(describe_error(&error)),
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
            Screen::Dashboard | Screen::Portability => {}
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
            Screen::Dashboard | Screen::Portability => {}
        }
    }

    fn select(&mut self) {
        if self.screen == Screen::Secrets && !self.secrets.is_empty() {
            self.go_to(Screen::Versions);
        }
    }
}

fn describe_import_summary(summary: &PortabilityImportSummary) -> String {
    format!(
        "import committed: {} created, {} replaced, {} skipped, {} versions appended",
        summary.created, summary.replaced, summary.skipped, summary.versions_appended
    )
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;

    use super::*;
    use crate::tui::test_support::{
        FakeClient, sample_admin_status, sample_env_preview, sample_import_summary, sample_profile,
        sample_secret, sample_status, sample_version,
    };

    fn app_with(client: FakeClient) -> App<FakeClient> {
        let mut app = App::new(client);
        app.refresh_dashboard();
        app
    }

    #[test]
    fn navigation_moves_between_screens_and_refreshes_each_list() {
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(false)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(false)));
        client
            .profiles
            .borrow_mut()
            .push_back(Ok(vec![sample_profile("base", None)]));
        // Secrets is refreshed twice: once on entry, once again when Esc
        // returns from Versions back to Secrets.
        for _ in 0..2 {
            client
                .secrets
                .borrow_mut()
                .push_back(Ok(vec![sample_secret("db-password", None)]));
        }
        client
            .versions
            .borrow_mut()
            .push_back(Ok(vec![sample_version(1)]));
        let mut app = app_with(client);
        assert_eq!(app.screen(), Screen::Dashboard);

        app.on_key(KeyCode::Char('p'));
        assert_eq!(app.screen(), Screen::Profiles);
        assert_eq!(app.profiles().len(), 1);

        app.on_key(KeyCode::Char('s'));
        assert_eq!(app.screen(), Screen::Secrets);
        assert_eq!(app.secrets().len(), 1);

        app.on_key(KeyCode::Enter);
        assert_eq!(app.screen(), Screen::Versions);
        assert_eq!(app.versions().len(), 1);

        app.on_key(KeyCode::Esc);
        assert_eq!(app.screen(), Screen::Secrets);
    }

    #[test]
    fn password_input_cancel_returns_to_normal_without_calling_the_client() {
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(false)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(false)));
        // No entry queued in `admin_unlock`: if Esc-cancel ever reached the
        // client, `pop()` would panic instead of the assertion below firing.
        let mut app = app_with(client);

        app.on_key(KeyCode::Char('u'));
        assert!(matches!(app.mode(), Mode::PasswordInput(..)));
        app.on_key(KeyCode::Char('x'));
        app.on_key(KeyCode::Esc);
        assert!(matches!(app.mode(), Mode::Normal));
        assert!(!app.admin_lease_active());
    }

    #[test]
    fn mutating_action_requires_explicit_confirmation_before_it_can_commit() {
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(true)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(true)));
        client.profiles.borrow_mut().push_back(Ok(Vec::new()));
        let mut app = app_with(client);
        app.on_key(KeyCode::Char('p'));

        app.on_key(KeyCode::Char('c'));
        for character in "team".chars() {
            app.on_key(KeyCode::Char(character));
        }
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Enter);
        assert!(matches!(
            app.mode(),
            Mode::Confirm(PendingAction::CreateProfile { .. })
        ));

        // A single keypress that both selects and commits would be a defect;
        // cancelling here must not have sent anything (no `profiles` entry
        // beyond the initial listing is queued, so a real send would panic).
        app.on_key(KeyCode::Char('n'));
        assert!(matches!(app.mode(), Mode::Normal));
    }

    #[test]
    fn reissuing_a_preview_clears_the_prior_plan_hash_before_the_new_response_lands() {
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(true)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(true)));
        client
            .preview_env
            .borrow_mut()
            .push_back(Ok(sample_env_preview("hash-one")));
        client
            .preview_env
            .borrow_mut()
            .push_back(Err(ClientError::Timeout));
        let mut app = app_with(client);

        app.request_env_preview("base".to_string(), "/tmp/one.env".to_string());
        assert_eq!(app.portability_preview().unwrap().plan_hash(), "hash-one");

        // The old hash is cleared the moment a new preview is requested, not
        // only once a response arrives, so even a failing re-preview leaves
        // no stale hash behind.
        app.request_env_preview("base".to_string(), "/tmp/one.env".to_string());
        assert!(app.portability_preview().is_none());
    }

    #[test]
    fn commit_consumes_the_preview_so_a_repeated_commit_cannot_reuse_a_hash() {
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(true)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(true)));
        client
            .preview_env
            .borrow_mut()
            .push_back(Ok(sample_env_preview("hash-two")));
        client
            .commit_env
            .borrow_mut()
            .push_back(Ok(sample_import_summary()));
        // A successful `.env` commit refreshes the secrets list.
        client.secrets.borrow_mut().push_back(Ok(Vec::new()));
        let mut app = app_with(client);

        app.request_env_preview("base".to_string(), "/tmp/two.env".to_string());
        assert!(app.portability_preview().is_some());

        app.execute_portability_commit();
        assert!(
            app.portability_preview().is_none(),
            "a successful commit must consume the held preview"
        );

        // A second commit attempt with no fresh preview must not reach the
        // client at all: the `commit_env` queue is empty, so a real send
        // would panic instead of the status message below being set.
        app.execute_portability_commit();
        assert_eq!(app.status_message(), Some("no preview to commit"));
    }

    #[test]
    fn reveal_is_gated_behind_an_active_admin_lease() {
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(false)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(false)));
        client
            .secrets
            .borrow_mut()
            .push_back(Ok(vec![sample_secret("db-password", None)]));
        let mut app = app_with(client);
        app.on_key(KeyCode::Char('s'));
        assert_eq!(app.screen(), Screen::Secrets);

        // No entry queued in `reveal`: if the lease check were skipped, the
        // client call would panic instead of the assertion below firing.
        app.on_key(KeyCode::Char('v'));
        assert!(matches!(app.mode(), Mode::Normal));
        assert_eq!(
            app.status_message(),
            Some("admin lease required; press 'u' to unlock")
        );
    }

    #[test]
    fn reveal_shows_plaintext_in_a_popup_that_any_key_closes() {
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(true)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(true)));
        client
            .secrets
            .borrow_mut()
            .push_back(Ok(vec![sample_secret("db-password", None)]));
        client
            .reveal
            .borrow_mut()
            .push_back(Ok(SensitiveBytes::new(b"s3cr3t-value".to_vec())));
        let mut app = app_with(client);
        app.reveal_token = Some(SensitiveBytes::new(b"reveal-token".to_vec()));
        app.on_key(KeyCode::Char('s'));

        app.on_key(KeyCode::Char('v'));
        match app.mode() {
            Mode::Reveal(name, value) => {
                assert_eq!(name, "db-password");
                assert_eq!(value.as_str(), "s3cr3t-value");
            }
            other => panic!("expected Mode::Reveal, got {other:?}"),
        }

        app.on_key(KeyCode::Esc);
        assert!(matches!(app.mode(), Mode::Normal));
    }

    #[test]
    fn entering_the_tui_without_an_active_lease_opens_the_admin_unlock_prompt() {
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(false)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(false)));
        let mut app = app_with(client);

        app.require_admin_on_entry();
        assert!(matches!(app.mode(), Mode::PasswordInput(..)));
    }

    #[test]
    fn entering_the_tui_with_an_active_lease_but_no_reveal_token_still_prompts() {
        // An admin lease active from some other same-uid connection is never
        // sufficient on its own: this process must re-prove the password
        // itself to mint its own reveal token.
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(true)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(true)));
        let mut app = app_with(client);

        app.require_admin_on_entry();
        assert!(matches!(app.mode(), Mode::PasswordInput(..)));
    }

    #[test]
    fn entering_the_tui_with_a_cached_reveal_token_does_not_prompt() {
        let client = FakeClient::default();
        client
            .status
            .borrow_mut()
            .push_back(Ok(sample_status(true)));
        client
            .admin_status
            .borrow_mut()
            .push_back(Ok(sample_admin_status(true)));
        let mut app = app_with(client);
        app.reveal_token = Some(SensitiveBytes::new(b"reveal-token".to_vec()));

        app.require_admin_on_entry();
        assert!(matches!(app.mode(), Mode::Normal));
    }
}
