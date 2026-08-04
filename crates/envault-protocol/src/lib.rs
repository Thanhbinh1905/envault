#![forbid(unsafe_code)]

use std::io::Write;

pub use envault_broker::{HttpConstraint, HttpContentType, HttpMethod, HttpRequest, HttpResponse};
use envault_core::{
    ConfigFormat, ConfigPreview, ConfigSelector, EnvImportPreview, GeneratorSpec,
    ImportConflictStrategy, PackageKind, PlaintextExportSummary, PortabilityExportSummary,
    PortabilityImportSummary, PortabilityPreview, ProfileView, ResolvedSecretView,
    SecretVersionView, SecretView, WorkspaceView,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 5;
pub const PORTABILITY_REQUEST_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Request<T> {
    pub version: u16,
    pub request_id: Uuid,
    pub body: T,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Response<T> {
    pub version: u16,
    pub request_id: Uuid,
    pub body: ResponseBody<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ResponseBody<T> {
    Ok(T),
    Error(StructuredError),
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn matches(&self, other: &Self) -> bool {
        envault_crypto::constant_time_eq(&self.0, &other.0)
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

envault_crypto::redacted_debug!(SensitiveBytes);

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapRequest {
    pub password: SensitiveBytes,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    pub operation: Operation,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Operation {
    Status,
    Lock,
    Stop,
    AdminUnlock {
        password: SensitiveBytes,
        /// `None` requests a lease with no expiration (`--no-expiration`).
        ttl_minutes: Option<u8>,
    },
    AdminStatus,
    AdminLock,
    CreateProfile {
        name: String,
        description: Option<String>,
        workspace: Option<String>,
    },
    ShowProfile {
        name: String,
    },
    ListProfiles,
    CreateWorkspace {
        name: String,
    },
    ListWorkspaces,
    ShowWorkspace {
        name: String,
    },
    LoadWorkspace {
        name: String,
    },
    BindProfileToWorkspace {
        workspace: String,
        profile: String,
    },
    UnbindProfileFromWorkspace {
        workspace: String,
        profile: String,
    },
    DeleteWorkspace {
        name: String,
    },
    UpdateProfile {
        name: String,
        description: Option<String>,
        activate_on_start: Option<bool>,
    },
    RenameProfile {
        old_name: String,
        new_name: String,
    },
    DeleteProfile {
        name: String,
    },
    LoadProfile {
        name: String,
    },
    UnloadProfile {
        name: String,
    },
    CreateSecret {
        profile: String,
        name: String,
        description: Option<String>,
        value: SensitiveBytes,
    },
    CreateGeneratedSecret {
        profile: String,
        name: String,
        description: Option<String>,
        generator: GeneratorSpec,
    },
    ListSecrets,
    ListResolvedSecrets {
        profile: String,
    },
    DescribeSecret {
        profile: String,
        name: String,
    },
    UpdateSecret {
        profile: String,
        name: String,
        description: Option<String>,
    },
    RenameSecret {
        profile: String,
        old_name: String,
        new_name: String,
    },
    DeleteSecret {
        profile: String,
        name: String,
    },
    SetSecretValue {
        profile: String,
        name: String,
        value: SensitiveBytes,
    },
    GenerateSecretValue {
        profile: String,
        name: String,
        generator: GeneratorSpec,
    },
    /// Admin-gated. `password` lets a single call prove admin identity
    /// inline instead of requiring a standing lease from `AdminUnlock`;
    /// `None` falls back to the caller's active lease, if any.
    SetSecretHttpAccess {
        profile: String,
        name: String,
        constraint: HttpConstraint,
        password: Option<SensitiveBytes>,
    },
    RemoveSecretHttpAccess {
        profile: String,
        name: String,
    },
    HttpRequest {
        profile: String,
        name: String,
        request: HttpRequest,
    },
    /// Resolves plaintext env values for `envault run` - the sole path that
    /// hands plaintext to a CLI client, never through stdout.
    RunEnv {
        profiles: Vec<String>,
    },
    /// Resolves a single secret's plaintext for a `{{profile.NAME}}`
    /// placeholder in `envault run`'s command args. Never printed - the CLI
    /// feeds it directly into an anonymous pipe inherited by the spawned
    /// child, substituting the placeholder with a `/dev/fd/<n>` path.
    /// Requires the profile to be in the loaded set, same as `RunEnv`.
    ResolveArgvSecret {
        profile: String,
        name: String,
    },
    /// Mints a bearer token proving the caller just supplied the vault
    /// password, independent of and in addition to the coarser uid-scoped
    /// admin lease. Only a connection holding this token can call
    /// `RevealSecretValue` - a same-uid process that merely observes an
    /// active admin lease cannot mint one for itself without the password.
    IssueRevealToken {
        password: SensitiveBytes,
    },
    /// Decrypts a secret's value for the TUI's admin-gated `Reveal` popup -
    /// the sole path that hands plaintext to a human's eyes. `token` must be
    /// a still-valid token from `IssueRevealToken`.
    RevealSecretValue {
        profile: String,
        name: String,
        token: SensitiveBytes,
    },
    ExportPackage {
        kind: PackageKind,
        profile_name: Option<String>,
        output_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_recipients: Vec<String>,
    },
    PreviewPackageImport {
        expected_kind: PackageKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
        strategy: ImportConflictStrategy,
        rename_to: Option<String>,
    },
    CommitPackageImport {
        expected_kind: PackageKind,
        input_path: String,
        transfer_password: Option<SensitiveBytes>,
        age_identity_path: Option<String>,
        strategy: ImportConflictStrategy,
        rename_to: Option<String>,
        expected_plan_hash: String,
    },
    PreviewEnvImport {
        profile_name: String,
        input_path: String,
        strategy: ImportConflictStrategy,
    },
    CommitEnvImport {
        profile_name: String,
        input_path: String,
        strategy: ImportConflictStrategy,
        expected_plan_hash: String,
    },
    ExportPlaintextEnv {
        profile_name: String,
        output_path: String,
        allow_plaintext: bool,
    },
    /// Plaintext `config export --format yaml`. `--format env` and
    /// `--format encrypted` are dispatched client-side to the existing
    /// `ExportPlaintextEnv`/`ExportPackage` operations instead - see
    /// `docs/adr` on the config CLI surface.
    ExportConfig {
        selector: ConfigSelector,
        format: ConfigFormat,
        output_path: String,
    },
    PreviewConfigImport {
        format: ConfigFormat,
        input_path: String,
        strategy: ImportConflictStrategy,
    },
    CommitConfigImport {
        format: ConfigFormat,
        input_path: String,
        strategy: ImportConflictStrategy,
        expected_plan_hash: String,
    },
}

impl Operation {
    pub const fn is_portability(&self) -> bool {
        matches!(
            self,
            Self::ExportPackage { .. }
                | Self::PreviewPackageImport { .. }
                | Self::CommitPackageImport { .. }
                | Self::PreviewEnvImport { .. }
                | Self::CommitEnvImport { .. }
                | Self::ExportPlaintextEnv { .. }
                | Self::ExportConfig { .. }
                | Self::PreviewConfigImport { .. }
                | Self::CommitConfigImport { .. }
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ServiceState {
    Unlocked,
    Locked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub service: ServiceState,
    pub pid: u32,
    pub loaded_profiles: Vec<String>,
    pub admin_lease_active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdminLeaseStatus {
    pub active: bool,
    pub expires_at: Option<i64>,
}

/// A single resolved `envault run` env var. Carries plaintext across the IPC
/// boundary to the CLI client only so it can be set on a child process's
/// environment - never printed.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: SensitiveBytes,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Reply {
    Status(DaemonStatus),
    AdminStatus(AdminLeaseStatus),
    Profile(ProfileView),
    Profiles(Vec<ProfileView>),
    Workspace(WorkspaceView),
    Workspaces(Vec<WorkspaceView>),
    WorkspaceProfiles(Vec<ProfileView>),
    Secret(SecretView),
    Secrets(Vec<SecretView>),
    ResolvedSecrets(Vec<ResolvedSecretView>),
    SecretValueSet(SecretVersionView),
    HttpResponse(HttpResponse),
    PortabilityExport(PortabilityExportSummary),
    PortabilityPreview(PortabilityPreview),
    PortabilityImport(PortabilityImportSummary),
    EnvImportPreview(EnvImportPreview),
    PlaintextExport(PlaintextExportSummary),
    ConfigPlan(ConfigPreview),
    RunEnv(Vec<EnvVar>),
    ArgvSecret(SensitiveBytes),
    RevealToken(SensitiveBytes),
    SecretPlaintext(SensitiveBytes),
    Acknowledged { no_op: bool },
}

/// Distinguishes an error an agent can resolve by correcting its own input
/// (never reaching a dependency call) from one where a dependency was
/// invoked and failed. Drives the CLI's exit code: `Usage` maps to 2,
/// `Runtime` to 1, so an agent can tell "fix your command" from "the
/// operation genuinely failed" without parsing the message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Usage,
    Runtime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructuredError {
    pub code: String,
    pub message: String,
    pub help: Vec<String>,
    pub request_id: Uuid,
    pub retryable: bool,
    pub kind: ErrorKind,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("frame exceeds one MiB")]
    FrameTooLarge,
    #[error("frame length does not match payload")]
    InvalidLength,
    #[error("protocol version is unsupported")]
    UnsupportedVersion,
    #[error("protocol I/O deadline was exceeded")]
    DeadlineExceeded,
    #[error("CBOR encoding failed")]
    Encode,
    #[error("CBOR decoding failed")]
    Decode,
}

pub fn validate_version(version: u16) -> Result<(), ProtocolError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedVersion)
    }
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = BoundedPayload::new();
    let serialized = ciborium::into_writer(value, &mut payload);
    if payload.overflowed {
        return Err(ProtocolError::FrameTooLarge);
    }
    serialized.map_err(|_| ProtocolError::Encode)?;
    let length = u32::try_from(payload.bytes.len()).map_err(|_| ProtocolError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(4 + payload.bytes.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload.bytes);
    Ok(frame)
}

struct BoundedPayload {
    bytes: Zeroizing<Vec<u8>>,
    overflowed: bool,
}

impl BoundedPayload {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            overflowed: false,
        }
    }
}

impl Write for BoundedPayload {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(total) = self.bytes.len().checked_add(bytes.len()) else {
            self.overflowed = true;
            return Err(std::io::Error::other("frame size overflow"));
        };
        if total > MAX_FRAME_BYTES {
            self.overflowed = true;
            return Err(std::io::Error::other("frame exceeds one MiB"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, ProtocolError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(ProtocolError::InvalidLength)?
        .try_into()
        .map_err(|_| ProtocolError::InvalidLength)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let payload = frame.get(4..).ok_or(ProtocolError::InvalidLength)?;
    if payload.len() != length {
        return Err(ProtocolError::InvalidLength);
    }
    let mut cursor = std::io::Cursor::new(payload);
    let decoded = ciborium::from_reader(&mut cursor).map_err(|_| ProtocolError::Decode)?;
    if usize::try_from(cursor.position()).ok() != Some(payload.len()) {
        return Err(ProtocolError::Decode);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_is_length_delimited() {
        let request = Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            body: AuthenticatedRequest {
                operation: Operation::Status,
            },
        };
        let frame = encode_frame(&request).expect("encode");
        assert_eq!(
            decode_frame::<Request<AuthenticatedRequest>>(&frame).expect("decode"),
            request
        );
    }

    #[test]
    fn frame_decoder_rejects_trailing_cbor_data_inside_the_declared_length() {
        let mut payload = Vec::new();
        ciborium::into_writer(&42_u8, &mut payload).expect("encode");
        payload.push(0);
        let mut frame = u32::try_from(payload.len())
            .expect("bounded payload")
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(&payload);
        assert!(matches!(
            decode_frame::<u8>(&frame),
            Err(ProtocolError::Decode)
        ));
    }

    #[test]
    fn rejects_mismatched_length_and_oversized_frames() {
        let mut frame = encode_frame(&"status").expect("encode");
        frame[3] = frame[3].saturating_add(1);
        assert!(matches!(
            decode_frame::<String>(&frame),
            Err(ProtocolError::InvalidLength)
        ));
        let oversized = vec![0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            decode_frame::<String>(&oversized),
            Err(ProtocolError::FrameTooLarge)
        ));
        assert!(matches!(
            encode_frame(&vec![0_u8; MAX_FRAME_BYTES + 1]),
            Err(ProtocolError::FrameTooLarge)
        ));
    }

    #[test]
    fn sensitive_fields_are_redacted_and_version_is_exact() {
        let secret = SensitiveBytes::new(b"protocol-secret-sentinel".to_vec());
        assert_eq!(format!("{secret:?}"), "SensitiveBytes([REDACTED])");
        assert!(!format!("{secret:?}").contains("protocol-secret-sentinel"));
        assert_eq!(validate_version(PROTOCOL_VERSION), Ok(()));
        assert!(matches!(
            validate_version(PROTOCOL_VERSION + 1),
            Err(ProtocolError::UnsupportedVersion)
        ));
    }
}
