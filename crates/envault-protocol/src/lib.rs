#![forbid(unsafe_code)]

use std::{fmt, io::Write};

pub use envault_broker::{HttpConstraint, HttpContentType, HttpMethod, HttpRequest, HttpResponse};
use envault_core::{
    ApprovalId, GeneratorSpec, GrantId, PrincipalId, PrincipalKind, PrincipalView, ProfileView,
    SecretId, SecretVersionView, SecretView, VaultId,
};
use envault_policy::{Action, Effect, ResourceSelector, Rule};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 5;

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
        if self.0.len() != other.0.len() {
            return false;
        }
        self.0
            .iter()
            .zip(&other.0)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveBytes([REDACTED])")
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapRequest {
    pub password: SensitiveBytes,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    pub capability_token: Option<SensitiveBytes>,
    pub operation: Operation,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Operation {
    Status,
    Context,
    Lock,
    Stop,
    AdminUnlock {
        password: SensitiveBytes,
        ttl_minutes: u8,
    },
    AdminStatus,
    AdminLock,
    CreateAgentSession {
        principal_id: PrincipalId,
        action: Action,
        resource: ResourceSelector,
        http_constraint: Option<HttpConstraint>,
        ttl_minutes: u8,
        max_requests: u32,
    },
    AgentSessionStatus,
    RevokeAgentSession {
        grant_id: GrantId,
    },
    CreatePrincipal {
        kind: PrincipalKind,
        name: String,
    },
    ListPrincipals,
    SetPrincipalDisabled {
        principal_id: PrincipalId,
        disabled: bool,
    },
    CreatePolicyRule {
        principal_id: PrincipalId,
        effect: Effect,
        action: Action,
        resource: ResourceSelector,
    },
    ListPolicyRules,
    CreateProfile {
        name: String,
        description: Option<String>,
    },
    ShowProfile {
        name: String,
    },
    ListProfiles,
    UpdateProfile {
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
        value: SensitiveBytes,
    },
    CreateGeneratedSecret {
        name: String,
        description: Option<String>,
        generator: GeneratorSpec,
    },
    ListSecrets,
    DescribeSecret {
        name: String,
    },
    UpdateSecret {
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
    SetSecretValue {
        name: String,
        value: SensitiveBytes,
    },
    GenerateSecretValue {
        name: String,
        generator: GeneratorSpec,
    },
    ListSecretVersions {
        name: String,
    },
    DiscoverSecrets,
    HttpRequest {
        secret_id: SecretId,
        request: HttpRequest,
    },
}

impl Operation {
    pub const fn accepts_agent_capability(&self) -> bool {
        matches!(
            self,
            Self::Status
                | Self::Context
                | Self::AgentSessionStatus
                | Self::DiscoverSecrets
                | Self::HttpRequest { .. }
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
    pub active_profile: Option<String>,
    pub admin_lease_active: bool,
    pub agent_session_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdminLeaseStatus {
    pub active: bool,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionCreated {
    pub token: SensitiveBytes,
    pub grant_id: GrantId,
    pub approval_id: ApprovalId,
    pub expires_at: i64,
    pub max_requests: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionView {
    pub grant_id: GrantId,
    pub principal_id: PrincipalId,
    pub action: Action,
    pub resource: ResourceSelector,
    pub http_constraint: Option<HttpConstraint>,
    pub expires_at: i64,
    pub remaining_requests: u32,
    pub revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentContext {
    pub vault_id: VaultId,
    pub active_profile: ProfileView,
    pub session: AgentSessionView,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Reply {
    Status(DaemonStatus),
    Context(AgentContext),
    AdminStatus(AdminLeaseStatus),
    AgentSessionCreated(AgentSessionCreated),
    AgentSessionStatus(AgentSessionView),
    Principal(PrincipalView),
    Principals(Vec<PrincipalView>),
    PolicyRule(Rule),
    PolicyRules(Vec<Rule>),
    Profile(ProfileView),
    Profiles(Vec<ProfileView>),
    Secret(SecretView),
    Secrets(Vec<SecretView>),
    SecretVersion(SecretVersionView),
    SecretVersions(Vec<SecretVersionView>),
    HttpResponse(HttpResponse),
    Acknowledged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructuredError {
    pub code: String,
    pub message: String,
    pub help: Vec<String>,
    pub request_id: Uuid,
    pub retryable: bool,
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
    ciborium::from_reader(payload).map_err(|_| ProtocolError::Decode)
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
                capability_token: None,
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
        assert!(Operation::Status.accepts_agent_capability());
        assert!(Operation::Context.accepts_agent_capability());
        assert!(Operation::AgentSessionStatus.accepts_agent_capability());
        assert!(Operation::DiscoverSecrets.accepts_agent_capability());
        assert!(!Operation::Lock.accepts_agent_capability());
        assert!(!Operation::AdminLock.accepts_agent_capability());
    }
}
