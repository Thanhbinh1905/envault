use std::str::FromStr;

use envault_broker::{
    BrokerError, HttpConstraint, HttpMethod, HttpRequest, HttpResponse, PreparedHttpRequest,
    normalize_constraint, prepare_bearer_request,
};
use envault_store::SecretHttpAccessRecord;

use super::{EntityKind, ServiceError, VaultSession};

pub struct AgentHttpRequest(PreparedHttpRequest);

impl core::fmt::Debug for AgentHttpRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AgentHttpRequest([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerFailure {
    RequestRejected,
    NetworkFailure,
    ProviderRejected(u16),
    ResponseRejected,
}

pub fn normalize_agent_http_constraint(
    constraint: HttpConstraint,
) -> Result<HttpConstraint, ServiceError> {
    normalize_constraint(constraint).map_err(ServiceError::from)
}

pub async fn execute_agent_http_request(
    request: AgentHttpRequest,
) -> Result<HttpResponse, BrokerFailure> {
    envault_broker::execute(request.0)
        .await
        .map_err(|error| classify_broker_failure(&error))
}

pub fn classify_broker_failure(error: &BrokerError) -> BrokerFailure {
    match error {
        BrokerError::NetworkFailure | BrokerError::ResolutionFailed => {
            BrokerFailure::NetworkFailure
        }
        BrokerError::ProviderRejected(status) => BrokerFailure::ProviderRejected(*status),
        BrokerError::RedirectDenied(_)
        | BrokerError::ResponseTypeDenied
        | BrokerError::ResponseTooLarge
        | BrokerError::InvalidResponseEncoding
        | BrokerError::CredentialEchoDenied => BrokerFailure::ResponseRejected,
        BrokerError::InvalidConstraint
        | BrokerError::InvalidUrl
        | BrokerError::InsecureScheme
        | BrokerError::EmbeddedCredentials
        | BrokerError::FragmentDenied
        | BrokerError::OriginDenied
        | BrokerError::UnsupportedMethod
        | BrokerError::MethodDenied
        | BrokerError::PathDenied
        | BrokerError::BodyDenied
        | BrokerError::RequestTooLarge
        | BrokerError::InvalidCredential
        | BrokerError::PrivateAddressDenied => BrokerFailure::RequestRejected,
    }
}

impl VaultSession {
    /// Configures (or replaces) the HTTP allowlist rule for one secret -
    /// the only thing standing between an agent-driven request and the
    /// broker actually calling out. Requires the secret's profile to be
    /// loaded (mirrors `profile load ... --action http`).
    pub fn set_secret_http_access(
        &mut self,
        profile: &str,
        name: &str,
        constraint: HttpConstraint,
    ) -> Result<(), ServiceError> {
        let constraint = normalize_agent_http_constraint(constraint)?;
        let secret = self.secret_by_ref(profile, name, true)?;
        let record = SecretHttpAccessRecord {
            secret_id: secret.id,
            encrypted_host: self.encrypt_entity_text(
                EntityKind::Secret,
                secret.id.0,
                "http_host",
                &constraint.host,
            )?,
            port: constraint.port,
            methods: constraint
                .methods
                .iter()
                .map(HttpMethod::to_string)
                .collect::<Vec<_>>()
                .join(","),
            encrypted_path_prefix: self.encrypt_entity_text(
                EntityKind::Secret,
                secret.id.0,
                "http_path_prefix",
                &constraint.path_prefix,
            )?,
            max_request_bytes: u64::try_from(constraint.max_request_bytes)
                .map_err(|_| ServiceError::Corrupt)?,
            max_response_bytes: u64::try_from(constraint.max_response_bytes)
                .map_err(|_| ServiceError::Corrupt)?,
        };
        self.store.set_secret_http_access(&record)?;
        Ok(())
    }

    pub fn remove_secret_http_access(
        &mut self,
        profile: &str,
        name: &str,
    ) -> Result<(), ServiceError> {
        let secret = self.secret_by_ref(profile, name, false)?;
        self.store.remove_secret_http_access(secret.id)?;
        Ok(())
    }

    /// Prepares an agent-driven HTTP call: the secret must be loaded and
    /// have an allowlist rule matching this request's host/port/method/path;
    /// the plaintext credential goes straight into the broker, never back
    /// to the caller.
    pub fn prepare_http_request(
        &mut self,
        profile: &str,
        name: &str,
        request: HttpRequest,
    ) -> Result<AgentHttpRequest, ServiceError> {
        let secret = self.secret_by_ref(profile, name, true)?;
        let access = self
            .store
            .secret_http_access(secret.id)?
            .ok_or(ServiceError::PermissionDenied)?;
        let host = self.decrypt_entity_text(
            EntityKind::Secret,
            secret.id.0,
            "http_host",
            &access.encrypted_host,
        )?;
        let path_prefix = self.decrypt_entity_text(
            EntityKind::Secret,
            secret.id.0,
            "http_path_prefix",
            &access.encrypted_path_prefix,
        )?;
        let methods = access
            .methods
            .split(',')
            .map(HttpMethod::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ServiceError::Corrupt)?;
        let constraint = HttpConstraint {
            host,
            port: access.port,
            methods,
            path_prefix,
            max_request_bytes: usize::try_from(access.max_request_bytes)
                .map_err(|_| ServiceError::Corrupt)?,
            max_response_bytes: usize::try_from(access.max_response_bytes)
                .map_err(|_| ServiceError::Corrupt)?,
        };
        if secret.status != 0 || secret.value.is_none() {
            return Err(ServiceError::NotFound);
        }
        let credential = self.decrypt_secret_value(&secret)?.into_vec();
        prepare_bearer_request(request, constraint, credential)
            .map(AgentHttpRequest)
            .map_err(ServiceError::from)
    }
}
