use envault_broker::{
    BrokerError, HttpConstraint, HttpRequest, HttpResponse, PreparedHttpRequest,
    normalize_constraint, prepare_bearer_request, validate_http_request,
};
use envault_core::{ProfileView, SecretStatus, SecretView};
use envault_policy::{Action, Decision, Grant, Request, ResourceSelector, authorize};
use uuid::Uuid;

use super::{ServiceError, VaultSession};

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
    pub fn active_profile(&self) -> Result<ProfileView, ServiceError> {
        self.profiles()?
            .into_iter()
            .find(|profile| profile.activate_on_start)
            .ok_or(ServiceError::Corrupt)
    }

    pub fn discover_secrets(
        &mut self,
        grant: &mut Grant,
        now: i64,
        request_id: Uuid,
    ) -> Result<Vec<SecretView>, ServiceError> {
        if grant.action != Action::Discover {
            return Err(ServiceError::PermissionDenied);
        }
        let principal_id = grant.principal_id;
        let resource = grant.resource;
        let explanation = self.explain_policy(
            principal_id,
            Action::Discover,
            resource,
            Some(grant),
            now,
            request_id,
        )?;
        if explanation.decision != Decision::Allow {
            return Err(ServiceError::PermissionDenied);
        }

        let candidates = match resource {
            ResourceSelector::Vault(vault_id) if vault_id == self.vault_id => self
                .resolved_secrets(self.active_profile()?.scope_id)?
                .into_iter()
                .map(|resolved| resolved.secret)
                .collect::<Vec<_>>(),
            ResourceSelector::ScopeTree(scope_id) => self
                .resolved_secrets(scope_id)?
                .into_iter()
                .map(|resolved| resolved.secret)
                .collect::<Vec<_>>(),
            ResourceSelector::Secret(secret_id) => {
                let record = self
                    .store
                    .secret_by_id(secret_id)?
                    .ok_or(ServiceError::NotFound)?;
                vec![self.secret_view(&record)?]
            }
            ResourceSelector::Vault(_) => return Err(ServiceError::NotFound),
        };

        let rules = self.policy_rules()?;
        let mut filtered = Vec::new();
        for secret in candidates
            .into_iter()
            .filter(|secret| secret.status == SecretStatus::Active)
        {
            let (scope_chain, secret_id) =
                self.resource_context(ResourceSelector::Secret(secret.id))?;
            let explanation = authorize(
                &rules,
                Request {
                    principal_id,
                    action: Action::Discover,
                    vault_id: self.vault_id,
                    scope_chain: &scope_chain,
                    secret_id,
                },
                None,
                now,
            )?;
            if explanation.decision != Decision::DenyExplicit {
                filtered.push(secret);
            }
        }
        Ok(filtered)
    }

    pub fn prepare_agent_http_request(
        &mut self,
        grant: &mut Grant,
        constraint: HttpConstraint,
        secret_id: envault_core::SecretId,
        request: HttpRequest,
        now: i64,
        request_id: Uuid,
    ) -> Result<AgentHttpRequest, ServiceError> {
        validate_http_request(&request, &constraint)?;
        if grant.action != Action::HttpRequest
            || grant.resource != ResourceSelector::Secret(secret_id)
        {
            return Err(ServiceError::PermissionDenied);
        }
        let explanation = self.explain_policy(
            grant.principal_id,
            Action::HttpRequest,
            ResourceSelector::Secret(secret_id),
            Some(grant),
            now,
            request_id,
        )?;
        if explanation.decision != Decision::Allow {
            return Err(ServiceError::PermissionDenied);
        }
        let secret = self
            .store
            .secret_by_id(secret_id)?
            .ok_or(ServiceError::NotFound)?;
        if secret.status != 0 || secret.current_version == 0 {
            return Err(ServiceError::NotFound);
        }
        let version = self
            .store
            .secret_versions(secret.id)?
            .into_iter()
            .find(|version| version.version == secret.current_version)
            .ok_or(ServiceError::Corrupt)?;
        let credential = self.decrypt_secret_version(&secret, &version)?.into_vec();
        prepare_bearer_request(request, constraint, credential)
            .map(AgentHttpRequest)
            .map_err(ServiceError::from)
    }
}
