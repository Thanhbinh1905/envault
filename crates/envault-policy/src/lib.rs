#![forbid(unsafe_code)]

use envault_core::{
    ApprovalId, GrantId, PolicyRuleId, PrincipalId, ScopeId, SecretId, VaultId,
    validate_scope_chain,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_GRANT_LIFETIME_SECONDS: i64 = 60 * 60;
pub const MAX_GRANT_USES: u32 = 1_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Action {
    Discover,
    UseSecret,
    HttpRequest,
    Admin,
    Reveal,
    PlaintextExport,
    PolicyWrite,
    GenericExecution,
}

impl Action {
    #[must_use]
    pub const fn agent_grantable(self) -> bool {
        matches!(self, Self::Discover | Self::UseSecret | Self::HttpRequest)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ResourceSelector {
    Vault(VaultId),
    ScopeTree(ScopeId),
    Secret(SecretId),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: PolicyRuleId,
    pub effect: Effect,
    pub principal_id: PrincipalId,
    pub action: Action,
    pub resource: ResourceSelector,
    pub disabled: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub principal_id: PrincipalId,
    pub action: Action,
    pub vault_id: VaultId,
    pub scope_chain: &'a [ScopeId],
    pub secret_id: Option<SecretId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    DenyExplicit,
    DenyDefault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Reason {
    AllowRule,
    Grant,
    ExplicitDeny,
    NoMatch,
    GrantExpired,
    GrantNotYetValid,
    GrantExhausted,
    GrantRevoked,
    GrantMismatch,
    PrincipalDisabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Explanation {
    pub decision: Decision,
    pub reason: Reason,
    pub matched_deny_rules: Vec<PolicyRuleId>,
    pub matched_allow_rules: Vec<PolicyRuleId>,
    pub grant_id: Option<GrantId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub id: GrantId,
    pub principal_id: PrincipalId,
    pub action: Action,
    pub resource: ResourceSelector,
    pub issued_at: i64,
    pub expires_at: i64,
    pub max_uses: u32,
    pub uses: u32,
    pub revoked: bool,
    pub nonce: [u8; 32],
    pub approval_id: ApprovalId,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("scope chain is invalid")]
    InvalidScopeChain,
    #[error("grant lifetime must be positive and at most sixty minutes")]
    InvalidGrantLifetime,
    #[error("grant use count must be between one and one thousand")]
    InvalidGrantUses,
    #[error("action cannot be delegated to an agent grant")]
    PrivilegedGrantAction,
    #[error("an agent principal cannot receive an allow rule for a privileged action")]
    PrivilegedAgentRule,
    #[error("grant identifiers and nonce must be non-zero")]
    InvalidGrantIdentity,
}

impl Grant {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.id.0.is_nil()
            || self.principal_id.0.is_nil()
            || self.approval_id.0.is_nil()
            || self.nonce == [0; 32]
            || selector_is_nil(self.resource)
        {
            return Err(PolicyError::InvalidGrantIdentity);
        }
        let lifetime = self
            .expires_at
            .checked_sub(self.issued_at)
            .ok_or(PolicyError::InvalidGrantLifetime)?;
        if !(1..=MAX_GRANT_LIFETIME_SECONDS).contains(&lifetime) {
            return Err(PolicyError::InvalidGrantLifetime);
        }
        if !(1..=MAX_GRANT_USES).contains(&self.max_uses) || self.uses > self.max_uses {
            return Err(PolicyError::InvalidGrantUses);
        }
        if !self.action.agent_grantable() {
            return Err(PolicyError::PrivilegedGrantAction);
        }
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

pub fn authorize(
    rules: &[Rule],
    request: Request<'_>,
    mut grant: Option<&mut Grant>,
    now: i64,
) -> Result<Explanation, PolicyError> {
    validate_scope_chain(request.scope_chain).map_err(|_| PolicyError::InvalidScopeChain)?;
    let mut deny = Vec::new();
    let mut allow = Vec::new();
    for rule in rules.iter().filter(|rule| {
        !rule.disabled
            && rule.principal_id == request.principal_id
            && rule.action == request.action
            && selector_matches(rule.resource, request)
    }) {
        match rule.effect {
            Effect::Allow => allow.push(rule.id),
            Effect::Deny => deny.push(rule.id),
        }
    }
    deny.sort_unstable();
    deny.dedup();
    allow.sort_unstable();
    allow.dedup();
    if !deny.is_empty() {
        return Ok(Explanation {
            decision: Decision::DenyExplicit,
            reason: Reason::ExplicitDeny,
            matched_deny_rules: deny,
            matched_allow_rules: allow,
            grant_id: grant.as_deref().map(|grant| grant.id),
        });
    }
    if !allow.is_empty() {
        return Ok(Explanation {
            decision: Decision::Allow,
            reason: Reason::AllowRule,
            matched_deny_rules: deny,
            matched_allow_rules: allow,
            grant_id: None,
        });
    }
    let Some(grant) = grant.as_mut() else {
        return Ok(default_denial(Reason::NoMatch));
    };
    grant.validate()?;
    if grant.revoked {
        return Ok(denied_grant(grant.id, Reason::GrantRevoked));
    }
    if now < grant.issued_at {
        return Ok(denied_grant(grant.id, Reason::GrantNotYetValid));
    }
    if now >= grant.expires_at {
        return Ok(denied_grant(grant.id, Reason::GrantExpired));
    }
    if grant.uses >= grant.max_uses {
        return Ok(denied_grant(grant.id, Reason::GrantExhausted));
    }
    if grant.principal_id != request.principal_id
        || grant.action != request.action
        || !selector_matches(grant.resource, request)
    {
        return Ok(denied_grant(grant.id, Reason::GrantMismatch));
    }
    grant.uses = grant
        .uses
        .checked_add(1)
        .ok_or(PolicyError::InvalidGrantUses)?;
    Ok(Explanation {
        decision: Decision::Allow,
        reason: Reason::Grant,
        matched_deny_rules: deny,
        matched_allow_rules: allow,
        grant_id: Some(grant.id),
    })
}

fn selector_matches(selector: ResourceSelector, request: Request<'_>) -> bool {
    match selector {
        ResourceSelector::Vault(vault_id) => vault_id == request.vault_id,
        ResourceSelector::ScopeTree(scope_id) => request.scope_chain.contains(&scope_id),
        ResourceSelector::Secret(secret_id) => request.secret_id == Some(secret_id),
    }
}

fn selector_is_nil(selector: ResourceSelector) -> bool {
    match selector {
        ResourceSelector::Vault(id) => id.0.is_nil(),
        ResourceSelector::ScopeTree(id) => id.0.is_nil(),
        ResourceSelector::Secret(id) => id.0.is_nil(),
    }
}

fn default_denial(reason: Reason) -> Explanation {
    Explanation {
        decision: Decision::DenyDefault,
        reason,
        matched_deny_rules: Vec::new(),
        matched_allow_rules: Vec::new(),
        grant_id: None,
    }
}

fn denied_grant(grant_id: GrantId, reason: Reason) -> Explanation {
    Explanation {
        grant_id: Some(grant_id),
        ..default_denial(reason)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use uuid::Uuid;

    use super::*;

    fn ids() -> (VaultId, ScopeId, ScopeId, PrincipalId, SecretId) {
        (
            VaultId(Uuid::from_u128(1)),
            ScopeId(Uuid::from_u128(2)),
            ScopeId(Uuid::from_u128(3)),
            PrincipalId(Uuid::from_u128(4)),
            SecretId(Uuid::from_u128(5)),
        )
    }

    fn request(
        chain: &[ScopeId],
        vault_id: VaultId,
        principal_id: PrincipalId,
        secret_id: SecretId,
    ) -> Request<'_> {
        Request {
            principal_id,
            action: Action::HttpRequest,
            vault_id,
            scope_chain: chain,
            secret_id: Some(secret_id),
        }
    }

    #[test]
    fn deny_always_wins_over_allow_and_grant() {
        let (vault_id, root, child, principal_id, secret_id) = ids();
        let chain = [root, child];
        let rules = [
            Rule {
                id: PolicyRuleId(Uuid::from_u128(10)),
                effect: Effect::Allow,
                principal_id,
                action: Action::HttpRequest,
                resource: ResourceSelector::Vault(vault_id),
                disabled: false,
            },
            Rule {
                id: PolicyRuleId(Uuid::from_u128(11)),
                effect: Effect::Deny,
                principal_id,
                action: Action::HttpRequest,
                resource: ResourceSelector::ScopeTree(root),
                disabled: false,
            },
        ];
        let mut grant = Grant {
            id: GrantId(Uuid::from_u128(20)),
            principal_id,
            action: Action::HttpRequest,
            resource: ResourceSelector::Secret(secret_id),
            issued_at: 100,
            expires_at: 200,
            max_uses: 1,
            uses: 0,
            revoked: false,
            nonce: [7; 32],
            approval_id: ApprovalId(Uuid::from_u128(21)),
        };
        let explanation = authorize(
            &rules,
            request(&chain, vault_id, principal_id, secret_id),
            Some(&mut grant),
            150,
        )
        .expect("authorize");
        assert_eq!(explanation.decision, Decision::DenyExplicit);
        assert_eq!(grant.uses, 0);
    }

    #[test]
    fn grant_is_bounded_revocable_and_privilege_safe() {
        let (vault_id, root, child, principal_id, secret_id) = ids();
        let chain = [root, child];
        let mut grant = Grant {
            id: GrantId(Uuid::from_u128(20)),
            principal_id,
            action: Action::UseSecret,
            resource: ResourceSelector::ScopeTree(root),
            issued_at: 100,
            expires_at: 200,
            max_uses: 1,
            uses: 0,
            revoked: false,
            nonce: [7; 32],
            approval_id: ApprovalId(Uuid::from_u128(21)),
        };
        let use_request = Request {
            action: Action::UseSecret,
            ..request(&chain, vault_id, principal_id, secret_id)
        };
        assert_eq!(
            authorize(&[], use_request, Some(&mut grant), 99)
                .expect("not yet valid")
                .reason,
            Reason::GrantNotYetValid
        );
        assert_eq!(grant.uses, 0);
        assert_eq!(
            authorize(&[], use_request, Some(&mut grant), 150)
                .expect("grant")
                .decision,
            Decision::Allow
        );
        assert_eq!(grant.uses, 1);
        assert_eq!(
            authorize(&[], use_request, Some(&mut grant), 151)
                .expect("exhausted")
                .reason,
            Reason::GrantExhausted
        );
        grant.revoke();
        assert_eq!(
            authorize(&[], use_request, Some(&mut grant), 151)
                .expect("revoked")
                .reason,
            Reason::GrantRevoked
        );
        grant.action = Action::Reveal;
        assert_eq!(grant.validate(), Err(PolicyError::PrivilegedGrantAction));
        grant.action = Action::UseSecret;
        grant.nonce = [0; 32];
        assert_eq!(grant.validate(), Err(PolicyError::InvalidGrantIdentity));
    }

    proptest! {
        #[test]
        fn evaluation_is_independent_of_rule_order(effects in proptest::collection::vec(any::<bool>(), 0..40)) {
            let (vault_id, root, child, principal_id, secret_id) = ids();
            let chain = [root, child];
            let rules = effects
                .iter()
                .enumerate()
                .map(|(index, deny)| Rule {
                    id: PolicyRuleId(Uuid::from_u128(100 + index as u128)),
                    effect: if *deny { Effect::Deny } else { Effect::Allow },
                    principal_id,
                    action: Action::HttpRequest,
                    resource: ResourceSelector::Vault(vault_id),
                    disabled: false,
                })
                .collect::<Vec<_>>();
            let mut reversed = rules.clone();
            reversed.reverse();
            let request = request(&chain, vault_id, principal_id, secret_id);
            let forward = authorize(&rules, request, None, 150);
            let reverse = authorize(&reversed, request, None, 150);
            prop_assert_eq!(&forward, &reverse);
            let expected = if effects.iter().any(|deny| *deny) {
                Decision::DenyExplicit
            } else if effects.is_empty() {
                Decision::DenyDefault
            } else {
                Decision::Allow
            };
            prop_assert_eq!(forward.expect("valid policy").decision, expected);
        }
    }
}
