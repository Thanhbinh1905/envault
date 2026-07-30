use envault_core::{
    AuditEventId, PolicyRuleId, PrincipalId, PrincipalKind, PrincipalView, ProfileSession,
    ResolvedSecretView, ScopeId, ScopeKind, ScopeResolutionEntry, ScopeView, SecretId,
    SecretStatus, resolve_scope_entries, validate_scope_chain,
};
use envault_crypto::{SecretKey, lookup_digest};
use envault_policy::{
    Action, Decision, Effect, Explanation, Grant, Reason, Request, ResourceSelector, Rule,
    authorize,
};
use envault_store::{
    AuditEventDraft, AuditEventRecord, PolicyRuleRecord, PrincipalRecord, ScopeRecord, SecretRecord,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    EntityKind, GeneratorSpec, SCOPE_LOOKUP_DOMAIN, SECRET_LOOKUP_DOMAIN, SensitiveInput,
    ServiceError, VaultSession, normalize_name, unix_seconds,
};

pub(super) const PRINCIPAL_LOOKUP_DOMAIN: &str = "envault principal lookup v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactedAuditMetadata {
    pub principal_id: PrincipalId,
    pub action: Action,
    pub resource: ResourceSelector,
    pub decision: Decision,
    pub request_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditView {
    pub sequence: u64,
    pub id: AuditEventId,
    pub metadata: RedactedAuditMetadata,
    pub previous_hash: [u8; 32],
    pub event_hash: [u8; 32],
    pub created_at: i64,
}

impl VaultSession {
    pub fn create_scope(
        &mut self,
        parent_id: ScopeId,
        kind: ScopeKind,
        label: &str,
    ) -> Result<ScopeView, ServiceError> {
        if kind == ScopeKind::Root {
            return Err(ServiceError::Invariant(
                envault_core::InvariantError::InvalidScopeChain,
            ));
        }
        let normalized = normalize_scope_label(label)?;
        let parent_chain = self.scope_chain(parent_id)?;
        if parent_chain.len() >= envault_core::MAX_SCOPE_DEPTH {
            return Err(ServiceError::Invariant(
                envault_core::InvariantError::InvalidScopeChain,
            ));
        }
        let parent = self.scope_record(parent_id)?;
        let parent_path = self.decrypt_entity_text(
            EntityKind::Scope,
            parent.id.0,
            "path",
            &parent.encrypted_path,
        )?;
        let path = format!("{parent_path}/{normalized}");
        let path_lookup = lookup_digest(&self.master_key, SCOPE_LOOKUP_DOMAIN, path.as_bytes());
        if self
            .store
            .scopes()?
            .iter()
            .any(|scope| scope.vault_id == self.vault_id && scope.path_lookup == path_lookup)
        {
            return Err(ServiceError::Conflict);
        }
        let id = ScopeId(Uuid::new_v4());
        let record = ScopeRecord {
            id,
            vault_id: self.vault_id,
            parent_id: Some(parent_id),
            kind: scope_kind_code(kind),
            encrypted_path: self.encrypt_entity_text(EntityKind::Scope, id.0, "path", &path)?,
            path_lookup: path_lookup.to_vec(),
        };
        self.store.insert_scope(&record)?;
        self.scope_view(&record)
    }

    pub fn scopes(&self) -> Result<Vec<ScopeView>, ServiceError> {
        let mut scopes = self
            .store
            .scopes()?
            .iter()
            .map(|record| self.scope_view(record))
            .collect::<Result<Vec<_>, _>>()?;
        scopes.sort_by(|left, right| left.path.cmp(&right.path).then(left.id.cmp(&right.id)));
        Ok(scopes)
    }

    pub fn scope_chain(&self, scope_id: ScopeId) -> Result<Vec<ScopeId>, ServiceError> {
        let mut chain = Vec::new();
        let mut current = Some(scope_id);
        while let Some(id) = current {
            if chain.len() >= envault_core::MAX_SCOPE_DEPTH || chain.contains(&id) {
                return Err(ServiceError::Corrupt);
            }
            let record = self.scope_record(id)?;
            chain.push(record.id);
            current = record.parent_id;
        }
        chain.reverse();
        validate_scope_chain(&chain).map_err(|_| ServiceError::Corrupt)?;
        if chain.first().copied() != Some(self.root_scope_id) {
            return Err(ServiceError::Corrupt);
        }
        Ok(chain)
    }

    pub fn bind_profile(&self, name: &str) -> Result<ProfileSession, ServiceError> {
        let profile = self.profile_by_name(name)?;
        self.scope_chain(profile.scope_id)?;
        Ok(ProfileSession {
            profile_id: profile.id,
            scope_id: profile.scope_id,
            profile_generation: profile.generation,
            bound_at: unix_seconds()?,
        })
    }

    pub fn create_secret_in_scope(
        &mut self,
        scope_id: ScopeId,
        name: &str,
        description: Option<&str>,
        value: SensitiveInput,
    ) -> Result<envault_core::SecretView, ServiceError> {
        self.scope_chain(scope_id)?;
        self.create_secret_inner(scope_id, name, description, value.into_secret(), None)
    }

    pub fn create_generated_secret_in_scope(
        &mut self,
        scope_id: ScopeId,
        name: &str,
        description: Option<&str>,
        spec: GeneratorSpec,
    ) -> Result<envault_core::SecretView, ServiceError> {
        self.scope_chain(scope_id)?;
        let generated = super::generate_value(spec)?;
        self.create_secret_inner(
            scope_id,
            name,
            description,
            generated.value,
            Some(generated.metadata),
        )
    }

    pub fn tombstone_secret(
        &mut self,
        scope_id: ScopeId,
        name: &str,
    ) -> Result<envault_core::SecretView, ServiceError> {
        self.scope_chain(scope_id)?;
        let normalized = normalize_name(name)?;
        let lookup = lookup_digest(
            &self.master_key,
            SECRET_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        if let Some(mut existing) = self.store.secret_by_lookup(scope_id, &lookup)? {
            if existing.status == 1 {
                return self.secret_view(&existing);
            }
            existing.encrypted_name =
                self.encrypt_entity_text(EntityKind::Secret, existing.id.0, "name", name.trim())?;
            existing.encrypted_description = None;
            existing.current_version = 0;
            existing.status = 1;
            self.store.convert_secret_to_tombstone(
                existing.id,
                &existing.encrypted_name,
                &existing.name_lookup,
            )?;
            return self.secret_view(&existing);
        }
        let id = SecretId(Uuid::new_v4());
        let record = SecretRecord {
            id,
            scope_id,
            encrypted_name: self.encrypt_entity_text(
                EntityKind::Secret,
                id.0,
                "name",
                name.trim(),
            )?,
            name_lookup: lookup.to_vec(),
            encrypted_description: None,
            current_version: 0,
            status: 1,
        };
        self.store.insert_tombstone(&record)?;
        self.secret_view(&record)
    }

    pub fn resolved_secrets(
        &self,
        scope_id: ScopeId,
    ) -> Result<Vec<ResolvedSecretView>, ServiceError> {
        let chain = self.scope_chain(scope_id)?;
        let entries = self
            .store
            .secrets()?
            .into_iter()
            .filter(|record| chain.contains(&record.scope_id))
            .map(|record| {
                Ok(ScopeResolutionEntry {
                    scope_id: record.scope_id,
                    name_lookup: record.name_lookup,
                    secret_id: record.id,
                    status: secret_status(record.status)?,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        let resolved = resolve_scope_entries(&chain, &entries)?
            .into_iter()
            .map(|entry| {
                let record = self
                    .store
                    .secret_by_id(entry.secret_id)?
                    .ok_or(ServiceError::Corrupt)?;
                Ok(ResolvedSecretView {
                    secret: self.secret_view(&record)?,
                    source_scope_id: entry.scope_id,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        let mut ordered = resolved
            .into_iter()
            .map(|resolved| Ok((normalize_name(&resolved.secret.name)?, resolved)))
            .collect::<Result<Vec<_>, ServiceError>>()?;
        ordered.sort_by(|(left_name, left), (right_name, right)| {
            left_name
                .cmp(right_name)
                .then(left.secret.id.cmp(&right.secret.id))
        });
        Ok(ordered.into_iter().map(|(_, resolved)| resolved).collect())
    }

    pub fn resolve_secret(
        &self,
        scope_id: ScopeId,
        name: &str,
    ) -> Result<ResolvedSecretView, ServiceError> {
        let normalized = normalize_name(name)?;
        self.resolved_secrets(scope_id)?
            .into_iter()
            .find(|resolved| normalize_name(&resolved.secret.name).as_ref() == Ok(&normalized))
            .ok_or(ServiceError::NotFound)
    }

    pub fn create_principal(
        &mut self,
        kind: PrincipalKind,
        name: &str,
    ) -> Result<PrincipalView, ServiceError> {
        let normalized = normalize_name(name)?;
        let lookup = lookup_digest(
            &self.master_key,
            PRINCIPAL_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        if self
            .store
            .principal_by_lookup(self.vault_id, &lookup)?
            .is_some()
        {
            return Err(ServiceError::Conflict);
        }
        let id = PrincipalId(Uuid::new_v4());
        let record = PrincipalRecord {
            id,
            vault_id: self.vault_id,
            kind: principal_kind_code(kind),
            encrypted_name: self.encrypt_entity_text(
                EntityKind::Principal,
                id.0,
                "name",
                name.trim(),
            )?,
            name_lookup: lookup.to_vec(),
            disabled: false,
            generation: 1,
        };
        self.store.insert_principal(&record)?;
        self.principal_view(&record)
    }

    pub fn principals(&self) -> Result<Vec<PrincipalView>, ServiceError> {
        let mut principals = self
            .store
            .principals()?
            .iter()
            .map(|record| self.principal_view(record))
            .collect::<Result<Vec<_>, _>>()?;
        principals.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        Ok(principals)
    }

    pub fn set_principal_disabled(
        &mut self,
        principal_id: PrincipalId,
        disabled: bool,
    ) -> Result<PrincipalView, ServiceError> {
        let mut record = self
            .store
            .principal_by_id(principal_id)?
            .ok_or(ServiceError::NotFound)?;
        if record.vault_id != self.vault_id {
            return Err(ServiceError::Corrupt);
        }
        if record.disabled != disabled {
            record.disabled = disabled;
            record.generation = record
                .generation
                .checked_add(1)
                .ok_or(ServiceError::Corrupt)?;
            self.store.update_principal(&record)?;
        }
        self.principal_view(&record)
    }

    pub fn create_policy_rule(
        &mut self,
        principal_id: PrincipalId,
        effect: Effect,
        action: Action,
        resource: ResourceSelector,
    ) -> Result<Rule, ServiceError> {
        let principal = self
            .store
            .principal_by_id(principal_id)?
            .ok_or(ServiceError::NotFound)?;
        if principal.vault_id != self.vault_id {
            return Err(ServiceError::Corrupt);
        }
        if principal.kind == principal_kind_code(PrincipalKind::Agent)
            && effect == Effect::Allow
            && !action.agent_grantable()
        {
            return Err(ServiceError::Policy(
                envault_policy::PolicyError::PrivilegedAgentRule,
            ));
        }
        self.validate_resource(resource)?;
        let id = PolicyRuleId(Uuid::new_v4());
        let record = PolicyRuleRecord {
            id,
            vault_id: self.vault_id,
            principal_id,
            effect: effect_code(effect),
            action: action_code(action),
            resource_kind: resource_kind_code(resource),
            resource_id: resource_id(resource).as_bytes().to_vec(),
            disabled: false,
            created_at: unix_seconds()?,
        };
        self.store.insert_policy_rule(&record)?;
        policy_rule(&record)
    }

    pub fn policy_rules(&self) -> Result<Vec<Rule>, ServiceError> {
        self.store.policy_rules()?.iter().map(policy_rule).collect()
    }

    pub fn validate_policy_resource(&self, resource: ResourceSelector) -> Result<(), ServiceError> {
        self.validate_resource(resource)
    }

    pub fn explain_policy(
        &mut self,
        principal_id: PrincipalId,
        action: Action,
        resource: ResourceSelector,
        grant: Option<&mut Grant>,
        now: i64,
        request_id: Uuid,
    ) -> Result<Explanation, ServiceError> {
        let principal = self
            .store
            .principal_by_id(principal_id)?
            .ok_or(ServiceError::NotFound)?;
        if principal.vault_id != self.vault_id {
            return Err(ServiceError::Corrupt);
        }
        let (scope_chain, secret_id) = self.resource_context(resource)?;
        let mut evaluated_grant = grant.as_deref().cloned();
        let explanation = if principal.disabled {
            Explanation {
                decision: Decision::DenyDefault,
                reason: Reason::PrincipalDisabled,
                matched_deny_rules: Vec::new(),
                matched_allow_rules: Vec::new(),
                grant_id: evaluated_grant.as_ref().map(|grant| grant.id),
            }
        } else {
            authorize(
                &self.policy_rules()?,
                Request {
                    principal_id,
                    action,
                    vault_id: self.vault_id,
                    scope_chain: &scope_chain,
                    secret_id,
                },
                evaluated_grant.as_mut(),
                now,
            )?
        };
        self.append_policy_audit(
            &RedactedAuditMetadata {
                principal_id,
                action,
                resource,
                decision: explanation.decision,
                request_id,
            },
            unix_seconds()?,
        )?;
        if let (Some(original), Some(updated)) = (grant, evaluated_grant) {
            *original = updated;
        }
        Ok(explanation)
    }

    pub fn audit_events(&self) -> Result<Vec<AuditView>, ServiceError> {
        self.store.audit_events()?.iter().map(audit_view).collect()
    }

    pub fn verify_audit_chain(&self) -> Result<(), ServiceError> {
        let key = &self.master_key;
        self.store.verify_audit_chain(
            |sequence, draft, previous| audit_event_hash(key, sequence, draft, previous),
            |count, head| audit_state_mac(key, count, head),
        )?;
        Ok(())
    }

    fn scope_record(&self, scope_id: ScopeId) -> Result<ScopeRecord, ServiceError> {
        let record = self
            .store
            .scope_by_id(scope_id)?
            .ok_or(ServiceError::NotFound)?;
        if record.vault_id != self.vault_id {
            return Err(ServiceError::Corrupt);
        }
        Ok(record)
    }

    fn scope_view(&self, record: &ScopeRecord) -> Result<ScopeView, ServiceError> {
        Ok(ScopeView {
            id: record.id,
            parent_id: record.parent_id,
            kind: scope_kind(record.kind)?,
            path: self.decrypt_entity_text(
                EntityKind::Scope,
                record.id.0,
                "path",
                &record.encrypted_path,
            )?,
        })
    }

    pub(super) fn principal_view(
        &self,
        record: &PrincipalRecord,
    ) -> Result<PrincipalView, ServiceError> {
        Ok(PrincipalView {
            id: record.id,
            kind: principal_kind(record.kind)?,
            name: self.decrypt_entity_text(
                EntityKind::Principal,
                record.id.0,
                "name",
                &record.encrypted_name,
            )?,
            disabled: record.disabled,
            generation: record.generation,
        })
    }

    pub(super) fn validate_resource(&self, resource: ResourceSelector) -> Result<(), ServiceError> {
        self.resource_context(resource).map(|_| ())
    }

    pub(super) fn resource_context(
        &self,
        resource: ResourceSelector,
    ) -> Result<(Vec<ScopeId>, Option<SecretId>), ServiceError> {
        match resource {
            ResourceSelector::Vault(vault_id) if vault_id == self.vault_id => {
                Ok((vec![self.root_scope_id], None))
            }
            ResourceSelector::ScopeTree(scope_id) => Ok((self.scope_chain(scope_id)?, None)),
            ResourceSelector::Secret(secret_id) => {
                let secret = self
                    .store
                    .secret_by_id(secret_id)?
                    .ok_or(ServiceError::NotFound)?;
                Ok((self.scope_chain(secret.scope_id)?, Some(secret_id)))
            }
            ResourceSelector::Vault(_) => Err(ServiceError::NotFound),
        }
    }

    fn append_policy_audit(
        &mut self,
        metadata: &RedactedAuditMetadata,
        created_at: i64,
    ) -> Result<(), ServiceError> {
        let action = action_code(metadata.action);
        let outcome = decision_code(metadata.decision);
        let redacted_metadata = super::encode_cbor(&metadata)?;
        let draft = AuditEventDraft {
            id: AuditEventId(Uuid::new_v4()),
            action,
            outcome,
            redacted_metadata,
            created_at,
        };
        let key = &self.master_key;
        self.store.append_audit(
            &draft,
            |sequence, draft, previous| audit_event_hash(key, sequence, draft, previous),
            |count, head| audit_state_mac(key, count, head),
        )?;
        Ok(())
    }
}

pub(super) const fn scope_kind_code(kind: ScopeKind) -> u8 {
    match kind {
        ScopeKind::Root => 0,
        ScopeKind::Profile => 1,
        ScopeKind::Workspace => 2,
        ScopeKind::Project => 3,
    }
}

fn scope_kind(code: u8) -> Result<ScopeKind, ServiceError> {
    match code {
        0 => Ok(ScopeKind::Root),
        1 => Ok(ScopeKind::Profile),
        2 => Ok(ScopeKind::Workspace),
        3 => Ok(ScopeKind::Project),
        _ => Err(ServiceError::Corrupt),
    }
}

fn normalize_scope_label(label: &str) -> Result<String, ServiceError> {
    let normalized = normalize_name(label)?;
    if normalized.contains('/') {
        Err(ServiceError::Invariant(
            envault_core::InvariantError::InvalidName,
        ))
    } else {
        Ok(normalized)
    }
}

fn secret_status(code: u8) -> Result<SecretStatus, ServiceError> {
    match code {
        0 => Ok(SecretStatus::Active),
        1 => Ok(SecretStatus::Tombstone),
        _ => Err(ServiceError::Corrupt),
    }
}

fn principal_kind_code(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::Human => 0,
        PrincipalKind::Agent => 1,
        PrincipalKind::Process => 2,
    }
}

fn principal_kind(code: u8) -> Result<PrincipalKind, ServiceError> {
    match code {
        0 => Ok(PrincipalKind::Human),
        1 => Ok(PrincipalKind::Agent),
        2 => Ok(PrincipalKind::Process),
        _ => Err(ServiceError::Corrupt),
    }
}

fn effect_code(effect: Effect) -> u8 {
    match effect {
        Effect::Allow => 0,
        Effect::Deny => 1,
    }
}

fn effect(code: u8) -> Result<Effect, ServiceError> {
    match code {
        0 => Ok(Effect::Allow),
        1 => Ok(Effect::Deny),
        _ => Err(ServiceError::Corrupt),
    }
}

fn action_code(action: Action) -> u8 {
    match action {
        Action::Discover => 0,
        Action::UseSecret => 1,
        Action::HttpRequest => 2,
        Action::Admin => 3,
        Action::Reveal => 4,
        Action::PlaintextExport => 5,
        Action::PolicyWrite => 6,
        Action::GenericExecution => 7,
    }
}

fn action(code: u8) -> Result<Action, ServiceError> {
    match code {
        0 => Ok(Action::Discover),
        1 => Ok(Action::UseSecret),
        2 => Ok(Action::HttpRequest),
        3 => Ok(Action::Admin),
        4 => Ok(Action::Reveal),
        5 => Ok(Action::PlaintextExport),
        6 => Ok(Action::PolicyWrite),
        7 => Ok(Action::GenericExecution),
        _ => Err(ServiceError::Corrupt),
    }
}

fn resource_kind_code(resource: ResourceSelector) -> u8 {
    match resource {
        ResourceSelector::Vault(_) => 0,
        ResourceSelector::ScopeTree(_) => 1,
        ResourceSelector::Secret(_) => 2,
    }
}

fn resource_id(resource: ResourceSelector) -> Uuid {
    match resource {
        ResourceSelector::Vault(id) => id.0,
        ResourceSelector::ScopeTree(id) => id.0,
        ResourceSelector::Secret(id) => id.0,
    }
}

fn resource_selector(kind: u8, id: &[u8]) -> Result<ResourceSelector, ServiceError> {
    let id = Uuid::from_slice(id).map_err(|_| ServiceError::Corrupt)?;
    match kind {
        0 => Ok(ResourceSelector::Vault(envault_core::VaultId(id))),
        1 => Ok(ResourceSelector::ScopeTree(ScopeId(id))),
        2 => Ok(ResourceSelector::Secret(SecretId(id))),
        _ => Err(ServiceError::Corrupt),
    }
}

pub(super) fn policy_rule(record: &PolicyRuleRecord) -> Result<Rule, ServiceError> {
    Ok(Rule {
        id: record.id,
        effect: effect(record.effect)?,
        principal_id: record.principal_id,
        action: action(record.action)?,
        resource: resource_selector(record.resource_kind, &record.resource_id)?,
        disabled: record.disabled,
    })
}

fn decision_code(decision: Decision) -> u8 {
    match decision {
        Decision::Allow => 0,
        Decision::DenyExplicit => 1,
        Decision::DenyDefault => 2,
    }
}

fn audit_view(record: &AuditEventRecord) -> Result<AuditView, ServiceError> {
    let metadata: RedactedAuditMetadata = super::decode_cbor(&record.redacted_metadata)?;
    if action_code(metadata.action) != record.action
        || decision_code(metadata.decision) != record.outcome
    {
        return Err(ServiceError::Corrupt);
    }
    Ok(AuditView {
        sequence: record.sequence,
        id: record.id,
        metadata,
        previous_hash: record.previous_hash,
        event_hash: record.event_hash,
        created_at: record.created_at,
    })
}

fn audit_event_hash(
    key: &SecretKey,
    sequence: u64,
    draft: &AuditEventDraft,
    previous_hash: &[u8; 32],
) -> [u8; 32] {
    let sequence = sequence.to_be_bytes();
    let action = [draft.action];
    let outcome = [draft.outcome];
    let created_at = draft.created_at.to_be_bytes();
    audit_digest(
        key,
        "envault audit event v1",
        &[
            sequence.as_slice(),
            draft.id.0.as_bytes(),
            action.as_slice(),
            outcome.as_slice(),
            draft.redacted_metadata.as_slice(),
            previous_hash.as_slice(),
            created_at.as_slice(),
        ],
    )
}

pub(super) fn audit_state_mac(key: &SecretKey, count: u64, head_hash: &[u8; 32]) -> [u8; 32] {
    let count = count.to_be_bytes();
    audit_digest(
        key,
        "envault audit state v1",
        &[count.as_slice(), head_hash.as_slice()],
    )
}

fn audit_digest(key: &SecretKey, domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut encoded = Vec::new();
    for part in parts {
        let length = u64::try_from(part.len()).expect("audit field length fits u64");
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(part);
    }
    lookup_digest(key, domain, &encoded)
}
