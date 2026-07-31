use envault_core::{
    ProfileSession, ResolvedSecretView, ScopeId, ScopeKind, ScopeResolutionEntry, ScopeView,
    SecretId, SecretStatus, resolve_scope_entries, validate_scope_chain,
};
use envault_crypto::lookup_digest;
use envault_store::{ScopeRecord, SecretRecord};
use uuid::Uuid;

use super::{
    EntityKind, GeneratorSpec, SCOPE_LOOKUP_DOMAIN, SECRET_LOOKUP_DOMAIN, SensitiveInput,
    ServiceError, VaultSession, normalize_name, unix_seconds,
};

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

    /// Creates a Workspace scope directly under root - a named grouping
    /// layer for multiple profiles, not an authorization primitive.
    pub fn create_workspace(&mut self, name: &str) -> Result<ScopeView, ServiceError> {
        self.create_scope(self.root_scope_id, ScopeKind::Workspace, name)
    }

    pub fn workspaces(&self) -> Result<Vec<ScopeView>, ServiceError> {
        Ok(self
            .scopes()?
            .into_iter()
            .filter(|scope| scope.kind == ScopeKind::Workspace)
            .collect())
    }

    pub fn workspace_by_name(&self, name: &str) -> Result<ScopeView, ServiceError> {
        let root = self.store.root_scope()?;
        let root_path =
            self.decrypt_entity_text(EntityKind::Scope, root.id.0, "path", &root.encrypted_path)?;
        let normalized = normalize_scope_label(name)?;
        let path = format!("{root_path}/{normalized}");
        let lookup = lookup_digest(&self.master_key, SCOPE_LOOKUP_DOMAIN, path.as_bytes());
        let record = self
            .store
            .scope_by_path_lookup(self.vault_id, &lookup)?
            .ok_or(ServiceError::NotFound)?;
        if scope_kind(record.kind)? != ScopeKind::Workspace {
            return Err(ServiceError::NotFound);
        }
        self.scope_view(&record)
    }

    /// All scope ids in the subtree rooted at `scope_id` (inclusive) -
    /// every profile/secret grouped under a workspace, for `workspace load`
    /// and workspace-scoped grants (`ResourceSelector::ScopeTree`).
    pub fn subtree_scope_ids(&self, scope_id: ScopeId) -> Result<Vec<ScopeId>, ServiceError> {
        let all = self.store.scopes()?;
        let mut result = vec![scope_id];
        let mut frontier = vec![scope_id];
        while let Some(current) = frontier.pop() {
            for scope in &all {
                if scope.parent_id == Some(current) {
                    result.push(scope.id);
                    frontier.push(scope.id);
                }
            }
        }
        Ok(result)
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
