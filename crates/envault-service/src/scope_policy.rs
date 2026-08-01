use envault_core::{
    ProfileSession, ProfileView, ResolvedSecretView, ScopeId, ScopeKind, ScopeResolutionEntry,
    ScopeView, SecretId, SecretStatus, WorkspaceId, WorkspaceView, resolve_scope_entries,
    validate_scope_chain,
};
use envault_crypto::lookup_digest;
use envault_store::{ScopeRecord, SecretRecord, WorkspaceRecord};
use uuid::Uuid;

pub(crate) const WORKSPACE_LOOKUP_DOMAIN: &str = "envault workspace lookup v1";

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

    /// Creates a workspace: a dedicated `workspace` table row, independent of
    /// the scope tree. Membership (which profiles load together under it) is
    /// tracked separately in `workspace_membership` - see
    /// `bind_profile_to_workspace`.
    pub fn create_workspace(&mut self, name: &str) -> Result<WorkspaceView, ServiceError> {
        let normalized = normalize_name(name)?;
        let lookup = lookup_digest(
            &self.master_key,
            WORKSPACE_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        if self
            .store
            .workspace_by_lookup(self.vault_id, &lookup)?
            .is_some()
        {
            return Err(ServiceError::Conflict);
        }
        let id = WorkspaceId(Uuid::new_v4());
        let record = WorkspaceRecord {
            id,
            vault_id: self.vault_id,
            encrypted_name: self.encrypt_entity_text(
                EntityKind::Workspace,
                id.0,
                "name",
                name.trim(),
            )?,
            name_lookup: lookup.to_vec(),
        };
        self.store.create_workspace(&record)?;
        self.workspace_view(&record)
    }

    pub fn workspaces(&self) -> Result<Vec<WorkspaceView>, ServiceError> {
        let mut workspaces = self
            .store
            .workspaces()?
            .iter()
            .map(|record| self.workspace_view(record))
            .collect::<Result<Vec<_>, _>>()?;
        workspaces.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        Ok(workspaces)
    }

    pub fn workspace_by_name(&self, name: &str) -> Result<WorkspaceView, ServiceError> {
        let record = self.workspace_record_by_name(name)?;
        self.workspace_view(&record)
    }

    /// Binds `profile` into `workspace`'s membership set. A profile is
    /// independent of any workspace tree - it can belong to several
    /// workspaces at once, purely as a "load these together" grouping;
    /// this never touches the profile's own scope/parenting.
    pub fn bind_profile_to_workspace(
        &mut self,
        workspace: &str,
        profile: &str,
    ) -> Result<(), ServiceError> {
        let workspace_record = self.workspace_record_by_name(workspace)?;
        let profile_record = self.profile_by_name(profile)?;
        self.store
            .add_workspace_membership(workspace_record.id, profile_record.id)?;
        Ok(())
    }

    pub fn unbind_profile_from_workspace(
        &mut self,
        workspace: &str,
        profile: &str,
    ) -> Result<(), ServiceError> {
        let workspace_record = self.workspace_record_by_name(workspace)?;
        let profile_record = self.profile_by_name(profile)?;
        self.store
            .remove_workspace_membership(workspace_record.id, profile_record.id)?;
        Ok(())
    }

    /// Every profile currently bound to `workspace` - a plain membership
    /// join, unrelated to the scope tree.
    pub fn profiles_in_workspace(&self, workspace: &str) -> Result<Vec<ProfileView>, ServiceError> {
        let workspace_record = self.workspace_record_by_name(workspace)?;
        self.store
            .profiles_in_workspace(workspace_record.id)?
            .iter()
            .map(|record| self.profile_view(record))
            .collect()
    }

    pub fn delete_workspace(&mut self, name: &str) -> Result<(), ServiceError> {
        let record = self.workspace_record_by_name(name)?;
        self.store.delete_workspace(record.id)?;
        Ok(())
    }

    fn workspace_record_by_name(&self, name: &str) -> Result<WorkspaceRecord, ServiceError> {
        let normalized = normalize_name(name)?;
        let lookup = lookup_digest(
            &self.master_key,
            WORKSPACE_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        self.store
            .workspace_by_lookup(self.vault_id, &lookup)?
            .ok_or(ServiceError::NotFound)
    }

    fn workspace_view(&self, record: &WorkspaceRecord) -> Result<WorkspaceView, ServiceError> {
        Ok(WorkspaceView {
            id: record.id,
            name: self.decrypt_entity_text(
                EntityKind::Workspace,
                record.id.0,
                "name",
                &record.encrypted_name,
            )?,
        })
    }

    /// All scope ids in the subtree rooted at `scope_id` (inclusive).
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

// Kind code 2 previously meant `ScopeKind::Workspace` and is retired: no
// scope row is ever written with it again, but `scope_kind` below still
// rejects it explicitly (rather than silently accepting it as an unknown
// value) so a stray legacy row fails closed instead of being misread.
pub(super) const fn scope_kind_code(kind: ScopeKind) -> u8 {
    match kind {
        ScopeKind::Root => 0,
        ScopeKind::Profile => 1,
        ScopeKind::Project => 3,
    }
}

fn scope_kind(code: u8) -> Result<ScopeKind, ServiceError> {
    match code {
        0 => Ok(ScopeKind::Root),
        1 => Ok(ScopeKind::Profile),
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
