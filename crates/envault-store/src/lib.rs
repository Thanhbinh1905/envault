#![forbid(unsafe_code)]

use std::{path::Path, time::Duration};

use envault_core::{ProfileId, ScopeId, SecretId, SecretVersionId, VaultId, WorkspaceId};
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, backup::Backup, params,
};
use thiserror::Error;

const SCHEMA_VERSION: i64 = 5;

#[derive(Debug)]
pub struct Store {
    connection: Connection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultRecord {
    pub id: VaultId,
    pub format_version: u32,
    pub wrapped_master_key: Vec<u8>,
    pub kdf_parameters: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeRecord {
    pub id: ScopeId,
    pub vault_id: VaultId,
    pub parent_id: Option<ScopeId>,
    pub kind: u8,
    pub encrypted_path: Vec<u8>,
    pub path_lookup: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRecord {
    pub id: ProfileId,
    pub vault_id: VaultId,
    pub scope_id: ScopeId,
    pub encrypted_name: Vec<u8>,
    pub name_lookup: Vec<u8>,
    pub encrypted_description: Option<Vec<u8>>,
    pub activate_on_start: bool,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceRecord {
    pub id: WorkspaceId,
    pub vault_id: VaultId,
    pub encrypted_name: Vec<u8>,
    pub name_lookup: Vec<u8>,
}

/// A secret's single current value - there is no retained history. Present
/// iff the owning `SecretRecord.status` is active (0); `None` for
/// tombstones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretValueRecord {
    pub value_id: SecretVersionId,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub aad_digest: Vec<u8>,
    pub generator: Option<u8>,
    pub generated_length: Option<u64>,
    pub entropy_bits: Option<u32>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretRecord {
    pub id: SecretId,
    pub scope_id: ScopeId,
    pub encrypted_name: Vec<u8>,
    pub name_lookup: Vec<u8>,
    pub encrypted_description: Option<Vec<u8>>,
    pub current_version: u64,
    pub status: u8,
    pub value: Option<SecretValueRecord>,
}

/// Allowlist rule binding a secret to exactly one HTTP origin/path prefix -
/// the replacement for Grant + `HttpConstraint` (no principal/token involved,
/// see docs/adr/0006-agent-blind-broker.md addendum).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretHttpAccessRecord {
    pub secret_id: SecretId,
    pub encrypted_host: Vec<u8>,
    pub port: u16,
    pub methods: String,
    pub encrypted_path_prefix: Vec<u8>,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImportReset {
    None,
    Workspace {
        root_scope_id: ScopeId,
        base_profile_id: ProfileId,
    },
    Profile {
        retained_scope_id: ScopeId,
        removed_scope_ids: Vec<ScopeId>,
    },
}

/// Overwrites an existing active secret's value in place - the replace-strategy
/// counterpart to `ImportBatch.secrets` (which only ever creates brand-new
/// secrets). CAS-guarded on `expected_current_version` like
/// `Store::overwrite_secret_value`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretValueOverwrite {
    pub secret_id: SecretId,
    pub expected_current_version: u64,
    pub value: SecretValueRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBatch {
    pub reset: ImportReset,
    pub scope_updates: Vec<ScopeRecord>,
    pub profile_updates: Vec<ProfileRecord>,
    pub scopes: Vec<ScopeRecord>,
    pub profiles: Vec<ProfileRecord>,
    pub secrets: Vec<SecretRecord>,
    pub value_overwrites: Vec<SecretValueOverwrite>,
    pub workspaces: Vec<WorkspaceRecord>,
    pub workspace_memberships: Vec<(WorkspaceId, ProfileId)>,
}

impl Default for ImportBatch {
    fn default() -> Self {
        Self {
            reset: ImportReset::None,
            scope_updates: Vec::new(),
            profile_updates: Vec::new(),
            scopes: Vec::new(),
            profiles: Vec::new(),
            secrets: Vec::new(),
            value_overwrites: Vec::new(),
            workspaces: Vec::new(),
            workspace_memberships: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("unsupported schema version {0}")]
    UnsupportedSchema(i64),
    #[error("opening schema version {0} would discard immutable secret history")]
    SecretHistoryMigrationRequired(i64),
    #[error("vault is not initialized")]
    NotInitialized,
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("database integrity check failed")]
    Integrity,
    #[error("numeric value is out of range")]
    NumericRange,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        Self::configure(&connection)?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory()?;
        Self::configure(&connection)?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn schema_version(&self) -> Result<i64, StoreError> {
        self.connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(StoreError::from)
    }

    pub fn initialize(
        &mut self,
        vault: &VaultRecord,
        root_scope: &ScopeRecord,
        base_profile: &ProfileRecord,
    ) -> Result<(), StoreError> {
        if root_scope.parent_id.is_some()
            || root_scope.vault_id != vault.id
            || base_profile.vault_id != vault.id
            || base_profile.scope_id != root_scope.id
        {
            return Err(StoreError::Integrity);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM vault", [], |row| row.get(0))?;
        if count != 0 {
            return Err(StoreError::AlreadyInitialized);
        }
        insert_vault(&transaction, vault)?;
        insert_scope(&transaction, root_scope)?;
        insert_profile(&transaction, base_profile)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn vault(&self) -> Result<VaultRecord, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, format_version, wrapped_master_key, kdf_parameters, kdf_salt, created_at
             FROM vault",
        )?;
        let records = statement
            .query_map([], map_vault)?
            .collect::<Result<Vec<_>, _>>()?;
        match records.as_slice() {
            [] => Err(StoreError::NotInitialized),
            [record] => Ok(record.clone()),
            _ => Err(StoreError::Integrity),
        }
    }

    pub fn profiles(&self) -> Result<Vec<ProfileRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, vault_id, scope_id, encrypted_name, name_lookup, encrypted_description,
                    activate_on_start, generation
             FROM profile ORDER BY rowid",
        )?;
        statement
            .query_map([], map_profile)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn profile_by_lookup(
        &self,
        vault_id: VaultId,
        lookup: &[u8],
    ) -> Result<Option<ProfileRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, vault_id, scope_id, encrypted_name, name_lookup, encrypted_description,
                        activate_on_start, generation
                 FROM profile WHERE vault_id = ?1 AND name_lookup = ?2",
                params![id_bytes(vault_id.0), lookup],
                map_profile,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn insert_profile(&mut self, profile: &ProfileRecord) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_profile(&transaction, profile)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn insert_scope_with_profile(
        &mut self,
        scope: &ScopeRecord,
        profile: &ProfileRecord,
    ) -> Result<(), StoreError> {
        if profile.scope_id != scope.id || profile.vault_id != scope.vault_id {
            return Err(StoreError::Integrity);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_scope(&transaction, scope)?;
        insert_profile(&transaction, profile)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn update_profile_metadata(&mut self, profile: &ProfileRecord) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE profile
             SET encrypted_name = ?1, name_lookup = ?2, encrypted_description = ?3,
                 generation = ?4
             WHERE id = ?5",
            params![
                profile.encrypted_name,
                profile.name_lookup,
                profile.encrypted_description,
                to_i64(profile.generation)?,
                id_bytes(profile.id.0),
            ],
        )?;
        expect_single_change(changed)
    }

    /// Sets a single profile's `activate_on_start` preference (auto-load the
    /// next time the vault unlocks), independent of every other profile's
    /// flag and independent of whether the profile is loaded in the current
    /// runtime session.
    pub fn set_profile_activate_on_start(
        &mut self,
        profile_id: ProfileId,
        activate_on_start: bool,
    ) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE profile SET activate_on_start = ?1, generation = generation + 1 WHERE id = ?2",
            params![activate_on_start, id_bytes(profile_id.0)],
        )?;
        expect_single_change(changed)
    }

    pub fn delete_profile(&mut self, profile_id: ProfileId) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "DELETE FROM profile WHERE id = ?1 AND activate_on_start = 0",
            params![id_bytes(profile_id.0)],
        )?;
        expect_single_change(changed)
    }

    pub fn delete_profile_and_scope(
        &mut self,
        profile_id: ProfileId,
        scope_id: ScopeId,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let profile_deleted = transaction.execute(
            "DELETE FROM profile WHERE id = ?1 AND scope_id = ?2 AND activate_on_start = 0",
            params![id_bytes(profile_id.0), id_bytes(scope_id.0)],
        )?;
        if profile_deleted != 1 {
            return Err(StoreError::Integrity);
        }
        let scope_deleted = transaction.execute(
            "DELETE FROM scope WHERE id = ?1 AND parent_id IS NOT NULL",
            params![id_bytes(scope_id.0)],
        )?;
        if scope_deleted != 1 {
            return Err(StoreError::Integrity);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn root_scope(&self) -> Result<ScopeRecord, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, vault_id, parent_id, kind, encrypted_path, path_lookup
             FROM scope WHERE parent_id IS NULL",
        )?;
        let records = statement
            .query_map([], map_scope)?
            .collect::<Result<Vec<_>, _>>()?;
        match records.as_slice() {
            [] => Err(StoreError::NotInitialized),
            [record] => Ok(record.clone()),
            _ => Err(StoreError::Integrity),
        }
    }

    pub fn scope_by_id(&self, scope_id: ScopeId) -> Result<Option<ScopeRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, vault_id, parent_id, kind, encrypted_path, path_lookup
                 FROM scope WHERE id = ?1",
                params![id_bytes(scope_id.0)],
                map_scope,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn scope_by_path_lookup(
        &self,
        vault_id: VaultId,
        path_lookup: &[u8],
    ) -> Result<Option<ScopeRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, vault_id, parent_id, kind, encrypted_path, path_lookup
                 FROM scope WHERE vault_id = ?1 AND path_lookup = ?2",
                params![id_bytes(vault_id.0), path_lookup],
                map_scope,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn scopes(&self) -> Result<Vec<ScopeRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, vault_id, parent_id, kind, encrypted_path, path_lookup
             FROM scope ORDER BY rowid",
        )?;
        statement
            .query_map([], map_scope)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn insert_scope(&mut self, scope: &ScopeRecord) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_scope(&transaction, scope)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn create_workspace(&mut self, workspace: &WorkspaceRecord) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_workspace(&transaction, workspace)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn workspaces(&self) -> Result<Vec<WorkspaceRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, vault_id, encrypted_name, name_lookup
             FROM workspace ORDER BY rowid",
        )?;
        statement
            .query_map([], map_workspace)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn workspace_by_lookup(
        &self,
        vault_id: VaultId,
        lookup: &[u8],
    ) -> Result<Option<WorkspaceRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, vault_id, encrypted_name, name_lookup
                 FROM workspace WHERE vault_id = ?1 AND name_lookup = ?2",
                params![id_bytes(vault_id.0), lookup],
                map_workspace,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn add_workspace_membership(
        &mut self,
        workspace_id: WorkspaceId,
        profile_id: ProfileId,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO workspace_membership (workspace_id, profile_id) VALUES (?1, ?2)",
            params![id_bytes(workspace_id.0), id_bytes(profile_id.0)],
        )?;
        Ok(())
    }

    pub fn remove_workspace_membership(
        &mut self,
        workspace_id: WorkspaceId,
        profile_id: ProfileId,
    ) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "DELETE FROM workspace_membership WHERE workspace_id = ?1 AND profile_id = ?2",
            params![id_bytes(workspace_id.0), id_bytes(profile_id.0)],
        )?;
        expect_single_change(changed)
    }

    pub fn profiles_in_workspace(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ProfileRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT profile.id, profile.vault_id, profile.scope_id, profile.encrypted_name,
                    profile.name_lookup, profile.encrypted_description,
                    profile.activate_on_start, profile.generation
             FROM profile
             JOIN workspace_membership ON workspace_membership.profile_id = profile.id
             WHERE workspace_membership.workspace_id = ?1
             ORDER BY profile.rowid",
        )?;
        statement
            .query_map(params![id_bytes(workspace_id.0)], map_profile)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Every `(workspace_id, profile_id)` membership pair in the vault, in one
    /// query - used by the portability layer to avoid N+1 lookups when
    /// exporting/digesting the whole workspace/membership state.
    pub fn all_workspace_memberships(&self) -> Result<Vec<(WorkspaceId, ProfileId)>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT workspace_id, profile_id FROM workspace_membership
             ORDER BY workspace_id, profile_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((WorkspaceId(read_id(row, 0)?), ProfileId(read_id(row, 1)?)))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn delete_workspace(&mut self, workspace_id: WorkspaceId) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let member_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM workspace_membership WHERE workspace_id = ?1",
            params![id_bytes(workspace_id.0)],
            |row| row.get(0),
        )?;
        if member_count != 0 {
            return Err(StoreError::Integrity);
        }
        let changed = transaction.execute(
            "DELETE FROM workspace WHERE id = ?1",
            params![id_bytes(workspace_id.0)],
        )?;
        if changed != 1 {
            return Err(StoreError::Integrity);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn secrets(&self) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare(SECRET_SELECT_COLUMNS_QUERY)?;
        statement
            .query_map([], map_secret)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn secret_by_lookup(
        &self,
        scope_id: ScopeId,
        lookup: &[u8],
    ) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .query_row(
                &format!("{SECRET_SELECT_COLUMNS_QUERY} WHERE scope_id = ?1 AND name_lookup = ?2"),
                params![id_bytes(scope_id.0), lookup],
                map_secret,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn secret_by_id(&self, secret_id: SecretId) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .query_row(
                &format!("{SECRET_SELECT_COLUMNS_QUERY} WHERE id = ?1"),
                params![id_bytes(secret_id.0)],
                map_secret,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn secret_http_access(
        &self,
        secret_id: SecretId,
    ) -> Result<Option<SecretHttpAccessRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT secret_id, encrypted_host, port, methods, encrypted_path_prefix,
                        max_request_bytes, max_response_bytes
                 FROM secret_http_access WHERE secret_id = ?1",
                params![id_bytes(secret_id.0)],
                map_secret_http_access,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn set_secret_http_access(
        &mut self,
        record: &SecretHttpAccessRecord,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO secret_http_access
             (secret_id, encrypted_host, port, methods, encrypted_path_prefix,
              max_request_bytes, max_response_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(secret_id) DO UPDATE SET
                 encrypted_host = excluded.encrypted_host,
                 port = excluded.port,
                 methods = excluded.methods,
                 encrypted_path_prefix = excluded.encrypted_path_prefix,
                 max_request_bytes = excluded.max_request_bytes,
                 max_response_bytes = excluded.max_response_bytes",
            params![
                id_bytes(record.secret_id.0),
                record.encrypted_host,
                i64::from(record.port),
                record.methods,
                record.encrypted_path_prefix,
                to_i64(record.max_request_bytes)?,
                to_i64(record.max_response_bytes)?,
            ],
        )?;
        Ok(())
    }

    pub fn remove_secret_http_access(&mut self, secret_id: SecretId) -> Result<(), StoreError> {
        self.connection.execute(
            "DELETE FROM secret_http_access WHERE secret_id = ?1",
            params![id_bytes(secret_id.0)],
        )?;
        Ok(())
    }

    pub fn insert_secret(&mut self, secret: &SecretRecord) -> Result<(), StoreError> {
        validate_secret_shape(secret)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_secret(&transaction, secret)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn convert_secret_to_tombstone(
        &mut self,
        secret_id: SecretId,
        encrypted_name: &[u8],
        name_lookup: &[u8],
    ) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE secret
             SET encrypted_name = ?1, name_lookup = ?2, encrypted_description = NULL,
                 current_version = 0, status = 1,
                 value_id = NULL, ciphertext = NULL, wrapped_dek = NULL, aad_digest = NULL,
                 generator = NULL, generated_length = NULL, entropy_bits = NULL,
                 value_created_at = NULL
             WHERE id = ?3 AND status = 0",
            params![encrypted_name, name_lookup, id_bytes(secret_id.0)],
        )?;
        expect_single_change(changed)
    }

    /// Overwrites a secret's value in place - no history is retained, the
    /// previous ciphertext/DEK/metadata are gone once this returns. CAS on
    /// `expected_current_version` (the write-generation counter, purely
    /// internal bookkeeping for concurrency + AAD domain separation, never
    /// surfaced as a "version number").
    pub fn overwrite_secret_value(
        &mut self,
        secret_id: SecretId,
        expected_current_version: u64,
        value: &SecretValueRecord,
    ) -> Result<(), StoreError> {
        let next_version = expected_current_version
            .checked_add(1)
            .ok_or(StoreError::NumericRange)?;
        let changed = self.connection.execute(
            "UPDATE secret
             SET current_version = ?1, value_id = ?2, ciphertext = ?3, wrapped_dek = ?4,
                 aad_digest = ?5, generator = ?6, generated_length = ?7, entropy_bits = ?8,
                 value_created_at = ?9
             WHERE id = ?10 AND current_version = ?11 AND status = 0",
            params![
                to_i64(next_version)?,
                id_bytes(value.value_id.0),
                value.ciphertext,
                value.wrapped_dek,
                value.aad_digest,
                value.generator.map(i64::from),
                value.generated_length.map(to_i64).transpose()?,
                value.entropy_bits.map(i64::from),
                value.created_at,
                id_bytes(secret_id.0),
                to_i64(expected_current_version)?,
            ],
        )?;
        expect_single_change(changed)
    }

    pub fn update_secret_metadata(&mut self, secret: &SecretRecord) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE secret
             SET encrypted_name = ?1, name_lookup = ?2, encrypted_description = ?3
             WHERE id = ?4",
            params![
                secret.encrypted_name,
                secret.name_lookup,
                secret.encrypted_description,
                id_bytes(secret.id.0),
            ],
        )?;
        expect_single_change(changed)
    }

    pub fn delete_secret(&mut self, secret_id: SecretId) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM secret_http_access WHERE secret_id = ?1",
            params![id_bytes(secret_id.0)],
        )?;
        let secret_deleted = transaction.execute(
            "DELETE FROM secret WHERE id = ?1",
            params![id_bytes(secret_id.0)],
        )?;
        if secret_deleted != 1 {
            return Err(StoreError::Integrity);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn apply_import_batch(&mut self, batch: &ImportBatch) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        apply_import_reset(&transaction, &batch.reset)?;
        for scope in &batch.scope_updates {
            update_scope(&transaction, scope)?;
        }
        for profile in &batch.profile_updates {
            update_profile(&transaction, profile)?;
        }
        for scope in &batch.scopes {
            insert_scope(&transaction, scope)?;
        }
        for profile in &batch.profiles {
            insert_profile(&transaction, profile)?;
        }
        for workspace in &batch.workspaces {
            insert_workspace(&transaction, workspace)?;
        }
        for (workspace_id, profile_id) in &batch.workspace_memberships {
            transaction.execute(
                "INSERT INTO workspace_membership (workspace_id, profile_id) VALUES (?1, ?2)",
                params![id_bytes(workspace_id.0), id_bytes(profile_id.0)],
            )?;
        }
        for secret in &batch.secrets {
            validate_secret_shape(secret)?;
            insert_secret(&transaction, secret)?;
        }
        for overwrite in &batch.value_overwrites {
            let next_version = overwrite
                .expected_current_version
                .checked_add(1)
                .ok_or(StoreError::Integrity)?;
            let changed = transaction.execute(
                "UPDATE secret
                 SET current_version = ?1, value_id = ?2, ciphertext = ?3, wrapped_dek = ?4,
                     aad_digest = ?5, generator = ?6, generated_length = ?7, entropy_bits = ?8,
                     value_created_at = ?9
                 WHERE id = ?10 AND current_version = ?11 AND status = 0",
                params![
                    to_i64(next_version)?,
                    id_bytes(overwrite.value.value_id.0),
                    overwrite.value.ciphertext,
                    overwrite.value.wrapped_dek,
                    overwrite.value.aad_digest,
                    overwrite.value.generator.map(i64::from),
                    overwrite.value.generated_length.map(to_i64).transpose()?,
                    overwrite.value.entropy_bits.map(i64::from),
                    overwrite.value.created_at,
                    id_bytes(overwrite.secret_id.0),
                    to_i64(overwrite.expected_current_version)?,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Integrity);
            }
        }
        validate_import_transaction(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn integrity_check(&self) -> Result<(), StoreError> {
        let result: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if result == "ok" {
            Ok(())
        } else {
            Err(StoreError::Integrity)
        }
    }

    pub fn checkpoint(&self) -> Result<(), StoreError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    pub fn backup(&self, destination: &Path) -> Result<(), StoreError> {
        let mut destination = Connection::open(destination)?;
        let backup = Backup::new(&self.connection, &mut destination)?;
        backup.run_to_completion(64, Duration::from_millis(5), None)?;
        Ok(())
    }

    fn configure(connection: &Connection) -> Result<(), StoreError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.busy_timeout(Duration::from_secs(5))?;
        Ok(())
    }

    fn migrate(&mut self) -> Result<(), StoreError> {
        let current = self.schema_version()?;
        if current > SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema(current));
        }
        if current == 0 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(SCHEMA_V5)?;
            transaction.commit()?;
        } else if current == 1 {
            let vault_count: i64 =
                self.connection
                    .query_row("SELECT COUNT(*) FROM vault", [], |row| row.get(0))?;
            if vault_count != 0 {
                return Err(StoreError::UnsupportedSchema(1));
            }
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "DROP TABLE audit_event;
                 DROP TABLE secret_version;
                 DROP TABLE secret;
                 DROP TABLE profile;
                 DROP TABLE scope;
                 DROP TABLE vault;",
            )?;
            transaction.execute_batch(SCHEMA_V5)?;
            transaction.commit()?;
        } else if current <= 4 {
            return Err(StoreError::SecretHistoryMigrationRequired(current));
        }
        Ok(())
    }
}

const SECRET_SELECT_COLUMNS_QUERY: &str = "SELECT id, scope_id, encrypted_name, name_lookup, \
     encrypted_description, current_version, status, value_id, ciphertext, wrapped_dek, \
     aad_digest, generator, generated_length, entropy_bits, value_created_at FROM secret";

fn validate_secret_shape(secret: &SecretRecord) -> Result<(), StoreError> {
    let shape_ok = match (secret.status, &secret.value) {
        (0, Some(_)) => secret.current_version >= 1,
        (1, None) => secret.current_version == 0,
        _ => false,
    };
    if shape_ok {
        Ok(())
    } else {
        Err(StoreError::Integrity)
    }
}

const SCHEMA_V5: &str = "
CREATE TABLE vault (
    id BLOB PRIMARY KEY NOT NULL,
    format_version INTEGER NOT NULL,
    wrapped_master_key BLOB NOT NULL,
    kdf_parameters BLOB NOT NULL,
    kdf_salt BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE scope (
    id BLOB PRIMARY KEY NOT NULL,
    vault_id BLOB NOT NULL REFERENCES vault(id),
    parent_id BLOB REFERENCES scope(id),
    kind INTEGER NOT NULL,
    encrypted_path BLOB NOT NULL,
    path_lookup BLOB NOT NULL,
    UNIQUE(vault_id, path_lookup)
) STRICT;
CREATE UNIQUE INDEX one_root_scope_per_vault
    ON scope(vault_id) WHERE parent_id IS NULL;
CREATE TABLE profile (
    id BLOB PRIMARY KEY NOT NULL,
    vault_id BLOB NOT NULL REFERENCES vault(id),
    scope_id BLOB NOT NULL REFERENCES scope(id),
    encrypted_name BLOB NOT NULL,
    name_lookup BLOB NOT NULL,
    encrypted_description BLOB,
    activate_on_start INTEGER NOT NULL CHECK (activate_on_start IN (0, 1)),
    generation INTEGER NOT NULL CHECK (generation >= 1),
    UNIQUE(vault_id, name_lookup)
) STRICT;
CREATE TABLE secret (
    id BLOB PRIMARY KEY NOT NULL,
    scope_id BLOB NOT NULL REFERENCES scope(id),
    encrypted_name BLOB NOT NULL,
    name_lookup BLOB NOT NULL,
    encrypted_description BLOB,
    current_version INTEGER NOT NULL CHECK (current_version >= 0),
    status INTEGER NOT NULL CHECK (status IN (0, 1)),
    value_id BLOB,
    ciphertext BLOB,
    wrapped_dek BLOB,
    aad_digest BLOB,
    generator INTEGER,
    generated_length INTEGER,
    entropy_bits INTEGER,
    value_created_at INTEGER,
    CHECK ((status = 0 AND current_version >= 1 AND value_id IS NOT NULL
                AND ciphertext IS NOT NULL AND wrapped_dek IS NOT NULL
                AND aad_digest IS NOT NULL AND value_created_at IS NOT NULL)
        OR (status = 1 AND current_version = 0 AND value_id IS NULL
                AND ciphertext IS NULL AND wrapped_dek IS NULL
                AND aad_digest IS NULL AND value_created_at IS NULL)),
    UNIQUE(scope_id, name_lookup)
) STRICT;
CREATE TABLE secret_http_access (
    secret_id BLOB PRIMARY KEY NOT NULL REFERENCES secret(id),
    encrypted_host BLOB NOT NULL,
    port INTEGER NOT NULL,
    methods TEXT NOT NULL,
    encrypted_path_prefix BLOB NOT NULL,
    max_request_bytes INTEGER NOT NULL,
    max_response_bytes INTEGER NOT NULL
) STRICT;
CREATE TABLE workspace (
    id BLOB PRIMARY KEY NOT NULL,
    vault_id BLOB NOT NULL REFERENCES vault(id),
    encrypted_name BLOB NOT NULL,
    name_lookup BLOB NOT NULL,
    UNIQUE(vault_id, name_lookup)
) STRICT;
CREATE TABLE workspace_membership (
    workspace_id BLOB NOT NULL REFERENCES workspace(id),
    profile_id BLOB NOT NULL REFERENCES profile(id),
    PRIMARY KEY (workspace_id, profile_id)
) STRICT;
PRAGMA user_version = 5;
";

fn insert_vault(transaction: &Transaction<'_>, record: &VaultRecord) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO vault
         (id, format_version, wrapped_master_key, kdf_parameters, kdf_salt, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            id_bytes(record.id.0),
            i64::from(record.format_version),
            record.wrapped_master_key,
            record.kdf_parameters,
            record.kdf_salt,
            record.created_at,
        ],
    )?;
    Ok(())
}

fn insert_scope(transaction: &Transaction<'_>, record: &ScopeRecord) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO scope
         (id, vault_id, parent_id, kind, encrypted_path, path_lookup)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            id_bytes(record.id.0),
            id_bytes(record.vault_id.0),
            record.parent_id.map(|id| id_bytes(id.0)),
            i64::from(record.kind),
            record.encrypted_path,
            record.path_lookup,
        ],
    )?;
    Ok(())
}

fn insert_profile(transaction: &Transaction<'_>, record: &ProfileRecord) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO profile
         (id, vault_id, scope_id, encrypted_name, name_lookup, encrypted_description,
          activate_on_start, generation)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id_bytes(record.id.0),
            id_bytes(record.vault_id.0),
            id_bytes(record.scope_id.0),
            record.encrypted_name,
            record.name_lookup,
            record.encrypted_description,
            record.activate_on_start,
            to_i64(record.generation)?,
        ],
    )?;
    Ok(())
}

fn insert_workspace(
    transaction: &Transaction<'_>,
    record: &WorkspaceRecord,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO workspace
         (id, vault_id, encrypted_name, name_lookup)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            id_bytes(record.id.0),
            id_bytes(record.vault_id.0),
            record.encrypted_name,
            record.name_lookup,
        ],
    )?;
    Ok(())
}

fn insert_secret(transaction: &Transaction<'_>, record: &SecretRecord) -> Result<(), StoreError> {
    let value = record.value.as_ref();
    transaction.execute(
        "INSERT INTO secret
         (id, scope_id, encrypted_name, name_lookup, encrypted_description,
          current_version, status, value_id, ciphertext, wrapped_dek, aad_digest,
          generator, generated_length, entropy_bits, value_created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            id_bytes(record.id.0),
            id_bytes(record.scope_id.0),
            record.encrypted_name,
            record.name_lookup,
            record.encrypted_description,
            to_i64(record.current_version)?,
            i64::from(record.status),
            value.map(|value| id_bytes(value.value_id.0)),
            value.map(|value| value.ciphertext.clone()),
            value.map(|value| value.wrapped_dek.clone()),
            value.map(|value| value.aad_digest.clone()),
            value.and_then(|value| value.generator).map(i64::from),
            value
                .and_then(|value| value.generated_length)
                .map(to_i64)
                .transpose()?,
            value.and_then(|value| value.entropy_bits).map(i64::from),
            value.map(|value| value.created_at),
        ],
    )?;
    Ok(())
}

fn apply_import_reset(
    transaction: &Transaction<'_>,
    reset: &ImportReset,
) -> Result<(), StoreError> {
    match reset {
        ImportReset::None => Ok(()),
        ImportReset::Workspace {
            root_scope_id,
            base_profile_id,
        } => {
            transaction.execute("DELETE FROM secret_http_access", [])?;
            transaction.execute("DELETE FROM secret", [])?;
            transaction.execute("DELETE FROM workspace_membership", [])?;
            transaction.execute("DELETE FROM workspace", [])?;
            transaction.execute(
                "DELETE FROM profile WHERE id != ?1",
                params![id_bytes(base_profile_id.0)],
            )?;
            transaction.execute(
                "DELETE FROM scope WHERE id != ?1",
                params![id_bytes(root_scope_id.0)],
            )?;
            Ok(())
        }
        ImportReset::Profile {
            retained_scope_id,
            removed_scope_ids,
        } => {
            for scope_id in removed_scope_ids.iter().rev() {
                if scope_id == retained_scope_id {
                    continue;
                }
                transaction.execute(
                    "DELETE FROM secret WHERE scope_id = ?1",
                    params![id_bytes(scope_id.0)],
                )?;
                transaction.execute(
                    "DELETE FROM scope WHERE id = ?1",
                    params![id_bytes(scope_id.0)],
                )?;
            }
            transaction.execute(
                "DELETE FROM secret WHERE scope_id = ?1",
                params![id_bytes(retained_scope_id.0)],
            )?;
            Ok(())
        }
    }
}

fn validate_import_transaction(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let foreign_key_violation: Option<i64> = transaction
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if foreign_key_violation.is_some() {
        return Err(StoreError::Integrity);
    }
    let startup_profiles: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM profile WHERE activate_on_start = 1",
        [],
        |row| row.get(0),
    )?;
    if startup_profiles < 1 {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

fn update_scope(transaction: &Transaction<'_>, record: &ScopeRecord) -> Result<(), StoreError> {
    let changed = transaction.execute(
        "UPDATE scope
         SET vault_id = ?1, parent_id = ?2, kind = ?3, encrypted_path = ?4, path_lookup = ?5
         WHERE id = ?6",
        params![
            id_bytes(record.vault_id.0),
            record.parent_id.map(|id| id_bytes(id.0)),
            i64::from(record.kind),
            record.encrypted_path,
            record.path_lookup,
            id_bytes(record.id.0),
        ],
    )?;
    expect_single_change(changed)
}

fn update_profile(transaction: &Transaction<'_>, record: &ProfileRecord) -> Result<(), StoreError> {
    let changed = transaction.execute(
        "UPDATE profile
         SET vault_id = ?1, scope_id = ?2, encrypted_name = ?3, name_lookup = ?4,
             encrypted_description = ?5, activate_on_start = ?6, generation = ?7
         WHERE id = ?8",
        params![
            id_bytes(record.vault_id.0),
            id_bytes(record.scope_id.0),
            record.encrypted_name,
            record.name_lookup,
            record.encrypted_description,
            record.activate_on_start,
            to_i64(record.generation)?,
            id_bytes(record.id.0),
        ],
    )?;
    expect_single_change(changed)
}

fn map_vault(row: &rusqlite::Row<'_>) -> rusqlite::Result<VaultRecord> {
    Ok(VaultRecord {
        id: VaultId(read_id(row, 0)?),
        format_version: read_u32(row, 1)?,
        wrapped_master_key: row.get(2)?,
        kdf_parameters: row.get(3)?,
        kdf_salt: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn map_scope(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScopeRecord> {
    Ok(ScopeRecord {
        id: ScopeId(read_id(row, 0)?),
        vault_id: VaultId(read_id(row, 1)?),
        parent_id: read_optional_id(row, 2)?.map(ScopeId),
        kind: read_u8(row, 3)?,
        encrypted_path: row.get(4)?,
        path_lookup: row.get(5)?,
    })
}

fn map_profile(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProfileRecord> {
    Ok(ProfileRecord {
        id: ProfileId(read_id(row, 0)?),
        vault_id: VaultId(read_id(row, 1)?),
        scope_id: ScopeId(read_id(row, 2)?),
        encrypted_name: row.get(3)?,
        name_lookup: row.get(4)?,
        encrypted_description: row.get(5)?,
        activate_on_start: row.get(6)?,
        generation: read_u64(row, 7)?,
    })
}

fn map_workspace(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkspaceRecord> {
    Ok(WorkspaceRecord {
        id: WorkspaceId(read_id(row, 0)?),
        vault_id: VaultId(read_id(row, 1)?),
        encrypted_name: row.get(2)?,
        name_lookup: row.get(3)?,
    })
}

fn map_secret_http_access(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretHttpAccessRecord> {
    Ok(SecretHttpAccessRecord {
        secret_id: SecretId(read_id(row, 0)?),
        encrypted_host: row.get(1)?,
        port: read_u16(row, 2)?,
        methods: row.get(3)?,
        encrypted_path_prefix: row.get(4)?,
        max_request_bytes: read_u64(row, 5)?,
        max_response_bytes: read_u64(row, 6)?,
    })
}

fn map_secret(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRecord> {
    let value_id: Option<Vec<u8>> = row.get(7)?;
    let value = match value_id {
        Some(value_id) => Some(SecretValueRecord {
            value_id: SecretVersionId(uuid::Uuid::from_slice(&value_id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?),
            ciphertext: row.get(8)?,
            wrapped_dek: row.get(9)?,
            aad_digest: row.get(10)?,
            generator: row.get(11)?,
            generated_length: read_optional_u64(row, 12)?,
            entropy_bits: read_optional_u32(row, 13)?,
            created_at: row.get(14)?,
        }),
        None => None,
    };
    Ok(SecretRecord {
        id: SecretId(read_id(row, 0)?),
        scope_id: ScopeId(read_id(row, 1)?),
        encrypted_name: row.get(2)?,
        name_lookup: row.get(3)?,
        encrypted_description: row.get(4)?,
        current_version: read_u64(row, 5)?,
        status: read_u8(row, 6)?,
        value,
    })
}

fn id_bytes(id: uuid::Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}

fn read_id(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<uuid::Uuid> {
    let bytes: Vec<u8> = row.get(index)?;
    uuid::Uuid::from_slice(&bytes).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Blob,
            Box::new(error),
        )
    })
}

fn read_optional_id(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<uuid::Uuid>> {
    row.get::<_, Option<Vec<u8>>>(index)?
        .map(|bytes| uuid::Uuid::from_slice(&bytes))
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })
}

fn to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::NumericRange)
}

fn expect_single_change(changed: usize) -> Result<(), StoreError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::Integrity)
    }
}

fn read_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn read_u32(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u32> {
    let value: i64 = row.get(index)?;
    u32::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn read_u8(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u8> {
    let value: i64 = row.get(index)?;
    u8::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn read_u16(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u16> {
    let value: i64 = row.get(index)?;
    u16::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn read_optional_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(u64::try_from)
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })
}

fn read_optional_u32(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u32>> {
    row.get::<_, Option<i64>>(index)?
        .map(u32::try_from)
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn fixture() -> (VaultRecord, ScopeRecord, ProfileRecord) {
        let vault_id = VaultId(Uuid::new_v4());
        let scope_id = ScopeId(Uuid::new_v4());
        (
            VaultRecord {
                id: vault_id,
                format_version: 1,
                wrapped_master_key: vec![1; 72],
                kdf_parameters: vec![2],
                kdf_salt: vec![3; 16],
                created_at: 1,
            },
            ScopeRecord {
                id: scope_id,
                vault_id,
                parent_id: None,
                kind: 0,
                encrypted_path: vec![4],
                path_lookup: vec![5; 32],
            },
            ProfileRecord {
                id: ProfileId(Uuid::new_v4()),
                vault_id,
                scope_id,
                encrypted_name: vec![6],
                name_lookup: vec![7; 32],
                encrypted_description: None,
                activate_on_start: true,
                generation: 1,
            },
        )
    }

    fn value_fixture() -> SecretValueRecord {
        SecretValueRecord {
            value_id: SecretVersionId(Uuid::new_v4()),
            ciphertext: vec![3; 64],
            wrapped_dek: vec![4; 72],
            aad_digest: vec![5; 32],
            generator: None,
            generated_length: None,
            entropy_bits: None,
            created_at: 1,
        }
    }

    const SCHEMA_V2_FIXTURE: &str = "
    CREATE TABLE vault (
        id BLOB PRIMARY KEY NOT NULL,
        format_version INTEGER NOT NULL,
        wrapped_master_key BLOB NOT NULL,
        kdf_parameters BLOB NOT NULL,
        kdf_salt BLOB NOT NULL,
        created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE scope (
        id BLOB PRIMARY KEY NOT NULL,
        vault_id BLOB NOT NULL REFERENCES vault(id),
        parent_id BLOB REFERENCES scope(id),
        kind INTEGER NOT NULL,
        encrypted_path BLOB NOT NULL,
        path_lookup BLOB NOT NULL,
        UNIQUE(vault_id, path_lookup)
    ) STRICT;
    CREATE UNIQUE INDEX one_root_scope_per_vault
        ON scope(vault_id) WHERE parent_id IS NULL;
    CREATE TABLE profile (
        id BLOB PRIMARY KEY NOT NULL,
        vault_id BLOB NOT NULL REFERENCES vault(id),
        encrypted_name BLOB NOT NULL,
        name_lookup BLOB NOT NULL,
        encrypted_description BLOB,
        activate_on_start INTEGER NOT NULL CHECK (activate_on_start IN (0, 1)),
        generation INTEGER NOT NULL CHECK (generation >= 1),
        UNIQUE(vault_id, name_lookup)
    ) STRICT;
    CREATE UNIQUE INDEX one_startup_profile_per_vault
        ON profile(vault_id) WHERE activate_on_start = 1;
    CREATE TABLE secret (
        id BLOB PRIMARY KEY NOT NULL,
        scope_id BLOB NOT NULL REFERENCES scope(id),
        encrypted_name BLOB NOT NULL,
        name_lookup BLOB NOT NULL,
        encrypted_description BLOB,
        current_version INTEGER NOT NULL CHECK (current_version >= 1),
        status INTEGER NOT NULL,
        UNIQUE(scope_id, name_lookup)
    ) STRICT;
    CREATE TABLE secret_version (
        id BLOB PRIMARY KEY NOT NULL,
        secret_id BLOB NOT NULL REFERENCES secret(id),
        version INTEGER NOT NULL CHECK (version >= 1),
        ciphertext BLOB NOT NULL,
        wrapped_dek BLOB NOT NULL,
        aad_digest BLOB NOT NULL,
        generator INTEGER,
        generated_length INTEGER,
        entropy_bits INTEGER,
        created_at INTEGER NOT NULL,
        UNIQUE(secret_id, version)
    ) STRICT;
    CREATE TABLE audit_event (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        id BLOB UNIQUE NOT NULL,
        action INTEGER NOT NULL,
        outcome INTEGER NOT NULL,
        redacted_metadata BLOB NOT NULL,
        previous_hash BLOB NOT NULL,
        event_hash BLOB NOT NULL,
        created_at INTEGER NOT NULL
    ) STRICT;
    PRAGMA user_version = 2;
    ";

    #[test]
    fn migration_is_idempotent_and_initialization_is_atomic() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("vault.db");
        let (vault, scope, profile) = fixture();
        let mut store = Store::open(&path).expect("first open");
        assert_eq!(store.schema_version().expect("version"), 5);
        store
            .initialize(&vault, &scope, &profile)
            .expect("initialize");
        assert_eq!(store.vault().expect("vault"), vault);
        assert!(matches!(
            store.initialize(&vault, &scope, &profile),
            Err(StoreError::AlreadyInitialized)
        ));
        drop(store);
        assert_eq!(
            Store::open(&path)
                .expect("second open")
                .schema_version()
                .expect("version"),
            5
        );
    }

    #[test]
    fn portability_batch_rolls_back_every_record_on_late_failure() {
        let (vault, scope, profile) = fixture();
        let mut store = Store::open_in_memory().expect("store");
        store
            .initialize(&vault, &scope, &profile)
            .expect("initialize");
        let secret_id = SecretId(Uuid::new_v4());
        let batch = ImportBatch {
            secrets: vec![SecretRecord {
                id: secret_id,
                scope_id: scope.id,
                encrypted_name: vec![1],
                name_lookup: vec![2; 32],
                encrypted_description: None,
                current_version: 1,
                status: 0,
                value: None,
            }],
            ..ImportBatch::default()
        };
        assert!(store.apply_import_batch(&batch).is_err());
        assert!(store.secrets().expect("rolled back").is_empty());
    }

    #[test]
    fn backup_preserves_integrity_and_semantics() {
        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("vault.db");
        let backup = directory.path().join("backup.db");
        let (vault, scope, profile) = fixture();
        let mut store = Store::open(&source).expect("store");
        store
            .initialize(&vault, &scope, &profile)
            .expect("initialize");
        store.integrity_check().expect("integrity");
        store.backup(&backup).expect("backup");
        let recovered = Store::open(&backup).expect("recovered");
        recovered.integrity_check().expect("recovered integrity");
        assert_eq!(recovered.vault().expect("vault"), vault);
        assert_eq!(recovered.profiles().expect("profiles"), vec![profile]);
    }

    #[test]
    fn versioned_schema_refuses_destructive_migration() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("phase-one.db");
        let (vault, scope, profile) = fixture();
        let secret_id = SecretId(Uuid::new_v4());
        let version_id = SecretVersionId(Uuid::new_v4());
        let connection = Connection::open(&path).expect("open v2");
        connection
            .execute_batch(SCHEMA_V2_FIXTURE)
            .expect("schema v2");
        connection
            .execute(
                "INSERT INTO vault VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id_bytes(vault.id.0),
                    i64::from(vault.format_version),
                    vault.wrapped_master_key,
                    vault.kdf_parameters,
                    vault.kdf_salt,
                    vault.created_at,
                ],
            )
            .expect("vault");
        connection
            .execute(
                "INSERT INTO scope VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
                params![
                    id_bytes(scope.id.0),
                    id_bytes(scope.vault_id.0),
                    i64::from(scope.kind),
                    scope.encrypted_path,
                    scope.path_lookup,
                ],
            )
            .expect("scope");
        connection
            .execute(
                "INSERT INTO profile VALUES (?1, ?2, ?3, ?4, NULL, 1, 1)",
                params![
                    id_bytes(profile.id.0),
                    id_bytes(profile.vault_id.0),
                    profile.encrypted_name,
                    profile.name_lookup,
                ],
            )
            .expect("profile");
        connection
            .execute(
                "INSERT INTO secret VALUES (?1, ?2, ?3, ?4, NULL, 1, 0)",
                params![
                    id_bytes(secret_id.0),
                    id_bytes(scope.id.0),
                    vec![8_u8],
                    vec![9_u8; 32],
                ],
            )
            .expect("secret");
        connection
            .execute(
                "INSERT INTO secret_version VALUES
                 (?1, ?2, 1, ?3, ?4, ?5, NULL, NULL, NULL, 1)",
                params![
                    id_bytes(version_id.0),
                    id_bytes(secret_id.0),
                    vec![10_u8],
                    vec![11_u8],
                    vec![12_u8; 32],
                ],
            )
            .expect("version");
        drop(connection);

        assert!(matches!(
            Store::open(&path),
            Err(StoreError::SecretHistoryMigrationRequired(2))
        ));
        let connection = Connection::open(&path).expect("reopen v2");
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("version"),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT id FROM secret_version WHERE secret_id = ?1",
                    [id_bytes(secret_id.0)],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .expect("secret version"),
            id_bytes(version_id.0),
        );
    }

    const SCHEMA_V3_FIXTURE: &str = "
    CREATE TABLE vault (
        id BLOB PRIMARY KEY NOT NULL,
        format_version INTEGER NOT NULL,
        wrapped_master_key BLOB NOT NULL,
        kdf_parameters BLOB NOT NULL,
        kdf_salt BLOB NOT NULL,
        created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE scope (
        id BLOB PRIMARY KEY NOT NULL,
        vault_id BLOB NOT NULL REFERENCES vault(id),
        parent_id BLOB REFERENCES scope(id),
        kind INTEGER NOT NULL,
        encrypted_path BLOB NOT NULL,
        path_lookup BLOB NOT NULL,
        UNIQUE(vault_id, path_lookup)
    ) STRICT;
    CREATE UNIQUE INDEX one_root_scope_per_vault
        ON scope(vault_id) WHERE parent_id IS NULL;
    CREATE TABLE profile (
        id BLOB PRIMARY KEY NOT NULL,
        vault_id BLOB NOT NULL REFERENCES vault(id),
        scope_id BLOB NOT NULL REFERENCES scope(id),
        encrypted_name BLOB NOT NULL,
        name_lookup BLOB NOT NULL,
        encrypted_description BLOB,
        activate_on_start INTEGER NOT NULL CHECK (activate_on_start IN (0, 1)),
        generation INTEGER NOT NULL CHECK (generation >= 1),
        UNIQUE(vault_id, name_lookup)
    ) STRICT;
    CREATE TABLE secret (
        id BLOB PRIMARY KEY NOT NULL,
        scope_id BLOB NOT NULL REFERENCES scope(id),
        encrypted_name BLOB NOT NULL,
        name_lookup BLOB NOT NULL,
        encrypted_description BLOB,
        current_version INTEGER NOT NULL CHECK (current_version >= 0),
        status INTEGER NOT NULL CHECK (status IN (0, 1)),
        CHECK ((status = 0 AND current_version >= 1) OR (status = 1 AND current_version = 0)),
        UNIQUE(scope_id, name_lookup)
    ) STRICT;
    CREATE TABLE secret_version (
        id BLOB PRIMARY KEY NOT NULL,
        secret_id BLOB NOT NULL REFERENCES secret(id),
        version INTEGER NOT NULL CHECK (version >= 1),
        ciphertext BLOB NOT NULL,
        wrapped_dek BLOB NOT NULL,
        aad_digest BLOB NOT NULL,
        generator INTEGER,
        generated_length INTEGER,
        entropy_bits INTEGER,
        created_at INTEGER NOT NULL,
        UNIQUE(secret_id, version)
    ) STRICT;
    CREATE TABLE secret_http_access (
        secret_id BLOB PRIMARY KEY NOT NULL REFERENCES secret(id),
        encrypted_host BLOB NOT NULL,
        port INTEGER NOT NULL,
        methods TEXT NOT NULL,
        encrypted_path_prefix BLOB NOT NULL,
        max_request_bytes INTEGER NOT NULL,
        max_response_bytes INTEGER NOT NULL
    ) STRICT;
    PRAGMA user_version = 3;
    ";

    #[test]
    fn versioned_workspace_schema_refuses_destructive_migration() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("phase-two.db");
        let (vault, scope, profile) = fixture();
        let connection = Connection::open(&path).expect("open v3");
        connection
            .execute_batch(SCHEMA_V3_FIXTURE)
            .expect("schema v3");
        connection
            .execute(
                "INSERT INTO vault VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id_bytes(vault.id.0),
                    i64::from(vault.format_version),
                    vault.wrapped_master_key,
                    vault.kdf_parameters,
                    vault.kdf_salt,
                    vault.created_at,
                ],
            )
            .expect("vault");
        connection
            .execute(
                "INSERT INTO scope VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
                params![
                    id_bytes(scope.id.0),
                    id_bytes(scope.vault_id.0),
                    i64::from(scope.kind),
                    scope.encrypted_path,
                    scope.path_lookup,
                ],
            )
            .expect("scope");
        connection
            .execute(
                "INSERT INTO profile VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
                params![
                    id_bytes(profile.id.0),
                    id_bytes(profile.vault_id.0),
                    id_bytes(profile.scope_id.0),
                    profile.encrypted_name,
                    profile.name_lookup,
                    profile.activate_on_start,
                    to_i64(profile.generation).expect("generation"),
                ],
            )
            .expect("profile");
        drop(connection);

        assert!(matches!(
            Store::open(&path),
            Err(StoreError::SecretHistoryMigrationRequired(3))
        ));
    }

    #[test]
    fn singleton_and_mutation_invariants_fail_closed() {
        let (vault, scope, profile) = fixture();
        let mut store = Store::open_in_memory().expect("store");
        store
            .initialize(&vault, &scope, &profile)
            .expect("initialize");

        assert!(matches!(
            store.set_profile_activate_on_start(ProfileId(Uuid::new_v4()), true),
            Err(StoreError::Integrity)
        ));
        assert!(store.profiles().expect("profiles")[0].activate_on_start);

        let second_vault = VaultRecord {
            id: VaultId(Uuid::new_v4()),
            ..vault.clone()
        };
        let transaction = store.connection.transaction().expect("transaction");
        insert_vault(&transaction, &second_vault).expect("second vault");
        transaction.commit().expect("commit");
        assert!(matches!(store.vault(), Err(StoreError::Integrity)));
    }

    #[test]
    fn secret_value_overwrite_requires_matching_generation_and_active_status() {
        let (vault, scope, profile) = fixture();
        let mut store = Store::open_in_memory().expect("store");
        store
            .initialize(&vault, &scope, &profile)
            .expect("initialize");
        let secret_id = SecretId(Uuid::new_v4());
        let secret = SecretRecord {
            id: secret_id,
            scope_id: scope.id,
            encrypted_name: vec![1],
            name_lookup: vec![2; 32],
            encrypted_description: None,
            current_version: 1,
            status: 0,
            value: Some(value_fixture()),
        };
        store.insert_secret(&secret).expect("first value");
        assert!(matches!(
            store.overwrite_secret_value(secret_id, 99, &value_fixture()),
            Err(StoreError::Integrity)
        ));
        store
            .overwrite_secret_value(secret_id, 1, &value_fixture())
            .expect("overwrite");
        let overwritten = store
            .secret_by_id(secret_id)
            .expect("secret")
            .expect("present");
        assert_eq!(overwritten.current_version, 2);
    }

    #[test]
    fn overwriting_a_secret_value_discards_the_previous_one() {
        let (vault, scope, profile) = fixture();
        let mut store = Store::open_in_memory().expect("store");
        store
            .initialize(&vault, &scope, &profile)
            .expect("initialize");
        let secret_id = SecretId(Uuid::new_v4());
        let first_value = value_fixture();
        let first_value_id = first_value.value_id;
        store
            .insert_secret(&SecretRecord {
                id: secret_id,
                scope_id: scope.id,
                encrypted_name: vec![1],
                name_lookup: vec![2; 32],
                encrypted_description: None,
                current_version: 1,
                status: 0,
                value: Some(first_value),
            })
            .expect("first value");
        store
            .overwrite_secret_value(secret_id, 1, &value_fixture())
            .expect("overwrite");
        let overwritten = store
            .secret_by_id(secret_id)
            .expect("secret")
            .expect("present")
            .value
            .expect("value");
        assert_ne!(overwritten.value_id, first_value_id);
    }

    #[test]
    fn schema_has_no_plaintext_name_columns() {
        let store = Store::open_in_memory().expect("store");
        let mut statement = store
            .connection
            .prepare("SELECT sql FROM sqlite_schema WHERE type = 'table' AND sql IS NOT NULL")
            .expect("schema query");
        let schemas = statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("rows")
            .join("\n")
            .to_lowercase();
        assert!(!schemas.contains("logical_name"));
        assert!(!schemas.contains("normalized_name"));
        assert!(schemas.contains("encrypted_name"));
    }

    #[test]
    fn empty_phase_zero_schema_migrates_but_nonempty_schema_fails_closed() {
        let directory = tempfile::tempdir().expect("tempdir");
        let empty = directory.path().join("empty-v1.db");
        let connection = Connection::open(&empty).expect("open v1");
        connection
            .execute_batch(
                "CREATE TABLE vault (
                    id BLOB PRIMARY KEY NOT NULL,
                    format_version INTEGER NOT NULL,
                    wrapped_master_key BLOB NOT NULL,
                    kdf_parameters BLOB NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE scope (id BLOB PRIMARY KEY);
                CREATE TABLE profile (id BLOB PRIMARY KEY);
                CREATE TABLE secret (id BLOB PRIMARY KEY);
                CREATE TABLE secret_version (id BLOB PRIMARY KEY);
                CREATE TABLE audit_event (id BLOB PRIMARY KEY);
                PRAGMA user_version = 1;",
            )
            .expect("v1 schema");
        drop(connection);
        assert_eq!(
            Store::open(&empty)
                .expect("migrate")
                .schema_version()
                .expect("version"),
            5
        );

        let occupied = directory.path().join("occupied-v1.db");
        let connection = Connection::open(&occupied).expect("open occupied v1");
        connection
            .execute_batch(
                "CREATE TABLE vault (
                    id BLOB PRIMARY KEY NOT NULL,
                    format_version INTEGER NOT NULL,
                    wrapped_master_key BLOB NOT NULL,
                    kdf_parameters BLOB NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE scope (id BLOB PRIMARY KEY);
                CREATE TABLE profile (id BLOB PRIMARY KEY);
                CREATE TABLE secret (id BLOB PRIMARY KEY);
                CREATE TABLE secret_version (id BLOB PRIMARY KEY);
                CREATE TABLE audit_event (id BLOB PRIMARY KEY);
                INSERT INTO vault VALUES (x'00', 1, x'00', x'00', 0);
                PRAGMA user_version = 1;",
            )
            .expect("occupied schema");
        drop(connection);
        assert!(matches!(
            Store::open(&occupied),
            Err(StoreError::UnsupportedSchema(1))
        ));
    }
}
