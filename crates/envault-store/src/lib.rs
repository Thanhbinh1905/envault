#![forbid(unsafe_code)]

use std::{path::Path, time::Duration};

use envault_core::{ProfileId, ScopeId, SecretId, SecretVersionId, VaultId};
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, backup::Backup, params,
};
use thiserror::Error;

const SCHEMA_VERSION: i64 = 3;

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
pub struct SecretRecord {
    pub id: SecretId,
    pub scope_id: ScopeId,
    pub encrypted_name: Vec<u8>,
    pub name_lookup: Vec<u8>,
    pub encrypted_description: Option<Vec<u8>>,
    pub current_version: u64,
    pub status: u8,
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
pub struct SecretVersionRecord {
    pub id: SecretVersionId,
    pub secret_id: SecretId,
    pub version: u64,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub aad_digest: Vec<u8>,
    pub generator: Option<u8>,
    pub generated_length: Option<u64>,
    pub entropy_bits: Option<u32>,
    pub created_at: i64,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretVersionAppend {
    pub secret_id: SecretId,
    pub expected_current_version: u64,
    pub version: SecretVersionRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBatch {
    pub reset: ImportReset,
    pub scope_updates: Vec<ScopeRecord>,
    pub profile_updates: Vec<ProfileRecord>,
    pub scopes: Vec<ScopeRecord>,
    pub profiles: Vec<ProfileRecord>,
    pub secrets: Vec<SecretRecord>,
    pub secret_versions: Vec<SecretVersionRecord>,
    pub version_appends: Vec<SecretVersionAppend>,
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
            secret_versions: Vec::new(),
            version_appends: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("unsupported schema version {0}")]
    UnsupportedSchema(i64),
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

    pub fn secrets(&self) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, scope_id, encrypted_name, name_lookup, encrypted_description,
                    current_version, status
             FROM secret ORDER BY rowid",
        )?;
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
                "SELECT id, scope_id, encrypted_name, name_lookup, encrypted_description,
                        current_version, status
                 FROM secret WHERE scope_id = ?1 AND name_lookup = ?2",
                params![id_bytes(scope_id.0), lookup],
                map_secret,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn secret_by_id(&self, secret_id: SecretId) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, scope_id, encrypted_name, name_lookup, encrypted_description,
                        current_version, status
                 FROM secret WHERE id = ?1",
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

    pub fn insert_secret_with_version(
        &mut self,
        secret: &SecretRecord,
        version: &SecretVersionRecord,
    ) -> Result<(), StoreError> {
        if secret.current_version != 1 || version.version != 1 || version.secret_id != secret.id {
            return Err(StoreError::Integrity);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_secret(&transaction, secret)?;
        insert_secret_version(&transaction, version)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn insert_tombstone(&mut self, secret: &SecretRecord) -> Result<(), StoreError> {
        if secret.status != 1 || secret.current_version != 0 {
            return Err(StoreError::Integrity);
        }
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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let versions_deleted = transaction.execute(
            "DELETE FROM secret_version WHERE secret_id = ?1",
            params![id_bytes(secret_id.0)],
        )?;
        if versions_deleted == 0 {
            return Err(StoreError::Integrity);
        }
        let changed = transaction.execute(
            "UPDATE secret
             SET encrypted_name = ?1, name_lookup = ?2, encrypted_description = NULL,
                 current_version = 0, status = 1
             WHERE id = ?3 AND status = 0",
            params![encrypted_name, name_lookup, id_bytes(secret_id.0)],
        )?;
        if changed != 1 {
            return Err(StoreError::Integrity);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn insert_secret_version(
        &mut self,
        secret_id: SecretId,
        expected_current_version: u64,
        version: &SecretVersionRecord,
    ) -> Result<(), StoreError> {
        if version.secret_id != secret_id
            || expected_current_version.checked_add(1) != Some(version.version)
        {
            return Err(StoreError::Integrity);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE secret SET current_version = ?1
             WHERE id = ?2 AND current_version = ?3",
            params![
                to_i64(version.version)?,
                id_bytes(secret_id.0),
                to_i64(expected_current_version)?,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Integrity);
        }
        insert_secret_version(&transaction, version)?;
        transaction.commit()?;
        Ok(())
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

    pub fn secret_versions(
        &self,
        secret_id: SecretId,
    ) -> Result<Vec<SecretVersionRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, secret_id, version, ciphertext, wrapped_dek, aad_digest,
                    generator, generated_length, entropy_bits, created_at
             FROM secret_version WHERE secret_id = ?1 ORDER BY version",
        )?;
        statement
            .query_map(params![id_bytes(secret_id.0)], map_secret_version)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn delete_secret(&mut self, secret_id: SecretId) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let versions_deleted = transaction.execute(
            "DELETE FROM secret_version WHERE secret_id = ?1",
            params![id_bytes(secret_id.0)],
        )?;
        transaction.execute(
            "DELETE FROM secret_http_access WHERE secret_id = ?1",
            params![id_bytes(secret_id.0)],
        )?;
        let status: Option<u8> = transaction
            .query_row(
                "SELECT status FROM secret WHERE id = ?1",
                params![id_bytes(secret_id.0)],
                |row| read_u8(row, 0),
            )
            .optional()?;
        let Some(status) = status else {
            return Err(StoreError::Integrity);
        };
        if status == 0 && versions_deleted == 0 {
            return Err(StoreError::Integrity);
        }
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
        for secret in &batch.secrets {
            insert_secret(&transaction, secret)?;
        }
        for version in &batch.secret_versions {
            insert_secret_version(&transaction, version)?;
        }
        for append in &batch.version_appends {
            if append.version.secret_id != append.secret_id
                || append.expected_current_version.checked_add(1) != Some(append.version.version)
            {
                return Err(StoreError::Integrity);
            }
            let changed = transaction.execute(
                "UPDATE secret SET current_version = ?1
                 WHERE id = ?2 AND current_version = ?3 AND status = 0",
                params![
                    to_i64(append.version.version)?,
                    id_bytes(append.secret_id.0),
                    to_i64(append.expected_current_version)?,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Integrity);
            }
            insert_secret_version(&transaction, &append.version)?;
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
            transaction.execute_batch(SCHEMA_V3)?;
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
            transaction.execute_batch(SCHEMA_V3)?;
            transaction.commit()?;
        } else if current == 2 {
            self.migrate_v2_to_v3()?;
        }
        Ok(())
    }

    fn migrate_v2_to_v3(&mut self) -> Result<(), StoreError> {
        self.connection.pragma_update(None, "foreign_keys", "OFF")?;
        let migration = (|| {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(MIGRATE_V2_TO_V3)?;
            transaction.commit()?;
            Ok::<(), StoreError>(())
        })();
        let restore = self.connection.pragma_update(None, "foreign_keys", "ON");
        migration?;
        restore?;
        let violation: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if violation.is_some() {
            return Err(StoreError::Integrity);
        }
        Ok(())
    }
}

const SCHEMA_V3: &str = "
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

const MIGRATE_V2_TO_V3: &str = "
CREATE TABLE profile_v3 (
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
INSERT INTO profile_v3
    (id, vault_id, scope_id, encrypted_name, name_lookup, encrypted_description,
     activate_on_start, generation)
SELECT profile.id, profile.vault_id,
       (SELECT scope.id FROM scope
        WHERE scope.vault_id = profile.vault_id AND scope.parent_id IS NULL),
       profile.encrypted_name, profile.name_lookup, profile.encrypted_description,
       profile.activate_on_start, profile.generation
FROM profile;
DROP INDEX one_startup_profile_per_vault;
DROP TABLE profile;
ALTER TABLE profile_v3 RENAME TO profile;

CREATE TABLE secret_v3 (
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
INSERT INTO secret_v3
    (id, scope_id, encrypted_name, name_lookup, encrypted_description, current_version, status)
SELECT id, scope_id, encrypted_name, name_lookup, encrypted_description, current_version, status
FROM secret;
DROP TABLE secret;
ALTER TABLE secret_v3 RENAME TO secret;

DROP TABLE IF EXISTS audit_event;
DROP TABLE IF EXISTS principal;
DROP TABLE IF EXISTS policy_rule;
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

fn insert_secret(transaction: &Transaction<'_>, record: &SecretRecord) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO secret
         (id, scope_id, encrypted_name, name_lookup, encrypted_description,
          current_version, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id_bytes(record.id.0),
            id_bytes(record.scope_id.0),
            record.encrypted_name,
            record.name_lookup,
            record.encrypted_description,
            to_i64(record.current_version)?,
            i64::from(record.status),
        ],
    )?;
    Ok(())
}

fn insert_secret_version(
    transaction: &Transaction<'_>,
    record: &SecretVersionRecord,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO secret_version
         (id, secret_id, version, ciphertext, wrapped_dek, aad_digest,
          generator, generated_length, entropy_bits, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            id_bytes(record.id.0),
            id_bytes(record.secret_id.0),
            to_i64(record.version)?,
            record.ciphertext,
            record.wrapped_dek,
            record.aad_digest,
            record.generator.map(i64::from),
            record.generated_length.map(to_i64).transpose()?,
            record.entropy_bits.map(i64::from),
            record.created_at,
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
            transaction.execute("DELETE FROM secret_version", [])?;
            transaction.execute("DELETE FROM secret", [])?;
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
                    "DELETE FROM secret_version
                     WHERE secret_id IN (SELECT id FROM secret WHERE scope_id = ?1)",
                    params![id_bytes(scope_id.0)],
                )?;
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
                "DELETE FROM secret_version
                 WHERE secret_id IN (SELECT id FROM secret WHERE scope_id = ?1)",
                params![id_bytes(retained_scope_id.0)],
            )?;
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
    let invalid_secret: Option<i64> = transaction
        .query_row(
            "SELECT 1
             FROM secret
             WHERE (status = 0 AND current_version !=
                       (SELECT COUNT(*) FROM secret_version WHERE secret_id = secret.id))
                OR (status = 1 AND EXISTS
                       (SELECT 1 FROM secret_version WHERE secret_id = secret.id))
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if invalid_secret.is_some() {
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

fn map_secret(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRecord> {
    Ok(SecretRecord {
        id: SecretId(read_id(row, 0)?),
        scope_id: ScopeId(read_id(row, 1)?),
        encrypted_name: row.get(2)?,
        name_lookup: row.get(3)?,
        encrypted_description: row.get(4)?,
        current_version: read_u64(row, 5)?,
        status: read_u8(row, 6)?,
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

fn map_secret_version(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretVersionRecord> {
    Ok(SecretVersionRecord {
        id: SecretVersionId(read_id(row, 0)?),
        secret_id: SecretId(read_id(row, 1)?),
        version: read_u64(row, 2)?,
        ciphertext: row.get(3)?,
        wrapped_dek: row.get(4)?,
        aad_digest: row.get(5)?,
        generator: row.get(6)?,
        generated_length: read_optional_u64(row, 7)?,
        entropy_bits: read_optional_u32(row, 8)?,
        created_at: row.get(9)?,
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
        assert_eq!(store.schema_version().expect("version"), 3);
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
            3
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
            }],
            secret_versions: vec![SecretVersionRecord {
                id: SecretVersionId(Uuid::new_v4()),
                secret_id: SecretId(Uuid::new_v4()),
                version: 1,
                ciphertext: vec![3; 64],
                wrapped_dek: vec![4; 72],
                aad_digest: vec![5; 32],
                generator: None,
                generated_length: None,
                entropy_bits: None,
                created_at: 1,
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
    fn phase_one_schema_migrates_profiles_and_secret_versions_losslessly() {
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

        let migrated = Store::open(&path).expect("migrate");
        assert_eq!(migrated.schema_version().expect("version"), 3);
        assert_eq!(migrated.profiles().expect("profiles")[0].scope_id, scope.id);
        assert_eq!(
            migrated.secret_versions(secret_id).expect("versions")[0].id,
            version_id
        );
        migrated.integrity_check().expect("integrity");
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
    fn secret_version_insertion_requires_matching_consecutive_identity() {
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
        };
        let first = SecretVersionRecord {
            id: SecretVersionId(Uuid::new_v4()),
            secret_id,
            version: 1,
            ciphertext: vec![3],
            wrapped_dek: vec![4],
            aad_digest: vec![5; 32],
            generator: None,
            generated_length: None,
            entropy_bits: None,
            created_at: 1,
        };
        store
            .insert_secret_with_version(&secret, &first)
            .expect("first version");
        let nonconsecutive = SecretVersionRecord {
            id: SecretVersionId(Uuid::new_v4()),
            version: 3,
            ..first
        };
        assert!(matches!(
            store.insert_secret_version(secret_id, 1, &nonconsecutive),
            Err(StoreError::Integrity)
        ));
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
            3
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
