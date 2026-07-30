#![forbid(unsafe_code)]

use std::{path::Path, time::Duration};

use envault_core::{ProfileId, ScopeId, SecretId, SecretVersionId, VaultId};
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, backup::Backup, params,
};
use thiserror::Error;

const SCHEMA_VERSION: i64 = 2;

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
            "SELECT id, vault_id, encrypted_name, name_lookup, encrypted_description,
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
                "SELECT id, vault_id, encrypted_name, name_lookup, encrypted_description,
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

    pub fn set_startup_profile(&mut self, profile_id: ProfileId) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deactivated = transaction.execute(
            "UPDATE profile
             SET activate_on_start = 0, generation = generation + 1
             WHERE activate_on_start = 1",
            [],
        )?;
        if deactivated != 1 {
            return Err(StoreError::Integrity);
        }
        let activated = transaction.execute(
            "UPDATE profile SET activate_on_start = 1, generation = generation + 1 WHERE id = ?1",
            params![id_bytes(profile_id.0)],
        )?;
        if activated != 1 {
            return Err(StoreError::Integrity);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_profile(&mut self, profile_id: ProfileId) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "DELETE FROM profile WHERE id = ?1 AND activate_on_start = 0",
            params![id_bytes(profile_id.0)],
        )?;
        expect_single_change(changed)
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
        if versions_deleted == 0 {
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
            transaction.execute_batch(SCHEMA_V2)?;
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
            transaction.execute_batch(SCHEMA_V2)?;
            transaction.commit()?;
        }
        Ok(())
    }
}

const SCHEMA_V2: &str = "
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
         (id, vault_id, encrypted_name, name_lookup, encrypted_description,
          activate_on_start, generation)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id_bytes(record.id.0),
            id_bytes(record.vault_id.0),
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
        encrypted_name: row.get(2)?,
        name_lookup: row.get(3)?,
        encrypted_description: row.get(4)?,
        activate_on_start: row.get(5)?,
        generation: read_u64(row, 6)?,
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
                encrypted_name: vec![6],
                name_lookup: vec![7; 32],
                encrypted_description: None,
                activate_on_start: true,
                generation: 1,
            },
        )
    }

    #[test]
    fn migration_is_idempotent_and_initialization_is_atomic() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("vault.db");
        let (vault, scope, profile) = fixture();
        let mut store = Store::open(&path).expect("first open");
        assert_eq!(store.schema_version().expect("version"), 2);
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
            2
        );
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
    fn singleton_and_mutation_invariants_fail_closed() {
        let (vault, scope, profile) = fixture();
        let mut store = Store::open_in_memory().expect("store");
        store
            .initialize(&vault, &scope, &profile)
            .expect("initialize");

        assert!(matches!(
            store.set_startup_profile(ProfileId(Uuid::new_v4())),
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
            2
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
