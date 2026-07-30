#![forbid(unsafe_code)]

use std::path::Path;

use rusqlite::Connection;
use thiserror::Error;

const SCHEMA_VERSION: i64 = 1;

#[derive(Debug)]
pub struct Store {
    connection: Connection,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("unsupported schema version {0}")]
    UnsupportedSchema(i64),
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn schema_version(&self) -> Result<i64, StoreError> {
        self.connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(StoreError::from)
    }

    fn migrate(&mut self) -> Result<(), StoreError> {
        let current: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if current > SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema(current));
        }
        if current == 0 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "
                CREATE TABLE vault (
                    id BLOB PRIMARY KEY NOT NULL,
                    format_version INTEGER NOT NULL,
                    wrapped_master_key BLOB NOT NULL,
                    kdf_parameters BLOB NOT NULL,
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
                CREATE TABLE profile (
                    id BLOB PRIMARY KEY NOT NULL,
                    vault_id BLOB NOT NULL REFERENCES vault(id),
                    encrypted_name BLOB NOT NULL,
                    name_lookup BLOB NOT NULL,
                    encrypted_description BLOB,
                    activate_on_start INTEGER NOT NULL CHECK (activate_on_start IN (0, 1)),
                    generation INTEGER NOT NULL,
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
                    status INTEGER NOT NULL,
                    UNIQUE(scope_id, name_lookup)
                ) STRICT;
                CREATE TABLE secret_version (
                    id BLOB PRIMARY KEY NOT NULL,
                    secret_id BLOB NOT NULL REFERENCES secret(id),
                    version INTEGER NOT NULL,
                    ciphertext BLOB NOT NULL,
                    wrapped_dek BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    aad_digest BLOB NOT NULL,
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
                PRAGMA user_version = 1;
                ",
            )?;
            transaction.commit()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_is_idempotent() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("vault.db");
        assert_eq!(
            Store::open(&path)
                .expect("first open")
                .schema_version()
                .expect("version"),
            1
        );
        assert_eq!(
            Store::open(&path)
                .expect("second open")
                .schema_version()
                .expect("version"),
            1
        );
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
}
