use std::fs;

use envault_core::{GeneratorFormat, GeneratorLength};

use super::*;

fn fast_kdf() -> KdfParameters {
    KdfParameters {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    }
}

fn initialized() -> (tempfile::TempDir, PathBuf, SensitiveInput, VaultSession) {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault.db");
    let password = SensitiveInput::copy_from_slice(b"correct horse battery staple");
    initialize_with_parameters(&path, &password, fast_kdf()).expect("initialize");
    let session = VaultSession::unlock(&path, &password).expect("unlock");
    (directory, path, password, session)
}

#[test]
fn initialization_is_atomic_and_wrong_password_fails() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault.db");
    let password = SensitiveInput::copy_from_slice(b"correct horse battery staple");
    let initialization =
        initialize_with_parameters(&path, &password, fast_kdf()).expect("initialize");
    assert!(path.is_file());
    assert!(matches!(
        initialize_with_parameters(&path, &password, fast_kdf()),
        Err(ServiceError::AlreadyInitialized)
    ));
    assert!(matches!(
        VaultSession::unlock(&path, &SensitiveInput::copy_from_slice(b"wrong password")),
        Err(ServiceError::AuthenticationFailed)
    ));
    let session = VaultSession::unlock(&path, &password).expect("unlock");
    assert_eq!(session.vault_id(), initialization.vault_id);
    assert_eq!(session.root_scope_id(), initialization.root_scope_id);
    assert_eq!(
        session.profiles().expect("profiles"),
        vec![ProfileView {
            id: initialization.base_profile_id,
            name: "base".into(),
            description: None,
            activate_on_start: true,
            generation: 1,
        }]
    );
}

#[test]
fn profile_rename_preserves_identity_and_startup_invariant() {
    let (_directory, _path, _password, mut session) = initialized();
    let created = session
        .create_profile("Development", Some("Developer credentials"))
        .expect("create profile");
    let renamed = session
        .rename_profile("development", "Engineering")
        .expect("rename profile");
    assert_eq!(renamed.id, created.id);
    assert_eq!(renamed.name, "Engineering");
    assert_eq!(renamed.generation, 2);
    let updated = session
        .update_profile("engineering", Some("Rotated developer credentials"))
        .expect("update profile");
    assert_eq!(updated.id, created.id);
    assert_eq!(
        session.profile("engineering").expect("show profile"),
        updated
    );
    assert_eq!(updated.generation, 3);
    session.activate_profile("engineering").expect("activate");
    let profiles = session.profiles().expect("profiles");
    assert_eq!(
        profiles
            .iter()
            .find(|profile| profile.name == "base")
            .expect("base")
            .generation,
        2
    );
    assert!(matches!(
        session.delete_profile("engineering"),
        Err(ServiceError::StartupProfileRequired)
    ));
    session.activate_profile("base").expect("activate base");
    session.delete_profile("engineering").expect("delete");
    assert_eq!(session.profiles().expect("profiles").len(), 1);
}

#[test]
fn secret_versions_are_immutable_and_rename_preserves_identity() {
    let (_directory, _path, _password, mut session) = initialized();
    let created = session
        .create_secret(
            "OPENAI_API_KEY",
            Some("OpenAI credential"),
            SensitiveInput::copy_from_slice(b"phase-one-plaintext-sentinel"),
        )
        .expect("create secret");
    let renamed = session
        .rename_secret("openai_api_key", "OPENAI_PRIMARY_KEY")
        .expect("rename secret");
    assert_eq!(renamed.id, created.id);
    assert_eq!(renamed.current_version, 1);
    let updated = session
        .update_secret("openai_primary_key", Some("Primary OpenAI credential"))
        .expect("update secret");
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.current_version, 1);
    assert_eq!(
        session.secret("openai_primary_key").expect("show secret"),
        updated
    );
    let second = session
        .set_secret_value(
            "openai_primary_key",
            SensitiveInput::copy_from_slice(b"phase-one-second-sentinel"),
        )
        .expect("set value");
    assert_eq!(second.version, 2);
    let versions = session
        .secret_versions("openai_primary_key")
        .expect("versions");
    assert_eq!(versions.len(), 2);
    assert_ne!(versions[0].id, versions[1].id);
    let record = session
        .secret_by_name("openai_primary_key")
        .expect("secret");
    let stored_versions = session
        .store
        .secret_versions(record.id)
        .expect("stored versions");
    assert_eq!(
        session
            .decrypt_secret_version(&record, &stored_versions[0])
            .expect("first value")
            .as_ref(),
        b"phase-one-plaintext-sentinel"
    );
    assert_eq!(
        session
            .decrypt_secret_version(&record, &stored_versions[1])
            .expect("second value")
            .as_ref(),
        b"phase-one-second-sentinel"
    );
}

#[test]
fn generators_return_only_redacted_metadata() {
    let (_directory, _path, _password, mut session) = initialized();
    let secret = session
        .create_generated_secret(
            "SESSION_TOKEN",
            None,
            GeneratorSpec {
                format: GeneratorFormat::Base64Url,
                length: GeneratorLength::Chars(64),
                allow_weak: false,
            },
        )
        .expect("generated secret");
    assert_eq!(secret.current_version, 1);
    let versions = session.secret_versions("session_token").expect("versions");
    assert_eq!(versions[0].generated_length, Some(64));
    assert_eq!(versions[0].entropy_bits, Some(384));
    assert_eq!(versions[0].generator, Some(GeneratorFormat::Base64Url));
}

#[test]
fn generator_formats_have_exact_lengths_and_entropy() {
    let uuid = generate_value(GeneratorSpec {
        format: GeneratorFormat::UuidV4,
        length: GeneratorLength::Default,
        allow_weak: false,
    })
    .expect("uuid");
    assert_eq!(uuid.value.as_ref().len(), 36);
    assert_eq!(uuid.metadata.entropy_bits, 122);

    let url = generate_value(GeneratorSpec {
        format: GeneratorFormat::Base64Url,
        length: GeneratorLength::Bytes(32),
        allow_weak: false,
    })
    .expect("base64url");
    assert_eq!(url.value.as_ref().len(), 43);
    assert!(!url.value.as_ref().contains(&b'='));

    let standard = generate_value(GeneratorSpec {
        format: GeneratorFormat::Base64,
        length: GeneratorLength::Bytes(32),
        allow_weak: false,
    })
    .expect("base64");
    assert_eq!(standard.value.as_ref().len(), 44);
    assert!(standard.value.as_ref().ends_with(b"="));
}

#[test]
fn backup_round_trip_preserves_encrypted_semantics() {
    let (directory, _path, password, mut session) = initialized();
    session
        .create_secret(
            "DATABASE_URL",
            None,
            SensitiveInput::copy_from_slice(b"postgres://forensic-sentinel"),
        )
        .expect("create secret");
    let backup = directory.path().join("backup.db");
    session.backup(&backup).expect("backup");
    drop(session);
    let recovered = VaultSession::unlock(&backup, &password).expect("unlock backup");
    assert_eq!(
        recovered.secrets().expect("secrets")[0].name,
        "DATABASE_URL"
    );
    recovered.integrity_check().expect("integrity");
}

#[test]
fn forensic_scan_finds_no_plaintext_in_persistent_artifacts() {
    let (directory, path, _password, mut session) = initialized();
    let sentinels = [
        "FORENSIC_SECRET_NAME_7f162f64",
        "FORENSIC_SECRET_VALUE_0f4bb31a",
        "FORENSIC_DESCRIPTION_86ce61aa",
    ];
    session
        .create_secret(
            sentinels[0],
            Some(sentinels[2]),
            SensitiveInput::copy_from_slice(sentinels[1].as_bytes()),
        )
        .expect("create secret");
    let backup = directory.path().join("forensic-backup.db");
    session.backup(&backup).expect("backup");
    session.checkpoint().expect("checkpoint");
    drop(session);
    let artifacts = [
        path.clone(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
        backup,
    ];
    for artifact in artifacts.into_iter().filter(|artifact| artifact.exists()) {
        let bytes = fs::read(&artifact).expect("read artifact");
        for sentinel in sentinels {
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel.as_bytes()),
                "plaintext sentinel found in {}",
                artifact.display()
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn vault_and_backup_are_private_from_first_publication() {
    use std::os::unix::fs::PermissionsExt;

    let (directory, path, _password, session) = initialized();
    let backup = directory.path().join("private-backup.db");
    session.backup(&backup).expect("backup");
    for artifact in [path, backup] {
        let mode = fs::metadata(artifact)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[cfg(unix)]
#[test]
fn unlock_repairs_database_permissions_before_reading() {
    use std::os::unix::fs::PermissionsExt;

    let (_directory, path, password, session) = initialized();
    drop(session);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen permissions");
    let reopened = VaultSession::unlock(&path, &password).expect("unlock");
    drop(reopened);
    let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn encrypted_metadata_tamper_fails_unlock_closed() {
    let (_directory, path, password, session) = initialized();
    drop(session);
    let connection = rusqlite::Connection::open(&path).expect("open database");
    let mut encrypted: Vec<u8> = connection
        .query_row("SELECT encrypted_name FROM profile LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("encrypted name");
    let last = encrypted.last_mut().expect("ciphertext byte");
    *last ^= 0x80;
    connection
        .execute(
            "UPDATE profile SET encrypted_name = ?1",
            rusqlite::params![encrypted],
        )
        .expect("tamper");
    drop(connection);
    assert!(matches!(
        VaultSession::unlock(&path, &password),
        Err(ServiceError::Corrupt)
    ));
}

#[test]
fn lookup_digest_tamper_fails_unlock_closed() {
    let (_directory, path, password, session) = initialized();
    drop(session);
    let connection = rusqlite::Connection::open(&path).expect("open database");
    connection
        .execute("UPDATE profile SET name_lookup = zeroblob(32)", [])
        .expect("tamper lookup");
    drop(connection);
    assert!(matches!(
        VaultSession::unlock(&path, &password),
        Err(ServiceError::Corrupt)
    ));
}

#[test]
fn cryptographic_integrity_check_detects_secret_value_tamper() {
    let (_directory, path, _password, mut session) = initialized();
    session
        .create_secret(
            "SIGNING_KEY",
            None,
            SensitiveInput::copy_from_slice(b"integrity-sentinel"),
        )
        .expect("create secret");
    session.checkpoint().expect("checkpoint");
    let connection = rusqlite::Connection::open(&path).expect("open database");
    let mut ciphertext: Vec<u8> = connection
        .query_row("SELECT ciphertext FROM secret_version LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("ciphertext");
    let last = ciphertext.last_mut().expect("ciphertext byte");
    *last ^= 0x40;
    connection
        .execute(
            "UPDATE secret_version SET ciphertext = ?1",
            rusqlite::params![ciphertext],
        )
        .expect("tamper value");
    drop(connection);
    assert!(matches!(
        session.integrity_check(),
        Err(ServiceError::Corrupt)
    ));
}
