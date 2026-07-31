use std::{collections::BTreeMap, fs};

use envault_broker::{HttpConstraint, HttpMethod, HttpRequest};
use envault_core::{GeneratorFormat, GeneratorLength, ScopeKind, SecretStatus};

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
            scope_id: initialization.root_scope_id,
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
    session.load_profile("engineering").expect("load");
    assert!(matches!(
        session.delete_profile("base"),
        Err(ServiceError::Conflict)
    ));
    assert!(matches!(
        session.unload_profile("base"),
        Err(ServiceError::StartupProfileRequired)
    ));
    assert!(matches!(
        session.delete_profile("engineering"),
        Err(ServiceError::StartupProfileRequired)
    ));
    session.unload_profile("engineering").expect("unload");
    session.delete_profile("engineering").expect("delete");
    assert_eq!(session.profiles().expect("profiles").len(), 1);
}

#[test]
fn secret_versions_are_immutable_and_rename_preserves_identity() {
    let (_directory, _path, _password, mut session) = initialized();
    let created = session
        .create_secret(
            "base",
            "OPENAI_API_KEY",
            Some("OpenAI credential"),
            SensitiveInput::copy_from_slice(b"phase-one-plaintext-sentinel"),
        )
        .expect("create secret");
    let renamed = session
        .rename_secret("base", "openai_api_key", "OPENAI_PRIMARY_KEY")
        .expect("rename secret");
    assert_eq!(renamed.id, created.id);
    assert_eq!(renamed.current_version, 1);
    let updated = session
        .update_secret(
            "base",
            "openai_primary_key",
            Some("Primary OpenAI credential"),
        )
        .expect("update secret");
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.current_version, 1);
    assert_eq!(
        session
            .secret("base", "openai_primary_key")
            .expect("show secret"),
        updated
    );
    let second = session
        .set_secret_value(
            "base",
            "openai_primary_key",
            SensitiveInput::copy_from_slice(b"phase-one-second-sentinel"),
        )
        .expect("set value");
    assert_eq!(second.version, 2);
    let versions = session
        .secret_versions("base", "openai_primary_key")
        .expect("versions");
    assert_eq!(versions.len(), 2);
    assert_ne!(versions[0].id, versions[1].id);
    let record = session
        .secret_by_ref("base", "openai_primary_key", false)
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
            "base",
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
    let versions = session
        .secret_versions("base", "session_token")
        .expect("versions");
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
            "base",
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
            "base",
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
            "base",
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

#[test]
fn scope_override_tombstone_and_profile_binding_are_deterministic() {
    let (_directory, _path, _password, mut session) = initialized();
    session
        .create_secret(
            "base",
            "SHARED_TOKEN",
            Some("root value"),
            SensitiveInput::copy_from_slice(b"root-secret"),
        )
        .expect("root secret");
    let profile = session
        .create_profile("Development", Some("Development profile"))
        .expect("profile");
    let environment_before = std::env::vars_os().collect::<BTreeMap<_, _>>();
    let binding = session.bind_profile("development").expect("bind");
    let environment_after = std::env::vars_os().collect::<BTreeMap<_, _>>();
    assert_eq!(environment_before, environment_after);
    assert_eq!(binding.profile_id, profile.id);
    assert_eq!(binding.scope_id, profile.scope_id);

    let inherited = session
        .resolve_secret(profile.scope_id, "shared_token")
        .expect("inherited");
    assert_eq!(inherited.source_scope_id, session.root_scope_id());
    session
        .create_secret_in_scope(
            profile.scope_id,
            "SHARED_TOKEN",
            Some("profile override"),
            SensitiveInput::copy_from_slice(b"profile-secret"),
        )
        .expect("override");
    let overridden = session
        .resolve_secret(profile.scope_id, "shared_token")
        .expect("overridden");
    assert_eq!(overridden.source_scope_id, profile.scope_id);
    assert_eq!(
        overridden.secret.description.as_deref(),
        Some("profile override")
    );

    let tombstone = session
        .tombstone_secret(profile.scope_id, "SHARED_TOKEN")
        .expect("tombstone");
    assert_eq!(tombstone.status, SecretStatus::Tombstone);
    assert!(matches!(
        session.resolve_secret(profile.scope_id, "shared_token"),
        Err(ServiceError::NotFound)
    ));
    session.integrity_check().expect("integrity");
}

#[test]
fn nested_scope_cycles_fail_unlock_closed() {
    let (_directory, path, password, mut session) = initialized();
    let workspace = session
        .create_scope(session.root_scope_id(), ScopeKind::Workspace, "workspace")
        .expect("workspace");
    let project = session
        .create_scope(workspace.id, ScopeKind::Project, "project")
        .expect("project");
    drop(session);
    let connection = rusqlite::Connection::open(&path).expect("open database");
    connection
        .execute(
            "UPDATE scope SET parent_id = ?1 WHERE id = ?2",
            rusqlite::params![project.id.0.as_bytes(), workspace.id.0.as_bytes()],
        )
        .expect("create cycle");
    drop(connection);
    assert!(matches!(
        VaultSession::unlock(&path, &password),
        Err(ServiceError::Corrupt)
    ));
}

#[test]
fn profile_scope_rebinding_fails_unlock_closed() {
    let (_directory, path, password, mut session) = initialized();
    let profile = session.create_profile("protected", None).expect("profile");
    let workspace = session
        .create_scope(session.root_scope_id(), ScopeKind::Workspace, "workspace")
        .expect("workspace");
    drop(session);
    let connection = rusqlite::Connection::open(&path).expect("open database");
    connection
        .execute(
            "UPDATE profile SET scope_id = ?1 WHERE id = ?2",
            rusqlite::params![workspace.id.0.as_bytes(), profile.id.0.as_bytes()],
        )
        .expect("rebind profile");
    drop(connection);
    assert!(matches!(
        VaultSession::unlock(&path, &password),
        Err(ServiceError::Corrupt)
    ));
}

#[test]
fn scope_depth_is_bounded_at_sixty_four_nodes() {
    let (_directory, _path, _password, mut session) = initialized();
    let mut parent = session.root_scope_id();
    for depth in 1..envault_core::MAX_SCOPE_DEPTH {
        parent = session
            .create_scope(parent, ScopeKind::Project, &format!("level-{depth}"))
            .expect("scope within depth limit")
            .id;
    }
    assert!(matches!(
        session.create_scope(parent, ScopeKind::Project, "too-deep"),
        Err(ServiceError::Invariant(
            envault_core::InvariantError::InvalidScopeChain
        ))
    ));
}

#[test]
fn http_preparation_authorizes_exact_secret_without_exposing_credential() {
    let (_directory, _path, _password, mut session) = initialized();
    session
        .create_secret(
            "base",
            "HTTP_TOKEN",
            None,
            SensitiveInput::copy_from_slice(b"broker-token-1234"),
        )
        .expect("secret");
    session
        .set_secret_http_access(
            "base",
            "HTTP_TOKEN",
            HttpConstraint {
                host: "api.example.com".into(),
                port: 443,
                methods: vec![HttpMethod::Get],
                path_prefix: "/v1".into(),
                max_request_bytes: 1024,
                max_response_bytes: 4096,
            },
        )
        .expect("configure http access");
    let prepared = session
        .prepare_http_request(
            "base",
            "HTTP_TOKEN",
            HttpRequest {
                url: "https://api.example.com/v1/status".into(),
                method: HttpMethod::Get,
                body: Vec::new(),
                content_type: None,
            },
        )
        .expect("prepare request");
    let debug = format!("{prepared:?}");
    assert_eq!(debug, "AgentHttpRequest([REDACTED])");
    assert!(!debug.contains("broker-token-1234"));
}
