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
            loaded: true,
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
        .update_profile("engineering", Some("Rotated developer credentials"), None)
        .expect("update profile");
    assert_eq!(updated.id, created.id);
    assert_eq!(
        session.profile("engineering").expect("show profile"),
        updated
    );
    assert_eq!(updated.generation, 3);
    let loaded = session.load_profile("engineering").expect("load");
    assert!(loaded.loaded);
    assert!(!loaded.activate_on_start);
    assert!(matches!(
        session.delete_profile("base"),
        Err(ServiceError::Conflict)
    ));
    assert!(matches!(
        session.unload_profile("base"),
        Err(ServiceError::StartupProfileRequired)
    ));

    // Loading a profile is session-only and does not protect it from
    // deletion - only the persisted `activate_on_start` preference does,
    // set independently via `update_profile`.
    session
        .update_profile("engineering", None, Some(true))
        .expect("set activate_on_start");
    assert!(matches!(
        session.delete_profile("engineering"),
        Err(ServiceError::StartupProfileRequired)
    ));
    session
        .update_profile("engineering", None, Some(false))
        .expect("clear activate_on_start");

    let unloaded = session.unload_profile("engineering").expect("unload");
    assert!(!unloaded.loaded);
    session.delete_profile("engineering").expect("delete");
    assert_eq!(session.profiles().expect("profiles").len(), 1);
}

#[test]
fn loaded_set_is_session_only_and_reseeded_from_activate_on_start_on_unlock() {
    let (_directory, path, password, mut session) = initialized();
    session
        .create_profile("Personal", Some("Personal profile"))
        .expect("create profile");

    // Not yet loaded this session, regardless of `activate_on_start`.
    assert!(!session.profile("personal").expect("show").loaded);
    assert!(matches!(
        session.secrets_in_profile("personal"),
        Err(ServiceError::ProfileNotLoaded)
    ));

    // Loading is session-only: it does not persist `activate_on_start`.
    session.load_profile("personal").expect("load");
    assert!(session.profile("personal").expect("show").loaded);
    drop(session);
    let mut session = VaultSession::unlock(&path, &password).expect("unlock");
    assert!(!session.profile("personal").expect("show").loaded);

    // Flagging `activate_on_start` does persist: the next unlock reseeds
    // the loaded set from it without any explicit `load_profile` call.
    session
        .update_profile("personal", None, Some(true))
        .expect("set activate_on_start");
    drop(session);
    let session = VaultSession::unlock(&path, &password).expect("unlock");
    let personal = session.profile("personal").expect("show");
    assert!(personal.activate_on_start);
    assert!(personal.loaded);
    session.secrets_in_profile("personal").expect("resolve");
}

#[test]
fn update_profile_rejects_clearing_the_last_activate_on_start_profile() {
    let (_directory, _path, _password, mut session) = initialized();
    assert!(matches!(
        session.update_profile("base", None, Some(false)),
        Err(ServiceError::StartupProfileRequired)
    ));

    session
        .create_profile("Personal", Some("Personal profile"))
        .expect("create profile");
    session
        .update_profile("personal", None, Some(true))
        .expect("set activate_on_start");
    // `base` is the permanent underlay: it can never have
    // `activate_on_start` cleared, even when another profile is active.
    assert!(matches!(
        session.update_profile("base", None, Some(false)),
        Err(ServiceError::StartupProfileRequired)
    ));

    session
        .update_profile("personal", None, Some(false))
        .expect("clear activate_on_start on a non-root profile");
}

#[test]
fn set_secret_value_overwrites_in_place_and_rename_preserves_identity() {
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
    let updated = session
        .update_secret(
            "base",
            "openai_primary_key",
            Some("Primary OpenAI credential"),
        )
        .expect("update secret");
    assert_eq!(updated.id, created.id);
    assert_eq!(
        session
            .secret("base", "openai_primary_key")
            .expect("show secret"),
        updated
    );
    let before_overwrite = session
        .secret_by_ref("base", "openai_primary_key", false)
        .expect("secret")
        .id;
    session
        .set_secret_value(
            "base",
            "openai_primary_key",
            SensitiveInput::copy_from_slice(b"phase-one-second-sentinel"),
        )
        .expect("set value");
    let record = session
        .secret_by_ref("base", "openai_primary_key", false)
        .expect("secret");
    assert_eq!(record.id, before_overwrite);
    assert_eq!(record.current_version, 2);
    assert_eq!(
        session
            .decrypt_secret_value(&record)
            .expect("current value")
            .as_ref(),
        b"phase-one-second-sentinel"
    );
}

#[test]
fn generators_return_only_redacted_metadata() {
    let (_directory, _path, _password, mut session) = initialized();
    session
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
    let record = session
        .secret_by_ref("base", "session_token", false)
        .expect("secret");
    assert_eq!(record.current_version, 1);
    let value = record.value.as_ref().expect("value");
    assert_eq!(value.generated_length, Some(64));
    assert_eq!(value.entropy_bits, Some(384));
    assert_eq!(value.generator, Some(2));
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
        .query_row("SELECT ciphertext FROM secret LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("ciphertext");
    let last = ciphertext.last_mut().expect("ciphertext byte");
    *last ^= 0x40;
    connection
        .execute(
            "UPDATE secret SET ciphertext = ?1",
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
    let outer = session
        .create_scope(session.root_scope_id(), ScopeKind::Project, "outer")
        .expect("outer project");
    let inner = session
        .create_scope(outer.id, ScopeKind::Project, "inner")
        .expect("inner project");
    drop(session);
    let connection = rusqlite::Connection::open(&path).expect("open database");
    connection
        .execute(
            "UPDATE scope SET parent_id = ?1 WHERE id = ?2",
            rusqlite::params![inner.id.0.as_bytes(), outer.id.0.as_bytes()],
        )
        .expect("create cycle");
    drop(connection);
    assert!(matches!(
        VaultSession::unlock(&path, &password),
        Err(ServiceError::Corrupt)
    ));
}

/// Workspace membership is a plain join table, entirely outside the
/// integrity checks `unlock` runs over the scope/profile tree - so a
/// membership row referencing a deleted profile does not, and should not,
/// fail unlock closed. Coverage for that corruption shape lives at the
/// store layer instead (`delete_profile_and_scope` cannot leave such a row
/// behind because `workspace_membership.profile_id` is a foreign key with
/// no `ON DELETE CASCADE`: deleting a profile that still has memberships
/// fails closed with `StoreError::Integrity`, exercised by
/// `deleting_profile_with_workspace_memberships_fails_closed` below).
#[test]
fn workspace_membership_spans_multiple_workspaces_and_survives_unbind() {
    let (_directory, _path, _password, mut session) = initialized();
    session.create_workspace("blue").expect("workspace blue");
    session.create_workspace("green").expect("workspace green");
    session
        .create_profile("alpha", None)
        .expect("profile alpha");
    session.create_profile("beta", None).expect("profile beta");

    session
        .bind_profile_to_workspace("blue", "alpha")
        .expect("bind alpha to blue");
    session
        .bind_profile_to_workspace("blue", "beta")
        .expect("bind beta to blue");
    session
        .bind_profile_to_workspace("green", "alpha")
        .expect("bind alpha to green");

    let mut blue_members = session
        .profiles_in_workspace("blue")
        .expect("blue members")
        .into_iter()
        .map(|profile| profile.name)
        .collect::<Vec<_>>();
    blue_members.sort();
    assert_eq!(blue_members, vec!["alpha".to_string(), "beta".to_string()]);

    let green_members = session
        .profiles_in_workspace("green")
        .expect("green members")
        .into_iter()
        .map(|profile| profile.name)
        .collect::<Vec<_>>();
    assert_eq!(green_members, vec!["alpha".to_string()]);

    let mut loaded = session
        .load_workspace("blue")
        .expect("load blue")
        .into_iter()
        .map(|profile| profile.name)
        .collect::<Vec<_>>();
    loaded.sort();
    assert_eq!(loaded, vec!["alpha".to_string(), "beta".to_string()]);

    session
        .unbind_profile_from_workspace("blue", "beta")
        .expect("unbind beta from blue");
    let blue_members = session
        .profiles_in_workspace("blue")
        .expect("blue members after unbind")
        .into_iter()
        .map(|profile| profile.name)
        .collect::<Vec<_>>();
    assert_eq!(blue_members, vec!["alpha".to_string()]);
    // `alpha` is still bound to `green` - unbinding from `blue` must not
    // touch its other memberships.
    assert_eq!(
        session
            .profiles_in_workspace("green")
            .expect("green members unaffected")
            .len(),
        1
    );
}

#[test]
fn deleting_profile_with_workspace_memberships_fails_closed() {
    let (_directory, _path, _password, mut session) = initialized();
    session.create_workspace("blue").expect("workspace blue");
    let profile = session
        .create_profile("alpha", None)
        .expect("profile alpha");
    session
        .bind_profile_to_workspace("blue", "alpha")
        .expect("bind alpha to blue");

    // The profile still has a workspace_membership row referencing it; the
    // store's foreign key (no ON DELETE CASCADE) must reject the delete
    // rather than silently orphaning or cascading it away.
    assert!(matches!(
        session.delete_profile("alpha"),
        Err(ServiceError::Store(_))
    ));

    session
        .unbind_profile_from_workspace("blue", "alpha")
        .expect("unbind alpha from blue");
    session.delete_profile("alpha").expect("delete now clean");
    assert!(matches!(
        session.profile("alpha"),
        Err(ServiceError::NotFound)
    ));
    let _ = profile;
}

#[test]
fn workspace_names_are_unique_and_deletion_requires_empty_membership() {
    let (_directory, _path, _password, mut session) = initialized();
    session.create_workspace("blue").expect("workspace blue");
    assert!(matches!(
        session.create_workspace("blue"),
        Err(ServiceError::Conflict)
    ));

    session
        .create_profile("alpha", None)
        .expect("profile alpha");
    session
        .bind_profile_to_workspace("blue", "alpha")
        .expect("bind alpha to blue");
    assert!(matches!(
        session.delete_workspace("blue"),
        Err(ServiceError::Store(_))
    ));

    session
        .unbind_profile_from_workspace("blue", "alpha")
        .expect("unbind alpha from blue");
    session.delete_workspace("blue").expect("delete workspace");
    assert!(matches!(
        session.workspace_by_name("blue"),
        Err(ServiceError::NotFound)
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
