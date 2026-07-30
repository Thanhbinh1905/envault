#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use envault_core::{
    EntityKind, GeneratorSpec, InvariantError, ProfileId, ProfileSummary, ProfileView, ScopeId,
    ScopeKind, SecretId, SecretStatus, SecretVersionId, SecretVersionView, SecretView, VaultId,
    normalize_name, validate_startup_profile,
};
use envault_crypto::{
    Ciphertext, CryptoError, KdfParameters, SALT_BYTES, SecretBytes, SecretKey, decrypt,
    derive_key, encrypt, lookup_digest, random_array, unwrap_key, wrap_key,
};
use envault_store::{
    ProfileRecord, ScopeRecord, SecretRecord, SecretVersionRecord, Store, StoreError, VaultRecord,
};
use thiserror::Error;
use uuid::Uuid;

mod internal;
mod scope_policy;

use internal::{
    GeneratorMetadata, decode_cbor, encode_cbor, encrypt_text, generate_value, generator_code,
    map_store_initialization, metadata_aad, publish_no_replace, remove_database_artifacts,
    remove_sidecars, secret_value_aad, secret_wrap_aad, unix_seconds,
    validate_optional_description, version_view, vmk_aad,
};

const FORMAT_VERSION: u32 = 1;
const ALGORITHM_VERSION: &[u8] = b"xchacha20poly1305-v1";
const PROFILE_LOOKUP_DOMAIN: &str = "envault profile lookup v1";
const SCOPE_LOOKUP_DOMAIN: &str = "envault scope lookup v1";
const SECRET_LOOKUP_DOMAIN: &str = "envault secret lookup v1";

pub struct SensitiveInput(SecretBytes);

impl SensitiveInput {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBytes::new(bytes))
    }

    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self(SecretBytes::copy_from_slice(bytes))
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }

    fn secret(&self) -> &SecretBytes {
        &self.0
    }

    fn into_secret(self) -> SecretBytes {
        self.0
    }
}

impl core::fmt::Debug for SensitiveInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SensitiveInput([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Initialization {
    pub vault_id: VaultId,
    pub root_scope_id: ScopeId,
    pub base_profile_id: ProfileId,
    pub kdf_parameters: KdfParameters,
}

pub struct VaultSession {
    store: Store,
    vault_id: VaultId,
    root_scope_id: ScopeId,
    master_key: SecretKey,
    database_path: PathBuf,
}

impl core::fmt::Debug for VaultSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VaultSession")
            .field("vault_id", &self.vault_id)
            .field("root_scope_id", &self.root_scope_id)
            .field("master_key", &"[REDACTED]")
            .field("database_path", &self.database_path)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("vault is not initialized")]
    NotInitialized,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("master password must contain between 12 and 4096 bytes")]
    InvalidPasswordLength,
    #[error("resource already exists")]
    Conflict,
    #[error("resource was not found")]
    NotFound,
    #[error("the startup profile cannot be deleted")]
    StartupProfileRequired,
    #[error("vault data is corrupt")]
    Corrupt,
    #[error("path has no parent directory")]
    InvalidPath,
    #[error("encrypted text is not valid UTF-8")]
    InvalidUtf8,
    #[error("system time is unavailable")]
    Time,
    #[error("serialization failed")]
    Serialization,
    #[error(transparent)]
    Invariant(#[from] InvariantError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Platform(#[from] envault_platform::PlatformError),
    #[error(transparent)]
    Policy(#[from] envault_policy::PolicyError),
    #[error("filesystem operation failed")]
    Io(#[from] std::io::Error),
}

fn initialize_with_parameters(
    database_path: &Path,
    password: &SensitiveInput,
    kdf_parameters: KdfParameters,
) -> Result<Initialization, ServiceError> {
    if database_path.exists() {
        return Err(ServiceError::AlreadyInitialized);
    }
    let parent = database_path.parent().ok_or(ServiceError::InvalidPath)?;
    envault_platform::create_private_directory(parent)?;
    let temporary_path = parent.join(format!(".envault-init-{}.db", Uuid::new_v4()));
    let result = initialize_temporary(&temporary_path, password.secret(), kdf_parameters);
    match result {
        Ok(initialization) => {
            if let Err(error) = publish_no_replace(&temporary_path, database_path) {
                remove_database_artifacts(&temporary_path);
                return Err(error);
            }
            Ok(initialization)
        }
        Err(error) => {
            remove_database_artifacts(&temporary_path);
            Err(error)
        }
    }
}

pub fn initialize_with_recommended_kdf(
    database_path: &Path,
    password: &SensitiveInput,
) -> Result<Initialization, ServiceError> {
    if database_path.exists() {
        return Err(ServiceError::AlreadyInitialized);
    }
    if password.len() < 12 || password.len() > 4096 {
        return Err(ServiceError::InvalidPasswordLength);
    }
    let parameters = KdfParameters::benchmark(std::time::Duration::from_millis(250))?;
    initialize_with_parameters(database_path, password, parameters)
}

fn initialize_temporary(
    database_path: &Path,
    password: &SecretBytes,
    kdf_parameters: KdfParameters,
) -> Result<Initialization, ServiceError> {
    let vault_id = VaultId(Uuid::new_v4());
    let root_scope_id = ScopeId(Uuid::new_v4());
    let base_profile_id = ProfileId(Uuid::new_v4());
    let salt = random_array::<SALT_BYTES>()?;
    let kek = derive_key(password.as_ref(), &salt, kdf_parameters)?;
    let master_key = SecretKey::generate()?;
    let wrapped_master_key = wrap_key(&kek, &master_key, &vmk_aad(vault_id))?.encode();
    let kdf_parameters_encoded = encode_cbor(&kdf_parameters)?;
    let root_path = "user";
    let base_name = "base";
    let vault = VaultRecord {
        id: vault_id,
        format_version: FORMAT_VERSION,
        wrapped_master_key,
        kdf_parameters: kdf_parameters_encoded,
        kdf_salt: salt.to_vec(),
        created_at: unix_seconds()?,
    };
    let root_scope = ScopeRecord {
        id: root_scope_id,
        vault_id,
        parent_id: None,
        kind: 0,
        encrypted_path: encrypt_text(
            &master_key,
            vault_id,
            EntityKind::Scope,
            root_scope_id.0,
            "path",
            root_path,
        )?,
        path_lookup: lookup_digest(&master_key, SCOPE_LOOKUP_DOMAIN, root_path.as_bytes()).to_vec(),
    };
    let base_profile = ProfileRecord {
        id: base_profile_id,
        vault_id,
        scope_id: root_scope_id,
        encrypted_name: encrypt_text(
            &master_key,
            vault_id,
            EntityKind::Profile,
            base_profile_id.0,
            "name",
            base_name,
        )?,
        name_lookup: lookup_digest(&master_key, PROFILE_LOOKUP_DOMAIN, base_name.as_bytes())
            .to_vec(),
        encrypted_description: None,
        activate_on_start: true,
        generation: 1,
    };
    drop(envault_platform::create_private_file(database_path)?);
    let mut store = Store::open(database_path)?;
    envault_platform::set_private_file_permissions(database_path)?;
    store.initialize(&vault, &root_scope, &base_profile)?;
    store.initialize_audit_state(scope_policy::audit_state_mac(&master_key, 0, &[0; 32]))?;
    store.integrity_check()?;
    store.checkpoint()?;
    drop(store);
    remove_sidecars(database_path);
    Ok(Initialization {
        vault_id,
        root_scope_id,
        base_profile_id,
        kdf_parameters,
    })
}

impl VaultSession {
    pub fn unlock(database_path: &Path, password: &SensitiveInput) -> Result<Self, ServiceError> {
        if !database_path.exists() {
            return Err(ServiceError::NotInitialized);
        }
        envault_platform::set_private_file_permissions(database_path)?;
        let mut store = Store::open(database_path)?;
        let vault = store.vault().map_err(map_store_initialization)?;
        let parameters: KdfParameters = decode_cbor(&vault.kdf_parameters)?;
        let salt: [u8; SALT_BYTES] = vault
            .kdf_salt
            .as_slice()
            .try_into()
            .map_err(|_| ServiceError::Corrupt)?;
        let kek = derive_key(password.secret().as_ref(), &salt, parameters)?;
        let wrapped = Ciphertext::decode(&vault.wrapped_master_key)?;
        let master_key = unwrap_key(&kek, &wrapped, &vmk_aad(vault.id))
            .map_err(|_| ServiceError::AuthenticationFailed)?;
        store.initialize_audit_state(scope_policy::audit_state_mac(&master_key, 0, &[0; 32]))?;
        let root_scope = store.root_scope().map_err(|_| ServiceError::Corrupt)?;
        let profiles = store.profiles()?;
        let summaries = profiles
            .iter()
            .map(|profile| ProfileSummary {
                id: profile.id,
                encrypted_name: profile.encrypted_name.clone(),
                activate_on_start: profile.activate_on_start,
                generation: profile.generation,
            })
            .collect::<Vec<_>>();
        validate_startup_profile(&summaries).map_err(|_| ServiceError::Corrupt)?;
        let session = Self {
            store,
            vault_id: vault.id,
            root_scope_id: root_scope.id,
            master_key,
            database_path: database_path.to_path_buf(),
        };
        session.store.integrity_check()?;
        session
            .validate_encrypted_metadata()
            .map_err(|_| ServiceError::Corrupt)?;
        Ok(session)
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn root_scope_id(&self) -> ScopeId {
        self.root_scope_id
    }

    pub fn create_profile(
        &mut self,
        name: &str,
        description: Option<&str>,
    ) -> Result<ProfileView, ServiceError> {
        let normalized = normalize_name(name)?;
        validate_optional_description(description)?;
        let lookup = lookup_digest(
            &self.master_key,
            PROFILE_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        if self
            .store
            .profile_by_lookup(self.vault_id, &lookup)?
            .is_some()
        {
            return Err(ServiceError::Conflict);
        }
        let id = ProfileId(Uuid::new_v4());
        let scope_id = ScopeId(Uuid::new_v4());
        let root = self.store.root_scope()?;
        let root_path =
            self.decrypt_entity_text(EntityKind::Scope, root.id.0, "path", &root.encrypted_path)?;
        let scope_path = format!("{root_path}/profile/{}", scope_id.0);
        let scope = ScopeRecord {
            id: scope_id,
            vault_id: self.vault_id,
            parent_id: Some(self.root_scope_id),
            kind: scope_policy::scope_kind_code(ScopeKind::Profile),
            encrypted_path: self.encrypt_entity_text(
                EntityKind::Scope,
                scope_id.0,
                "path",
                &scope_path,
            )?,
            path_lookup: lookup_digest(
                &self.master_key,
                SCOPE_LOOKUP_DOMAIN,
                scope_path.as_bytes(),
            )
            .to_vec(),
        };
        let record = ProfileRecord {
            id,
            vault_id: self.vault_id,
            scope_id,
            encrypted_name: self.encrypt_entity_text(
                EntityKind::Profile,
                id.0,
                "name",
                name.trim(),
            )?,
            name_lookup: lookup.to_vec(),
            encrypted_description: self.encrypt_optional_entity_text(
                EntityKind::Profile,
                id.0,
                "description",
                description,
            )?,
            activate_on_start: false,
            generation: 1,
        };
        self.store.insert_scope_with_profile(&scope, &record)?;
        self.profile_view(&record)
    }

    pub fn profiles(&self) -> Result<Vec<ProfileView>, ServiceError> {
        self.store
            .profiles()?
            .iter()
            .map(|record| self.profile_view(record))
            .collect()
    }

    pub fn profile(&self, name: &str) -> Result<ProfileView, ServiceError> {
        let record = self.profile_by_name(name)?;
        self.profile_view(&record)
    }

    pub fn update_profile(
        &mut self,
        name: &str,
        description: Option<&str>,
    ) -> Result<ProfileView, ServiceError> {
        validate_optional_description(description)?;
        let mut record = self.profile_by_name(name)?;
        record.encrypted_description = self.encrypt_optional_entity_text(
            EntityKind::Profile,
            record.id.0,
            "description",
            description,
        )?;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(ServiceError::Corrupt)?;
        self.store.update_profile_metadata(&record)?;
        self.profile_view(&record)
    }

    pub fn rename_profile(
        &mut self,
        old_name: &str,
        new_name: &str,
    ) -> Result<ProfileView, ServiceError> {
        let mut record = self.profile_by_name(old_name)?;
        let normalized = normalize_name(new_name)?;
        let lookup = lookup_digest(
            &self.master_key,
            PROFILE_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        if self
            .store
            .profile_by_lookup(self.vault_id, &lookup)?
            .is_some_and(|existing| existing.id != record.id)
        {
            return Err(ServiceError::Conflict);
        }
        record.encrypted_name =
            self.encrypt_entity_text(EntityKind::Profile, record.id.0, "name", new_name.trim())?;
        record.name_lookup = lookup.to_vec();
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(ServiceError::Corrupt)?;
        self.store.update_profile_metadata(&record)?;
        self.profile_view(&record)
    }

    pub fn activate_profile(&mut self, name: &str) -> Result<ProfileView, ServiceError> {
        let record = self.profile_by_name(name)?;
        if record.activate_on_start {
            return self.profile_view(&record);
        }
        self.store.set_startup_profile(record.id)?;
        self.profile_by_name(name)
            .and_then(|updated| self.profile_view(&updated))
    }

    pub fn delete_profile(&mut self, name: &str) -> Result<(), ServiceError> {
        let record = self.profile_by_name(name)?;
        if record.activate_on_start {
            return Err(ServiceError::StartupProfileRequired);
        }
        if self.policy_rules()?.iter().any(|rule| {
            matches!(
                rule.resource,
                envault_policy::ResourceSelector::ScopeTree(scope_id)
                    if scope_id == record.scope_id
            )
        }) {
            return Err(ServiceError::Conflict);
        }
        if record.scope_id == self.root_scope_id {
            self.store.delete_profile(record.id)?;
        } else {
            self.store
                .delete_profile_and_scope(record.id, record.scope_id)?;
        }
        Ok(())
    }

    pub fn create_secret(
        &mut self,
        name: &str,
        description: Option<&str>,
        value: SensitiveInput,
    ) -> Result<SecretView, ServiceError> {
        self.create_secret_inner(
            self.root_scope_id,
            name,
            description,
            value.into_secret(),
            None,
        )
    }

    pub fn create_generated_secret(
        &mut self,
        name: &str,
        description: Option<&str>,
        spec: GeneratorSpec,
    ) -> Result<SecretView, ServiceError> {
        let generated = generate_value(spec)?;
        self.create_secret_inner(
            self.root_scope_id,
            name,
            description,
            generated.value,
            Some(generated.metadata),
        )
    }

    pub fn secrets(&self) -> Result<Vec<SecretView>, ServiceError> {
        self.store
            .secrets()?
            .iter()
            .map(|record| self.secret_view(record))
            .collect()
    }

    pub fn secret(&self, name: &str) -> Result<SecretView, ServiceError> {
        let record = self.secret_by_name(name)?;
        self.secret_view(&record)
    }

    pub fn update_secret(
        &mut self,
        name: &str,
        description: Option<&str>,
    ) -> Result<SecretView, ServiceError> {
        validate_optional_description(description)?;
        let mut record = self.secret_by_name(name)?;
        if record.status != 0 {
            return Err(ServiceError::Conflict);
        }
        record.encrypted_description = self.encrypt_optional_entity_text(
            EntityKind::Secret,
            record.id.0,
            "description",
            description,
        )?;
        self.store.update_secret_metadata(&record)?;
        self.secret_view(&record)
    }

    pub fn rename_secret(
        &mut self,
        old_name: &str,
        new_name: &str,
    ) -> Result<SecretView, ServiceError> {
        let mut record = self.secret_by_name(old_name)?;
        let normalized = normalize_name(new_name)?;
        let lookup = lookup_digest(
            &self.master_key,
            SECRET_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        if self
            .store
            .secret_by_lookup(self.root_scope_id, &lookup)?
            .is_some_and(|existing| existing.id != record.id)
        {
            return Err(ServiceError::Conflict);
        }
        record.encrypted_name =
            self.encrypt_entity_text(EntityKind::Secret, record.id.0, "name", new_name.trim())?;
        record.name_lookup = lookup.to_vec();
        self.store.update_secret_metadata(&record)?;
        self.secret_view(&record)
    }

    pub fn set_secret_value(
        &mut self,
        name: &str,
        value: SensitiveInput,
    ) -> Result<SecretVersionView, ServiceError> {
        let record = self.secret_by_name(name)?;
        self.add_secret_version(&record, value.into_secret(), None)
    }

    pub fn generate_secret_value(
        &mut self,
        name: &str,
        spec: GeneratorSpec,
    ) -> Result<SecretVersionView, ServiceError> {
        let record = self.secret_by_name(name)?;
        let generated = generate_value(spec)?;
        self.add_secret_version(&record, generated.value, Some(generated.metadata))
    }

    pub fn secret_versions(&self, name: &str) -> Result<Vec<SecretVersionView>, ServiceError> {
        let secret = self.secret_by_name(name)?;
        self.store
            .secret_versions(secret.id)?
            .iter()
            .map(version_view)
            .collect()
    }

    pub fn delete_secret(&mut self, name: &str) -> Result<(), ServiceError> {
        let record = self.secret_by_name(name)?;
        self.store.delete_secret(record.id)?;
        Ok(())
    }

    pub fn backup(&self, destination: &Path) -> Result<(), ServiceError> {
        if destination.exists() {
            return Err(ServiceError::Conflict);
        }
        let parent = destination.parent().ok_or(ServiceError::InvalidPath)?;
        envault_platform::create_private_directory(parent)?;
        let temporary = parent.join(format!(".envault-backup-{}.db", Uuid::new_v4()));
        drop(envault_platform::create_private_file(&temporary)?);
        self.store.checkpoint()?;
        if let Err(error) = self.store.backup(&temporary) {
            remove_database_artifacts(&temporary);
            return Err(ServiceError::Store(error));
        }
        if let Err(error) = publish_no_replace(&temporary, destination) {
            remove_database_artifacts(&temporary);
            return Err(error);
        }
        Ok(())
    }

    pub fn integrity_check(&self) -> Result<(), ServiceError> {
        self.store.integrity_check()?;
        self.validate_encrypted_metadata()
            .map_err(|_| ServiceError::Corrupt)?;
        for secret in self.store.secrets()? {
            let versions = self.store.secret_versions(secret.id)?;
            if (secret.status == 0 && secret.current_version == 0)
                || (secret.status == 1 && secret.current_version != 0)
                || secret.status > 1
            {
                return Err(ServiceError::Corrupt);
            }
            if usize::try_from(secret.current_version).ok() != Some(versions.len()) {
                return Err(ServiceError::Corrupt);
            }
            for (index, version) in versions.iter().enumerate() {
                let expected_version = u64::try_from(index)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ServiceError::Corrupt)?;
                if version.secret_id != secret.id || version.version != expected_version {
                    return Err(ServiceError::Corrupt);
                }
                let view = version_view(version).map_err(|_| ServiceError::Corrupt)?;
                match view.generator {
                    Some(_) if view.generated_length.is_some() && view.entropy_bits.is_some() => {}
                    None if view.generated_length.is_none() && view.entropy_bits.is_none() => {}
                    _ => return Err(ServiceError::Corrupt),
                }
                drop(
                    self.decrypt_secret_version(&secret, version)
                        .map_err(|_| ServiceError::Corrupt)?,
                );
            }
        }
        self.verify_audit_chain()?;
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<(), ServiceError> {
        self.store.checkpoint()?;
        Ok(())
    }

    fn create_secret_inner(
        &mut self,
        scope_id: ScopeId,
        name: &str,
        description: Option<&str>,
        value: SecretBytes,
        generator: Option<GeneratorMetadata>,
    ) -> Result<SecretView, ServiceError> {
        let normalized = normalize_name(name)?;
        validate_optional_description(description)?;
        let lookup = lookup_digest(
            &self.master_key,
            SECRET_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        if self.store.secret_by_lookup(scope_id, &lookup)?.is_some() {
            return Err(ServiceError::Conflict);
        }
        let id = SecretId(Uuid::new_v4());
        let secret = SecretRecord {
            id,
            scope_id,
            encrypted_name: self.encrypt_entity_text(
                EntityKind::Secret,
                id.0,
                "name",
                name.trim(),
            )?,
            name_lookup: lookup.to_vec(),
            encrypted_description: self.encrypt_optional_entity_text(
                EntityKind::Secret,
                id.0,
                "description",
                description,
            )?,
            current_version: 1,
            status: 0,
        };
        let version = self.encrypt_secret_version(&secret, 1, value, generator)?;
        self.store.insert_secret_with_version(&secret, &version)?;
        self.secret_view(&secret)
    }

    fn add_secret_version(
        &mut self,
        secret: &SecretRecord,
        value: SecretBytes,
        generator: Option<GeneratorMetadata>,
    ) -> Result<SecretVersionView, ServiceError> {
        if secret.status != 0 || secret.current_version == 0 {
            return Err(ServiceError::Conflict);
        }
        let next_version = secret
            .current_version
            .checked_add(1)
            .ok_or(ServiceError::Corrupt)?;
        let record = self.encrypt_secret_version(secret, next_version, value, generator)?;
        self.store
            .insert_secret_version(secret.id, secret.current_version, &record)?;
        version_view(&record)
    }

    fn encrypt_secret_version(
        &self,
        secret: &SecretRecord,
        version: u64,
        value: SecretBytes,
        generator: Option<GeneratorMetadata>,
    ) -> Result<SecretVersionRecord, ServiceError> {
        let id = SecretVersionId(Uuid::new_v4());
        let aad = secret_value_aad(self.vault_id, secret.id, id, secret.scope_id, version);
        let wrap_aad = secret_wrap_aad(self.vault_id, secret.id, id, secret.scope_id, version);
        let dek = SecretKey::generate()?;
        let ciphertext = encrypt(&dek, value.as_ref(), &aad)?.encode();
        drop(value);
        let wrapped_dek = wrap_key(&self.master_key, &dek, &wrap_aad)?.encode();
        Ok(SecretVersionRecord {
            id,
            secret_id: secret.id,
            version,
            ciphertext,
            wrapped_dek,
            aad_digest: blake3::hash(&aad).as_bytes().to_vec(),
            generator: generator.map(|metadata| generator_code(metadata.format)),
            generated_length: generator.map(|metadata| metadata.length as u64),
            entropy_bits: generator.map(|metadata| metadata.entropy_bits),
            created_at: unix_seconds()?,
        })
    }

    fn decrypt_secret_version(
        &self,
        secret: &SecretRecord,
        version: &SecretVersionRecord,
    ) -> Result<SecretBytes, ServiceError> {
        let aad = secret_value_aad(
            self.vault_id,
            secret.id,
            version.id,
            secret.scope_id,
            version.version,
        );
        if blake3::hash(&aad).as_bytes() != version.aad_digest.as_slice() {
            return Err(ServiceError::Corrupt);
        }
        let wrap_aad = secret_wrap_aad(
            self.vault_id,
            secret.id,
            version.id,
            secret.scope_id,
            version.version,
        );
        let dek = unwrap_key(
            &self.master_key,
            &Ciphertext::decode(&version.wrapped_dek)?,
            &wrap_aad,
        )?;
        decrypt(&dek, &Ciphertext::decode(&version.ciphertext)?, &aad).map_err(ServiceError::from)
    }

    fn profile_by_name(&self, name: &str) -> Result<ProfileRecord, ServiceError> {
        let normalized = normalize_name(name)?;
        let lookup = lookup_digest(
            &self.master_key,
            PROFILE_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        self.store
            .profile_by_lookup(self.vault_id, &lookup)?
            .ok_or(ServiceError::NotFound)
    }

    fn validate_encrypted_metadata(&self) -> Result<(), ServiceError> {
        self.validate_root_scope()?;
        self.validate_scopes()?;
        self.validate_profiles()?;
        self.validate_secrets()?;
        self.validate_principals()?;
        self.validate_policy_rules()?;
        self.audit_events()?;
        self.verify_audit_chain()?;
        Ok(())
    }

    fn validate_root_scope(&self) -> Result<(), ServiceError> {
        let root = self.store.root_scope()?;
        if root.vault_id != self.vault_id || root.parent_id.is_some() || root.kind != 0 {
            return Err(ServiceError::Corrupt);
        }
        let root_path = self
            .decrypt_entity_text(EntityKind::Scope, root.id.0, "path", &root.encrypted_path)
            .map_err(|_| ServiceError::Corrupt)?;
        if root_path != "user"
            || root.path_lookup
                != lookup_digest(&self.master_key, SCOPE_LOOKUP_DOMAIN, root_path.as_bytes())
                    .as_slice()
        {
            return Err(ServiceError::Corrupt);
        }
        Ok(())
    }

    fn validate_scopes(&self) -> Result<(), ServiceError> {
        for scope in self.store.scopes()? {
            if scope.vault_id != self.vault_id
                || (scope.id != self.root_scope_id && scope.parent_id.is_none())
                || (scope.id == self.root_scope_id && scope.kind != 0)
                || (scope.id != self.root_scope_id && scope.kind == 0)
            {
                return Err(ServiceError::Corrupt);
            }
            let path = self.decrypt_entity_text(
                EntityKind::Scope,
                scope.id.0,
                "path",
                &scope.encrypted_path,
            )?;
            if scope.path_lookup
                != lookup_digest(&self.master_key, SCOPE_LOOKUP_DOMAIN, path.as_bytes()).as_slice()
            {
                return Err(ServiceError::Corrupt);
            }
            self.scope_chain(scope.id)?;
        }
        Ok(())
    }

    fn validate_profiles(&self) -> Result<(), ServiceError> {
        for record in self.store.profiles()? {
            if record.vault_id != self.vault_id
                || self.store.scope_by_id(record.scope_id)?.is_none()
            {
                return Err(ServiceError::Corrupt);
            }
            let view = self.profile_view(&record)?;
            validate_optional_description(view.description.as_deref())?;
            let normalized = normalize_name(&view.name)?;
            if record.name_lookup
                != lookup_digest(
                    &self.master_key,
                    PROFILE_LOOKUP_DOMAIN,
                    normalized.as_bytes(),
                )
                .as_slice()
            {
                return Err(ServiceError::Corrupt);
            }
        }
        Ok(())
    }

    fn validate_secrets(&self) -> Result<(), ServiceError> {
        for record in self.store.secrets()? {
            if self.store.scope_by_id(record.scope_id)?.is_none()
                || (record.status == 0 && record.current_version == 0)
                || (record.status == 1 && record.current_version != 0)
                || record.status > 1
            {
                return Err(ServiceError::Corrupt);
            }
            let view = self.secret_view(&record)?;
            validate_optional_description(view.description.as_deref())?;
            let normalized = normalize_name(&view.name)?;
            if record.name_lookup
                != lookup_digest(
                    &self.master_key,
                    SECRET_LOOKUP_DOMAIN,
                    normalized.as_bytes(),
                )
                .as_slice()
            {
                return Err(ServiceError::Corrupt);
            }
        }
        Ok(())
    }

    fn validate_principals(&self) -> Result<(), ServiceError> {
        for record in self.store.principals()? {
            if record.vault_id != self.vault_id {
                return Err(ServiceError::Corrupt);
            }
            let view = self.principal_view(&record)?;
            let normalized = normalize_name(&view.name)?;
            if record.name_lookup
                != lookup_digest(
                    &self.master_key,
                    scope_policy::PRINCIPAL_LOOKUP_DOMAIN,
                    normalized.as_bytes(),
                )
                .as_slice()
            {
                return Err(ServiceError::Corrupt);
            }
        }
        Ok(())
    }

    fn validate_policy_rules(&self) -> Result<(), ServiceError> {
        for record in self.store.policy_rules()? {
            if record.vault_id != self.vault_id
                || self.store.principal_by_id(record.principal_id)?.is_none()
            {
                return Err(ServiceError::Corrupt);
            }
            let rule = scope_policy::policy_rule(&record)?;
            self.validate_resource(rule.resource)?;
        }
        Ok(())
    }

    fn secret_by_name(&self, name: &str) -> Result<SecretRecord, ServiceError> {
        let normalized = normalize_name(name)?;
        let lookup = lookup_digest(
            &self.master_key,
            SECRET_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        self.store
            .secret_by_lookup(self.root_scope_id, &lookup)?
            .ok_or(ServiceError::NotFound)
    }

    fn profile_view(&self, record: &ProfileRecord) -> Result<ProfileView, ServiceError> {
        Ok(ProfileView {
            id: record.id,
            scope_id: record.scope_id,
            name: self.decrypt_entity_text(
                EntityKind::Profile,
                record.id.0,
                "name",
                &record.encrypted_name,
            )?,
            description: self.decrypt_optional_entity_text(
                EntityKind::Profile,
                record.id.0,
                "description",
                record.encrypted_description.as_deref(),
            )?,
            activate_on_start: record.activate_on_start,
            generation: record.generation,
        })
    }

    fn secret_view(&self, record: &SecretRecord) -> Result<SecretView, ServiceError> {
        Ok(SecretView {
            id: record.id,
            scope_id: record.scope_id,
            name: self.decrypt_entity_text(
                EntityKind::Secret,
                record.id.0,
                "name",
                &record.encrypted_name,
            )?,
            description: self.decrypt_optional_entity_text(
                EntityKind::Secret,
                record.id.0,
                "description",
                record.encrypted_description.as_deref(),
            )?,
            current_version: record.current_version,
            status: match record.status {
                0 => SecretStatus::Active,
                1 => SecretStatus::Tombstone,
                _ => return Err(ServiceError::Corrupt),
            },
        })
    }

    fn encrypt_entity_text(
        &self,
        kind: EntityKind,
        id: Uuid,
        field: &str,
        value: &str,
    ) -> Result<Vec<u8>, ServiceError> {
        encrypt_text(&self.master_key, self.vault_id, kind, id, field, value)
    }

    fn encrypt_optional_entity_text(
        &self,
        kind: EntityKind,
        id: Uuid,
        field: &str,
        value: Option<&str>,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        value
            .map(|text| self.encrypt_entity_text(kind, id, field, text))
            .transpose()
    }

    fn decrypt_entity_text(
        &self,
        kind: EntityKind,
        id: Uuid,
        field: &str,
        value: &[u8],
    ) -> Result<String, ServiceError> {
        let aad = metadata_aad(self.vault_id, kind, id, field);
        let plaintext = decrypt(&self.master_key, &Ciphertext::decode(value)?, &aad)?;
        String::from_utf8(plaintext.into_vec()).map_err(|_| ServiceError::InvalidUtf8)
    }

    fn decrypt_optional_entity_text(
        &self,
        kind: EntityKind,
        id: Uuid,
        field: &str,
        value: Option<&[u8]>,
    ) -> Result<Option<String>, ServiceError> {
        value
            .map(|bytes| self.decrypt_entity_text(kind, id, field, bytes))
            .transpose()
    }
}

#[cfg(test)]
mod tests;
