use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
    str::FromStr,
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use envault_core::{
    ConfigMembershipEntryView, ConfigPreview, ConfigProfileEntryView, ConfigSecretEntryView,
    ConfigSelector, ConfigWorkspaceEntryView, EntityKind, EnvImportEntryView, EnvImportPreview,
    ImportAction, ImportConflictStrategy, ImportConflictView, MAX_CONFIG_FILE_BYTES,
    MAX_ENV_FILE_BYTES, MAX_ENV_LINE_BYTES, MAX_NAME_BYTES, MAX_PORTABILITY_ENTITIES,
    MAX_PORTABILITY_KEY_SLOTS, MAX_PORTABILITY_PACKAGE_BYTES, MAX_SECRET_VALUE_BYTES, PackageKind,
    PlaintextExportSummary, PortabilityCounts, PortabilityExportSummary, PortabilityImportSummary,
    PortabilityPreview, ProfileId, ProfileView, ScopeId, ScopeKind, SecretId, SecretVersionId,
    VaultId, WorkspaceId, WorkspaceView, normalize_name,
};
use envault_crypto::{
    Ciphertext, KEY_BYTES, KdfParameters, SALT_BYTES, SecretBytes, SecretKey, decrypt, derive_key,
    encrypt, lookup_digest, random_array, unwrap_key, wrap_key,
};
use envault_store::{
    ImportBatch, ImportReset, ProfileRecord, ScopeRecord, SecretRecord, SecretValueOverwrite,
    SecretValueRecord, WorkspaceRecord,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{
    ALGORITHM_VERSION, PROFILE_LOOKUP_DOMAIN, SCOPE_LOOKUP_DOMAIN, SECRET_LOOKUP_DOMAIN,
    SensitiveInput, ServiceError, VaultSession, internal::unix_seconds, scope_policy,
    secret_value_aad, secret_wrap_aad,
};

const PACKAGE_VERSION: u16 = 2;
const PACKAGE_MAGIC: &[u8] = b"ENVAULT-PORTABLE-CBOR";
const TRANSFER_PASSWORD_MIN_BYTES: usize = 12;
const TRANSFER_PASSWORD_MAX_BYTES: usize = 4096;
const TRANSFER_KDF_MIN_MEMORY_KIB: u32 = 8 * 1024;
const TRANSFER_KDF_MAX_MEMORY_KIB: u32 = 128 * 1024;
const TRANSFER_KDF_MAX_ITERATIONS: u32 = 6;
const TRANSFER_KDF_MAX_PARALLELISM: u32 = 4;
const MAX_AGE_SLOT_BYTES: usize = 64 * 1024;
const PLAN_HASH_DOMAIN: &str = "envault import plan v1";

#[derive(Serialize, Deserialize)]
struct PackageEnvelope {
    magic: Vec<u8>,
    version: u16,
    package_id: Uuid,
    kind: PackageKind,
    source_vault_id: VaultId,
    created_at: i64,
    key_slots: Vec<KeySlot>,
    payload_ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum KeySlot {
    Password {
        parameters: KdfParameters,
        salt: [u8; SALT_BYTES],
        wrapped_transfer_key: Vec<u8>,
    },
    AgeX25519 {
        encrypted_transfer_key: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize)]
struct PackagePayload {
    version: u16,
    package_id: Uuid,
    kind: PackageKind,
    source_vault_id: VaultId,
    created_at: i64,
    scopes: Vec<PortableScope>,
    profiles: Vec<PortableProfile>,
    secrets: Vec<PortableSecret>,
    workspaces: Vec<PortableWorkspace>,
    memberships: Vec<PortableWorkspaceMembership>,
}

impl Drop for PackagePayload {
    fn drop(&mut self) {
        for scope in &mut self.scopes {
            scope.path.zeroize();
        }
        for profile in &mut self.profiles {
            profile.name.zeroize();
            if let Some(description) = &mut profile.description {
                description.zeroize();
            }
        }
        for workspace in &mut self.workspaces {
            workspace.name.zeroize();
        }
        for secret in &mut self.secrets {
            secret.name.zeroize();
            if let Some(description) = &mut secret.description {
                description.zeroize();
            }
            if let Some(value) = &mut secret.value {
                value.ciphertext.zeroize();
                value.transfer_wrapped_dek.zeroize();
                value.aad_digest.zeroize();
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PortableScope {
    id: ScopeId,
    parent_id: Option<ScopeId>,
    kind: u8,
    path: String,
}

#[derive(Serialize, Deserialize)]
struct PortableProfile {
    id: ProfileId,
    scope_id: ScopeId,
    name: String,
    description: Option<String>,
    activate_on_start: bool,
    generation: u64,
}

#[derive(Serialize, Deserialize)]
struct PortableWorkspace {
    id: WorkspaceId,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct PortableWorkspaceMembership {
    workspace_id: WorkspaceId,
    profile_id: ProfileId,
}

#[derive(Serialize, Deserialize)]
struct PortableSecret {
    id: SecretId,
    scope_id: ScopeId,
    name: String,
    description: Option<String>,
    current_version: u64,
    status: u8,
    /// The secret's single current value - packages never carry history.
    value: Option<PortableSecretValue>,
}

#[derive(Serialize, Deserialize)]
struct PortableSecretValue {
    id: SecretVersionId,
    ciphertext: Vec<u8>,
    transfer_wrapped_dek: Vec<u8>,
    aad_digest: Vec<u8>,
    generator: Option<u8>,
    generated_length: Option<u64>,
    entropy_bits: Option<u32>,
    created_at: i64,
}

struct LoadedPackage {
    envelope: PackageEnvelope,
    payload: PackagePayload,
    transfer_key: SecretKey,
    source_digest: [u8; 32],
}

/// Discriminates which import surface produced a plan hash, so a config plan
/// hash can never collide with a package or env plan hash even if every
/// other fingerprint field happened to coincide.
#[derive(Serialize)]
enum PlanKind {
    Package,
    Env,
    Config,
}

#[derive(Serialize)]
struct PlanFingerprint<'a> {
    kind: PlanKind,
    source_digest: [u8; 32],
    package_id: Option<Uuid>,
    destination_vault_id: VaultId,
    destination_state_digest: [u8; 32],
    profile_name: Option<&'a str>,
    strategy: ImportConflictStrategy,
    rename_to: Option<&'a str>,
    actions: &'a [ImportConflictView],
}

struct PackagePlan {
    preview: PortabilityPreview,
    mode: PackagePlanMode,
    ids: PackageIdMaps,
}

#[derive(Default)]
struct PackageIdMaps {
    scopes: BTreeMap<ScopeId, ScopeId>,
    profiles: BTreeMap<ProfileId, ProfileId>,
    secrets: BTreeMap<SecretId, SecretId>,
    versions: BTreeMap<SecretVersionId, SecretVersionId>,
}

enum PackagePlanMode {
    Workspace,
    ProfileCreate,
    ProfileReplace {
        existing_profile: ProfileRecord,
        removed_scope_ids: Vec<ScopeId>,
    },
    Skip,
    Reject,
}

struct ParsedEnvEntry {
    name: String,
    value: Zeroizing<Vec<u8>>,
}

struct EnvPlan {
    preview: EnvImportPreview,
    profile: ProfileRecord,
    entries: Vec<(ParsedEnvEntry, Option<SecretRecord>, ImportAction)>,
    rejected: bool,
}

const CONFIG_DOCUMENT_VERSION: u32 = 1;

/// The full-fidelity plaintext YAML schema for `config export`/`config
/// import`. Flat - no scope-tree nesting, matching the decoupled
/// workspace/profile model. `workspaces` is omitted entirely (not merely
/// empty) for a profile-scoped export, via `skip_serializing_if`.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ConfigDocument {
    version: u32,
    source_vault_id: Uuid,
    profiles: Vec<ConfigDocProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    workspaces: Vec<ConfigDocWorkspace>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ConfigDocProfile {
    id: Uuid,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    activate_on_start: bool,
    #[serde(default)]
    secrets: Vec<ConfigDocSecret>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ConfigDocSecret {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ConfigDocWorkspace {
    id: Uuid,
    name: String,
    #[serde(default)]
    members: Vec<String>,
}

impl Drop for ConfigDocument {
    fn drop(&mut self) {
        for profile in &mut self.profiles {
            profile.name.zeroize();
            if let Some(description) = &mut profile.description {
                description.zeroize();
            }
            for secret in &mut profile.secrets {
                secret.name.zeroize();
                secret.value.zeroize();
                if let Some(description) = &mut secret.description {
                    description.zeroize();
                }
            }
        }
    }
}

/// One resolved secret-import decision for a `config import` plan - the
/// per-secret analogue of `PackagePlanMode`, keyed to the owning profile by
/// its normalized name since new profiles do not have a destination id
/// until `plan_config_import` assigns one.
#[derive(Clone)]
struct ConfigSecretDecision {
    profile_normalized: String,
    entry: ConfigDocSecret,
    existing: Option<SecretRecord>,
    action: ImportAction,
}

struct ConfigProfilePlan {
    profile_entries: Vec<ConfigProfileEntryView>,
    secret_entries: Vec<ConfigSecretEntryView>,
    secret_decisions: Vec<ConfigSecretDecision>,
    profile_ids: BTreeMap<String, ProfileId>,
    new_profiles: BTreeSet<String>,
    rejected: bool,
}

struct ConfigWorkspacePlan {
    workspace_entries: Vec<ConfigWorkspaceEntryView>,
    membership_entries: Vec<ConfigMembershipEntryView>,
    workspace_ids: BTreeMap<String, WorkspaceId>,
    new_workspaces: BTreeSet<String>,
    new_memberships: Vec<(WorkspaceId, ProfileId)>,
}

struct ConfigPlan {
    preview: ConfigPreview,
    rejected: bool,
    document: ConfigDocument,
    /// Normalized profile name -> destination `ProfileId`, for both
    /// already-existing profiles and ones this plan will create.
    profile_ids: BTreeMap<String, ProfileId>,
    /// Normalized names of profiles this plan will create (as opposed to
    /// ones that already exist and are merely gaining/skipping secrets).
    new_profiles: BTreeSet<String>,
    secret_decisions: Vec<ConfigSecretDecision>,
    /// Normalized workspace name -> destination `WorkspaceId`.
    workspace_ids: BTreeMap<String, WorkspaceId>,
    new_workspaces: BTreeSet<String>,
    /// Membership pairs to add - config import only ever adds membership,
    /// never removes one the file doesn't mention.
    new_memberships: Vec<(WorkspaceId, ProfileId)>,
}

#[derive(Clone, Copy, Debug)]
pub struct PackageImportOptions<'a> {
    pub expected_kind: PackageKind,
    pub input_path: &'a Path,
    pub transfer_password: Option<&'a SensitiveInput>,
    pub age_identity_path: Option<&'a Path>,
    pub strategy: ImportConflictStrategy,
    pub rename_to: Option<&'a str>,
}

impl VaultSession {
    pub fn export_package(
        &self,
        kind: PackageKind,
        profile_name: Option<&str>,
        output_path: &Path,
        transfer_password: Option<&SensitiveInput>,
        age_recipients: &[String],
    ) -> Result<PortabilityExportSummary, ServiceError> {
        validate_package_suffix(output_path, kind)?;
        if output_path.exists() {
            return Err(ServiceError::Conflict);
        }
        if transfer_password.is_none() && age_recipients.is_empty() {
            return Err(ServiceError::PackageAuthenticationFailed);
        }
        if age_recipients
            .len()
            .saturating_add(usize::from(transfer_password.is_some()))
            > MAX_PORTABILITY_KEY_SLOTS
        {
            return Err(ServiceError::InvalidPackage);
        }
        if let Some(password) = transfer_password {
            validate_transfer_password(password)?;
        }
        let package_id = Uuid::new_v4();
        let created_at = unix_seconds()?;
        let transfer_key = SecretKey::generate()?;
        let payload =
            self.build_export_payload(package_id, created_at, kind, profile_name, &transfer_key)?;
        validate_payload(&payload)?;
        let counts = payload_counts(&payload)?;
        let mut payload_bytes = Zeroizing::new(super::encode_cbor(&payload)?);
        let payload_aad = package_aad(package_id, kind, self.vault_id, created_at, PACKAGE_VERSION);
        let payload_ciphertext = encrypt(&transfer_key, &payload_bytes, &payload_aad)?.encode();
        payload_bytes.zeroize();
        let mut key_slots = Vec::new();
        if let Some(password) = transfer_password {
            let parameters = KdfParameters::default();
            let salt = random_array::<SALT_BYTES>()?;
            let password_key = derive_key(password.secret().as_ref(), &salt, parameters)?;
            let wrapped_transfer_key = wrap_key(
                &password_key,
                &transfer_key,
                &password_slot_aad(package_id, kind, self.vault_id),
            )?
            .encode();
            key_slots.push(KeySlot::Password {
                parameters,
                salt,
                wrapped_transfer_key,
            });
        }
        for recipient_text in age_recipients {
            let recipient = age::x25519::Recipient::from_str(recipient_text.trim())
                .map_err(|_| ServiceError::InvalidPackage)?;
            let transfer_bytes = transfer_key.copy_bytes();
            let encrypted_transfer_key = age::encrypt(&recipient, transfer_bytes.as_ref())
                .map_err(|_| ServiceError::InvalidPackage)?;
            if encrypted_transfer_key.len() > MAX_AGE_SLOT_BYTES {
                return Err(ServiceError::InvalidPackage);
            }
            key_slots.push(KeySlot::AgeX25519 {
                encrypted_transfer_key,
            });
        }
        let password_slots = u32::from(transfer_password.is_some());
        let age_slots =
            u32::try_from(age_recipients.len()).map_err(|_| ServiceError::InvalidPackage)?;
        let envelope = PackageEnvelope {
            magic: PACKAGE_MAGIC.to_vec(),
            version: PACKAGE_VERSION,
            package_id,
            kind,
            source_vault_id: self.vault_id,
            created_at,
            key_slots,
            payload_ciphertext,
        };
        let encoded = Zeroizing::new(super::encode_cbor(&envelope)?);
        if encoded.len() > MAX_PORTABILITY_PACKAGE_BYTES {
            return Err(ServiceError::InvalidPackage);
        }
        write_private_no_replace(output_path, &encoded)?;
        Ok(PortabilityExportSummary {
            package_id,
            kind,
            output_path: output_path.display().to_string(),
            counts,
            password_slots,
            age_slots,
        })
    }

    pub fn preview_package_import_for_kind(
        &self,
        options: PackageImportOptions<'_>,
    ) -> Result<PortabilityPreview, ServiceError> {
        let loaded = load_package(
            options.input_path,
            options.transfer_password,
            options.age_identity_path,
        )?;
        if loaded.envelope.kind != options.expected_kind {
            return Err(ServiceError::InvalidPackage);
        }
        Ok(self
            .plan_package_import(&loaded, options.strategy, options.rename_to)?
            .preview)
    }

    #[cfg(test)]
    fn preview_package_import(
        &self,
        input_path: &Path,
        transfer_password: Option<&SensitiveInput>,
        age_identity_path: Option<&Path>,
        strategy: ImportConflictStrategy,
        rename_to: Option<&str>,
    ) -> Result<PortabilityPreview, ServiceError> {
        let loaded = load_package(input_path, transfer_password, age_identity_path)?;
        Ok(self
            .plan_package_import(&loaded, strategy, rename_to)?
            .preview)
    }

    pub fn commit_package_import_for_kind(
        &mut self,
        options: PackageImportOptions<'_>,
        expected_plan_hash: &str,
    ) -> Result<PortabilityImportSummary, ServiceError> {
        validate_plan_hash(expected_plan_hash)?;
        let loaded = load_package(
            options.input_path,
            options.transfer_password,
            options.age_identity_path,
        )?;
        if loaded.envelope.kind != options.expected_kind {
            return Err(ServiceError::InvalidPackage);
        }
        self.commit_loaded_package(
            &loaded,
            options.strategy,
            options.rename_to,
            expected_plan_hash,
        )
    }

    #[cfg(test)]
    fn commit_package_import(
        &mut self,
        input_path: &Path,
        transfer_password: Option<&SensitiveInput>,
        age_identity_path: Option<&Path>,
        strategy: ImportConflictStrategy,
        rename_to: Option<&str>,
        expected_plan_hash: &str,
    ) -> Result<PortabilityImportSummary, ServiceError> {
        validate_plan_hash(expected_plan_hash)?;
        let loaded = load_package(input_path, transfer_password, age_identity_path)?;
        self.commit_loaded_package(&loaded, strategy, rename_to, expected_plan_hash)
    }

    fn commit_loaded_package(
        &mut self,
        loaded: &LoadedPackage,
        strategy: ImportConflictStrategy,
        rename_to: Option<&str>,
        expected_plan_hash: &str,
    ) -> Result<PortabilityImportSummary, ServiceError> {
        let plan = self.plan_package_import(loaded, strategy, rename_to)?;
        if !constant_time_text_eq(&plan.preview.plan_hash, expected_plan_hash) {
            return Err(ServiceError::StaleImportPlan);
        }
        match plan.mode {
            PackagePlanMode::Reject => return Err(ServiceError::Conflict),
            PackagePlanMode::Skip => {
                return Ok(PortabilityImportSummary {
                    package_id: Some(loaded.envelope.package_id),
                    kind: Some(loaded.envelope.kind),
                    counts: plan.preview.counts,
                    created: 0,
                    replaced: 0,
                    skipped: plan.preview.counts.profiles.max(1),
                });
            }
            PackagePlanMode::Workspace
            | PackagePlanMode::ProfileCreate
            | PackagePlanMode::ProfileReplace { .. } => {}
        }
        let batch = self.build_package_batch(loaded, &plan)?;
        let replaced = u64::from(matches!(
            plan.mode,
            PackagePlanMode::Workspace | PackagePlanMode::ProfileReplace { .. }
        ));
        self.store.apply_import_batch(&batch)?;
        self.store.integrity_check()?;
        self.validate_encrypted_metadata()
            .map_err(|_| ServiceError::Corrupt)?;
        Ok(PortabilityImportSummary {
            package_id: Some(loaded.envelope.package_id),
            kind: Some(loaded.envelope.kind),
            counts: plan.preview.counts,
            created: plan.preview.counts.profiles + plan.preview.counts.secrets,
            replaced,
            skipped: 0,
        })
    }

    pub fn preview_env_import(
        &self,
        profile_name: &str,
        input_path: &Path,
        strategy: ImportConflictStrategy,
    ) -> Result<EnvImportPreview, ServiceError> {
        Ok(self
            .plan_env_import(profile_name, input_path, strategy)?
            .preview)
    }

    pub fn commit_env_import(
        &mut self,
        profile_name: &str,
        input_path: &Path,
        strategy: ImportConflictStrategy,
        expected_plan_hash: &str,
    ) -> Result<PortabilityImportSummary, ServiceError> {
        validate_plan_hash(expected_plan_hash)?;
        let plan = self.plan_env_import(profile_name, input_path, strategy)?;
        if !constant_time_text_eq(&plan.preview.plan_hash, expected_plan_hash) {
            return Err(ServiceError::StaleImportPlan);
        }
        if plan.rejected {
            return Err(ServiceError::Conflict);
        }
        let mut batch = ImportBatch::default();
        let mut created = 0_u64;
        let mut skipped = 0_u64;
        let mut overwritten = 0_u64;
        for (entry, existing, action) in plan.entries {
            match action {
                ImportAction::Create => {
                    let normalized = normalize_name(&entry.name)?;
                    let id = SecretId(Uuid::new_v4());
                    let secret = SecretRecord {
                        id,
                        scope_id: plan.profile.scope_id,
                        encrypted_name: self.encrypt_entity_text(
                            EntityKind::Secret,
                            id.0,
                            "name",
                            entry.name.trim(),
                        )?,
                        name_lookup: lookup_digest(
                            &self.master_key,
                            SECRET_LOOKUP_DOMAIN,
                            normalized.as_bytes(),
                        )
                        .to_vec(),
                        encrypted_description: None,
                        current_version: 1,
                        status: 0,
                        value: None,
                    };
                    let value = self.encrypt_secret_value(
                        &secret,
                        1,
                        SecretBytes::new(entry.value.to_vec()),
                        None,
                    )?;
                    batch.secrets.push(SecretRecord {
                        value: Some(value),
                        ..secret
                    });
                    created = created.saturating_add(1);
                }
                ImportAction::Overwrite => {
                    let secret = existing.ok_or(ServiceError::Corrupt)?;
                    let next = secret
                        .current_version
                        .checked_add(1)
                        .ok_or(ServiceError::Corrupt)?;
                    let value = self.encrypt_secret_value(
                        &secret,
                        next,
                        SecretBytes::new(entry.value.to_vec()),
                        None,
                    )?;
                    batch.value_overwrites.push(SecretValueOverwrite {
                        secret_id: secret.id,
                        expected_current_version: secret.current_version,
                        value,
                    });
                    overwritten = overwritten.saturating_add(1);
                }
                ImportAction::Skip => skipped = skipped.saturating_add(1),
                ImportAction::Reject | ImportAction::Replace | ImportAction::Rename => {
                    return Err(ServiceError::Corrupt);
                }
            }
        }
        self.store.apply_import_batch(&batch)?;
        self.store.integrity_check()?;
        Ok(PortabilityImportSummary {
            package_id: None,
            kind: None,
            counts: PortabilityCounts {
                secrets: created,
                ..PortabilityCounts::default()
            },
            created,
            replaced: overwritten,
            skipped,
        })
    }

    pub fn export_plaintext_env(
        &self,
        profile_name: &str,
        output_path: &Path,
        allow_plaintext: bool,
    ) -> Result<PlaintextExportSummary, ServiceError> {
        if !allow_plaintext {
            return Err(ServiceError::PlaintextAcknowledgementRequired);
        }
        if output_path.exists() {
            return Err(ServiceError::Conflict);
        }
        let profile = self.profile_by_name(profile_name)?;
        let mut resolved = self.resolved_secrets(profile.scope_id)?;
        resolved.sort_by(|left, right| left.secret.name.cmp(&right.secret.name));
        let mut output = Zeroizing::new(Vec::new());
        for item in &resolved {
            if !valid_env_name(&item.secret.name) {
                return Err(ServiceError::PlaintextExportUnsupported);
            }
            let secret = self
                .store
                .secret_by_id(item.secret.id)?
                .ok_or(ServiceError::Corrupt)?;
            let value = self.decrypt_secret_value(&secret)?;
            let text = std::str::from_utf8(value.as_ref())
                .map_err(|_| ServiceError::PlaintextExportUnsupported)?;
            output.extend_from_slice(item.secret.name.as_bytes());
            output.extend_from_slice(b"=\"");
            append_env_escaped(&mut output, text)?;
            output.extend_from_slice(b"\"\n");
        }
        write_plaintext_no_replace(output_path, &output)?;
        Ok(PlaintextExportSummary {
            profile: profile_name.to_owned(),
            output_path: output_path.display().to_string(),
            secret_count: u64::try_from(resolved.len()).map_err(|_| ServiceError::Corrupt)?,
        })
    }

    /// Full-fidelity plaintext YAML export - a whole vault or a named slice
    /// of it (see `ConfigSelector`). Secrets belong only to profiles, so
    /// `workspaces:` never carries secret material, only membership names;
    /// it is omitted entirely for a profile-scoped selector.
    pub fn export_config_yaml(
        &self,
        selector: ConfigSelector,
        output_path: &Path,
    ) -> Result<PortabilityExportSummary, ServiceError> {
        if output_path.exists() {
            return Err(ServiceError::Conflict);
        }
        let (profiles, workspaces, package_kind) =
            self.resolve_config_export_selection(selector)?;
        let (profiles_doc, secret_count) = self.build_config_profile_docs(&profiles)?;
        let (workspaces_doc, membership_count) = self.build_config_workspace_docs(&workspaces)?;

        let document = ConfigDocument {
            version: CONFIG_DOCUMENT_VERSION,
            source_vault_id: self.vault_id.0,
            profiles: profiles_doc,
            workspaces: workspaces_doc,
        };
        let yaml = Zeroizing::new(
            serde_yaml::to_string(&document).map_err(|_| ServiceError::Serialization)?,
        );
        write_plaintext_no_replace(output_path, yaml.as_bytes())?;
        let counts = PortabilityCounts {
            scopes: 0,
            profiles: u64::try_from(document.profiles.len()).map_err(|_| ServiceError::Corrupt)?,
            secrets: secret_count,
            workspaces: u64::try_from(document.workspaces.len())
                .map_err(|_| ServiceError::Corrupt)?,
            memberships: membership_count,
        };
        Ok(PortabilityExportSummary {
            package_id: Uuid::new_v4(),
            kind: package_kind,
            output_path: output_path.display().to_string(),
            counts,
            password_slots: 0,
            age_slots: 0,
        })
    }

    /// Resolves a `ConfigSelector` to the concrete profiles/workspaces an
    /// export should include, deduplicated, plus the `PackageKind` used only
    /// to describe the selection's shape in `PortabilityExportSummary`
    /// (`Profiles` -> `Profile`; `Vault`/`Workspaces` -> `Workspace`, since
    /// both touch workspace state).
    fn resolve_config_export_selection(
        &self,
        selector: ConfigSelector,
    ) -> Result<(Vec<ProfileView>, Vec<WorkspaceView>, PackageKind), ServiceError> {
        match selector {
            ConfigSelector::Vault => {
                Ok((self.profiles()?, self.workspaces()?, PackageKind::Workspace))
            }
            ConfigSelector::Profiles(names) => {
                let mut selected = Vec::new();
                let mut seen = BTreeSet::new();
                for name in &names {
                    let profile = self.profile(name)?;
                    if seen.insert(profile.id) {
                        selected.push(profile);
                    }
                }
                Ok((selected, Vec::new(), PackageKind::Profile))
            }
            ConfigSelector::Workspaces(names) => {
                let mut selected_workspaces = Vec::new();
                let mut seen_workspaces = BTreeSet::new();
                for name in &names {
                    let workspace = self.workspace_by_name(name)?;
                    if seen_workspaces.insert(workspace.id) {
                        selected_workspaces.push(workspace);
                    }
                }
                let mut selected_profiles = Vec::new();
                let mut seen_profiles = BTreeSet::new();
                for workspace in &selected_workspaces {
                    for profile in self.profiles_in_workspace(&workspace.name)? {
                        if seen_profiles.insert(profile.id) {
                            selected_profiles.push(profile);
                        }
                    }
                }
                Ok((
                    selected_profiles,
                    selected_workspaces,
                    PackageKind::Workspace,
                ))
            }
        }
    }

    fn build_config_profile_docs(
        &self,
        profiles: &[ProfileView],
    ) -> Result<(Vec<ConfigDocProfile>, u64), ServiceError> {
        let mut profiles_doc = Vec::with_capacity(profiles.len());
        let mut secret_count = 0_u64;
        for profile in profiles {
            let mut resolved = self.resolved_secrets(profile.scope_id)?;
            resolved.sort_by(|left, right| left.secret.name.cmp(&right.secret.name));
            let mut secrets_doc = Vec::with_capacity(resolved.len());
            for item in &resolved {
                let secret = self
                    .store
                    .secret_by_id(item.secret.id)?
                    .ok_or(ServiceError::Corrupt)?;
                let value = self.decrypt_secret_value(&secret)?;
                let text = std::str::from_utf8(value.as_ref())
                    .map_err(|_| ServiceError::PlaintextExportUnsupported)?
                    .to_owned();
                secrets_doc.push(ConfigDocSecret {
                    name: item.secret.name.clone(),
                    description: item.secret.description.clone(),
                    value: text,
                });
            }
            secret_count = secret_count.saturating_add(
                u64::try_from(secrets_doc.len()).map_err(|_| ServiceError::Corrupt)?,
            );
            profiles_doc.push(ConfigDocProfile {
                id: profile.id.0,
                name: profile.name.clone(),
                description: profile.description.clone(),
                activate_on_start: profile.activate_on_start,
                secrets: secrets_doc,
            });
        }
        profiles_doc.sort_by(|left, right| left.name.cmp(&right.name));
        Ok((profiles_doc, secret_count))
    }

    fn build_config_workspace_docs(
        &self,
        workspaces: &[WorkspaceView],
    ) -> Result<(Vec<ConfigDocWorkspace>, u64), ServiceError> {
        let mut membership_count = 0_u64;
        let mut workspaces_doc = Vec::with_capacity(workspaces.len());
        for workspace in workspaces {
            let mut members = self
                .profiles_in_workspace(&workspace.name)?
                .into_iter()
                .map(|profile| profile.name)
                .collect::<Vec<_>>();
            members.sort();
            membership_count = membership_count
                .saturating_add(u64::try_from(members.len()).map_err(|_| ServiceError::Corrupt)?);
            workspaces_doc.push(ConfigDocWorkspace {
                id: workspace.id.0,
                name: workspace.name.clone(),
                members,
            });
        }
        workspaces_doc.sort_by(|left, right| left.name.cmp(&right.name));
        Ok((workspaces_doc, membership_count))
    }

    pub fn preview_config_import(
        &self,
        input_path: &Path,
        strategy: ImportConflictStrategy,
    ) -> Result<ConfigPreview, ServiceError> {
        Ok(self.plan_config_import(input_path, strategy)?.preview)
    }

    pub fn commit_config_import(
        &mut self,
        input_path: &Path,
        strategy: ImportConflictStrategy,
        expected_plan_hash: &str,
    ) -> Result<PortabilityImportSummary, ServiceError> {
        validate_plan_hash(expected_plan_hash)?;
        let plan = self.plan_config_import(input_path, strategy)?;
        if !constant_time_text_eq(&plan.preview.plan_hash, expected_plan_hash) {
            return Err(ServiceError::StaleImportPlan);
        }
        if plan.rejected {
            return Err(ServiceError::Conflict);
        }
        let mut batch = ImportBatch::default();
        let (profile_scope_ids, created_profiles) =
            self.stage_config_profiles(&plan, &mut batch)?;
        let (created_secrets, appended_versions, skipped) =
            self.stage_config_secrets(&plan, &profile_scope_ids, &mut batch)?;
        let created_workspaces = self.stage_config_workspaces(&plan, &mut batch)?;
        let created_memberships =
            u64::try_from(plan.new_memberships.len()).map_err(|_| ServiceError::Corrupt)?;
        batch
            .workspace_memberships
            .clone_from(&plan.new_memberships);

        self.store.apply_import_batch(&batch)?;
        self.store.integrity_check()?;
        self.validate_encrypted_metadata()
            .map_err(|_| ServiceError::Corrupt)?;

        let created = created_profiles
            .saturating_add(created_secrets)
            .saturating_add(created_workspaces)
            .saturating_add(created_memberships);
        Ok(PortabilityImportSummary {
            package_id: None,
            kind: None,
            counts: plan.preview.counts,
            created,
            replaced: appended_versions,
            skipped,
        })
    }

    /// Stages scope+profile inserts for every profile the plan will create,
    /// and records every profile's (new or existing) scope id so
    /// `stage_config_secrets` knows where to place its secrets. Returns the
    /// scope-id map and the number of profiles created.
    fn stage_config_profiles(
        &self,
        plan: &ConfigPlan,
        batch: &mut ImportBatch,
    ) -> Result<(BTreeMap<String, ScopeId>, u64), ServiceError> {
        let root_path = self.root_scope_path()?;
        let mut profile_scope_ids: BTreeMap<String, ScopeId> = BTreeMap::new();
        let mut created_profiles = 0_u64;
        for doc_profile in &plan.document.profiles {
            let normalized = normalize_name(&doc_profile.name)?;
            let profile_id = *plan
                .profile_ids
                .get(&normalized)
                .ok_or(ServiceError::Corrupt)?;
            if plan.new_profiles.contains(&normalized) {
                let scope_id = ScopeId(Uuid::new_v4());
                let scope_path = format!("{root_path}/profile/{}", scope_id.0);
                batch.scopes.push(ScopeRecord {
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
                });
                batch.profiles.push(ProfileRecord {
                    id: profile_id,
                    vault_id: self.vault_id,
                    scope_id,
                    encrypted_name: self.encrypt_entity_text(
                        EntityKind::Profile,
                        profile_id.0,
                        "name",
                        doc_profile.name.trim(),
                    )?,
                    name_lookup: lookup_digest(
                        &self.master_key,
                        PROFILE_LOOKUP_DOMAIN,
                        normalized.as_bytes(),
                    )
                    .to_vec(),
                    encrypted_description: self.encrypt_optional_entity_text(
                        EntityKind::Profile,
                        profile_id.0,
                        "description",
                        doc_profile.description.as_deref(),
                    )?,
                    activate_on_start: false,
                    generation: 1,
                });
                profile_scope_ids.insert(normalized.clone(), scope_id);
                created_profiles = created_profiles.saturating_add(1);
            } else {
                let lookup = lookup_digest(
                    &self.master_key,
                    PROFILE_LOOKUP_DOMAIN,
                    normalized.as_bytes(),
                );
                let existing = self
                    .store
                    .profile_by_lookup(self.vault_id, &lookup)?
                    .ok_or(ServiceError::Corrupt)?;
                profile_scope_ids.insert(normalized.clone(), existing.scope_id);
            }
        }
        Ok((profile_scope_ids, created_profiles))
    }

    /// Stages secret creates and in-place value overwrites per
    /// `plan.secret_decisions`. Returns `(created, overwritten, skipped)`.
    fn stage_config_secrets(
        &self,
        plan: &ConfigPlan,
        profile_scope_ids: &BTreeMap<String, ScopeId>,
        batch: &mut ImportBatch,
    ) -> Result<(u64, u64, u64), ServiceError> {
        let mut created_secrets = 0_u64;
        let mut appended_versions = 0_u64;
        let mut skipped = 0_u64;
        for decision in &plan.secret_decisions {
            let scope_id = *profile_scope_ids
                .get(&decision.profile_normalized)
                .ok_or(ServiceError::Corrupt)?;
            match decision.action {
                ImportAction::Create => {
                    let secret_normalized = normalize_name(&decision.entry.name)?;
                    let id = SecretId(Uuid::new_v4());
                    let secret = SecretRecord {
                        id,
                        scope_id,
                        encrypted_name: self.encrypt_entity_text(
                            EntityKind::Secret,
                            id.0,
                            "name",
                            decision.entry.name.trim(),
                        )?,
                        name_lookup: lookup_digest(
                            &self.master_key,
                            SECRET_LOOKUP_DOMAIN,
                            secret_normalized.as_bytes(),
                        )
                        .to_vec(),
                        encrypted_description: self.encrypt_optional_entity_text(
                            EntityKind::Secret,
                            id.0,
                            "description",
                            decision.entry.description.as_deref(),
                        )?,
                        current_version: 1,
                        status: 0,
                        value: None,
                    };
                    let value = self.encrypt_secret_value(
                        &secret,
                        1,
                        SecretBytes::new(decision.entry.value.clone().into_bytes()),
                        None,
                    )?;
                    batch.secrets.push(SecretRecord {
                        value: Some(value),
                        ..secret
                    });
                    created_secrets = created_secrets.saturating_add(1);
                }
                ImportAction::Overwrite => {
                    let existing = decision.existing.clone().ok_or(ServiceError::Corrupt)?;
                    let next = existing
                        .current_version
                        .checked_add(1)
                        .ok_or(ServiceError::Corrupt)?;
                    let value = self.encrypt_secret_value(
                        &existing,
                        next,
                        SecretBytes::new(decision.entry.value.clone().into_bytes()),
                        None,
                    )?;
                    batch.value_overwrites.push(SecretValueOverwrite {
                        secret_id: existing.id,
                        expected_current_version: existing.current_version,
                        value,
                    });
                    appended_versions = appended_versions.saturating_add(1);
                }
                ImportAction::Skip => skipped = skipped.saturating_add(1),
                ImportAction::Reject | ImportAction::Replace | ImportAction::Rename => {
                    return Err(ServiceError::Corrupt);
                }
            }
        }
        Ok((created_secrets, appended_versions, skipped))
    }

    /// Stages workspace inserts for every workspace the plan will create.
    /// Membership rows are staged directly onto `batch.workspace_memberships`
    /// by the caller, since they need no per-row encryption.
    fn stage_config_workspaces(
        &self,
        plan: &ConfigPlan,
        batch: &mut ImportBatch,
    ) -> Result<u64, ServiceError> {
        let mut created_workspaces = 0_u64;
        for doc_workspace in &plan.document.workspaces {
            let normalized = normalize_name(&doc_workspace.name)?;
            if !plan.new_workspaces.contains(&normalized) {
                continue;
            }
            let id = *plan
                .workspace_ids
                .get(&normalized)
                .ok_or(ServiceError::Corrupt)?;
            batch.workspaces.push(WorkspaceRecord {
                id,
                vault_id: self.vault_id,
                encrypted_name: self.encrypt_entity_text(
                    EntityKind::Workspace,
                    id.0,
                    "name",
                    doc_workspace.name.trim(),
                )?,
                name_lookup: lookup_digest(
                    &self.master_key,
                    scope_policy::WORKSPACE_LOOKUP_DOMAIN,
                    normalized.as_bytes(),
                )
                .to_vec(),
            });
            created_workspaces = created_workspaces.saturating_add(1);
        }
        Ok(created_workspaces)
    }

    fn plan_config_import(
        &self,
        input_path: &Path,
        strategy: ImportConflictStrategy,
    ) -> Result<ConfigPlan, ServiceError> {
        if !matches!(
            strategy,
            ImportConflictStrategy::Abort
                | ImportConflictStrategy::Skip
                | ImportConflictStrategy::Replace
        ) {
            return Err(ServiceError::InvalidImportStrategy);
        }
        let bytes = Zeroizing::new(
            envault_platform::read_bounded_private_file(input_path, MAX_CONFIG_FILE_BYTES)
                .map_err(|error| match error {
                    envault_platform::PlatformError::FileTooLarge => {
                        ServiceError::InvalidConfigFile
                    }
                    error => ServiceError::Platform(error),
                })?,
        );
        let source_digest = *blake3::hash(&bytes).as_bytes();
        let document: ConfigDocument =
            serde_yaml::from_slice(&bytes).map_err(|_| ServiceError::InvalidConfigFile)?;
        if document.version != CONFIG_DOCUMENT_VERSION
            || document.profiles.len() > MAX_PORTABILITY_ENTITIES
            || document.workspaces.len() > MAX_PORTABILITY_ENTITIES
        {
            return Err(ServiceError::InvalidConfigFile);
        }

        let profile_plan = self.plan_config_profiles(&document, strategy)?;
        let workspace_plan = self.plan_config_workspaces(&document, &profile_plan.profile_ids)?;
        self.finalize_config_plan(
            document,
            strategy,
            source_digest,
            profile_plan,
            workspace_plan,
        )
    }

    /// Builds the plan-hash fingerprint (via `ImportConflictView`
    /// projections of every profile/secret/workspace/membership decision),
    /// the summary counts, and the final `ConfigPlan` from the already
    /// resolved profile and workspace sub-plans.
    fn finalize_config_plan(
        &self,
        document: ConfigDocument,
        strategy: ImportConflictStrategy,
        source_digest: [u8; 32],
        profile_plan: ConfigProfilePlan,
        workspace_plan: ConfigWorkspacePlan,
    ) -> Result<ConfigPlan, ServiceError> {
        let mut conflicts = Vec::new();
        for entry in &profile_plan.profile_entries {
            conflicts.push(ImportConflictView {
                resource: "profile".to_owned(),
                name: entry.name.clone(),
                action: entry.action,
            });
        }
        for entry in &profile_plan.secret_entries {
            conflicts.push(ImportConflictView {
                resource: "secret".to_owned(),
                name: format!("{}.{}", entry.profile, entry.name),
                action: entry.action,
            });
        }
        for entry in &workspace_plan.workspace_entries {
            conflicts.push(ImportConflictView {
                resource: "workspace".to_owned(),
                name: entry.name.clone(),
                action: entry.action,
            });
        }
        for entry in &workspace_plan.membership_entries {
            conflicts.push(ImportConflictView {
                resource: "membership".to_owned(),
                name: format!("{}.{}", entry.workspace, entry.profile),
                action: entry.action,
            });
        }

        let created_secrets = profile_plan
            .secret_entries
            .iter()
            .filter(|entry| entry.action == ImportAction::Create)
            .count();
        let counts = PortabilityCounts {
            scopes: 0,
            profiles: u64::try_from(profile_plan.new_profiles.len())
                .map_err(|_| ServiceError::Corrupt)?,
            secrets: u64::try_from(created_secrets).map_err(|_| ServiceError::Corrupt)?,
            workspaces: u64::try_from(workspace_plan.new_workspaces.len())
                .map_err(|_| ServiceError::Corrupt)?,
            memberships: u64::try_from(workspace_plan.new_memberships.len())
                .map_err(|_| ServiceError::Corrupt)?,
        };

        let state_digest = self.destination_state_digest()?;
        let plan_hash = self.compute_plan_hash(&PlanFingerprint {
            kind: PlanKind::Config,
            source_digest,
            package_id: None,
            destination_vault_id: self.vault_id,
            destination_state_digest: state_digest,
            profile_name: None,
            strategy,
            rename_to: None,
            actions: &conflicts,
        })?;

        Ok(ConfigPlan {
            preview: ConfigPreview {
                source_vault_id: document.source_vault_id,
                strategy,
                counts,
                profiles: profile_plan.profile_entries,
                secrets: profile_plan.secret_entries,
                workspaces: workspace_plan.workspace_entries,
                memberships: workspace_plan.membership_entries,
                plan_hash,
                warnings: vec![
                    "Values are redacted from preview output.".to_owned(),
                    "The plaintext source file remains on disk after import.".to_owned(),
                ],
            },
            rejected: profile_plan.rejected,
            document,
            profile_ids: profile_plan.profile_ids,
            new_profiles: profile_plan.new_profiles,
            secret_decisions: profile_plan.secret_decisions,
            workspace_ids: workspace_plan.workspace_ids,
            new_workspaces: workspace_plan.new_workspaces,
            new_memberships: workspace_plan.new_memberships,
        })
    }

    /// Per-profile (and per-secret-within-profile) plan: an existing profile
    /// is never replaced, only merged into per the secret conflict strategy;
    /// a missing profile is always created.
    fn plan_config_profiles(
        &self,
        document: &ConfigDocument,
        strategy: ImportConflictStrategy,
    ) -> Result<ConfigProfilePlan, ServiceError> {
        let mut profile_entries = Vec::new();
        let mut secret_entries = Vec::new();
        let mut secret_decisions = Vec::new();
        let mut profile_ids = BTreeMap::new();
        let mut new_profiles = BTreeSet::new();
        let mut rejected = false;

        for doc_profile in &document.profiles {
            let normalized = normalize_name(&doc_profile.name)?;
            let lookup = lookup_digest(
                &self.master_key,
                PROFILE_LOOKUP_DOMAIN,
                normalized.as_bytes(),
            );
            let existing = self.store.profile_by_lookup(self.vault_id, &lookup)?;
            let Some(record) = existing else {
                profile_entries.push(ConfigProfileEntryView {
                    name: doc_profile.name.clone(),
                    action: ImportAction::Create,
                });
                let id = ProfileId(Uuid::new_v4());
                profile_ids.insert(normalized.clone(), id);
                new_profiles.insert(normalized.clone());
                for doc_secret in &doc_profile.secrets {
                    secret_entries.push(ConfigSecretEntryView {
                        profile: doc_profile.name.clone(),
                        name: doc_secret.name.clone(),
                        action: ImportAction::Create,
                    });
                    secret_decisions.push(ConfigSecretDecision {
                        profile_normalized: normalized.clone(),
                        entry: doc_secret.clone(),
                        existing: None,
                        action: ImportAction::Create,
                    });
                }
                continue;
            };
            profile_entries.push(ConfigProfileEntryView {
                name: doc_profile.name.clone(),
                action: ImportAction::Skip,
            });
            profile_ids.insert(normalized.clone(), record.id);
            for doc_secret in &doc_profile.secrets {
                let secret_normalized = normalize_name(&doc_secret.name)?;
                let secret_lookup = lookup_digest(
                    &self.master_key,
                    SECRET_LOOKUP_DOMAIN,
                    secret_normalized.as_bytes(),
                );
                let existing_secret = self
                    .store
                    .secret_by_lookup(record.scope_id, &secret_lookup)?;
                let action = match (&existing_secret, strategy) {
                    (None, _) => ImportAction::Create,
                    (Some(_), ImportConflictStrategy::Skip) => ImportAction::Skip,
                    (Some(secret), ImportConflictStrategy::Replace) if secret.status == 0 => {
                        ImportAction::Overwrite
                    }
                    (Some(_), ImportConflictStrategy::Abort | ImportConflictStrategy::Replace) => {
                        ImportAction::Reject
                    }
                    (Some(_), ImportConflictStrategy::Rename) => {
                        return Err(ServiceError::InvalidImportStrategy);
                    }
                };
                if action == ImportAction::Reject {
                    rejected = true;
                }
                secret_entries.push(ConfigSecretEntryView {
                    profile: doc_profile.name.clone(),
                    name: doc_secret.name.clone(),
                    action,
                });
                secret_decisions.push(ConfigSecretDecision {
                    profile_normalized: normalized.clone(),
                    entry: doc_secret.clone(),
                    existing: existing_secret,
                    action,
                });
            }
        }

        Ok(ConfigProfilePlan {
            profile_entries,
            secret_entries,
            secret_decisions,
            profile_ids,
            new_profiles,
            rejected,
        })
    }

    /// Per-workspace (and per-membership) plan. Config import only ever adds
    /// workspaces/memberships the file mentions - it never removes an
    /// existing membership the file is silent about, to avoid surprising
    /// deletions on a partial/scoped import.
    fn plan_config_workspaces(
        &self,
        document: &ConfigDocument,
        profile_ids: &BTreeMap<String, ProfileId>,
    ) -> Result<ConfigWorkspacePlan, ServiceError> {
        let mut workspace_entries = Vec::new();
        let mut membership_entries = Vec::new();
        let mut workspace_ids = BTreeMap::new();
        let mut new_workspaces = BTreeSet::new();
        let mut new_memberships = Vec::new();
        for doc_workspace in &document.workspaces {
            let normalized = normalize_name(&doc_workspace.name)?;
            let workspace_id = match self.workspace_by_name(&doc_workspace.name) {
                Ok(view) => {
                    workspace_entries.push(ConfigWorkspaceEntryView {
                        name: doc_workspace.name.clone(),
                        action: ImportAction::Skip,
                    });
                    view.id
                }
                Err(ServiceError::NotFound) => {
                    workspace_entries.push(ConfigWorkspaceEntryView {
                        name: doc_workspace.name.clone(),
                        action: ImportAction::Create,
                    });
                    new_workspaces.insert(normalized.clone());
                    WorkspaceId(Uuid::new_v4())
                }
                Err(error) => return Err(error),
            };
            workspace_ids.insert(normalized.clone(), workspace_id);
            let existing_members = self.store.profiles_in_workspace(workspace_id)?;
            for member in &doc_workspace.members {
                let member_normalized = normalize_name(member)?;
                let profile_id = *profile_ids
                    .get(&member_normalized)
                    .ok_or(ServiceError::InvalidConfigFile)?;
                let already_member = existing_members
                    .iter()
                    .any(|profile| profile.id == profile_id);
                let action = if already_member {
                    ImportAction::Skip
                } else {
                    new_memberships.push((workspace_id, profile_id));
                    ImportAction::Create
                };
                membership_entries.push(ConfigMembershipEntryView {
                    workspace: doc_workspace.name.clone(),
                    profile: member.clone(),
                    action,
                });
            }
        }

        Ok(ConfigWorkspacePlan {
            workspace_entries,
            membership_entries,
            workspace_ids,
            new_workspaces,
            new_memberships,
        })
    }

    fn root_scope_path(&self) -> Result<String, ServiceError> {
        let root = self
            .store
            .scope_by_id(self.root_scope_id)?
            .ok_or(ServiceError::Corrupt)?;
        self.decrypt_entity_text(EntityKind::Scope, root.id.0, "path", &root.encrypted_path)
    }

    fn build_export_payload(
        &self,
        package_id: Uuid,
        created_at: i64,
        kind: PackageKind,
        profile_name: Option<&str>,
        transfer_key: &SecretKey,
    ) -> Result<PackagePayload, ServiceError> {
        let all_scopes = self.store.scopes()?;
        let all_profiles = self.store.profiles()?;
        let selected_profile = match kind {
            PackageKind::Profile => {
                Some(self.profile_by_name(profile_name.ok_or(ServiceError::InvalidPackage)?)?)
            }
            PackageKind::Workspace => {
                if profile_name.is_some() {
                    return Err(ServiceError::InvalidPackage);
                }
                None
            }
        };
        let selected_scope_ids =
            select_export_scopes(kind, selected_profile.as_ref(), &all_scopes, &all_profiles)?;
        let profile_records = match selected_profile {
            Some(profile) => vec![profile],
            None => all_profiles,
        };
        let scopes = self.export_scopes(&all_scopes, &selected_scope_ids)?;
        let profiles = self.export_profiles(&profile_records)?;
        let secrets = self.export_secrets(package_id, transfer_key, &selected_scope_ids)?;
        let (workspaces, memberships) = match kind {
            PackageKind::Profile => (Vec::new(), Vec::new()),
            PackageKind::Workspace => {
                let workspaces = self.export_workspaces(&self.store.workspaces()?)?;
                let memberships = self
                    .store
                    .all_workspace_memberships()?
                    .into_iter()
                    .map(|(workspace_id, profile_id)| PortableWorkspaceMembership {
                        workspace_id,
                        profile_id,
                    })
                    .collect();
                (workspaces, memberships)
            }
        };
        Ok(PackagePayload {
            version: PACKAGE_VERSION,
            package_id,
            kind,
            source_vault_id: self.vault_id,
            created_at,
            scopes,
            profiles,
            secrets,
            workspaces,
            memberships,
        })
    }

    fn export_workspaces(
        &self,
        workspace_records: &[WorkspaceRecord],
    ) -> Result<Vec<PortableWorkspace>, ServiceError> {
        workspace_records
            .iter()
            .map(|workspace| {
                Ok(PortableWorkspace {
                    id: workspace.id,
                    name: self.decrypt_entity_text(
                        EntityKind::Workspace,
                        workspace.id.0,
                        "name",
                        &workspace.encrypted_name,
                    )?,
                })
            })
            .collect()
    }

    fn export_scopes(
        &self,
        all_scopes: &[ScopeRecord],
        selected_scope_ids: &BTreeSet<ScopeId>,
    ) -> Result<Vec<PortableScope>, ServiceError> {
        all_scopes
            .iter()
            .filter(|scope| selected_scope_ids.contains(&scope.id))
            .map(|scope| {
                Ok(PortableScope {
                    id: scope.id,
                    parent_id: scope
                        .parent_id
                        .filter(|parent| selected_scope_ids.contains(parent)),
                    kind: scope.kind,
                    path: self.decrypt_entity_text(
                        EntityKind::Scope,
                        scope.id.0,
                        "path",
                        &scope.encrypted_path,
                    )?,
                })
            })
            .collect()
    }

    fn export_profiles(
        &self,
        profile_records: &[ProfileRecord],
    ) -> Result<Vec<PortableProfile>, ServiceError> {
        profile_records
            .iter()
            .map(|profile| {
                let view = self.profile_view(profile)?;
                Ok(PortableProfile {
                    id: profile.id,
                    scope_id: profile.scope_id,
                    name: view.name,
                    description: view.description,
                    activate_on_start: profile.activate_on_start,
                    generation: profile.generation,
                })
            })
            .collect()
    }

    fn export_secrets(
        &self,
        package_id: Uuid,
        transfer_key: &SecretKey,
        selected_scope_ids: &BTreeSet<ScopeId>,
    ) -> Result<Vec<PortableSecret>, ServiceError> {
        let mut secrets = Vec::new();
        for secret in self
            .store
            .secrets()?
            .into_iter()
            .filter(|secret| selected_scope_ids.contains(&secret.scope_id))
        {
            let view = self.secret_view(&secret)?;
            let value = secret
                .value
                .as_ref()
                .map(|value| {
                    let wrap_aad = secret_wrap_aad(
                        self.vault_id,
                        secret.id,
                        value.value_id,
                        secret.scope_id,
                        secret.current_version,
                    );
                    let dek = unwrap_key(
                        &self.master_key,
                        &Ciphertext::decode(&value.wrapped_dek)?,
                        &wrap_aad,
                    )?;
                    let transfer_wrapped_dek = wrap_key(
                        transfer_key,
                        &dek,
                        &transfer_dek_aad(
                            package_id,
                            self.vault_id,
                            secret.id,
                            value.value_id,
                            secret.scope_id,
                            secret.current_version,
                        ),
                    )?
                    .encode();
                    Ok::<_, ServiceError>(PortableSecretValue {
                        id: value.value_id,
                        ciphertext: value.ciphertext.clone(),
                        transfer_wrapped_dek,
                        aad_digest: value.aad_digest.clone(),
                        generator: value.generator,
                        generated_length: value.generated_length,
                        entropy_bits: value.entropy_bits,
                        created_at: value.created_at,
                    })
                })
                .transpose()?;
            secrets.push(PortableSecret {
                id: secret.id,
                scope_id: secret.scope_id,
                name: view.name,
                description: view.description,
                current_version: secret.current_version,
                status: secret.status,
                value,
            });
        }
        Ok(secrets)
    }

    fn plan_package_import(
        &self,
        loaded: &LoadedPackage,
        strategy: ImportConflictStrategy,
        rename_to: Option<&str>,
    ) -> Result<PackagePlan, ServiceError> {
        let payload = &loaded.payload;
        let counts = payload_counts(payload)?;
        let state_digest = self.destination_state_digest()?;
        let mut actions = Vec::new();
        let mut ids = PackageIdMaps::default();
        let destination_profile;
        let mode = match payload.kind {
            PackageKind::Workspace => {
                destination_profile = None;
                self.plan_workspace_import(payload, strategy, rename_to, &mut actions, &mut ids)?
            }
            PackageKind::Profile => {
                let (profile, mode) =
                    self.plan_profile_import(loaded, strategy, rename_to, &mut actions, &mut ids)?;
                destination_profile = Some(profile);
                mode
            }
        };
        let plan_hash = self.compute_plan_hash(&PlanFingerprint {
            kind: PlanKind::Package,
            source_digest: loaded.source_digest,
            package_id: Some(loaded.envelope.package_id),
            destination_vault_id: self.vault_id,
            destination_state_digest: state_digest,
            profile_name: destination_profile.as_deref(),
            strategy,
            rename_to,
            actions: &actions,
        })?;
        Ok(PackagePlan {
            preview: PortabilityPreview {
                package_id: Some(loaded.envelope.package_id),
                kind: Some(loaded.envelope.kind),
                source_vault_id: Some(loaded.envelope.source_vault_id),
                destination_profile,
                strategy,
                counts,
                conflicts: actions,
                plan_hash,
                warnings: vec![
                    "Commit requires this exact plan hash and revalidates source plus destination state."
                        .to_owned(),
                ],
            },
            mode,
            ids,
        })
    }

    fn plan_workspace_import(
        &self,
        payload: &PackagePayload,
        strategy: ImportConflictStrategy,
        rename_to: Option<&str>,
        actions: &mut Vec<ImportConflictView>,
        ids: &mut PackageIdMaps,
    ) -> Result<PackagePlanMode, ServiceError> {
        if rename_to.is_some()
            || !matches!(
                strategy,
                ImportConflictStrategy::Abort | ImportConflictStrategy::Replace
            )
        {
            return Err(ServiceError::InvalidImportStrategy);
        }
        if strategy == ImportConflictStrategy::Abort && !self.workspace_is_portably_empty()? {
            actions.push(ImportConflictView {
                resource: "workspace".to_owned(),
                name: "destination".to_owned(),
                action: ImportAction::Reject,
            });
        }
        let source_root = payload_root_scope(payload)?;
        let source_base = payload_base_profile(payload, source_root.id)?;
        ids.scopes.insert(source_root.id, self.root_scope_id);
        ids.profiles
            .insert(source_base.id, self.destination_base_profile()?.id);
        map_workspace_ids(
            payload,
            &mut ids.scopes,
            &mut ids.profiles,
            &mut ids.secrets,
            &mut ids.versions,
        );
        Ok(if actions.is_empty() {
            PackagePlanMode::Workspace
        } else {
            PackagePlanMode::Reject
        })
    }

    fn plan_profile_import(
        &self,
        loaded: &LoadedPackage,
        strategy: ImportConflictStrategy,
        rename_to: Option<&str>,
        actions: &mut Vec<ImportConflictView>,
        ids: &mut PackageIdMaps,
    ) -> Result<(String, PackagePlanMode), ServiceError> {
        if !matches!(
            strategy,
            ImportConflictStrategy::Abort
                | ImportConflictStrategy::Skip
                | ImportConflictStrategy::Replace
                | ImportConflictStrategy::Rename
        ) {
            return Err(ServiceError::InvalidImportStrategy);
        }
        let payload = &loaded.payload;
        let source_profile = payload
            .profiles
            .first()
            .ok_or(ServiceError::InvalidPackage)?;
        let desired_name = match strategy {
            ImportConflictStrategy::Rename => {
                rename_to.ok_or(ServiceError::InvalidImportStrategy)?
            }
            ImportConflictStrategy::Replace => rename_to.unwrap_or(&source_profile.name),
            ImportConflictStrategy::Abort | ImportConflictStrategy::Skip => {
                if rename_to.is_some() {
                    return Err(ServiceError::InvalidImportStrategy);
                }
                &source_profile.name
            }
        };
        let normalized = normalize_name(desired_name)?;
        let desired_lookup = lookup_digest(
            &self.master_key,
            PROFILE_LOOKUP_DOMAIN,
            normalized.as_bytes(),
        );
        let existing = self
            .store
            .profile_by_lookup(self.vault_id, &desired_lookup)?;
        let source_root = payload_root_scope(payload)?;
        let mode = match (existing, strategy) {
            (Some(_), ImportConflictStrategy::Abort | ImportConflictStrategy::Rename) => {
                actions.push(profile_import_action(desired_name, ImportAction::Reject));
                PackagePlanMode::Reject
            }
            (Some(_), ImportConflictStrategy::Skip) => {
                actions.push(profile_import_action(desired_name, ImportAction::Skip));
                PackagePlanMode::Skip
            }
            (Some(existing), ImportConflictStrategy::Replace) => {
                let removed_scope_ids = self.profile_subtree_scope_ids(existing.scope_id)?;
                ids.scopes.insert(source_root.id, existing.scope_id);
                ids.profiles.insert(source_profile.id, existing.id);
                map_profile_ids(
                    loaded.envelope.package_id,
                    self.vault_id,
                    &normalized,
                    payload,
                    &mut ids.scopes,
                    &mut ids.profiles,
                    &mut ids.secrets,
                    &mut ids.versions,
                );
                actions.push(profile_import_action(desired_name, ImportAction::Replace));
                PackagePlanMode::ProfileReplace {
                    existing_profile: existing,
                    removed_scope_ids,
                }
            }
            (None, _) => {
                map_profile_ids(
                    loaded.envelope.package_id,
                    self.vault_id,
                    &normalized,
                    payload,
                    &mut ids.scopes,
                    &mut ids.profiles,
                    &mut ids.secrets,
                    &mut ids.versions,
                );
                let action = if strategy == ImportConflictStrategy::Rename {
                    ImportAction::Rename
                } else {
                    ImportAction::Create
                };
                actions.push(profile_import_action(desired_name, action));
                PackagePlanMode::ProfileCreate
            }
        };
        Ok((desired_name.to_owned(), mode))
    }

    fn build_package_batch(
        &self,
        loaded: &LoadedPackage,
        plan: &PackagePlan,
    ) -> Result<ImportBatch, ServiceError> {
        let payload = &loaded.payload;
        let source_root = payload_root_scope(payload)?;
        let destination_root_id = mapped(&plan.ids.scopes, source_root.id)?;
        let destination_root_path = if payload.kind == PackageKind::Workspace
            || destination_root_id == self.root_scope_id
        {
            "user".to_owned()
        } else {
            format!("user/profile/{}", destination_root_id.0)
        };
        let mut batch = ImportBatch {
            reset: match &plan.mode {
                PackagePlanMode::Workspace => ImportReset::Workspace {
                    root_scope_id: self.root_scope_id,
                    base_profile_id: self.destination_base_profile()?.id,
                },
                PackagePlanMode::ProfileReplace {
                    existing_profile,
                    removed_scope_ids,
                } => ImportReset::Profile {
                    retained_scope_id: existing_profile.scope_id,
                    removed_scope_ids: removed_scope_ids.clone(),
                },
                PackagePlanMode::ProfileCreate => ImportReset::None,
                PackagePlanMode::Skip | PackagePlanMode::Reject => {
                    return Err(ServiceError::Corrupt);
                }
            },
            ..ImportBatch::default()
        };
        self.append_import_scopes(
            payload,
            plan,
            source_root,
            destination_root_id,
            &destination_root_path,
            &mut batch,
        )?;
        self.append_import_profiles(payload, plan, &mut batch)?;
        self.append_import_secrets(loaded, plan, &mut batch)?;
        self.append_import_workspaces(payload, plan, &mut batch)?;
        Ok(batch)
    }

    fn append_import_workspaces(
        &self,
        payload: &PackagePayload,
        plan: &PackagePlan,
        batch: &mut ImportBatch,
    ) -> Result<(), ServiceError> {
        if payload.kind != PackageKind::Workspace {
            return Ok(());
        }
        for workspace in &payload.workspaces {
            batch.workspaces.push(WorkspaceRecord {
                id: workspace.id,
                vault_id: self.vault_id,
                encrypted_name: self.encrypt_entity_text(
                    EntityKind::Workspace,
                    workspace.id.0,
                    "name",
                    &workspace.name,
                )?,
                name_lookup: lookup_digest(
                    &self.master_key,
                    scope_policy::WORKSPACE_LOOKUP_DOMAIN,
                    normalize_name(&workspace.name)?.as_bytes(),
                )
                .to_vec(),
            });
        }
        for membership in &payload.memberships {
            let profile_id = mapped(&plan.ids.profiles, membership.profile_id)?;
            batch
                .workspace_memberships
                .push((membership.workspace_id, profile_id));
        }
        Ok(())
    }

    fn append_import_scopes(
        &self,
        payload: &PackagePayload,
        plan: &PackagePlan,
        source_root: &PortableScope,
        destination_root_id: ScopeId,
        destination_root_path: &str,
        batch: &mut ImportBatch,
    ) -> Result<(), ServiceError> {
        let mut ordered_scopes = payload.scopes.iter().collect::<Vec<_>>();
        ordered_scopes.sort_by_key(|scope| scope_depth(payload, scope.id).unwrap_or(usize::MAX));
        for source in ordered_scopes {
            let id = mapped(&plan.ids.scopes, source.id)?;
            let parent_id = if source.id == source_root.id {
                (id != self.root_scope_id).then_some(self.root_scope_id)
            } else {
                source
                    .parent_id
                    .map(|parent| mapped(&plan.ids.scopes, parent))
                    .transpose()?
            };
            let path = remap_scope_path(&source.path, &source_root.path, destination_root_path)?;
            let kind = if source.id == source_root.id {
                if id == self.root_scope_id {
                    scope_policy::scope_kind_code(ScopeKind::Root)
                } else {
                    scope_policy::scope_kind_code(ScopeKind::Profile)
                }
            } else {
                source.kind
            };
            let record = ScopeRecord {
                id,
                vault_id: self.vault_id,
                parent_id,
                kind,
                encrypted_path: self.encrypt_entity_text(EntityKind::Scope, id.0, "path", &path)?,
                path_lookup: lookup_digest(&self.master_key, SCOPE_LOOKUP_DOMAIN, path.as_bytes())
                    .to_vec(),
            };
            if (matches!(plan.mode, PackagePlanMode::Workspace) && id == self.root_scope_id)
                || matches!(plan.mode, PackagePlanMode::ProfileReplace { .. })
                    && id == destination_root_id
            {
                batch.scope_updates.push(record);
            } else {
                batch.scopes.push(record);
            }
        }
        Ok(())
    }

    fn append_import_profiles(
        &self,
        payload: &PackagePayload,
        plan: &PackagePlan,
        batch: &mut ImportBatch,
    ) -> Result<(), ServiceError> {
        let desired_profile_name = plan.preview.destination_profile.as_deref();
        let destination_base_id = if payload.kind == PackageKind::Workspace {
            Some(self.destination_base_profile()?.id)
        } else {
            None
        };
        for source in &payload.profiles {
            let id = mapped(&plan.ids.profiles, source.id)?;
            let scope_id = mapped(&plan.ids.scopes, source.scope_id)?;
            let name = if payload.kind == PackageKind::Profile {
                desired_profile_name.ok_or(ServiceError::Corrupt)?
            } else {
                &source.name
            };
            let activate_on_start = match &plan.mode {
                PackagePlanMode::ProfileCreate => false,
                PackagePlanMode::ProfileReplace {
                    existing_profile, ..
                } => existing_profile.activate_on_start,
                PackagePlanMode::Workspace => source.activate_on_start,
                PackagePlanMode::Skip | PackagePlanMode::Reject => {
                    return Err(ServiceError::Corrupt);
                }
            };
            let record = ProfileRecord {
                id,
                vault_id: self.vault_id,
                scope_id,
                encrypted_name: self.encrypt_entity_text(
                    EntityKind::Profile,
                    id.0,
                    "name",
                    name,
                )?,
                name_lookup: lookup_digest(
                    &self.master_key,
                    PROFILE_LOOKUP_DOMAIN,
                    normalize_name(name)?.as_bytes(),
                )
                .to_vec(),
                encrypted_description: self.encrypt_optional_entity_text(
                    EntityKind::Profile,
                    id.0,
                    "description",
                    source.description.as_deref(),
                )?,
                activate_on_start,
                generation: source.generation.max(1),
            };
            let is_update = matches!(plan.mode, PackagePlanMode::Workspace)
                && Some(id) == destination_base_id
                || matches!(plan.mode, PackagePlanMode::ProfileReplace { .. });
            if is_update {
                batch.profile_updates.push(record);
            } else {
                batch.profiles.push(record);
            }
        }
        Ok(())
    }

    fn append_import_secrets(
        &self,
        loaded: &LoadedPackage,
        plan: &PackagePlan,
        batch: &mut ImportBatch,
    ) -> Result<(), ServiceError> {
        let payload = &loaded.payload;
        for source in &payload.secrets {
            let id = mapped(&plan.ids.secrets, source.id)?;
            let scope_id = mapped(&plan.ids.scopes, source.scope_id)?;
            let record = SecretRecord {
                id,
                scope_id,
                encrypted_name: self.encrypt_entity_text(
                    EntityKind::Secret,
                    id.0,
                    "name",
                    &source.name,
                )?,
                name_lookup: lookup_digest(
                    &self.master_key,
                    SECRET_LOOKUP_DOMAIN,
                    normalize_name(&source.name)?.as_bytes(),
                )
                .to_vec(),
                encrypted_description: self.encrypt_optional_entity_text(
                    EntityKind::Secret,
                    id.0,
                    "description",
                    source.description.as_deref(),
                )?,
                current_version: source.current_version,
                status: source.status,
                value: None,
            };
            let value = source
                .value
                .as_ref()
                .map(|value| {
                    self.import_secret_value(
                        loaded,
                        source,
                        value,
                        &record,
                        mapped(&plan.ids.versions, value.id)?,
                    )
                })
                .transpose()?;
            batch.secrets.push(SecretRecord { value, ..record });
        }
        Ok(())
    }

    fn import_secret_value(
        &self,
        loaded: &LoadedPackage,
        source_secret: &PortableSecret,
        source_value: &PortableSecretValue,
        destination_secret: &SecretRecord,
        destination_value_id: SecretVersionId,
    ) -> Result<SecretValueRecord, ServiceError> {
        let transfer_wrap_aad = transfer_dek_aad(
            loaded.envelope.package_id,
            loaded.envelope.source_vault_id,
            source_secret.id,
            source_value.id,
            source_secret.scope_id,
            source_secret.current_version,
        );
        let dek = unwrap_key(
            &loaded.transfer_key,
            &Ciphertext::decode(&source_value.transfer_wrapped_dek)?,
            &transfer_wrap_aad,
        )
        .map_err(|_| ServiceError::InvalidPackage)?;
        let source_aad = secret_value_aad(
            loaded.envelope.source_vault_id,
            source_secret.id,
            source_value.id,
            source_secret.scope_id,
            source_secret.current_version,
        );
        if blake3::hash(&source_aad).as_bytes() != source_value.aad_digest.as_slice() {
            return Err(ServiceError::InvalidPackage);
        }
        let plaintext = decrypt(
            &dek,
            &Ciphertext::decode(&source_value.ciphertext)?,
            &source_aad,
        )
        .map_err(|_| ServiceError::InvalidPackage)?;
        let destination_aad = secret_value_aad(
            self.vault_id,
            destination_secret.id,
            destination_value_id,
            destination_secret.scope_id,
            destination_secret.current_version,
        );
        let ciphertext = if source_aad == destination_aad {
            source_value.ciphertext.clone()
        } else {
            encrypt(&dek, plaintext.as_ref(), &destination_aad)?.encode()
        };
        let destination_wrap_aad = secret_wrap_aad(
            self.vault_id,
            destination_secret.id,
            destination_value_id,
            destination_secret.scope_id,
            destination_secret.current_version,
        );
        Ok(SecretValueRecord {
            value_id: destination_value_id,
            ciphertext,
            wrapped_dek: wrap_key(&self.master_key, &dek, &destination_wrap_aad)?.encode(),
            aad_digest: blake3::hash(&destination_aad).as_bytes().to_vec(),
            generator: source_value.generator,
            generated_length: source_value.generated_length,
            entropy_bits: source_value.entropy_bits,
            created_at: source_value.created_at,
        })
    }

    fn plan_env_import(
        &self,
        profile_name: &str,
        input_path: &Path,
        strategy: ImportConflictStrategy,
    ) -> Result<EnvPlan, ServiceError> {
        if !matches!(
            strategy,
            ImportConflictStrategy::Abort
                | ImportConflictStrategy::Skip
                | ImportConflictStrategy::Replace
        ) {
            return Err(ServiceError::InvalidImportStrategy);
        }
        let bytes = Zeroizing::new(
            envault_platform::read_bounded_private_file(input_path, MAX_ENV_FILE_BYTES).map_err(
                |error| match error {
                    envault_platform::PlatformError::FileTooLarge => {
                        ServiceError::InvalidEnvFile { line: 1 }
                    }
                    error => ServiceError::Platform(error),
                },
            )?,
        );
        let source_digest = *blake3::hash(&bytes).as_bytes();
        let parsed = parse_env(&bytes)?;
        let profile = self.profile_by_name(profile_name)?;
        let mut entries = Vec::new();
        let mut views = Vec::new();
        let mut conflicts = Vec::new();
        for entry in parsed {
            let normalized = normalize_name(&entry.name)?;
            let lookup = lookup_digest(
                &self.master_key,
                SECRET_LOOKUP_DOMAIN,
                normalized.as_bytes(),
            );
            let existing = self.store.secret_by_lookup(profile.scope_id, &lookup)?;
            let action = match (&existing, strategy) {
                (None, _) => ImportAction::Create,
                (Some(_), ImportConflictStrategy::Skip) => ImportAction::Skip,
                (Some(existing), ImportConflictStrategy::Replace) if existing.status == 0 => {
                    ImportAction::Overwrite
                }
                (Some(_), ImportConflictStrategy::Abort | ImportConflictStrategy::Replace) => {
                    ImportAction::Reject
                }
                (Some(_), ImportConflictStrategy::Rename) => {
                    return Err(ServiceError::InvalidImportStrategy);
                }
            };
            if existing.is_some() {
                conflicts.push(ImportConflictView {
                    resource: "secret".to_owned(),
                    name: entry.name.clone(),
                    action,
                });
            }
            views.push(EnvImportEntryView {
                name: entry.name.clone(),
                value_bytes: u64::try_from(entry.value.len()).map_err(|_| ServiceError::Corrupt)?,
                action,
            });
            entries.push((entry, existing, action));
        }
        let state_digest = self.destination_state_digest()?;
        let plan_hash = self.compute_plan_hash(&PlanFingerprint {
            kind: PlanKind::Env,
            source_digest,
            package_id: None,
            destination_vault_id: self.vault_id,
            destination_state_digest: state_digest,
            profile_name: Some(profile_name),
            strategy,
            rename_to: None,
            actions: &conflicts,
        })?;
        let rejected = views
            .iter()
            .any(|entry| entry.action == ImportAction::Reject);
        Ok(EnvPlan {
            preview: EnvImportPreview {
                profile: profile_name.to_owned(),
                entries: views,
                strategy,
                plan_hash,
                warnings: vec![
                    "Values are redacted from preview output.".to_owned(),
                    "The plaintext source file remains on disk after import.".to_owned(),
                ],
            },
            profile,
            entries,
            rejected,
        })
    }

    fn compute_plan_hash(&self, fingerprint: &PlanFingerprint<'_>) -> Result<String, ServiceError> {
        let encoded = Zeroizing::new(super::encode_cbor(&fingerprint)?);
        Ok(URL_SAFE_NO_PAD.encode(lookup_digest(&self.master_key, PLAN_HASH_DOMAIN, &encoded)))
    }

    fn destination_state_digest(&self) -> Result<[u8; 32], ServiceError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"envault destination portability state v1");
        let mut scopes = self.store.scopes()?;
        scopes.sort_by_key(|record| record.id);
        for record in scopes {
            hash_state_field(&mut hasher, b"scope");
            hash_state_field(&mut hasher, record.id.0.as_bytes());
            hash_state_field(&mut hasher, record.vault_id.0.as_bytes());
            if let Some(parent) = record.parent_id {
                hash_state_field(&mut hasher, parent.0.as_bytes());
            } else {
                hash_state_field(&mut hasher, &[]);
            }
            hash_state_field(&mut hasher, &[record.kind]);
            hash_state_field(&mut hasher, &record.encrypted_path);
            hash_state_field(&mut hasher, &record.path_lookup);
        }
        let mut profiles = self.store.profiles()?;
        profiles.sort_by_key(|record| record.id);
        for record in profiles {
            hash_state_field(&mut hasher, b"profile");
            hash_state_field(&mut hasher, record.id.0.as_bytes());
            hash_state_field(&mut hasher, record.scope_id.0.as_bytes());
            hash_state_field(&mut hasher, &record.encrypted_name);
            hash_state_field(&mut hasher, &record.name_lookup);
            hash_state_field(
                &mut hasher,
                record.encrypted_description.as_deref().unwrap_or_default(),
            );
            hash_state_field(&mut hasher, &[u8::from(record.activate_on_start)]);
            hash_state_field(&mut hasher, &record.generation.to_be_bytes());
        }
        let mut secrets = self.store.secrets()?;
        secrets.sort_by_key(|record| record.id);
        for record in &secrets {
            hash_state_field(&mut hasher, b"secret");
            hash_state_field(&mut hasher, record.id.0.as_bytes());
            hash_state_field(&mut hasher, record.scope_id.0.as_bytes());
            hash_state_field(&mut hasher, &record.encrypted_name);
            hash_state_field(&mut hasher, &record.name_lookup);
            hash_state_field(
                &mut hasher,
                record.encrypted_description.as_deref().unwrap_or_default(),
            );
            hash_state_field(&mut hasher, &record.current_version.to_be_bytes());
            hash_state_field(&mut hasher, &[record.status]);
            if let Some(value) = &record.value {
                hash_state_field(&mut hasher, b"value");
                hash_state_field(&mut hasher, value.value_id.0.as_bytes());
                hash_state_field(&mut hasher, &value.ciphertext);
                hash_state_field(&mut hasher, &value.wrapped_dek);
                hash_state_field(&mut hasher, &value.aad_digest);
                if let Some(generator) = value.generator {
                    hash_state_field(&mut hasher, &[1, generator]);
                } else {
                    hash_state_field(&mut hasher, &[0]);
                }
                hash_state_field(
                    &mut hasher,
                    &value.generated_length.unwrap_or_default().to_be_bytes(),
                );
                hash_state_field(
                    &mut hasher,
                    &value.entropy_bits.unwrap_or_default().to_be_bytes(),
                );
                hash_state_field(&mut hasher, &value.created_at.to_be_bytes());
            }
        }
        let mut workspaces = self.store.workspaces()?;
        workspaces.sort_by_key(|record| record.id);
        for record in workspaces {
            hash_state_field(&mut hasher, b"workspace");
            hash_state_field(&mut hasher, record.id.0.as_bytes());
            hash_state_field(&mut hasher, &record.encrypted_name);
            hash_state_field(&mut hasher, &record.name_lookup);
        }
        let mut memberships = self.store.all_workspace_memberships()?;
        memberships.sort();
        for (workspace_id, profile_id) in memberships {
            hash_state_field(&mut hasher, b"workspace_membership");
            hash_state_field(&mut hasher, workspace_id.0.as_bytes());
            hash_state_field(&mut hasher, profile_id.0.as_bytes());
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn workspace_is_portably_empty(&self) -> Result<bool, ServiceError> {
        Ok(self.store.scopes()?.len() == 1
            && self.store.profiles()?.len() == 1
            && self.store.secrets()?.is_empty()
            && self.store.workspaces()?.is_empty())
    }

    fn destination_base_profile(&self) -> Result<ProfileRecord, ServiceError> {
        self.store
            .profiles()?
            .into_iter()
            .find(|profile| profile.scope_id == self.root_scope_id)
            .ok_or(ServiceError::Corrupt)
    }

    fn profile_subtree_scope_ids(&self, root: ScopeId) -> Result<Vec<ScopeId>, ServiceError> {
        let scopes = self.store.scopes()?;
        let profile_scope_ids = self
            .store
            .profiles()?
            .into_iter()
            .filter_map(|profile| (profile.scope_id != root).then_some(profile.scope_id))
            .collect::<BTreeSet<_>>();
        let mut selected = BTreeSet::from([root]);
        loop {
            let before = selected.len();
            for scope in &scopes {
                if scope
                    .parent_id
                    .is_some_and(|parent| selected.contains(&parent))
                    && !profile_scope_ids.contains(&scope.id)
                {
                    selected.insert(scope.id);
                }
            }
            if selected.len() == before {
                break;
            }
        }
        let mut ordered = selected.into_iter().collect::<Vec<_>>();
        ordered.sort_by_key(|id| scope_depth_records(&scopes, *id).unwrap_or(usize::MAX));
        Ok(ordered)
    }
}

fn load_package(
    input_path: &Path,
    transfer_password: Option<&SensitiveInput>,
    age_identity_path: Option<&Path>,
) -> Result<LoadedPackage, ServiceError> {
    if transfer_password.is_none() && age_identity_path.is_none() {
        return Err(ServiceError::PackageAuthenticationFailed);
    }
    if let Some(password) = transfer_password {
        validate_transfer_password(password)?;
    }
    let bytes = Zeroizing::new(
        envault_platform::read_bounded_regular_file(input_path, MAX_PORTABILITY_PACKAGE_BYTES)
            .map_err(|error| match error {
                envault_platform::PlatformError::FileTooLarge => ServiceError::InvalidPackage,
                error => ServiceError::Platform(error),
            })?,
    );
    let source_digest = *blake3::hash(&bytes).as_bytes();
    let envelope: PackageEnvelope =
        super::decode_cbor(&bytes).map_err(|_| ServiceError::InvalidPackage)?;
    validate_envelope(&envelope)?;
    validate_package_suffix(input_path, envelope.kind)?;
    let identity = age_identity_path.map(read_age_identity).transpose()?;
    let mut transfer_key = None;
    for slot in &envelope.key_slots {
        let candidate = match slot {
            KeySlot::Password {
                parameters,
                salt,
                wrapped_transfer_key,
            } => transfer_password.and_then(|password| {
                derive_key(password.secret().as_ref(), salt, *parameters)
                    .ok()
                    .and_then(|password_key| {
                        Ciphertext::decode(wrapped_transfer_key)
                            .ok()
                            .and_then(|ciphertext| {
                                unwrap_key(
                                    &password_key,
                                    &ciphertext,
                                    &password_slot_aad(
                                        envelope.package_id,
                                        envelope.kind,
                                        envelope.source_vault_id,
                                    ),
                                )
                                .ok()
                            })
                    })
            }),
            KeySlot::AgeX25519 {
                encrypted_transfer_key,
            } => identity.as_ref().and_then(|identity| {
                age::decrypt(identity, encrypted_transfer_key)
                    .ok()
                    .and_then(|mut bytes| {
                        let key_bytes: Result<[u8; KEY_BYTES], _> = bytes.as_slice().try_into();
                        bytes.zeroize();
                        key_bytes.ok().map(SecretKey::from_bytes)
                    })
            }),
        };
        if candidate.is_some() {
            transfer_key = candidate;
            break;
        }
    }
    let transfer_key = transfer_key.ok_or(ServiceError::PackageAuthenticationFailed)?;
    let payload_aad = package_aad(
        envelope.package_id,
        envelope.kind,
        envelope.source_vault_id,
        envelope.created_at,
        envelope.version,
    );
    let payload_bytes = decrypt(
        &transfer_key,
        &Ciphertext::decode(&envelope.payload_ciphertext)
            .map_err(|_| ServiceError::InvalidPackage)?,
        &payload_aad,
    )
    .map_err(|_| ServiceError::PackageAuthenticationFailed)?;
    let payload: PackagePayload =
        super::decode_cbor(payload_bytes.as_ref()).map_err(|_| ServiceError::InvalidPackage)?;
    validate_payload(&payload)?;
    if payload.version != envelope.version
        || payload.package_id != envelope.package_id
        || payload.kind != envelope.kind
        || payload.source_vault_id != envelope.source_vault_id
        || payload.created_at != envelope.created_at
    {
        return Err(ServiceError::InvalidPackage);
    }
    validate_payload_crypto(&payload, &transfer_key)?;
    Ok(LoadedPackage {
        envelope,
        payload,
        transfer_key,
        source_digest,
    })
}

fn validate_envelope(envelope: &PackageEnvelope) -> Result<(), ServiceError> {
    if envelope.magic != PACKAGE_MAGIC
        || envelope.package_id.is_nil()
        || envelope.source_vault_id.0.is_nil()
        || envelope.created_at < 0
        || envelope.key_slots.is_empty()
        || envelope.key_slots.len() > MAX_PORTABILITY_KEY_SLOTS
        || envelope.payload_ciphertext.len() > MAX_PORTABILITY_PACKAGE_BYTES
    {
        return Err(ServiceError::InvalidPackage);
    }
    if envelope.version != PACKAGE_VERSION {
        return Err(ServiceError::UnsupportedPackageVersion);
    }
    let mut password_slots = 0_usize;
    for slot in &envelope.key_slots {
        match slot {
            KeySlot::Password {
                parameters,
                wrapped_transfer_key,
                ..
            } => {
                password_slots = password_slots.saturating_add(1);
                if !(TRANSFER_KDF_MIN_MEMORY_KIB..=TRANSFER_KDF_MAX_MEMORY_KIB)
                    .contains(&parameters.memory_kib)
                    || !(1..=TRANSFER_KDF_MAX_ITERATIONS).contains(&parameters.iterations)
                    || !(1..=TRANSFER_KDF_MAX_PARALLELISM).contains(&parameters.parallelism)
                {
                    return Err(ServiceError::InvalidPackage);
                }
                Ciphertext::decode(wrapped_transfer_key)
                    .map_err(|_| ServiceError::InvalidPackage)?;
            }
            KeySlot::AgeX25519 {
                encrypted_transfer_key,
            } => {
                if encrypted_transfer_key.is_empty()
                    || encrypted_transfer_key.len() > MAX_AGE_SLOT_BYTES
                {
                    return Err(ServiceError::InvalidPackage);
                }
            }
        }
    }
    if password_slots > 1 {
        return Err(ServiceError::InvalidPackage);
    }
    Ok(())
}

fn validate_payload(payload: &PackagePayload) -> Result<(), ServiceError> {
    validate_payload_header(payload)?;
    let ids = payload_ids(payload)?;
    validate_payload_scopes_and_profiles(payload, &ids.scopes)?;
    validate_payload_secrets(payload, &ids.scopes)?;
    Ok(())
}

struct PayloadIds {
    scopes: BTreeSet<ScopeId>,
}

fn validate_payload_header(payload: &PackagePayload) -> Result<(), ServiceError> {
    if payload.version != PACKAGE_VERSION
        || payload.package_id.is_nil()
        || payload.source_vault_id.0.is_nil()
        || payload.scopes.is_empty()
        || payload.profiles.is_empty()
    {
        return Err(ServiceError::InvalidPackage);
    }
    if payload.kind == PackageKind::Profile && payload.profiles.len() != 1 {
        return Err(ServiceError::InvalidPackage);
    }
    let total = payload
        .scopes
        .len()
        .saturating_add(payload.profiles.len())
        .saturating_add(payload.secrets.len())
        .saturating_add(
            payload
                .secrets
                .iter()
                .filter(|secret| secret.value.is_some())
                .count(),
        );
    if total > MAX_PORTABILITY_ENTITIES {
        return Err(ServiceError::InvalidPackage);
    }
    Ok(())
}

fn payload_ids(payload: &PackagePayload) -> Result<PayloadIds, ServiceError> {
    ensure_unique(payload.scopes.iter().map(|scope| scope.id.0))?;
    ensure_unique(payload.profiles.iter().map(|profile| profile.id.0))?;
    ensure_unique(payload.secrets.iter().map(|secret| secret.id.0))?;
    Ok(PayloadIds {
        scopes: payload.scopes.iter().map(|scope| scope.id).collect(),
    })
}

fn validate_payload_scopes_and_profiles(
    payload: &PackagePayload,
    scope_ids: &BTreeSet<ScopeId>,
) -> Result<(), ServiceError> {
    let roots = payload
        .scopes
        .iter()
        .filter(|scope| scope.parent_id.is_none())
        .count();
    if roots != 1 {
        return Err(ServiceError::InvalidPackage);
    }
    let root = payload_root_scope(payload)?;
    if (payload.kind == PackageKind::Workspace && root.kind != 0)
        || payload
            .scopes
            .iter()
            .any(|scope| scope.id != root.id && scope.kind == 0)
    {
        return Err(ServiceError::InvalidPackage);
    }
    let scopes_by_id = payload
        .scopes
        .iter()
        .map(|scope| (scope.id, scope))
        .collect::<BTreeMap<_, _>>();
    let mut scope_paths = BTreeSet::new();
    for scope in &payload.scopes {
        validate_portable_text(&scope.path, MAX_NAME_BYTES.saturating_mul(64))?;
        if !scope_paths.insert(scope.path.clone())
            || scope.kind > scope_policy::scope_kind_code(ScopeKind::Project)
            || scope
                .parent_id
                .is_some_and(|parent| !scope_ids.contains(&parent))
            || scope_depth(payload, scope.id).is_none()
        {
            return Err(ServiceError::InvalidPackage);
        }
        if let Some(parent_id) = scope.parent_id {
            let parent = scopes_by_id
                .get(&parent_id)
                .ok_or(ServiceError::InvalidPackage)?;
            let expected_prefix = format!("{}/", parent.path);
            if !scope.path.starts_with(&expected_prefix)
                || scope.path.len() == expected_prefix.len()
            {
                return Err(ServiceError::InvalidPackage);
            }
        }
    }
    let mut profile_names = BTreeSet::new();
    let mut profile_scopes = BTreeSet::new();
    for profile in &payload.profiles {
        let normalized = normalize_name(&profile.name).map_err(|_| ServiceError::InvalidPackage)?;
        profile
            .description
            .as_deref()
            .map(envault_core::validate_description)
            .transpose()
            .map_err(|_| ServiceError::InvalidPackage)?;
        if !scope_ids.contains(&profile.scope_id)
            || profile.generation == 0
            || !profile_names.insert(normalized)
            || !profile_scopes.insert(profile.scope_id)
        {
            return Err(ServiceError::InvalidPackage);
        }
    }
    validate_profile_scope_relationships(payload, root, &scopes_by_id, &profile_scopes)?;
    if payload.kind == PackageKind::Workspace
        && payload
            .profiles
            .iter()
            .filter(|profile| profile.activate_on_start)
            .count()
            != 1
    {
        return Err(ServiceError::InvalidPackage);
    }
    Ok(())
}

fn validate_profile_scope_relationships(
    payload: &PackagePayload,
    root: &PortableScope,
    scopes_by_id: &BTreeMap<ScopeId, &PortableScope>,
    profile_scopes: &BTreeSet<ScopeId>,
) -> Result<(), ServiceError> {
    if payload.kind == PackageKind::Profile && payload.profiles[0].scope_id != root.id {
        return Err(ServiceError::InvalidPackage);
    }
    if payload.kind == PackageKind::Workspace {
        let _ = payload_base_profile(payload, root.id)?;
        for profile in &payload.profiles {
            if profile.scope_id == root.id {
                continue;
            }
            let scope = scopes_by_id
                .get(&profile.scope_id)
                .ok_or(ServiceError::InvalidPackage)?;
            if scope.kind != scope_policy::scope_kind_code(ScopeKind::Profile)
                || scope.parent_id != Some(root.id)
            {
                return Err(ServiceError::InvalidPackage);
            }
        }
    }
    if payload.scopes.iter().any(|scope| {
        scope.kind == scope_policy::scope_kind_code(ScopeKind::Profile)
            && !profile_scopes.contains(&scope.id)
    }) {
        return Err(ServiceError::InvalidPackage);
    }
    Ok(())
}

fn validate_payload_secrets(
    payload: &PackagePayload,
    scope_ids: &BTreeSet<ScopeId>,
) -> Result<(), ServiceError> {
    let mut value_ids = BTreeSet::new();
    let mut secret_names = BTreeSet::new();
    for secret in &payload.secrets {
        let normalized = normalize_name(&secret.name).map_err(|_| ServiceError::InvalidPackage)?;
        secret
            .description
            .as_deref()
            .map(envault_core::validate_description)
            .transpose()
            .map_err(|_| ServiceError::InvalidPackage)?;
        if !scope_ids.contains(&secret.scope_id)
            || !secret_names.insert((secret.scope_id, normalized))
            || secret.status > 1
            || (secret.status == 0 && secret.current_version == 0)
            || (secret.status == 1 && secret.current_version != 0)
            || (secret.status == 0) != secret.value.is_some()
        {
            return Err(ServiceError::InvalidPackage);
        }
        if let Some(value) = &secret.value {
            if value.id.0.is_nil()
                || !value_ids.insert(value.id)
                || value.ciphertext.len() > MAX_SECRET_VALUE_BYTES.saturating_add(64)
                || value.transfer_wrapped_dek.len() > 256
                || value.aad_digest.len() != 32
                || value.created_at < 0
                || match value.generator {
                    Some(1..=3) => value.generated_length.is_none() || value.entropy_bits.is_none(),
                    None => value.generated_length.is_some() || value.entropy_bits.is_some(),
                    Some(_) => true,
                }
            {
                return Err(ServiceError::InvalidPackage);
            }
            Ciphertext::decode(&value.ciphertext).map_err(|_| ServiceError::InvalidPackage)?;
            Ciphertext::decode(&value.transfer_wrapped_dek)
                .map_err(|_| ServiceError::InvalidPackage)?;
        }
    }
    Ok(())
}

fn validate_payload_crypto(
    payload: &PackagePayload,
    transfer_key: &SecretKey,
) -> Result<(), ServiceError> {
    for secret in &payload.secrets {
        let Some(value) = &secret.value else {
            continue;
        };
        let transfer_aad = transfer_dek_aad(
            payload.package_id,
            payload.source_vault_id,
            secret.id,
            value.id,
            secret.scope_id,
            secret.current_version,
        );
        let dek = unwrap_key(
            transfer_key,
            &Ciphertext::decode(&value.transfer_wrapped_dek)?,
            &transfer_aad,
        )
        .map_err(|_| ServiceError::InvalidPackage)?;
        let value_aad = secret_value_aad(
            payload.source_vault_id,
            secret.id,
            value.id,
            secret.scope_id,
            secret.current_version,
        );
        if blake3::hash(&value_aad).as_bytes() != value.aad_digest.as_slice() {
            return Err(ServiceError::InvalidPackage);
        }
        let plaintext = decrypt(&dek, &Ciphertext::decode(&value.ciphertext)?, &value_aad)
            .map_err(|_| ServiceError::InvalidPackage)?;
        validate_generator_metadata(value, plaintext.as_ref())?;
    }
    Ok(())
}

fn validate_generator_metadata(
    version: &PortableSecretValue,
    plaintext: &[u8],
) -> Result<(), ServiceError> {
    let (Some(generator), Some(length), Some(entropy_bits)) = (
        version.generator,
        version.generated_length,
        version.entropy_bits,
    ) else {
        return if version.generator.is_none()
            && version.generated_length.is_none()
            && version.entropy_bits.is_none()
        {
            Ok(())
        } else {
            Err(ServiceError::InvalidPackage)
        };
    };
    if usize::try_from(length).ok() != Some(plaintext.len()) || length == 0 || entropy_bits == 0 {
        return Err(ServiceError::InvalidPackage);
    }
    match generator {
        1 => {
            let text = std::str::from_utf8(plaintext).map_err(|_| ServiceError::InvalidPackage)?;
            let uuid = Uuid::parse_str(text).map_err(|_| ServiceError::InvalidPackage)?;
            if text.len() != 36
                || uuid.get_version_num() != 4
                || uuid.hyphenated().to_string() != text
                || entropy_bits != 122
            {
                return Err(ServiceError::InvalidPackage);
            }
        }
        2 => {
            if !plaintext
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(ServiceError::InvalidPackage);
            }
            let character_entropy = u32::try_from(plaintext.len().saturating_mul(6))
                .map_err(|_| ServiceError::InvalidPackage)?;
            let encoded_entropy = URL_SAFE_NO_PAD.decode(plaintext).ok().and_then(|decoded| {
                (URL_SAFE_NO_PAD.encode(&decoded).as_bytes() == plaintext)
                    .then(|| u32::try_from(decoded.len().saturating_mul(8)).ok())
                    .flatten()
            });
            if entropy_bits != character_entropy && encoded_entropy != Some(entropy_bits) {
                return Err(ServiceError::InvalidPackage);
            }
        }
        3 => {
            let decoded = STANDARD
                .decode(plaintext)
                .map_err(|_| ServiceError::InvalidPackage)?;
            let expected_entropy = u32::try_from(decoded.len().saturating_mul(8))
                .map_err(|_| ServiceError::InvalidPackage)?;
            if STANDARD.encode(&decoded).as_bytes() != plaintext || entropy_bits != expected_entropy
            {
                return Err(ServiceError::InvalidPackage);
            }
        }
        _ => return Err(ServiceError::InvalidPackage),
    }
    Ok(())
}

fn validate_transfer_password(password: &SensitiveInput) -> Result<(), ServiceError> {
    if (TRANSFER_PASSWORD_MIN_BYTES..=TRANSFER_PASSWORD_MAX_BYTES).contains(&password.len()) {
        Ok(())
    } else {
        Err(ServiceError::InvalidPasswordLength)
    }
}

fn validate_package_suffix(path: &Path, kind: PackageKind) -> Result<(), ServiceError> {
    let expected = match kind {
        PackageKind::Profile => "envault-profile",
        PackageKind::Workspace => "envault-workspace",
    };
    if path.extension().and_then(|extension| extension.to_str()) == Some(expected) {
        Ok(())
    } else {
        Err(ServiceError::InvalidPackage)
    }
}

fn payload_counts(payload: &PackagePayload) -> Result<PortabilityCounts, ServiceError> {
    Ok(PortabilityCounts {
        scopes: u64::try_from(payload.scopes.len()).map_err(|_| ServiceError::InvalidPackage)?,
        profiles: u64::try_from(payload.profiles.len())
            .map_err(|_| ServiceError::InvalidPackage)?,
        secrets: u64::try_from(payload.secrets.len()).map_err(|_| ServiceError::InvalidPackage)?,
        workspaces: u64::try_from(payload.workspaces.len())
            .map_err(|_| ServiceError::InvalidPackage)?,
        memberships: u64::try_from(payload.memberships.len())
            .map_err(|_| ServiceError::InvalidPackage)?,
    })
}

fn select_export_scopes(
    kind: PackageKind,
    selected_profile: Option<&ProfileRecord>,
    scopes: &[ScopeRecord],
    profiles: &[ProfileRecord],
) -> Result<BTreeSet<ScopeId>, ServiceError> {
    if kind == PackageKind::Workspace {
        return Ok(scopes.iter().map(|scope| scope.id).collect());
    }
    let root = selected_profile
        .ok_or(ServiceError::InvalidPackage)?
        .scope_id;
    let excluded_profile_scopes = profiles
        .iter()
        .filter_map(|profile| (profile.scope_id != root).then_some(profile.scope_id))
        .collect::<BTreeSet<_>>();
    let mut selected = BTreeSet::from([root]);
    loop {
        let before = selected.len();
        for scope in scopes {
            if scope
                .parent_id
                .is_some_and(|parent| selected.contains(&parent))
                && !excluded_profile_scopes.contains(&scope.id)
            {
                selected.insert(scope.id);
            }
        }
        if selected.len() == before {
            break;
        }
    }
    Ok(selected)
}

fn payload_root_scope(payload: &PackagePayload) -> Result<&PortableScope, ServiceError> {
    let mut roots = payload
        .scopes
        .iter()
        .filter(|scope| scope.parent_id.is_none());
    let root = roots.next().ok_or(ServiceError::InvalidPackage)?;
    if roots.next().is_some() {
        return Err(ServiceError::InvalidPackage);
    }
    Ok(root)
}

fn payload_base_profile(
    payload: &PackagePayload,
    root_scope_id: ScopeId,
) -> Result<&PortableProfile, ServiceError> {
    let mut profiles = payload
        .profiles
        .iter()
        .filter(|profile| profile.scope_id == root_scope_id);
    let profile = profiles.next().ok_or(ServiceError::InvalidPackage)?;
    if profiles.next().is_some() {
        return Err(ServiceError::InvalidPackage);
    }
    Ok(profile)
}

fn profile_import_action(name: &str, action: ImportAction) -> ImportConflictView {
    ImportConflictView {
        resource: "profile".to_owned(),
        name: name.to_owned(),
        action,
    }
}

#[allow(clippy::too_many_arguments)]
fn map_workspace_ids(
    payload: &PackagePayload,
    scope_ids: &mut BTreeMap<ScopeId, ScopeId>,
    profile_ids: &mut BTreeMap<ProfileId, ProfileId>,
    secret_ids: &mut BTreeMap<SecretId, SecretId>,
    version_ids: &mut BTreeMap<SecretVersionId, SecretVersionId>,
) {
    for scope in &payload.scopes {
        scope_ids.entry(scope.id).or_insert(scope.id);
    }
    for profile in &payload.profiles {
        profile_ids.entry(profile.id).or_insert(profile.id);
    }
    for secret in &payload.secrets {
        secret_ids.entry(secret.id).or_insert(secret.id);
        if let Some(value) = &secret.value {
            version_ids.entry(value.id).or_insert(value.id);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn map_profile_ids(
    package_id: Uuid,
    vault_id: VaultId,
    destination_profile_name: &str,
    payload: &PackagePayload,
    scope_ids: &mut BTreeMap<ScopeId, ScopeId>,
    profile_ids: &mut BTreeMap<ProfileId, ProfileId>,
    secret_ids: &mut BTreeMap<SecretId, SecretId>,
    version_ids: &mut BTreeMap<SecretVersionId, SecretVersionId>,
) {
    for scope in &payload.scopes {
        scope_ids.entry(scope.id).or_insert_with(|| {
            ScopeId(mapped_uuid(
                package_id,
                vault_id,
                destination_profile_name,
                scope.id.0,
                b"scope",
            ))
        });
    }
    for profile in &payload.profiles {
        profile_ids.entry(profile.id).or_insert_with(|| {
            ProfileId(mapped_uuid(
                package_id,
                vault_id,
                destination_profile_name,
                profile.id.0,
                b"profile",
            ))
        });
    }
    for secret in &payload.secrets {
        secret_ids.entry(secret.id).or_insert_with(|| {
            SecretId(mapped_uuid(
                package_id,
                vault_id,
                destination_profile_name,
                secret.id.0,
                b"secret",
            ))
        });
        if let Some(value) = &secret.value {
            version_ids.entry(value.id).or_insert_with(|| {
                SecretVersionId(mapped_uuid(
                    package_id,
                    vault_id,
                    destination_profile_name,
                    value.id.0,
                    b"version",
                ))
            });
        }
    }
}

fn mapped_uuid(
    package_id: Uuid,
    vault_id: VaultId,
    destination_profile_name: &str,
    source_id: Uuid,
    domain: &[u8],
) -> Uuid {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"envault portability id map v1");
    hasher.update(package_id.as_bytes());
    hasher.update(vault_id.0.as_bytes());
    hash_state_field(&mut hasher, destination_profile_name.as_bytes());
    hasher.update(source_id.as_bytes());
    hasher.update(domain);
    let mut bytes = *hasher.finalize().as_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes[..16].try_into().expect("slice length"))
}

fn mapped<K: Ord + Copy, V: Copy>(map: &BTreeMap<K, V>, key: K) -> Result<V, ServiceError> {
    map.get(&key).copied().ok_or(ServiceError::InvalidPackage)
}

fn remap_scope_path(
    source: &str,
    source_root: &str,
    destination_root: &str,
) -> Result<String, ServiceError> {
    if source == source_root {
        return Ok(destination_root.to_owned());
    }
    let suffix = source
        .strip_prefix(source_root)
        .filter(|suffix| suffix.starts_with('/'))
        .ok_or(ServiceError::InvalidPackage)?;
    Ok(format!("{destination_root}{suffix}"))
}

fn scope_depth(payload: &PackagePayload, scope_id: ScopeId) -> Option<usize> {
    let mut depth = 0_usize;
    let mut current = Some(scope_id);
    let mut seen = BTreeSet::new();
    while let Some(id) = current {
        if !seen.insert(id) || depth > envault_core::MAX_SCOPE_DEPTH {
            return None;
        }
        let scope = payload.scopes.iter().find(|scope| scope.id == id)?;
        current = scope.parent_id;
        depth = depth.checked_add(1)?;
    }
    Some(depth)
}

fn scope_depth_records(scopes: &[ScopeRecord], scope_id: ScopeId) -> Option<usize> {
    let mut depth = 0_usize;
    let mut current = Some(scope_id);
    let mut seen = BTreeSet::new();
    while let Some(id) = current {
        if !seen.insert(id) || depth > envault_core::MAX_SCOPE_DEPTH {
            return None;
        }
        let scope = scopes.iter().find(|scope| scope.id == id)?;
        current = scope.parent_id;
        depth = depth.checked_add(1)?;
    }
    Some(depth)
}

fn package_aad(
    package_id: Uuid,
    kind: PackageKind,
    source_vault_id: VaultId,
    created_at: i64,
    version: u16,
) -> Vec<u8> {
    aad(&[
        b"envault-portability-payload",
        PACKAGE_MAGIC,
        &version.to_be_bytes(),
        &[package_kind_code(kind)],
        package_id.as_bytes(),
        source_vault_id.0.as_bytes(),
        &created_at.to_be_bytes(),
        ALGORITHM_VERSION,
    ])
}

fn password_slot_aad(package_id: Uuid, kind: PackageKind, source_vault_id: VaultId) -> Vec<u8> {
    aad(&[
        b"envault-portability-password-slot",
        package_id.as_bytes(),
        &[package_kind_code(kind)],
        source_vault_id.0.as_bytes(),
        ALGORITHM_VERSION,
    ])
}

fn transfer_dek_aad(
    package_id: Uuid,
    source_vault_id: VaultId,
    secret_id: SecretId,
    version_id: SecretVersionId,
    scope_id: ScopeId,
    version: u64,
) -> Vec<u8> {
    aad(&[
        b"envault-portability-dek",
        package_id.as_bytes(),
        source_vault_id.0.as_bytes(),
        secret_id.0.as_bytes(),
        version_id.0.as_bytes(),
        scope_id.0.as_bytes(),
        &version.to_be_bytes(),
        ALGORITHM_VERSION,
    ])
}

fn aad(parts: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    for part in parts {
        let length = u32::try_from(part.len()).expect("bounded AAD component");
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(part);
    }
    output
}

const fn package_kind_code(kind: PackageKind) -> u8 {
    match kind {
        PackageKind::Profile => 1,
        PackageKind::Workspace => 2,
    }
}

fn write_private_no_replace(path: &Path, bytes: &[u8]) -> Result<(), ServiceError> {
    let parent = path.parent().ok_or(ServiceError::InvalidPath)?;
    if !parent.is_dir() {
        return Err(ServiceError::InvalidPath);
    }
    let temporary = parent.join(format!(".envault-package-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = envault_platform::create_private_file(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        envault_platform::publish_private_file_no_replace(&temporary, path)?;
        Ok::<(), ServiceError>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(map_private_publish_error)
}

fn write_plaintext_no_replace(path: &Path, bytes: &[u8]) -> Result<(), ServiceError> {
    let mut file =
        envault_platform::create_private_file(path).map_err(map_private_publish_error)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    envault_platform::validate_private_file_path(path, &file)?;
    Ok(())
}

fn map_private_publish_error(error: impl Into<ServiceError>) -> ServiceError {
    let error = error.into();
    match error {
        ServiceError::Platform(envault_platform::PlatformError::Io(error))
        | ServiceError::Io(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            ServiceError::Conflict
        }
        error => error,
    }
}

fn read_age_identity(path: &Path) -> Result<age::x25519::Identity, ServiceError> {
    let bytes = Zeroizing::new(
        envault_platform::read_bounded_private_file(path, 64 * 1024).map_err(
            |error| match error {
                envault_platform::PlatformError::FileTooLarge => {
                    ServiceError::PackageAuthenticationFailed
                }
                error => ServiceError::Platform(error),
            },
        )?,
    );
    let text =
        std::str::from_utf8(&bytes).map_err(|_| ServiceError::PackageAuthenticationFailed)?;
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find_map(|line| age::x25519::Identity::from_str(line).ok())
        .ok_or(ServiceError::PackageAuthenticationFailed)
}

fn parse_env(bytes: &[u8]) -> Result<Vec<ParsedEnvEntry>, ServiceError> {
    if bytes.contains(&0) {
        return Err(ServiceError::InvalidEnvFile { line: 1 });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ServiceError::InvalidEnvFile { line: 1 })?;
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        if raw_line.len() > MAX_ENV_LINE_BYTES {
            return Err(ServiceError::InvalidEnvFile { line: line_number });
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let assignment = line.strip_prefix("export ").unwrap_or(line);
        let (name, raw_value) = assignment
            .split_once('=')
            .ok_or(ServiceError::InvalidEnvFile { line: line_number })?;
        let name = name.trim();
        if !valid_env_name(name) || !names.insert(name.to_owned()) {
            return Err(ServiceError::InvalidEnvFile { line: line_number });
        }
        let value = parse_env_value(raw_value, line_number)?;
        if value.len() > MAX_SECRET_VALUE_BYTES {
            return Err(ServiceError::InvalidEnvFile { line: line_number });
        }
        entries.push(ParsedEnvEntry {
            name: name.to_owned(),
            value: Zeroizing::new(value),
        });
    }
    if entries.len() > MAX_PORTABILITY_ENTITIES {
        return Err(ServiceError::InvalidEnvFile { line: 1 });
    }
    if entries.is_empty() {
        return Err(ServiceError::InvalidEnvFile { line: 1 });
    }
    Ok(entries)
}

fn parse_env_value(raw: &str, line: u64) -> Result<Vec<u8>, ServiceError> {
    let trimmed = raw.trim_start();
    if let Some(rest) = trimmed.strip_prefix('"') {
        let mut output = Vec::new();
        let mut escaped = false;
        let mut closed_at = None;
        for (index, character) in rest.char_indices() {
            if escaped {
                match character {
                    'n' => output.push(b'\n'),
                    'r' => output.push(b'\r'),
                    't' => output.push(b'\t'),
                    '\\' => output.push(b'\\'),
                    '"' => output.push(b'"'),
                    _ => return Err(ServiceError::InvalidEnvFile { line }),
                }
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                closed_at = Some(index + character.len_utf8());
                break;
            } else {
                let mut buffer = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
        }
        if escaped {
            return Err(ServiceError::InvalidEnvFile { line });
        }
        let closed_at = closed_at.ok_or(ServiceError::InvalidEnvFile { line })?;
        let trailing = rest[closed_at..].trim();
        if !trailing.is_empty() && !trailing.starts_with('#') {
            return Err(ServiceError::InvalidEnvFile { line });
        }
        return Ok(output);
    }
    if let Some(rest) = trimmed.strip_prefix('\'') {
        let end = rest
            .find('\'')
            .ok_or(ServiceError::InvalidEnvFile { line })?;
        let trailing = rest[end + 1..].trim();
        if !trailing.is_empty() && !trailing.starts_with('#') {
            return Err(ServiceError::InvalidEnvFile { line });
        }
        return Ok(rest.as_bytes()[..end].to_vec());
    }
    let unquoted = trimmed.trim_end();
    let value = unquoted
        .char_indices()
        .find_map(|(index, character)| {
            (character == '#' && index > 0 && unquoted[..index].ends_with(char::is_whitespace))
                .then_some(&unquoted[..index])
        })
        .unwrap_or(unquoted)
        .trim_end();
    Ok(value.as_bytes().to_vec())
}

fn valid_env_name(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some('_' | 'A'..='Z' | 'a'..='z'))
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
        && name.len() <= MAX_NAME_BYTES
}

fn append_env_escaped(output: &mut Vec<u8>, value: &str) -> Result<(), ServiceError> {
    for character in value.chars() {
        match character {
            '\0' => return Err(ServiceError::PlaintextExportUnsupported),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            '\\' => output.extend_from_slice(b"\\\\"),
            '"' => output.extend_from_slice(b"\\\""),
            _ => {
                let mut buffer = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    Ok(())
}

fn validate_plan_hash(value: &str) -> Result<(), ServiceError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|_| ServiceError::StaleImportPlan)?;
    if decoded.len() == 32 {
        Ok(())
    } else {
        Err(ServiceError::StaleImportPlan)
    }
}

fn constant_time_text_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hash_state_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn ensure_unique(ids: impl Iterator<Item = Uuid>) -> Result<(), ServiceError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if id.is_nil() || !seen.insert(id) {
            return Err(ServiceError::InvalidPackage);
        }
    }
    Ok(())
}

fn validate_portable_text(value: &str, maximum_bytes: usize) -> Result<(), ServiceError> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        Err(ServiceError::InvalidPackage)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER_PASSWORD: &[u8] = b"correct horse battery staple";
    const TRANSFER_PASSWORD: &[u8] = b"portable transfer password";

    fn test_session(path: &Path) -> VaultSession {
        let password = SensitiveInput::copy_from_slice(MASTER_PASSWORD);
        crate::initialize_with_parameters(
            path,
            &password,
            KdfParameters {
                memory_kib: 8 * 1024,
                iterations: 1,
                parallelism: 1,
            },
        )
        .expect("initialize");
        VaultSession::unlock(path, &password).expect("unlock")
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = envault_platform::create_private_file(path).expect("private file");
        file.write_all(bytes).expect("write");
        file.sync_all().expect("sync");
    }

    fn secret_value(session: &VaultSession, secret_id: SecretId) -> Vec<u8> {
        let secret = session
            .store
            .secret_by_id(secret_id)
            .expect("lookup")
            .expect("secret");
        session
            .decrypt_secret_value(&secret)
            .expect("decrypt")
            .into_vec()
    }

    fn mutate_authenticated_password_payload(
        source: &Path,
        destination: &Path,
        mutate: impl FnOnce(&mut PackagePayload),
    ) {
        let bytes = std::fs::read(source).expect("package bytes");
        let mut envelope: PackageEnvelope = super::super::decode_cbor(&bytes).expect("envelope");
        let (parameters, salt, wrapped_transfer_key) = envelope
            .key_slots
            .iter()
            .find_map(|slot| match slot {
                KeySlot::Password {
                    parameters,
                    salt,
                    wrapped_transfer_key,
                } => Some((*parameters, *salt, wrapped_transfer_key)),
                KeySlot::AgeX25519 { .. } => None,
            })
            .expect("password slot");
        let password_key = derive_key(TRANSFER_PASSWORD, &salt, parameters).expect("password key");
        let transfer_key = unwrap_key(
            &password_key,
            &Ciphertext::decode(wrapped_transfer_key).expect("wrapped transfer key"),
            &password_slot_aad(envelope.package_id, envelope.kind, envelope.source_vault_id),
        )
        .expect("transfer key");
        let payload_aad = package_aad(
            envelope.package_id,
            envelope.kind,
            envelope.source_vault_id,
            envelope.created_at,
            envelope.version,
        );
        let payload_bytes = decrypt(
            &transfer_key,
            &Ciphertext::decode(&envelope.payload_ciphertext).expect("payload ciphertext"),
            &payload_aad,
        )
        .expect("payload plaintext");
        let mut payload: PackagePayload =
            super::super::decode_cbor(payload_bytes.as_ref()).expect("payload");
        mutate(&mut payload);
        let encoded_payload = Zeroizing::new(super::super::encode_cbor(&payload).expect("encode"));
        envelope.payload_ciphertext = encrypt(&transfer_key, &encoded_payload, &payload_aad)
            .expect("encrypt")
            .encode();
        let encoded_envelope = super::super::encode_cbor(&envelope).expect("encode envelope");
        write_private(destination, &encoded_envelope);
    }

    fn generated_value(generator: u8, value: &[u8], entropy_bits: u32) -> PortableSecretValue {
        PortableSecretValue {
            id: SecretVersionId(Uuid::new_v4()),
            ciphertext: Vec::new(),
            transfer_wrapped_dek: Vec::new(),
            aad_digest: Vec::new(),
            generator: Some(generator),
            generated_length: Some(u64::try_from(value.len()).expect("bounded test value")),
            entropy_bits: Some(entropy_bits),
            created_at: 1,
        }
    }

    #[test]
    fn env_parser_is_literal_and_redacts_nothing_into_names() {
        let parsed = parse_env(
            b"# comment\nexport API_TOKEN=literal-$HOME\nQUOTED=\"line\\nvalue\"\nSINGLE='raw value'\n",
        )
        .expect("parse");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].name, "API_TOKEN");
        assert_eq!(parsed[0].value.as_slice(), b"literal-$HOME");
        assert_eq!(parsed[1].value.as_slice(), b"line\nvalue");
        assert_eq!(parsed[2].value.as_slice(), b"raw value");
    }

    #[test]
    fn env_parser_rejects_duplicates_and_unsupported_escapes() {
        assert!(parse_env(b"A=one\nA=two\n").is_err());
        assert!(parse_env(b"A=\"bad\\xescape\"\n").is_err());
    }

    #[test]
    fn generator_metadata_requires_canonical_format_length_and_exact_entropy() {
        let uuid = b"550e8400-e29b-41d4-a716-446655440000";
        assert!(validate_generator_metadata(&generated_value(1, uuid, 122), uuid).is_ok());
        let uppercase_uuid = b"550E8400-E29B-41D4-A716-446655440000";
        assert!(
            validate_generator_metadata(&generated_value(1, uppercase_uuid, 122), uppercase_uuid)
                .is_err()
        );

        let base64url = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        assert!(
            validate_generator_metadata(
                &generated_value(2, base64url.as_bytes(), 256),
                base64url.as_bytes()
            )
            .is_ok()
        );
        assert!(
            validate_generator_metadata(
                &generated_value(2, base64url.as_bytes(), 255),
                base64url.as_bytes()
            )
            .is_err()
        );

        let base64 = STANDARD.encode([0_u8; 32]);
        assert!(
            validate_generator_metadata(
                &generated_value(3, base64.as_bytes(), 256),
                base64.as_bytes()
            )
            .is_ok()
        );
        assert!(
            validate_generator_metadata(
                &generated_value(3, base64.as_bytes(), 255),
                base64.as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn mapped_identifiers_are_stable_and_namespaced() {
        let package = Uuid::new_v4();
        let vault = VaultId(Uuid::new_v4());
        let source = Uuid::new_v4();
        assert_eq!(
            mapped_uuid(package, vault, "profile", source, b"scope"),
            mapped_uuid(package, vault, "profile", source, b"scope")
        );
        assert_ne!(
            mapped_uuid(package, vault, "profile", source, b"scope"),
            mapped_uuid(package, vault, "profile", source, b"secret")
        );
        assert_ne!(
            mapped_uuid(package, vault, "profile", source, b"scope"),
            mapped_uuid(package, vault, "renamed", source, b"scope")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn workspace_password_round_trip_preserves_semantics_and_rewraps_keys() {
        let directory = tempfile::tempdir().expect("tempdir");
        let source_path = directory.path().join("source.db");
        let destination_path = directory.path().join("destination.db");
        let package_path = directory.path().join("workspace.envault-workspace");
        let mut source = test_session(&source_path);
        let base_secret = source
            .create_secret(
                "base",
                "API_TOKEN",
                Some("provider token"),
                SensitiveInput::copy_from_slice(b"workspace-secret-sentinel"),
            )
            .expect("base secret");
        source
            .set_secret_value(
                "base",
                "API_TOKEN",
                SensitiveInput::copy_from_slice(b"workspace-secret-current"),
            )
            .expect("second version");
        let profile = source
            .create_profile("production", Some("production profile"))
            .expect("profile");
        source
            .create_secret_in_scope(
                profile.scope_id,
                "DATABASE_URL",
                None,
                SensitiveInput::copy_from_slice(b"postgres://private"),
            )
            .expect("scoped secret");
        let transfer = SensitiveInput::copy_from_slice(TRANSFER_PASSWORD);
        let summary = source
            .export_package(
                PackageKind::Workspace,
                None,
                &package_path,
                Some(&transfer),
                &[],
            )
            .expect("export");
        assert_eq!(summary.counts.profiles, 2);
        assert_eq!(summary.counts.secrets, 2);
        let package_bytes = std::fs::read(&package_path).expect("package");
        assert!(
            !package_bytes
                .windows(b"workspace-secret-current".len())
                .any(|window| window == b"workspace-secret-current")
        );
        assert!(
            !package_bytes
                .windows(b"API_TOKEN".len())
                .any(|window| window == b"API_TOKEN")
        );

        let before = source
            .store
            .secret_by_id(base_secret.id)
            .expect("source secret")
            .expect("present")
            .value
            .expect("source value");
        let self_preview = source
            .preview_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                None,
            )
            .expect("self preview");
        source
            .commit_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                None,
                &self_preview.plan_hash,
            )
            .expect("self replace");
        let after = source
            .store
            .secret_by_id(base_secret.id)
            .expect("source secret")
            .expect("present")
            .value
            .expect("replaced value");
        assert_eq!(before.ciphertext, after.ciphertext);
        assert_ne!(before.wrapped_dek, after.wrapped_dek);

        let mut destination = test_session(&destination_path);
        let wrong = SensitiveInput::copy_from_slice(b"wrong portable password");
        assert!(matches!(
            destination.preview_package_import_for_kind(PackageImportOptions {
                expected_kind: PackageKind::Profile,
                input_path: &package_path,
                transfer_password: Some(&transfer),
                age_identity_path: None,
                strategy: ImportConflictStrategy::Replace,
                rename_to: None,
            }),
            Err(ServiceError::InvalidPackage)
        ));
        assert!(matches!(
            destination.preview_package_import(
                &package_path,
                Some(&wrong),
                None,
                ImportConflictStrategy::Abort,
                None,
            ),
            Err(ServiceError::PackageAuthenticationFailed)
        ));
        assert!(destination.store.secrets().expect("unchanged").is_empty());
        let preview = destination
            .preview_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Abort,
                None,
            )
            .expect("preview");
        assert!(!format!("{preview:?}").contains("workspace-secret-current"));
        assert!(preview.conflicts.is_empty());
        destination
            .commit_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Abort,
                None,
                &preview.plan_hash,
            )
            .expect("commit");
        assert_eq!(destination.profiles().expect("profiles").len(), 2);
        let imported_base = destination
            .secret("base", "API_TOKEN")
            .expect("base secret");
        assert_eq!(
            destination
                .store
                .secret_by_id(imported_base.id)
                .expect("secret")
                .expect("present")
                .current_version,
            2
        );
        assert_eq!(
            secret_value(&destination, imported_base.id),
            b"workspace-secret-current"
        );
        let imported_profile = destination.profile("production").expect("profile");
        let imported_scoped = destination
            .resolve_secret(imported_profile.scope_id, "DATABASE_URL")
            .expect("scoped secret");
        assert_eq!(
            secret_value(&destination, imported_scoped.secret.id),
            b"postgres://private"
        );
        assert_eq!(base_secret.id, imported_base.id);
    }

    #[test]
    fn workspace_package_import_preserves_workspace_and_membership_bindings() {
        let directory = tempfile::tempdir().expect("tempdir");
        let source_path = directory.path().join("source.db");
        let destination_path = directory.path().join("destination.db");
        let package_path = directory.path().join("workspace.envault-workspace");
        let mut source = test_session(&source_path);
        source.create_profile("alpha", None).expect("profile alpha");
        source.create_profile("beta", None).expect("profile beta");
        source.create_workspace("team").expect("workspace");
        source
            .bind_profile_to_workspace("team", "alpha")
            .expect("bind alpha");
        source
            .bind_profile_to_workspace("team", "beta")
            .expect("bind beta");
        let transfer = SensitiveInput::copy_from_slice(TRANSFER_PASSWORD);
        let summary = source
            .export_package(
                PackageKind::Workspace,
                None,
                &package_path,
                Some(&transfer),
                &[],
            )
            .expect("export");
        assert_eq!(summary.counts.workspaces, 1);
        assert_eq!(summary.counts.memberships, 2);

        let mut destination = test_session(&destination_path);
        let preview = destination
            .preview_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                None,
            )
            .expect("preview");
        destination
            .commit_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                None,
                &preview.plan_hash,
            )
            .expect("commit");

        let workspaces = destination.workspaces().expect("workspaces");
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].name, "team");
        let members = destination.profiles_in_workspace("team").expect("members");
        let mut member_names = members
            .iter()
            .map(|profile| profile.name.clone())
            .collect::<Vec<_>>();
        member_names.sort();
        assert_eq!(member_names, vec!["alpha".to_owned(), "beta".to_owned()]);
    }

    #[test]
    fn workspace_import_plan_goes_stale_on_concurrent_membership_change() {
        let directory = tempfile::tempdir().expect("tempdir");
        let source_path = directory.path().join("source.db");
        let destination_path = directory.path().join("destination.db");
        let package_path = directory.path().join("workspace.envault-workspace");
        let mut source = test_session(&source_path);
        source.create_profile("alpha", None).expect("profile alpha");
        source.create_workspace("team").expect("workspace");
        source
            .bind_profile_to_workspace("team", "alpha")
            .expect("bind alpha");
        let transfer = SensitiveInput::copy_from_slice(TRANSFER_PASSWORD);
        source
            .export_package(
                PackageKind::Workspace,
                None,
                &package_path,
                Some(&transfer),
                &[],
            )
            .expect("export");

        let mut destination = test_session(&destination_path);
        let preview = destination
            .preview_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                None,
            )
            .expect("preview");

        // Concurrent workspace/membership change between preview and commit.
        destination
            .create_workspace("concurrent")
            .expect("concurrent workspace");
        destination
            .bind_profile_to_workspace("concurrent", "base")
            .expect("concurrent bind");

        assert!(matches!(
            destination.commit_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                None,
                &preview.plan_hash,
            ),
            Err(ServiceError::StaleImportPlan)
        ));
    }

    #[test]
    fn age_profile_import_tamper_and_stale_plan_fail_without_partial_mutation() {
        use age::secrecy::ExposeSecret as _;

        let directory = tempfile::tempdir().expect("tempdir");
        let source_path = directory.path().join("source.db");
        let destination_path = directory.path().join("destination.db");
        let package_path = directory.path().join("profile.envault-profile");
        let tampered_path = directory.path().join("tampered.envault-profile");
        let identity_path = directory.path().join("identity.txt");
        let mut source = test_session(&source_path);
        source
            .create_secret(
                "base",
                "PROFILE_TOKEN",
                None,
                SensitiveInput::copy_from_slice(b"age-secret-sentinel"),
            )
            .expect("secret");
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let identity_text = identity.to_string();
        write_private(&identity_path, identity_text.expose_secret().as_bytes());
        source
            .export_package(
                PackageKind::Profile,
                Some("base"),
                &package_path,
                None,
                &[recipient],
            )
            .expect("age export");

        let mut tampered = std::fs::read(&package_path).expect("read package");
        let last = tampered.last_mut().expect("nonempty");
        *last ^= 0x80;
        write_private(&tampered_path, &tampered);
        let mut destination = test_session(&destination_path);
        assert!(
            destination
                .preview_package_import(
                    &tampered_path,
                    None,
                    Some(&identity_path),
                    ImportConflictStrategy::Rename,
                    Some("imported"),
                )
                .is_err()
        );
        assert_eq!(destination.profiles().expect("unchanged").len(), 1);
        let preview = destination
            .preview_package_import(
                &package_path,
                None,
                Some(&identity_path),
                ImportConflictStrategy::Rename,
                Some("imported"),
            )
            .expect("preview");
        destination
            .create_profile("drift", None)
            .expect("destination drift");
        assert!(matches!(
            destination.commit_package_import(
                &package_path,
                None,
                Some(&identity_path),
                ImportConflictStrategy::Rename,
                Some("imported"),
                &preview.plan_hash,
            ),
            Err(ServiceError::StaleImportPlan)
        ));
        assert!(matches!(
            destination.profile("imported"),
            Err(ServiceError::NotFound)
        ));
        let refreshed = destination
            .preview_package_import(
                &package_path,
                None,
                Some(&identity_path),
                ImportConflictStrategy::Rename,
                Some("imported"),
            )
            .expect("refreshed preview");
        destination
            .commit_package_import(
                &package_path,
                None,
                Some(&identity_path),
                ImportConflictStrategy::Rename,
                Some("imported"),
                &refreshed.plan_hash,
            )
            .expect("age commit");
        let imported = destination.profile("imported").expect("profile");
        let secret = destination
            .resolve_secret(imported.scope_id, "PROFILE_TOKEN")
            .expect("secret");
        assert_eq!(
            secret_value(&destination, secret.secret.id),
            b"age-secret-sentinel"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn mixed_slots_and_hostile_packages_fail_closed_before_mutation() {
        use age::secrecy::ExposeSecret as _;

        let directory = tempfile::tempdir().expect("tempdir");
        let source_path = directory.path().join("source.db");
        let destination_path = directory.path().join("destination.db");
        let package_path = directory.path().join("mixed.envault-profile");
        let identity_path = directory.path().join("identity.txt");
        let wrong_identity_path = directory.path().join("wrong-identity.txt");
        let mut source = test_session(&source_path);
        source
            .create_secret(
                "base",
                "MIXED_TOKEN",
                None,
                SensitiveInput::copy_from_slice(b"mixed-slot-secret"),
            )
            .expect("secret");
        let identity = age::x25519::Identity::generate();
        let wrong_identity = age::x25519::Identity::generate();
        write_private(
            &identity_path,
            identity.to_string().expose_secret().as_bytes(),
        );
        write_private(
            &wrong_identity_path,
            wrong_identity.to_string().expose_secret().as_bytes(),
        );
        let transfer = SensitiveInput::copy_from_slice(TRANSFER_PASSWORD);
        source
            .export_package(
                PackageKind::Profile,
                Some("base"),
                &package_path,
                Some(&transfer),
                &[identity.to_public().to_string()],
            )
            .expect("mixed export");

        let destination = test_session(&destination_path);
        assert!(matches!(
            destination.preview_package_import(
                &package_path,
                None,
                Some(&wrong_identity_path),
                ImportConflictStrategy::Rename,
                Some("wrong-identity"),
            ),
            Err(ServiceError::PackageAuthenticationFailed)
        ));
        let wrong_password = SensitiveInput::copy_from_slice(b"wrong portable password");
        destination
            .preview_package_import(
                &package_path,
                Some(&wrong_password),
                Some(&identity_path),
                ImportConflictStrategy::Rename,
                Some("age-fallback"),
            )
            .expect("age fallback after wrong password");

        let swapped_path = directory.path().join("swapped.envault-profile");
        let mut swapped: PackageEnvelope =
            super::super::decode_cbor(&std::fs::read(&package_path).expect("package"))
                .expect("envelope");
        swapped.key_slots.reverse();
        write_private(
            &swapped_path,
            &super::super::encode_cbor(&swapped).expect("swapped envelope"),
        );
        destination
            .preview_package_import(
                &swapped_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Rename,
                Some("slot-order"),
            )
            .expect("slot order is not security-sensitive");

        let header_path = directory.path().join("header.envault-profile");
        let mut header: PackageEnvelope =
            super::super::decode_cbor(&std::fs::read(&package_path).expect("package"))
                .expect("envelope");
        header.created_at = header.created_at.saturating_add(1);
        write_private(
            &header_path,
            &super::super::encode_cbor(&header).expect("header envelope"),
        );
        assert!(matches!(
            destination.preview_package_import(
                &header_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Rename,
                Some("header-tamper"),
            ),
            Err(ServiceError::PackageAuthenticationFailed)
        ));

        let unsupported_path = directory.path().join("unsupported.envault-profile");
        let mut unsupported: PackageEnvelope =
            super::super::decode_cbor(&std::fs::read(&package_path).expect("package"))
                .expect("envelope");
        unsupported.version = PACKAGE_VERSION.saturating_add(1);
        write_private(
            &unsupported_path,
            &super::super::encode_cbor(&unsupported).expect("unsupported envelope"),
        );
        assert!(matches!(
            destination.preview_package_import(
                &unsupported_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Rename,
                Some("unsupported"),
            ),
            Err(ServiceError::UnsupportedPackageVersion)
        ));

        let hostile_kdf_path = directory.path().join("hostile-kdf.envault-profile");
        let mut hostile_kdf: PackageEnvelope =
            super::super::decode_cbor(&std::fs::read(&package_path).expect("package"))
                .expect("envelope");
        let password_parameters = hostile_kdf
            .key_slots
            .iter_mut()
            .find_map(|slot| match slot {
                KeySlot::Password { parameters, .. } => Some(parameters),
                KeySlot::AgeX25519 { .. } => None,
            })
            .expect("password slot");
        password_parameters.memory_kib = TRANSFER_KDF_MAX_MEMORY_KIB.saturating_add(1);
        write_private(
            &hostile_kdf_path,
            &super::super::encode_cbor(&hostile_kdf).expect("hostile KDF envelope"),
        );
        assert!(matches!(
            destination.preview_package_import(
                &hostile_kdf_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Rename,
                Some("hostile-kdf"),
            ),
            Err(ServiceError::InvalidPackage)
        ));

        let inner_tamper_path = directory.path().join("inner-tamper.envault-profile");
        mutate_authenticated_password_payload(&package_path, &inner_tamper_path, |payload| {
            let byte = payload.secrets[0]
                .value
                .as_mut()
                .expect("value")
                .ciphertext
                .last_mut()
                .expect("ciphertext");
            *byte ^= 0x40;
        });
        assert!(matches!(
            destination.preview_package_import(
                &inner_tamper_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Rename,
                Some("inner-tamper"),
            ),
            Err(ServiceError::InvalidPackage)
        ));

        let invalid_scope_path = directory.path().join("invalid-scope.envault-profile");
        mutate_authenticated_password_payload(&package_path, &invalid_scope_path, |payload| {
            payload.scopes[0].kind = u8::MAX;
        });
        assert!(matches!(
            destination.preview_package_import(
                &invalid_scope_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Rename,
                Some("invalid-scope"),
            ),
            Err(ServiceError::InvalidPackage)
        ));

        let oversized_path = directory.path().join("oversized.envault-profile");
        let oversized = envault_platform::create_private_file(&oversized_path).expect("oversized");
        oversized
            .set_len(u64::try_from(MAX_PORTABILITY_PACKAGE_BYTES).expect("size") + 1)
            .expect("sparse package");
        drop(oversized);
        assert!(
            destination
                .preview_package_import(
                    &oversized_path,
                    Some(&transfer),
                    None,
                    ImportConflictStrategy::Rename,
                    Some("oversized"),
                )
                .is_err()
        );
        assert_eq!(destination.profiles().expect("unchanged").len(), 1);
        assert!(destination.store.secrets().expect("unchanged").is_empty());
    }

    #[test]
    fn one_profile_package_can_be_imported_under_multiple_explicit_names() {
        let directory = tempfile::tempdir().expect("tempdir");
        let source_path = directory.path().join("source.db");
        let destination_path = directory.path().join("destination.db");
        let package_path = directory.path().join("profile.envault-profile");
        let mut source = test_session(&source_path);
        source
            .create_secret(
                "base",
                "DUPLICATED_TOKEN",
                None,
                SensitiveInput::copy_from_slice(b"duplicated-profile-value"),
            )
            .expect("secret");
        let transfer = SensitiveInput::copy_from_slice(TRANSFER_PASSWORD);
        source
            .export_package(
                PackageKind::Profile,
                Some("base"),
                &package_path,
                Some(&transfer),
                &[],
            )
            .expect("export");
        let mut destination = test_session(&destination_path);
        let mut imported_ids = Vec::new();
        for name in ["first-copy", "second-copy"] {
            let preview = destination
                .preview_package_import(
                    &package_path,
                    Some(&transfer),
                    None,
                    ImportConflictStrategy::Rename,
                    Some(name),
                )
                .expect("preview");
            destination
                .commit_package_import(
                    &package_path,
                    Some(&transfer),
                    None,
                    ImportConflictStrategy::Rename,
                    Some(name),
                    &preview.plan_hash,
                )
                .expect("commit");
            let profile = destination.profile(name).expect("profile");
            let secret = destination
                .resolve_secret(profile.scope_id, "DUPLICATED_TOKEN")
                .expect("secret");
            assert_eq!(
                secret_value(&destination, secret.secret.id),
                b"duplicated-profile-value"
            );
            imported_ids.push(secret.secret.id);
        }
        assert_ne!(imported_ids[0], imported_ids[1]);
        let first_before = destination.profile("first-copy").expect("first profile");
        let replace = destination
            .preview_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                Some("first-copy"),
            )
            .expect("replace renamed preview");
        destination
            .commit_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                Some("first-copy"),
                &replace.plan_hash,
            )
            .expect("replace renamed commit");
        assert_eq!(
            destination.profile("first-copy").expect("first profile").id,
            first_before.id
        );
        assert!(destination.profile("second-copy").is_ok());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn profile_abort_skip_and_replace_are_explicit_and_scope_bounded() {
        let directory = tempfile::tempdir().expect("tempdir");
        let source_path = directory.path().join("source.db");
        let destination_path = directory.path().join("destination.db");
        let package_path = directory.path().join("base.envault-profile");
        let mut source = test_session(&source_path);
        source
            .create_secret(
                "base",
                "IMPORTED_TOKEN",
                None,
                SensitiveInput::copy_from_slice(b"imported-profile-value"),
            )
            .expect("source secret");
        let transfer = SensitiveInput::copy_from_slice(TRANSFER_PASSWORD);
        source
            .export_package(
                PackageKind::Profile,
                Some("base"),
                &package_path,
                Some(&transfer),
                &[],
            )
            .expect("export");

        let mut destination = test_session(&destination_path);
        let base_before = destination.profile("base").expect("base");
        destination
            .create_secret(
                "base",
                "OLD_TOKEN",
                None,
                SensitiveInput::copy_from_slice(b"old-value"),
            )
            .expect("old secret");
        destination
            .create_profile("keep", None)
            .expect("keep profile");
        let abort = destination
            .preview_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Abort,
                None,
            )
            .expect("abort preview");
        assert_eq!(abort.conflicts[0].action, ImportAction::Reject);
        assert!(matches!(
            destination.commit_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Abort,
                None,
                &abort.plan_hash,
            ),
            Err(ServiceError::Conflict)
        ));
        assert!(destination.secret("base", "OLD_TOKEN").is_ok());

        let skip = destination
            .preview_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Skip,
                None,
            )
            .expect("skip preview");
        let skipped = destination
            .commit_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Skip,
                None,
                &skip.plan_hash,
            )
            .expect("skip commit");
        assert_eq!(skipped.skipped, 1);
        assert!(destination.secret("base", "OLD_TOKEN").is_ok());

        let replace = destination
            .preview_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                None,
            )
            .expect("replace preview");
        destination
            .commit_package_import(
                &package_path,
                Some(&transfer),
                None,
                ImportConflictStrategy::Replace,
                None,
                &replace.plan_hash,
            )
            .expect("replace commit");
        assert!(matches!(
            destination.secret("base", "OLD_TOKEN"),
            Err(ServiceError::NotFound)
        ));
        let imported = destination
            .secret("base", "IMPORTED_TOKEN")
            .expect("imported");
        assert_eq!(
            secret_value(&destination, imported.id),
            b"imported-profile-value"
        );
        assert_eq!(
            destination.profile("base").expect("base").id,
            base_before.id
        );
        assert!(destination.profile("keep").is_ok());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn env_preview_commit_replace_and_plaintext_export_are_redacted_and_atomic() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("tempdir");
        let database_path = directory.path().join("vault.db");
        let env_path = directory.path().join("input.env");
        let export_path = directory.path().join("output.env");
        write_private(
            &env_path,
            b"API_KEY=first-secret\nLITERAL=literal-$HOME\nMULTILINE=\"line\\nvalue\"\n",
        );
        let mut session = test_session(&database_path);
        let preview = session
            .preview_env_import("base", &env_path, ImportConflictStrategy::Abort)
            .expect("preview");
        let serialized = format!("{preview:?}");
        assert!(!serialized.contains("first-secret"));
        assert_eq!(preview.entries[0].value_bytes, 12);
        session
            .commit_env_import(
                "base",
                &env_path,
                ImportConflictStrategy::Abort,
                &preview.plan_hash,
            )
            .expect("commit");
        let api_key = session.secret("base", "API_KEY").expect("secret");
        assert_eq!(secret_value(&session, api_key.id), b"first-secret");

        std::fs::write(&env_path, b"API_KEY=second-secret\n").expect("replace source");
        let abort_conflict = session
            .preview_env_import("base", &env_path, ImportConflictStrategy::Abort)
            .expect("abort conflict preview");
        assert_eq!(abort_conflict.entries[0].action, ImportAction::Reject);
        assert!(matches!(
            session.commit_env_import(
                "base",
                &env_path,
                ImportConflictStrategy::Abort,
                &abort_conflict.plan_hash,
            ),
            Err(ServiceError::Conflict)
        ));
        let skip = session
            .preview_env_import("base", &env_path, ImportConflictStrategy::Skip)
            .expect("skip preview");
        session
            .commit_env_import(
                "base",
                &env_path,
                ImportConflictStrategy::Skip,
                &skip.plan_hash,
            )
            .expect("skip commit");
        assert_eq!(secret_value(&session, api_key.id), b"first-secret");
        let stale_preview = session
            .preview_env_import("base", &env_path, ImportConflictStrategy::Replace)
            .expect("replace preview");
        std::fs::write(&env_path, b"API_KEY=third-secret\n").expect("source drift");
        assert!(matches!(
            session.commit_env_import(
                "base",
                &env_path,
                ImportConflictStrategy::Replace,
                &stale_preview.plan_hash,
            ),
            Err(ServiceError::StaleImportPlan)
        ));
        assert_eq!(secret_value(&session, api_key.id), b"first-secret");
        let refreshed = session
            .preview_env_import("base", &env_path, ImportConflictStrategy::Replace)
            .expect("refreshed");
        session
            .commit_env_import(
                "base",
                &env_path,
                ImportConflictStrategy::Replace,
                &refreshed.plan_hash,
            )
            .expect("replace commit");
        assert_eq!(secret_value(&session, api_key.id), b"third-secret");

        assert!(matches!(
            session.export_plaintext_env("base", &export_path, false),
            Err(ServiceError::PlaintextAcknowledgementRequired)
        ));
        session
            .export_plaintext_env("base", &export_path, true)
            .expect("plaintext export");
        let exported = std::fs::read_to_string(&export_path).expect("exported file");
        assert!(exported.contains("API_KEY=\"third-secret\""));
        assert!(exported.contains("LITERAL=\"literal-$HOME\""));
        assert!(exported.contains("MULTILINE=\"line\\nvalue\""));
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&export_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            std::fs::read_dir(directory.path())
                .expect("directory")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".envault-package-"))
        );
        assert!(matches!(
            session.export_plaintext_env("base", &export_path, true),
            Err(ServiceError::Conflict)
        ));
    }
}
