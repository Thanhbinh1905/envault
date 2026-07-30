//! Test-only fixtures shared by `app` and `view` unit tests: a queue-backed
//! fake [`DaemonClient`](super::app::DaemonClient) and cheap sample view
//! values. Kept out of the release binary entirely via `#[cfg(test)]`.

use std::cell::RefCell;
use std::collections::VecDeque;

use envault_core::{
    EnvImportPreview, GeneratorFormat, GeneratorSpec, ImportConflictStrategy, PackageKind,
    PortabilityCounts, PortabilityExportSummary, PortabilityImportSummary, PortabilityPreview,
    ProfileId, ProfileView, ScopeId, SecretId, SecretStatus, SecretVersionId, SecretVersionView,
    SecretView,
};
use envault_protocol::{AdminLeaseStatus, DaemonStatus, SensitiveBytes, ServiceState};
use uuid::Uuid;

use super::app::DaemonClient;
use crate::client::ClientError;

fn pop<T>(queue: &RefCell<VecDeque<Result<T, ClientError>>>) -> Result<T, ClientError> {
    queue
        .borrow_mut()
        .pop_front()
        .expect("fake client call was not primed with a queued response")
}

/// A [`DaemonClient`] double whose read operations are driven by explicit
/// per-call response queues (so a test controls exactly what each call
/// returns and in what order) and whose mutating operations return a cheap
/// deterministic sample value, since most state-machine tests only care that
/// the call happened and the returned name round-trips into a status
/// message, not the exact daemon-side record shape.
#[derive(Default)]
pub(crate) struct FakeClient {
    pub status: RefCell<VecDeque<Result<DaemonStatus, ClientError>>>,
    pub admin_status: RefCell<VecDeque<Result<AdminLeaseStatus, ClientError>>>,
    pub profiles: RefCell<VecDeque<Result<Vec<ProfileView>, ClientError>>>,
    pub secrets: RefCell<VecDeque<Result<Vec<SecretView>, ClientError>>>,
    pub versions: RefCell<VecDeque<Result<Vec<SecretVersionView>, ClientError>>>,
    pub admin_unlock: RefCell<VecDeque<Result<AdminLeaseStatus, ClientError>>>,
    pub preview_package: RefCell<VecDeque<Result<PortabilityPreview, ClientError>>>,
    pub commit_package: RefCell<VecDeque<Result<PortabilityImportSummary, ClientError>>>,
    pub preview_env: RefCell<VecDeque<Result<EnvImportPreview, ClientError>>>,
    pub commit_env: RefCell<VecDeque<Result<PortabilityImportSummary, ClientError>>>,
}

impl DaemonClient for FakeClient {
    fn status(&self) -> Result<DaemonStatus, ClientError> {
        pop(&self.status)
    }

    fn admin_status(&self) -> Result<AdminLeaseStatus, ClientError> {
        pop(&self.admin_status)
    }

    fn list_profiles(&self) -> Result<Vec<ProfileView>, ClientError> {
        pop(&self.profiles)
    }

    fn list_secrets(&self) -> Result<Vec<SecretView>, ClientError> {
        pop(&self.secrets)
    }

    fn list_secret_versions(&self, _name: &str) -> Result<Vec<SecretVersionView>, ClientError> {
        pop(&self.versions)
    }

    fn admin_unlock(
        &self,
        _password: SensitiveBytes,
        _ttl_minutes: u8,
    ) -> Result<AdminLeaseStatus, ClientError> {
        pop(&self.admin_unlock)
    }

    fn admin_lock(&self) -> Result<(), ClientError> {
        Ok(())
    }

    fn create_profile(
        &self,
        name: String,
        description: Option<String>,
    ) -> Result<ProfileView, ClientError> {
        Ok(sample_profile(&name, description))
    }

    fn rename_profile(
        &self,
        _old_name: String,
        new_name: String,
    ) -> Result<ProfileView, ClientError> {
        Ok(sample_profile(&new_name, None))
    }

    fn delete_profile(&self, _name: String) -> Result<(), ClientError> {
        Ok(())
    }

    fn activate_profile(&self, name: String) -> Result<ProfileView, ClientError> {
        Ok(sample_profile(&name, None))
    }

    fn create_generated_secret(
        &self,
        name: String,
        description: Option<String>,
        _generator: GeneratorSpec,
    ) -> Result<SecretView, ClientError> {
        Ok(sample_secret(&name, description))
    }

    fn update_secret_description(
        &self,
        name: String,
        description: Option<String>,
    ) -> Result<SecretView, ClientError> {
        Ok(sample_secret(&name, description))
    }

    fn rename_secret(
        &self,
        _old_name: String,
        new_name: String,
    ) -> Result<SecretView, ClientError> {
        Ok(sample_secret(&new_name, None))
    }

    fn delete_secret(&self, _name: String) -> Result<(), ClientError> {
        Ok(())
    }

    fn generate_secret_value(
        &self,
        _name: String,
        _generator: GeneratorSpec,
    ) -> Result<SecretVersionView, ClientError> {
        Ok(sample_version(2))
    }

    fn preview_package_import(
        &self,
        _expected_kind: PackageKind,
        _input_path: String,
        _transfer_password: Option<SensitiveBytes>,
        _age_identity_path: Option<String>,
        _strategy: ImportConflictStrategy,
        _rename_to: Option<String>,
    ) -> Result<PortabilityPreview, ClientError> {
        pop(&self.preview_package)
    }

    fn commit_package_import(
        &self,
        _expected_kind: PackageKind,
        _input_path: String,
        _transfer_password: Option<SensitiveBytes>,
        _age_identity_path: Option<String>,
        _strategy: ImportConflictStrategy,
        _rename_to: Option<String>,
        _expected_plan_hash: String,
    ) -> Result<PortabilityImportSummary, ClientError> {
        pop(&self.commit_package)
    }

    fn preview_env_import(
        &self,
        _profile_name: String,
        _input_path: String,
        _strategy: ImportConflictStrategy,
    ) -> Result<EnvImportPreview, ClientError> {
        pop(&self.preview_env)
    }

    fn commit_env_import(
        &self,
        _profile_name: String,
        _input_path: String,
        _strategy: ImportConflictStrategy,
        _expected_plan_hash: String,
    ) -> Result<PortabilityImportSummary, ClientError> {
        pop(&self.commit_env)
    }

    fn export_package(
        &self,
        kind: PackageKind,
        _profile_name: Option<String>,
        output_path: String,
        _transfer_password: Option<SensitiveBytes>,
        _age_recipients: Vec<String>,
    ) -> Result<PortabilityExportSummary, ClientError> {
        Ok(PortabilityExportSummary {
            package_id: Uuid::new_v4(),
            kind,
            output_path,
            counts: PortabilityCounts::default(),
            password_slots: 1,
            age_slots: 0,
        })
    }
}

pub(crate) fn sample_status(admin_lease_active: bool) -> DaemonStatus {
    DaemonStatus {
        service: ServiceState::Unlocked,
        pid: 4242,
        active_profile: Some("base".to_string()),
        admin_lease_active,
        agent_session_count: 0,
    }
}

pub(crate) fn sample_admin_status(active: bool) -> AdminLeaseStatus {
    AdminLeaseStatus {
        active,
        expires_at: None,
    }
}

pub(crate) fn sample_profile(name: &str, description: Option<String>) -> ProfileView {
    ProfileView {
        id: ProfileId(Uuid::new_v4()),
        scope_id: ScopeId(Uuid::new_v4()),
        name: name.to_string(),
        description,
        activate_on_start: false,
        generation: 1,
    }
}

pub(crate) fn sample_secret(name: &str, description: Option<String>) -> SecretView {
    SecretView {
        id: SecretId(Uuid::new_v4()),
        scope_id: ScopeId(Uuid::new_v4()),
        name: name.to_string(),
        description,
        current_version: 1,
        status: SecretStatus::Active,
    }
}

pub(crate) fn sample_version(version: u64) -> SecretVersionView {
    SecretVersionView {
        id: SecretVersionId(Uuid::new_v4()),
        secret_id: SecretId(Uuid::new_v4()),
        version,
        generator: Some(GeneratorFormat::Base64Url),
        generated_length: Some(32),
        entropy_bits: Some(192),
    }
}

pub(crate) fn sample_env_preview(plan_hash: &str) -> EnvImportPreview {
    EnvImportPreview {
        profile: "base".to_string(),
        entries: Vec::new(),
        strategy: ImportConflictStrategy::Abort,
        plan_hash: plan_hash.to_string(),
        warnings: Vec::new(),
    }
}

pub(crate) fn sample_import_summary() -> PortabilityImportSummary {
    PortabilityImportSummary {
        package_id: None,
        kind: None,
        counts: PortabilityCounts::default(),
        created: 1,
        replaced: 0,
        skipped: 0,
        versions_appended: 0,
    }
}
