#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_ADMIN_LEASE_MINUTES: u8 = 5;
pub const DEFAULT_AGENT_GRANT_MINUTES: u8 = 15;
pub const MIN_ADMIN_LEASE_MINUTES: u8 = 1;
pub const MAX_ADMIN_LEASE_MINUTES: u8 = 30;
pub const MAX_DESCRIPTION_CHARS: usize = 240;
pub const MAX_NAME_BYTES: usize = 128;
pub const MIN_STRONG_GENERATED_CHARS: usize = 22;
pub const MAX_GENERATED_SIZE: usize = 4096;
pub const MAX_SCOPE_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct VaultId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProfileId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ScopeId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SecretId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SecretVersionId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PrincipalId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PolicyRuleId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct GrantId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ApprovalId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct AuditEventId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum EntityKind {
    Profile,
    Scope,
    Secret,
    SecretVersion,
    Principal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ScopeKind {
    Root,
    Profile,
    Workspace,
    Project,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SecretStatus {
    Active,
    Tombstone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrincipalKind {
    Human,
    Agent,
    Process,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GeneratorFormat {
    UuidV4,
    Base64Url,
    Base64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GeneratorLength {
    Default,
    Bytes(usize),
    Chars(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GeneratorSpec {
    pub format: GeneratorFormat,
    pub length: GeneratorLength,
    pub allow_weak: bool,
}

impl Default for GeneratorSpec {
    fn default() -> Self {
        Self {
            format: GeneratorFormat::Base64Url,
            length: GeneratorLength::Bytes(32),
            allow_weak: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileView {
    pub id: ProfileId,
    pub scope_id: ScopeId,
    pub name: String,
    pub description: Option<String>,
    pub activate_on_start: bool,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretView {
    pub id: SecretId,
    pub scope_id: ScopeId,
    pub name: String,
    pub description: Option<String>,
    pub current_version: u64,
    pub status: SecretStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScopeView {
    pub id: ScopeId,
    pub parent_id: Option<ScopeId>,
    pub kind: ScopeKind,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileSession {
    pub profile_id: ProfileId,
    pub scope_id: ScopeId,
    pub profile_generation: u64,
    pub bound_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrincipalView {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
    pub name: String,
    pub disabled: bool,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSecretView {
    pub secret: SecretView,
    pub source_scope_id: ScopeId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeResolutionEntry {
    pub scope_id: ScopeId,
    pub name_lookup: Vec<u8>,
    pub secret_id: SecretId,
    pub status: SecretStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretVersionView {
    pub id: SecretVersionId,
    pub secret_id: SecretId,
    pub version: u64,
    pub generator: Option<GeneratorFormat>,
    pub generated_length: Option<usize>,
    pub entropy_bits: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: ProfileId,
    pub encrypted_name: Vec<u8>,
    pub activate_on_start: bool,
    pub generation: u64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum InvariantError {
    #[error("exactly one profile must activate on start, found {0}")]
    StartupProfileCount(usize),
    #[error("admin lease must be between 1 and 30 minutes")]
    InvalidAdminLease,
    #[error("description exceeds 240 UTF-8 characters")]
    DescriptionTooLong,
    #[error("name must contain between 1 and 128 UTF-8 bytes without control characters")]
    InvalidName,
    #[error("generator size must be between 1 and 4096")]
    InvalidGeneratorSize,
    #[error("generated value shorter than 22 characters requires explicit weak-value approval")]
    WeakGeneratorLength,
    #[error("generator length is incompatible with the selected format")]
    InvalidGeneratorLength,
    #[error("scope chain is empty, cyclic, disconnected, or too deep")]
    InvalidScopeChain,
    #[error("scope resolution contains an ambiguous duplicate entry")]
    AmbiguousScopeEntry,
}

pub fn validate_startup_profile(profiles: &[ProfileSummary]) -> Result<(), InvariantError> {
    let active_count = profiles
        .iter()
        .filter(|profile| profile.activate_on_start)
        .count();
    if active_count == 1 {
        Ok(())
    } else {
        Err(InvariantError::StartupProfileCount(active_count))
    }
}

pub fn validate_admin_lease(minutes: u8) -> Result<(), InvariantError> {
    if (MIN_ADMIN_LEASE_MINUTES..=MAX_ADMIN_LEASE_MINUTES).contains(&minutes) {
        Ok(())
    } else {
        Err(InvariantError::InvalidAdminLease)
    }
}

pub fn validate_description(description: &str) -> Result<(), InvariantError> {
    if description.chars().count() <= MAX_DESCRIPTION_CHARS {
        Ok(())
    } else {
        Err(InvariantError::DescriptionTooLong)
    }
}

pub fn normalize_name(name: &str) -> Result<String, InvariantError> {
    let normalized = name.trim().to_lowercase();
    if normalized.is_empty()
        || normalized.len() > MAX_NAME_BYTES
        || normalized.chars().any(char::is_control)
    {
        Err(InvariantError::InvalidName)
    } else {
        Ok(normalized)
    }
}

pub fn validate_generator(spec: GeneratorSpec) -> Result<GeneratorSpec, InvariantError> {
    match (spec.format, spec.length) {
        (GeneratorFormat::UuidV4, GeneratorLength::Default) => Ok(spec),
        (GeneratorFormat::UuidV4, _) | (GeneratorFormat::Base64, GeneratorLength::Chars(_)) => {
            Err(InvariantError::InvalidGeneratorLength)
        }
        (_, GeneratorLength::Default) => Ok(spec),
        (format, GeneratorLength::Bytes(size)) => {
            validate_generator_size(size)?;
            let output_chars = match format {
                GeneratorFormat::Base64Url => size.saturating_mul(4).saturating_add(2) / 3,
                GeneratorFormat::Base64 => size.div_ceil(3).saturating_mul(4),
                GeneratorFormat::UuidV4 => unreachable!("UUID byte lengths are rejected above"),
            };
            if output_chars < MIN_STRONG_GENERATED_CHARS && !spec.allow_weak {
                Err(InvariantError::WeakGeneratorLength)
            } else {
                Ok(spec)
            }
        }
        (GeneratorFormat::Base64Url, GeneratorLength::Chars(size)) => {
            validate_generator_size(size)?;
            if size < MIN_STRONG_GENERATED_CHARS && !spec.allow_weak {
                Err(InvariantError::WeakGeneratorLength)
            } else {
                Ok(spec)
            }
        }
    }
}

fn validate_generator_size(size: usize) -> Result<(), InvariantError> {
    if (1..=MAX_GENERATED_SIZE).contains(&size) {
        Ok(())
    } else {
        Err(InvariantError::InvalidGeneratorSize)
    }
}

pub fn validate_scope_chain(chain: &[ScopeId]) -> Result<(), InvariantError> {
    if chain.is_empty() || chain.len() > MAX_SCOPE_DEPTH {
        return Err(InvariantError::InvalidScopeChain);
    }
    let unique = chain.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() == chain.len() {
        Ok(())
    } else {
        Err(InvariantError::InvalidScopeChain)
    }
}

pub fn resolve_scope_entries(
    chain: &[ScopeId],
    entries: &[ScopeResolutionEntry],
) -> Result<Vec<ScopeResolutionEntry>, InvariantError> {
    validate_scope_chain(chain)?;
    let depth = chain
        .iter()
        .copied()
        .enumerate()
        .map(|(index, id)| (id, index))
        .collect::<BTreeMap<_, _>>();
    let mut ordered = entries
        .iter()
        .map(|entry| {
            depth
                .get(&entry.scope_id)
                .copied()
                .map(|index| (index, entry.clone()))
                .ok_or(InvariantError::InvalidScopeChain)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ordered.sort_by(|(left_depth, left), (right_depth, right)| {
        left_depth
            .cmp(right_depth)
            .then_with(|| left.name_lookup.cmp(&right.name_lookup))
            .then_with(|| left.secret_id.0.cmp(&right.secret_id.0))
    });
    let mut seen = BTreeSet::new();
    let mut resolved = BTreeMap::new();
    for (entry_depth, entry) in ordered {
        if !seen.insert((entry_depth, entry.name_lookup.clone())) {
            return Err(InvariantError::AmbiguousScopeEntry);
        }
        match entry.status {
            SecretStatus::Active => {
                resolved.insert(entry.name_lookup.clone(), entry);
            }
            SecretStatus::Tombstone => {
                resolved.remove(&entry.name_lookup);
            }
        }
    }
    Ok(resolved.into_values().collect())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn profile(active: bool) -> ProfileSummary {
        ProfileSummary {
            id: ProfileId(Uuid::new_v4()),
            encrypted_name: vec![1, 2, 3],
            activate_on_start: active,
            generation: 0,
        }
    }

    #[test]
    fn exactly_one_startup_profile_is_valid() {
        assert_eq!(validate_startup_profile(&[profile(true)]), Ok(()));
        assert!(validate_startup_profile(&[profile(false)]).is_err());
        assert!(validate_startup_profile(&[profile(true), profile(true)]).is_err());
    }

    #[test]
    fn admin_lease_is_bounded() {
        assert!(validate_admin_lease(1).is_ok());
        assert!(validate_admin_lease(30).is_ok());
        assert!(validate_admin_lease(0).is_err());
        assert!(validate_admin_lease(31).is_err());
    }

    #[test]
    fn names_are_normalized_and_validated() {
        assert_eq!(
            normalize_name("  Production  ").expect("name"),
            "production"
        );
        assert!(normalize_name("\n").is_err());
    }

    #[test]
    fn generator_contract_rejects_ambiguous_or_weak_lengths() {
        assert!(validate_generator(GeneratorSpec::default()).is_ok());
        assert!(
            validate_generator(GeneratorSpec {
                format: GeneratorFormat::UuidV4,
                length: GeneratorLength::Chars(36),
                allow_weak: false,
            })
            .is_err()
        );
        assert!(
            validate_generator(GeneratorSpec {
                format: GeneratorFormat::Base64Url,
                length: GeneratorLength::Chars(12),
                allow_weak: false,
            })
            .is_err()
        );
        assert!(
            validate_generator(GeneratorSpec {
                format: GeneratorFormat::Base64Url,
                length: GeneratorLength::Bytes(8),
                allow_weak: false,
            })
            .is_err()
        );
    }

    #[test]
    fn child_override_and_tombstone_are_deterministic() {
        let root = ScopeId(Uuid::from_u128(1));
        let child = ScopeId(Uuid::from_u128(2));
        let leaf = ScopeId(Uuid::from_u128(3));
        let entries = [
            ScopeResolutionEntry {
                scope_id: child,
                name_lookup: vec![1],
                secret_id: SecretId(Uuid::from_u128(11)),
                status: SecretStatus::Active,
            },
            ScopeResolutionEntry {
                scope_id: root,
                name_lookup: vec![1],
                secret_id: SecretId(Uuid::from_u128(10)),
                status: SecretStatus::Active,
            },
            ScopeResolutionEntry {
                scope_id: leaf,
                name_lookup: vec![1],
                secret_id: SecretId(Uuid::from_u128(12)),
                status: SecretStatus::Tombstone,
            },
            ScopeResolutionEntry {
                scope_id: root,
                name_lookup: vec![2],
                secret_id: SecretId(Uuid::from_u128(20)),
                status: SecretStatus::Active,
            },
        ];
        let resolved = resolve_scope_entries(&[root, child, leaf], &entries).expect("resolve");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].secret_id, SecretId(Uuid::from_u128(20)));
    }

    proptest! {
        #[test]
        fn scope_resolution_is_independent_of_input_order(
            raw in proptest::collection::vec((0_u8..3, 0_u8..8, any::<bool>()), 0..40)
        ) {
            let chain = [
                ScopeId(Uuid::from_u128(1)),
                ScopeId(Uuid::from_u128(2)),
                ScopeId(Uuid::from_u128(3)),
            ];
            let entries = raw
                .iter()
                .enumerate()
                .map(|(index, (depth, key, tombstone))| ScopeResolutionEntry {
                    scope_id: chain[usize::from(*depth)],
                    name_lookup: vec![*key],
                    secret_id: SecretId(Uuid::from_u128(100 + index as u128)),
                    status: if *tombstone {
                        SecretStatus::Tombstone
                    } else {
                        SecretStatus::Active
                    },
                })
                .collect::<Vec<_>>();
            let mut reversed = entries.clone();
            reversed.reverse();
            prop_assert_eq!(
                resolve_scope_entries(&chain, &entries),
                resolve_scope_entries(&chain, &reversed)
            );
        }
    }
}
