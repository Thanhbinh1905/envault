#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_ADMIN_LEASE_MINUTES: u8 = 5;
pub const DEFAULT_AGENT_GRANT_MINUTES: u8 = 15;
pub const MIN_ADMIN_LEASE_MINUTES: u8 = 1;
pub const MAX_ADMIN_LEASE_MINUTES: u8 = 30;
pub const MAX_DESCRIPTION_BYTES: usize = 240;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct VaultId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ProfileId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ScopeId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SecretId(pub Uuid);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SecretVersionId(pub Uuid);

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
    #[error("description exceeds 240 UTF-8 bytes")]
    DescriptionTooLong,
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
    if description.len() <= MAX_DESCRIPTION_BYTES {
        Ok(())
    } else {
        Err(InvariantError::DescriptionTooLong)
    }
}

#[cfg(test)]
mod tests {
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
}
