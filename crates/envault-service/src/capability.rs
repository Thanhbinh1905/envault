use envault_crypto::{SecretBytes, SecretKey, lookup_digest, random_array};

use super::ServiceError;

const TOKEN_HASH_DOMAIN: &str = "envault daemon capability token v1";

pub struct CapabilityTokenKey(SecretKey);

impl CapabilityTokenKey {
    pub fn generate() -> Result<Self, ServiceError> {
        SecretKey::generate().map(Self).map_err(ServiceError::from)
    }

    pub fn issue(&self) -> Result<IssuedCapabilityMaterial, ServiceError> {
        let token = SecretBytes::new(random_array::<32>()?.to_vec());
        let digest = lookup_digest(&self.0, TOKEN_HASH_DOMAIN, token.as_ref());
        Ok(IssuedCapabilityMaterial {
            token,
            digest,
            nonce: random_array()?,
        })
    }

    pub fn digest(&self, token: &[u8]) -> [u8; 32] {
        lookup_digest(&self.0, TOKEN_HASH_DOMAIN, token)
    }
}

impl core::fmt::Debug for CapabilityTokenKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CapabilityTokenKey([REDACTED])")
    }
}

pub struct IssuedCapabilityMaterial {
    token: SecretBytes,
    digest: [u8; 32],
    nonce: [u8; 32],
}

impl IssuedCapabilityMaterial {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub fn into_token(self) -> Vec<u8> {
        self.token.into_vec()
    }
}

impl core::fmt::Debug for IssuedCapabilityMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IssuedCapabilityMaterial")
            .field("token", &"[REDACTED]")
            .field("digest", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_capability_material_is_random_hashed_and_redacted() {
        let key = CapabilityTokenKey::generate().expect("key");
        let issued = key.issue().expect("issue");
        assert_eq!(format!("{key:?}"), "CapabilityTokenKey([REDACTED])");
        assert!(!format!("{issued:?}").contains(&format!("{:?}", issued.digest())));
        assert_ne!(issued.nonce(), [0; 32]);
        let digest = issued.digest();
        let token = issued.into_token();
        assert_eq!(token.len(), 32);
        assert_eq!(key.digest(&token), digest);
        assert_ne!(digest, token.as_slice());
    }
}
