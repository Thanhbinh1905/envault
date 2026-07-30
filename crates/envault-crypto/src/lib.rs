#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const SALT_BYTES: usize = 16;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_BYTES]);

impl SecretKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0_u8; KEY_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::Random)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    fn expose(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParameters {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParameters {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    pub nonce: [u8; NONCE_BYTES],
    pub bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("operating system randomness unavailable")]
    Random,
    #[error("invalid Argon2id parameters")]
    InvalidKdfParameters,
    #[error("encryption failed")]
    Encryption,
    #[error("authentication failed")]
    Authentication,
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_BYTES],
    parameters: KdfParameters,
) -> Result<SecretKey, CryptoError> {
    let params = Params::new(
        parameters.memory_kib,
        parameters.iterations,
        parameters.parallelism,
        Some(KEY_BYTES),
    )
    .map_err(|_| CryptoError::InvalidKdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; KEY_BYTES];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| CryptoError::Authentication)?;
    Ok(SecretKey::from_bytes(output))
}

pub fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Random)?;
    let bytes = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;
    Ok(Ciphertext { nonce, bytes })
}

pub fn decrypt(
    key: &SecretKey,
    ciphertext: &Ciphertext,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    cipher
        .decrypt(
            &XNonce::from(ciphertext.nonce),
            Payload {
                msg: &ciphertext.bytes,
                aad,
            },
        )
        .map_err(|_| CryptoError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_binds_associated_data() {
        let key = SecretKey::generate().expect("random key");
        let encrypted = encrypt(&key, b"fixture-value", b"vault:one").expect("encrypt");
        assert_eq!(
            decrypt(&key, &encrypted, b"vault:one").expect("decrypt"),
            b"fixture-value"
        );
        assert!(decrypt(&key, &encrypted, b"vault:two").is_err());
    }

    #[test]
    fn debug_never_exposes_key_material() {
        let key = SecretKey::from_bytes([7; KEY_BYTES]);
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
    }
}
