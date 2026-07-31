#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const SALT_BYTES: usize = 16;
pub const TAG_BYTES: usize = 16;
pub const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;
pub const MAX_KDF_ITERATIONS: u32 = 20;
pub const MAX_KDF_PARALLELISM: u32 = 16;

/// Implements a `Debug` impl that never prints a type's contents, only its
/// name - for newtypes wrapping secret material where the derived `Debug`
/// would otherwise leak the plaintext on the first `{:?}` format call.
#[macro_export]
macro_rules! redacted_debug {
    ($type_name:ty) => {
        impl core::fmt::Debug for $type_name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str(concat!(stringify!($type_name), "([REDACTED])"))
            }
        }
    };
}

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

    pub fn copy_bytes(&self) -> SecretBytes {
        SecretBytes::copy_from_slice(&self.0)
    }

    fn expose(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

redacted_debug!(SecretBytes);
redacted_debug!(SecretKey);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

impl KdfParameters {
    pub fn benchmark(target: Duration) -> Result<Self, CryptoError> {
        let salt = random_array::<SALT_BYTES>()?;
        let password = b"envault-kdf-calibration";
        let baseline = Self {
            memory_kib: 64 * 1024,
            iterations: 1,
            parallelism: 1,
        };
        let started = Instant::now();
        let key = derive_key(password, &salt, baseline)?;
        drop(key);
        let elapsed = started.elapsed().max(Duration::from_millis(1));
        let target_millis = target.as_millis().max(1);
        let elapsed_millis = elapsed.as_millis().max(1);
        let iterations = u32::try_from(target_millis.div_ceil(elapsed_millis))
            .unwrap_or(u32::MAX)
            .clamp(1, 10);
        Ok(Self {
            iterations,
            ..baseline
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    pub nonce: [u8; NONCE_BYTES],
    pub bytes: Vec<u8>,
}

impl Ciphertext {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(NONCE_BYTES + self.bytes.len());
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.bytes);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CryptoError> {
        if encoded.len() < NONCE_BYTES + TAG_BYTES {
            return Err(CryptoError::InvalidCiphertext);
        }
        let nonce = encoded[..NONCE_BYTES]
            .try_into()
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        Ok(Self {
            nonce,
            bytes: encoded[NONCE_BYTES..].to_vec(),
        })
    }
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
    #[error("ciphertext is malformed")]
    InvalidCiphertext,
    #[error("wrapped key has an invalid length")]
    InvalidKeyLength,
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_BYTES],
    parameters: KdfParameters,
) -> Result<SecretKey, CryptoError> {
    if parameters.memory_kib > MAX_KDF_MEMORY_KIB
        || parameters.iterations > MAX_KDF_ITERATIONS
        || parameters.parallelism > MAX_KDF_PARALLELISM
    {
        return Err(CryptoError::InvalidKdfParameters);
    }
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

pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Random)?;
    Ok(bytes)
}

pub fn random_bytes(size: usize) -> Result<SecretBytes, CryptoError> {
    let mut bytes = vec![0_u8; size];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Random)?;
    Ok(SecretBytes::new(bytes))
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
) -> Result<SecretBytes, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    cipher
        .decrypt(
            &XNonce::from(ciphertext.nonce),
            Payload {
                msg: &ciphertext.bytes,
                aad,
            },
        )
        .map(SecretBytes::new)
        .map_err(|_| CryptoError::Authentication)
}

pub fn wrap_key(
    wrapping_key: &SecretKey,
    key: &SecretKey,
    aad: &[u8],
) -> Result<Ciphertext, CryptoError> {
    encrypt(wrapping_key, key.expose(), aad)
}

pub fn unwrap_key(
    wrapping_key: &SecretKey,
    ciphertext: &Ciphertext,
    aad: &[u8],
) -> Result<SecretKey, CryptoError> {
    let plaintext = decrypt(wrapping_key, ciphertext, aad)?;
    let bytes: [u8; KEY_BYTES] = plaintext
        .as_ref()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(SecretKey::from_bytes(bytes))
}

pub fn lookup_digest(key: &SecretKey, domain: &str, value: &[u8]) -> [u8; 32] {
    let subkey = blake3::derive_key(domain, key.expose());
    *blake3::keyed_hash(&subkey, value).as_bytes()
}

/// Constant-time byte comparison: unequal lengths short-circuit (length is
/// not secret in any of this crate's callers), but for equal-length inputs
/// every byte is folded regardless of earlier mismatches.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_binds_associated_data() {
        let key = SecretKey::generate().expect("random key");
        let encrypted = encrypt(&key, b"fixture-value", b"vault:one").expect("encrypt");
        assert_eq!(
            decrypt(&key, &encrypted, b"vault:one")
                .expect("decrypt")
                .as_ref(),
            b"fixture-value".as_slice()
        );
        assert!(decrypt(&key, &encrypted, b"vault:two").is_err());
    }

    #[test]
    fn debug_never_exposes_key_material() {
        let key = SecretKey::from_bytes([7; KEY_BYTES]);
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
    }

    #[test]
    fn wrapped_key_round_trip_is_domain_bound() {
        let wrapping_key = SecretKey::generate().expect("wrapping key");
        let wrapped_key = SecretKey::generate().expect("wrapped key");
        let ciphertext = wrap_key(&wrapping_key, &wrapped_key, b"dek:one").expect("wrap");
        let unwrapped = unwrap_key(&wrapping_key, &ciphertext, b"dek:one").expect("unwrap");
        assert_eq!(
            lookup_digest(&wrapped_key, "test", b"value"),
            lookup_digest(&unwrapped, "test", b"value")
        );
        assert!(unwrap_key(&wrapping_key, &ciphertext, b"dek:two").is_err());
    }

    #[test]
    fn encoded_ciphertext_round_trips() {
        let key = SecretKey::generate().expect("key");
        let ciphertext = encrypt(&key, b"value", b"aad").expect("encrypt");
        assert_eq!(
            Ciphertext::decode(&ciphertext.encode()).expect("decode"),
            ciphertext
        );
    }

    #[test]
    fn random_nonces_do_not_repeat_in_a_large_sample() {
        let key = SecretKey::generate().expect("key");
        let mut nonces = std::collections::HashSet::new();
        for index in 0_u32..1024 {
            let ciphertext = encrypt(&key, &index.to_be_bytes(), b"nonce-test").expect("encrypt");
            assert!(nonces.insert(ciphertext.nonce));
        }
    }

    #[test]
    fn hostile_kdf_parameters_are_rejected_before_allocation() {
        let salt = [0_u8; SALT_BYTES];
        assert!(matches!(
            derive_key(
                b"password",
                &salt,
                KdfParameters {
                    memory_kib: u32::MAX,
                    iterations: u32::MAX,
                    parallelism: u32::MAX,
                }
            ),
            Err(CryptoError::InvalidKdfParameters)
        ));
    }
}
