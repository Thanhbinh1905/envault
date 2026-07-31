use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use envault_core::{
    EntityKind, GeneratorFormat, GeneratorLength, GeneratorSpec, InvariantError, ScopeId, SecretId,
    SecretVersionId, SecretVersionView, VaultId, validate_description, validate_generator,
};
use envault_crypto::{SecretBytes, SecretKey, encrypt, random_bytes};
use envault_store::{SecretVersionRecord, StoreError};
use uuid::Uuid;

use super::{ALGORITHM_VERSION, FORMAT_VERSION, ServiceError};

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(super) struct GeneratedValue {
    pub(super) value: SecretBytes,
    pub(super) metadata: GeneratorMetadata,
}

#[derive(Clone, Copy)]
pub(super) struct GeneratorMetadata {
    pub(super) format: GeneratorFormat,
    pub(super) length: usize,
    pub(super) entropy_bits: u32,
}

pub(super) fn generate_value(spec: GeneratorSpec) -> Result<GeneratedValue, ServiceError> {
    let spec = validate_generator(spec)?;
    match (spec.format, spec.length) {
        (GeneratorFormat::UuidV4, GeneratorLength::Default) => {
            let value = Uuid::new_v4().hyphenated().to_string();
            Ok(GeneratedValue {
                metadata: GeneratorMetadata {
                    format: spec.format,
                    length: value.len(),
                    entropy_bits: 122,
                },
                value: SecretBytes::new(value.into_bytes()),
            })
        }
        (GeneratorFormat::Base64Url, GeneratorLength::Default) => {
            generate_encoded_bytes(spec.format, 32, false)
        }
        (GeneratorFormat::Base64Url, GeneratorLength::Bytes(bytes)) => {
            generate_encoded_bytes(spec.format, bytes, false)
        }
        (GeneratorFormat::Base64Url, GeneratorLength::Chars(chars)) => {
            let random = random_bytes(chars)?;
            let value = random
                .as_ref()
                .iter()
                .map(|byte| BASE64URL_ALPHABET[usize::from(byte & 63)])
                .collect::<Vec<_>>();
            Ok(GeneratedValue {
                value: SecretBytes::new(value),
                metadata: GeneratorMetadata {
                    format: spec.format,
                    length: chars,
                    entropy_bits: u32::try_from(chars.saturating_mul(6)).unwrap_or(u32::MAX),
                },
            })
        }
        (GeneratorFormat::Base64, GeneratorLength::Default) => {
            generate_encoded_bytes(spec.format, 32, true)
        }
        (GeneratorFormat::Base64, GeneratorLength::Bytes(bytes)) => {
            generate_encoded_bytes(spec.format, bytes, true)
        }
        (GeneratorFormat::UuidV4, _) | (GeneratorFormat::Base64, GeneratorLength::Chars(_)) => Err(
            ServiceError::Invariant(InvariantError::InvalidGeneratorLength),
        ),
    }
}

fn generate_encoded_bytes(
    format: GeneratorFormat,
    byte_count: usize,
    padded: bool,
) -> Result<GeneratedValue, ServiceError> {
    let random = random_bytes(byte_count)?;
    let value = if padded {
        STANDARD.encode(random.as_ref())
    } else {
        URL_SAFE_NO_PAD.encode(random.as_ref())
    };
    Ok(GeneratedValue {
        metadata: GeneratorMetadata {
            format,
            length: value.len(),
            entropy_bits: u32::try_from(byte_count.saturating_mul(8)).unwrap_or(u32::MAX),
        },
        value: SecretBytes::new(value.into_bytes()),
    })
}

pub(super) fn version_view(
    record: &SecretVersionRecord,
) -> Result<SecretVersionView, ServiceError> {
    Ok(SecretVersionView {
        id: record.id,
        secret_id: record.secret_id,
        version: record.version,
        generator: record.generator.map(generator_format).transpose()?,
        generated_length: record
            .generated_length
            .map(usize::try_from)
            .transpose()
            .map_err(|_| ServiceError::Corrupt)?,
        entropy_bits: record.entropy_bits,
    })
}

pub(super) fn generator_code(format: GeneratorFormat) -> u8 {
    match format {
        GeneratorFormat::UuidV4 => 1,
        GeneratorFormat::Base64Url => 2,
        GeneratorFormat::Base64 => 3,
    }
}

fn generator_format(code: u8) -> Result<GeneratorFormat, ServiceError> {
    match code {
        1 => Ok(GeneratorFormat::UuidV4),
        2 => Ok(GeneratorFormat::Base64Url),
        3 => Ok(GeneratorFormat::Base64),
        _ => Err(ServiceError::Corrupt),
    }
}

pub(super) fn encrypt_text(
    key: &SecretKey,
    vault_id: VaultId,
    kind: EntityKind,
    id: Uuid,
    field: &str,
    value: &str,
) -> Result<Vec<u8>, ServiceError> {
    let aad = metadata_aad(vault_id, kind, id, field);
    Ok(encrypt(key, value.as_bytes(), &aad)?.encode())
}

pub(super) fn vmk_aad(vault_id: VaultId) -> Vec<u8> {
    encode_aad(&[
        b"envault-vmk-wrap",
        vault_id.0.as_bytes(),
        &FORMAT_VERSION.to_be_bytes(),
        ALGORITHM_VERSION,
    ])
}

pub(super) fn metadata_aad(vault_id: VaultId, kind: EntityKind, id: Uuid, field: &str) -> Vec<u8> {
    let kind = match kind {
        EntityKind::Profile => b"profile".as_slice(),
        EntityKind::Scope => b"scope".as_slice(),
        EntityKind::Secret => b"secret".as_slice(),
        EntityKind::SecretVersion => b"secret-version".as_slice(),
    };
    encode_aad(&[
        b"envault-metadata",
        vault_id.0.as_bytes(),
        kind,
        id.as_bytes(),
        field.as_bytes(),
        ALGORITHM_VERSION,
    ])
}

pub(super) fn secret_value_aad(
    vault_id: VaultId,
    secret_id: SecretId,
    version_id: SecretVersionId,
    scope_id: ScopeId,
    version: u64,
) -> Vec<u8> {
    encode_aad(&[
        b"envault-secret-value",
        vault_id.0.as_bytes(),
        secret_id.0.as_bytes(),
        version_id.0.as_bytes(),
        scope_id.0.as_bytes(),
        &version.to_be_bytes(),
        ALGORITHM_VERSION,
    ])
}

pub(super) fn secret_wrap_aad(
    vault_id: VaultId,
    secret_id: SecretId,
    version_id: SecretVersionId,
    scope_id: ScopeId,
    version: u64,
) -> Vec<u8> {
    encode_aad(&[
        b"envault-secret-dek-wrap",
        vault_id.0.as_bytes(),
        secret_id.0.as_bytes(),
        version_id.0.as_bytes(),
        scope_id.0.as_bytes(),
        &version.to_be_bytes(),
        ALGORITHM_VERSION,
    ])
}

fn encode_aad(parts: &[&[u8]]) -> Vec<u8> {
    let capacity = parts
        .iter()
        .map(|part| 4_usize.saturating_add(part.len()))
        .sum();
    let mut output = Vec::with_capacity(capacity);
    for part in parts {
        let length = u32::try_from(part.len()).expect("AAD component length is bounded");
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(part);
    }
    output
}

pub(super) fn validate_optional_description(description: Option<&str>) -> Result<(), ServiceError> {
    description.map(validate_description).transpose()?;
    Ok(())
}

pub(super) fn encode_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ServiceError> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).map_err(|_| ServiceError::Serialization)?;
    Ok(encoded)
}

pub(super) fn decode_cbor<T: serde::de::DeserializeOwned>(value: &[u8]) -> Result<T, ServiceError> {
    let mut cursor = std::io::Cursor::new(value);
    let decoded = ciborium::from_reader(&mut cursor).map_err(|_| ServiceError::Serialization)?;
    if usize::try_from(cursor.position()).ok() != Some(value.len()) {
        return Err(ServiceError::Serialization);
    }
    Ok(decoded)
}

pub(super) fn unix_seconds() -> Result<i64, ServiceError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServiceError::Time)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ServiceError::Time)
}

pub(super) fn map_store_initialization(error: StoreError) -> ServiceError {
    match error {
        StoreError::NotInitialized => ServiceError::NotInitialized,
        other => ServiceError::Store(other),
    }
}

pub(super) fn remove_database_artifacts(database_path: &Path) {
    let _ = fs::remove_file(database_path);
    remove_sidecars(database_path);
}

pub(super) fn publish_no_replace(source: &Path, destination: &Path) -> Result<(), ServiceError> {
    fs::hard_link(source, destination)?;
    let _ = fs::remove_file(source);
    Ok(())
}

pub(super) fn remove_sidecars(database_path: &Path) {
    let mut wal = database_path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shared_memory = database_path.as_os_str().to_os_string();
    shared_memory.push("-shm");
    let _ = fs::remove_file(PathBuf::from(wal));
    let _ = fs::remove_file(PathBuf::from(shared_memory));
}
