#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Request<T> {
    pub version: u16,
    pub request_id: Uuid,
    pub body: T,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructuredError {
    pub code: String,
    pub message: String,
    pub help: Vec<String>,
    pub request_id: Uuid,
    pub retryable: bool,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame exceeds one MiB")]
    FrameTooLarge,
    #[error("frame length does not match payload")]
    InvalidLength,
    #[error("CBOR encoding failed")]
    Encode,
    #[error("CBOR decoding failed")]
    Decode,
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    ciborium::into_writer(value, &mut payload).map_err(|_| ProtocolError::Encode)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, ProtocolError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(ProtocolError::InvalidLength)?
        .try_into()
        .map_err(|_| ProtocolError::InvalidLength)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let payload = frame.get(4..).ok_or(ProtocolError::InvalidLength)?;
    if payload.len() != length {
        return Err(ProtocolError::InvalidLength);
    }
    ciborium::from_reader(payload).map_err(|_| ProtocolError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_is_length_delimited() {
        let request = Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            body: "status".to_owned(),
        };
        let frame = encode_frame(&request).expect("encode");
        assert_eq!(
            decode_frame::<Request<String>>(&frame).expect("decode"),
            request
        );
    }

    #[test]
    fn rejects_mismatched_length() {
        let mut frame = encode_frame(&"status").expect("encode");
        frame[3] = frame[3].saturating_add(1);
        assert!(matches!(
            decode_frame::<String>(&frame),
            Err(ProtocolError::InvalidLength)
        ));
    }
}
