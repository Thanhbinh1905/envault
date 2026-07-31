use std::io::{self, Read, Write};

use envault_protocol::{MAX_FRAME_BYTES, ProtocolError, decode_frame, encode_frame};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

pub(crate) fn read_sync_frame<T: DeserializeOwned>(
    reader: &mut impl Read,
) -> Result<T, ProtocolError> {
    let mut prefix = [0; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|error| map_read_error(&error))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let capacity = length.checked_add(4).ok_or(ProtocolError::FrameTooLarge)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(capacity));
    frame.extend_from_slice(&prefix);
    frame.resize(capacity, 0);
    reader
        .read_exact(&mut frame[4..])
        .map_err(|error| map_read_error(&error))?;
    decode_frame(&frame)
}

pub(crate) fn write_sync_frame<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
) -> Result<(), ProtocolError> {
    let frame = Zeroizing::new(encode_frame(value)?);
    writer
        .write_all(&frame)
        .map_err(|_| ProtocolError::Encode)?;
    writer.flush().map_err(|_| ProtocolError::Encode)
}

/// Reads one length-prefixed CBOR frame from any async byte stream. Generic
/// over the stream type rather than a concrete `tokio::net::UnixStream`
/// because the daemon's connection-handling and dispatch logic is shared
/// between the Unix socket transport and the Windows named-pipe transport;
/// both `tokio::net::UnixStream` and
/// `tokio::net::windows::named_pipe::NamedPipeServer` implement
/// `AsyncRead`/`AsyncWrite`, so this framing code needs no platform-specific
/// variant of its own.
pub(crate) async fn read_async_frame<T: DeserializeOwned>(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<T, ProtocolError> {
    use tokio::io::AsyncReadExt;

    let mut prefix = [0; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|error| map_read_error(&error))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let capacity = length.checked_add(4).ok_or(ProtocolError::FrameTooLarge)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(capacity));
    frame.extend_from_slice(&prefix);
    frame.resize(capacity, 0);
    stream
        .read_exact(&mut frame[4..])
        .await
        .map_err(|error| map_read_error(&error))?;
    decode_frame(&frame)
}

/// Writes one length-prefixed CBOR frame to any async byte stream. See
/// `read_async_frame` for why this is generic rather than Unix-specific.
pub(crate) async fn write_async_frame<T: Serialize>(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    value: &T,
) -> Result<(), ProtocolError> {
    use tokio::io::{AsyncWriteExt, BufWriter};

    let frame = Zeroizing::new(encode_frame(value)?);
    let mut writer = BufWriter::new(stream);
    writer
        .write_all(&frame)
        .await
        .map_err(|_| ProtocolError::Encode)?;
    writer.flush().await.map_err(|_| ProtocolError::Encode)
}

fn map_read_error(error: &io::Error) -> ProtocolError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => ProtocolError::InvalidLength,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ProtocolError::DeadlineExceeded,
        _ => ProtocolError::Decode,
    }
}
