use std::path::PathBuf;

#[cfg(unix)]
use std::{
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use envault_protocol::{
    AuthenticatedRequest, PROTOCOL_VERSION, ProtocolError, Request, Response, ResponseBody,
    validate_version,
};
#[cfg(unix)]
use envault_protocol::{BootstrapRequest, ServiceState};
use envault_protocol::{DaemonStatus, Operation, Reply, SensitiveBytes, StructuredError};
use thiserror::Error;
use uuid::Uuid;

use crate::ipc::{read_sync_frame, write_sync_frame};

#[cfg(unix)]
const DAEMON_TRANSITION_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(unix)]
const DAEMON_TRANSITION_INTERVAL: Duration = Duration::from_millis(100);

#[cfg(unix)]
const IPC_RESPONSE_TIMEOUT: Duration =
    Duration::from_secs(envault_protocol::DEFAULT_REQUEST_TIMEOUT_SECONDS + 1);

#[cfg(unix)]
const PORTABILITY_RESPONSE_TIMEOUT: Duration =
    Duration::from_secs(envault_protocol::PORTABILITY_REQUEST_TIMEOUT_SECONDS + 1);

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("EnVault daemon is not running")]
    NotRunning,
    #[error("EnVault daemon did not respond before the deadline")]
    Timeout,
    #[error("EnVault portability operation did not respond before the deadline")]
    PortabilityTimeout,
    #[error("EnVault IPC protocol failed")]
    Protocol,
    #[error("EnVault daemon returned an error")]
    Remote(StructuredError),
    #[error("EnVault daemon returned an unexpected response")]
    UnexpectedResponse,
    #[error("this platform does not support EnVault IPC yet")]
    UnsupportedPlatform,
}

pub fn socket_path() -> Result<PathBuf, ClientError> {
    envault_platform::runtime_directory()
        .map(|directory| directory.join("envault.sock"))
        .map_err(|_| ClientError::NotRunning)
}

pub fn request(operation: Operation) -> Result<Reply, ClientError> {
    request_with_capability(operation, None)
}

pub fn request_with_capability(
    operation: Operation,
    capability_token: Option<SensitiveBytes>,
) -> Result<Reply, ClientError> {
    request_at(&socket_path()?, operation, capability_token)
}

#[cfg(unix)]
pub fn start(password: SensitiveBytes) -> Result<DaemonStatus, ClientError> {
    let _start_lock = acquire_start_lock()?;
    match request(Operation::Status) {
        Ok(Reply::Status(status)) if status.service == ServiceState::Unlocked => return Ok(status),
        Ok(Reply::Status(_)) => {
            match request(Operation::Stop) {
                Ok(Reply::Acknowledged) | Err(ClientError::NotRunning) => {}
                Ok(_) => return Err(ClientError::UnexpectedResponse),
                Err(error) => return Err(error),
            }
            if let Some(status) = wait_for_daemon_exit()? {
                return Ok(status);
            }
        }
        Err(ClientError::NotRunning) => {}
        Ok(_) => return Err(ClientError::UnexpectedResponse),
        Err(error) => return Err(error),
    }
    match spawn_daemon(password) {
        Err(ClientError::Remote(error)) if error.code == "daemon_busy" => wait_for_running_daemon(),
        result => result,
    }
}

/// The named-pipe transport, peer authentication, and the daemon-side
/// accept loop `envaultd` now runs on Windows are all implemented (see ADR
/// 0013) and reachable by `request_at` below once a daemon is already
/// running. What remains unimplemented here is specifically the
/// spawn-on-demand convenience `start` provides on Unix: launching
/// `envaultd` as a detached background process and waiting for its
/// bootstrap handshake. Unix daemonization (`setsid`, closing inherited
/// descriptors, the bootstrap stdio protocol in `spawn_daemon`) has no
/// direct Windows equivalent, and getting that process-launch and
/// detachment story right is a distinct piece of work from the transport
/// itself; it has not been attempted yet under the same no-real-Windows-
/// runtime constraint that shaped the rest of this phase, and is tracked as
/// a follow-up rather than guessed at. A human or supervisor can still run
/// `envaultd` directly today and reach it through every other client
/// operation.
#[cfg(windows)]
pub fn start(_password: SensitiveBytes) -> Result<DaemonStatus, ClientError> {
    Err(ClientError::UnsupportedPlatform)
}

#[cfg(unix)]
pub fn request_at(
    path: &std::path::Path,
    operation: Operation,
    capability_token: Option<SensitiveBytes>,
) -> Result<Reply, ClientError> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(path).map_err(|_| ClientError::NotRunning)?;
    authenticate_server(path, &stream)?;
    let is_portability = operation.is_portability();
    let timeout = Some(if is_portability {
        PORTABILITY_RESPONSE_TIMEOUT
    } else {
        IPC_RESPONSE_TIMEOUT
    });
    stream
        .set_read_timeout(timeout)
        .map_err(|_| ClientError::Protocol)?;
    stream
        .set_write_timeout(timeout)
        .map_err(|_| ClientError::Protocol)?;
    let request_id = Uuid::new_v4();
    let request = Request {
        version: PROTOCOL_VERSION,
        request_id,
        body: AuthenticatedRequest {
            capability_token,
            operation,
        },
    };
    write_sync_frame(&mut stream, &request).map_err(|_| ClientError::Protocol)?;
    let response: Response<Reply> = read_sync_frame(&mut stream).map_err(|error| {
        if matches!(error, ProtocolError::DeadlineExceeded) {
            if is_portability {
                ClientError::PortabilityTimeout
            } else {
                ClientError::Timeout
            }
        } else {
            ClientError::Protocol
        }
    })?;
    validate_version(response.version).map_err(|_| ClientError::Protocol)?;
    if response.request_id != request_id {
        return Err(ClientError::Protocol);
    }
    match response.body {
        ResponseBody::Ok(reply) => Ok(reply),
        ResponseBody::Error(error) => Err(ClientError::Remote(error)),
    }
}

#[cfg(unix)]
fn spawn_daemon(password: SensitiveBytes) -> Result<DaemonStatus, ClientError> {
    let executable = daemon_executable()?;
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ClientError::NotRunning)?;
    let child_pid = child.id();
    let request_id = Uuid::new_v4();
    let bootstrap = Request {
        version: PROTOCOL_VERSION,
        request_id,
        body: BootstrapRequest { password },
    };
    let mut stdin = child.stdin.take().ok_or(ClientError::Protocol)?;
    if write_sync_frame(&mut stdin, &bootstrap).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ClientError::Protocol);
    }
    drop(stdin);
    drop(bootstrap);
    let mut stdout = child.stdout.take().ok_or(ClientError::Protocol)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let response = read_sync_frame::<Response<Reply>>(&mut stdout);
        let _ = sender.send(response);
    });
    let response = match receiver.recv_timeout(Duration::from_secs(30)) {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ClientError::Protocol);
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ClientError::Timeout);
        }
    };
    validate_version(response.version).map_err(|_| ClientError::Protocol)?;
    if response.request_id != request_id {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ClientError::Protocol);
    }
    match response.body {
        ResponseBody::Ok(Reply::Status(status))
            if status.service == ServiceState::Unlocked && status.pid == child_pid =>
        {
            drop(child);
            Ok(status)
        }
        ResponseBody::Ok(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(ClientError::UnexpectedResponse)
        }
        ResponseBody::Error(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(ClientError::Remote(error))
        }
    }
}

#[cfg(unix)]
fn daemon_executable() -> Result<PathBuf, ClientError> {
    let executable = std::env::current_exe().map_err(|_| ClientError::NotRunning)?;
    let daemon = executable.with_file_name("envaultd");
    if daemon.is_file() {
        Ok(daemon)
    } else {
        Err(ClientError::NotRunning)
    }
}

#[cfg(unix)]
fn wait_for_daemon_exit() -> Result<Option<DaemonStatus>, ClientError> {
    let runtime = envault_platform::runtime_directory().map_err(|_| ClientError::Protocol)?;
    envault_platform::create_private_directory(&runtime).map_err(|_| ClientError::Protocol)?;
    let lock_path = runtime.join("envaultd.lock");
    let lock =
        envault_platform::open_private_lock_file(&lock_path).map_err(|_| ClientError::Protocol)?;
    let deadline = Instant::now()
        .checked_add(DAEMON_TRANSITION_TIMEOUT)
        .ok_or(ClientError::Timeout)?;
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(None),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(_) => return Err(ClientError::Protocol),
        }
        match request(Operation::Status) {
            Ok(Reply::Status(status)) if status.service == ServiceState::Unlocked => {
                return Ok(Some(status));
            }
            Ok(Reply::Status(_))
            | Err(ClientError::NotRunning | ClientError::Protocol | ClientError::Timeout) => {}
            Ok(_) => return Err(ClientError::UnexpectedResponse),
            Err(ClientError::Remote(error)) if error.retryable => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(ClientError::Timeout);
        }
        std::thread::sleep(DAEMON_TRANSITION_INTERVAL);
    }
}

#[cfg(unix)]
fn acquire_start_lock() -> Result<std::fs::File, ClientError> {
    let runtime = envault_platform::runtime_directory().map_err(|_| ClientError::Protocol)?;
    envault_platform::create_private_directory(&runtime).map_err(|_| ClientError::Protocol)?;
    let lock = envault_platform::open_private_lock_file(&runtime.join("envault-start.lock"))
        .map_err(|_| ClientError::Protocol)?;
    let deadline = Instant::now()
        .checked_add(DAEMON_TRANSITION_TIMEOUT)
        .ok_or(ClientError::Timeout)?;
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(lock),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(_) => return Err(ClientError::Protocol),
        }
        if Instant::now() >= deadline {
            return Err(ClientError::Timeout);
        }
        std::thread::sleep(DAEMON_TRANSITION_INTERVAL);
    }
}

#[cfg(unix)]
fn wait_for_running_daemon() -> Result<DaemonStatus, ClientError> {
    let deadline = Instant::now()
        .checked_add(DAEMON_TRANSITION_TIMEOUT)
        .ok_or(ClientError::Timeout)?;
    loop {
        match request(Operation::Status) {
            Ok(Reply::Status(status)) if status.service == ServiceState::Unlocked => {
                return Ok(status);
            }
            Ok(Reply::Status(_))
            | Err(ClientError::NotRunning | ClientError::Protocol | ClientError::Timeout) => {}
            Ok(_) => return Err(ClientError::UnexpectedResponse),
            Err(ClientError::Remote(error)) if error.retryable => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(ClientError::Timeout);
        }
        std::thread::sleep(DAEMON_TRANSITION_INTERVAL);
    }
}

#[cfg(unix)]
fn authenticate_server(
    path: &std::path::Path,
    stream: &std::os::unix::net::UnixStream,
) -> Result<(), ClientError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let socket = std::fs::symlink_metadata(path).map_err(|_| ClientError::Protocol)?;
    let parent = path.parent().ok_or(ClientError::Protocol)?;
    let directory = std::fs::symlink_metadata(parent).map_err(|_| ClientError::Protocol)?;
    if !socket.file_type().is_socket()
        || socket.file_type().is_symlink()
        || socket.permissions().mode() & 0o777 != 0o600
        || socket.nlink() != 1
        || !directory.file_type().is_dir()
        || directory.file_type().is_symlink()
        || directory.permissions().mode() & 0o777 != 0o700
        || socket.uid() != directory.uid()
    {
        return Err(ClientError::Protocol);
    }
    let peer_uid = server_peer_uid(stream)?;
    if peer_uid != socket.uid() {
        return Err(ClientError::Protocol);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn server_peer_uid(stream: &std::os::unix::net::UnixStream) -> Result<u32, ClientError> {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map(|credentials| credentials.uid())
        .map_err(|_| ClientError::Protocol)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
fn server_peer_uid(stream: &std::os::unix::net::UnixStream) -> Result<u32, ClientError> {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerCred)
        .map(|credentials| credentials.uid())
        .map_err(|_| ClientError::Protocol)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
fn server_peer_uid(_stream: &std::os::unix::net::UnixStream) -> Result<u32, ClientError> {
    Err(ClientError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_daemon_path_does_not_use_shell_or_environment_lookup() {
        let current = std::env::current_exe().expect("current exe");
        let sibling = current.with_file_name("envaultd");
        assert_eq!(sibling.parent(), current.parent());
        assert_eq!(
            sibling.file_name().and_then(|name| name.to_str()),
            Some("envaultd")
        );
    }

    #[test]
    fn socket_path_is_runtime_scoped() {
        let path = socket_path();
        if let Ok(path) = path {
            assert_eq!(
                path.file_name().and_then(|name| name.to_str()),
                Some("envault.sock")
            );
        }
    }
}

/// Named pipes live in their own namespace (`\\.\pipe\`), not on a
/// filesystem the runtime directory's ownership/permission metadata
/// describes, so this derives a pipe name from the same `socket_path`
/// input instead of treating it as a literal path, keeping one scoped name
/// per runtime directory the same way the Unix socket file is scoped.
#[cfg(windows)]
pub(crate) fn windows_pipe_name(socket_path: &std::path::Path) -> String {
    let sanitized: String = socket_path
        .to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect();
    format!(r"\\.\pipe\{sanitized}")
}

/// Known gap: unlike the Unix path, which sets a socket read/write timeout
/// via `set_read_timeout`/`set_write_timeout`, a `File`-wrapped named-pipe
/// handle has no equivalent synchronous timeout primitive in `std`; enforcing
/// `IPC_RESPONSE_TIMEOUT`/`PORTABILITY_RESPONSE_TIMEOUT` here requires either
/// a watchdog thread that closes the handle past the deadline or switching to
/// overlapped I/O, neither of which is implemented in this pass. Tracked as a
/// follow-up alongside the daemon-side listener this transport currently has
/// nothing to connect to.
#[cfg(windows)]
pub fn request_at(
    path: &std::path::Path,
    operation: Operation,
    capability_token: Option<SensitiveBytes>,
) -> Result<Reply, ClientError> {
    let pipe_name = windows_pipe_name(path);
    let mut stream =
        envault_windows_ffi::connect_named_pipe_client(std::ffi::OsStr::new(&pipe_name))
            .map_err(|_| ClientError::NotRunning)?;
    match envault_windows_ffi::verify_pipe_server_is_current_user(&stream) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Err(ClientError::Protocol),
    }
    let is_portability = operation.is_portability();
    let request_id = Uuid::new_v4();
    let request = Request {
        version: PROTOCOL_VERSION,
        request_id,
        body: AuthenticatedRequest {
            capability_token,
            operation,
        },
    };
    write_sync_frame(&mut stream, &request).map_err(|_| ClientError::Protocol)?;
    let response: Response<Reply> = read_sync_frame(&mut stream).map_err(|error| {
        if matches!(error, ProtocolError::DeadlineExceeded) {
            if is_portability {
                ClientError::PortabilityTimeout
            } else {
                ClientError::Timeout
            }
        } else {
            ClientError::Protocol
        }
    })?;
    validate_version(response.version).map_err(|_| ClientError::Protocol)?;
    if response.request_id != request_id {
        return Err(ClientError::Protocol);
    }
    match response.body {
        ResponseBody::Ok(reply) => Ok(reply),
        ResponseBody::Error(error) => Err(ClientError::Remote(error)),
    }
}
