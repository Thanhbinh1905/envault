#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeMap,
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use envault_core::validate_admin_lease;
use envault_protocol::{
    AdminLeaseStatus, AuthenticatedRequest, BootstrapRequest, DaemonStatus, ErrorKind,
    HttpConstraint, Operation, PROTOCOL_VERSION, Reply, Request, Response, ResponseBody,
    SensitiveBytes, ServiceState, StructuredError, validate_version,
};
use envault_service::{
    BrokerFailure, CapabilityTokenKey, PackageImportOptions, SensitiveInput, ServiceError,
    VaultSession, classify_broker_failure, execute_agent_http_request,
};
use thiserror::Error;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinSet,
};
use uuid::Uuid;

use crate::ipc::{read_async_frame, read_sync_frame, write_async_frame, write_sync_frame};

const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const MAX_RATE_WINDOWS: usize = 256;
const REQUESTS_PER_MINUTE: u32 = 600;
const GLOBAL_REQUESTS_PER_MINUTE: u32 = 1_200;
const AUTH_ATTEMPTS_PER_MINUTE: u32 = 5;
const GLOBAL_AUTH_ATTEMPTS_PER_MINUTE: u32 = 10;
const ERROR_RESPONSE_GRACE: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
struct ConnectionTiming {
    request_timeout: Duration,
    portability_timeout: Duration,
    error_response_grace: Duration,
}

const CONNECTION_TIMING: ConnectionTiming = ConnectionTiming {
    request_timeout: Duration::from_secs(envault_protocol::DEFAULT_REQUEST_TIMEOUT_SECONDS),
    portability_timeout: Duration::from_secs(envault_protocol::PORTABILITY_REQUEST_TIMEOUT_SECONDS),
    error_response_grace: ERROR_RESPONSE_GRACE,
};

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub database_path: PathBuf,
    pub runtime_directory: PathBuf,
    pub socket_path: PathBuf,
    pub lock_path: PathBuf,
}

impl DaemonConfig {
    pub fn from_platform() -> Result<Self, DaemonError> {
        let database_path = envault_platform::data_directory()?.join("vault.db");
        let runtime_directory = envault_platform::runtime_directory()?;
        Ok(Self {
            database_path,
            socket_path: runtime_directory.join("envault.sock"),
            lock_path: runtime_directory.join("envaultd.lock"),
            runtime_directory,
        })
    }
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("daemon is already running")]
    AlreadyRunning,
    #[error("daemon bootstrap protocol failed")]
    BootstrapProtocol,
    #[error("daemon filesystem operation failed")]
    Io(#[from] io::Error),
    #[error("daemon platform setup failed")]
    Platform(#[from] envault_platform::PlatformError),
    #[error("daemon vault setup failed")]
    Service(#[from] ServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PeerIdentity {
    uid: u32,
    pid: u32,
    session_id: u32,
}

#[derive(Debug)]
struct AdminLease {
    uid: u32,
    /// `None` means no expiration (`--no-expiration`); the lease then only
    /// ends via `lock`/`stop` or an explicit `admin lock`.
    deadline: Option<Instant>,
    expires_at: Option<i64>,
    /// Set only once a connection has re-proven the vault password via
    /// `IssueRevealToken`; cleared along with the rest of the lease, so a
    /// same-uid process that merely observes an active lease can never
    /// reveal a value without independently supplying the password.
    reveal_token_digest: Option<[u8; 32]>,
}

struct RuntimeState {
    vault: Option<VaultSession>,
    database_path: PathBuf,
    admin_lease: Option<AdminLease>,
    reveal_token_key: CapabilityTokenKey,
    rate_limits: BTreeMap<(u32, u32), RateWindow>,
    global_rate_limit: RateWindow,
}

impl RuntimeState {
    fn new(vault: VaultSession, database_path: PathBuf) -> Result<Self, DaemonError> {
        Ok(Self {
            vault: Some(vault),
            database_path,
            admin_lease: None,
            reveal_token_key: CapabilityTokenKey::generate()?,
            rate_limits: BTreeMap::new(),
            global_rate_limit: RateWindow::new(),
        })
    }

    fn status(&mut self, peer: PeerIdentity) -> Result<DaemonStatus, RuntimeFailure> {
        let loaded_profiles = self
            .vault
            .as_ref()
            .map(|vault| {
                Ok::<_, RuntimeFailure>(
                    vault
                        .profiles()
                        .map_err(|_| RuntimeFailure::Internal)?
                        .into_iter()
                        .filter(|profile| profile.activate_on_start)
                        .map(|profile| profile.name)
                        .collect::<Vec<_>>(),
                )
            })
            .transpose()?
            .unwrap_or_default();
        Ok(DaemonStatus {
            service: if self.vault.is_some() {
                ServiceState::Unlocked
            } else {
                ServiceState::Locked
            },
            pid: std::process::id(),
            loaded_profiles,
            admin_lease_active: self.admin_lease_active(peer),
        })
    }

    fn lock(&mut self) {
        self.vault = None;
        self.admin_lease = None;
    }

    fn admin_status(&mut self, peer: PeerIdentity) -> AdminLeaseStatus {
        if self.admin_lease_active(peer) {
            AdminLeaseStatus {
                active: true,
                expires_at: self.admin_lease.as_ref().and_then(|lease| lease.expires_at),
            }
        } else {
            AdminLeaseStatus {
                active: false,
                expires_at: None,
            }
        }
    }

    fn issue_admin_lease(
        &mut self,
        peer: PeerIdentity,
        ttl_minutes: Option<u8>,
    ) -> Result<AdminLeaseStatus, RuntimeFailure> {
        if self.vault.is_none() {
            return Err(RuntimeFailure::Locked);
        }
        let (deadline, expires_at) = match ttl_minutes {
            Some(ttl_minutes) => {
                validate_admin_lease(ttl_minutes).map_err(|_| RuntimeFailure::InvalidTtl)?;
                let duration = Duration::from_secs(u64::from(ttl_minutes) * 60);
                let deadline = Instant::now()
                    .checked_add(duration)
                    .ok_or(RuntimeFailure::Internal)?;
                let expires_at = unix_seconds()?
                    .checked_add(i64::from(ttl_minutes) * 60)
                    .ok_or(RuntimeFailure::Internal)?;
                (Some(deadline), Some(expires_at))
            }
            None => (None, None),
        };
        self.admin_lease = Some(AdminLease {
            uid: peer.uid,
            deadline,
            expires_at,
            reveal_token_digest: None,
        });
        Ok(AdminLeaseStatus {
            active: true,
            expires_at,
        })
    }

    fn clear_admin_lease(&mut self, peer: PeerIdentity) -> Result<(), RuntimeFailure> {
        self.require_admin(peer)?;
        self.admin_lease = None;
        Ok(())
    }

    /// Mints a fresh reveal token bound to the current admin lease, but only
    /// once the caller has re-proven the vault password (checked by the
    /// caller, `issue_reveal_token`, before this runs) - an active lease
    /// alone is not enough. Any previously issued token for this lease is
    /// invalidated by construction, since only one digest is kept.
    fn mint_reveal_token(&mut self, peer: PeerIdentity) -> Result<SensitiveBytes, RuntimeFailure> {
        self.require_admin(peer)?;
        let material = self
            .reveal_token_key
            .issue()
            .map_err(|error| map_service_failure(&error))?;
        self.admin_lease
            .as_mut()
            .ok_or(RuntimeFailure::AdminRequired)?
            .reveal_token_digest = Some(material.digest());
        Ok(SensitiveBytes::new(material.into_token()))
    }

    /// Requires both an active admin lease and a token whose digest matches
    /// the one minted for that lease - a same-uid process that never called
    /// `IssueRevealToken` (and so never supplied the password) has no way to
    /// produce a token that passes this check.
    fn verify_reveal_token(
        &mut self,
        peer: PeerIdentity,
        token: &SensitiveBytes,
    ) -> Result<(), RuntimeFailure> {
        self.require_admin(peer)?;
        let expected_digest = self
            .admin_lease
            .as_ref()
            .and_then(|lease| lease.reveal_token_digest)
            .ok_or(RuntimeFailure::AdminRequired)?;
        let digest = self.reveal_token_key.digest(token.as_slice());
        if envault_crypto::constant_time_eq(&digest, &expected_digest) {
            Ok(())
        } else {
            Err(RuntimeFailure::AdminRequired)
        }
    }

    /// Admin-gated: loads `profile` and configures the HTTP allowlist rule
    /// for one secret in it (`envault profile load ... --action http`).
    fn set_secret_http_access(
        &mut self,
        peer: PeerIdentity,
        profile: &str,
        name: &str,
        constraint: HttpConstraint,
    ) -> Result<(), RuntimeFailure> {
        self.require_admin(peer)?;
        let vault = self.vault.as_mut().ok_or(RuntimeFailure::Locked)?;
        vault
            .load_profile(profile)
            .map_err(|error| map_service_failure(&error))?;
        vault
            .set_secret_http_access(profile, name, constraint)
            .map_err(|error| map_service_failure(&error))
    }

    fn remove_secret_http_access(
        &mut self,
        peer: PeerIdentity,
        profile: &str,
        name: &str,
    ) -> Result<(), RuntimeFailure> {
        self.require_admin(peer)?;
        self.vault
            .as_mut()
            .ok_or(RuntimeFailure::Locked)?
            .remove_secret_http_access(profile, name)
            .map_err(|error| map_service_failure(&error))
    }

    /// Not admin-gated: succeeds only if `profile` is loaded and a matching
    /// `secret_http_access` rule exists for this secret - no principal/token.
    fn prepare_http_request(
        &mut self,
        profile: &str,
        name: &str,
        request: envault_protocol::HttpRequest,
    ) -> Result<envault_service::AgentHttpRequest, RuntimeFailure> {
        self.vault
            .as_mut()
            .ok_or(RuntimeFailure::Locked)?
            .prepare_http_request(profile, name, request)
            .map_err(|error| map_service_failure(&error))
    }

    /// Not admin-gated and not loaded-set-gated: naming a profile here is
    /// itself the explicit action `envault run` requires.
    fn resolve_run_env(
        &mut self,
        profiles: &[String],
    ) -> Result<Vec<envault_protocol::EnvVar>, RuntimeFailure> {
        let values = self
            .vault
            .as_ref()
            .ok_or(RuntimeFailure::Locked)?
            .resolve_run_env(profiles)
            .map_err(|error| map_service_failure(&error))?;
        Ok(values
            .into_iter()
            .map(|(name, value)| envault_protocol::EnvVar {
                name,
                value: SensitiveBytes::new(value.into_vec()),
            })
            .collect())
    }

    fn require_admin(&mut self, peer: PeerIdentity) -> Result<(), RuntimeFailure> {
        if self.vault.is_none() {
            return Err(RuntimeFailure::Locked);
        }
        if self.admin_lease_active(peer) {
            Ok(())
        } else {
            Err(RuntimeFailure::AdminRequired)
        }
    }

    /// Scoped by `uid` alone (not `session_id`): unlocking admin from any
    /// terminal covers every session of that same OS user, so a human can
    /// step up from a second terminal without interrupting an agent running
    /// in the first one.
    fn admin_lease_active(&mut self, peer: PeerIdentity) -> bool {
        if self.admin_lease.as_ref().is_some_and(|lease| {
            lease
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        }) {
            self.admin_lease = None;
        }
        self.admin_lease
            .as_ref()
            .is_some_and(|lease| lease.uid == peer.uid)
    }

    fn rate_window(&mut self, peer: PeerIdentity) -> Result<&mut RateWindow, RuntimeFailure> {
        let key = (peer.uid, peer.session_id);
        if !self.rate_limits.contains_key(&key) {
            self.rate_limits.retain(|_, window| !window.is_stale());
            if self.rate_limits.len() >= MAX_RATE_WINDOWS {
                return Err(RuntimeFailure::RateLimited);
            }
            self.rate_limits.insert(key, RateWindow::new());
        }
        self.rate_limits
            .get_mut(&key)
            .ok_or(RuntimeFailure::Internal)
    }

    fn check_connection_rate(&mut self, peer: PeerIdentity) -> Result<(), RuntimeFailure> {
        self.global_rate_limit
            .check_request(GLOBAL_REQUESTS_PER_MINUTE)?;
        self.rate_window(peer)?.check_request(REQUESTS_PER_MINUTE)
    }

    fn check_authentication_rate(&mut self, peer: PeerIdentity) -> Result<(), RuntimeFailure> {
        self.global_rate_limit
            .check_authentication(GLOBAL_AUTH_ATTEMPTS_PER_MINUTE)?;
        self.rate_window(peer)?
            .check_authentication(AUTH_ATTEMPTS_PER_MINUTE)
    }
}

#[derive(Debug)]
struct RateWindow {
    started: Instant,
    requests: u32,
    authentication_attempts: u32,
}

impl RateWindow {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            requests: 0,
            authentication_attempts: 0,
        }
    }

    fn refresh(&mut self) {
        if self.is_stale() {
            *self = Self::new();
        }
    }

    fn is_stale(&self) -> bool {
        self.started.elapsed() >= Duration::from_mins(1)
    }

    fn check_request(&mut self, limit: u32) -> Result<(), RuntimeFailure> {
        self.refresh();
        if self.requests >= limit {
            return Err(RuntimeFailure::RateLimited);
        }
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or(RuntimeFailure::RateLimited)?;
        Ok(())
    }

    fn check_authentication(&mut self, limit: u32) -> Result<(), RuntimeFailure> {
        self.refresh();
        if self.authentication_attempts >= limit {
            return Err(RuntimeFailure::RateLimited);
        }
        self.authentication_attempts = self
            .authentication_attempts
            .checked_add(1)
            .ok_or(RuntimeFailure::RateLimited)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeFailure {
    Locked,
    AuthenticationFailed,
    AdminRequired,
    PermissionDenied,
    InvalidTtl,
    InvalidInput,
    Io,
    PackageError,
    PackageAuthenticationFailed,
    StaleImportPlan,
    PlaintextAcknowledgementRequired,
    Conflict,
    NotFound,
    ProfileNotLoaded,
    DuplicateSecretAcrossProfiles,
    RequestRejected,
    ResponseRejected,
    ProviderRejected(u16),
    NetworkFailure,
    RateLimited,
    Busy,
    Corrupt,
    DeadlineExceeded,
    PortabilityDeadlineExceeded,
    InvalidRequest,
    ProtocolMismatch,
    Internal,
}

/// A fixed placeholder `PeerIdentity.uid` for every Windows connection.
/// Windows named pipes have no per-connection UID the way Unix sockets do;
/// by the time a connection reaches `RuntimeState`, `is_current_user_pid`
/// has already verified the connecting process shares the daemon's own
/// security identifier, so every authenticated peer is equally "the owner"
/// and a constant here is exactly as meaningful as comparing real UIDs would
/// be on Unix, where every accepted connection also has `peer.uid ==
/// owner_uid` by construction. `peer.session_id`, not `peer.uid`, is what
/// actually distinguishes separate login sessions of that one owner.
#[cfg(windows)]
const WINDOWS_PEER_UID: u32 = 0;

#[cfg(unix)]
struct Server {
    listener: UnixListener,
    state: Arc<Mutex<RuntimeState>>,
    owner_uid: u32,
    socket_guard: SocketGuard,
    _lock_file: File,
    shutdown: Arc<Notify>,
    connections: Arc<Semaphore>,
    authentication: Arc<Semaphore>,
}

#[cfg(windows)]
struct Server {
    listener: NamedPipeServer,
    pipe_name: String,
    state: Arc<Mutex<RuntimeState>>,
    _lock_file: File,
    shutdown: Arc<Notify>,
    connections: Arc<Semaphore>,
    authentication: Arc<Semaphore>,
}

/// Shared by the Unix and Windows `Server::prepare` impls: creates the
/// private runtime directory, acquires the single-instance lock file, and
/// unlocks the vault. Only listener/transport creation differs by platform.
fn prepare_runtime_lock_and_state(
    config: &DaemonConfig,
    password: SensitiveBytes,
) -> Result<(std::fs::File, RuntimeState), DaemonError> {
    envault_platform::create_private_directory(&config.runtime_directory)?;
    let lock_file = envault_platform::open_private_lock_file(&config.lock_path)?;
    match lock_file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Err(DaemonError::AlreadyRunning),
        Err(std::fs::TryLockError::Error(error)) => return Err(DaemonError::Io(error)),
    }
    let sensitive = SensitiveInput::new(password.into_vec());
    let vault = VaultSession::unlock(&config.database_path, &sensitive)?;
    drop(sensitive);
    let state = RuntimeState::new(vault, config.database_path.clone())?;
    Ok((lock_file, state))
}

#[cfg(unix)]
impl Server {
    fn prepare(config: &DaemonConfig, password: SensitiveBytes) -> Result<Self, DaemonError> {
        let (lock_file, state) = prepare_runtime_lock_and_state(config, password)?;
        remove_stale_socket(&config.socket_path)?;
        let listener = UnixListener::bind(&config.socket_path)?;
        envault_platform::set_private_socket_permissions(&config.socket_path)?;
        let socket_guard = SocketGuard::new(config.socket_path.clone())?;
        let owner_uid = std::fs::metadata(&config.runtime_directory)?.uid();
        Ok(Self {
            listener,
            state: Arc::new(Mutex::new(state)),
            owner_uid,
            socket_guard,
            _lock_file: lock_file,
            shutdown: Arc::new(Notify::new()),
            connections: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            authentication: Arc::new(Semaphore::new(1)),
        })
    }

    fn peer_uid(&self) -> u32 {
        self.owner_uid
    }

    async fn run(self) -> Result<(), DaemonError> {
        let mut tasks = JoinSet::new();
        let signal = shutdown_signal();
        tokio::pin!(signal);
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(credentials) = stream.peer_cred() else {
                        continue;
                    };
                    let Some(peer) = peer_identity(credentials) else {
                        continue;
                    };
                    if !authenticated_peer(self.owner_uid, peer) {
                        continue;
                    }
                    if self
                        .state
                        .lock()
                        .map_or(true, |mut state| state.check_connection_rate(peer).is_err())
                    {
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&self.connections).try_acquire_owned() else {
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    let shutdown = Arc::clone(&self.shutdown);
                    let authentication = Arc::clone(&self.authentication);
                    tasks.spawn(async move {
                        let _permit = permit;
                        handle_connection(stream, peer, state, shutdown, authentication).await;
                    });
                }
                () = self.shutdown.notified() => break,
                result = &mut signal => {
                    result?;
                    break;
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        self.state
            .lock()
            .map_err(|_| DaemonError::BootstrapProtocol)?
            .lock();
        drop(self.socket_guard);
        Ok(())
    }
}

#[cfg(windows)]
impl Server {
    fn prepare(config: &DaemonConfig, password: SensitiveBytes) -> Result<Self, DaemonError> {
        let (lock_file, state) = prepare_runtime_lock_and_state(config, password)?;
        let pipe_name = crate::client::windows_pipe_name(&config.socket_path);
        let listener = envault_windows_ffi::create_named_pipe_server(&pipe_name, true)?;
        Ok(Self {
            listener,
            pipe_name,
            state: Arc::new(Mutex::new(state)),
            _lock_file: lock_file,
            shutdown: Arc::new(Notify::new()),
            connections: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            authentication: Arc::new(Semaphore::new(1)),
        })
    }

    fn peer_uid(&self) -> u32 {
        WINDOWS_PEER_UID
    }

    async fn run(mut self) -> Result<(), DaemonError> {
        use std::os::windows::io::AsRawHandle;

        let mut tasks = JoinSet::new();
        let signal = shutdown_signal();
        tokio::pin!(signal);
        loop {
            tokio::select! {
                connected = self.listener.connect() => {
                    if connected.is_err() {
                        continue;
                    }
                    // Recycle the instance immediately: hand the
                    // now-connected pipe off to the spawned task and put a
                    // fresh, not-yet-connected instance in its place so the
                    // next client can connect while this one is served,
                    // mirroring how a Unix listener keeps accepting after
                    // handing off one accepted connection.
                    let Ok(next) = envault_windows_ffi::create_named_pipe_server(&self.pipe_name, false) else {
                        continue;
                    };
                    let stream = std::mem::replace(&mut self.listener, next);
                    let handle = stream.as_raw_handle();
                    let Ok(pid) = envault_windows_ffi::named_pipe_client_process_id(handle) else {
                        continue;
                    };
                    if !matches!(envault_windows_ffi::is_current_user_pid(pid), Ok(true)) {
                        continue;
                    }
                    let Ok(session_id) = envault_windows_ffi::named_pipe_client_session_id(pid) else {
                        continue;
                    };
                    let peer = PeerIdentity {
                        uid: WINDOWS_PEER_UID,
                        pid,
                        session_id,
                    };
                    if self
                        .state
                        .lock()
                        .map_or(true, |mut state| state.check_connection_rate(peer).is_err())
                    {
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&self.connections).try_acquire_owned() else {
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    let shutdown = Arc::clone(&self.shutdown);
                    let authentication = Arc::clone(&self.authentication);
                    tasks.spawn(async move {
                        let _permit = permit;
                        handle_connection(stream, peer, state, shutdown, authentication).await;
                    });
                }
                () = self.shutdown.notified() => break,
                result = &mut signal => {
                    result?;
                    break;
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        self.state
            .lock()
            .map_err(|_| DaemonError::BootstrapProtocol)?
            .lock();
        Ok(())
    }
}

pub async fn run_from_stdio() -> Result<(), DaemonError> {
    envault_platform::harden_sensitive_process()?;
    let request: Request<BootstrapRequest> =
        read_sync_frame(&mut io::stdin().lock()).map_err(|_| DaemonError::BootstrapProtocol)?;
    let request_id = request.request_id;
    if validate_version(request.version).is_err() {
        let response = error_response(request_id, RuntimeFailure::ProtocolMismatch);
        let _ = write_sync_frame(&mut io::stdout().lock(), &response);
        return Err(DaemonError::BootstrapProtocol);
    }
    let config = DaemonConfig::from_platform()?;
    match Server::prepare(&config, request.body.password) {
        Ok(server) => {
            let status = server
                .state
                .lock()
                .map_err(|_| DaemonError::BootstrapProtocol)?
                .status(PeerIdentity {
                    uid: server.peer_uid(),
                    pid: std::process::id(),
                    session_id: current_session_id()?,
                })
                .map_err(|_| DaemonError::BootstrapProtocol)?;
            write_sync_frame(
                &mut io::stdout().lock(),
                &Response {
                    version: PROTOCOL_VERSION,
                    request_id,
                    body: ResponseBody::Ok(Reply::Status(status)),
                },
            )
            .map_err(|_| DaemonError::BootstrapProtocol)?;
            server.run().await
        }
        Err(error) => {
            let failure = match error {
                DaemonError::AlreadyRunning => RuntimeFailure::Busy,
                DaemonError::Service(ServiceError::AuthenticationFailed) => {
                    RuntimeFailure::AuthenticationFailed
                }
                DaemonError::Service(ServiceError::Corrupt | ServiceError::Store(_)) => {
                    RuntimeFailure::Corrupt
                }
                _ => RuntimeFailure::Internal,
            };
            let response = error_response(request_id, failure);
            let _ = write_sync_frame(&mut io::stdout().lock(), &response);
            Err(error)
        }
    }
}

async fn handle_connection<S>(
    stream: S,
    peer: PeerIdentity,
    state: Arc<Mutex<RuntimeState>>,
    shutdown: Arc<Notify>,
    authentication: Arc<Semaphore>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    handle_connection_with_timing(
        stream,
        peer,
        state,
        shutdown,
        authentication,
        CONNECTION_TIMING,
    )
    .await;
}

async fn handle_connection_with_timing<S>(
    mut stream: S,
    peer: PeerIdentity,
    state: Arc<Mutex<RuntimeState>>,
    shutdown: Arc<Notify>,
    authentication: Arc<Semaphore>,
    timing: ConnectionTiming,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let read_deadline = tokio::time::Instant::now() + timing.request_timeout;
    let request = tokio::time::timeout_at(read_deadline, read_async_frame(&mut stream)).await;
    let (response, stop, write_deadline) = match request {
        Ok(Ok(request)) => {
            let request: Request<AuthenticatedRequest> = request;
            let request_id = request.request_id;
            let is_portability = request.body.operation.is_portability();
            let operation_deadline = if is_portability {
                tokio::time::Instant::now() + timing.portability_timeout
            } else {
                read_deadline
            };
            match tokio::time::timeout_at(
                operation_deadline,
                process_decoded_request(request, peer, &state, &authentication),
            )
            .await
            {
                Ok(Ok((response, stop))) => (response, stop, operation_deadline),
                Ok(Err((request_id, failure))) => (
                    error_response(request_id, failure),
                    false,
                    operation_deadline,
                ),
                Err(_) => (
                    error_response(request_id, deadline_failure(is_portability)),
                    false,
                    tokio::time::Instant::now() + timing.error_response_grace,
                ),
            }
        }
        Ok(Err(_)) => (
            error_response(Uuid::new_v4(), RuntimeFailure::InvalidRequest),
            false,
            read_deadline,
        ),
        Err(_) => (
            error_response(Uuid::new_v4(), RuntimeFailure::DeadlineExceeded),
            false,
            tokio::time::Instant::now() + timing.error_response_grace,
        ),
    };
    let _ =
        tokio::time::timeout_at(write_deadline, write_async_frame(&mut stream, &response)).await;
    if stop {
        shutdown.notify_one();
    }
}

const fn deadline_failure(is_portability: bool) -> RuntimeFailure {
    if is_portability {
        RuntimeFailure::PortabilityDeadlineExceeded
    } else {
        RuntimeFailure::DeadlineExceeded
    }
}

async fn process_decoded_request(
    request: Request<AuthenticatedRequest>,
    peer: PeerIdentity,
    state: &Arc<Mutex<RuntimeState>>,
    authentication: &Arc<Semaphore>,
) -> Result<(Response<Reply>, bool), (Uuid, RuntimeFailure)> {
    let request_id = request.request_id;
    validate_version(request.version)
        .map_err(|_| (request_id, RuntimeFailure::ProtocolMismatch))?;
    if let Operation::AdminUnlock {
        ttl_minutes: Some(ttl_minutes),
        ..
    } = &request.body.operation
    {
        validate_admin_lease(*ttl_minutes).map_err(|_| (request_id, RuntimeFailure::InvalidTtl))?;
    }
    if matches!(
        &request.body.operation,
        Operation::AdminUnlock { .. } | Operation::IssueRevealToken { .. }
    ) {
        state
            .try_lock()
            .map_err(|_| (request_id, RuntimeFailure::Busy))?
            .check_authentication_rate(peer)
            .map_err(|failure| (request_id, failure))?;
    }
    let operation = request.body.operation;
    let result = match operation {
        Operation::AdminUnlock {
            password,
            ttl_minutes,
        } => authenticate_admin(
            state,
            peer,
            password,
            ttl_minutes,
            Arc::clone(authentication),
        )
        .await
        .map(|status| (Reply::AdminStatus(status), false)),
        Operation::IssueRevealToken { password } => {
            issue_reveal_token(state, peer, password, Arc::clone(authentication))
                .await
                .map(|token| (Reply::RevealToken(token), false))
        }
        Operation::HttpRequest {
            profile,
            name,
            request,
        } => {
            let prepared = state
                .try_lock()
                .map_err(|_| (request_id, RuntimeFailure::Busy))?
                .prepare_http_request(&profile, &name, request)
                .map_err(|failure| (request_id, failure))?;
            execute_agent_http_request(prepared)
                .await
                .map(|response| (Reply::HttpResponse(response), false))
                .map_err(map_broker_failure)
        }
        operation if operation.is_portability() => {
            let state = Arc::clone(state);
            tokio::task::spawn_blocking(move || {
                state
                    .try_lock()
                    .map_err(|_| RuntimeFailure::Busy)?
                    .handle(peer, operation)
            })
            .await
            .map_err(|_| (request_id, RuntimeFailure::Internal))?
        }
        operation => state
            .try_lock()
            .map_err(|_| (request_id, RuntimeFailure::Busy))?
            .handle(peer, operation),
    };
    let (reply, stop) = result.map_err(|failure| (request_id, failure))?;
    Ok((
        Response {
            version: PROTOCOL_VERSION,
            request_id,
            body: ResponseBody::Ok(reply),
        },
        stop,
    ))
}

impl RuntimeState {
    fn handle(
        &mut self,
        peer: PeerIdentity,
        operation: Operation,
    ) -> Result<(Reply, bool), RuntimeFailure> {
        match operation {
            Operation::Status => Ok((Reply::Status(self.status(peer)?), false)),
            Operation::Lock => {
                if self.vault.is_none() {
                    return Ok((Reply::Acknowledged { no_op: true }, false));
                }
                self.lock();
                Ok((Reply::Acknowledged { no_op: false }, false))
            }
            Operation::Stop => {
                self.lock();
                Ok((Reply::Acknowledged { no_op: false }, true))
            }
            Operation::AdminStatus => {
                if self.vault.is_none() {
                    return Err(RuntimeFailure::Locked);
                }
                Ok((Reply::AdminStatus(self.admin_status(peer)), false))
            }
            Operation::AdminLock => {
                self.clear_admin_lease(peer)?;
                Ok((Reply::Acknowledged { no_op: false }, false))
            }
            Operation::SetSecretHttpAccess {
                profile,
                name,
                constraint,
            } => {
                self.set_secret_http_access(peer, &profile, &name, constraint)?;
                Ok((Reply::Acknowledged { no_op: false }, false))
            }
            Operation::RemoveSecretHttpAccess { profile, name } => {
                self.remove_secret_http_access(peer, &profile, &name)?;
                Ok((Reply::Acknowledged { no_op: false }, false))
            }
            Operation::RunEnv { profiles } => {
                let vars = self.resolve_run_env(&profiles)?;
                Ok((Reply::RunEnv(vars), false))
            }
            Operation::RevealSecretValue {
                profile,
                name,
                version,
                token,
            } => {
                self.verify_reveal_token(peer, &token)?;
                let value = self
                    .vault
                    .as_ref()
                    .ok_or(RuntimeFailure::Locked)?
                    .reveal_secret_value(&profile, &name, version)
                    .map_err(|error| map_service_failure(&error))?;
                Ok((
                    Reply::SecretPlaintext(SensitiveBytes::new(value.into_vec())),
                    false,
                ))
            }
            operation @ (Operation::CreateProfile { .. }
            | Operation::ShowProfile { .. }
            | Operation::ListProfiles
            | Operation::UpdateProfile { .. }
            | Operation::RenameProfile { .. }
            | Operation::DeleteProfile { .. }
            | Operation::LoadProfile { .. }
            | Operation::UnloadProfile { .. }) => self.handle_profile(peer, operation),
            operation @ (Operation::CreateWorkspace { .. }
            | Operation::ListWorkspaces
            | Operation::ShowWorkspace { .. }
            | Operation::LoadWorkspace { .. }) => self.handle_workspace(peer, operation),
            operation @ (Operation::CreateSecret { .. }
            | Operation::CreateGeneratedSecret { .. }
            | Operation::ListSecrets
            | Operation::ListResolvedSecrets { .. }
            | Operation::DescribeSecret { .. }
            | Operation::UpdateSecret { .. }
            | Operation::RenameSecret { .. }
            | Operation::DeleteSecret { .. }
            | Operation::SetSecretValue { .. }
            | Operation::GenerateSecretValue { .. }
            | Operation::ListSecretVersions { .. }) => self.handle_secret(peer, operation),
            operation @ (Operation::ExportPackage { .. }
            | Operation::PreviewPackageImport { .. }
            | Operation::CommitPackageImport { .. }
            | Operation::PreviewEnvImport { .. }
            | Operation::CommitEnvImport { .. }
            | Operation::ExportPlaintextEnv { .. }) => self.handle_portability(peer, operation),
            Operation::HttpRequest { .. }
            | Operation::AdminUnlock { .. }
            | Operation::IssueRevealToken { .. } => Err(RuntimeFailure::Internal),
        }
    }

    fn handle_profile(
        &mut self,
        peer: PeerIdentity,
        operation: Operation,
    ) -> Result<(Reply, bool), RuntimeFailure> {
        if matches!(
            operation,
            Operation::ShowProfile { .. } | Operation::ListProfiles
        ) {
            let vault = self.vault.as_ref().ok_or(RuntimeFailure::Locked)?;
            let reply = match operation {
                Operation::ShowProfile { name } => Reply::Profile(
                    vault
                        .profile(&name)
                        .map_err(|error| map_service_failure(&error))?,
                ),
                Operation::ListProfiles => Reply::Profiles(
                    vault
                        .profiles()
                        .map_err(|error| map_service_failure(&error))?,
                ),
                _ => return Err(RuntimeFailure::Internal),
            };
            return Ok((reply, false));
        }
        self.require_admin(peer)?;
        let vault = self.vault.as_mut().ok_or(RuntimeFailure::Locked)?;
        let reply = match operation {
            Operation::CreateProfile {
                name,
                description,
                workspace,
            } => Reply::Profile(
                match &workspace {
                    Some(workspace) => {
                        vault.create_profile_in_workspace(workspace, &name, description.as_deref())
                    }
                    None => vault.create_profile(&name, description.as_deref()),
                }
                .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::UpdateProfile { name, description } => Reply::Profile(
                vault
                    .update_profile(&name, description.as_deref())
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::RenameProfile { old_name, new_name } => Reply::Profile(
                vault
                    .rename_profile(&old_name, &new_name)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::DeleteProfile { name } => match vault.delete_profile(&name) {
                Ok(()) => Reply::Acknowledged { no_op: false },
                Err(ServiceError::NotFound) => Reply::Acknowledged { no_op: true },
                Err(error) => return Err(map_service_failure(&error)),
            },
            Operation::LoadProfile { name } => Reply::Profile(
                vault
                    .load_profile(&name)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::UnloadProfile { name } => Reply::Profile(
                vault
                    .unload_profile(&name)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            _ => return Err(RuntimeFailure::Internal),
        };
        Ok((reply, false))
    }

    fn handle_workspace(
        &mut self,
        peer: PeerIdentity,
        operation: Operation,
    ) -> Result<(Reply, bool), RuntimeFailure> {
        if matches!(
            operation,
            Operation::ListWorkspaces | Operation::ShowWorkspace { .. }
        ) {
            let vault = self.vault.as_ref().ok_or(RuntimeFailure::Locked)?;
            let reply = match operation {
                Operation::ListWorkspaces => Reply::Workspaces(
                    vault
                        .workspaces()
                        .map_err(|error| map_service_failure(&error))?,
                ),
                Operation::ShowWorkspace { name } => Reply::WorkspaceProfiles(
                    vault
                        .profiles_in_workspace(&name)
                        .map_err(|error| map_service_failure(&error))?,
                ),
                _ => return Err(RuntimeFailure::Internal),
            };
            return Ok((reply, false));
        }
        self.require_admin(peer)?;
        let vault = self.vault.as_mut().ok_or(RuntimeFailure::Locked)?;
        let reply = match operation {
            Operation::CreateWorkspace { name } => Reply::Workspace(
                vault
                    .create_workspace(&name)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::LoadWorkspace { name } => Reply::WorkspaceProfiles(
                vault
                    .load_workspace(&name)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            _ => return Err(RuntimeFailure::Internal),
        };
        Ok((reply, false))
    }

    fn handle_secret(
        &mut self,
        peer: PeerIdentity,
        operation: Operation,
    ) -> Result<(Reply, bool), RuntimeFailure> {
        if is_secret_read_only(&operation) {
            return self.handle_secret_read(operation);
        }
        self.require_admin(peer)?;
        self.handle_secret_mutation(operation)
    }

    fn handle_secret_read(&self, operation: Operation) -> Result<(Reply, bool), RuntimeFailure> {
        let vault = self.vault.as_ref().ok_or(RuntimeFailure::Locked)?;
        let reply = match operation {
            Operation::ListSecrets => Reply::Secrets(
                vault
                    .secrets()
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::ListResolvedSecrets { profile } => Reply::ResolvedSecrets(
                vault
                    .secrets_in_profile(&profile)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::DescribeSecret { profile, name } => Reply::Secret(
                vault
                    .secret(&profile, &name)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::ListSecretVersions { profile, name } => Reply::SecretVersions(
                vault
                    .secret_versions(&profile, &name)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            _ => return Err(RuntimeFailure::Internal),
        };
        Ok((reply, false))
    }

    fn handle_secret_mutation(
        &mut self,
        operation: Operation,
    ) -> Result<(Reply, bool), RuntimeFailure> {
        let vault = self.vault.as_mut().ok_or(RuntimeFailure::Locked)?;
        let reply = match operation {
            Operation::CreateSecret {
                profile,
                name,
                description,
                value,
            } => Reply::Secret(
                vault
                    .create_secret(
                        &profile,
                        &name,
                        description.as_deref(),
                        SensitiveInput::new(value.into_vec()),
                    )
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::CreateGeneratedSecret {
                profile,
                name,
                description,
                generator,
            } => Reply::Secret(
                vault
                    .create_generated_secret(&profile, &name, description.as_deref(), generator)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::UpdateSecret {
                profile,
                name,
                description,
            } => Reply::Secret(
                vault
                    .update_secret(&profile, &name, description.as_deref())
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::RenameSecret {
                profile,
                old_name,
                new_name,
            } => Reply::Secret(
                vault
                    .rename_secret(&profile, &old_name, &new_name)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::DeleteSecret { profile, name } => {
                match vault.delete_secret(&profile, &name) {
                    Ok(()) => Reply::Acknowledged { no_op: false },
                    Err(ServiceError::NotFound) => Reply::Acknowledged { no_op: true },
                    Err(error) => return Err(map_service_failure(&error)),
                }
            }
            Operation::SetSecretValue {
                profile,
                name,
                value,
            } => Reply::SecretVersion(
                vault
                    .set_secret_value(&profile, &name, SensitiveInput::new(value.into_vec()))
                    .map_err(|error| map_service_failure(&error))?,
            ),
            Operation::GenerateSecretValue {
                profile,
                name,
                generator,
            } => Reply::SecretVersion(
                vault
                    .generate_secret_value(&profile, &name, generator)
                    .map_err(|error| map_service_failure(&error))?,
            ),
            _ => return Err(RuntimeFailure::Internal),
        };
        Ok((reply, false))
    }

    fn handle_portability(
        &mut self,
        peer: PeerIdentity,
        operation: Operation,
    ) -> Result<(Reply, bool), RuntimeFailure> {
        self.require_admin(peer)?;
        let vault = self.vault.as_mut().ok_or(RuntimeFailure::Locked)?;
        let reply = match operation {
            Operation::ExportPackage { .. }
            | Operation::PreviewPackageImport { .. }
            | Operation::CommitPackageImport { .. } => {
                Self::handle_package_operation(vault, operation)?
            }
            Operation::PreviewEnvImport { .. }
            | Operation::CommitEnvImport { .. }
            | Operation::ExportPlaintextEnv { .. } => {
                Self::handle_env_portability_operation(vault, operation)?
            }
            _ => return Err(RuntimeFailure::Internal),
        };
        Ok((reply, false))
    }

    fn handle_package_operation(
        vault: &mut VaultSession,
        operation: Operation,
    ) -> Result<Reply, RuntimeFailure> {
        match operation {
            Operation::ExportPackage {
                kind,
                profile_name,
                output_path,
                transfer_password,
                age_recipients,
            } => {
                let transfer_password =
                    transfer_password.map(|password| SensitiveInput::new(password.into_vec()));
                Ok(Reply::PortabilityExport(
                    vault
                        .export_package(
                            kind,
                            profile_name.as_deref(),
                            Path::new(&output_path),
                            transfer_password.as_ref(),
                            &age_recipients,
                        )
                        .map_err(|error| map_service_failure(&error))?,
                ))
            }
            Operation::PreviewPackageImport {
                expected_kind,
                input_path,
                transfer_password,
                age_identity_path,
                strategy,
                rename_to,
            } => {
                let transfer_password =
                    transfer_password.map(|password| SensitiveInput::new(password.into_vec()));
                Ok(Reply::PortabilityPreview(
                    vault
                        .preview_package_import_for_kind(PackageImportOptions {
                            expected_kind,
                            input_path: Path::new(&input_path),
                            transfer_password: transfer_password.as_ref(),
                            age_identity_path: age_identity_path.as_deref().map(Path::new),
                            strategy,
                            rename_to: rename_to.as_deref(),
                        })
                        .map_err(|error| map_service_failure(&error))?,
                ))
            }
            Operation::CommitPackageImport {
                expected_kind,
                input_path,
                transfer_password,
                age_identity_path,
                strategy,
                rename_to,
                expected_plan_hash,
            } => {
                let transfer_password =
                    transfer_password.map(|password| SensitiveInput::new(password.into_vec()));
                Ok(Reply::PortabilityImport(
                    vault
                        .commit_package_import_for_kind(
                            PackageImportOptions {
                                expected_kind,
                                input_path: Path::new(&input_path),
                                transfer_password: transfer_password.as_ref(),
                                age_identity_path: age_identity_path.as_deref().map(Path::new),
                                strategy,
                                rename_to: rename_to.as_deref(),
                            },
                            &expected_plan_hash,
                        )
                        .map_err(|error| map_service_failure(&error))?,
                ))
            }
            _ => Err(RuntimeFailure::Internal),
        }
    }

    fn handle_env_portability_operation(
        vault: &mut VaultSession,
        operation: Operation,
    ) -> Result<Reply, RuntimeFailure> {
        match operation {
            Operation::PreviewEnvImport {
                profile_name,
                input_path,
                strategy,
            } => Ok(Reply::EnvImportPreview(
                vault
                    .preview_env_import(&profile_name, Path::new(&input_path), strategy)
                    .map_err(|error| map_service_failure(&error))?,
            )),
            Operation::CommitEnvImport {
                profile_name,
                input_path,
                strategy,
                expected_plan_hash,
            } => Ok(Reply::PortabilityImport(
                vault
                    .commit_env_import(
                        &profile_name,
                        Path::new(&input_path),
                        strategy,
                        &expected_plan_hash,
                    )
                    .map_err(|error| map_service_failure(&error))?,
            )),
            Operation::ExportPlaintextEnv {
                profile_name,
                output_path,
                allow_plaintext,
            } => Ok(Reply::PlaintextExport(
                vault
                    .export_plaintext_env(&profile_name, Path::new(&output_path), allow_plaintext)
                    .map_err(|error| map_service_failure(&error))?,
            )),
            _ => Err(RuntimeFailure::Internal),
        }
    }
}

async fn authenticate_admin(
    state: &Arc<Mutex<RuntimeState>>,
    peer: PeerIdentity,
    password: SensitiveBytes,
    ttl_minutes: Option<u8>,
    authentication: Arc<Semaphore>,
) -> Result<AdminLeaseStatus, RuntimeFailure> {
    if let Some(ttl_minutes) = ttl_minutes {
        validate_admin_lease(ttl_minutes).map_err(|_| RuntimeFailure::InvalidTtl)?;
    }
    let database_path = {
        let state = state.try_lock().map_err(|_| RuntimeFailure::Busy)?;
        if state.vault.is_none() {
            return Err(RuntimeFailure::Locked);
        }
        state.database_path.clone()
    };
    let permit = authentication
        .acquire_owned()
        .await
        .map_err(|_| RuntimeFailure::Internal)?;
    let authenticated = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let input = SensitiveInput::new(password.into_vec());
        let result = VaultSession::unlock(&database_path, &input);
        drop(input);
        result
    })
    .await
    .map_err(|_| RuntimeFailure::Internal)?
    .map_err(|error| map_service_failure(&error))?;
    drop(authenticated);
    state
        .try_lock()
        .map_err(|_| RuntimeFailure::Busy)?
        .issue_admin_lease(peer, ttl_minutes)
}

/// Re-verifies the vault password (same cost/rate-limit shape as
/// `authenticate_admin`) before minting a reveal token, so holding an
/// active admin lease is never sufficient on its own to obtain one.
async fn issue_reveal_token(
    state: &Arc<Mutex<RuntimeState>>,
    peer: PeerIdentity,
    password: SensitiveBytes,
    authentication: Arc<Semaphore>,
) -> Result<SensitiveBytes, RuntimeFailure> {
    let database_path = {
        let mut state = state.try_lock().map_err(|_| RuntimeFailure::Busy)?;
        state.require_admin(peer)?;
        state.database_path.clone()
    };
    let permit = authentication
        .acquire_owned()
        .await
        .map_err(|_| RuntimeFailure::Internal)?;
    let authenticated = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let input = SensitiveInput::new(password.into_vec());
        let result = VaultSession::unlock(&database_path, &input);
        drop(input);
        result
    })
    .await
    .map_err(|_| RuntimeFailure::Internal)?
    .map_err(|error| map_service_failure(&error))?;
    drop(authenticated);
    state
        .try_lock()
        .map_err(|_| RuntimeFailure::Busy)?
        .mint_reveal_token(peer)
}

/// Named, explicit categorization of every `Operation` variant `handle`'s
/// outer match routes to `handle_secret` (the `CreateSecret | ... |
/// ListSecretVersions` group). Kept as one deliberate list rather than an
/// inline `matches!` so the read/mutation split for a new secret operation
/// is a conscious choice made here, next to every existing one, instead of
/// a copy-pasted addition to whichever arm looked closest by analogy.
/// Anything not listed defaults fail-closed to mutation (admin-gated).
fn is_secret_read_only(operation: &Operation) -> bool {
    match operation {
        Operation::ListSecrets
        | Operation::ListResolvedSecrets { .. }
        | Operation::DescribeSecret { .. }
        | Operation::ListSecretVersions { .. } => true,
        // Mutations (`CreateSecret`, `CreateGeneratedSecret`, `UpdateSecret`,
        // `RenameSecret`, `DeleteSecret`, `SetSecretValue`,
        // `GenerateSecretValue`) and anything not yet listed both fall
        // through here, fail-closed to admin-gated.
        _ => false,
    }
}

fn map_service_failure(error: &ServiceError) -> RuntimeFailure {
    match error {
        ServiceError::AuthenticationFailed => RuntimeFailure::AuthenticationFailed,
        ServiceError::PermissionDenied => RuntimeFailure::PermissionDenied,
        ServiceError::Conflict | ServiceError::StartupProfileRequired => RuntimeFailure::Conflict,
        ServiceError::NotFound => RuntimeFailure::NotFound,
        ServiceError::ProfileNotLoaded => RuntimeFailure::ProfileNotLoaded,
        ServiceError::DuplicateSecretAcrossProfiles => {
            RuntimeFailure::DuplicateSecretAcrossProfiles
        }
        ServiceError::Corrupt | ServiceError::Store(_) => RuntimeFailure::Corrupt,
        ServiceError::Invariant(_) | ServiceError::InvalidPasswordLength => {
            RuntimeFailure::InvalidInput
        }
        ServiceError::InvalidPackage | ServiceError::UnsupportedPackageVersion => {
            RuntimeFailure::PackageError
        }
        ServiceError::PackageAuthenticationFailed => RuntimeFailure::PackageAuthenticationFailed,
        ServiceError::InvalidImportStrategy
        | ServiceError::InvalidEnvFile { .. }
        | ServiceError::PlaintextExportUnsupported => RuntimeFailure::InvalidInput,
        ServiceError::StaleImportPlan => RuntimeFailure::StaleImportPlan,
        ServiceError::PlaintextAcknowledgementRequired => {
            RuntimeFailure::PlaintextAcknowledgementRequired
        }
        ServiceError::Io(_) | ServiceError::Platform(_) => RuntimeFailure::Io,
        ServiceError::Broker(error) => map_broker_failure(classify_broker_failure(error)),
        _ => RuntimeFailure::Internal,
    }
}

fn map_broker_failure(failure: BrokerFailure) -> RuntimeFailure {
    match failure {
        BrokerFailure::RequestRejected => RuntimeFailure::RequestRejected,
        BrokerFailure::NetworkFailure => RuntimeFailure::NetworkFailure,
        BrokerFailure::ProviderRejected(status) => RuntimeFailure::ProviderRejected(status),
        BrokerFailure::ResponseRejected => RuntimeFailure::ResponseRejected,
    }
}

fn error_response(request_id: Uuid, failure: RuntimeFailure) -> Response<Reply> {
    Response {
        version: PROTOCOL_VERSION,
        request_id,
        body: ResponseBody::Error(structured_error(request_id, failure)),
    }
}

fn structured_error(request_id: Uuid, failure: RuntimeFailure) -> StructuredError {
    let (code, message, help, retryable) = failure_details(failure);
    StructuredError {
        code: code.into(),
        message: message.into(),
        help: vec![help.into()],
        request_id,
        retryable,
        kind: ErrorKind::Runtime,
    }
}

type FailureDetails = (&'static str, &'static str, &'static str, bool);

#[allow(clippy::too_many_lines)]
fn failure_details(failure: RuntimeFailure) -> FailureDetails {
    match failure {
        RuntimeFailure::Locked => (
            "envault_locked",
            "EnVault daemon is locked",
            "Run `envault start`",
            true,
        ),
        RuntimeFailure::AuthenticationFailed => (
            "authentication_failed",
            "master password authentication failed",
            "Retry from a trusted terminal",
            true,
        ),
        RuntimeFailure::AdminRequired => (
            "admin_auth_required",
            "an active admin lease is required",
            "Run `envault admin unlock`",
            true,
        ),
        RuntimeFailure::PermissionDenied => (
            "permission_denied",
            "the authenticated principal is not permitted",
            "Request a new bounded grant",
            false,
        ),
        RuntimeFailure::InvalidTtl => (
            "invalid_ttl",
            "admin lease must be between one and thirty minutes",
            "Choose a supported lease duration",
            false,
        ),
        RuntimeFailure::InvalidInput => (
            "invalid_input",
            "the request violates the EnVault contract",
            "Correct the bounded command arguments",
            false,
        ),
        RuntimeFailure::Io => (
            "io_error",
            "the trusted local filesystem operation failed",
            "Check the path, permissions, free space, and file stability",
            true,
        ),
        failure @ (RuntimeFailure::PackageError
        | RuntimeFailure::PackageAuthenticationFailed
        | RuntimeFailure::StaleImportPlan
        | RuntimeFailure::PlaintextAcknowledgementRequired
        | RuntimeFailure::PortabilityDeadlineExceeded) => portability_failure_details(failure),
        RuntimeFailure::Conflict => (
            "conflict",
            "the requested mutation conflicts with existing vault state",
            "Inspect the existing resource before retrying",
            false,
        ),
        RuntimeFailure::NotFound => (
            "not_found",
            "the requested resource was not found",
            "Refresh the current EnVault context",
            false,
        ),
        RuntimeFailure::ProfileNotLoaded => (
            "profile_not_loaded",
            "the profile is not loaded in this session",
            "Run `envault profile load \"<profile>\"` first",
            false,
        ),
        RuntimeFailure::DuplicateSecretAcrossProfiles => (
            "duplicate_secret_across_profiles",
            "two or more profiles in the workspace resolve a secret with the same name",
            "Run with `--profile \"<profile>\"` to select one profile, or rename the secret in one profile to remove the collision",
            false,
        ),
        failure @ (RuntimeFailure::RequestRejected
        | RuntimeFailure::ResponseRejected
        | RuntimeFailure::ProviderRejected(_)
        | RuntimeFailure::NetworkFailure
        | RuntimeFailure::DeadlineExceeded
        | RuntimeFailure::InvalidRequest
        | RuntimeFailure::ProtocolMismatch) => transport_failure_details(failure),
        RuntimeFailure::RateLimited => (
            "rate_limited",
            "too many requests were received",
            "Retry after the current rate window",
            true,
        ),
        RuntimeFailure::Busy => (
            "daemon_busy",
            "EnVault daemon is busy or already running",
            "Retry after the current operation completes",
            true,
        ),
        RuntimeFailure::Corrupt => (
            "vault_corrupt",
            "vault integrity validation failed",
            "Restore from a verified backup",
            false,
        ),
        RuntimeFailure::Internal => (
            "internal_error",
            "EnVault daemon could not complete the request",
            "Retry and inspect redacted diagnostics",
            true,
        ),
    }
}

fn portability_failure_details(failure: RuntimeFailure) -> FailureDetails {
    match failure {
        RuntimeFailure::PackageError => (
            "package_error",
            "the encrypted portability package is invalid or unsupported",
            "Verify the package source, suffix, version, and integrity",
            false,
        ),
        RuntimeFailure::PackageAuthenticationFailed => (
            "package_authentication_failed",
            "the portability package could not be authenticated",
            "Retry with the correct transfer password or age identity",
            false,
        ),
        RuntimeFailure::StaleImportPlan => (
            "stale_import_plan",
            "the import source or destination changed after preview",
            "Preview again and commit the new exact plan hash",
            true,
        ),
        RuntimeFailure::PlaintextAcknowledgementRequired => (
            "plaintext_acknowledgement_required",
            "plaintext export requires explicit acknowledgement",
            "Pass --allow-plaintext only from a trusted terminal",
            false,
        ),
        RuntimeFailure::PortabilityDeadlineExceeded => (
            "request_timeout",
            "the portability request exceeded its deadline",
            "Preview current state before retrying because an atomic commit may have completed",
            false,
        ),
        _ => (
            "internal_error",
            "EnVault daemon could not complete the request",
            "Retry and inspect redacted diagnostics",
            true,
        ),
    }
}

fn transport_failure_details(failure: RuntimeFailure) -> FailureDetails {
    match failure {
        RuntimeFailure::RequestRejected => (
            "request_rejected",
            "the HTTP request violates its capability constraints",
            "Use the exact granted HTTPS origin, method, and path",
            false,
        ),
        RuntimeFailure::ResponseRejected => (
            "response_rejected",
            "the HTTP response was blocked by the credential firewall",
            "Ask the provider for a bounded non-credential response",
            false,
        ),
        RuntimeFailure::ProviderRejected(status) => provider_failure_details(status),
        RuntimeFailure::NetworkFailure => (
            "network_error",
            "the brokered HTTP request could not reach its public target",
            "Retry after checking trusted network connectivity",
            true,
        ),
        RuntimeFailure::DeadlineExceeded => (
            "request_timeout",
            "the IPC request exceeded its deadline",
            "Retry with one bounded request",
            true,
        ),
        RuntimeFailure::InvalidRequest => (
            "invalid_request",
            "the IPC request is malformed",
            "Send one bounded versioned CBOR request",
            false,
        ),
        RuntimeFailure::ProtocolMismatch => (
            "protocol_mismatch",
            "the IPC protocol version is unsupported",
            "Use matching EnVault client and daemon versions",
            false,
        ),
        _ => (
            "internal_error",
            "EnVault daemon could not complete the request",
            "Retry and inspect redacted diagnostics",
            true,
        ),
    }
}

fn provider_failure_details(status: u16) -> FailureDetails {
    let help = if status == 429 {
        "Retry after the provider rate limit"
    } else {
        "Check the provider request without exposing its response body"
    };
    (
        "provider_error",
        "the HTTP provider rejected the brokered request",
        help,
        status == 429 || status >= 500,
    )
}

fn unix_seconds() -> Result<i64, RuntimeFailure> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeFailure::Internal)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| RuntimeFailure::Internal)
}

#[cfg(unix)]
fn remove_stale_socket(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::FileTypeExt;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon socket path contains a non-socket object",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn peer_identity(credentials: tokio::net::unix::UCred) -> Option<PeerIdentity> {
    use nix::unistd::{Pid, getsid};

    let raw_pid = credentials.pid()?;
    let pid = u32::try_from(raw_pid).ok()?;
    let session_id = u32::try_from(getsid(Some(Pid::from_raw(raw_pid))).ok()?.as_raw()).ok()?;
    Some(PeerIdentity {
        uid: credentials.uid(),
        pid,
        session_id,
    })
}

#[cfg(unix)]
fn authenticated_peer(owner_uid: u32, peer: PeerIdentity) -> bool {
    peer.uid == owner_uid && peer.pid != 0 && peer.session_id != 0
}

#[cfg(unix)]
fn current_session_id() -> Result<u32, DaemonError> {
    use nix::unistd::getsid;

    let raw = getsid(None).map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    u32::try_from(raw.as_raw()).map_err(|_| DaemonError::BootstrapProtocol)
}

/// The Windows analog of `current_session_id`: the Terminal Services session
/// ID of the daemon's own process, used for the bootstrap status query's
/// `PeerIdentity` before the accept loop starts serving real connections.
#[cfg(windows)]
fn current_session_id() -> Result<u32, DaemonError> {
    envault_windows_ffi::named_pipe_client_session_id(std::process::id()).map_err(DaemonError::Io)
}

#[cfg(unix)]
struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl SocketGuard {
    fn new(path: PathBuf) -> Result<Self, io::Error> {
        let metadata = std::fs::symlink_metadata(&path)?;
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn still_owns_path(&self) -> bool {
        std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
    }
}

#[cfg(unix)]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if self.still_owns_path() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<(), io::Error> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
        _ = hangup.recv() => {}
    }
    Ok(())
}

/// The Windows shutdown signal set is narrower than Unix's by design for
/// this pass: it handles Ctrl+C, the interactive-console signal every
/// Windows process receives, and not yet the service-manager/close/logoff
/// signals `tokio::signal::windows` also exposes (`ctrl_break`,
/// `ctrl_close`, `ctrl_shutdown`). Those matter for a process running as a
/// Windows service or responding to console-window close, which is out of
/// scope until `envaultd` actually ships as a service; tracked as a
/// follow-up rather than silently assumed equivalent to the Unix signal
/// set.
#[cfg(windows)]
async fn shutdown_signal() -> Result<(), io::Error> {
    let mut ctrl_c = tokio::signal::windows::ctrl_c()?;
    ctrl_c.recv().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use envault_core::{ImportConflictStrategy, PackageKind};

    fn peer() -> PeerIdentity {
        PeerIdentity {
            uid: 1000,
            pid: 2000,
            session_id: 3000,
        }
    }

    fn state() -> (tempfile::TempDir, RuntimeState, SensitiveInput) {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("vault.db");
        let password = SensitiveInput::copy_from_slice(b"daemon test password");
        envault_service::initialize_with_recommended_kdf(&path, &password).expect("initialize");
        let vault = VaultSession::unlock(&path, &password).expect("unlock");
        (
            directory,
            RuntimeState::new(vault, path).expect("runtime state"),
            password,
        )
    }

    #[test]
    fn lock_clears_vault_and_admin_lease() {
        let (_directory, mut state, _password) = state();
        state.issue_admin_lease(peer(), Some(5)).expect("lease");
        // Scoped by uid alone: a different terminal (different session_id,
        // same uid) still sees the lease as active - the whole point of the
        // uid-scoped step-up (Phase 5).
        let mut other_session = peer();
        other_session.session_id += 1;
        assert!(state.admin_lease_active(other_session));
        // A different uid entirely must never see it.
        let mut other_uid = peer();
        other_uid.uid += 1;
        assert!(!state.admin_lease_active(other_uid));
        assert!(state.admin_lease.is_some());
        assert!(state.require_admin(peer()).is_ok());
        state.admin_lease.as_mut().expect("lease").deadline = Some(Instant::now());
        assert!(!state.admin_lease_active(peer()));
        assert!(state.admin_lease.is_none());
        state
            .issue_admin_lease(peer(), Some(5))
            .expect("renew lease");
        state.lock();
        assert!(state.vault.is_none());
        assert!(state.admin_lease.is_none());
    }

    #[test]
    fn is_secret_read_only_matches_exactly_the_four_read_operations() {
        assert!(is_secret_read_only(&Operation::ListSecrets));
        assert!(is_secret_read_only(&Operation::ListResolvedSecrets {
            profile: "base".to_string(),
        }));
        assert!(is_secret_read_only(&Operation::DescribeSecret {
            profile: "base".to_string(),
            name: "x".to_string(),
        }));
        assert!(is_secret_read_only(&Operation::ListSecretVersions {
            profile: "base".to_string(),
            name: "x".to_string(),
        }));

        assert!(!is_secret_read_only(&Operation::CreateSecret {
            profile: "base".to_string(),
            name: "x".to_string(),
            description: None,
            value: SensitiveBytes::new(b"v".to_vec()),
        }));
        assert!(!is_secret_read_only(&Operation::DeleteSecret {
            profile: "base".to_string(),
            name: "x".to_string(),
        }));
        assert!(!is_secret_read_only(&Operation::SetSecretValue {
            profile: "base".to_string(),
            name: "x".to_string(),
            value: SensitiveBytes::new(b"v".to_vec()),
        }));
    }

    #[test]
    fn reveal_requires_a_token_minted_for_this_lease_not_just_an_active_lease() {
        let (_directory, mut state, _password) = state();
        state.issue_admin_lease(peer(), Some(5)).expect("lease");

        // An active lease alone (e.g. observed by another same-uid process
        // that never called `IssueRevealToken`) must not be enough.
        assert_eq!(
            state.verify_reveal_token(peer(), &SensitiveBytes::new(b"guessed".to_vec())),
            Err(RuntimeFailure::AdminRequired)
        );

        let token = state.mint_reveal_token(peer()).expect("mint token");
        assert!(state.verify_reveal_token(peer(), &token).is_ok());

        // A different, unrelated token must not verify.
        assert_eq!(
            state.verify_reveal_token(peer(), &SensitiveBytes::new(b"wrong-token".to_vec())),
            Err(RuntimeFailure::AdminRequired)
        );

        // Clearing the lease invalidates the token with it.
        state.clear_admin_lease(peer()).expect("clear lease");
        assert_eq!(
            state.verify_reveal_token(peer(), &token),
            Err(RuntimeFailure::AdminRequired)
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_peer_requires_matching_owner_uid() {
        assert!(authenticated_peer(1000, peer()));
        assert!(!authenticated_peer(1001, peer()));
    }

    #[test]
    fn rate_limit_bounds_authentication_attempts() {
        let (_directory, mut state, _password) = state();
        for _ in 0..AUTH_ATTEMPTS_PER_MINUTE {
            state
                .check_connection_rate(peer())
                .expect("request allowed");
            state
                .check_authentication_rate(peer())
                .expect("authentication allowed");
        }
        assert_eq!(
            state.check_authentication_rate(peer()),
            Err(RuntimeFailure::RateLimited)
        );
        let mut unrelated = peer();
        unrelated.session_id += 1;
        assert!(state.check_connection_rate(unrelated).is_ok());
        assert!(state.check_authentication_rate(unrelated).is_ok());
        for offset in 1..=(GLOBAL_AUTH_ATTEMPTS_PER_MINUTE - AUTH_ATTEMPTS_PER_MINUTE - 2) {
            unrelated.session_id += offset;
            state
                .check_authentication_rate(unrelated)
                .expect("global authentication window remains");
        }
        unrelated.session_id += 1;
        assert_eq!(
            state.check_authentication_rate(unrelated),
            Err(RuntimeFailure::RateLimited)
        );
    }

    #[test]
    fn rate_limit_state_is_globally_bounded() {
        let (_directory, mut state, _password) = state();
        for offset in 0..MAX_RATE_WINDOWS {
            let mut identity = peer();
            identity.session_id = identity
                .session_id
                .checked_add(u32::try_from(offset).expect("bounded offset"))
                .expect("bounded session");
            state
                .check_connection_rate(identity)
                .expect("window within bound");
        }
        let mut overflow = peer();
        overflow.session_id = overflow
            .session_id
            .checked_add(u32::try_from(MAX_RATE_WINDOWS).expect("bounded maximum"))
            .expect("bounded session");
        assert_eq!(
            state.check_connection_rate(overflow),
            Err(RuntimeFailure::RateLimited)
        );
        assert_eq!(state.rate_limits.len(), MAX_RATE_WINDOWS);
    }

    #[cfg(unix)]
    #[test]
    fn socket_guard_never_removes_a_replaced_path() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("envault.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let guard = SocketGuard::new(path.clone()).expect("guard");
        std::fs::remove_file(&path).expect("unlink socket");
        std::fs::write(&path, b"replacement").expect("replacement");
        drop(guard);
        assert_eq!(
            std::fs::read(&path).expect("replacement remains"),
            b"replacement"
        );
        drop(listener);
    }

    #[tokio::test]
    async fn deadline_error_preserves_the_decoded_request_id() {
        let (_directory, state, _password) = state();
        let request_id = Uuid::new_v4();
        // An in-memory duplex pair, not a real Unix socket or named pipe,
        // since `handle_connection_with_timing` is generic over any
        // `AsyncRead + AsyncWrite` stream and this test only exercises its
        // framing/deadline logic, which is identical on every platform.
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(handle_connection_with_timing(
            server,
            peer(),
            Arc::new(Mutex::new(state)),
            Arc::new(Notify::new()),
            Arc::new(Semaphore::new(0)),
            ConnectionTiming {
                request_timeout: Duration::from_millis(100),
                portability_timeout: Duration::from_secs(1),
                error_response_grace: Duration::from_secs(1),
            },
        ));
        write_async_frame(
            &mut client,
            &Request {
                version: PROTOCOL_VERSION,
                request_id,
                body: AuthenticatedRequest {
                    operation: Operation::AdminUnlock {
                        password: SensitiveBytes::new(b"daemon test password".to_vec()),
                        ttl_minutes: Some(5),
                    },
                },
            },
        )
        .await
        .expect("request");
        let response: Response<Reply> = read_async_frame(&mut client).await.expect("response");
        assert_eq!(response.request_id, request_id);
        let ResponseBody::Error(error) = response.body else {
            panic!("expected deadline error");
        };
        assert_eq!(error.code, "request_timeout");
        task.await.expect("connection task");
    }

    #[test]
    fn portability_deadline_requires_a_fresh_preview_before_retry() {
        let error = structured_error(
            Uuid::new_v4(),
            deadline_failure(
                Operation::PreviewPackageImport {
                    expected_kind: PackageKind::Profile,
                    input_path: "/tmp/package.envault-profile".into(),
                    transfer_password: None,
                    age_identity_path: None,
                    strategy: ImportConflictStrategy::Abort,
                    rename_to: None,
                }
                .is_portability(),
            ),
        );
        assert_eq!(error.code, "request_timeout");
        assert!(!error.retryable);
        assert!(error.help[0].contains("Preview current state"));
    }
}
