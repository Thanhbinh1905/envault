use std::{
    collections::BTreeMap,
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use envault_core::{ApprovalId, GrantId, PrincipalId, PrincipalKind, validate_admin_lease};
use envault_crypto::{SecretKey, lookup_digest, random_array};
use envault_policy::{Action, Grant, MAX_GRANT_LIFETIME_SECONDS, MAX_GRANT_USES, ResourceSelector};
use envault_protocol::{
    AdminLeaseStatus, AgentSessionCreated, AgentSessionView, AuthenticatedRequest,
    BootstrapRequest, DaemonStatus, Operation, PROTOCOL_VERSION, Reply, Request, Response,
    ResponseBody, SensitiveBytes, ServiceState, StructuredError, validate_version,
};
use envault_service::{SensitiveInput, ServiceError, VaultSession};
use thiserror::Error;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Notify, Semaphore},
    task::JoinSet,
};
use uuid::Uuid;

use crate::ipc::{read_async_frame, read_sync_frame, write_async_frame, write_sync_frame};

const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const MAX_AGENT_SESSIONS: usize = 1024;
const MAX_RATE_WINDOWS: usize = 256;
const REQUESTS_PER_MINUTE: u32 = 600;
const GLOBAL_REQUESTS_PER_MINUTE: u32 = 1_200;
const AUTH_ATTEMPTS_PER_MINUTE: u32 = 5;
const GLOBAL_AUTH_ATTEMPTS_PER_MINUTE: u32 = 10;
const TOKEN_HASH_DOMAIN: &str = "envault daemon capability token v1";
const ERROR_RESPONSE_GRACE: Duration = Duration::from_millis(250);

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
    session_id: u32,
    deadline: Instant,
    expires_at: i64,
}

#[derive(Debug)]
struct CapabilitySession {
    grant: Grant,
    deadline: Instant,
}

struct RuntimeState {
    vault: Option<VaultSession>,
    database_path: PathBuf,
    token_hash_key: Option<SecretKey>,
    admin_lease: Option<AdminLease>,
    capabilities: BTreeMap<[u8; 32], CapabilitySession>,
    rate_limits: BTreeMap<(u32, u32), RateWindow>,
    global_rate_limit: RateWindow,
}

impl RuntimeState {
    fn new(vault: VaultSession, database_path: PathBuf) -> Result<Self, RuntimeFailure> {
        Ok(Self {
            vault: Some(vault),
            database_path,
            token_hash_key: Some(SecretKey::generate().map_err(|_| RuntimeFailure::Internal)?),
            admin_lease: None,
            capabilities: BTreeMap::new(),
            rate_limits: BTreeMap::new(),
            global_rate_limit: RateWindow::new(),
        })
    }

    fn status(&mut self, peer: PeerIdentity) -> Result<DaemonStatus, RuntimeFailure> {
        self.remove_expired_capabilities();
        let active_profile = self
            .vault
            .as_ref()
            .map(|vault| {
                vault
                    .profiles()
                    .map_err(|_| RuntimeFailure::Internal)?
                    .into_iter()
                    .find(|profile| profile.activate_on_start)
                    .map(|profile| profile.name)
                    .ok_or(RuntimeFailure::Internal)
            })
            .transpose()?;
        let agent_session_count = self
            .capabilities
            .values()
            .filter(|session| !session.grant.revoked)
            .count()
            .try_into()
            .map_err(|_| RuntimeFailure::Internal)?;
        Ok(DaemonStatus {
            service: if self.vault.is_some() {
                ServiceState::Unlocked
            } else {
                ServiceState::Locked
            },
            pid: std::process::id(),
            active_profile,
            admin_lease_active: self.admin_lease_active(peer),
            agent_session_count,
        })
    }

    fn lock(&mut self) {
        self.vault = None;
        self.token_hash_key = None;
        self.admin_lease = None;
        self.capabilities.clear();
    }

    fn admin_status(&mut self, peer: PeerIdentity) -> AdminLeaseStatus {
        if self.admin_lease_active(peer) {
            AdminLeaseStatus {
                active: true,
                expires_at: self.admin_lease.as_ref().map(|lease| lease.expires_at),
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
        ttl_minutes: u8,
    ) -> Result<AdminLeaseStatus, RuntimeFailure> {
        validate_admin_lease(ttl_minutes).map_err(|_| RuntimeFailure::InvalidTtl)?;
        if self.vault.is_none() {
            return Err(RuntimeFailure::Locked);
        }
        let duration = Duration::from_secs(u64::from(ttl_minutes) * 60);
        let deadline = Instant::now()
            .checked_add(duration)
            .ok_or(RuntimeFailure::Internal)?;
        let expires_at = unix_seconds()?
            .checked_add(i64::from(ttl_minutes) * 60)
            .ok_or(RuntimeFailure::Internal)?;
        self.admin_lease = Some(AdminLease {
            uid: peer.uid,
            session_id: peer.session_id,
            deadline,
            expires_at,
        });
        Ok(AdminLeaseStatus {
            active: true,
            expires_at: Some(expires_at),
        })
    }

    fn clear_admin_lease(&mut self, peer: PeerIdentity) -> Result<(), RuntimeFailure> {
        self.require_admin(peer)?;
        self.admin_lease = None;
        Ok(())
    }

    fn create_agent_session(
        &mut self,
        peer: PeerIdentity,
        principal_id: PrincipalId,
        action: Action,
        resource: ResourceSelector,
        ttl_minutes: u8,
        max_requests: u32,
    ) -> Result<AgentSessionCreated, RuntimeFailure> {
        self.require_admin(peer)?;
        self.remove_expired_capabilities();
        if self.capabilities.len() >= MAX_AGENT_SESSIONS {
            return Err(RuntimeFailure::Busy);
        }
        let vault = self.vault.as_ref().ok_or(RuntimeFailure::Locked)?;
        let principal = vault
            .principals()
            .map_err(|_| RuntimeFailure::Internal)?
            .into_iter()
            .find(|principal| principal.id == principal_id)
            .ok_or(RuntimeFailure::NotFound)?;
        if principal.kind != PrincipalKind::Agent || principal.disabled {
            return Err(RuntimeFailure::PermissionDenied);
        }
        vault
            .validate_policy_resource(resource)
            .map_err(|error| map_service_failure(&error))?;
        let lifetime_seconds = i64::from(ttl_minutes) * 60;
        if !(1..=MAX_GRANT_LIFETIME_SECONDS).contains(&lifetime_seconds)
            || !(1..=MAX_GRANT_USES).contains(&max_requests)
        {
            return Err(RuntimeFailure::InvalidGrant);
        }
        let issued_at = unix_seconds()?;
        let expires_at = issued_at
            .checked_add(i64::from(ttl_minutes) * 60)
            .ok_or(RuntimeFailure::Internal)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(u64::from(ttl_minutes) * 60))
            .ok_or(RuntimeFailure::Internal)?;
        let grant_id = GrantId(Uuid::new_v4());
        let approval_id = ApprovalId(Uuid::new_v4());
        let grant = Grant {
            id: grant_id,
            principal_id,
            action,
            resource,
            issued_at,
            expires_at,
            max_uses: max_requests,
            uses: 0,
            revoked: false,
            nonce: random_array().map_err(|_| RuntimeFailure::Internal)?,
            approval_id,
        };
        grant.validate().map_err(|_| RuntimeFailure::InvalidGrant)?;
        let key = self.token_hash_key.as_ref().ok_or(RuntimeFailure::Locked)?;
        for _ in 0..4 {
            let token: [u8; 32] = random_array().map_err(|_| RuntimeFailure::Internal)?;
            let hash = lookup_digest(key, TOKEN_HASH_DOMAIN, &token);
            if let std::collections::btree_map::Entry::Vacant(entry) = self.capabilities.entry(hash)
            {
                entry.insert(CapabilitySession { grant, deadline });
                return Ok(AgentSessionCreated {
                    token: SensitiveBytes::new(token.to_vec()),
                    grant_id,
                    approval_id,
                    expires_at,
                    max_requests,
                });
            }
        }
        Err(RuntimeFailure::Internal)
    }

    fn agent_session_status(
        &mut self,
        token: Option<&SensitiveBytes>,
    ) -> Result<AgentSessionView, RuntimeFailure> {
        self.remove_expired_capabilities();
        let token = token.ok_or(RuntimeFailure::PermissionDenied)?;
        let hash = self.token_hash(token.as_slice())?;
        let session = self
            .capabilities
            .get(&hash)
            .ok_or(RuntimeFailure::PermissionDenied)?;
        if session.grant.revoked {
            return Err(RuntimeFailure::PermissionDenied);
        }
        Ok(capability_view(session))
    }

    fn revoke_agent_session(
        &mut self,
        peer: PeerIdentity,
        grant_id: GrantId,
    ) -> Result<(), RuntimeFailure> {
        self.require_admin(peer)?;
        let hash = self
            .capabilities
            .iter()
            .find_map(|(hash, session)| (session.grant.id == grant_id).then_some(*hash))
            .ok_or(RuntimeFailure::NotFound)?;
        self.capabilities.remove(&hash);
        Ok(())
    }

    #[cfg(test)]
    fn consume_capability(
        &mut self,
        token: &[u8],
        action: Action,
        resource: ResourceSelector,
    ) -> Result<PrincipalId, RuntimeFailure> {
        self.remove_expired_capabilities();
        let hash = self.token_hash(token)?;
        let session = self
            .capabilities
            .get_mut(&hash)
            .ok_or(RuntimeFailure::PermissionDenied)?;
        if session.grant.revoked
            || session.grant.action != action
            || session.grant.resource != resource
            || session.grant.uses >= session.grant.max_uses
        {
            return Err(RuntimeFailure::PermissionDenied);
        }
        session.grant.uses = session
            .grant
            .uses
            .checked_add(1)
            .ok_or(RuntimeFailure::Internal)?;
        Ok(session.grant.principal_id)
    }

    fn token_hash(&self, token: &[u8]) -> Result<[u8; 32], RuntimeFailure> {
        if token.len() != 32 {
            return Err(RuntimeFailure::PermissionDenied);
        }
        let key = self.token_hash_key.as_ref().ok_or(RuntimeFailure::Locked)?;
        Ok(lookup_digest(key, TOKEN_HASH_DOMAIN, token))
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

    fn admin_lease_active(&mut self, peer: PeerIdentity) -> bool {
        if self
            .admin_lease
            .as_ref()
            .is_some_and(|lease| Instant::now() >= lease.deadline)
        {
            self.admin_lease = None;
        }
        self.admin_lease
            .as_ref()
            .is_some_and(|lease| lease.uid == peer.uid && lease.session_id == peer.session_id)
    }

    fn remove_expired_capabilities(&mut self) {
        let now = Instant::now();
        self.capabilities
            .retain(|_, session| now < session.deadline);
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
    InvalidGrant,
    NotFound,
    RateLimited,
    Busy,
    Corrupt,
    DeadlineExceeded,
    InvalidRequest,
    ProtocolMismatch,
    Internal,
}

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

impl Server {
    fn prepare(config: &DaemonConfig, password: SensitiveBytes) -> Result<Self, DaemonError> {
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
        remove_stale_socket(&config.socket_path)?;
        let listener = UnixListener::bind(&config.socket_path)?;
        envault_platform::set_private_file_permissions(&config.socket_path)?;
        let socket_guard = SocketGuard::new(config.socket_path.clone())?;
        let owner_uid = std::fs::metadata(&config.runtime_directory)?.uid();
        let state = RuntimeState::new(vault, config.database_path.clone())
            .map_err(|_| DaemonError::BootstrapProtocol)?;
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
                    uid: server.owner_uid,
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

async fn handle_connection(
    mut stream: UnixStream,
    peer: PeerIdentity,
    state: Arc<Mutex<RuntimeState>>,
    shutdown: Arc<Notify>,
    authentication: Arc<Semaphore>,
) {
    let timeout = Duration::from_secs(envault_protocol::DEFAULT_REQUEST_TIMEOUT_SECONDS);
    let deadline = tokio::time::Instant::now() + timeout;
    let processed = tokio::time::timeout_at(
        deadline,
        process_request(&mut stream, peer, &state, &authentication),
    )
    .await;
    let (response, stop, write_deadline) = match processed {
        Ok(Ok((response, stop))) => (response, stop, deadline),
        Ok(Err((request_id, failure))) => (error_response(request_id, failure), false, deadline),
        Err(_) => {
            let grace = tokio::time::Instant::now() + ERROR_RESPONSE_GRACE;
            (
                error_response(Uuid::new_v4(), RuntimeFailure::DeadlineExceeded),
                false,
                grace,
            )
        }
    };
    let _ =
        tokio::time::timeout_at(write_deadline, write_async_frame(&mut stream, &response)).await;
    if stop {
        shutdown.notify_one();
    }
}

async fn process_request(
    stream: &mut UnixStream,
    peer: PeerIdentity,
    state: &Arc<Mutex<RuntimeState>>,
    authentication: &Arc<Semaphore>,
) -> Result<(Response<Reply>, bool), (Uuid, RuntimeFailure)> {
    let request: Request<AuthenticatedRequest> = read_async_frame(stream)
        .await
        .map_err(|_| (Uuid::new_v4(), RuntimeFailure::InvalidRequest))?;
    let request_id = request.request_id;
    validate_version(request.version)
        .map_err(|_| (request_id, RuntimeFailure::ProtocolMismatch))?;
    if request.body.capability_token.is_some() && !request.body.operation.accepts_agent_capability()
    {
        return Err((request_id, RuntimeFailure::PermissionDenied));
    }
    if let Operation::AdminUnlock { ttl_minutes, .. } = &request.body.operation {
        validate_admin_lease(*ttl_minutes).map_err(|_| (request_id, RuntimeFailure::InvalidTtl))?;
        state
            .lock()
            .map_err(|_| (request_id, RuntimeFailure::Internal))?
            .check_authentication_rate(peer)
            .map_err(|failure| (request_id, failure))?;
    }
    let operation = request.body.operation;
    let capability_token = request.body.capability_token;
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
        operation => state
            .lock()
            .map_err(|_| (request_id, RuntimeFailure::Internal))?
            .handle(peer, &operation, capability_token.as_ref()),
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
        operation: &Operation,
        token: Option<&SensitiveBytes>,
    ) -> Result<(Reply, bool), RuntimeFailure> {
        match operation {
            Operation::Status => Ok((Reply::Status(self.status(peer)?), false)),
            Operation::Lock => {
                if self.vault.is_none() {
                    return Err(RuntimeFailure::Locked);
                }
                self.lock();
                Ok((Reply::Acknowledged, false))
            }
            Operation::Stop => {
                self.lock();
                Ok((Reply::Acknowledged, true))
            }
            Operation::AdminStatus => {
                if self.vault.is_none() {
                    return Err(RuntimeFailure::Locked);
                }
                Ok((Reply::AdminStatus(self.admin_status(peer)), false))
            }
            Operation::AdminLock => {
                self.clear_admin_lease(peer)?;
                Ok((Reply::Acknowledged, false))
            }
            Operation::CreateAgentSession {
                principal_id,
                action,
                resource,
                ttl_minutes,
                max_requests,
            } => Ok((
                Reply::AgentSessionCreated(self.create_agent_session(
                    peer,
                    *principal_id,
                    *action,
                    *resource,
                    *ttl_minutes,
                    *max_requests,
                )?),
                false,
            )),
            Operation::AgentSessionStatus => Ok((
                Reply::AgentSessionStatus(self.agent_session_status(token)?),
                false,
            )),
            Operation::RevokeAgentSession { grant_id } => {
                self.revoke_agent_session(peer, *grant_id)?;
                Ok((Reply::Acknowledged, false))
            }
            Operation::AdminUnlock { .. } => Err(RuntimeFailure::Internal),
        }
    }
}

async fn authenticate_admin(
    state: &Arc<Mutex<RuntimeState>>,
    peer: PeerIdentity,
    password: SensitiveBytes,
    ttl_minutes: u8,
    authentication: Arc<Semaphore>,
) -> Result<AdminLeaseStatus, RuntimeFailure> {
    validate_admin_lease(ttl_minutes).map_err(|_| RuntimeFailure::InvalidTtl)?;
    let database_path = {
        let state = state.lock().map_err(|_| RuntimeFailure::Internal)?;
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
        .lock()
        .map_err(|_| RuntimeFailure::Internal)?
        .issue_admin_lease(peer, ttl_minutes)
}

fn capability_view(session: &CapabilitySession) -> AgentSessionView {
    AgentSessionView {
        grant_id: session.grant.id,
        principal_id: session.grant.principal_id,
        action: session.grant.action,
        resource: session.grant.resource,
        expires_at: session.grant.expires_at,
        remaining_requests: session.grant.max_uses.saturating_sub(session.grant.uses),
        revoked: session.grant.revoked,
    }
}

fn map_service_failure(error: &ServiceError) -> RuntimeFailure {
    match error {
        ServiceError::AuthenticationFailed => RuntimeFailure::AuthenticationFailed,
        ServiceError::NotFound => RuntimeFailure::NotFound,
        ServiceError::Corrupt | ServiceError::Store(_) => RuntimeFailure::Corrupt,
        _ => RuntimeFailure::Internal,
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
    let (code, message, help, retryable) = match failure {
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
        RuntimeFailure::InvalidGrant => (
            "invalid_grant",
            "capability grant violates security bounds",
            "Use an agent-safe action and bounded lifetime",
            false,
        ),
        RuntimeFailure::NotFound => (
            "not_found",
            "the requested resource was not found",
            "Refresh the current EnVault context",
            false,
        ),
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
        RuntimeFailure::Internal => (
            "internal_error",
            "EnVault daemon could not complete the request",
            "Retry and inspect redacted diagnostics",
            true,
        ),
    };
    StructuredError {
        code: code.into(),
        message: message.into(),
        help: vec![help.into()],
        request_id,
        retryable,
    }
}

fn unix_seconds() -> Result<i64, RuntimeFailure> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeFailure::Internal)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| RuntimeFailure::Internal)
}

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

fn authenticated_peer(owner_uid: u32, peer: PeerIdentity) -> bool {
    peer.uid == owner_uid && peer.pid != 0 && peer.session_id != 0
}

fn current_session_id() -> Result<u32, DaemonError> {
    use nix::unistd::getsid;

    let raw = getsid(None).map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    u32::try_from(raw.as_raw()).map_err(|_| DaemonError::BootstrapProtocol)
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

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

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if self.still_owns_path() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
            RuntimeState::new(vault, path).expect("state"),
            password,
        )
    }

    #[test]
    fn lock_clears_vault_leases_tokens_and_hash_key() {
        let (_directory, mut state, _password) = state();
        state.issue_admin_lease(peer(), 5).expect("lease");
        let mut unrelated = peer();
        unrelated.session_id += 1;
        assert!(!state.admin_lease_active(unrelated));
        assert!(state.admin_lease.is_some());
        assert!(state.require_admin(peer()).is_ok());
        state.admin_lease.as_mut().expect("lease").deadline = Instant::now();
        assert!(!state.admin_lease_active(peer()));
        assert!(state.admin_lease.is_none());
        state.issue_admin_lease(peer(), 5).expect("renew lease");
        state.lock();
        assert!(state.vault.is_none());
        assert!(state.admin_lease.is_none());
        assert!(state.capabilities.is_empty());
        assert!(state.token_hash_key.is_none());
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

    #[test]
    fn capability_is_hashed_bounded_revocable_and_privilege_safe() {
        let (_directory, mut state, _password) = state();
        let principal = state
            .vault
            .as_mut()
            .expect("vault")
            .create_principal(PrincipalKind::Agent, "agent:test")
            .expect("principal");
        let vault_id = state.vault.as_ref().expect("vault").vault_id();
        state.issue_admin_lease(peer(), 5).expect("lease");
        assert!(matches!(
            state.create_agent_session(
                peer(),
                principal.id,
                Action::Reveal,
                ResourceSelector::Vault(vault_id),
                15,
                1,
            ),
            Err(RuntimeFailure::InvalidGrant)
        ));
        let created = state
            .create_agent_session(
                peer(),
                principal.id,
                Action::Discover,
                ResourceSelector::Vault(vault_id),
                envault_core::DEFAULT_AGENT_GRANT_MINUTES,
                1,
            )
            .expect("capability");
        let token = created.token.into_vec();
        assert_eq!(token.len(), 32);
        let raw_token: [u8; 32] = token.as_slice().try_into().expect("token array");
        assert!(!state.capabilities.contains_key(&raw_token));
        assert_eq!(
            state
                .consume_capability(&token, Action::Discover, ResourceSelector::Vault(vault_id))
                .expect("consume"),
            principal.id
        );
        assert!(matches!(
            state.consume_capability(&token, Action::Discover, ResourceSelector::Vault(vault_id)),
            Err(RuntimeFailure::PermissionDenied)
        ));
        state
            .revoke_agent_session(peer(), created.grant_id)
            .expect("revoke");
        assert!(state.capabilities.is_empty());
        assert!(matches!(
            state.agent_session_status(Some(&SensitiveBytes::new(token.clone()))),
            Err(RuntimeFailure::PermissionDenied)
        ));
        let expiring = state
            .create_agent_session(
                peer(),
                principal.id,
                Action::Discover,
                ResourceSelector::Vault(vault_id),
                envault_core::DEFAULT_AGENT_GRANT_MINUTES,
                1,
            )
            .expect("expiring capability");
        let expiring_token = expiring.token.into_vec();
        state
            .capabilities
            .values_mut()
            .next()
            .expect("session")
            .deadline = Instant::now();
        assert!(matches!(
            state.agent_session_status(Some(&SensitiveBytes::new(expiring_token))),
            Err(RuntimeFailure::PermissionDenied)
        ));
        assert!(state.capabilities.is_empty());
    }
}
