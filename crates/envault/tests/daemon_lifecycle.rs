#![forbid(unsafe_code)]
#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    net::Shutdown,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::time::SystemTime;

use envault_core::PrincipalKind;
use envault_policy::{Action, ResourceSelector};
use envault_protocol::{
    AuthenticatedRequest, MAX_FRAME_BYTES, Operation, PROTOCOL_VERSION, Reply, Request, Response,
    ResponseBody, SensitiveBytes, encode_frame,
};
use serde_json::Value;
use uuid::Uuid;

const PASSWORD: &[u8] = b"daemon-e2e-sentinel-password";

struct DaemonFixture {
    directory: tempfile::TempDir,
    data_home: PathBuf,
    runtime_home: PathBuf,
}

impl DaemonFixture {
    fn initialize() -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        let data_home = directory.path().join("data");
        let runtime_home = directory.path().join("run");
        fs::create_dir_all(&runtime_home).expect("runtime home");
        let fixture = Self {
            directory,
            data_home,
            runtime_home,
        };
        assert_success(&fixture.run(
            &["--output", "json", "init", "--password-stdin"],
            Some(PASSWORD),
        ));
        fixture
    }

    fn initialize_and_start() -> Self {
        let fixture = Self::initialize();
        fixture.start();
        fixture
    }

    fn start(&self) {
        let started = self.run(
            &["--output", "json", "start", "--password-stdin"],
            Some(PASSWORD),
        );
        assert_success(&started);
        assert_no_bytes(&started.stdout, PASSWORD);
        assert_no_bytes(&started.stderr, PASSWORD);
    }

    fn run(&self, arguments: &[&str], input: Option<&[u8]>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_envault"))
            .args(arguments)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("XDG_RUNTIME_DIR", &self.runtime_home)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn envault");
        if let Some(input) = input {
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(input)
                .expect("write input");
        }
        child.wait_with_output().expect("wait for envault")
    }

    fn json(&self, arguments: &[&str]) -> Value {
        let output = self.run(arguments, None);
        assert_success(&output);
        serde_json::from_slice(&output.stdout).expect("JSON output")
    }

    fn socket_path(&self) -> PathBuf {
        self.runtime_home.join("envault/envault.sock")
    }

    fn lock_path(&self) -> PathBuf {
        self.runtime_home.join("envault/envaultd.lock")
    }

    fn start_lock_path(&self) -> PathBuf {
        self.runtime_home.join("envault/envault-start.lock")
    }

    fn wait_for_exit(&self) {
        let lock = envault_platform::open_private_lock_file(&self.lock_path()).expect("lock file");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(error) => panic!("daemon lock: {error}"),
            }
            assert!(Instant::now() < deadline, "daemon did not release its lock");
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn stop(&self) {
        let output = self.run(&["--output", "json", "stop"], None);
        if output.status.success() {
            self.wait_for_exit();
        }
    }
}

impl Drop for DaemonFixture {
    fn drop(&mut self) {
        self.stop();
    }
}

#[test]
fn real_daemon_lifecycle_is_explicit_private_and_idle() {
    let fixture = DaemonFixture::initialize_and_start();
    let first_pid = assert_initial_runtime(&fixture);
    exercise_admin_and_lock(&fixture);
    exercise_recovery_and_shutdown(&fixture, first_pid);
}

#[test]
fn concurrent_start_commands_converge_on_one_unlocked_daemon() {
    let fixture = DaemonFixture::initialize();
    let mut first = spawn_start(&fixture);
    let mut second = spawn_start(&fixture);
    first
        .stdin
        .take()
        .expect("first stdin")
        .write_all(PASSWORD)
        .expect("first password");
    second
        .stdin
        .take()
        .expect("second stdin")
        .write_all(PASSWORD)
        .expect("second password");
    let first = first.wait_with_output().expect("first start");
    let second = second.wait_with_output().expect("second start");
    assert_success(&first);
    assert_success(&second);
    let first_status: Value = serde_json::from_slice(&first.stdout).expect("first status");
    let second_status: Value = serde_json::from_slice(&second.stdout).expect("second status");
    assert_eq!(first_status["service"], "unlocked");
    assert_eq!(second_status["service"], "unlocked");
    assert_eq!(first_status["pid"], second_status["pid"]);
    assert_eq!(
        fixture.json(&["--output", "json", "status"])["pid"],
        first_status["pid"]
    );
}

#[test]
fn phase_four_cli_filters_discovery_and_rejects_private_http_targets() {
    let fixture = DaemonFixture::initialize_and_start();
    let setup = setup_phase_four(&fixture);
    assert_phase_four_discovery(&fixture, &setup);
    assert_phase_four_private_http_rejection(&fixture, &setup);
    assert_tree_has_no_bytes(&fixture.data_home, b"phase4-e2e-credential");
    assert_tree_has_no_bytes(&fixture.data_home, b"hidden-phase4-credential");
    assert_tree_has_no_bytes(&fixture.data_home, setup.discovery_token.as_bytes());
}

struct PhaseFourSetup {
    visible_id: String,
    principal_id: String,
    discovery_token: String,
}

fn setup_phase_four(fixture: &DaemonFixture) -> PhaseFourSetup {
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    let credential = b"phase4-e2e-credential";
    let visible_output = fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "VISIBLE_TOKEN",
            "--description",
            "Visible metadata",
            "--stdin",
        ],
        Some(credential),
    );
    assert_success(&visible_output);
    assert_no_bytes(&visible_output.stdout, credential);
    let visible: Value = serde_json::from_slice(&visible_output.stdout).expect("visible secret");
    let visible_id = visible[0]["id"].as_str().expect("visible id").to_owned();
    let scope_id = visible[0]["scope_id"]
        .as_str()
        .expect("scope id")
        .to_owned();
    let hidden = fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "HIDDEN_TOKEN",
            "--stdin",
        ],
        Some(b"hidden-phase4-credential"),
    );
    assert_success(&hidden);
    let hidden: Value = serde_json::from_slice(&hidden.stdout).expect("hidden secret");
    let hidden_id = hidden[0]["id"].as_str().expect("hidden id").to_owned();
    let principal = fixture.json(&[
        "--output",
        "json",
        "admin",
        "agent",
        "create",
        "agent:phase4-e2e",
    ]);
    let principal_id = principal[0]["id"]
        .as_str()
        .expect("principal id")
        .to_owned();
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "admin",
            "policy",
            "create",
            "--principal",
            &principal_id,
            "--effect",
            "deny",
            "--action",
            "discover",
            "--secret",
            &hidden_id,
        ],
        None,
    ));

    let grant = fixture.run(
        &[
            "--output",
            "json",
            "admin",
            "grant",
            "create",
            "--principal",
            &principal_id,
            "--action",
            "discover",
            "--scope",
            &scope_id,
            "--max-requests",
            "3",
        ],
        None,
    );
    assert_success(&grant);
    let grant: Value = serde_json::from_slice(&grant.stdout).expect("grant");
    let discovery_token = grant["token"].as_str().expect("token").to_owned();
    PhaseFourSetup {
        visible_id,
        principal_id,
        discovery_token,
    }
}

fn assert_phase_four_discovery(fixture: &DaemonFixture, setup: &PhaseFourSetup) {
    let token = setup.discovery_token.as_bytes();
    let context = fixture.run(
        &["--output", "json", "context", "--token-stdin"],
        Some(token),
    );
    assert_success(&context);
    assert_no_bytes(&context.stdout, token);
    let context: Value = serde_json::from_slice(&context.stdout).expect("context");
    assert_eq!(context["session"]["remaining_requests"], 3);
    let toon_context = fixture.run(
        &["--output", "toon", "context", "--token-stdin"],
        Some(token),
    );
    assert_success(&toon_context);
    let toon_context = String::from_utf8(toon_context.stdout).expect("TOON context");
    assert!(toon_context.contains("resource"));
    assert!(toon_context.contains("http_constraint{present}: false"));

    let discovery = fixture.run(
        &[
            "--output",
            "toon",
            "secret",
            "list",
            "--describe",
            "--token-stdin",
        ],
        Some(token),
    );
    assert_success(&discovery);
    assert!(
        discovery
            .stdout
            .windows(b"VISIBLE_TOKEN".len())
            .any(|window| window == b"VISIBLE_TOKEN")
    );
    assert_no_bytes(&discovery.stdout, b"HIDDEN_TOKEN");
    assert_no_bytes(&discovery.stdout, token);
    let session = fixture.run(
        &[
            "--output",
            "json",
            "agent",
            "session",
            "status",
            "--token-stdin",
        ],
        Some(token),
    );
    assert_success(&session);
    let session: Value = serde_json::from_slice(&session.stdout).expect("session");
    assert_eq!(session["remaining_requests"], 2);
}

fn assert_phase_four_private_http_rejection(fixture: &DaemonFixture, setup: &PhaseFourSetup) {
    let http_grant = fixture.run(
        &[
            "--output",
            "json",
            "admin",
            "grant",
            "create",
            "--principal",
            &setup.principal_id,
            "--action",
            "http",
            "--secret",
            &setup.visible_id,
            "--host",
            "localhost",
            "--method",
            "get",
            "--path-prefix",
            "/v1",
        ],
        None,
    );
    assert_success(&http_grant);
    let http_grant: Value = serde_json::from_slice(&http_grant.stdout).expect("HTTP grant");
    let http_token = http_grant["token"].as_str().expect("HTTP token");
    let rejected = fixture.run(
        &[
            "--output",
            "json",
            "request",
            "http",
            "https://localhost/v1/status",
            "--method",
            "get",
            "--secret",
            &setup.visible_id,
            "--token-stdin",
        ],
        Some(http_token.as_bytes()),
    );
    assert!(!rejected.status.success());
    assert_no_bytes(&rejected.stderr, http_token.as_bytes());
    assert_no_bytes(&rejected.stderr, b"phase4-e2e-credential");
    let error: Value = serde_json::from_slice(&rejected.stderr).expect("structured error");
    assert_eq!(error["code"], "request_rejected");
    let session = fixture.run(
        &[
            "--output",
            "json",
            "agent",
            "session",
            "status",
            "--token-stdin",
        ],
        Some(http_token.as_bytes()),
    );
    assert_success(&session);
    let session: Value = serde_json::from_slice(&session.stdout).expect("HTTP session");
    assert_eq!(session["remaining_requests"], 0);
    assert_tree_has_no_bytes(&fixture.data_home, http_token.as_bytes());
}

fn assert_initial_runtime(fixture: &DaemonFixture) -> u32 {
    let status = fixture.json(&["--output", "json", "status"]);
    assert_eq!(status["daemon"], "running");
    assert_eq!(status["service"], "unlocked");
    assert_eq!(status["profile"], "base");
    let first_pid = u32::try_from(status["pid"].as_u64().expect("pid")).expect("u32 pid");
    let already_running = fixture.run(&["--output", "json", "start"], None);
    assert_success(&already_running);
    assert_eq!(
        serde_json::from_slice::<Value>(&already_running.stdout).expect("running status")["pid"],
        u64::from(first_pid)
    );
    assert_eq!(mode(&fixture.runtime_home.join("envault")), 0o700);
    assert_eq!(mode(&fixture.socket_path()), 0o600);
    assert_eq!(mode(&fixture.lock_path()), 0o600);
    assert_eq!(mode(&fixture.start_lock_path()), 0o600);
    assert_process_has_no_password(first_pid);
    assert_persistent_tree_has_no_password(fixture.directory.path());
    assert_process_is_idle(first_pid, &fixture.data_home);
    first_pid
}

fn exercise_admin_and_lock(fixture: &DaemonFixture) {
    let wrong = fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(b"wrong-daemon-password"),
    );
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("authentication_failed"));
    let invalid_ttl = fixture.run(
        &[
            "--output",
            "json",
            "admin",
            "unlock",
            "--password-stdin",
            "--minutes",
            "0",
        ],
        Some(PASSWORD),
    );
    assert!(!invalid_ttl.status.success());
    assert!(String::from_utf8_lossy(&invalid_ttl.stderr).contains("invalid_ttl"));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "admin",
            "unlock",
            "--password-stdin",
            "--minutes",
            "1",
        ],
        Some(PASSWORD),
    ));
    assert_eq!(
        fixture.json(&["--output", "json", "admin", "status"])["active"],
        true
    );
    assert_success(&fixture.run(&["--output", "json", "admin", "lock"], None));
    assert_success(&fixture.run(&["--output", "json", "lock"], None));
    assert_eq!(
        fixture.json(&["--output", "json", "status"])["service"],
        "locked"
    );
    assert_cli_error_code(
        &fixture.run(&["--output", "json", "lock"], None),
        "envault_locked",
    );
    assert_cli_error_code(
        &fixture.run(&["--output", "json", "admin", "status"], None),
        "envault_locked",
    );
}

fn exercise_recovery_and_shutdown(fixture: &DaemonFixture, first_pid: u32) {
    assert_success(&fixture.run(
        &["--output", "json", "start", "--password-stdin"],
        Some(PASSWORD),
    ));
    let restarted = fixture.json(&["--output", "json", "status"]);
    assert_eq!(restarted["service"], "unlocked");
    assert_ne!(restarted["pid"].as_u64(), Some(u64::from(first_pid)));

    fixture.stop();
    assert_eq!(
        fixture.json(&["--output", "json", "status"])["daemon"],
        "stopped"
    );
    let stopped_human = fixture.run(&["status"], None);
    assert_success(&stopped_human);
    assert!(String::from_utf8_lossy(&stopped_human.stdout).contains("envault start"));
    let stopped_toon = fixture.run(&["--output", "toon", "status"], None);
    assert_success(&stopped_toon);
    assert!(String::from_utf8_lossy(&stopped_toon.stdout).contains("help[1]"));
    assert!(!fixture.socket_path().exists());

    fs::write(fixture.socket_path(), b"must-not-be-deleted").expect("non-socket fixture");
    let unsafe_recovery = fixture.run(
        &["--output", "json", "start", "--password-stdin"],
        Some(PASSWORD),
    );
    assert!(!unsafe_recovery.status.success());
    assert_eq!(
        fs::read(fixture.socket_path()).expect("non-socket remains"),
        b"must-not-be-deleted"
    );
    fs::remove_file(fixture.socket_path()).expect("remove test fixture");

    drop(UnixListener::bind(fixture.socket_path()).expect("stale socket"));
    assert_success(&fixture.run(
        &["--output", "json", "start", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_eq!(
        fixture.json(&["--output", "json", "status"])["service"],
        "unlocked"
    );

    let graceful_pid = fixture.json(&["--output", "json", "status"])["pid"]
        .as_i64()
        .and_then(|pid| i32::try_from(pid).ok())
        .expect("signal pid");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(graceful_pid),
        nix::sys::signal::Signal::SIGHUP,
    )
    .expect("hangup daemon");
    fixture.wait_for_exit();
    assert!(!fixture.socket_path().exists());

    assert_success(&fixture.run(
        &["--output", "json", "start", "--password-stdin"],
        Some(PASSWORD),
    ));
    let crash_pid = fixture.json(&["--output", "json", "status"])["pid"]
        .as_i64()
        .and_then(|pid| i32::try_from(pid).ok())
        .expect("crash pid");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(crash_pid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect("crash daemon");
    fixture.wait_for_exit();
    assert!(fixture.socket_path().exists());
    assert_success(&fixture.run(
        &["--output", "json", "start", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_eq!(
        fixture.json(&["--output", "json", "status"])["service"],
        "unlocked"
    );
}

#[test]
fn malformed_local_clients_fail_closed_without_crashing_daemon() {
    let fixture = DaemonFixture::initialize_and_start();

    let mut oversized = UnixStream::connect(fixture.socket_path()).expect("connect");
    oversized
        .write_all(
            &u32::try_from(MAX_FRAME_BYTES + 1)
                .expect("bounded")
                .to_be_bytes(),
        )
        .expect("write oversized length");
    oversized
        .shutdown(Shutdown::Write)
        .expect("shutdown oversized writer");
    assert_error_code(read_response(&mut oversized), "invalid_request");

    let mut truncated = UnixStream::connect(fixture.socket_path()).expect("connect");
    truncated.write_all(&10_u32.to_be_bytes()).expect("length");
    truncated.write_all(&[0x01, 0x02]).expect("partial payload");
    truncated
        .shutdown(Shutdown::Write)
        .expect("shutdown truncated writer");
    assert_error_code(read_response(&mut truncated), "invalid_request");

    let mut random = UnixStream::connect(fixture.socket_path()).expect("connect");
    random.write_all(&3_u32.to_be_bytes()).expect("length");
    random.write_all(&[0xff, 0x01, 0x02]).expect("payload");
    random
        .shutdown(Shutdown::Write)
        .expect("shutdown random writer");
    assert_error_code(read_response(&mut random), "invalid_request");

    let request_id = Uuid::new_v4();
    let mismatched = Request {
        version: PROTOCOL_VERSION + 1,
        request_id,
        body: AuthenticatedRequest {
            capability_token: None,
            operation: Operation::Status,
        },
    };
    let mut versioned = UnixStream::connect(fixture.socket_path()).expect("connect");
    versioned
        .write_all(&encode_frame(&mismatched).expect("encode"))
        .expect("write mismatch");
    versioned
        .shutdown(Shutdown::Write)
        .expect("shutdown version writer");
    let response = read_response(&mut versioned);
    assert_eq!(response.request_id, request_id);
    assert_error_code(response, "protocol_mismatch");

    let mut stalled = UnixStream::connect(fixture.socket_path()).expect("connect");
    assert_error_code(read_response(&mut stalled), "request_timeout");

    let first_request = Request {
        version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        body: AuthenticatedRequest {
            capability_token: None,
            operation: Operation::Status,
        },
    };
    let second_request = Request {
        version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        body: AuthenticatedRequest {
            capability_token: None,
            operation: Operation::Status,
        },
    };
    let mut repeated = UnixStream::connect(fixture.socket_path()).expect("connect");
    repeated
        .write_all(&encode_frame(&first_request).expect("first frame"))
        .expect("first request");
    repeated
        .write_all(&encode_frame(&second_request).expect("second frame"))
        .expect("second request");
    let response = read_response(&mut repeated);
    assert_eq!(response.request_id, first_request.request_id);
    let mut extra = [0; 1];
    match repeated.read(&mut extra) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) => {}
        result => panic!("second request was not rejected by connection close: {result:?}"),
    }

    let status = fixture.json(&["--output", "json", "status"]);
    assert_eq!(status["service"], "unlocked");
    assert_persistent_tree_has_no_password(fixture.directory.path());
}

#[test]
fn agent_capabilities_are_narrow_hashed_revocable_and_never_admin() {
    let fixture = DaemonFixture::initialize();
    let database_path = fixture.data_home.join("envault/vault.db");
    let password = envault_service::SensitiveInput::copy_from_slice(PASSWORD);
    let mut vault =
        envault_service::VaultSession::unlock(&database_path, &password).expect("unlock vault");
    let principal = vault
        .create_principal(PrincipalKind::Agent, "agent:e2e")
        .expect("agent principal");
    let vault_id = vault.vault_id();
    drop(vault);
    drop(password);
    fixture.start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));

    let privileged = envault::client::request_at(
        &fixture.socket_path(),
        Operation::CreateAgentSession {
            principal_id: principal.id,
            action: Action::Reveal,
            resource: ResourceSelector::Vault(vault_id),
            http_constraint: None,
            ttl_minutes: 15,
            max_requests: 2,
        },
        None,
    );
    assert_remote_code(privileged, "invalid_grant");

    let created = match envault::client::request_at(
        &fixture.socket_path(),
        Operation::CreateAgentSession {
            principal_id: principal.id,
            action: Action::Discover,
            resource: ResourceSelector::Vault(vault_id),
            http_constraint: None,
            ttl_minutes: 15,
            max_requests: 2,
        },
        None,
    )
    .expect("create session")
    {
        Reply::AgentSessionCreated(created) => created,
        reply => panic!("unexpected create reply: {reply:?}"),
    };
    let token = created.token.into_vec();
    assert_eq!(token.len(), 32);
    assert_tree_has_no_bytes(fixture.directory.path(), &token);
    let status = envault::client::request_at(
        &fixture.socket_path(),
        Operation::AgentSessionStatus,
        Some(SensitiveBytes::new(token.clone())),
    )
    .expect("session status");
    match status {
        Reply::AgentSessionStatus(status) => {
            assert_eq!(status.principal_id, principal.id);
            assert_eq!(status.action, Action::Discover);
            assert_eq!(status.remaining_requests, 2);
        }
        reply => panic!("unexpected status reply: {reply:?}"),
    }

    assert_agent_token_cannot_authorize_service_or_admin(&fixture, &token);
    assert_success(&fixture.run(&["--output", "json", "admin", "lock"], None));
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert!(matches!(
        envault::client::request_at(
            &fixture.socket_path(),
            Operation::RevokeAgentSession {
                grant_id: created.grant_id,
            },
            None,
        ),
        Ok(Reply::Acknowledged)
    ));
    assert_remote_code(
        envault::client::request_at(
            &fixture.socket_path(),
            Operation::AgentSessionStatus,
            Some(SensitiveBytes::new(token)),
        ),
        "permission_denied",
    );
}

fn assert_agent_token_cannot_authorize_service_or_admin(fixture: &DaemonFixture, token: &[u8]) {
    assert_remote_code(
        envault::client::request_at(
            &fixture.socket_path(),
            Operation::AdminLock,
            Some(SensitiveBytes::new(token.to_vec())),
        ),
        "permission_denied",
    );
    assert_eq!(
        fixture.json(&["--output", "json", "admin", "status"])["active"],
        true
    );
    assert_remote_code(
        envault::client::request_at(
            &fixture.socket_path(),
            Operation::Lock,
            Some(SensitiveBytes::new(token.to_vec())),
        ),
        "permission_denied",
    );
    assert_eq!(
        fixture.json(&["--output", "json", "status"])["service"],
        "unlocked"
    );
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_cli_error_code(output: &Output, expected: &str) {
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured CLI error");
    assert_eq!(error["code"], expected);
    assert!(
        error["help"]
            .as_array()
            .expect("help array")
            .iter()
            .any(|item| item
                .as_str()
                .is_some_and(|item| item.contains("envault start")))
    );
}

fn spawn_start(fixture: &DaemonFixture) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_envault"))
        .args(["--output", "json", "start", "--password-stdin"])
        .env("XDG_DATA_HOME", &fixture.data_home)
        .env("XDG_RUNTIME_DIR", &fixture.runtime_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn concurrent start")
}

fn read_response(stream: &mut UnixStream) -> Response<Reply> {
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .expect("timeout");
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).expect("response prefix");
    let length = u32::from_be_bytes(prefix) as usize;
    assert!(length <= MAX_FRAME_BYTES);
    let mut frame = Vec::with_capacity(length + 4);
    frame.extend_from_slice(&prefix);
    frame.resize(length + 4, 0);
    stream
        .read_exact(&mut frame[4..])
        .expect("response payload");
    envault_protocol::decode_frame(&frame).expect("response")
}

fn assert_error_code(response: Response<Reply>, expected: &str) {
    match response.body {
        ResponseBody::Error(error) => assert_eq!(error.code, expected),
        ResponseBody::Ok(reply) => panic!("expected error response, got {reply:?}"),
    }
}

fn assert_remote_code(result: Result<Reply, envault::client::ClientError>, expected: &str) {
    match result {
        Err(envault::client::ClientError::Remote(error)) => assert_eq!(error.code, expected),
        result => panic!("expected remote error {expected}, got {result:?}"),
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

fn assert_no_bytes(haystack: &[u8], needle: &[u8]) {
    assert!(
        !haystack
            .windows(needle.len())
            .any(|window| window == needle)
    );
}

fn assert_persistent_tree_has_no_password(root: &Path) {
    assert_tree_has_no_bytes(root, PASSWORD);
}

fn assert_tree_has_no_bytes(root: &Path, forbidden: &[u8]) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("read directory") {
                pending.push(entry.expect("directory entry").path());
            }
        } else if metadata.is_file()
            && let Ok(bytes) = fs::read(path)
        {
            assert_no_bytes(&bytes, forbidden);
        }
    }
}

#[cfg(target_os = "linux")]
fn assert_process_has_no_password(pid: u32) {
    assert_no_bytes(
        &fs::read(format!("/proc/{pid}/cmdline")).expect("cmdline"),
        PASSWORD,
    );
    match fs::read(format!("/proc/{pid}/environ")) {
        Ok(environment) => assert_no_bytes(&environment, PASSWORD),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => panic!("read daemon environment: {error}"),
    }
    let limits = fs::read_to_string(format!("/proc/{pid}/limits")).expect("limits");
    let core = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .expect("core limit");
    assert!(
        core.split_whitespace()
            .skip(4)
            .take(2)
            .all(|value| value == "0")
    );
}

#[cfg(not(target_os = "linux"))]
fn assert_process_has_no_password(_pid: u32) {}

#[cfg(target_os = "linux")]
fn assert_process_is_idle(pid: u32, persistent_root: &Path) {
    thread::sleep(Duration::from_millis(200));
    let before_cpu = process_cpu_ticks(pid);
    let before_io = process_disk_bytes(pid);
    let before_files = persistent_metadata(persistent_root);
    thread::sleep(Duration::from_millis(500));
    assert_eq!(process_cpu_ticks(pid), before_cpu);
    let after_io = process_disk_bytes(pid);
    if before_io.is_some() {
        assert_eq!(after_io, before_io);
    } else {
        assert!(after_io.is_none());
    }
    assert_eq!(persistent_metadata(persistent_root), before_files);
}

#[cfg(not(target_os = "linux"))]
fn assert_process_is_idle(_pid: u32, _persistent_root: &Path) {}

#[cfg(target_os = "linux")]
fn process_cpu_ticks(pid: u32) -> (u64, u64) {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let fields = stat
        .split_once(") ")
        .expect("stat command boundary")
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    (
        fields[11].parse().expect("user ticks"),
        fields[12].parse().expect("system ticks"),
    )
}

#[cfg(target_os = "linux")]
fn process_disk_bytes(pid: u32) -> Option<(u64, u64)> {
    let io = match fs::read_to_string(format!("/proc/{pid}/io")) {
        Ok(io) => io,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("read daemon I/O counters: {error}"),
    };
    let value = |key: &str| {
        io.lines()
            .find_map(|line| line.strip_prefix(key))
            .expect("counter")
            .trim()
            .parse()
            .expect("numeric counter")
    };
    Some((value("read_bytes:"), value("write_bytes:")))
}

#[cfg(target_os = "linux")]
fn persistent_metadata(root: &Path) -> Vec<(PathBuf, u64, Option<SystemTime>)> {
    let mut pending = vec![root.to_path_buf()];
    let mut snapshot = Vec::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).expect("persistent metadata");
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("persistent directory") {
                pending.push(entry.expect("persistent entry").path());
            }
        } else if metadata.is_file() {
            snapshot.push((
                path.strip_prefix(root)
                    .expect("relative path")
                    .to_path_buf(),
                metadata.len(),
                metadata.modified().ok(),
            ));
        }
    }
    snapshot.sort();
    snapshot
}
