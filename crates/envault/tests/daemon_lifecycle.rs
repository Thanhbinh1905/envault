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

use envault_protocol::{
    AuthenticatedRequest, MAX_FRAME_BYTES, Operation, PROTOCOL_VERSION, Reply, Request, Response,
    ResponseBody, encode_frame,
};
use serde_json::Value;
use uuid::Uuid;

const PASSWORD: &[u8] = b"daemon-e2e-sentinel-password";
const TRANSFER_PASSWORD: &[u8] = b"daemon-e2e-transfer-password";

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
#[allow(clippy::too_many_lines)]
fn phase_five_cli_round_trips_workspace_and_env_without_plaintext_output() {
    let source = DaemonFixture::initialize_and_start();
    let destination = DaemonFixture::initialize_and_start();
    for fixture in [&source, &destination] {
        assert_success(&fixture.run(
            &["--output", "json", "admin", "unlock", "--password-stdin"],
            Some(PASSWORD),
        ));
    }
    let sentinel = b"phase5-cli-secret-sentinel";
    assert_success(&source.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "PHASE5_TOKEN",
            "--stdin",
        ],
        Some(sentinel),
    ));
    let package = source.directory.path().join("transfer.envault-workspace");
    let package_text = package.to_string_lossy().into_owned();
    let exported = source.run(
        &[
            "--output",
            "json",
            "portability",
            "export",
            "--output-file",
            &package_text,
            "--transfer-password-stdin",
        ],
        Some(TRANSFER_PASSWORD),
    );
    assert_success(&exported);
    assert_no_bytes(&exported.stdout, sentinel);
    assert_no_bytes(&exported.stdout, TRANSFER_PASSWORD);
    assert_no_bytes(&exported.stderr, sentinel);
    assert_no_bytes(&fs::read(&package).expect("package"), sentinel);
    assert_eq!(mode(&package), 0o600);

    let preview = destination.run(
        &[
            "--output",
            "json",
            "portability",
            "import",
            &package_text,
            "--transfer-password-stdin",
            "--strategy",
            "abort",
        ],
        Some(TRANSFER_PASSWORD),
    );
    assert_success(&preview);
    assert_no_bytes(&preview.stdout, sentinel);
    let preview: Value = serde_json::from_slice(&preview.stdout).expect("preview");
    let plan_hash = preview["plan_hash"].as_str().expect("plan hash");
    let committed = destination.run(
        &[
            "--output",
            "json",
            "portability",
            "import",
            &package_text,
            "--transfer-password-stdin",
            "--strategy",
            "abort",
            "--commit",
            "--plan-hash",
            plan_hash,
        ],
        Some(TRANSFER_PASSWORD),
    );
    assert_success(&committed);
    assert_no_bytes(&committed.stdout, sentinel);
    assert_no_bytes(&committed.stderr, sentinel);

    let env_input = destination.directory.path().join("guided.env");
    write_private_fixture(&env_input, b"GUIDED_TOKEN=guided-import-sentinel\n");
    let env_input_text = env_input.to_string_lossy().into_owned();
    let env_preview = destination.run(
        &[
            "--output",
            "json",
            "profile",
            "import-env",
            "base",
            &env_input_text,
            "--strategy",
            "abort",
        ],
        None,
    );
    assert_success(&env_preview);
    assert_no_bytes(&env_preview.stdout, b"guided-import-sentinel");
    let env_preview: Value = serde_json::from_slice(&env_preview.stdout).expect("env preview");
    let env_plan_hash = env_preview["plan_hash"].as_str().expect("env plan hash");
    assert_success(&destination.run(
        &[
            "--output",
            "json",
            "profile",
            "import-env",
            "base",
            &env_input_text,
            "--strategy",
            "abort",
            "--commit",
            "--plan-hash",
            env_plan_hash,
        ],
        None,
    ));

    let plaintext = destination.directory.path().join("recovery.env");
    let plaintext_text = plaintext.to_string_lossy().into_owned();
    let plaintext_output = destination.run(
        &[
            "--output",
            "json",
            "profile",
            "export-env",
            "base",
            "--output-file",
            &plaintext_text,
            "--allow-plaintext",
        ],
        None,
    );
    assert_success(&plaintext_output);
    assert_no_bytes(&plaintext_output.stdout, sentinel);
    assert_no_bytes(&plaintext_output.stdout, b"guided-import-sentinel");
    let plaintext_bytes = fs::read(&plaintext).expect("plaintext export");
    assert!(
        plaintext_bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel)
    );
    assert!(
        plaintext_bytes
            .windows(b"guided-import-sentinel".len())
            .any(|window| window == b"guided-import-sentinel")
    );
    assert_eq!(mode(&plaintext), 0o600);
    assert_tree_has_no_bytes(&destination.data_home, sentinel);
    assert_tree_has_no_bytes(&destination.data_home, b"guided-import-sentinel");
}

#[test]
fn secret_list_fields_flag_gates_description_and_rejects_unknown_fields() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "FIELDS_TEST",
            "--description",
            "fields-flag-sentinel",
            "--stdin",
        ],
        Some(b"fields-flag-secret-value"),
    ));

    let default_list = fixture.json(&["--output", "json", "secret", "list"]);
    assert_eq!(default_list[0]["description"], Value::Null);

    let with_fields = fixture.json(&[
        "--output",
        "json",
        "secret",
        "list",
        "--fields",
        "description",
    ]);
    assert_eq!(with_fields[0]["description"], "fields-flag-sentinel");

    let with_legacy_describe = fixture.json(&["--output", "json", "secret", "list", "--describe"]);
    assert_eq!(
        with_legacy_describe[0]["description"],
        "fields-flag-sentinel"
    );

    let rejected = fixture.run(
        &["--output", "json", "secret", "list", "--fields", "bogus"],
        None,
    );
    assert!(!rejected.status.success());
    let error: Value = serde_json::from_slice(&rejected.stderr).expect("structured CLI error");
    assert_eq!(error["code"], "unknown_field");
    assert_eq!(error["kind"], "usage");
}

#[test]
fn exit_codes_distinguish_usage_from_runtime_errors() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));

    let usage_error = fixture.run(
        &["--output", "json", "secret", "list", "--fields", "bogus"],
        None,
    );
    assert_eq!(usage_error.status.code(), Some(2));
    let usage_body: Value = serde_json::from_slice(&usage_error.stderr).expect("usage error");
    assert_eq!(usage_body["kind"], "usage");

    let runtime_error = fixture.run(
        &["--output", "json", "profile", "show", "no-such-profile"],
        None,
    );
    assert_eq!(runtime_error.status.code(), Some(1));
    let runtime_body: Value = serde_json::from_slice(&runtime_error.stderr).expect("runtime error");
    assert_eq!(runtime_body["kind"], "runtime");
    assert_eq!(runtime_body["code"], "not_found");
}

#[test]
fn profile_and_secret_delete_are_idempotent_no_ops() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "profile",
            "create",
            "IDEMPOTENT_PROFILE",
        ],
        None,
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "IDEMPOTENT_SECRET",
            "--stdin",
        ],
        Some(b"idempotent-delete-sentinel"),
    ));

    let first_profile_delete = fixture.json(&[
        "--output",
        "json",
        "profile",
        "delete",
        "IDEMPOTENT_PROFILE",
    ]);
    assert_eq!(first_profile_delete["no_op"], false);
    let second_profile_delete = fixture.json(&[
        "--output",
        "json",
        "profile",
        "delete",
        "IDEMPOTENT_PROFILE",
    ]);
    assert_eq!(second_profile_delete["no_op"], true);

    let first_secret_delete =
        fixture.json(&["--output", "json", "secret", "delete", "IDEMPOTENT_SECRET"]);
    assert_eq!(first_secret_delete["no_op"], false);
    let second_secret_delete =
        fixture.json(&["--output", "json", "secret", "delete", "IDEMPOTENT_SECRET"]);
    assert_eq!(second_secret_delete["no_op"], true);
}

#[test]
fn empty_secret_list_reports_zero_explicitly() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));

    let secrets = fixture.run(&["--output", "human", "secret", "list"], None);
    assert_success(&secrets);
    let secrets = String::from_utf8(secrets.stdout).expect("human secrets output");
    assert!(secrets.starts_with("secrets: 0 secrets found\n"));
}

#[test]
fn session_context_reports_daemon_state_without_secret_material() {
    let fixture = DaemonFixture::initialize();
    let stopped = fixture.json(&["--output", "json", "session", "context"]);
    assert_eq!(stopped["daemon"], "stopped");
    assert_eq!(stopped["service"], "inactive");
    assert_eq!(stopped["profile"], Value::Null);

    fixture.start();
    let sentinel = b"session-context-secret-sentinel";
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "SESSION_SECRET",
            "--stdin",
        ],
        Some(sentinel),
    ));

    let running = fixture.run(&["--output", "toon", "session", "context"], None);
    assert_success(&running);
    assert_no_bytes(&running.stdout, sentinel);
    let running = String::from_utf8(running.stdout).expect("TOON session context");
    assert!(running.contains("session{daemon,service,profile}: running,unlocked,\"base\""));
}

#[test]
fn session_setup_is_idempotent_and_repairs_a_stale_command() {
    let directory = tempfile::tempdir().expect("tempdir");
    let settings_path = directory.path().join(".claude/settings.json");
    let settings_arg = settings_path.to_string_lossy().into_owned();

    let installed = Command::new(env!("CARGO_BIN_EXE_envault"))
        .args([
            "--output",
            "json",
            "session",
            "setup",
            "--settings-file",
            &settings_arg,
        ])
        .output()
        .expect("spawn envault session setup");
    assert_success(&installed);
    let installed_body: Value =
        serde_json::from_slice(&installed.stdout).expect("structured setup result");
    assert_eq!(installed_body["status"], "installed");

    let settings_text = fs::read_to_string(&settings_path).expect("settings file");
    let settings: Value = serde_json::from_str(&settings_text).expect("settings JSON");
    let command = settings["hooks"]["SessionStart"][0]["hooks"][0]["command"]
        .as_str()
        .expect("hook command")
        .to_owned();
    assert!(command.contains("session context"));
    assert!(command.contains("--output toon"));

    let unchanged = Command::new(env!("CARGO_BIN_EXE_envault"))
        .args([
            "--output",
            "json",
            "session",
            "setup",
            "--settings-file",
            &settings_arg,
        ])
        .output()
        .expect("spawn envault session setup again");
    assert_success(&unchanged);
    let unchanged_body: Value =
        serde_json::from_slice(&unchanged.stdout).expect("structured setup result");
    assert_eq!(unchanged_body["status"], "unchanged");

    let stale = settings_text.replace(
        &command,
        "/stale/relocated/envault session context --output toon --envault-session-hook",
    );
    fs::write(&settings_path, stale).expect("write stale settings");
    let repaired = Command::new(env!("CARGO_BIN_EXE_envault"))
        .args([
            "--output",
            "json",
            "session",
            "setup",
            "--settings-file",
            &settings_arg,
        ])
        .output()
        .expect("spawn envault session setup after relocation");
    assert_success(&repaired);
    let repaired_body: Value =
        serde_json::from_slice(&repaired.stdout).expect("structured setup result");
    assert_eq!(repaired_body["status"], "repaired");

    let repaired_settings: Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).expect("settings file"))
            .expect("settings JSON");
    let repaired_command = repaired_settings["hooks"]["SessionStart"][0]["hooks"][0]["command"]
        .as_str()
        .expect("hook command");
    assert_eq!(repaired_command, command);
}

#[test]
fn session_setup_preserves_unrelated_settings_and_hooks() {
    let directory = tempfile::tempdir().expect("tempdir");
    let settings_path = directory.path().join(".claude/settings.json");
    fs::create_dir_all(settings_path.parent().expect("parent")).expect("settings dir");
    fs::write(
        &settings_path,
        r#"{"theme":"dark","hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"echo other-hook"}]}],"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo audit"}]}]}}"#,
    )
    .expect("write existing settings");
    let settings_arg = settings_path.to_string_lossy().into_owned();

    let installed = Command::new(env!("CARGO_BIN_EXE_envault"))
        .args([
            "--output",
            "json",
            "session",
            "setup",
            "--settings-file",
            &settings_arg,
        ])
        .output()
        .expect("spawn envault session setup");
    assert_success(&installed);

    let settings: Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).expect("settings file"))
            .expect("settings JSON");
    assert_eq!(settings["theme"], "dark");
    assert_eq!(
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "echo audit"
    );
    let session_start = settings["hooks"]["SessionStart"]
        .as_array()
        .expect("SessionStart array");
    assert_eq!(session_start.len(), 2);
    assert_eq!(session_start[0]["hooks"][0]["command"], "echo other-hook");
    assert!(
        session_start[1]["hooks"][0]["command"]
            .as_str()
            .expect("command")
            .contains("session context")
    );
}

#[test]
fn session_setup_preserves_hooks_that_only_contain_session_context_text() {
    let directory = tempfile::tempdir().expect("tempdir");
    let settings_path = directory.path().join(".claude/settings.json");
    fs::create_dir_all(settings_path.parent().expect("parent")).expect("settings dir");
    fs::write(
        &settings_path,
        r#"{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"echo 'session context from another tool'"}]}]}}"#,
    )
    .expect("write existing settings");
    let settings_arg = settings_path.to_string_lossy().into_owned();

    let installed = Command::new(env!("CARGO_BIN_EXE_envault"))
        .args([
            "--output",
            "json",
            "session",
            "setup",
            "--settings-file",
            &settings_arg,
        ])
        .output()
        .expect("spawn envault session setup");
    assert_success(&installed);

    let settings: Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).expect("settings file"))
            .expect("settings JSON");
    let session_start = settings["hooks"]["SessionStart"]
        .as_array()
        .expect("SessionStart array");
    assert_eq!(session_start.len(), 2);
    assert_eq!(
        session_start[0]["hooks"][0]["command"],
        "echo 'session context from another tool'"
    );
    assert!(
        session_start[1]["hooks"][0]["command"]
            .as_str()
            .expect("command")
            .contains("--envault-session-hook")
    );
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
    let repeat_lock = fixture.run(&["--output", "json", "lock"], None);
    assert_success(&repeat_lock);
    let repeat_lock_body: Value =
        serde_json::from_slice(&repeat_lock.stdout).expect("structured lock acknowledgement");
    assert_eq!(
        repeat_lock_body["no_op"], true,
        "locking an already-locked daemon is an idempotent no-op, not an error"
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
            operation: Operation::Status,
        },
    };
    let second_request = Request {
        version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        body: AuthenticatedRequest {
            operation: Operation::Status,
        },
    };
    let mut repeated = UnixStream::connect(fixture.socket_path()).expect("connect");
    repeated
        .write_all(&encode_frame(&first_request).expect("first frame"))
        .expect("first request");
    // The daemon serves exactly one request per connection and then drops the
    // stream, closing it. Depending on scheduling, that close can race far
    // enough ahead of this client that the *second* write (not just the
    // subsequent read) observes the closed pipe. Both landing spots are
    // benign evidence of the same "connection rejected after one request"
    // contract, so both are tolerated; anything else still fails the test.
    let second_write = repeated.write_all(&encode_frame(&second_request).expect("second frame"));
    let response = read_response(&mut repeated);
    assert_eq!(response.request_id, first_request.request_id);
    let is_closed_error = |error: &std::io::Error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        )
    };
    match second_write {
        Ok(()) => {
            let mut extra = [0; 1];
            match repeated.read(&mut extra) {
                Ok(0) => {}
                Err(error) if is_closed_error(&error) => {}
                result => panic!("second request was not rejected by connection close: {result:?}"),
            }
        }
        Err(error) if is_closed_error(&error) => {}
        Err(error) => panic!("second request write failed unexpectedly: {error:?}"),
    }

    let status = fixture.json(&["--output", "json", "status"]);
    assert_eq!(status["service"], "unlocked");
    assert_persistent_tree_has_no_password(fixture.directory.path());
}

#[test]
fn secret_http_access_rejects_private_and_loopback_hosts() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "base.PRIVATE_HOST_TOKEN",
            "--stdin",
        ],
        Some(b"phase4-e2e-credential"),
    ));

    // Configuring the allowlist rule succeeds - `--host` is just a name at
    // this point, not yet resolved.
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "profile",
            "load",
            "base",
            "--secret",
            "PRIVATE_HOST_TOKEN",
            "--host",
            "localhost",
            "--method",
            "get",
            "--path-prefix",
            "/v1",
        ],
        None,
    ));

    // The broker itself refuses to actually connect to a loopback/private
    // address at request time, independent of the allowlist rule matching.
    assert_stderr_error_code(
        &fixture.run(
            &[
                "--output",
                "json",
                "request",
                "http",
                "https://localhost/v1/status",
                "--secret",
                "base.PRIVATE_HOST_TOKEN",
            ],
            None,
        ),
        "request_rejected",
    );
}

#[test]
fn secret_http_access_gates_request_http_without_any_principal_or_token() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "base.HTTP_TOKEN",
            "--stdin",
        ],
        Some(b"broker-token-e2e"),
    ));

    // No access rule configured yet: request http must fail closed.
    assert_stderr_error_code(
        &fixture.run(
            &[
                "--output",
                "json",
                "request",
                "http",
                "https://api.example.com/v1/status",
                "--secret",
                "base.HTTP_TOKEN",
            ],
            None,
        ),
        "permission_denied",
    );

    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "profile",
            "load",
            "base",
            "--secret",
            "HTTP_TOKEN",
            "--host",
            "api.example.com",
            "--method",
            "get",
        ],
        None,
    ));

    // Same-uid caller, still no principal/token involved - just profile
    // loaded + a matching secret_http_access rule that denies the wrong host.
    assert_stderr_error_code(
        &fixture.run(
            &[
                "--output",
                "json",
                "request",
                "http",
                "https://attacker.example.com/v1/status",
                "--secret",
                "base.HTTP_TOKEN",
            ],
            None,
        ),
        "request_rejected",
    );
}

#[test]
fn run_accepts_repeated_profile_flags_across_unrelated_profiles() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(&["--output", "json", "profile", "create", "db"], None));
    assert_success(&fixture.run(&["--output", "json", "profile", "create", "cache"], None));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "db.PGHOST",
            "--stdin",
        ],
        Some(b"db-host"),
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "cache.REDIS_HOST",
            "--stdin",
        ],
        Some(b"cache-host"),
    ));
    assert_success(&fixture.run(&["--output", "json", "profile", "load", "db"], None));
    assert_success(&fixture.run(&["--output", "json", "profile", "load", "cache"], None));

    let output = fixture.run(
        &[
            "run",
            "--profile",
            "db",
            "--profile",
            "cache",
            "--",
            "sh",
            "-c",
            "printf '%s %s' \"$PGHOST\" \"$REDIS_HOST\"",
        ],
        None,
    );
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "db-host cache-host"
    );
}

#[cfg(unix)]
#[test]
fn run_resolves_argv_placeholders_via_a_pipe_without_a_profile_or_workspace_flag() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(&["--output", "json", "profile", "create", "db"], None));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "db.PGPASSWORD",
            "--stdin",
        ],
        Some(b"argv-placeholder-secret"),
    ));
    assert_success(&fixture.run(&["--output", "json", "profile", "load", "db"], None));

    let output = fixture.run(&["run", "--", "cat", "{{db.PGPASSWORD}}"], None);
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "argv-placeholder-secret"
    );

    // The placeholder's own text never appears in the exec'd argv - only a
    // /dev/fd path does, so `ps`-style inspection never sees the secret.
    let unloaded = fixture.run(&["run", "--", "cat", "{{db.MISSING}}"], None);
    assert_eq!(unloaded.status.code(), Some(1));

    let malformed = fixture.run(&["run", "--", "cat", "{{no-dot-here}}"], None);
    assert_eq!(malformed.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&malformed.stderr).contains("invalid_placeholder"),
        "stderr: {}",
        String::from_utf8_lossy(&malformed.stderr)
    );
}

#[test]
fn run_injects_resolved_secrets_into_child_env_never_into_its_own_stdout() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "base.RUN_TOKEN",
            "--stdin",
        ],
        Some(b"run-command-e2e-secret"),
    ));

    let output = fixture.run(
        &["run", "--profile", "base", "--", "printenv", "RUN_TOKEN"],
        None,
    );
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "run-command-e2e-secret"
    );

    // `run` itself never prints the resolved value - only the child process
    // it spawns (which explicitly asked for it via printenv) does.
    let bare_status = fixture.run(&["run", "--profile", "base", "--", "true"], None);
    assert_success(&bare_status);
    assert_no_bytes(&bare_status.stdout, b"run-command-e2e-secret");
    assert_no_bytes(&bare_status.stderr, b"run-command-e2e-secret");
}

#[test]
fn run_rejects_a_profile_that_has_not_been_loaded() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(&["--output", "json", "profile", "create", "unloaded"], None));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "unloaded.RUN_TOKEN",
            "--stdin",
        ],
        Some(b"unloaded-secret"),
    ));

    let output = fixture.run(
        &[
            "run",
            "--profile",
            "unloaded",
            "--",
            "printenv",
            "RUN_TOKEN",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("profile_not_loaded"), "stderr: {stderr}");
    assert_no_bytes(&output.stdout, b"unloaded-secret");

    assert_success(&fixture.run(&["--output", "json", "profile", "load", "unloaded"], None));
    let output = fixture.run(
        &[
            "run",
            "--profile",
            "unloaded",
            "--",
            "printenv",
            "RUN_TOKEN",
        ],
        None,
    );
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "unloaded-secret"
    );
}

#[test]
fn run_workspace_rejects_duplicate_secret_name_across_profiles() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(&["--output", "json", "workspace", "create", "team"], None));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "profile",
            "create",
            "team-a",
            "--workspace",
            "team",
        ],
        None,
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "profile",
            "create",
            "team-b",
            "--workspace",
            "team",
        ],
        None,
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "team-a.SHARED_TOKEN",
            "--stdin",
        ],
        Some(b"team-a-secret"),
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "team-b.SHARED_TOKEN",
            "--stdin",
        ],
        Some(b"team-b-secret"),
    ));
    assert_success(&fixture.run(&["--output", "json", "profile", "load", "team-a"], None));
    assert_success(&fixture.run(&["--output", "json", "profile", "load", "team-b"], None));

    let output = fixture.run(
        &[
            "run",
            "--workspace",
            "team",
            "--",
            "printenv",
            "SHARED_TOKEN",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("duplicate_secret_across_profiles"),
        "stderr: {stderr}"
    );
    assert_no_bytes(&output.stdout, b"team-a-secret");
    assert_no_bytes(&output.stdout, b"team-b-secret");
}

#[test]
fn describe_secret_typo_suggests_the_closest_existing_name() {
    let fixture = DaemonFixture::initialize_and_start();
    assert_success(&fixture.run(
        &["--output", "json", "admin", "unlock", "--password-stdin"],
        Some(PASSWORD),
    ));
    assert_success(&fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "create",
            "base.DATABASE_URL",
            "--stdin",
        ],
        Some(b"typo-suggestion-e2e-secret"),
    ));

    let output = fixture.run(
        &[
            "--output",
            "json",
            "secret",
            "describe",
            "base.DATABASE_URI",
        ],
        None,
    );
    assert_stderr_error_code(&output, "not_found");
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured CLI error");
    assert!(
        error["help"]
            .as_array()
            .expect("help array")
            .iter()
            .any(|item| item
                .as_str()
                .is_some_and(|item| item.contains("did you mean \"DATABASE_URL\"")))
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

fn assert_stderr_error_code(output: &Output, expected: &str) {
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured CLI error");
    assert_eq!(error["code"], expected);
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

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

fn write_private_fixture(path: &Path, bytes: &[u8]) {
    let mut file = envault_platform::create_private_file(path).expect("private fixture");
    file.write_all(bytes).expect("write fixture");
    file.sync_all().expect("sync fixture");
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
