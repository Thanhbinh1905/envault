#![forbid(unsafe_code)]

use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

fn run_init(data_home: &std::path::Path, password: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_envault"))
        .args(["--output", "json", "init", "--password-stdin"])
        .env("XDG_DATA_HOME", data_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn envault");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(password)
        .expect("write password");
    child.wait_with_output().expect("wait for envault")
}

#[test]
fn init_accepts_only_stdin_and_never_echoes_password() {
    let directory = tempfile::tempdir().expect("tempdir");
    let password = b"cli-initialization-sentinel-password";
    let output = run_init(directory.path(), password);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output
            .stdout
            .windows(password.len())
            .any(|window| window == password)
    );
    assert!(
        !output
            .stderr
            .windows(password.len())
            .any(|window| window == password)
    );
    let database = directory.path().join("envault/vault.db");
    assert!(database.is_file());
    let database_bytes = std::fs::read(database).expect("read database");
    assert!(
        !database_bytes
            .windows(password.len())
            .any(|window| window == password)
    );

    let second = run_init(directory.path(), password);
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("vault_already_initialized"));
}

#[test]
fn plaintext_value_flags_are_rejected_by_clap() {
    let output = Command::new(env!("CARGO_BIN_EXE_envault"))
        .args(["secret", "create", "EXAMPLE", "--value", "plaintext"])
        .output()
        .expect("run envault");
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("phase_not_implemented"));
}
