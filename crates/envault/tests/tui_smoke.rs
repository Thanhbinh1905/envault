#![forbid(unsafe_code)]
#![cfg(unix)]

//! Real-binary coverage for `envault-tui`.
//!
//! A full interactive walkthrough (spawn a real daemon, drive `envault-tui`
//! over a pseudo-terminal, send keystrokes, scan the transcript for secret or
//! password leakage) is deferred: no pseudo-terminal crate is a dependency
//! anywhere in this workspace yet, and adding one plus a robust,
//! non-flaky PTY harness in the same pass that built this smoke test would
//! risk exactly the kind of environment-dependent flakiness this project
//! does not accept. This test instead exercises the one thing that *is*
//! safely testable against the real binary in a headless environment: the
//! non-interactive-stdout guard in `envault::tui::run` never attempts to
//! render and never leaks anything to stdout on that path.

use std::process::{Command, Stdio};

#[test]
fn tui_refuses_to_render_without_an_interactive_terminal() {
    let output = Command::new(env!("CARGO_BIN_EXE_envault-tui"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn envault-tui");

    assert!(
        !output.status.success(),
        "envault-tui must not report success when it never rendered"
    );
    assert!(
        output.stdout.is_empty(),
        "envault-tui must write nothing to stdout when refusing to render"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive terminal"),
        "expected the interactive-terminal guard message, got: {stderr}"
    );
}
