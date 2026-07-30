//! Interactive terminal dashboard for scopes, profiles, secret metadata, and
//! daemon status. See docs/plans/phase-6.md and ADR 0012: this module never
//! requests or renders a decrypted secret value.

mod app;
mod terminal;
mod view;

use std::io::{self, IsTerminal};
use std::time::Duration;

use crossterm::event::{self, Event, KeyEventKind};

pub use app::{App, DaemonClient, InputKind, Mode, PendingAction, RealClient, Screen};
pub use terminal::TerminalGuard;

const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Runs the terminal UI to completion. Returns a non-zero process outcome via
/// the `Result` when standard output is not an interactive terminal, since
/// rendering would otherwise corrupt a pipe or redirected file.
pub fn run() -> io::Result<()> {
    if !io::stdout().is_terminal() {
        return Err(io::Error::other(
            "envault-tui requires an interactive terminal on standard output",
        ));
    }
    terminal::install_panic_hook();
    let mut guard = TerminalGuard::enter()?;
    let mut app = App::new(RealClient);
    app.refresh_dashboard();
    run_event_loop(&mut guard, &mut app)
}

fn run_event_loop<C: DaemonClient>(guard: &mut TerminalGuard, app: &mut App<C>) -> io::Result<()> {
    while !app.should_quit() {
        guard.terminal().draw(|frame| view::draw(frame, app))?;
        if event::poll(POLL_INTERVAL)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            app.on_key(key.code);
        }
    }
    Ok(())
}
