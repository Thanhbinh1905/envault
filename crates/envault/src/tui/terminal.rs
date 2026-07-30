use std::io::{self, Stdout};

use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

/// Owns the terminal's raw-mode and alternate-screen state and restores the
/// terminal on every exit path, including an early return before rendering
/// begins.
#[allow(missing_debug_implementations)]
pub struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    restored: bool,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error);
        }
        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(terminal) => Ok(Self {
                terminal,
                restored: false,
            }),
            Err(error) => {
                let _ = execute!(io::stdout(), LeaveAlternateScreen);
                let _ = disable_raw_mode();
                Err(error)
            }
        }
    }

    pub fn terminal(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }

    fn restore(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Installs a panic hook that restores the terminal before the default hook
/// prints the panic, so a panic during rendering never leaves the terminal
/// stuck in raw mode or the alternate screen. Must run before
/// [`TerminalGuard::enter`].
pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
        default_hook(panic_info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TerminalGuard::enter` requires a real terminal on stdout for raw mode
    /// and the alternate screen to mean anything. Under the test harness,
    /// stdout is ordinarily not a tty, so entry must fail cleanly rather than
    /// leave stdout half-configured; on the rare occasion this test runs
    /// attached to a real terminal, entry succeeds and `Drop` must restore it
    /// without panicking. Either branch is exercised here; which one runs
    /// depends on the environment, which is inherent to testing a real
    /// terminal without a pseudo-terminal harness (see the real-binary
    /// end-to-end coverage gap noted in docs/plans/phase-6.md).
    #[test]
    fn enter_either_fails_cleanly_or_restores_on_drop() {
        match TerminalGuard::enter() {
            Err(_) => {}
            Ok(guard) => drop(guard),
        }
    }

    /// The panic hook must restore the terminal and then let the panic keep
    /// propagating; it must never swallow the panic or abort the process.
    /// This does not observe raw-mode/alternate-screen state directly (there
    /// is no portable way to do that in a unit test without a real
    /// terminal), only that the hook composes correctly with unwinding.
    #[test]
    fn panic_hook_restores_then_lets_the_panic_propagate() {
        install_panic_hook();
        let result = std::panic::catch_unwind(|| {
            panic!("simulated render-loop panic for terminal-restoration test");
        });
        assert!(
            result.is_err(),
            "the panic must still propagate to the caller"
        );
    }
}
