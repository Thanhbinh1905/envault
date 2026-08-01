#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match envault::tui::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("envaultui: {error}");
            ExitCode::FAILURE
        }
    }
}
