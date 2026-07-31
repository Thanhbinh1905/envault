#![forbid(unsafe_code)]

pub mod client;
pub mod tui;

#[cfg(any(unix, windows))]
pub mod daemon;

mod ipc;
