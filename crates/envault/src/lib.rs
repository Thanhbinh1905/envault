#![forbid(unsafe_code)]

pub mod client;
pub mod tui;

#[cfg(unix)]
pub mod daemon;

mod ipc;
