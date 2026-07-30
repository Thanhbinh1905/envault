#![forbid(unsafe_code)]

pub mod client;
pub mod tui;

#[cfg(unix)]
pub mod daemon;

#[cfg(unix)]
mod ipc;
