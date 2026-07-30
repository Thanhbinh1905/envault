#![forbid(unsafe_code)]

pub mod client;

#[cfg(unix)]
pub mod daemon;

#[cfg(unix)]
mod ipc;
