# ADR 0013: Windows Named-Pipe Transport and Peer Authentication

## Status

Accepted on 2026-07-31.

## Context

ADR 0003 authenticates IPC using operating-system-supplied peer identity: the daemon reads the connecting Unix socket's credential and compares its UID against the runtime directory owner.
Windows has no Unix domain socket and no `SO_PEERCRED` equivalent; the standard interprocess transport is a named pipe, and the standard way to identify a connected client is to resolve its process token rather than a credential attached to the socket itself.
The length-prefixed CBOR framing introduced in ADR 0003 already operates on any reader and writer, so the transport substitution does not require any change to request or reply encoding, versioning, or size bounds.

## Decision

On Windows, the daemon listens on a named pipe created with an explicit security descriptor restricting access to the owning user's security identifier, and the client connects to the same named pipe.
Peer authentication resolves the connecting client's process token and compares its owning security identifier against the daemon's own security identifier before any request reaches the application service.
A mismatched or unresolvable identity is rejected with the same fail-closed posture as a Unix UID mismatch.
The existing one-request-per-connection contract is preserved unchanged.
Every Unix-specific test that exercises peer-identity rejection, permission hardening, or symbolic-link rejection gains a Windows-native counterpart exercising the named-pipe security descriptor, process-token comparison, and reparse-point rejection respectively, rather than being assumed equivalent from shared framing code.

## Consequences

The transport and peer-authentication layers are platform-specific and separately tested, while the protocol, application service, and every higher layer remain unchanged and shared.
Windows peer authentication is a materially different security primitive than `SO_PEERCRED`; equivalence is a design goal enforced by a parallel test matrix, not an assumption.
CI gains a Windows runtime job that exercises real daemon startup and IPC round trips on `windows-latest`, in addition to the existing Windows compile check.

**Implementation status**: `envault-windows-ffi` implements the owner-only security descriptor, named-pipe instance creation, named-pipe client connect, and peer-SID resolution and comparison for both the client-connecting-to-server and server-connecting-to-client directions.
`envault-platform`'s Windows private-path hardening now calls into it to restrict access control lists on private files, directories, and the daemon's transport endpoint, replacing what was previously verification without restriction; its reparse-point rejection and same-file-identity checks (via `GetFileInformationByHandle`, not the unstable `windows_by_handle` std feature an earlier pass mistakenly relied on) need no `unsafe` code and remain outside this crate.
`crates/envault`'s client transport connects to a named pipe and authenticates the server's peer SID before trusting anything it sends.
Deferred: the daemon-side async named-pipe listener and accept loop (`daemon.rs` remains Unix-only), since restructuring its full accept loop without any way to exercise the result on real Windows runtime in a Linux-only development sandbox was judged too risky to do blind; and a client-side read/write timeout equivalent to the Unix socket's `set_read_timeout`/`set_write_timeout`, since a `File`-wrapped named-pipe handle has no synchronous timeout primitive in `std` (a watchdog thread or overlapped I/O would be needed). Both are tracked follow-ups, not silently dropped scope.

## Unsafe-code policy resolution

This workspace's `#![forbid(unsafe_code)]` has always governed code written in this workspace, not the transitive dependency graph: `rusqlite` (bundled SQLite C library), `chacha20poly1305`, `ring` via `rustls`, `getrandom`, `nix`, and `age` all contain `unsafe` internally today, and none of that has ever been treated as a violation of the policy, because the invariant is "we do not write unsafe code," not "no unsafe code exists anywhere in the dependency tree."
The named-pipe security descriptor and process-token SID comparison this ADR requires have no safe published crate that fully covers them, so this ADR grants one narrowly scoped exception, structured to respect a hard Rust compiler rule: a `forbid`-level lint can never be overridden by a nested `allow`, in the same or a child scope, so isolating an exception inside an existing `forbid(unsafe_code)` crate is not mechanically possible.
The exception is therefore a new, dedicated crate, `envault-windows-ffi`, added to the workspace and compiled only on Windows targets.
This crate does not opt into `[lints] workspace = true` and does not write `#![forbid(unsafe_code)]`; instead its crate root uses `#![deny(unsafe_code)]`, with a local `#[allow(unsafe_code)]` on each specific function that contains an `unsafe` block, since `deny`, unlike `forbid`, can be locally overridden.
It depends only on `windows-sys`, the official Microsoft-maintained low-level Win32 binding crate, using the minimal feature set needed (named pipes, security descriptors, process and token queries), and every `unsafe` block carries a safety comment stating the invariant it relies on (buffer sizes, handle validity, lifetime of borrowed data) per standard Rust unsafe-code documentation convention.
This crate exposes only safe function signatures to its callers; no `unsafe` keyword appears anywhere outside it.
`envault-platform` depends on `envault-windows-ffi` only under `#[cfg(windows)]` and re-exports its safe wrappers; `envault-platform`'s own `forbid(unsafe_code)` is untouched because it contains no `unsafe` itself, and every other crate in the workspace is completely unaffected.
This exception is scoped to Windows peer authentication and named-pipe security descriptor construction specifically; it is not a general license to add unsafe code elsewhere, and any future use of this crate for an unrelated purpose should prompt a fresh review of whether it still belongs there.
