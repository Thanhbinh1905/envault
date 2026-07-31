# Phase 7 Plan: Windows Runtime and OS-Native Convenience Unlock

## Objective

Deliver a Windows named-pipe IPC runtime for `envaultd`, `envault`, and `envault-tui` with peer-authentication and filesystem-hardening guarantees equivalent in intent to the existing Unix implementation, backed by real Windows runtime CI rather than a compile-only check.
Deliver an optional, explicitly opt-in OS-native credential-store convenience unlock as the phase's desktop-adapter surface.
A graphical desktop application is explicitly out of scope; it is deferred to a future phase that will make its own framework and distribution decisions.

## Ownership

`envault-platform` replaces its current `cfg(not(unix))` fallbacks, which compile but provide no real hardening, with genuine Windows implementations of private file and directory creation, path validation, and permission hardening using Windows ACLs.
`envault` owns the Windows named-pipe client connect path behind the same conditional-compilation seam that already isolates Unix socket types; the daemon-side listener remains a deferred follow-up (see "Windows named-pipe IPC transport" below).
`envault-protocol`'s length-prefixed CBOR framing is transport-agnostic and requires no change; it already operates over any reader and writer.
`envault-service` gains one new bounded capability: reading and writing an opt-in OS-keystore-backed unlock credential, gated by the same admin-lease and explicit-acknowledgement discipline the plaintext export escape hatch established in Phase 5.
CI gains a Windows runtime job that runs the workspace test suite on `windows-latest`, alongside the existing Windows compile check.
The CLI and terminal UI require no change; both are IPC-only and already unaware of the underlying transport.

## Windows named-pipe IPC transport

The daemon listens on a named pipe instead of a Unix domain socket when compiled for Windows; the client connects to the same named pipe path convention.
Both ends read and write through the existing length-prefixed CBOR framing unchanged, since framing operates on any `Read` and `Write` implementation rather than on socket-specific types.
The pipe is created with an explicit security descriptor restricting access to the owning user, mirroring the Unix socket's directory-permission-based restriction rather than relying on default pipe ACLs.
Connection handling preserves the existing one-request-per-connection contract; a client that sends a second request on an already-answered connection observes the connection close, exactly as the Unix transport already behaves.
Constructing the named-pipe security descriptor requires raw Win32 FFI with no adequate safe published wrapper; ADR 0013 grants one narrowly scoped `unsafe`-code exception for this, isolated to a new, dedicated, Windows-only crate (`envault-windows-ffi`) rather than relaxing the no-unsafe-code policy of any existing crate.
The client side of this transport is implemented: it connects to a named pipe and authenticates the server's peer security identifier before trusting anything it sends.
The daemon-side async named-pipe listener and accept loop is deferred to a follow-up pass; `daemon.rs` remains Unix-only rather than being restructured blind with no Windows runtime available to exercise the result, and `envaultd` continues to report Windows runtime support as unavailable until that listener exists.
The client transport also has a known, tracked gap: it does not yet enforce a read/write timeout equivalent to the Unix socket's `set_read_timeout`/`set_write_timeout`, since a `File`-wrapped named-pipe handle has no synchronous timeout primitive in `std`.

## Windows peer authentication

Unix peer authentication compares the connecting socket's credential-derived UID against the runtime directory owner.
Windows named pipes have no equivalent kernel-supplied UID; peer identity is instead derived by resolving the connecting client's process token and comparing its owning security identifier against the daemon's own security identifier before any request is dispatched.
A mismatched or unresolvable client identity is rejected before any operation reaches the application service, with the same fail-closed posture the Unix path already requires.
This is a materially different security primitive from `SO_PEERCRED`, not a drop-in substitution, and is treated as such in the implementation and its tests rather than assumed equivalent by construction.
Resolving a named pipe's connected client process and its token's security identifier requires `GetNamedPipeClientProcessId`, `OpenProcessToken`, and `GetTokenInformation`, each raw Win32 FFI with no adequate safe published wrapper.
ADR 0013 resolves this the same way as the pipe's security descriptor: the same dedicated, isolated, safety-commented `envault-windows-ffi` crate, exposing only safe function signatures to every caller, with no change to any existing crate's `forbid(unsafe_code)`.
Because this sandbox has no Windows runtime, this code cannot be exercised end-to-end until the Windows runtime CI job runs it; the review gate for this phase treats that first green Windows runtime CI run as required evidence, not merely a nice-to-have, before treating peer authentication as trustworthy.

## Windows filesystem and permission hardening

Path validation rejects reparse points (the Windows analog of symbolic links) on every component between the stable parent and the target, mirroring the no-follow discipline the Unix implementation already applies, and same-file identity after creation, opening, or publication is verified using a volume-serial-number and file-index pair read via `GetFileInformationByHandle` through `envault-windows-ffi`, the Unix `(dev, ino)` pair's Windows equivalent; an earlier pass had instead relied on `std`'s `file_index`/`volume_serial_number`, which remain behind the unstable `windows_by_handle` feature and do not compile on stable Rust, so this was corrected rather than left broken.
Every platform test that currently exercises Unix symlink-rejection and same-file-identity behavior gains a Windows-native counterpart.
Restricting a private file or directory's access control list to the owning user's security identifier uses the same isolated `envault-windows-ffi` crate ADR 0013 establishes for the named-pipe security descriptor and peer-token comparison, rather than a second, separately reviewed exception.

## Windows runtime CI

A new CI job runs on `windows-latest` and executes `cargo nextest run --workspace`, exercising real daemon startup, named-pipe IPC round trips, admin lease lifecycle, and portability workflows natively on Windows rather than only checking that the workspace compiles.
The existing Windows compile check is retained unchanged as a fast pre-check; the new runtime job runs alongside it rather than replacing it.
`cargo xwin` cross-compilation checking remains a local, developer-invoked verification step outside CI, unchanged from prior phases.

## OS-native convenience unlock

An optional convenience unlock stores the vault's master password in the operating system's native credential store, specifically the platform keychain, credential manager, or Secret Service, rather than requiring the human to type it on every `start` invocation.
This is opt-in per profile, requires an explicit acknowledgement naming the change in security posture at the moment it is enabled, and is independently revocable without affecting the vault's actual encryption.
Enabling this measurably changes the vault's practical unlock guarantee from "requires a memorized secret" to "requires access to the current OS session," and the CLI's acknowledgement text says so explicitly rather than presenting this as a value-neutral convenience.
The stored credential is read only by the `start` command's own unlock path; no other command, including the terminal UI, reads or writes it.
Disabling convenience unlock for a profile removes the stored credential from the OS store and does not affect any already-issued admin lease.
ADR 0014 records this as a deliberate, bounded, opt-in trade of confidentiality-at-rest for convenience rather than a silent default.

## Explicitly out of scope

A graphical desktop application, system tray integration, and any packaging or distribution mechanism for one are out of scope for Phase 7 and are deferred to a future phase that will make an explicit framework and distribution decision informed by product and infrastructure constraints not yet settled.
Agent principal management, grant issuance and revocation, and policy authoring in the terminal UI, deferred in Phase 6, remain deferred.

## Test matrix

Windows platform tests cover private file and directory ACL restriction, reparse-point rejection on every path component, and permission-hardening parity with the Unix test matrix.
Windows IPC tests cover named-pipe connection lifecycle, the one-request-per-connection contract, peer-identity mismatch rejection, and framing round trips identical to the existing Unix IPC test matrix.
Windows daemon lifecycle tests cover start, lock, stop, and admin lease unlock and expiry natively on `windows-latest`.
Convenience-unlock tests cover opt-in enablement with explicit acknowledgement text, credential storage and retrieval round trips, independent revocation, and that no command other than `start` reads the stored credential.
Cross-platform regression tests confirm the CBOR framing and application-service behavior are identical on Unix and Windows for the same operation sequence.

## Exit gate

All local verification, the new Windows runtime CI job, the existing Windows compile check, Linux and macOS CI, dependency policy, vulnerability audit, and packaging pass.
Windows peer authentication and filesystem hardening provide guarantees equivalent in intent to the Unix implementation, verified by a parallel Windows-native test matrix rather than assumed from compilation success alone.
Convenience unlock is opt-in, explicitly acknowledged, independently revocable, and read only by the `start` command.
The Phase 7 review has no unresolved Windows-transport, peer-authentication, filesystem-hardening, or convenience-unlock-disclosure finding.
