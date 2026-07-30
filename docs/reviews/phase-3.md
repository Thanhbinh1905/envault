# Phase 3 Review

## Scope

Phase 3 delivers the explicit `envaultd` lifecycle, authenticated Unix-socket IPC, daemon-owned unlocked vault state, bounded admin leases, in-memory agent capability sessions, hostile-client handling, shutdown cleanup, and idle-runtime guarantees.
Policy-filtered discovery and broker execution remain assigned to Phase 4, portability packages to Phase 5, TUI workflows to Phase 6, and Windows runtime support to Phase 7.

## Plan review

The implementation follows `docs/plans/phase-3.md` and ADR 0009.
`envault-protocol` owns versioned CBOR envelopes, one-MiB frame bounds, structured replies and errors, sensitive protocol fields, and the explicit operation set.
`envault-platform` owns private runtime objects, no-follow permission changes, reusable private lock files, core-dump suppression, and Linux dumpability hardening.
The `envault` library owns client transport, start coordination, daemon bootstrap, runtime state, authorization dispatch, request deadlines, and socket cleanup.
The executable package exposes `envault`, `envaultd`, and the reserved `envault-tui` binary without allowing the CLI or TUI to reach storage or cryptography directly.

## Implementation review

`envault start` is the only public command that spawns the sibling `envaultd` executable.
The parent sends the password through an anonymous standard-input pipe in one bounded zeroizing frame and verifies the readiness response version, request identifier, unlocked state, and child process identifier.
A short-lived private start lock serializes concurrent starts, while the daemon lifetime lock prevents multiple active servers and permits safe stale-socket recovery.
The daemon unlocks the vault before publishing readiness and retains the `VaultSession` until explicit lock, stop, signal shutdown, logout hangup, or process exit.
Lock clears the vault session, admin lease, capability map, and keyed token-hash secret while leaving status and stop available.
The Unix runtime directory is mode `0700`, and the socket plus coordination and daemon lock files are mode `0600`.
Final path components reject symbolic links, sensitive regular files reject hard links, permission changes use no-follow operations, and stale recovery removes only an actual socket.
Socket cleanup compares device and inode before unlinking so it cannot delete a replacement object.
The client validates the endpoint type, mode, owner consistency, link count, and operating-system server peer UID before sending any request.
The daemon validates client UID and PID from operating-system credentials, derives the client operating-system session identifier, and rejects peers outside the runtime owner boundary.
The accept loop is event-driven, bounds active connections to sixty-four, permits one request per connection, and applies both per-session and global connection and authentication rate limits.
Rate-limit maps have a fixed upper bound and discard stale windows before admitting a new operating-system session.
Read and execution share a five-second deadline, and a timed-out request receives only a short bounded error-response grace interval.
Argon2 verification runs on the blocking pool under a single authentication semaphore whose permit remains held even if the network request times out.
Admin leases are bounded to one through thirty minutes and bind UID plus operating-system session to a monotonic deadline.
Capability sessions require an active admin lease, an enabled agent principal, an existing typed resource, an agent-safe action, a maximum one-hour lifetime, and at most one thousand uses.
Each capability token contains thirty-two random bytes, is returned once, and is represented in daemon memory only by a keyed digest.
Expired capabilities are removed before capacity checks, revoked capabilities are removed immediately, and lock or stop invalidates the token-hash key and every session.
Any capability-bearing request fails before dispatch unless the operation is explicitly agent-callable, so a token cannot fall back to ambient service or admin authorization.
Stopped and locked states return stable structured errors with request identifiers, retryability, and direct `envault start` guidance in human, JSON, and TOON workflows.

## Test evidence

Protocol tests cover exact versioning, structured round trips, redacted sensitive debug output, constant-work equality for equal-length password confirmation, malformed lengths, decoding failure, and bounded encoding without retaining an unzeroized intermediate payload.
Platform tests cover directory, private file, reusable lock-file modes, final-component symbolic-link rejection, and hard-link rejection.
Runtime unit tests cover owner peer acceptance, foreign UID rejection, admin lease session binding and expiry, lock zeroization, per-session and global authentication limits, bounded rate state, token hashing, privilege rejection, exhaustion, revocation, expiry, and inode-safe socket cleanup.
End-to-end tests run the real binaries in isolated XDG directories and cover concurrent start convergence, already-running start without a password prompt, explicit lock and restart, admin unlock and lock, locked-state failures, stop, stale-socket recovery, non-destructive non-socket refusal, hangup cleanup, crash recovery, and private runtime modes.
Hostile-client tests cover oversized frames, truncated frames, random CBOR, protocol mismatch, stalled requests, multiple requests on one connection, and daemon survival afterward.
Capability E2E verifies that privileged grants are rejected, raw tokens are absent from persistent files, token inspection is bounded, token-bearing service and admin operations are denied while the ambient lease remains active, and revocation takes effect immediately.
Linux runtime tests verify no scheduler tick change and no persistent I/O change during an idle interval.
Forensic checks verify the password sentinel is absent from arguments, environment, captured output, database, runtime objects, and the persistent test tree.
`cargo xtask verify`, workspace Clippy with warnings denied, workspace tests, doc tests, `cargo nextest run --workspace`, `cargo deny check`, `cargo audit`, workspace package generation, release binary builds, and `git diff --check` pass locally.
The local nextest run passes all sixty-six tests.
A clean release-binary workflow passes initialization, start, status, admin lease, lock, authenticated restart, stop, private-mode inspection, daemon-lock synchronization, and post-run plaintext scanning.
Targeted `envault-platform` and `envault-protocol` cross-checks pass locally for Windows MSVC and macOS targets.
Native full-workspace macOS and Windows verification remains delegated to protected GitHub CI runners because bundled SQLite requires each target's native toolchain.

## Security review

Password and capability bytes zeroize at protocol ownership boundaries, and every serialized IPC buffer containing sensitive material is wrapped in zeroizing storage.
No password is passed through arguments, environment variables, filesystem paths, logs, or shell-visible daemon metadata.
The daemon disables core dumps on Unix and disables Linux process dumpability before reading bootstrap input.
Filesystem checks fail closed on symlink, hard-link, mode, owner, type, device, or inode inconsistency.
Server and client peer checks prevent cross-user IPC impersonation, while capability and login-session boundaries constrain same-user callers according to the accepted threat model.
Admin authentication is rate limited before Argon2 execution but validates lease bounds before consuming an authentication attempt.
The token-bearing dispatch rule prevents confused-deputy fallback from agent authentication into service or admin handlers.
Malformed, slow, excessive, and repeated local requests are bounded by frame size, deadlines, semaphores, global limits, per-session limits, and fixed state capacity.
Daemon shutdown clears authorization and key-bearing state before the socket path is removed.

## Review findings resolved

Concurrent starts now use a dedicated coordination lock and converge on one daemon instead of racing through stop, lock wait, and duplicate spawn.
The start client now validates the child PID in the readiness frame and retries only bounded transient transition failures.
IPC authentication is now bidirectional at the operating-system UID boundary instead of validating only the client at the daemon.
Rate limiting now has global bounds and a fixed session-map capacity instead of being bypassable through unbounded new session identifiers.
Capability-bearing requests now fail before non-agent handlers instead of silently ignoring the token and using ambient authority.
Protocol encoding now limits memory while serializing and zeroizes its intermediate payload instead of checking only after an unbounded plaintext allocation.
Revocation and expiry now release capability capacity immediately.
Stale recovery now refuses non-socket objects, and shutdown cleanup no longer unlinks a path whose inode has been replaced.
Private runtime operations now reject symbolic links and hard links and use no-follow permission changes.
Request processing and normal response writing now share one deadline instead of allowing two full consecutive timeout windows.
Locked lifecycle and admin-status calls now return `envault_locked` with actionable guidance instead of reporting success or an ambiguous inactive lease.
Native cross-target checking exposed and resolved the macOS filesystem-mode width difference.

## Decision

Phase 3 is approved when the final clean verification run and all protected GitHub quality, Linux, macOS, and Windows checks pass for this review change.
No unresolved Phase 3 lifecycle, IPC, authentication, authorization, concurrency, zeroization, filesystem, portability, hostile-client, or idle-runtime finding remains in the reviewed implementation.
