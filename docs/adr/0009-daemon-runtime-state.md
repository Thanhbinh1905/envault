# ADR 0009: Daemon Runtime State and Authentication

## Status

Accepted for Phase 3.

## Context

EnVault must keep the unlocked VMK inside one event-driven daemon, authenticate local clients without trusting caller-provided identity, support explicit lifecycle commands, and issue revocable agent capabilities without retaining raw tokens.
The runtime must remain portable across Linux and macOS while Windows named pipes remain a Phase 7 adapter.

## Decision

`envault start` is the only executable path that spawns `envaultd`.
The parent sends the master password through an anonymous standard-input pipe using a bounded sensitive protocol frame and waits for one readiness frame from the child.
The password is never passed through arguments, environment variables, files, logs, or shell-visible process metadata.

The daemon owns the unlocked `VaultSession`, listens on one Unix socket, blocks on operating-system events while idle, and handles one bounded request per accepted connection.
Every request has a five-second I/O deadline and global concurrency is bounded by a semaphore.
The socket directory is mode `0700`, the socket and lock files are mode `0600`, and peer UID is obtained from the operating system and matched to the runtime-directory owner.
Before sending any request, the client rejects symbolic links, non-socket endpoints, non-private modes, owner mismatch, and a server peer UID that differs from the socket-directory owner.
Filesystem permission changes use no-follow operations, stale recovery removes only an actual socket, and cleanup removes the path only when its device and inode still match the bound socket.

`lock` drops the vault session, admin leases, capability sessions, and token-hash key while leaving the daemon available for status and stop.
`stop`, termination signals, hangup, and process exit drop the same state and remove the socket.
Starting a locked daemon stops that process and launches a fresh authenticated daemon instead of sending the master password over the filesystem socket.
A short-lived private start lock serializes concurrent CLI transitions, while the daemon lifetime lock remains held until shutdown.

Admin leases bind the authenticated peer UID and operating-system session identifier to a monotonic deadline.
An unrelated same-user process session cannot reuse or invalidate the lease.
The daemon verifies `admin unlock` by opening and authenticating the vault independently, then drops the verification session before issuing a lease.
Lease duration defaults to five minutes and is bounded to one through thirty minutes.

Agent capability tokens contain 32 random bytes and are returned only once.
The daemon stores only a VMK-independent keyed digest of each token in memory.
Capabilities bind a principal, one agent-safe action, one typed resource selector, an approval identifier, an expiry, a nonce, and a bounded request count.
Admin handlers never accept capability tokens as authorization.
Any request carrying an agent capability is rejected before dispatch unless the operation is explicitly agent-callable.
Connection and authentication limits apply both per operating-system session and globally, and their state is bounded in memory.

## Consequences

Stopping or locking the daemon invalidates every admin and agent authorization immediately.
The daemon can later expose policy-filtered discovery and broker operations without adding a plaintext secret-reading protocol.
Protocol and bootstrap decoders remain hostile-input boundaries and require fuzzing and malformed-client tests.

## Addendum (2026-07-31): admin lease rescoped to uid, agent capabilities removed

The admin lease is now scoped to the authenticated peer `uid` alone, not `(uid, session_id)`: unlocking admin from any terminal or process running as that user covers every other process of that same user, reducing friction when an agent runs in the same terminal session as the human. `lock` and `stop` still drop the lease immediately.
Agent capability tokens, `CapabilitySession`, and the `Principal` concept described above were removed entirely; there is no token-hash key, capability digest, nonce, or approval identity in daemon memory. Agent metadata discovery is now gated by the loaded set (`activate_on_start`) and agent-initiated HTTP actions by the `secret_http_access` record on the target secret, both checked by same-uid trust alone. See ADR 0004's and ADR 0010's addenda for the corresponding protocol and broker changes.
