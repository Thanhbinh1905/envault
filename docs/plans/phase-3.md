# Phase 3 Plan: Daemon and Authenticated IPC

## Objective

Deliver the explicit EnVault service lifecycle, authenticated Unix-socket IPC, daemon-owned VMK state, bounded request execution, admin leases, in-memory agent capability sessions, structured failures, shutdown handling, and idle-runtime guarantees.

## Protocol

`envault-protocol` defines versioned request and response envelopes, daemon lifecycle requests, admin lease requests, capability-session requests, status views, and redacted structured errors.
Every frame uses a four-byte big-endian length prefix and a maximum payload of one MiB.
Sensitive password and token fields zeroize on drop and redact debug output.
The daemon rejects protocol-version mismatch, malformed CBOR, oversized frames, truncated frames, and multiple requests on one connection.

## Bootstrap

`envault start` reads a masked terminal password and never asks for confirmation because enrollment already occurred during `init`.
The CLI spawns the sibling `envaultd` binary with piped standard input and standard output.
It sends one bounded bootstrap request containing the password and waits for one bounded readiness response.
The daemon unlocks and validates the vault before binding the public socket and reporting success.
Failure paths terminate the child and return a structured error without echoing sensitive input.

## Runtime

The daemon holds an exclusive lock file for singleton ownership and safely replaces a stale socket only while holding that lock.
Concurrent `start` commands are serialized by a separate short-lived coordination lock and converge on one unlocked daemon.
Stale recovery refuses to delete symbolic links or non-socket filesystem objects.
The accept loop is event-driven and uses no polling timer.
Each connection is authenticated from operating-system peer credentials, rate limited, bounded by a semaphore, and wrapped in a five-second deadline.
The client also validates the endpoint type, private modes, owner consistency, and server peer UID before transmitting a request.
Mutable vault, lease, capability, and rate-limit state is serialized behind one runtime lock without holding that lock across network awaits.

## Lifecycle

`status` reports stopped, locked, or unlocked state by connecting to the daemon rather than trusting socket existence.
`lock` zeroizes daemon-owned vault and authorization state but keeps the status endpoint alive.
`stop` shuts down the process and removes the socket.
`start` returns success for an already-unlocked daemon and replaces a locked daemon with a freshly authenticated process.
Termination, interrupt, and hangup signals follow the same zeroizing shutdown path.

## Authorization

Admin unlock verifies the master password and issues a peer UID plus operating-system session-bound lease with a monotonic deadline.
Admin status and lock never expose password, VMK, or capability data.
Capability creation requires an active admin lease and an enabled agent principal.
Tokens are random, narrow, expiring, revocable, use bounded, returned once, and stored only as keyed hashes.
Capabilities cannot authorize administration, reveal, plaintext export, policy mutation, or generic execution.
Supplying a capability token to any non-agent operation fails before the privileged handler is reached.

## Test matrix

Protocol tests cover sensitive redaction, zeroization-compatible ownership, version mismatch, frame bounds, malformed length, and request-response round trips.
Runtime tests cover peer acceptance, peer rejection, admin lease bounds and expiry, token hash lookup, revocation, exhaustion, privilege rejection, rate limits, and state clearing on lock.
End-to-end tests initialize a real vault, converge concurrent starts, query status, acquire and expire admin leases, reject agent-token privilege escalation, lock, restart, stop, recover from a stale socket, refuse destructive non-socket recovery, and verify password sentinels do not reach arguments, environment, output, database, socket files, or logs.
Linux idle tests verify process CPU ticks and daemon I/O counters do not increase while no client is active.
Malformed local-client tests verify oversized, truncated, version-mismatched, and random frames cannot reveal secret data or crash the daemon.

## Exit gate

All local verification, property tests, end-to-end lifecycle tests, malformed-client tests, dependency policy, vulnerability audit, packaging, Linux and macOS CI, and Windows compile checks pass.
Idle CPU remains at zero scheduler ticks during the measured quiet interval and idle disk counters do not increase.
Lock, stop, signal shutdown, and daemon crash recovery leave no usable VMK, admin lease, raw token, or live socket.
The Phase 3 review has no unresolved lifecycle, IPC, authentication, concurrency, zeroization, portability, or hostile-client finding.
