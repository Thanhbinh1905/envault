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
