# ADR 0007: Application Service Boundary

## Status

Accepted for Phase 1.

## Context

The approved architecture forbids CLI and TUI clients from accessing storage or cryptographic primitives directly.
Bootstrap initialization still requires orchestration before the daemon exists.
Domain, storage, cryptography, policy, protocol, and presentation concerns need a one-way dependency graph.

## Decision

Add `envault-service` as the application-service boundary.
The service crate depends on domain, cryptography, storage, policy, broker, protocol, and platform crates as needed.
The executable package depends on the service boundary and protocol types, but never on storage or cryptography directly.
Bootstrap initialization runs through this service boundary.
The daemon will own long-lived unlocked service sessions in Phase 3.

## Consequences

CLI, TUI, and future desktop clients share one orchestration layer.
Cryptographic keys never become presentation-layer types.
Phase 1 can test the full encrypted core independently from IPC while preserving the final runtime ownership model.
