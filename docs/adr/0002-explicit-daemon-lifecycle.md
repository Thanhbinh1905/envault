# ADR 0002: Explicit Daemon Lifecycle

## Status

Accepted on 2026-07-30.

## Decision

The CLI does not autostart or poll for the daemon.
`envault start` may spawn `envaultd` and request human authentication.
The packaged desktop application may start its bundled daemon in the locked state without receiving a password.
The service remains active until lock, stop, logout, or shutdown.
Admin and agent grants retain independent TTLs.

## Consequences

All non-bootstrap commands fail loudly while stopped or locked.
Idle runtime must block on operating-system events with near-zero CPU and no idle disk I/O.
