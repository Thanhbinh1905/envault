# ADR 0003: Authenticated Local IPC

## Status

Accepted on 2026-07-30.

## Decision

Linux and macOS use an authenticated Unix socket.
Messages use versioned CBOR with a four-byte length prefix and a one MiB frame limit.
Peer identity comes from the operating system, not client-provided fields.
The socket directory uses mode `0700`, and socket and sensitive files use mode `0600`.

## Consequences

Protocol decoding is an untrusted-input boundary and requires fuzzing.
Windows named pipes are designed as a platform adapter and implemented in Phase 7.

