# ADR 0005: Encrypted Portability Packages

## Status

Accepted on 2026-07-30.

## Decision

Profile and workspace exports use versioned encrypted CBOR packages.
A random transfer key protects the package and is wrapped by a transfer-password Argon2id slot or an age recipient slot.
Secret ciphertext remains unchanged when possible while DEKs are re-wrapped.
Import verifies integrity, builds a preview plan, resolves an explicit conflict strategy, and commits in one SQLite transaction.

## Consequences

Packages never contain the source VMK, session state, capability tokens, audit history, or plaintext secrets.
Tamper, wrong-password, unsupported-version, and interruption failures must not create partial mutations.

