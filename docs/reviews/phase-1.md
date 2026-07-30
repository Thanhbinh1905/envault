# Phase 1 Review

## Scope

Phase 1 delivers the encrypted vault core, safe bootstrap enrollment, immutable secret versions, encrypted profile and secret metadata, private storage, backup, recovery validation, and forensic leak checks.
Daemon-owned lifecycle and public profile or secret commands remain fail-closed until authenticated IPC is implemented in Phase 3.
This staging follows ADR 0007 and prevents a temporary direct-storage CLI path from becoming part of the public architecture.

## Plan review

The implementation follows the Phase 1 ownership split documented in `docs/plans/phase-1.md`.
`envault-core` owns identifiers, views, validation, and generator semantics.
`envault-crypto` owns Argon2id, random material, XChaCha20-Poly1305, key wrapping, keyed lookup digests, and zeroizing buffers.
`envault-store` owns schema migration, transactions, semantic row invariants, WAL checkpoints, SQLite integrity checks, and online backup.
`envault-platform` owns private directory and file permissions.
`envault-service` is the only application boundary that composes storage and cryptography.
The executable package depends on the service boundary and does not depend directly on storage or cryptography.

## Implementation review

Bootstrap initialization accepts a masked terminal password or explicitly piped standard input and exposes no plaintext argument or environment input option.
Host-calibrated Argon2id derives a KEK from a random salt and bounded persisted parameters.
The KEK wraps a random VMK, and each secret version uses a separate random DEK.
Metadata and values use domain-separated AAD that binds vault, entity, scope, version, field, and algorithm identity as applicable.
The SQLite schema stores encrypted names and descriptions, keyed lookup digests, wrapped keys, ciphertext, and redacted generator metadata.
Vault and root-scope cardinality, exactly-one startup profile, mutation row counts, secret-version identity, and consecutive version numbers fail closed.
Profile and secret create, show, list, update, rename, delete, activation, generation, and immutable value-version workflows are implemented through `envault-service`.
Initialization and backup publish with no-replace hard links from private temporary files in the destination directory.
Database and backup files are private from first creation, and unlock repairs a loosened Unix database mode before reading.
The schema migration accepts the empty Phase 0 schema and rejects an occupied incompatible schema because its old ciphertext layout cannot be converted safely.

## Test evidence

Unit tests cover password derivation, hostile KDF bounds, key redaction, AEAD AAD binding, key wrapping, ciphertext encoding, random nonce uniqueness, validation, and generators.
Storage tests cover migration, atomic initialization, singleton invariants, mutation rollback, version identity, schema confidentiality, integrity, and backup recovery.
Service tests cover initialization, authentication failure, profile CRUD, stable rename identity, startup activation, secret CRUD, immutable version history, generators, backup recovery, private permissions, lookup tamper, metadata tamper, and ciphertext tamper.
The forensic suite scans database, WAL, shared-memory, backup, temporary workspace, captured standard output, and captured standard error for unique plaintext sentinels.
The real CLI smoke test verifies JSON initialization, inactive status, directory mode `0700`, database mode `0600`, and absence of the bootstrap password from persistent and captured artifacts.
`cargo xtask verify`, workspace clippy with warnings denied, workspace tests, doc tests, `cargo deny check`, `cargo audit`, package generation, and `git diff --check` pass locally.
Native Linux verification passes locally.
Native macOS and Windows verification is delegated to the protected-branch CI runners because bundled SQLite and BLAKE3 require each target's native C toolchain.

## Security review

No plaintext value is accepted through an argument, positional parameter, or application-read environment variable.
Secret inputs and keys zeroize on drop, and debug output is redacted.
Names and descriptions are encrypted, while equality lookup uses domain-separated keyed BLAKE3 digests.
Cryptographic integrity validation recomputes lookup digests, checks semantic ownership and version history, unwraps every DEK, and authenticates every stored value without retaining plaintext.
Corrupt metadata, lookup digests, wrapped keys, ciphertext, singleton state, or version structure fail closed.
Temporary database artifacts are private and cleaned after failed initialization or backup.
The public CLI still denies lifecycle, profile, and secret operations while the daemon is unavailable, so no direct-storage compatibility path bypasses future IPC policy.

## Review findings resolved

The application service was split so generator, AAD, serialization, and publication helpers no longer inflate the main workflow module.
SQLite reads no longer select an arbitrary vault or root scope when cardinality is corrupt.
Mutations now require exactly the expected affected rows and roll back on missing targets.
Deep integrity checks now authenticate secret ciphertext instead of relying only on SQLite `quick_check`.
Unlock now validates lookup digests and repairs database permissions before opening the store.
Successful no-replace publication no longer reports false failure if removal of the private temporary hard link fails afterward.

## Decision

Phase 1 is approved when the final clean verification run and all protected GitHub quality, Linux, macOS, and Windows checks pass for this review change.
No unresolved Phase 1 correctness, security, migration, ownership, or forensic finding remains in the reviewed implementation.
