# Phase 1 Plan: Encrypted Vault Core

## Objective

Deliver a complete encrypted local vault core with password enrollment, calibrated Argon2id, VMK and DEK wrapping, encrypted metadata, immutable secret versions, transactional profile and secret mutation, generators, backup, integrity checks, recovery fixtures, and forensic verification.

## Ownership

`envault-core` owns stable identifiers, public domain views, validation, and generator semantics.
`envault-crypto` owns password derivation, random material, key wrapping, AEAD, lookup digests, and zeroizing secret buffers.
`envault-store` owns versioned SQLite migration, transactions, integrity checks, consistent backup, and opaque encrypted records.
`envault-platform` owns private directories and file permissions.
`envault-service` owns initialization, unlock, profile and secret workflows, AAD construction, metadata encryption, identity preservation, and error translation.
`envault` exposes bootstrap initialization through the service boundary and retains fail-closed runtime gating until authenticated IPC is available.

## Vertical slice

1. Initialize a new vault from password input received by masked TTY or stdin.
2. Benchmark Argon2id for the host and persist the selected parameters with a random salt.
3. Generate a random VMK, wrap it with the password-derived KEK, create the root scope, and create the encrypted `base` startup profile in one transaction.
4. Unlock the vault and validate the wrapped VMK plus the exactly-one startup-profile invariant.
5. Create a secret with stdin or generated value, encrypt its metadata, create a random DEK, encrypt the value with bound AAD, wrap the DEK, and commit the first immutable version atomically.
6. Rename the profile and secret without changing stable identifiers or secret versions.
7. Set or generate a new secret value as a new immutable version.
8. List and inspect decrypted metadata only inside an unlocked human service session.
9. Delete records transactionally, checkpoint WAL state, create a consistent encrypted backup, and run integrity checks.
10. Reopen a recovery fixture and prove semantic preservation without plaintext persistence.

## Cryptographic bindings

VMK wrapping AAD binds the vault identifier, format version, and algorithm version.
Metadata AAD binds the vault identifier, entity type, entity identifier, field name, and algorithm version.
Secret-value AAD binds the vault identifier, secret identifier, version identifier, scope identifier, version number, and algorithm version.
DEK wrapping AAD binds the same secret-version identity and a distinct key-wrap domain.
Lookup digests use a domain-separated keyed BLAKE3 subkey derived from the VMK.

## Generator contract

UUID v4 returns the canonical 36-character representation.
Base64URL supports exact unpadded character counts or byte counts.
Base64 supports byte counts and returns standard padded output.
The default generator is unpadded Base64URL from 32 random bytes.
Weak exact lengths below 22 characters are rejected unless the caller explicitly opts in.
All randomness comes from the operating system.

## Test matrix

Unit tests cover key redaction, password derivation, wrap and unwrap, AAD tamper rejection, generator lengths, and invalid parameters.
Storage tests cover migration, uniqueness, foreign keys, atomic rollback, WAL checkpoint, integrity checks, and backup recovery.
Service tests cover initialization, wrong-password rejection, startup-profile invariant, profile CRUD, stable rename identity, secret CRUD, immutable version history, generator metadata, backup round trip, and corruption detection.
Forensic tests scan the database, WAL, shared-memory file, backup, logs, temporary directory, and captured CLI output for unique plaintext sentinels.
CLI tests verify no plaintext argv option exists and stdin buffers are zeroized after service handoff.

## Exit gate

All Phase 1 tests, clippy, formatting, dependency policy, audit, packaging, Linux and macOS integration, and Windows compile checks pass.
The forensic suite finds no plaintext sentinel in persistent artifacts or output.
The phase review finds no unresolved correctness, security, migration, or ownership issue.
