# ADR 0001: Crypto Key Hierarchy

## Status

Accepted on 2026-07-30.

## Context

EnVault needs password-based recovery, efficient master-key rotation, replaceable secret values, and minimal plaintext lifetime.

## Decision

Argon2id derives a KEK from the master password and a per-vault salt.
The KEK unwraps a random VMK.
Every secret value receives a random DEK.
Writing a value replaces the existing encrypted value and its DEK; EnVault retains no secret-value history.
XChaCha20-Poly1305 encrypts values and sensitive metadata with AAD binding vault, entity, value identifier, scope, and algorithm version.
VMK rotation re-wraps DEKs without decrypting secret values.

## Consequences

KDF parameters are stored per vault and can be upgraded.
Nonce generation and AAD construction become critical invariants.
Key types must zeroize on drop and must not appear in debug output.
