# ADR 0011: Portability Import Plans and Atomic Commits

## Status

Accepted on 2026-07-30.

## Context

Encrypted packages and `.env` files can change between preview and commit.
Destination names, identifiers, profile activation, policies, and secret versions can also change after a preview.
A preview that is not bound to the exact source bytes and destination state can misrepresent the operation that is later committed.

## Decision

Every import is a two-step preview and commit workflow.
Preview computes a deterministic keyed plan hash over the source digest, package identity, destination vault identity, relevant destination state, explicit conflict strategy, optional rename target, and every planned action.
Commit requires that exact plan hash and rebuilds the plan from newly opened source bytes and current destination state.
Any mismatch returns a stale-plan error without starting a write transaction.
After validation and cryptographic preparation complete, `envault-store` applies the complete record batch in one immediate SQLite transaction.
IPC deadlines bound how long a client waits but do not cancel an already running blocking filesystem, KDF, or SQLite operation.
If a portability request exceeds its deadline, the daemon reports an ambiguous atomic outcome and requires a fresh preview before any retry.
The rebuilt destination state and exact plan hash then reveal whether the previous commit completed and prevent blind duplicate mutation.
Profile and workspace packages transfer encrypted secret-version ciphertext and DEKs wrapped by the package transfer key.
Import re-wraps each DEK under the destination VMK and only re-encrypts value ciphertext when destination authenticated-data identifiers differ.

## Consequences

Preview is safe and non-mutating.
Commit cannot silently apply a different package or conflict resolution than the human reviewed.
Large package bytes remain outside the one MiB IPC frame because the daemon opens bounded paths through the platform adapter.
An interruption before the transaction has no persistent effect, and an interruption or error inside the transaction rolls back all portable mutations.
An IPC timeout never claims that the operation was cancelled or rolled back.
The implementation must keep plan construction deterministic and cover source, strategy, rename, and destination-state drift with regression tests.
