# Phase 5 Plan: Portability and Developer UX

## Objective

Deliver redacted `.env` discovery and guided import, encrypted profile and workspace packages, password and age transfer-key slots, deterministic import previews, explicit conflict handling, atomic import commits, and an intentionally narrow plaintext `.env` export escape hatch.

## Ownership

`envault-core` owns stable package kinds, conflict strategies, preview views, import summaries, and redacted environment-entry views.
`envault-crypto` continues to own key generation, Argon2id derivation, XChaCha20-Poly1305 encryption, and key wrapping.
`envault-store` owns validated portability mutation batches and commits each accepted batch in one immediate SQLite transaction.
`envault-platform` owns bounded no-follow file reads and private atomic no-replace writes.
On macOS it first expands only the fixed root-owned `/var`, `/tmp`, and `/etc` aliases to their `/private` targets, then applies the same no-follow walk to every remaining component.
`envault-service` owns `.env` parsing, encrypted package construction, key-slot handling, import planning, plan hashing, entity remapping, DEK re-wrapping, ciphertext migration, and plaintext export authorization boundaries.
`envault-protocol` owns path-based preview, commit, export, and response messages so package payloads never need to fit inside the IPC frame.
The daemon owns admin-lease enforcement and dispatches every portability operation through the application service.
The CLI uses IPC only and never accesses storage or cryptographic crates directly.

## Encrypted package format

Profile packages use the `.envault-profile` suffix and workspace packages use the `.envault-workspace` suffix.
Each CLI import operation binds the expected package kind into IPC, and the service rejects a valid package presented through the wrong profile or workspace command.
The outer envelope is bounded versioned CBOR containing a package identifier, kind, source vault identifier, creation time, key slots, and one XChaCha20-Poly1305 payload ciphertext.
The payload authentication data binds the package identifier, kind, source vault identifier, envelope version, and algorithm version.
Every package uses a fresh random thirty-two-byte transfer key.
A password slot derives a wrapping key with Argon2id bounded to 8-128 MiB of memory, one to six iterations, and one to four lanes, then wraps the transfer key with slot-specific authenticated data.
An age slot encrypts the transfer key independently to one X25519 recipient.
At least one key slot is required, and a package may contain both slot types for recovery diversity.
The encrypted payload contains decrypted logical metadata, original value ciphertext, and each secret-version DEK re-wrapped under the transfer key.
The payload never contains the source VMK, plaintext secret values, audit history, capability tokens, grants, sessions, or runtime state.

## Export behavior

Profile export includes the selected profile scope, its descendant non-profile scopes, and their secrets and immutable version history.
Traversal stops before any other profile scope so exporting the base profile does not silently export unrelated profiles.
Workspace export includes every scope, profile, secret version, principal, and policy rule but excludes audit and runtime state.
Metadata is decrypted only inside zeroizing memory before the outer package encryption is complete.
Value ciphertext is preserved and only its DEK is unwrapped from the VMK and re-wrapped under the transfer key.
Export writes a private temporary file, synchronizes it, publishes without replacing an existing destination, synchronizes the parent directory where supported, and leaves the final file at mode `0600` on Unix.

## Import preview and commit

Import opens a stable no-follow regular-file handle and enforces package, slot, entity, string, and ciphertext bounds before expensive or mutating work.
Wrong credentials, malformed CBOR, unsupported versions, invalid Argon2id parameters, age failure, authentication failure, and semantic corruption fail before any SQLite transaction begins.
Preview decrypts and validates the package, resolves immutable identifier remapping, evaluates conflicts, and returns only redacted counts, conflict descriptions, actions, and a deterministic plan hash.
Commit requires the caller to supply the exact preview plan hash.
Commit reopens and replans from current file and vault state, rejects any package or state drift, prepares encrypted destination records in memory, and performs one immediate SQLite transaction.
The client and daemon apply a bounded portability deadline, but blocking filesystem, KDF, and SQLite work is not falsely reported as cancelled.
If the deadline expires, the structured error is non-retryable and directs the human to preview current state before deciding whether another commit is needed.
Cross-vault or remapped versions decrypt the original value ciphertext with the transferred DEK and source authenticated data, then encrypt it with the same DEK and destination authenticated data.
Every imported value ciphertext is authenticated and decrypted before commit, including the same-vault path.
When all authenticated-data identifiers remain unchanged, the validated original value ciphertext remains byte-for-byte unchanged.
Every imported DEK is wrapped under the destination VMK before persistence.

## Conflict strategies

`abort` rejects any actionable name or immutable-identifier conflict and is the default.
`skip` is available for profile and `.env` imports and leaves matching destination items unchanged.
`replace` is available for profile, workspace, and `.env` imports and replaces the selected logical content inside the same atomic transaction.
Profile replacement accepts an optional explicit destination profile name so a previously renamed import can be updated without touching the base profile.
Profile replacement rejects a plan that would orphan an existing scope or secret policy resource, and the store revalidates every policy resource inside the import transaction.
`rename` is available for profile import and requires one explicit destination profile name.
Workspace root scope and base profile are destination anchors rather than replaceable vault records.
The base profile remains permanently bound to the root scope and cannot be deleted after another profile is activated.
Workspace replacement clears portable logical data while preserving the destination vault, VMK, root scope identity, base profile identity, and local audit chain.
Exactly one imported profile remains configured for startup after any successful workspace commit.
Every successful encrypted package commit revokes in-memory agent capability sessions so bulk profile, secret, principal, or policy replacement cannot silently reuse a pre-import authorization context.

## `.env` scanner and import

The scanner accepts UTF-8 files with bounded size and line length, blank lines, comments, optional `export`, unquoted values, single-quoted values, and a small explicit double-quote escape set.
The scanner never evaluates interpolation, command substitution, shell syntax, or includes.
Duplicate keys, malformed assignments, NUL bytes, multiline values, unsupported escapes, invalid names, and oversized values fail closed with a stable line number.
Preview reports secret names, byte lengths, conflicts, and planned actions but never value bytes.
`abort`, `skip`, and `replace` resolve conflicts against the selected profile scope.
One commit imports all accepted entries in one transaction, with replacement creating a new immutable secret version rather than overwriting history.
The scanner requires a stable private plaintext input file on Unix and warns that the source file remains outside EnVault after a successful import.

## Plaintext `.env` escape hatch

Plaintext export is human-only, requires an active admin lease, an explicit `--allow-plaintext` acknowledgement, a named profile, and a destination file path.
The command never writes plaintext to standard output, terminal scrollback, logs, errors, temporary package files, or environment variables.
The output uses deterministic name order, shell-safe quoting, direct no-replace creation at the explicit destination, and Unix mode `0600`.
Plaintext export does not create a second hidden temporary plaintext file.
The destination must not exist and symbolic-link or hard-link targets are rejected.
The service verifies that the visible destination still names the exact created inode after synchronization and never removes a path that may have been replaced concurrently.
An operating-system write failure or process interruption may leave a private partial file only at the explicit destination path, which the human can inspect and remove.

## Test matrix

Package unit tests cover password-only, age-only, mixed-slot, wrong-password, wrong-identity, slot swapping, payload tamper, header tamper, unsupported version, hostile KDF bounds, package bounds, and redacted debug behavior.
Service round-trip tests cover profile and workspace transfer between clean vaults, metadata semantics, immutable version history, generator metadata, policy relationships, startup profile selection, DEK re-wrapping, and ciphertext preservation where authenticated data is unchanged.
Import tests cover every supported conflict strategy, stale plan hashes, file replacement between preview and commit, concurrent destination drift, duplicate identifiers, malformed relationships, interrupted preparation, and transaction rollback without partial mutation.
Scanner tests cover quoting, comments, export prefixes, literal dollar syntax, invalid UTF-8, duplicates, invalid names, unsupported escapes, multiline rejection, file bounds, redacted previews, and atomic abort, skip, and version-appending replacement.
Plaintext export tests cover admin enforcement, explicit acknowledgement, deterministic escaping, no stdout value, no-replace behavior, symlink and hard-link rejection, and Unix mode `0600`.
Real-binary end-to-end tests exercise preview-to-commit workflows through the daemon and scan stdout, stderr, database, WAL, logs, package temporaries, and command history fixtures for plaintext leakage.
`cargo xtask package-verify` builds every generated crate archive together through local registry patches so unpublished coordinated workspace changes cannot accidentally verify against older registry versions.

## Exit gate

All local verification, portability adversarial tests, service transaction tests, real-binary end-to-end tests, dependency policy, vulnerability audit, packaging, Linux and macOS CI, and Windows compile checks pass.
Clean-vault profile and workspace round trips preserve logical semantics and immutable history.
Tamper, wrong credentials, unsupported inputs, stale previews, and interrupted imports create no partial mutation.
Plaintext `.env` export is the only portability path that writes raw values and its authorization, acknowledgement, path, permission, and output boundaries are verified.
The Phase 5 review has no unresolved package-format, cryptographic, key-slot, scanner, atomicity, conflict, filesystem, UX, portability, or plaintext-leakage finding.
