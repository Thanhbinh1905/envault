# Phase 5 Review

## Scope

Phase 5 delivers guided `.env` discovery and import, encrypted profile and workspace packages, transfer-password and age X25519 key slots, preview-bound conflict handling, atomic commits, and the explicit plaintext `.env` recovery escape hatch.
The terminal UI remains assigned to Phase 6, while desktop adapters and Windows runtime integration remain assigned to Phase 7.

## Plan review

The implementation follows `docs/plans/phase-5.md`, ADR 0005, and ADR 0011.
`envault-core` owns stable package kinds, conflict strategies, redacted previews, counts, actions, and summaries.
`envault-platform` owns stable-parent no-follow path traversal, bounded reads, private creation, no-replace publication, inode validation, and Unix permissions.
`envault-store` owns the portability mutation batch and validates its complete relational state inside one immediate SQLite transaction.
`envault-service` owns package construction, key slots, `.env` parsing, cryptographic validation, deterministic plans, identifier remapping, DEK re-wrapping, ciphertext migration, conflict semantics, and plaintext export formatting.
`envault-protocol` owns bounded path-based portability requests and redacted response types.
The daemon owns admin-lease enforcement, blocking-work isolation, request deadlines, successful package-commit capability revocation, and structured error mapping.
The CLI uses daemon IPC only and has no direct storage or cryptographic dependency.

## Implementation review

Profile and workspace export create a fresh random transfer key and one authenticated XChaCha20-Poly1305 payload.
Password slots derive an independent wrapping key through Argon2id with authenticated slot metadata.
Age X25519 slots encrypt only the transfer key and can coexist with a password slot for recovery diversity.
The outer envelope and encrypted payload bind package identity, package kind, source vault identity, creation time, format version, and algorithm version.
Packages contain encrypted logical metadata, immutable value ciphertext, and transfer-key-wrapped DEKs but contain no source VMK, plaintext value, audit history, grant, capability token, session, or runtime state.
Every decoded CBOR value must consume its complete bounded input, so trailing data is rejected instead of being silently ignored.
Import validates envelope bounds and semantics before attempting an expensive KDF.
Accepted transfer-password KDF parameters are limited to 8-128 MiB, one to six iterations, and one to four lanes.
Import validates every scope, profile, secret, version, principal, policy relationship, timestamp, generator field, wrapped DEK, AAD digest, and value ciphertext before preview or mutation.
Generator metadata requires canonical UUID v4 formatting or canonical Base64 encoding and an exact entropy value compatible with the generated representation.
The profile and workspace CLI commands bind their expected package kind into IPC, and the service rejects a valid package presented through the wrong command.
Preview computes a keyed deterministic plan hash over the exact source digest, destination vault and state, conflict strategy, optional rename target, destination profile, and planned actions.
Commit reopens the source, rebuilds the plan, uses constant-time plan-hash comparison, and rejects drift before a write transaction begins.
Workspace import supports only `abort` and `replace`.
Profile import supports `abort`, `skip`, `replace`, and explicit `rename`.
Plaintext `.env` import supports only `abort`, `skip`, and version-appending `replace`.
The CLI exposes only the strategy set supported by each command and requires `--rename-to` for profile rename.
Profile identifier remapping is deterministic over package, destination vault, normalized destination profile name, source identifier, and entity domain.
One profile package can therefore be imported under multiple explicit names without identifier collision, and a renamed destination can be replaced later without losing its profile identity.
Workspace replacement preserves the destination vault, VMK, root scope, base profile, and audit chain while replacing portable logical records.
The base profile is permanently bound to the root scope and cannot be deleted after another profile becomes active.
Profile replacement rejects any plan that would orphan an existing scope or secret policy resource.
The store independently validates every policy resource inside the import transaction before commit.
Every successful encrypted package commit clears all in-memory agent capability sessions before returning success.
Every imported DEK is authenticated under the transfer key and re-wrapped under the destination VMK.
Every imported value ciphertext is decrypted and authenticated with source AAD before commit.
Value ciphertext remains byte-for-byte unchanged only when all destination AAD identifiers remain unchanged, and otherwise it is re-encrypted with the same DEK and destination AAD.
All accepted package and `.env` mutations are applied in one immediate SQLite transaction and late validation failure rolls back the complete batch.
The `.env` scanner accepts a deliberately small literal assignment grammar and never evaluates interpolation, command substitution, shell syntax, includes, or unsupported escapes.
Preview output contains names, lengths, actions, counts, and warnings but never value bytes.
Plaintext export requires an active admin lease, explicit `--allow-plaintext`, a named profile, and a new destination path.
Plaintext export writes no value to stdout, stderr, logs, environment variables, or a hidden temporary file.
The explicit destination is created directly at mode `0600`, synchronized, and verified to still name the exact created inode.
Error handling never deletes a destination path that may have been concurrently replaced.
Encrypted package publication uses a private synchronized temporary file and an atomic no-replace rename through one held parent directory descriptor.
Unix path traversal opens every parent component with directory and no-follow flags and rejects symbolic-link parents plus `..` traversal.
macOS fixed root-owned `/var`, `/tmp`, and `/etc` aliases are normalized to their `/private` targets before the same no-follow walk, so standard platform temporary paths work without permitting arbitrary symbolic-link parents.
Portability work runs through `spawn_blocking` with a sixty-second client and daemon deadline.
An expired deadline never claims that blocking work was cancelled or rolled back.
Both daemon and client timeout errors are non-retryable for portability and require a fresh preview because an atomic commit may have completed.

## Test evidence

Package tests cover password-only, age-only, mixed slots, wrong password with age fallback, wrong identity, slot ordering, authenticated header tamper, payload tamper, unsupported version, hostile KDF parameters, inner ciphertext corruption, invalid relationships, invalid scope kinds, strict generator metadata, oversized sparse files, and redacted debug behavior.
Workspace round-trip tests preserve profiles, scopes, principals, policies, immutable secret history, logical values, and same-AAD ciphertext while re-wrapping every DEK.
Profile tests cover abort, skip, replace, rename, repeated import under different names, replacement of a previously renamed target, policy-orphan rejection, stale plans, and source or destination drift.
Store tests prove complete rollback after late failures and reject orphaned policy resources before transaction commit.
Platform tests cover private modes, hard-link and symbolic-link rejection, symbolic-link parents, parent traversal, stable bounded reads, private socket mode, no-replace publication, destination replacement detection, and inode ownership.
Scanner tests cover comments, optional `export`, quoted and unquoted values, literal dollar syntax, duplicates, invalid UTF-8, unsupported escapes, line and file bounds, redacted previews, atomic conflict handling, and version-appending replacement.
Plaintext export tests cover acknowledgement, deterministic escaping, no-replace behavior, private mode, absence of a hidden temporary plaintext file, and no plaintext in command output or vault persistence.
Real-binary end-to-end tests run workspace export, preview, commit, `.env` preview, `.env` commit, and plaintext recovery export through the daemon.
The end-to-end suite scans stdout, stderr, the encrypted package, database tree, WAL-related persistence, and output permissions for secret and transfer-password leakage.
The canonical CLI leaf set matches every implemented `commands.toml` entry, and the packaged command contract must match the repository contract byte-for-byte.
`cargo nextest run --workspace` passes all 112 tests across fifteen binaries.
`cargo xtask verify` passes the contract gate, formatting, workspace Clippy with warnings denied, all workspace tests, and all doc tests.
`cargo deny check` passes advisories, bans, licenses, and sources.
`cargo audit` reports no vulnerability across 368 locked dependencies.
`cargo xtask package-verify` packages the coordinated workspace and compiles all nine product crate archives together through local registry patches.
`cargo xwin check --workspace --all-targets` passes the full Windows MSVC compile check.
`cargo build --workspace --release` passes with the release optimization profile.
`cargo install --path crates/envault --locked` installs the `envault`, `envaultd`, and `envault-tui` executables together.
`git diff --check` passes.
Native macOS build and runtime coverage remains assigned to the protected macOS GitHub runner because the Linux development host has no Apple SDK.

## Review findings resolved

Stable file operations no longer follow symbolic-link parent components between validation and use.
Socket permission hardening now validates socket inodes instead of incorrectly applying regular-file checks that prevented daemon startup.
macOS standard temporary paths no longer fail stable-parent validation on the operating system's fixed `/var` and `/tmp` aliases.
Package preview now validates inner DEK wrapping and value ciphertext authentication instead of trusting only the outer payload tag.
Hostile transfer-password KDF parameters are rejected before derivation and cannot request unbounded memory or CPU.
Encrypted package commands cannot import the other package kind through a semantically incorrect CLI path.
Profile replacement cannot commit dangling policy resource identifiers.
Import transaction validation now covers policy resource existence in addition to foreign keys, startup profile count, and secret-version invariants.
Generator metadata tampering cannot retain syntactically valid output with a false length, format, or entropy claim.
Deterministic profile mapping includes the normalized destination name and no longer collides when the same package is imported under multiple names.
Previously renamed profile imports can be replaced explicitly without creating a second profile or changing the base profile.
The root-bound base profile can no longer be deleted after activation moves elsewhere.
Plaintext export no longer creates a hidden plaintext temporary file and no longer removes a concurrently replaced visible path.
Strict CBOR decoding rejects trailing package and IPC payload data.
Package publication and bounded reads now reject symbolic-link parents and traversal components through stable directory descriptors.
Package commits now revoke in-memory agent capability sessions before returning success.
Portability timeouts now describe an ambiguous atomic outcome and require re-preview instead of suggesting a blind retry.
Package verification no longer resolves coordinated unpublished crates against an older registry version.
The executable package now carries its synchronized command contract so packaged tests and local workspace tests evaluate the same source of truth.
CLI help no longer advertises unsupported conflict strategies and documents credentials, identity files, plan hashes, explicit commit, recipients, destinations, and plaintext acknowledgement.

## Decision

Phase 5 is locally approved.
No unresolved local package-format, cryptographic, KDF, key-slot, scanner, import-plan, transaction, policy-integrity, capability-lifecycle, filesystem-race, plaintext-leakage, CLI UX, packaging, release-build, or Windows compile finding remains.
Final Phase 5 approval requires the protected Linux, macOS, Windows, and quality checks to pass on the reviewed pull-request commit.
