# Phase 2 Review

## Scope

Phase 2 delivers deterministic hierarchical scope resolution, stable profile-bound sessions, encrypted principals, typed policy rules, bounded grants, redacted explanations, and a tamper-evident audit chain.
Daemon-owned peer identity, capability-token storage, rate limiting, and runtime grant persistence remain assigned to Phase 3.

## Plan review

The implementation follows the ownership split documented in `docs/plans/phase-2.md` and ADR 0008.
`envault-core` owns scope, session, principal, resolution, and identifier domain types plus deterministic pure resolution.
`envault-policy` owns typed matching, explicit-deny precedence, default denial, grant validation, grant consumption, and redacted explanations.
`envault-store` owns schema version 3, transactional scope and profile mutation, tombstones, principal and rule persistence, audit state, and migration from schema version 2.
`envault-service` owns encrypted metadata, stable profile scopes, scope-chain validation, policy orchestration, trusted audit timestamps, and VMK-keyed audit integrity.

## Implementation review

Scope traversal is root-to-leaf, rejects cycles and disconnected chains, and permits at most sixty-four nodes.
Resolution uses ordered collections and keyed name lookups so child overrides and tombstones are independent of row or input order.
The migrated base profile binds to the root scope, while each new profile receives a stable dedicated child scope whose path does not depend on the mutable profile name.
Profile binding returns an immutable descriptor and does not mutate process environment variables.
Principal names are encrypted and indexed with domain-separated keyed lookup digests.
Policy rules use exact principal, action, and typed resource identifiers.
Vault selectors, ancestor scope-tree selectors, and exact-secret selectors are evaluated against a validated resource context.
Explicit deny always wins over matching allow rules and grants, while no match denies by default.
Agent grants reject privileged actions, zero identities, zero nonces, invalid lifetimes, invalid use counts, exhaustion, revocation, premature use, expiry, and request mismatch.
Grant use is evaluated on a copy and committed only after the corresponding audit record is appended successfully.
Audit events contain only stable identifiers and typed action, resource, decision, and request fields.
Each audit event and the audit head state use VMK-keyed, domain-separated, length-delimited BLAKE3 digests.
The signed audit state detects deletion of the tail or all local audit rows in addition to mutation, insertion, and reordering.
Schema version 2 migrates profiles and secret versions losslessly, binds existing profiles to the root scope, and initializes the signed empty audit state after VMK recovery.

## Test evidence

Property tests prove resolution and policy evaluation are independent of input order.
Policy property assertions also prove any matching deny produces explicit denial, allow-only sets allow, and empty sets deny by default.
Core tests cover nearest override, tombstone removal, ambiguous duplicate rejection, cycle rejection, and depth bounds.
Service tests cover inherited resolution, profile override, tombstones, immutable binding, cycle tamper, sixty-four-node depth enforcement, privileged agent-rule rejection, disabled principals, redacted persistence, audit deletion, and transactional grant consumption.
Storage tests cover schema migration, principal and policy round trips, audit append ordering, event mutation, tail truncation, complete erasure, and signed-state verification.
`cargo xtask verify`, workspace Clippy with warnings denied, workspace tests, doc tests, `cargo nextest run --workspace`, `cargo deny check`, `cargo audit`, workspace package generation, and `git diff --check` pass locally.
The local nextest run passes all fifty-two tests.
Native Linux verification passes locally.
Native macOS and Windows verification is delegated to the protected GitHub CI runners.

## Security review

Scope paths, profile names and descriptions, secret names and descriptions, and principal names are encrypted at rest.
Lookup equality uses VMK-keyed domain separation and validation recomputes every digest after unlock.
Policy records expose only stable identifiers and numeric authorization types, never decrypted names or values.
Audit metadata excludes secret values, names, descriptions, capability material, approval material, and provider responses.
Policy evaluation validates the resource against the current vault before matching any rule or grant.
Database tampering with scope ownership, hierarchy, encrypted metadata, lookup digests, policy resources, audit events, or audit state fails closed during integrity validation.

## Review findings resolved

Large metadata validation logic was split into focused validators instead of suppressing Clippy maintainability checks.
Grant identity validation now rejects nil identifiers, nil resource selectors, and all-zero nonces.
Audit state now authenticates the empty chain so complete event and state deletion cannot silently reset history.
Grant use no longer changes when audit persistence fails.
Audit timestamps now come from the service clock instead of the policy evaluation timestamp supplied by the caller.
Depth enforcement and transactional grant rollback now have direct regression tests.

## Decision

Phase 2 is approved when the final clean verification run and all protected GitHub quality, Linux, macOS, and Windows checks pass for this review change.
No unresolved Phase 2 correctness, security, migration, ownership, determinism, or audit-integrity finding remains in the reviewed implementation.
