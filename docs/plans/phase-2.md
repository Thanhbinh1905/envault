# Phase 2 Plan: Scope, Profile, Policy, and Audit

## Objective

Deliver deterministic hierarchical secret resolution, stable profile-to-scope binding, typed principals and policy rules, bounded grants, redacted policy explanation, and an append-only tamper-evident audit chain.

## Ownership

`envault-core` owns scope, profile-session, principal, resource, audit, and resolved-view domain types.
`envault-policy` owns order-independent rule matching, deny precedence, default denial, bounded grant validation and consumption, and redacted explanations.
`envault-store` owns schema version 3, scope and principal persistence, policy-rule persistence, tombstone storage, transactional mutation, and audit-chain persistence and verification.
`envault-service` owns encrypted scope and principal metadata, scope-chain validation, profile binding, inherited secret resolution, policy orchestration, and audit metadata encoding.

## Scope model

The root scope remains `user`.
Additional scopes have stable UUIDs, encrypted canonical paths, a typed kind, and one parent in the same vault.
Traversal is root-to-leaf and rejects cycles or depth above sixty-four.
The nearest matching secret record wins.
An active child record overrides an ancestor record.
A tombstone has no value version and removes the inherited secret from the resolved view.
Resolved lists are sorted by normalized decrypted name after deterministic keyed-lookup resolution.

## Profile binding

Every profile stores a stable scope identifier.
The migrated `base` profile binds to the root scope.
New profiles receive a dedicated child scope whose encrypted path uses stable identity rather than the mutable profile name.
Binding returns an immutable session descriptor and does not write process environment variables.

## Policy model

Principals have stable identifiers, typed kinds, encrypted display names, keyed lookup digests, disabled state, and generation.
Rules use stable identifiers, exact principals, typed actions, and vault, scope-tree, or exact-secret resource selectors.
Evaluation collects all matching rule identifiers in stable order.
Any explicit deny returns `deny_explicit` even when an allow rule or valid grant also matches.
No match returns `deny_default`.

Grants bind principal, action, resource selector, issue time, expiry, maximum use count, revocation state, nonce, and approval identifier.
Expiry must be after issue time and no more than sixty minutes later.
Maximum use count is between one and one thousand.
Agent grants reject privileged actions.
Successful authorization consumes one use, while denied or mismatched requests do not.

## Audit model

Audit metadata is a typed redacted structure containing stable actor, action, resource, outcome, and request identifiers plus bounded non-sensitive tags.
The store assigns sequence numbers and chains each event to the previous event hash.
The event hash covers sequence, event identifier, action, outcome, metadata, previous hash, and timestamp with length-delimited canonical encoding.
No public API updates or deletes audit rows.

## Test matrix

Property tests permute scope entries and policy rules to prove deterministic output.
Property tests prove child override, tombstone removal, deny precedence, and default denial.
Unit tests cover grant expiry, use exhaustion, revocation, privileged-action rejection, and redacted explanations.
Storage tests cover schema migration, scope ownership, profile binding, tombstones, principal uniqueness, policy persistence, append ordering, and audit tamper detection.
Service tests cover encrypted scope and principal metadata, profile binding, inherited resolution, override, tombstone, cycle and depth defense, policy orchestration, and audit verification.

## Exit gate

All Phase 2 tests, property tests, clippy, formatting, dependency policy, audit, packaging, native Linux and macOS CI, and Windows compile checks pass.
Resolution and policy results remain identical under input permutation.
Deny always wins over allow and grant.
Audit verification detects every tested mutation without exposing plaintext metadata.
The phase review has no unresolved correctness, security, migration, ownership, or determinism issue.
