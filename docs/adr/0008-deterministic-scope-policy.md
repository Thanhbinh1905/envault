# ADR 0008: Deterministic Scope and Policy Evaluation

## Status

Accepted for Phase 2.

## Context

EnVault needs hierarchical secret resolution, profile-bound sessions, explicit tombstones, policy denial precedence, bounded grants, explainable decisions, and tamper-evident audit records.
The result must not depend on database row order, rule order, hash-map iteration order, or caller-controlled principal claims.

## Decision

Scope chains are evaluated from root to leaf.
A child record with the same keyed name lookup overrides its ancestor, and a child tombstone removes the inherited name from the resolved view.
Resolved collections use a stable ordered map and return deterministic output.
Scope traversal rejects cycles, cross-vault parents, and depth above sixty-four.

Profiles bind to stable scope identifiers.
A profile session is an immutable application value containing the profile identifier, scope identifier, profile generation, and binding timestamp.
Binding never mutates the environment of an existing process.

Policy requests use typed principal, action, and resource identifiers.
Explicit deny rules always override allow rules and grants.
Default is deny.
Explanations contain only decision codes and stable identifiers, never secret names, values, descriptions, tokens, or provider responses.

Agent grants are revocable and bounded by expiry and use count.
Agent grants cannot authorize administration, reveal, plaintext export, policy mutation, or generic execution.

Audit records are append-only through the public store API and form a BLAKE3 hash chain over canonical binary fields and redacted CBOR metadata.
Chain verification fails on mutation, deletion, insertion, or reordering.

## Consequences

Scope and policy behavior can be property-tested independently from storage order.
The daemon can later attach operating-system peer identity and in-memory capability hashes without changing the evaluator.
Import and portability code must preserve stable identifiers and rebuild deterministic resolution plans before commit.
