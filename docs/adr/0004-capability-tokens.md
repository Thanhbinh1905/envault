# ADR 0004: Capability Tokens

## Status

Accepted on 2026-07-30.

## Decision

Agent principals receive random, narrow, expiring, revocable capability tokens.
The daemon stores only token hashes in memory.
Tokens bind principal, action, secret reference, target constraints, request limits, expiry, nonce, and approval identity.

## Consequences

Stopping the daemon invalidates every agent token.
An agent token can never authorize admin actions, reveal, plaintext export, or generic execution.

