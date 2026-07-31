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

## Addendum (2026-07-31): superseded by Phase 4 rework

Capability tokens, `CapabilitySession`, agent grants, and the agent principal concept itself were removed entirely.
The one thing a token still meaningfully protected was the HTTP host/path allowlist, and that allowlist did not need a notion of "which agent is calling" to work.
It is now a `secret_http_access` record attached directly to a secret when its profile is loaded (host, port, methods, path prefix, byte limits), checked purely by same-uid trust.
There is no token, TTL, use count, nonce, or approval identity, and no per-agent revocation: revoking access means unloading the profile or removing the http-access rule, and either affects every process running as that user.
This is an accepted trade-off, not an oversight: running multiple agents concurrently under one user no longer allows distinguishing or individually revoking them.
See ADR 0010's addendum for the corresponding removal of agent sessions and principals.

