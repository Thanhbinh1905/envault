# ADR 0006: Agent-Blind Broker

## Status

Accepted on 2026-07-30.

## Decision

Agents discover only policy-filtered metadata and advertised capabilities.
The daemon resolves a credential internally and performs a constrained provider action.
The first adapter is HTTP Bearer with normalized URLs, redirect denial, host, method, path, request-count, response-size, and response-firewall constraints.

## Consequences

There is no `get_secret`, `eval`, or generic `exec` method.
Descriptions are untrusted metadata and never instructions.

## Addendum (2026-07-31): authorization input changed, broker design unchanged

The broker's agent-blind design is unchanged: it still decrypts internally, still requires HTTPS with no redirects, and still runs the response through the credential-echo firewall before anything reaches the caller.
What changed is only where the authorization check reads its constraint from.
It previously matched an agent's `HttpConstraint`-bearing grant; it now looks up the `secret_http_access` record attached to the target secret (see ADR 0004's addendum).
The broker itself was not weakened by removing grants, since grants never contributed to the broker's SSRF, redirect, or response-firewall protections in the first place.

