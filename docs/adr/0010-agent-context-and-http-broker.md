# ADR 0010: Agent Context and HTTP Bearer Broker

## Status

Accepted for Phase 4.

## Context

An agent must discover only policy-approved metadata and use a credential without receiving its plaintext.
The first provider adapter must constrain network destinations, prevent redirect and SSRF leakage, bound request and response data, and avoid introducing a generic secret-reading or execution API.
Human setup must be possible through authenticated daemon IPC so the supported workflow never requires direct database or cryptographic access.

## Decision

Agent capability sessions store their HTTP constraint in daemon memory beside the grant hash entry.
An HTTP capability binds one enabled agent principal, action `HttpRequest`, exactly one secret UUID, one HTTPS host and port, an allowed method set, a normalized path prefix, a response-size limit, expiry, use count, nonce, and approval identity.
Discovery capabilities may bind a vault, scope tree, or exact secret and return only metadata that remains allowed after explicit-deny evaluation.

The application service exposes specialized discovery and HTTP preparation workflows.
It does not expose a generic value getter.
HTTP preparation authorizes and audits the exact secret action, decrypts only the current version, transfers the value into an opaque broker request, and drops the service-owned plaintext buffer.
Only the broker can execute or inspect the opaque prepared request.

The broker accepts no caller-supplied authorization, host, proxy, redirect, cookie, or arbitrary header override.
It normalizes the URL, requires HTTPS, matches the exact host and port, validates method and path-segment boundaries, rejects encoded traversal, bounds request and response bytes, and disables redirects.
Before connecting, it resolves the allowed host, rejects non-public addresses, and pins the validated address set into the HTTP client to prevent DNS rebinding.

The response firewall returns only status, a bounded safe content type, and a UTF-8 body from a successful response.
It suppresses every provider error body and redirect location.
It rejects binary content, oversized content, and any successful body containing the raw credential or a supported encoded representation.

Agent tokens enter CLI commands only through bounded standard input.
Grant issuance returns a one-time base64url token only through explicitly piped standard output and refuses a terminal destination.
The skill never starts the daemon, performs authentication, creates grants, invokes admin commands, or asks a human to paste credential plaintext.

## Consequences

Stopping or locking the daemon invalidates every HTTP constraint and token together.
Changing a provider constraint requires a new human-approved capability instead of mutating an existing grant.
HTTP request failures may consume one bounded grant use after authorization because an attempted provider action is auditable even when transport or response filtering fails.
The first broker deliberately supports Bearer authentication only and cannot proxy generic sockets, commands, database sessions, or arbitrary headers.

## Addendum (2026-07-31): agent sessions and principals removed

`Operation::Context`, `CreateAgentSession`, `AgentSessionStatus`, `RevokeAgentSession`, and the entire `Principal`/`PrincipalKind::Agent` concept were removed.
There is no session, token, or identity distinguishing one agent process from another, or from a human's own CLI use.
Agent access to secret metadata is now governed purely by the loaded set (see the glossary); agent access to an HTTP action is governed purely by the `secret_http_access` record on the target secret (ADR 0004's addendum).
Both checks depend only on same-uid trust in the daemon's peer authentication (ADR 0009), not on any claim the caller presents.
The broker's own constraints (HTTPS-only, no redirects, host/method/path matching, response firewall) are unchanged, per ADR 0006's addendum.
