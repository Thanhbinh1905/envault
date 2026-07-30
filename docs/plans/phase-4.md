# Phase 4 Plan: AXI CLI and Agent Skill MVP

## Objective

Deliver a usable daemon-only human setup flow, policy-filtered agent context and discovery, bounded session inspection, TOON output, an agent-blind HTTP Bearer broker, and installable Codex and Claude Code skill metadata.

## Ownership

`envault-core` owns stable context and discovery view types.
`envault-broker` owns HTTP method and constraint types, URL and DNS validation, opaque prepared requests, rustls transport, response bounds, and the response firewall.
`envault-service` owns specialized policy-filtered discovery, exact-secret HTTP authorization, current-version decryption, opaque request preparation, and redacted audit persistence.
`envault-protocol` owns the new human, admin, agent, discovery, and HTTP request and response messages.
The daemon owns capability constraints, use counts, peer identity, service mutation dispatch, and asynchronous broker execution.
The CLI and skill consume IPC only and never depend on storage or cryptographic crates.

## Human setup surface

Profile metadata and activation commands run through daemon IPC.
Secret metadata, generated creation, standard-input creation and value mutation, rename, deletion, and version inspection run through daemon IPC without a reveal command.
Mutations require an active admin lease, while human metadata reads require only the unlocked service boundary.
Admin agent commands create and list agent principals.
Admin grant commands create narrow discovery or exact-secret HTTP capabilities and revoke them by immutable grant UUID.
One-time token delivery requires piped standard output and never writes a token to disk, arguments, or environment input.

## Agent surface

`envault context --token-stdin` reports daemon state, active profile, principal, grant resource, remaining uses, expiry, and advertised constraint without consuming a use.
`envault secret list --describe --token-stdin` performs one audited discovery operation and returns deterministic policy-filtered metadata.
`envault agent session status --token-stdin` inspects only the supplied capability.
`envault request http URL --secret SECRET_UUID --method METHOD --token-stdin` performs the bounded provider operation and returns only the firewalled response.
Every agent operation supports JSON and TOON output and preserves structured errors.

## HTTP broker

The HTTP grant requires one exact secret resource and one typed constraint.
The request accepts a URL, an allowed method, an optional bounded body file, and an optional safe content type.
The request cannot supply authorization, host, cookies, proxy settings, redirect policy, or arbitrary headers.
The broker requires HTTPS, exact normalized host and port, a segment-safe path prefix, no fragment, and a configured method.
DNS resolution rejects loopback, private, link-local, multicast, unspecified, documentation, benchmarking, and reserved addresses before pinning all accepted addresses into reqwest.
The reqwest client uses rustls, has redirects disabled, and applies connect plus total deadlines below the daemon request deadline.
Response streaming stops at the configured byte limit.
Only successful UTF-8 JSON or text responses may return a body.
Redirects, provider errors, binary responses, oversized responses, and credential echoes return stable redacted errors without response headers or provider diagnostics.

## Skill package

Keep `SKILL.md` concise and imperative.
Move the canonical command and security detail into one-level `references/` files.
Regenerate `agents/openai.yaml` from the finished skill with a default prompt that explicitly invokes `$envault`.
Validate the folder with the skill-creator validator and verify local installation through the supported `npx skills add` flow for Codex and Claude Code layouts.

## Test matrix

Broker unit and local TLS tests cover URL normalization, method and path boundaries, DNS classification, rebinding pinning, redirect denial, request bounds, response bounds, content types, provider-error suppression, and credential-echo rejection.
Service tests cover no generic secret getter, discovery deny precedence, one-use batch discovery, exact-secret HTTP authorization, audit append, current-version selection, and invalid credential handling.
Daemon tests cover typed capability-constraint validation, context without use consumption, discovery consumption, HTTP consumption, revocation, lock invalidation, and token-bearing privilege rejection.
Real-binary E2E covers human setup, one-time piped token handoff, JSON and TOON context, filtered discovery, session inspection, rejection of a private TLS target, a real public TLS provider request, and absence of credential plaintext from CLI output and persistent artifacts.
Broker-local TLS tests cover redirect and echo rejection without weakening the production SSRF boundary.
Skill tests cover frontmatter, references, generated OpenAI metadata, canonical command drift, security prohibitions, and local installer discovery.

## Exit gate

All local verification, broker adversarial tests, service and daemon tests, real-binary E2E, skill validation, dependency policy, vulnerability audit, packaging, Linux and macOS CI, and Windows compile checks pass.
Codex and Claude Code can install and discover the EnVault skill through the supported package layout.
An agent can complete a constrained HTTP request without receiving the credential, provider error body, redirect target, or rejected response payload.
The Phase 4 review has no unresolved CLI, policy, capability, HTTP, SSRF, response-firewall, skill, portability, or exfiltration finding.
