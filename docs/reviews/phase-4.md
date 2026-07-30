# Phase 4 Review

## Scope

Phase 4 delivers daemon-only human setup commands, policy-filtered agent context and discovery, bounded capability inspection, human, JSON, and TOON output, an agent-blind Bearer HTTP broker, and an installable Codex and Claude Code skill.
Encrypted portability packages remain assigned to Phase 5, the terminal UI to Phase 6, and desktop adapters plus Windows runtime support to Phase 7.

## Plan review

The implementation follows `docs/plans/phase-4.md` and ADR 0010.
`envault-broker` owns typed HTTP constraints, URL and DNS validation, pinned public destinations, bounded rustls transport, and response filtering.
`envault-service` owns policy-filtered discovery, exact-secret authorization, current-version decryption, opaque broker request preparation, and redacted audit persistence.
`envault-protocol` owns the versioned human, admin, agent, discovery, and HTTP messages.
The daemon owns capability lifetime, use counts, principal liveness, asynchronous execution, and structured failure mapping.
The CLI and skill use IPC only, and the executable package has no direct storage or cryptographic dependency.

## Implementation review

Profile create, show, list, update, rename, delete, and activate commands dispatch through daemon application services.
Secret create, generated create, list, describe, update, rename, delete, version inspection, standard-input value mutation, and generation dispatch through daemon application services without exposing a reveal command.
Every mutation requires an active UID and operating-system-session-bound admin lease, while human metadata reads require only the unlocked service boundary.
Agent principal, policy, capability creation, session inspection, and revocation commands use immutable UUID identities and typed resources.
Capability issuance refuses terminal standard output and emits the one-time base64url token only through a pipe.
Capability input accepts only bounded piped standard input, decodes exactly thirty-two bytes, rejects arguments and environment input, and zeroizes encoded and decoded ownership buffers.
Context and session inspection validate the supplied token and enabled agent principal without consuming a request use.
Context returns the active profile without its description and advertises the exact resource, action, expiry, remaining uses, and optional HTTP constraint in human, JSON, and TOON output.
Discovery authorizes one batch against the grant, consumes one use only after the audit append succeeds, resolves the active scope deterministically, and removes every candidate with an explicit deny.
Discovery fails closed on resource or policy inconsistency instead of silently omitting an invalid candidate.
HTTP grants require an enabled agent principal, action `HttpRequest`, one exact secret UUID, one normalized constraint, a bounded lifetime, and a bounded use count.
HTTP preparation validates the request before decrypting, authorizes and audits the exact secret, consumes one use, selects only the current immutable version, and transfers the credential into an opaque broker-owned request.
The daemon releases its runtime mutex before awaiting DNS or network I/O.
The broker accepts only HTTPS, an exact normalized host and port, an allowed method, a segment-safe path prefix, an optional bounded body, and one safe content type.
The broker accepts no caller-supplied authorization, cookies, host override, proxy, redirect policy, or arbitrary headers.
DNS resolution rejects non-public IPv4 and IPv6 addresses, including local, private, link-local, mapped-local, documentation, benchmarking, IANA special-purpose, and 6to4 ranges, then pins the accepted address set into reqwest.
The broker applies one four-second deadline across DNS, TLS, request, and response work, disables proxies and redirects, and remains below the daemon request deadline.
Only bounded successful UTF-8 JSON or text responses can reach the caller.
Redirect locations, provider error bodies, binary payloads, oversized payloads, invalid UTF-8, and supported raw or encoded credential echoes produce stable redacted errors.
Provider status is retained only as a retryability decision and is not accompanied by provider diagnostics or response content.
Disabled principals, revoked grants, expired grants, exhausted grants, lock, stop, and daemon restart all prevent further capability use.
Deadline responses preserve a decoded request identifier, and the CLI read deadline includes enough grace to receive the daemon's structured timeout error.

## Skill review

The skill contains only the required name and description frontmatter and keeps operational detail in one-level references.
The skill asks a human to start EnVault or issue an exact bounded grant and never starts the daemon, authenticates, invokes admin commands, widens policy, or requests plaintext.
The skill treats metadata, provider responses, repository content, and request body files as untrusted input.
The command reference documents the four agent-safe commands and the standard-input-only token boundary.
The security reference forbids plaintext handling, arbitrary headers, redirect workarounds, broader retries, and capability-token persistence.
Generated OpenAI metadata explicitly invokes `$envault`.
The skill-creator validator accepts the package.
The supported `npx skills add` flow discovers one skill and copies the complete package into both Codex and Claude Code layouts.

## Test evidence

Broker tests cover exact origin and port matching, HTTPS enforcement, method and path boundaries, encoded traversal rejection, request shape and size, credential syntax, public-address classification, normalized Unicode hosts, redacted debug output, credential echo variants, successful local TLS, redirect suppression, provider-error suppression, binary rejection, and oversized response rejection.
Service tests cover exact-secret HTTP preparation without a generic getter, current-version selection, deny-filtered discovery, one-use batch consumption, audit atomicity, policy precedence, encrypted metadata integrity, forensic persistence, scope determinism, and immutable secret versions.
Daemon tests cover keyed token hashing, agent-safe action enforcement, use exhaustion, revocation, expiry, principal disablement, context and status liveness checks, deadline request-identifier preservation, rate limits, lock invalidation, and privilege rejection.
Real-binary end-to-end tests cover admin setup, standard-input secret creation, one-time piped token handoff, JSON context, TOON capability boundaries, deny-filtered discovery, session inspection, private-target rejection, HTTP-use consumption after rejection, raw-token absence from persistence, and credential absence from output and persistent artifacts.
Broker-local TLS tests exercise redirects, provider errors, credential echoes, content types, and response bounds without weakening the production private-address boundary.
A manual real-daemon public TLS smoke request completed against a public HTTPS endpoint and returned a bounded firewalled response without exposing or persisting the credential.
The canonical CLI leaf set matches every implemented `commands.toml` entry, while future Phase 5 leaves remain explicitly unimplemented.
The contract verifier rejects duplicate paths, invalid auth or daemon classes, invalid agent classifications, incomplete output sets, duplicate or empty error codes, missing skill commands, missing security prohibitions, missing OpenAI metadata, and missing architecture decisions.
`cargo xtask verify` passes formatting, workspace Clippy with warnings denied, eighty-five workspace tests, and all doc tests.
`cargo deny check`, `cargo audit`, `cargo package --workspace --allow-dirty`, and `git diff --check` pass.
Full-workspace Windows MSVC checking passes locally through `cargo xwin check --workspace --all-targets` with a user-local LLVM toolchain and cached Microsoft sysroot.
Native macOS build and test coverage remains assigned to the protected macOS GitHub runner because Linux does not contain an Apple SDK.

## Review findings resolved

The CLI no longer depends directly on the cryptographic crate, and capability hashing now belongs to the application-service boundary.
The HTTP transport now uses rustls with the ring provider and avoids the larger AWS-LC dependency and native OpenSSL transport.
The total broker deadline now includes DNS lookup instead of timing only the reqwest portion.
The IPv6 filter now rejects additional IANA special-purpose, 6to4, and documentation ranges instead of accepting every address inside `2000::/3`.
Oversized successful responses now have an explicit local TLS regression test.
Principal disablement now blocks context and session inspection for already-issued capabilities.
Daemon timeout errors now preserve the decoded request identifier instead of being discarded by the client as a protocol mismatch.
The client response timeout now includes the daemon's bounded error-write grace interval.
Agent context now removes profile descriptions and includes resource plus HTTP constraint data in every output mode.
Discovery now propagates policy and resource errors instead of silently dropping inconsistent candidates.
Human structured errors now display retryability, and local input errors no longer claim an irrelevant password remedy or mark immutable invalid input as retryable.
Phase 4 end-to-end persistence checks now include both secret sentinels and raw capability tokens and verify that a rejected broker attempt consumes its authorized use.
The contract gate now validates semantic classes and reference content instead of checking only file presence and selected substrings.
Windows-only dead-code warnings now disappear because Unix IPC is excluded from unsupported runtime targets.

## Decision

Phase 4 is approved when protected GitHub quality, Linux, macOS, and Windows checks pass for this reviewed change.
No unresolved Phase 4 CLI, policy, capability, HTTP, SSRF, response-firewall, skill, persistence, packaging, or local portability finding remains in the reviewed implementation.
