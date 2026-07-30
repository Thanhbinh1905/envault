# Phase 6 Plan: Terminal UI

## Objective

Deliver `envault-tui`, an interactive terminal dashboard for scopes, profiles, secret metadata, admin leases, agent sessions, and portability workflows, built entirely on the existing authenticated daemon IPC surface.
The terminal UI never renders secret plaintext and introduces no new protocol operation, storage access, or cryptographic dependency.

## Ownership

`envault-core` contributes no new stable types; the terminal UI renders the existing redacted `ScopeView`, `ProfileView`, `SecretView`, `SecretVersionView`, `PortabilityPreview`, and status types unchanged.
`envault-crypto`, `envault-store`, and `envault-platform` are not linked into the terminal UI binary.
`envault-service` and `envault-protocol` gain no new operations; every terminal UI action maps to an `Operation` variant already dispatched by the daemon for the CLI.
`envault-service`'s application boundary and the daemon's admin-lease enforcement, agent-capability rules, and structured error mapping apply identically regardless of which client issued the request.
The `envault` crate owns the terminal UI binary alongside the existing CLI binary and reuses the crate's IPC client module (`envault::client`) instead of duplicating socket, framing, or timeout handling.
The CLI and terminal UI remain IPC-only clients with no direct storage or cryptographic crate dependency, per ADR 0007.

## Terminal application structure

`envault-tui` is a new `[[bin]]` target in the existing `envault` crate, replacing the placeholder in `src/bin/envault-tui.rs`.
The binary depends on `ratatui` for layout and widgets and `crossterm` for the terminal backend, both added as new workspace dependencies pinned to exact versions.
The terminal UI reuses `envault::client` for every daemon call, so socket discovery, CBOR framing, the one-megabyte frame cap, and the portability response deadline are identical to the CLI's behavior.
The application owns one `tokio` runtime, drives daemon calls on it, and keeps the render loop on the main thread; a background call never blocks input handling for more than one frame interval.
Raw mode and the alternate screen are entered only after the terminal is confirmed interactive and are unconditionally restored on every exit path, including panics, through a panic hook installed before raw mode begins and a guard type whose `Drop` restores the terminal.
The terminal UI never writes its own log file and never persists a session state file; all state is in-memory for the process lifetime.

## Read surface

The dashboard's default view shows daemon status, lock state, the active profile, and the admin lease and agent session summaries already exposed by `Status`, `AdminStatus`, and `AgentSessionStatus`.
A scope and profile browser lists `ScopeView` and `ProfileView` records in a tree matching the scope hierarchy, with secret counts per scope.
A secret list for the selected scope shows `SecretView` fields only: name, description, current version, and status, with no value field to omit because the type carries none.
A version history view for a selected secret lists `SecretVersionView` entries: version number, creation time, and generator metadata, again with no plaintext field to omit.
Every list and detail view is read-only and requires no admin lease, matching the same authorization the CLI's read commands already use.

## Admin surface

An admin panel exposes lease unlock, renewal, and explicit lock, issuing the same `AdminUnlock` and lock operations the CLI issues, with the human entering the master password through a masked input widget that is never echoed and never buffered to terminal scrollback.
Mutating actions gated behind an active admin lease, such as creating a scope or profile, generating a new secret version, and rotating a secret, are available from the terminal UI only while the lease is active and each requires an explicit confirmation prompt naming the exact target before the request is sent.
Agent session listing and explicit session revocation are available from the admin panel and call the same session-management operations the CLI exposes.
The terminal UI never creates or reads a capability token; capability issuance remains exclusive to the agent-facing broker path per ADR 0004.

## Portability surface

The terminal UI can trigger profile, workspace, and `.env` import preview and commit, and package export, through the same preview-then-commit protocol flow as the CLI.
The preview screen renders the deterministic plan hash, redacted counts, conflict descriptions, and planned actions returned by the daemon, and commit is only offered as an explicit action on the exact plan hash currently displayed.
If the terminal UI reissues a preview, for example after the human edits the conflict strategy, the previously displayed plan hash is discarded and cannot be committed.
The terminal UI does not implement its own retry-on-timeout behavior for portability calls; an expired deadline is shown as a non-retryable error directing the human to preview current state again, matching the CLI's behavior.
Plaintext `.env` export remains exclusively a CLI command; the terminal UI does not offer it, since the escape hatch's narrow authorization and output-path guarantees do not carry over to a screen-rendering client.

## Secret value non-disclosure boundary

The terminal UI never displays a secret's decrypted value and never requests one from the daemon; no code path in the terminal UI can trigger plaintext decryption because no such general-purpose operation exists in the protocol today, and the terminal UI does not introduce one.
Any future in-terminal reveal capability is out of scope for Phase 6 and requires its own ADR, since the correct authorization, rendering, and screen-recording exposure model needs dedicated design rather than an incidental extension of the read surface.
ADR 0012 records this boundary as a durable architectural constraint rather than a temporary omission.

## Terminal safety

The terminal UI validates that standard output is an interactive terminal before entering raw mode and exits with a structured error on non-interactive invocation instead of attempting to render.
Resizing, focus loss, and unsupported terminal capabilities degrade the layout without crashing or leaving the terminal in raw mode.
Every daemon error, including authentication and permission failures, renders as a bounded status message; the terminal UI never dumps a raw protocol error containing more than the structured fields the CLI would print.
Copy-to-clipboard and shell-out actions are not implemented in Phase 6, since neither has a bounded, auditable non-leakage story yet for value-bearing views, and no such view exists in this phase regardless.

## Test matrix

Unit tests cover terminal state transitions for navigation, selection, and confirmation flows using an in-memory fake IPC client, independent of any real daemon or terminal backend.
Rendering tests use `ratatui`'s test backend to assert that scope, profile, secret, and version views never interpolate a value field, that masked password input never appears in a rendered buffer, and that error views bound daemon error text to structured fields.
Portability flow tests assert that a stale or edited plan hash cannot be committed and that a reissued preview invalidates the prior plan hash in terminal UI state.
Panic-safety tests assert the terminal restoration guard runs on a simulated panic during the render loop.
Real-binary end-to-end tests drive `envault-tui` against a real daemon over a pseudo-terminal for status display, scope and secret browsing, admin lease unlock and lock, and one portability preview-to-commit round trip, then scan the pseudo-terminal transcript for secret values and master password characters.

## Exit gate

All local verification, terminal UI unit and rendering tests, real-binary end-to-end pseudo-terminal tests, dependency policy, vulnerability audit, packaging, Linux and macOS CI, and Windows compile checks pass.
The terminal UI performs every mutating action through the same authenticated, admin-leased, and capability-respecting daemon operations the CLI uses, with no new protocol surface.
No terminal UI code path decrypts or renders a secret value in any phase-6 build.
The Phase 6 review has no unresolved terminal-safety, authorization, portability-plan, or secret-disclosure finding.
