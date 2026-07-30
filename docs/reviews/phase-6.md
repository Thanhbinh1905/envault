# Phase 6 Review

## Scope

Phase 6 delivers `envault-tui`, an interactive terminal dashboard, admin panel, and portability client built entirely on the existing authenticated daemon IPC surface.
Desktop adapters and Windows runtime integration remain assigned to Phase 7.

## Plan review

The implementation follows `docs/plans/phase-6.md`, ADR 0007, and the new ADR 0012.
`envault-core` contributes no new stable types; the terminal UI renders the existing redacted `ProfileView`, `SecretView`, `SecretVersionView`, `PortabilityPreview`, and status types unchanged.
`envault-crypto`, `envault-store`, and `envault-platform` are not linked into the terminal UI binary.
`envault-service` and `envault-protocol` gain no new operations; every terminal UI action maps to an `Operation` variant already dispatched by the daemon for the CLI.
The `envault` crate owns the terminal UI binary alongside the existing CLI binary and reuses the crate's IPC client module instead of duplicating socket, framing, or timeout handling.
The plan was corrected twice during implementation to match the real protocol surface rather than an assumed one: no operation returns a `ScopeView` listing, so the terminal UI browses profiles and secrets directly instead of an invented scope tree; `AgentSessionStatus` reports only the calling session's own state, so the dashboard's session count comes from `DaemonStatus` instead; the IPC client is a synchronous blocking call, not a `tokio` runtime, so the terminal UI issues requests inline on the input loop.
The admin surface was scoped to profile lifecycle and secret lifecycle actions; agent principal management, grant issuance and revocation, and policy authoring remain CLI-only in this phase because each is its own bulk or structured-authoring workflow deserving dedicated screen design.

## Implementation review

The terminal UI validates that standard output is an interactive terminal before entering raw mode and exits with a structured error on non-interactive invocation instead of attempting to render.
A panic hook is installed before raw mode begins, and a guard type's `Drop` implementation restores the terminal on every exit path; the guard's own construction failure paths clean up raw mode and the alternate screen before returning an error, so there is no window where raw mode is left enabled without a corresponding guaranteed restoration.
The terminal UI never writes its own log file and never persists a session state file; all state is in-memory for the process lifetime.
The dashboard shows daemon status, lock state, the active profile, admin lease status, and agent session count.
The profile browser, secret list, and secret version history render only the fields their existing redacted view types expose; none of these types carry a value field, so there is no plaintext to omit by convention, only by construction.
The admin panel gates lease unlock and lock, profile lifecycle (create, rename, delete, activate), and secret lifecycle (create, update, rename, delete, generator-based rotation) behind an admin lease state derived live from the daemon's own responses, never cached across a failed call.
The master password and every transfer password or age-identity path are entered through a masked input that is never echoed, held in a zeroizing buffer while typed, and moved into a zeroize-on-drop byte buffer at submission with no lingering unwrapped copy.
Every mutating action, including portability commit and admin lock, requires a distinct confirmation step naming the exact target; no single keypress both selects and commits a mutating action.
The portability screen exposes only the conflict strategies each import kind actually supports: workspace import offers `abort` and `replace`; profile import offers `abort`, `skip`, `replace`, and `rename`; `.env` import offers `abort`, `skip`, and `replace`.
The held plan hash is cleared at the moment a new preview is requested, before the request is even sent, and commit consumes the held hash so a repeated commit attempt without a fresh preview cannot reuse it; no other code path reads the held hash.
A portability timeout renders as a non-retryable status message directing the human to preview current state again, matching the CLI's wording, and never claims the operation was cancelled or rolled back.
Package export supports a password key slot; age-recipient export is deferred as a follow-up rather than forced into the existing input modes.
Plaintext `.env` export and any secret-value reveal, peek, or copy action are absent from the terminal UI by design; ADR 0012 records this as a durable architectural boundary rather than a temporary omission, and no protocol operation exists today that would let the terminal UI request a decrypted value even if it tried.

## Test evidence

Unit tests cover screen navigation and list refresh, every input-mode transition including cancel paths, and that a mutating action requires an explicit confirmation step rather than a single keypress.
Portability tests assert the held plan hash is cleared the instant a new preview is requested, even before a response lands, and that commit consumes the hash so a repeated commit call cannot reuse it.
Rendering tests using `ratatui`'s test backend assert that view rendering surfaces only the fields the underlying types expose and that a typed master password never appears literally in the rendered buffer, only mask characters.
Terminal-guard tests cover panic-hook installation and guard construction and restoration behavior to the extent testable without a real attached terminal.
A real-binary smoke test drives `envault-tui` with non-interactive stdout and asserts a non-zero exit, no stdout output, and the structured interactive-terminal error.
A PTY-driven interactive end-to-end walkthrough was assessed and explicitly deferred: no PTY crate exists anywhere in the workspace, and building one plus a non-flaky harness in this phase was judged a disproportionate risk against the value delivered; it is noted here as follow-up work rather than left as a flaky or partially-working test.
An independent adversarial review pass re-read every changed file against `docs/plans/phase-6.md`, ADR 0012, `docs/threat-model.md`, and ADR 0007, specifically checking for plaintext leakage paths, credential zeroization on every exit path, the plan-hash staleness guarantee's actual code path rather than its self-report, confirmation-gating bypass through any keybinding, terminal-restoration coverage on every exit path, and IPC response handling that could assume success without checking a reply variant.
That review found zero blocking issues; the one documentation-accuracy nit it found, a dependency-versioning wording mismatch, was corrected in the plan.
`cargo build -p envault`, `cargo clippy -p envault --all-targets -- -D warnings`, `cargo fmt --check -p envault`, and `cargo test -p envault --lib tui` pass clean.
`cargo xtask verify` passes the contract gate, formatting, workspace Clippy with warnings denied, all workspace tests, and all doc tests.
`cargo deny check` passes advisories, bans, licenses, and sources.
`cargo audit` reports no vulnerability across 413 locked dependencies.
`cargo xtask package-verify` packages the coordinated workspace, including the new `ratatui` and `crossterm` dependencies, and compiles every product crate archive together through local registry patches.
Protected GitHub quality, Linux, macOS, and Windows checks passed for pull request 11.

## Review findings resolved

None; the adversarial review pass found zero blocking implementation issues and one documentation-wording nit, which was corrected directly in the plan rather than requiring a code change.

## Decision

Phase 6 is approved.
No unresolved terminal-safety, authorization, portability-plan, secret-disclosure, or packaging finding remains.
Deferred, explicitly documented follow-up work: age-recipient package export from the terminal UI, a PTY-driven interactive end-to-end test, and the agent principal, grant, and policy admin screens.
