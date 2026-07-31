# ADR 0016: TUI Admin Mode and Gated Plaintext Reveal

## Status

Accepted for Phase 7 of the 2026-07-31 rework.
Supersedes ADR 0012.

## Context

ADR 0012 held that `envault-tui` would never request or render a decrypted secret value, because a terminal surface cannot bound where a rendered value persists (scrollback, session recording, multiplexer copy buffers) the way the existing single-destination `.env` plaintext export can.
That ADR reserved the question for a future superseding decision with its own authorization gesture and rendering constraints, rather than treating reveal as an incidental extension of the metadata browser.

The user has since asked for exactly one place a human can look at a secret's value with their own eyes: the TUI (and, later, a desktop app).
Every CLI path, including the user's own scripts, must keep printing nothing but metadata; a human who needs to see a value opens the TUI.
This is a deliberate, narrow exception to ADR 0012's blanket prohibition, not a reversal of its reasoning about terminal surfaces in general: the exposure is still bounded to a transient, dismissible popup, gated by the same admin lease already used for every other mutating TUI action.

## Decision

`envault-tui` requires an active admin lease before the Dashboard is usable: on entry, if no lease is active, the admin-unlock password prompt opens immediately instead of waiting for the human to press `u`.
The lease is the uid-scoped lease from Phase 5 with its normal TTL; the TUI does not request `--no-expiration`.

A new `Reveal` action (`v`) is available on the Secrets screen (current value) and the Versions screen (a specific historical version).
It issues a new protocol operation, `Operation::RevealSecretValue { profile, name, version }`, answered by `Reply::SecretPlaintext`, decrypted daemon-side and never touching disk or the CLI's stdout path.
The daemon re-checks `admin_lease_active` at the moment this operation is handled, not from a cached flag, so a lease that expired between key presses still fails closed.
The value is shown in a transient modal; any keypress (including but not limited to `Esc`) closes it and the in-memory buffer is dropped.

## Consequences

The TUI remains the only client that can render a decrypted secret value; every CLI output path, including `envault run`'s child-process env injection, still never prints plaintext to its own stdout or logs.
Reveal has no independent TTL, max-uses, or audit trail beyond the admin lease itself: it is authorized by the same step-up credential as every other admin action, consistent with Phase 4's removal of Grant/Principal/capability-token machinery in favor of coarser, session-level trust.
A future desktop app that also needs to render plaintext should follow this same shape (admin-lease-gated, transient, no independent token) rather than reinvent one.
