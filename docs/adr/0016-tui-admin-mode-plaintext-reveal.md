# ADR 0016: Human Plaintext Reveal

## Status

Accepted.
Supersedes ADR 0012.

## Context

The TUI and desktop application can render a decrypted secret value for a human.
CLI output remains metadata-only, except for the existing process injection and explicitly named plaintext export paths.

## Decision

The TUI requires a password proof before its dashboard is usable.
The desktop application obtains the same proof during login.
Both clients use `Operation::IssueRevealToken { password }` to mint a token tied to the active admin lease.
`Operation::RevealSecretValue { profile, name, token }` returns only the secret's current value and never writes plaintext to disk or CLI stdout.
The daemon verifies both the active admin lease and reveal token when handling the operation.
The TUI displays the value in a transient modal that closes on any keypress.
The desktop application displays the value only on an explicit reveal action and clears it when the user hides it, closes the modal, or the desktop session locks.

## Consequences

Reveal tokens have no independent TTL, max-use count, or audit trail and clear when the admin lease clears.
An active same-user lease alone cannot reveal a value because the caller must also possess a token minted from a fresh password proof.
