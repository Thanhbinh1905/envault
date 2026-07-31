# ADR 0012: Terminal UI Never Displays Secret Plaintext

## Status

Accepted on 2026-07-31.

## Context

Phase 6 adds `envault-tui`, an interactive client that renders scope, profile, and secret metadata on a shared terminal surface.
No general-purpose protocol operation returns a decrypted secret value to any client; the only plaintext-disclosure path today is the human-only, admin-leased, explicitly acknowledged `.env` plaintext export, which writes directly to one named destination file and never to standard output, logs, or terminal scrollback.
A terminal dashboard is a rendering surface, not a single-destination file write: anything it draws can persist in terminal scrollback, session recording tools, screen sharing, or a terminal multiplexer's copy buffer, for an unbounded time after the process exits.
Extending the read surface to include decrypted values would require its own authorization gesture, rendering discipline, and non-persistence guarantee, and doing so incidentally as part of a metadata browser risks understating how different that exposure is from the existing escape hatch.

## Decision

`envault-tui` renders only the existing redacted view types (`ScopeView`, `ProfileView`, `SecretView`, `SecretVersionView`, and portability preview and summary types) and requests no operation that would return a decrypted secret value.
The terminal UI does not implement a reveal, peek, or copy-to-clipboard action for secret values in Phase 6.
Plaintext `.env` export remains exclusively a CLI command with its existing admin-lease, explicit-acknowledgement, and single-destination-file guarantees.
Any future in-terminal reveal capability requires a superseding ADR that defines its own authorization gesture, rendering constraints, and non-persistence guarantee; it is not an extension of the Phase 6 read surface.

## Consequences

Phase 6 introduces no new plaintext-disclosure path and no new protocol operation.
The terminal UI's threat surface for secret leakage is limited to the same structural redaction the CLI's read commands already rely on.
A future reveal feature starts from an explicit design decision instead of inheriting Phase 6 rendering code not built for that purpose.
Users who need a secret value outside the vault continue to use the plaintext export command, which remains the sole reviewed path for that disclosure.

## Addendum (2026-07-31): superseded by ADR 0016

Phase 7 introduces exactly the superseding ADR this document anticipated: ADR 0016 adds an admin-lease-gated `Reveal` action to the Secrets and Versions screens, with its own authorization gesture (admin lease required on TUI entry, re-checked at reveal time) and rendering constraint (a transient popup dismissed by any keypress, never written to disk or CLI stdout).
This document's original decision and reasoning remain the historical record of why Phase 6 shipped with no reveal capability at all; ADR 0016 is the design that replaced it.
