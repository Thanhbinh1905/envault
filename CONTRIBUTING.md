# Contributing

## Quality gates

Run `cargo xtask verify` before submitting a change.
Warnings, flaky tests, contract drift, and undocumented security behavior are release blockers.

## Architecture

Read `docs/threat-model.md`, `docs/glossary.md`, and the ADRs before changing a trust boundary.
Any change to an approved decision requires a new ADR covering context, alternatives, security impact, and migration.

## Safety

Never add plaintext fixtures that resemble production credentials.
Never pass secret values through command arguments or environment variables.
Never log request bodies, tokens, ciphertext-derived searchable values, or decrypted metadata.

