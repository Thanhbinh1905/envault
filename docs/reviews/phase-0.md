# Phase 0 Review

## Scope

Phase 0 establishes the security contract, repository boundaries, canonical command contract, architecture decisions, continuous integration, and packaging baseline.

## Plan review

The repository structure matches the approved one-way dependency boundaries.
The executable package owns `envault`, `envaultd`, and `envault-tui`.
The canonical `commands.toml` records authentication class, daemon requirement, agent eligibility, structured outputs, and expected errors.
Six accepted ADRs cover key hierarchy, daemon lifecycle, authenticated IPC, capability tokens, encrypted portability packages, and the agent-blind broker.
The threat model separates protected assets, trust boundaries, in-scope attacks, non-goals, invariants, residual risks, and verification strategy.

## Implementation review

The workspace uses Rust Edition 2024 and pins Rust 1.97.1 with rustfmt and clippy.
The repository commits `Cargo.lock` and forbids unsafe code by default.
Dual licensing uses `MIT OR Apache-2.0` consistently.
The `xtask` contract gate verifies required architecture documents and Agent Skill security text.
GitHub Actions run formatting, clippy with warnings denied, contract verification, nextest, doc tests, dependency policy, vulnerability audit, Linux and macOS builds, and Windows compile checks.
GitHub branch protection requires all platform and quality checks, linear history, and resolved conversations.
Private vulnerability reporting is enabled.

## Test evidence

`cargo xtask verify` passes locally.
`cargo deny check` passes without warnings after explicitly allowing unavoidable transitive duplicate versions.
`cargo audit` reports no known vulnerabilities.
`cargo package --workspace --no-verify` packages every workspace crate without metadata warnings.
GitHub CI passes on Linux, macOS, and Windows.

## Security review

Bootstrap commands do not expose plaintext input paths.
The contract contains no generic `get_secret`, `eval`, or `exec` endpoint.
Agent guidance forbids authentication, admin actions, reveal, plaintext export, and treating descriptions as instructions.
Runtime commands that are not implemented fail closed instead of simulating an insecure daemon.

## Decision

Phase 0 is approved when the final clean verification run and protected-branch CI both pass for this review change.
Phase 1 may then replace fail-closed placeholders only with fully authenticated and tested implementations.
