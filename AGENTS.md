# Agent Instructions

Guidance for AI agents (and the `no-mistakes` document step) working in this repository.

## Writing public documentation

README.md, SECURITY.md, CONTRIBUTING.md, docs/*.md, and docs/adr/*.md are public-facing and permanent.
Do not write sentences that narrate the development process instead of the actual decision, fact, or behavior.
Banned patterns:

- References to CI jobs, workflow file paths, or "review gates" as evidence a claim is true (e.g. "which the `windows-runtime` CI job now provides and the Phase N review gate requires as evidence").
- Self-referential commentary on a previous mistake or draft (e.g. "not the approach an earlier pass mistakenly relied on", "as an earlier draft assumed").
- Meta-narration about the current edit itself (e.g. "now implemented", "newly identified", "this update adds", "as part of this change/workflow").
- Internal-process qualifiers on dates or phases (e.g. "Phase 2 of the 2026-07-31 rework" instead of just "Phase 2").

That narration belongs in a commit message or PR description, not in a doc a reader opens months later with no session context.
Write the technical fact plainly: what the system does, what was decided, and why, without describing the act of writing it.

An ADR "Implementation status" or "Addendum" section stating what exists and what is deferred is fine.
Trim any sentence in it that would stop making sense to someone who wasn't in the conversation where it was written.

## Quality gates

Run `cargo xtask verify` before submitting a change (see CONTRIBUTING.md).
