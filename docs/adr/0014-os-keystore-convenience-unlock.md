# ADR 0014: Opt-In OS-Native Convenience Unlock

## Status

Accepted on 2026-07-31.

## Context

The vault unlocks only when a human supplies the master password, which is Argon2id-derived per ADR 0001's key hierarchy.
Some humans want to avoid retyping that password on every `start` invocation and would rather rely on their operating system's own credential store, which is itself gated by OS session or login authentication.
Storing the master password, or material equivalent to it, in an OS keystore changes the vault's practical unlock guarantee from "requires a memorized secret" to "requires access to the current OS session," even when the feature is optional.
Treating this as a value-neutral convenience would understate that trade-off to the human enabling it.

## Decision

Convenience unlock is opt-in per profile and disabled by default.
Enabling it requires an explicit acknowledgement naming the security posture change at the moment of enablement, not only in documentation.
The stored credential is read only by the `start` command's own unlock path; no other command, including the terminal UI, reads or writes it.
Disabling convenience unlock removes the stored credential from the OS store immediately and has no effect on the vault's encryption or on any already-issued admin lease.
The feature uses the operating system's native credential store on each platform, mirroring the platform-native approach Phase 7 already takes for IPC transport and filesystem hardening, rather than a custom cross-platform store.

## Consequences

A human who enables convenience unlock is explicitly trading confidentiality-at-rest of the master password for reduced friction, with that trade stated at the moment of the decision.
The vault's cryptographic guarantees are unchanged; only the practical bar for invoking `start` is lowered for profiles that opt in.
Revocation is immediate and local to the OS credential store; it requires no vault-side state change.
Audit and test coverage must demonstrate the acknowledgement text, the opt-in default, and that no command other than `start` can read the stored credential.
