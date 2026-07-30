# Glossary

## Agent-blind mediated use

A trusted broker uses a secret for a bounded action without returning plaintext to the agent.

## Admin lease

A short-lived human-authenticated grant for mutation, reveal, policy escalation, or plaintext export.
The default is five minutes and the configurable range is one to thirty minutes.

## Agent grant

A bounded, revocable capability for an agent principal.
The default lifetime is fifteen minutes.

## KEK

The Key Encryption Key derived from a master password with Argon2id.
It unwraps the VMK and does not encrypt secret values directly.

## VMK

The Vault Master Key held only in daemon memory while the service is active.
It wraps each secret-version DEK.

## DEK

A random Data Encryption Key dedicated to one immutable secret version.

## Scope

A stable node in a tree used for inheritance, override, tombstone, and policy resolution.

## Profile

A named set of scope and binding references.
Exactly one profile has `activate_on_start = true`.

## TOON

A compact, stable, agent-oriented output format.

