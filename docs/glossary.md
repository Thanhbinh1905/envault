# Glossary

## Agent-blind mediated use

A trusted broker uses a secret for a bounded action without returning plaintext to the agent.

## Admin lease

A short-lived human-authenticated grant for mutation, reveal, or plaintext export.
The default is five minutes and the configurable range is one to thirty minutes, or unbounded with `--no-expiration`.
The lease is scoped to the operating-system user id, not to a single terminal session, so unlocking from one terminal covers every process of that same user on the machine.

## Secret address (`<profile>.<secret>`)

The canonical way to name a secret.
A bare name with no `.` addresses the secret in the `base` profile.
A secret always belongs to exactly one profile and its name is unique within that profile.

## Workspace

A grouping scope over one or more profiles, backed by the pre-existing `ScopeKind::Workspace` scope kind.
`envault workspace create` makes the group, `envault profile create --workspace` binds a new profile under it, and `envault workspace load` loads every member profile at once.
It adds no new database table.

## Loaded set

The set of profiles a session can actually read secrets from, tracked by the existing `activate_on_start` flag on each profile (now zero-or-more rather than exactly-one).
`envault profile load`/`unload` and `envault workspace load` toggle membership at runtime.
Ambient reads (`secret describe`, `secret list --profile`, and similar) require the target profile to be in the loaded set; `envault run` does not, since naming a profile there is itself the explicit action.
The `base` profile is always loaded and cannot be unloaded.

## `secret_http_access`

A per-secret allowlist record (host, port, methods, path prefix, byte limits) attached when a profile is loaded with `--secret ... --host ...`.
It is the sole authorization input for `envault request http`: there is no per-caller identity, token, or expiry, only "does this secret have a rule that matches this request."
Revoking access means removing the rule or unloading the profile, which affects every process running as the same user.

## `envault run`

Resolves the secrets visible to one profile (or every profile in a workspace) and injects them as environment variables directly into a spawned child process.
This is the only path that lets plaintext leave the daemon into a CLI-driven process; the CLI itself never prints the value to stdout, stderr, or a log.
With `--workspace`, if two member profiles resolve a secret with the same name, resolution fails with `duplicate_secret_across_profiles` instead of silently picking one; use `--profile` to disambiguate.

## Reveal

The TUI-only action that decrypts and displays a secret's current or historical value in a transient popup.
It is the sole path that shows plaintext to a human's eyes; every CLI output path, including `envault run`, never prints a value.
Gated by an admin lease and a reveal token minted by re-proving the vault password; the token has no independent TTL beyond the lease it is attached to, and clears when that lease clears.

## KEK

The Key Encryption Key derived from a master password with Argon2id.
It unwraps the VMK and does not encrypt secret values directly.

## VMK

The Vault Master Key held only in daemon memory while the service is active.
It wraps each secret-version DEK.

## DEK

A random Data Encryption Key dedicated to one immutable secret version.

## Scope

A stable node in a tree used for inheritance, override, and tombstone resolution.

## Profile

A named set of scope and binding references, and the sole owner of any secret created within it.
One or more profiles may have `activate_on_start = true` (see Loaded set).
The base profile is the durable profile bound to the vault root scope and cannot be deleted or unloaded.

## TOON

A compact, stable, agent-oriented output format.

## Transfer key

A fresh random key that encrypts one portability package payload.
The transfer key is wrapped by a transfer-password slot or encrypted into one or more age recipient slots.

## Import plan hash

A keyed digest binding an import preview to the exact source bytes, destination state, conflict strategy, optional rename target, and planned actions.
Commit rejects a missing or stale plan hash before starting a write transaction.
