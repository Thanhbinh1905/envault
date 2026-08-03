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

A many-to-many grouping of profiles that should load together, backed by its own `workspace` table and a `workspace_membership` join - entirely independent of the scope tree that secrets inherit through.
A profile can belong to any number of workspaces at once; workspaces never hold secrets.
`envault workspace create` makes the group, `envault workspace bind`/`unbind` add or remove a profile's membership, `envault profile create --workspace` is sugar for creating a profile and binding it in one step, and `envault workspace load` loads every member profile at once.

## Loaded set

The set of profiles a session can actually read secrets from.
It is runtime-only and resets on every unlock, seeded at that point from every profile with `activate_on_start` set (see Profile), then mutated ad hoc by `envault profile load`/`unload`, `envault workspace load`, and `envault load`/`unload` for the rest of the session.
`envault load`/`unload` read the `.envault.toml` manifest in the current directory and apply the same profile/workspace load and unload operations, additionally tracking which profiles they auto-loaded per project path so a later `unload` (or a `load` that drops an entry from the manifest) only unloads what that directory previously auto-loaded.
Loading or unloading a profile never writes back to its `activate_on_start` preference; the two are deliberately decoupled.
Ambient reads (`secret describe`, `secret list --profile`, and similar) and `envault run` both require the target profile to already be in the loaded set - `run` never loads a profile as a side effect of naming it.
The `base` profile is always loaded and cannot be unloaded.

## `secret_http_access`

A per-secret allowlist record (host, port, methods, path prefix, byte limits) attached when a profile is loaded with `--secret ... --host ...`.
It is the sole authorization input for `envault request http`: there is no per-caller identity, token, or expiry, only "does this secret have a rule that matches this request."
Revoking access means removing the rule or unloading the profile, which affects every process running as the same user.

## `envault run`

Resolves the secrets visible to one or more profiles (`--profile`, repeatable to merge several) or every profile in a workspace (`--workspace`) and injects them as environment variables directly into a spawned child process.
Every named profile must already be in the loaded set (see Loaded set); `run` never loads one as a side effect.
This is the only path that lets plaintext leave the daemon into a CLI-driven process; the CLI itself never prints the value to stdout, stderr, or a log.
With `--workspace`, if two member profiles resolve a secret with the same name, resolution fails with `duplicate_secret_across_profiles` instead of silently picking one; repeat `--profile` to disambiguate instead.
A command argument may also reference `{{<profile>.<name>}}`; the value is substituted with a `/dev/fd/<n>` path backed by an anonymous pipe, never printed or placed in an environment variable.

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
