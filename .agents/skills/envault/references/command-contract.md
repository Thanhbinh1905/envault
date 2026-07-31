# Command Contract

The canonical machine-readable command source is `commands.toml` at the repository root.

Use `envault --output toon status` to check whether the daemon is available.
A missing socket returns `envault_not_running`.
A locked daemon returns `envault_locked`.
For either state, ask the human to run `envault start` and do not run it yourself.

There is no capability token, grant, or agent session in this contract; authorization is same-uid trust in the daemon's peer check, gated by which profiles are in the loaded set (`activate_on_start`).

Use these agent-safe commands:

- `envault --output toon session context` (daemon status and active profile only, safe to run anytime)
- `envault --output toon secret list --fields description` (optionally `--profile <name>`; `--describe` still works as a deprecated alias for `--fields description`)
- `envault request http ...`, gated by a `secret_http_access` record on the target secret; the broker performs the HTTP call and never returns the secret's plaintext to you
- `envault run --profile <name> -- <command> [args...]` (or `--workspace <name>`), run by the human, not by you: it injects plaintext directly into the spawned child's environment and never prints it

`session context` and `session setup` touch no secret and are safe at any time.
`session setup` installs a `SessionStart` hook into the human's agent settings file so future sessions start with `session context`'s output already visible; it is a human-approved setup step, not something to run inside an ongoing task.
`secret list` returns metadata (name, description if requested) for secrets in profiles that are currently loaded; it never returns a value.

Prefer TOON for compact agent work and JSON when strict machine parsing is necessary.
Every error contains `code`, `message`, `help`, `request_id`, and `retryable`.
