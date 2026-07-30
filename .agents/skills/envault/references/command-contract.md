# Command Contract

The canonical machine-readable command source is `commands.toml` at the repository root.

Bootstrap commands are `envault`, `envault init`, `envault status`, `envault start`, help, and version.
All other commands require the daemon to exist and be unlocked.
A missing socket returns `envault_not_running`.
A locked daemon returns `envault_locked`.
Both errors direct the human to run `envault start`.

Agent-safe commands include context, policy-filtered discovery, session inspection, and constrained requests.
Agent output should use JSON or TOON.
Every error contains `code`, `message`, `help`, `request_id`, and `retryable`.

