# Command Contract

The canonical machine-readable command source is `commands.toml` at the repository root.

Use `envault --output toon status` without a token to check whether the daemon is available.
A missing socket returns `envault_not_running`.
A locked daemon returns `envault_locked`.
For either state, ask the human to run `envault start` and do not run it yourself.

Every capability token enters exactly one CLI process through `--token-stdin` and piped standard input.
Never place the token in an argument, environment variable, file, transcript, or diagnostic.

Use these agent-safe commands:

- `envault --output toon session context` (no token; daemon status and active profile only, safe to run anytime)
- `envault --output toon context --token-stdin`
- `envault --output toon secret list --fields description --token-stdin` (`--describe` still works as a deprecated alias)
- `envault --output toon agent session status --token-stdin`
- `envault --output toon request http URL --method METHOD --secret UUID --token-stdin`

`session context` and `session setup` take no capability token and touch no secret; every other command in this list requires one.
`session setup` installs a `SessionStart` hook into the human's agent settings file so future sessions start with `session context`'s output already visible; it is a human-approved setup step, not something to run inside an ongoing task.
Context and session inspection do not consume a request use.
One discovery command consumes one request use and returns a deterministic policy-filtered metadata batch.
One HTTP command consumes one request use after authorization even if the provider, network, or response firewall rejects the attempt.

The HTTP command accepts only an exact URL, an allowed method, the granted secret UUID, an optional bounded `--body-file`, and an optional safe `--content-type`.
It does not accept authorization, cookies, redirects, proxies, host overrides, arbitrary headers, or plaintext credential input.

Prefer TOON for compact agent work and JSON when strict machine parsing is necessary.
Every error contains `code`, `message`, `help`, `request_id`, and `retryable`.
