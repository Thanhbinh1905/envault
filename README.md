<h1 align="center">EnVault</h1>

<p align="center">
  A local-first encrypted secret vault for developers and AI agents.
</p>

## The problem

Developers and AI agents need credentials to do their job, but handing an agent a plaintext API key or database password is a standing risk.
Once a secret is in an agent's context or environment, you can't take it back, scope it down, or make it expire.
A single prompt injection, misconfigured tool, or leaked log line can turn one credential into a full compromise.

## The solution

EnVault keeps secrets in an encrypted local vault and never releases plaintext to an agent.
A trusted local daemon, started only by an explicit human or automation action, brokers access on behalf of callers.
Agents can read secret metadata and use a narrow, per-secret HTTP access allowlist, but they can never request admin actions, plaintext export, reveal, or arbitrary execution.
Everything is local-first: no cloud dependency, no third party holding your secrets.

Read [the threat model](docs/threat-model.md) for the full security.

## Quick setup

Install the latest release on macOS or Linux with the verified installer:

```sh
curl -fsSL https://raw.githubusercontent.com/Thanhbinh1905/envault/main/install.sh | sh
```

The installer detects the platform, downloads the matching archive, verifies its SHA-256 checksum, and installs the binaries into `$HOME/.local/bin`.

Until then, use the [source installation instructions](docs/INSTALLATION.md#install-from-source).

Initialize the vault and start the daemon explicitly:

```sh
envault init
envault start
envault status
```

Install the EnVault Agent Skill for on-demand guidance in an agent harness:

```sh
npx skills add Thanhbinh1905/envault --skill envault
```

Alternatively, configure the explicit session hook:

```sh
envault session setup
```

Use either the Agent Skill or the session hook.
See [docs/INSTALLATION.md](docs/INSTALLATION.md) for Windows, source installation, upgrades, and security details.
See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the workspace layout, build commands, and CLI usage.

## Commands

Every command accepts a global `-o, --output <human|json|toon>` (default `human`).
Run `envault <command> --help` for the full, exact flag set - the tables below are a quick-reference, not the complete contract.

**Auth** tells you what has to be true before the command works:

| Auth | Meaning |
| --- | --- |
| none | Works standalone; no running daemon required |
| password | Prompts for the master password directly (masked terminal, or `--password-stdin`) |
| unlocked | Daemon must already be running and unlocked (`envault start`) |
| admin lease | Needs an active admin lease first (`envault admin unlock`) |

### Most used

The day-to-day loop: unlock the daemon, get write access, load a profile, work with its secrets, then lock/stop when done.

| Command | Purpose | Auth | Key flags |
| --- | --- | --- | --- |
| `start` | Start (or reach) the daemon and unlock the vault | password | `-p, --password-stdin` |
| `status` | Check whether the daemon is running/unlocked | none | - |
| `admin unlock` | Open a time-boxed lease so you can create/update/delete | password | `-p, --password-stdin`; `-m, --minutes` |
| `profile load <name>` | Load a profile into the session so `run`/HTTP requests can use it | admin lease | `-s, --secret` + `-H, --host` + `-m, --method` for scoped HTTP access |
| `secret create <name>` | Add a secret to the loaded profile | admin lease | `-s, --stdin` to pipe a value, or `-g, --generate <format>` |
| `secret list` | See what secrets exist | unlocked | `-p, --profile <name>`; `-f, --fields description` |
| `run -- <cmd>` | Run a command with secrets injected as env vars, never printed | unlocked | `-p, --profile <name>` (repeatable) or `-w, --workspace <name>` |
| `lock` | Lock the vault, keep the daemon running | unlocked | - |
| `stop` | Stop the daemon entirely | unlocked | - |

<details>
<summary><strong>Full command reference</strong> (every subcommand, grouped by area)</summary>

### Profile

Profiles are named containers of secrets.

| Command | Purpose | Auth | Key flags |
| --- | --- | --- | --- |
| `profile create <name>` | Create a new profile | admin lease | `-d, --description`; `-w, --workspace <name>` to group it under a workspace |
| `profile list` | List all profiles | unlocked | - |
| `profile show <name>` | Show one profile's secrets | unlocked | - |
| `profile update <name>` | Change description or auto-load behavior | admin lease | `-d, --description`; `-a, --activate-on-start <bool>` |
| `profile rename <old> <new>` | Rename a profile | admin lease | - |
| `profile delete <name>` | Delete a profile | admin lease | - |
| `profile load <name>` | Load a profile into the current session (needed before `run`/HTTP requests can use it) | admin lease | `-s, --secret <name>` + `-H, --host` + `-m, --method` to also grant that one secret scoped HTTP access |
| `profile unload <name>` | Remove a profile from the current session | admin lease | - |
| `profile export <name>` | Export one profile to an encrypted `.envault-profile` package | admin lease | `-O, --output-file <path>` (required); `-t/--transfer-password` or `-a, --age-recipient <key>` |
| `profile import <file>` | Import a `.envault-profile` package (preview-first, commit with the returned plan hash) | admin lease | `-t/-s` transfer password; `-S, --strategy`; `-c, --commit` + `-H, --plan-hash` |
| `profile import-env <name> <file>` | Import a plaintext `.env` file into a profile (preview-first) | admin lease | `-S, --strategy`; `-c, --commit` + `-H, --plan-hash` |
| `profile export-env <name>` | Export a profile to a plaintext `.env` file (human recovery escape hatch) | admin lease | `-O, --output-file <path>` (required); `-a, --allow-plaintext` (required acknowledgement) |

### Secret

Individual credentials that live inside a profile.

| Command | Purpose | Auth | Key flags |
| --- | --- | --- | --- |
| `secret create <name>` | Create a secret in the loaded profile | admin lease | `-d, --description`; `-s, --stdin` to pipe the value in, or `-g, --generate <format>` to generate one |
| `secret list` | List secret names (and metadata) | unlocked (agents: names only) | `-p, --profile <name>` for the effective set; `-f, --fields description` for extra columns |
| `secret describe <name>` | Show one secret's metadata (never its value) | unlocked | - |
| `secret update <name>` | Change a secret's description | admin lease | `-d, --description` |
| `secret rename <old> <new>` | Rename a secret | admin lease | - |
| `secret delete <name>` | Delete a secret | admin lease | - |
| `secret versions <name>` | List a secret's version history | unlocked | - |
| `secret value set <name>` | Set a new value for an existing secret | admin lease | `-s, --stdin` (required) |
| `secret value generate <name>` | Generate and set a new value | admin lease | `-f, --format <uuid-v4\|base64url\|base64>` (required); `-c/--chars` or `-b/--bytes`; `-a, --allow-weak` |

### Lifecycle

| Command | Purpose | Auth | Key flags |
| --- | --- | --- | --- |
| `init` | Create a new local vault (sets its master password) | password | `-p, --password-stdin` |
| `status` | Show daemon/service state | none | - |
| `start` | Start (or reach) the daemon and unlock the vault | password | `-p, --password-stdin` |
| `lock` | Lock the vault, keep the daemon running | unlocked | - |
| `stop` | Stop the daemon | unlocked | - |
| `admin unlock` | Open a time-boxed admin lease for write operations | password | `-p, --password-stdin`; `-m, --minutes`; `-n, --no-expiration` |
| `admin status` | Show whether an admin lease is active | unlocked | - |
| `admin lock` | End the admin lease early | admin lease | - |
| `run -- <cmd>` | Run a command with resolved secrets injected as env vars | unlocked | `-p, --profile <name>` (repeatable) or `-w, --workspace <name>` |

### Portability, workspace, and other utilities

| Command | Purpose | Auth | Key flags |
| --- | --- | --- | --- |
| `portability export` | Export the whole workspace to an encrypted `.envault-workspace` package | admin lease | `-O, --output-file <path>` (required); `-t/-s` transfer password; `-a, --age-recipient` |
| `portability import <file>` | Import a `.envault-workspace` package (preview-first) | admin lease | `-t/-s` transfer password; `-S, --strategy`; `-c, --commit` + `-H, --plan-hash` |
| `workspace create <name>` | Create a workspace to group profiles | admin lease | - |
| `workspace list` / `workspace show <name>` | List workspaces / show its member profiles | unlocked | - |
| `workspace load <name>` | Load every profile in a workspace | admin lease | - |
| `request http <url>` | Make an outbound HTTP request using a secret as a header/query value, without exposing it | unlocked | `-s, --secret <profile.name>`; `-m, --method`; `-b, --body-file`; `-f, --full` |
| `convenience-unlock enable` | Store the master password in the OS keyring so `start` doesn't need to prompt | password | `-p, --password-stdin`; `-a, --acknowledge-os-keystore` (required) |
| `convenience-unlock disable` / `status` | Remove the stored password / check whether it's enabled | none | - |
| `session context` | Print daemon state for an agent's session hook (no secret material) | none | - |
| `session setup` | Install the session hook into an agent harness's settings file | none | `-s, --settings-file <path>` |
| `uninstall` | Delete the vault, daemon runtime state, and any stored convenience-unlock credential (does not remove the installed binaries) | password | `-p, --password-stdin`; `--yes`; `--skip-backup`; `-O, --backup-path <path>` |

</details>

## License

Licensed under either the Apache License, Version 2.0 or the MIT license.
