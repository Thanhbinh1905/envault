<h1 align="center">EnVault</h1>

<p align="center">
  <img src="assets/brand/envault-logo.png" alt="EnVault logo" width="180">
</p>

<p align="center">
  Give developer tools and AI agents access to credentials without giving them the credentials themselves.
</p>

<p align="center">
  A local-first encrypted secret vault for developers and AI agents.
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> · <a href="#how-it-works">How it works</a> · <a href="#security-boundary">Security</a> · <a href="#command-reference">Command reference</a>
</p>

## Why EnVault

AI agents and developer tools need credentials to do useful work.
Giving them a plaintext API key or database password creates a standing risk.
Once a secret is in an agent's context, environment, logs, or tool output, you cannot reliably take it back, narrow its scope, or know where it travelled.

This is not only a prompt-injection problem.
An over-permissive tool, a copied terminal transcript, or a verbose error can turn one exposed credential into a much wider compromise.

EnVault is for the narrower, safer model: a human decides what may use a secret and for which action, while the agent never receives the secret value.

## The EnVault model

EnVault stores secrets in an encrypted vault on your machine.
A local daemon, started only by an explicit human or automation action, is the trusted boundary between callers and secret plaintext.
There is no cloud service, shared control plane, or third party that holds your vault.

For a human-operated command, EnVault can inject selected secrets into a child process without printing them.
For an agent, EnVault exposes metadata and a constrained HTTP broker action for a pre-authorized secret and destination.
Agents cannot request admin actions, plaintext reveal or export, arbitrary command execution, or daemon startup.

## How it works

1. Create a vault and start it explicitly.
2. Store credentials in named profiles and grant an admin lease only while making changes.
3. Run a trusted local command with secrets injected into its environment, or allow an agent to make one narrowly scoped HTTP request without seeing the credential.
4. Lock or stop the daemon when the work is finished.

The important distinction is who receives the plaintext.
Your selected child process can receive it when that is the intended action.
An AI agent never does.

## Quick start

Install the current release on macOS or Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/Thanhbinh1905/envault/main/install.sh | sh
```

The installer detects your platform, verifies the downloaded archive's SHA-256 checksum, and installs the binaries into `$HOME/.local/bin`.
For Windows, source installation, upgrades, and manual checksum verification, read the [installation guide](docs/INSTALLATION.md).

### Optional desktop app for Linux

The separate Linux desktop app provides tray-driven vault management.

```sh
curl -fsSL https://raw.githubusercontent.com/Thanhbinh1905/envault/main/crates/envault-desktop/install-linux.sh | sh
```

See the [Linux desktop installation guide](docs/INSTALLATION.md#optional-envault-desktop-for-linux) for supported platforms, AppImage and manual installation, and desktop lifecycle behavior.

Create your vault, start the daemon, and store a first secret in the default `base` profile:

```sh
envault init
envault start
envault admin unlock
printf '%s' "$MY_TOKEN" | envault secret create API_TOKEN --stdin
```

Run a command with the loaded profile's secrets injected only into that child process:

```sh
envault run -- your-command
```

EnVault does not print secret values to the terminal.
Use `envault status` to inspect the daemon state, `envault lock` to lock the vault, and `envault stop` to end the daemon.

### Use EnVault with an agent

Choose one integration for your agent harness.

Install the EnVault Agent Skill when you want on-demand guidance:

```sh
npx skills add Thanhbinh1905/envault --skill envault
```

Or configure the explicit session hook when the harness supports session-start context injection:

```sh
envault session setup
```

Neither integration starts the daemon, authenticates, changes the vault, or receives plaintext credentials.

## Security boundary

EnVault is designed around a small trusted local boundary.

- Secret values and metadata are encrypted at rest.
- The daemon starts through `envault start` or the optional desktop app and fails closed while stopped or locked.
- Passwords are prompted securely or read from standard input, never accepted as command-line arguments or environment variables.
- An admin lease is required for mutations, plaintext reveal, and plaintext export.
- Encrypted profile and workspace packages are previewed before import and committed only with the returned plan hash.

Read the [threat model](docs/threat-model.md) before allowing an agent to use the broker.
It explains the protection boundary, residual risks, and the cases EnVault deliberately does not claim to solve.

## Command reference

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
| `secret value set <name>` | Overwrite a secret's value in place (no history retained) | admin lease | `-s, --stdin` (required) |
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
| `portability export` | Export the whole vault to an encrypted `.envault-workspace` package | admin lease | `-O, --output-file <path>` (required); `-t/-s` transfer password; `-a, --age-recipient` |
| `portability import <file>` | Import a `.envault-workspace` package (preview-first) | admin lease | `-t/-s` transfer password; `-S, --strategy`; `-c, --commit` + `-H, --plan-hash` |
| `config export` | Export the vault (or a scoped slice of it) as plaintext YAML, plaintext `.env`, or an encrypted package | admin lease | `-F, --format <yaml\|env\|encrypted>`; `-k, --kind <vault\|profile\|workspace>`; `-n, --name <name>` (repeatable); `-d, --output-dir <dir>` (default `.`); `-f, --file-name <name>` |
| `config import <file>` | Import a `config export` file (preview-first, commit with the returned plan hash) | admin lease | `-F, --format <yaml\|env\|encrypted>`; `-S, --strategy`; `-c, --commit` + `-H, --plan-hash` |
| `workspace create <name>` | Create a workspace to group profiles | admin lease | - |
| `workspace list` / `workspace show <name>` | List workspaces / show its member profiles | unlocked | - |
| `workspace load <name>` | Load every profile in a workspace | admin lease | - |
| `workspace bind <workspace> <profile>` / `unbind <workspace> <profile>` | Add or remove a profile's membership in a workspace | admin lease | - |
| `workspace delete <name>` | Delete a workspace (must have no remaining members) | admin lease | - |
| `load` | Load the profiles/workspaces listed in this directory's `.envault.toml`, unloading anything this same directory previously auto-loaded that's no longer listed | admin lease | - |
| `unload` | Unload everything `load` previously auto-loaded for this directory | admin lease | - |
| `request http <url>` | Make an outbound HTTP request using a secret as a header/query value, without exposing it | unlocked | `-s, --secret <profile.name>`; `-m, --method`; `-b, --body-file`; `-f, --full` |
| `convenience-unlock enable` | Store the master password in the OS keyring so `start` doesn't need to prompt | password | `-p, --password-stdin`; `-a, --acknowledge-os-keystore` (required) |
| `convenience-unlock disable` / `status` | Remove the stored password / check whether it's enabled | none | - |
| `session context` | Print daemon state for an agent's session hook (no secret material) | none | - |
| `session setup` | Install the session hook into an agent harness's settings file | none | `-s, --settings-file <path>` |
| `uninstall` | Delete the vault, daemon runtime state, and any stored convenience-unlock credential (does not remove the installed binaries) | password | `-p, --password-stdin`; `--yes`; `--skip-backup`; `-O, --backup-path <path>` |

</details>

## License

Licensed under either the Apache License, Version 2.0 or the MIT license.
