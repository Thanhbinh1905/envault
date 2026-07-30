# EnVault

EnVault is a local-first encrypted secret vault for developers and AI agents.
It lets trusted local brokers use credentials without exposing plaintext values to an agent.

The project is in early development.
No release or crate is published yet.

## Security model

EnVault uses an explicit daemon lifecycle and denies access by default.
Only `envault start` may launch the daemon.
Agent principals can receive narrow, expiring capabilities but can never receive admin actions, plaintext export, reveal, or generic execution.

Read [the threat model](docs/threat-model.md) before relying on EnVault.

## Workspace

The Rust workspace separates domain, crypto, storage, policy, protocol, platform, broker, and executable concerns.
CLI and TUI code must access secrets through application services and IPC, never through crypto or storage directly.

## Development

```sh
cargo xtask verify
cargo xtask package-verify
```

Run `cargo xtask sync-contract` after intentionally changing the canonical `commands.toml`, then rerun both verification commands.

The pinned toolchain is Rust 1.97.1 with Rust Edition 2024.

## Bootstrap

Initialize a vault from an interactive masked terminal prompt:

```sh
cargo run -p envault -- init
```

Automation may provide the master password only through piped standard input:

```sh
read -r -s bootstrap_password
printf '%s\n' "$bootstrap_password" | cargo run -p envault -- init --password-stdin
unset bootstrap_password
```

The shell variable is not exported and is never read as an environment input by EnVault.
Do not place a real password directly in shell history.

Build the complete executable set before running from a development checkout:

```sh
cargo build -p envault --bins
```

Start the authenticated daemon from a masked terminal prompt:

```sh
target/debug/envault start
```

Automation may use `start --password-stdin` with the same safe input constraints as initialization.
Use `envault status`, `envault lock`, and `envault stop` for explicit lifecycle control.
Use `envault admin unlock --minutes 5`, `envault admin status`, and `envault admin lock` for the bounded admin lease.
Profile, versioned secret, policy-filtered agent discovery, capability inspection, and constrained HTTP broker workflows run only through daemon IPC.

## Encrypted portability

Export a profile with a masked transfer password:

```sh
target/debug/envault profile export base \
  --output-file ./base.envault-profile \
  --transfer-password
```

Use one or more public age X25519 recipients instead of, or in addition to, the transfer password:

```sh
target/debug/envault workspace export \
  --output-file ./workspace.envault-workspace \
  --age-recipient "$AGE_RECIPIENT"
```

Imports are preview-first and never commit without the exact returned plan hash:

```sh
target/debug/envault workspace import ./workspace.envault-workspace \
  --transfer-password

target/debug/envault workspace import ./workspace.envault-workspace \
  --transfer-password \
  --strategy abort \
  --commit \
  --plan-hash PLAN_HASH_FROM_PREVIEW
```

Transfer passwords are accepted only from a masked terminal or piped standard input.
Age identity files and plaintext `.env` input files must be stable private files on Unix.
Encrypted package files and plaintext export files are created without replacement at mode `0600` on Unix.

Preview and atomically import a private `.env` file into one profile:

```sh
target/debug/envault profile import-env base ./.env --strategy abort
```

Plaintext export is a human-only recovery escape hatch that requires an active admin lease, an explicit acknowledgement, and a new destination path:

```sh
target/debug/envault profile export-env base \
  --output-file ./recovery.env \
  --allow-plaintext
```

Never commit plaintext exports or transfer passwords to a repository or shell history.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option.
