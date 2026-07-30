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
```

The pinned toolchain is Rust 1.97.1 with Rust Edition 2024.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option.

