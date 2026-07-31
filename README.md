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
Agent principals can receive narrow, short-lived capabilities scoped to exactly what they need, but they can never request admin actions, plaintext export, reveal, or arbitrary execution.
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

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option.
