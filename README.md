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

Read [the threat model](docs/threat-model.md) for the full security guarantees.

## Status

The project is in early development. No release or crate is published yet.

## Getting started

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the workspace layout, build commands, and CLI usage.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option.
