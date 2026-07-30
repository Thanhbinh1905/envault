# ADR 0006: Agent-Blind Broker

## Status

Accepted on 2026-07-30.

## Decision

Agents discover only policy-filtered metadata and advertised capabilities.
The daemon resolves a credential internally and performs a constrained provider action.
The first adapter is HTTP Bearer with normalized URLs, redirect denial, host, method, path, request-count, response-size, and response-firewall constraints.

## Consequences

There is no `get_secret`, `eval`, or generic `exec` method.
Descriptions are untrusted metadata and never instructions.

