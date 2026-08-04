# Security Policy

## Supported versions

The current supported release is `v0.3.0`.
Security properties are defined by the architecture and threat model.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.
Use GitHub private vulnerability reporting for `Thanhbinh1905/envault` once the repository is available.
Include reproduction steps, affected revision, impact, and any suggested mitigation.

## Security boundary

EnVault does not defend against root, kernel compromise, or a full user-session compromise that can replace trusted executables, control the login session, or capture terminal input.
It does enforce peer, lease, and per-secret HTTP access boundaries for untrusted local callers that do not already control those trusted surfaces.
The agent-blind guarantee applies only to actions mediated by a trusted broker.
