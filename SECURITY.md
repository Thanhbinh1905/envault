# Security Policy

## Supported versions

EnVault has not published a supported release yet.
Security properties in the architecture and threat model are design targets until their exit gates are verified.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.
Use GitHub private vulnerability reporting for `Thanhbinh1905/envault` once the repository is available.
Include reproduction steps, affected revision, impact, and any suggested mitigation.

## Security boundary

EnVault does not defend against root, kernel compromise, or malware with equivalent privileges to the current user.
The agent-blind guarantee applies only to actions mediated by a trusted broker.

