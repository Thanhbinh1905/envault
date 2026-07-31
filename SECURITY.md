# Security Policy

## Supported versions

The release target is `v0.0.1`; no supported release has been published yet.
It becomes the supported release only when this branch merges into `main` and the `v0.0.1` tag completes the release workflow.
Until that tag is published, treat repository revisions as pre-release builds.
Security properties in the architecture and threat model remain release gates and are not weakened by the pre-release status.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.
Use GitHub private vulnerability reporting for `Thanhbinh1905/envault` once the repository is available.
Include reproduction steps, affected revision, impact, and any suggested mitigation.

## Security boundary

EnVault does not defend against root, kernel compromise, or a full user-session compromise that can replace trusted executables, control the login session, or capture terminal input.
It does enforce peer, lease, policy, and capability boundaries for untrusted local callers that do not already control those trusted surfaces.
The agent-blind guarantee applies only to actions mediated by a trusted broker.
