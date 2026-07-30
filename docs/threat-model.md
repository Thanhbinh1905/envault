# Threat Model

## Protected assets

EnVault protects secret plaintext, encrypted metadata, vault keys, capability tokens, policy decisions, and audit integrity from accidental disclosure and unauthorized local clients.

## Trust boundaries

`envaultd` is the trusted computing base.
CLI, TUI, desktop clients, and AI agents are untrusted callers outside the daemon boundary.
The operating system supplies peer identity and filesystem permissions.
External providers receive credentials only through a constrained broker action.

## In-scope threats

- Plaintext secrets committed to repositories, backups, shell history, logs, temporary files, and crash output.
- Agents reading process environments or requesting broad secret access.
- Same-user processes attempting to impersonate a client or replay a capability.
- Database theft while the vault is locked.
- Credential exfiltration through redirects, SSRF, response reflection, and verbose provider errors.
- Local database tampering and partial writes.

## Out-of-scope threats

- Root, kernel compromise, cold-boot attacks, or malware with equivalent privileges to the user.
- A trusted target application intentionally logging credentials after receiving them.
- Provider compromise after a credential reaches that provider.
- Cloud synchronization or account recovery services.

## Security invariants

- There is no generic API that returns a secret to an agent principal.
- Only `envault start` may spawn the daemon.
- A stopped or locked daemon fails closed with a structured error.
- Password input never uses process arguments, positional plaintext, or environment variables.
- Secret names, descriptions, and sensitive metadata are encrypted at rest.
- Each secret value mutation creates a new immutable version with a distinct DEK.
- Deny rules take precedence over allow rules.
- Capability tokens are random, bounded, revocable, stored as hashes in daemon memory, and invalid after daemon shutdown.
- Audit entries are redacted, append-only, and hash-chained.

## Residual risks

An agent can misuse a capability that is too broad even if it cannot read the credential.
Exact-match redaction cannot detect every transformed representation of a secret.
A weak master password lowers the cost of an offline attack despite Argon2id.
Metadata such as ciphertext lengths and timestamps may remain observable.

## Verification strategy

Every invariant must be covered by unit, property, integration, adversarial, or release-gate tests.
Claims remain unverified until the corresponding phase exit gate has passed on packaged binaries.

