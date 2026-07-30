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
- Portability package tampering, hostile KDF parameters, wrong transfer credentials, stale preview-to-commit state, and partial imports.
- Plaintext `.env` leakage through permissive files, terminal output, logs, replacement races, and unsafe parsing.

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
- A capability-bearing request cannot fall back to ambient service or admin authorization.
- IPC clients and the daemon verify operating-system peer identity, and runtime path handling refuses symbolic-link or non-socket substitution.
- Audit entries are redacted, append-only, and hash-chained.
- Encrypted packages use a fresh transfer key and contain no VMK, plaintext secret value, audit history, grant, token, session, or runtime state.
- Password key slots use Argon2id bounded to 8-128 MiB, one to six iterations, and one to four lanes, and age slots contain only an encrypted transfer key for an X25519 recipient.
- Import preview is non-mutating, commit requires the exact keyed plan hash, and accepted mutations use one immediate SQLite transaction.
- Profile replacement rejects policy-resource orphaning, and the import transaction validates vault, scope, and secret policy targets before commit.
- A successful encrypted package commit revokes all in-memory agent capability sessions before returning success.
- Import validates every transferred DEK and value ciphertext before mutation, re-wraps every DEK under the destination VMK, and re-encrypts value ciphertext only when authenticated-data identifiers change.
- `.env` scanning never evaluates shell syntax, interpolation, command substitution, or includes.
- Plaintext export never writes values to stdout or a hidden temporary file and creates the explicit private destination without replacing an existing path.
- Plaintext export verifies the synchronized destination inode and never deletes a concurrently replaced path during error handling.

## Residual risks

An agent can misuse a capability that is too broad even if it cannot read the credential.
Exact-match redaction cannot detect every transformed representation of a secret.
A weak master password lowers the cost of an offline attack despite Argon2id.
Metadata such as ciphertext lengths and timestamps may remain observable.
An admin lease deliberately trusts its originating operating-system login session, so code intentionally run inside that same session shares the ambient lease boundary until it expires or is locked.
An encrypted package remains vulnerable to offline guessing if its transfer password is weak.
Plaintext `.env` import and export deliberately place raw values in human-controlled files outside the vault, so the user must remove or protect those files.

## Verification strategy

Every invariant must be covered by unit, property, integration, adversarial, or release-gate tests.
Claims remain unverified until the corresponding phase exit gate has passed on packaged binaries.
