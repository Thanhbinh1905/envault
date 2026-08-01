# ADR 0015: Workspace as a Dedicated Membership Table

## Status

Accepted.

## Context

Users manage several unrelated profiles for the same project (for example a backend and a frontend profile that should be started, exported, or torn down together).
A profile is independent and can belong to several workspaces at once - "which profiles should load together" is a many-to-many relationship, not a tree.
The scope tree is strictly single-parent and is also where secret inheritance (root -> profile ancestor chain) lives, so reusing a scope node for workspace grouping conflated two unrelated concerns: secret inheritance and "load these together" membership.
A many-to-many relationship cannot be expressed by a single-parent scope tree, so workspace grouping needs its own storage, independent of scope.

## Decision

A workspace is a first-class entity with its own `workspace` table (`id`, `vault_id`, `encrypted_name`, `name_lookup`), entirely decoupled from `scope`.
Membership - which profiles are grouped under a workspace - is a separate `workspace_membership` join table keyed on `(workspace_id, profile_id)`, with no `ON DELETE CASCADE`: deleting a profile that still has membership rows, or deleting a workspace that still has members, fails closed instead of silently cascading.
`ScopeKind` is only `Root | Profile | Project`; profiles always parent at the vault root regardless of workspace membership, and workspaces never hold secrets or act as an inheritance ancestor.

`envault workspace create <name>` creates a `workspace` row.
`envault profile create <name> --workspace <ws>` is sugar for `create_profile` (always root-parented) followed by `workspace bind <ws> <name>`.
`envault workspace bind <ws> <name>` / `workspace unbind <ws> <name>` add or remove a membership row directly, and are the standalone operation to move (or duplicate) a profile's workspace membership after creation - the gap the original version of this ADR flagged as missing.
`envault workspace list` and `envault workspace show <name>` read the `workspace`/`workspace_membership` tables directly, with no scope-subtree traversal involved.
`envault workspace load <name>` adds every profile currently bound to the workspace to the runtime loaded set (see the glossary); it does not change `activate_on_start` - use `profile update --activate-on-start` for that.
`envault workspace delete <name>` requires the workspace to have no remaining members.

## Consequences

Workspace membership is a plain join query, with no override, tombstone, or subtree-traversal semantics to reason about - secret resolution is unaffected and continues to run only over the scope-parent chain.
A profile can belong to any number of workspaces simultaneously; binding or unbinding one workspace's membership never touches the profile's own scope or its membership in any other workspace.
Renaming or deleting a workspace only ever touches the `workspace` table; it never renames or deletes a profile or scope.
