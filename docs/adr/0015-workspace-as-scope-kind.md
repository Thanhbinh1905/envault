# ADR 0015: Workspace as a Reused Scope Kind

## Status

Accepted for Phase 2.

## Context

Users manage several unrelated profiles for the same project (for example a backend and a frontend profile that should be started, exported, or torn down together).
The scope tree already reserved a `ScopeKind::Workspace` variant, alongside `Root`, `Profile`, and `Project`, but nothing in the codebase constructed one.
Adding a real grouping table or a parallel container concept would duplicate the scope tree's existing parent-child, override, and subtree-traversal machinery for no new capability.

## Decision

A workspace is an ordinary scope node with `ScopeKind::Workspace`, created with `create_scope(root_scope_id, ScopeKind::Workspace, label)`.
No new database table, column, or resolution algorithm is introduced.

`envault workspace create <name>` creates the scope.
`envault profile create <name> --workspace <ws>` binds the new profile's scope under the workspace scope instead of under the vault root.
`envault workspace list` and `envault workspace show <name>` read the scope and its member profiles through the existing subtree-traversal helper.
`envault workspace load <name>` sets `activate_on_start = true` on every profile in the subtree, reusing the loaded-set mechanism (see the glossary) rather than adding a second runtime state.

There is no standalone command to move a profile into a workspace after creation.
A profile's workspace is fixed at creation time by which parent scope it is bound to.

## Consequences

Workspace membership, override, and tombstone behavior are exactly the pre-existing scope-tree semantics: no separate test surface is needed for "does a workspace override correctly," because it is the same scope-chain resolution already covered for profiles.
Renaming or deleting a workspace is renaming or deleting its scope, subject to the same non-empty and root-scope protections as any other scope.
A future need to move a profile between workspaces would require a scope re-parenting operation, which does not exist yet.

## Addendum (2026-08-01): workspace load targets the runtime loaded set only

`envault workspace load <name>` now adds every profile in the subtree to the runtime loaded set (see the glossary) instead of setting `activate_on_start = true`.
It no longer changes which profiles auto-load on the next unlock; use `profile update --activate-on-start` for that.
