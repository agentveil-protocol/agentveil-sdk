# Control artifact writer hardening (P2-11)

Date: 2026-07-29
Slice: `public-control-artifact-writer-hardening`
Repo: public SDK

## Problem

Local Approval Center / control writers could follow a pre-created target or
temp symlink and overwrite a victim file outside the control directory. Parent
directories could also be left with permissive modes (e.g. `0755`) under a
relaxed umask.

## Scope

Hardened writers only:

1. `save_manifest` (`approval/persistent.py`)
2. `publish_owner_claim` (`approval/server.py`)
3. `write_hook_runtime_binding` (`client_guidance.py`)

Shared custody helper: `agentveil_mcp_proxy/control_artifacts.py` (narrow; not a
generic filesystem framework).

## Guarantees

- Control parent directories are created as real directories owned by the current
  user with mode `0700`. Existing parents that are symlinks, non-directories,
  wrong-owner, or any mode other than `0700` are rejected with a bounded error (no silent
  chmod repair of an unsafe existing parent). Ancestors are not chmod'd.
- Published files use mode `0600` from the first written byte (`O_EXCL` create +
  `fchmod` where available). Owner-claim rewrite sets and verifies `0600` after
  lock acquisition and before truncate/write of secrets.
- Target and temp paths are opened with `O_NOFOLLOW` / `lstat` checks; symlink,
  non-regular, wrong-owner, and hardlinked claim targets are rejected.
- Manifest and binding publish via exclusive temp + `fsync` + atomic `replace` +
  directory `fsync`. Owner-claim publish writes the full payload, fsyncs the
  file, and fsyncs the claim directory. Short/zero write and fsync failures are
  not treated as successful publication.
- Owner-claim publish keeps the process-held OS lock; truncate/write happens only
  after exclusive lock acquisition. Concurrent same-claim publish has exactly one
  winner.
- Bounded errors (`control_artifact_write_failed` / directory codes) carry no
  tokens, paths, payloads, or tracebacks. Manifest/binding JSON field sets are
  unchanged.

## Non-goals

- No changes to passthrough, manager, evidence, policy, classification, package
  metadata, or workflows.
- Public release requires P2-11 to be merged first.
