# Runtime Gate privacy action wire corrective (2026-07-29)

Bounded public sender correction for Runtime Gate outbound `action` only.

## Problem

Private Runtime Gate accepts only dotted wire actions
(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`). Privacy modes previously forwarded
local tokens (`redacted`, `sha256:<hex>`), causing reached HTTP 400 and local
degraded fallback.

## Change

`RuntimeGateClient` now normalizes outbound `action` at the Runtime Gate
boundary from `config.privacy.action`:

- `plain` → local dotted action, byte-identical
- `redacted` → exactly `privacy.redacted`
- `hash` → exactly `privacy.h` + 64 lowercase hex from existing `action_hash`

Local `ClassifiedToolCall`, policy, and evidence metadata are unchanged.
Invalid plain action or malformed/mismatched privacy material fails locally before
HTTP as a terminal `RuntimeGateWireContractError` (subclass of
<!-- claim-check: allow fail-closed is bounded by the zero-HTTP and zero-downstream negative tests -->
`RuntimeGateUntrustedError`; fail-closed, no local fallback).

## Non-goals

- No `ToolCallClassifier` / local privacy representation changes
- No fallback, circuit breaker, receipt verification, or 4xx handling changes
- No private evaluator, billing, KMS, deployment, or source-truth details

## Proof

Focused Runtime Gate, classification, and public wire-contract regressions freeze
the three bounded wire representations and legacy invalid action tokens.
