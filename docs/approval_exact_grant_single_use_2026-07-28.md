# Exact approval grant single-use (2026-07-28)

## Problem

Exact grants were discovered with `find_active_exact_grant` and consumed later by
a separate `write_pending` child insert. Two independent SQLite connections could
both observe the same unconsumed grant before either child existed, producing two
`scope_cache_hit` approvals and two downstream mutations without a fresh confirm.

## Fix

- New durable `exact_grant_claims` table (schema v7) with `grant_request_id` PK.
- `consume_exact_grant_with_pending` selects, claims, and inserts the child pending
  row in one `BEGIN IMMEDIATE` transaction. Insert failure rolls the claim back.
- Migration backfills one claim per historical exact parent (earliest child) and
  tolerates legacy multi-child rows without adding an unsafe unique index on
  `granted_by_request_id`.
- ApprovalManager uses the atomic consume path for exact grants only; similar-scope
  reuse is unchanged.
- Exact-reuse child still persists `action_gate_metadata_jcs` (action_family,
  blast_radius, bounded facts) built before the atomic claim.

## Proof focus

- Cross-connection and process-level races: exactly one winner.
- Passthrough path: exactly one `tools/call` mutation.
- Hook at the read/write boundary proves reservation rollback on failure.
