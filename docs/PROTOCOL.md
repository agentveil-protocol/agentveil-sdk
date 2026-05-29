# AVP Protocol Specification v0.1

## Overview

AVP helps teams control risky AI agent actions: check pre-runtime risk,
gate execution, and prove what happened with signed receipts. The public
protocol combines cryptographic identity, peer reputation, and signed evidence.

## Agent Identity

Every agent has a W3C DID (did:key) based on Ed25519.

DID format: did:key:z{base58(multicodec_prefix + public_key)}
Multicodec prefix for Ed25519: 0xED01

Keys stored locally: ~/.avp/agents/{name}.json (chmod 0600)

## Authentication

All authenticated write operations are signed. Authenticated requests with
query parameters use AVP-Sig v2 so query values are covered by the signature.

Authorization: AVP-Sig did="...", ts="...", nonce="...", sig="..."

AVP-Sig v1 covers:

{METHOD}:{PATH}:{timestamp}:{nonce}:{sha256(body)}

AVP-Sig v2 adds canonical query binding:

Authorization: AVP-Sig v="2",did="...",ts="...",nonce="...",sig="..."

v2:{METHOD}:{PATH}:{canonical_query}:{timestamp}:{nonce}:{sha256(body)}

The canonical query string is built by decoding query parameters, preserving
repeated and blank values, sorting by key and value, then percent-encoding with
spaces as `%20`.

This prevents replay attacks and request tampering.

## Attestations

Structure:
- from_did: attesting agent
- to_did: attested agent
- outcome: positive | negative | neutral
- weight: 0.0 - 1.0
- context: task category
- evidence_hash: sha256 of interaction log (required for negative)
- signature: Ed25519 signature of attestation payload

## Agent Cards

Machine-readable capability declarations:
- did: agent identifier
- display_name: human readable name
- capabilities: list of skill tags
- provider: underlying model provider
- endpoint: optional HTTP endpoint

## Reputation

Reputation scores are computed server-side using
peer attestations as input. Scores range from 0.0 to 1.0.
Per-category tracks are supported.

## Verifiable Credentials and Proof Artifacts

AVP exposes multiple signed evidence formats. Each format has a specific
verification path.

| Artifact | Format | Signature / proof | Verification |
|----------|--------|-------------------|--------------|
| Reputation credential | AVP JSON | Ed25519-signed AVP JSON | `AVPAgent.verify_credential(...)` |
| Reputation credential | W3C VC | W3C VC v2.0 Data Integrity (`eddsa-jcs-2022`) | `AVPAgent.verify_w3c_credential(...)` or compatible verifier |
| DelegationReceipt v1 | W3C VC | W3C VC v2.0 Data Integrity (`eddsa-jcs-2022`) | `verify_delegation(...)` or standalone verifier |
| Runtime DecisionReceipt | JCS JSON | W3C Data Integrity `DataIntegrityProof` / `eddsa-jcs-2022` (`decision_receipt/3`; legacy `/1`,`/2` were raw-JCS) | `verify_eddsa_jcs_2022(...)` for `/3`; legacy `/1`,`/2` via `verify_signed_jcs(...)` |
| HumanApprovalReceipt | JCS JSON | Ed25519-signed JCS (`human_approval_receipt/2`) | `verify_signed_jcs(...)` or `verify_proof_packet(...)` |
| ExecutionReceipt | JCS JSON | Ed25519-signed JCS (`execution_receipt/2`) | `verify_signed_jcs(...)` or `verify_proof_packet(...)` |

Offline verification does not require server access.

## Starter Floor Semantics (Reputation)

Newly-registered agents start with a pinned displayed score of **0.25**
(`is_starter_score = true`, `algorithm_ver = "starter_v1"`). The floor
persists until the agent **graduates**:

- graduation requires **>= 3 trusted attesters** (attesters whose own
  `flow_score > 0`), and
- the raw computed signal crosses above the floor on the next batch
  recompute cycle.

While the floor is active, reputation-related API responses
(`GET /v1/reputation/{did}`, `GET /v1/reputation/{did}/trust-check`)
expose explicit explainability fields:

- `score` — the displayed value (pinned at the floor when applicable).
  Kept for backward compatibility; equals `display_score`.
- `display_score` — same as `score`.
- `raw_score` — the pre-floor computed signal, or `null` when the backend
  does not store it separately (current default: `null` while floor applied).
- `floor_applied` — boolean, `true` iff the displayed score diverges from
  the raw signal because of the starter floor.
- `floor_reason` — human-readable explanation when `floor_applied = true`.

Decision semantics are unchanged: trust decisions (`allowed`, `tier`,
`risk_level`) derive from the gated score. Negative attestations during
the floor window still affect risk signals and tier computation, even
when the displayed `score` does not visibly drop.

## What This Spec Covers

This document covers the public protocol interface:
identity format, authentication scheme, attestation
structure, and credential format.

Internal reputation algorithms, sybil detection logic,
and dispute resolution mechanisms are proprietary
implementations not covered by this specification.
