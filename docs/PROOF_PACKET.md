# Proof Packet Guide

A Proof Packet is a per-action evidence bundle for a controlled action. It
collects the DelegationReceipt, signed Runtime Gate DecisionReceipt, signed
ExecutionReceipt, optional HumanApprovalReceipt, and optional remediation
context into one JSON-serializable object.

Use a Proof Packet after `controlled_action(...)` returns `status="executed"`
or when you need to preserve the evidence around a blocked decision. For
approval flows, include the signed HumanApprovalReceipt before treating the
packet as fully verifiable approval evidence. A customer, auditor, or partner
can verify the packet offline with trusted backend signer DID(s).

Proof Packets are different from the audit-chain walkthrough in
[`examples/proof_pack/`](../examples/proof_pack/). A Proof Packet is one
controlled-action evidence bundle. The audit-chain walkthrough verifies
tamper resistance of audit events across a trail.

## Build

```python
def build_proof_packet(
    self,
    delegation_receipt: dict,
    outcome: ControlledActionOutcome,
    decision_receipt_jcs: str | None = None,
    approval_receipt_jcs: str | None = None,
    remediation_case: dict | None = None,
    remediation_refs: list[dict] | None = None,
) -> ProofPacket
```

Parameters:

| Parameter | Meaning |
|---|---|
| `delegation_receipt` | Signed DelegationReceipt authorizing the agent's action scope. |
| `outcome` | `ControlledActionOutcome` returned by `controlled_action(...)` or `execute_after_approval(...)`. |
| `decision_receipt_jcs` | Exact signed Runtime Gate DecisionReceipt JSON text. Recommended for full verification. |
| `approval_receipt_jcs` | Exact signed HumanApprovalReceipt JSON text, when approval was required. |
| `remediation_case` | Optional remediation/dispute context. |
| `remediation_refs` | Optional evidence references associated with remediation. |

The helper does not fetch remote resources or modify signed receipt text. Keep
the exact `*_receipt_jcs` strings returned by the SDK/API.

## Packet Structure

`build_proof_packet(...)` returns a `ProofPacket` object. Call
`packet.to_dict()` before JSON serialization.

| Field | Meaning |
|---|---|
| `agent_did` | Agent DID that requested the controlled action. |
| `base_url` | API base URL used by the SDK identity. |
| `sdk_version` | Installed SDK version that built the packet. |
| `generated_at` | UTC timestamp when the local packet was assembled. |
| `delegation_receipt` | Signed DelegationReceipt dictionary. |
| `outcome_status` | `executed`, `approval_required`, or `blocked`. |
| `audit_id` | Runtime Gate audit id when available. |
| `decision_receipt_jcs` | Exact signed DecisionReceipt JSON text. |
| `decision_receipt` | Parsed convenience copy of the DecisionReceipt. |
| `execution_receipt_jcs` | Exact signed ExecutionReceipt JSON text. |
| `execution_receipt` | Parsed convenience copy of the ExecutionReceipt. |
| `approval` | Parsed approval request metadata when available. |
| `approval_receipt_jcs` | Exact signed HumanApprovalReceipt JSON text. |
| `approval_receipt` | Parsed convenience copy of the approval receipt. |
| `remediation_case` | Optional remediation case metadata. |
| `remediation_refs` | Optional remediation evidence references. |

Hash linkage lives inside the signed receipt bodies. The verifier recomputes
and compares those links, including DelegationReceipt hash, DecisionReceipt
hash, approval hash, and execution linkage when present.

## Save And Reload

```python
import json
from pathlib import Path

path = Path("proof-packet.json")
path.write_text(json.dumps(packet.to_dict(), indent=2), encoding="utf-8")

loaded = json.loads(path.read_text(encoding="utf-8"))
```

Proof Packets are evidence artifacts, not private keys. Store them with normal
evidence-retention controls. For local files containing customer metadata, use
private storage or owner-only file permissions such as `0600`. Do not store
private keys, API tokens, cloud credentials, or passphrases with a packet.

## Verify

```python
from agentveil import verify_proof_packet

verified = verify_proof_packet(
    loaded,
    trusted_decision_signer_dids={decision_signer_did},
    trusted_execution_signer_dids={execution_signer_did},
    trusted_human_approval_signer_dids={approval_signer_did},
)
```

Signature:

```python
def verify_proof_packet(
    packet: object,
    trusted_backend_signer_dids: Iterable[str] | None = None,
    *,
    trusted_decision_signer_dids: Iterable[str] | None = None,
    trusted_execution_signer_dids: Iterable[str] | None = None,
    trusted_human_approval_signer_dids: Iterable[str] | None = None,
) -> dict
```

For deployments that intentionally use one backend signer for all AVP-issued
receipt types, pass `trusted_backend_signer_dids={...}` instead.

On success, the verifier returns:

| Key | Meaning |
|---|---|
| `valid` | Always `True` on success. |
| `decision_receipt` | Verified DecisionReceipt metadata, including signer DID and digest. |
| `approval_receipt` | Verified approval receipt metadata or `None`. |
| `execution_receipt` | Verified ExecutionReceipt metadata or `None`. |
| `delegation_receipt_hash` | Recomputed canonical DelegationReceipt hash. |

`verify_proof_packet(...)` raises `ProofVerificationError` when the packet is
malformed, a signature is invalid, a signer DID is not trusted, required
receipts are missing, or cross-receipt hashes/action fields do not match. It
verifies historical evidence; it does not require a currently unexpired
DelegationReceipt window. `ProofVerificationError` is a `ValueError` subclass;
read the reason with `str(exc)`.

## Common Patterns

| Pattern | Flow | Notes |
|---|---|---|
| Single action proof export | `controlled_action(...)` -> `build_proof_packet(...)` -> save JSON | Keep the exact signed receipt strings. |
| Batch proof export | Build one packet per controlled action, then store an array of packet dictionaries | Do not merge signed receipt strings across actions. |
| Auditor verification | Load JSON -> `verify_proof_packet(...)` -> inspect `valid`, signer DIDs, and digests | The auditor must know the trusted backend signer DID(s). |
| Long-term archival | Store packet JSON with audit-chain reference and release metadata | Retain raw signed receipts exactly as emitted. |

## Error Handling

Catch `ProofVerificationError` separately from API exceptions:

```python
try:
    verified = verify_proof_packet(packet, trusted_backend_signer_dids={trusted_did})
except ProofVerificationError as exc:
    print(str(exc))
```

Common causes include:

| Failure | Recovery |
|---|---|
| Missing DecisionReceipt or ExecutionReceipt | Export the full proof artifacts from the controlled-action flow. |
| Approval path without signed approval receipt | Fetch and include the HumanApprovalReceipt before verification. |
| Untrusted signer DID | Use the correct AVP backend signer DID for the environment. |
| Signature invalid | Treat the packet as tampered or corrupted. Re-export from source artifacts. |
| Hash linkage mismatch | Treat the packet as assembled from mismatched action artifacts. |
| DelegationReceipt invalid | Obtain the original signed DelegationReceipt from the principal. |

## Related Guides

- [Customer Integration](CUSTOMER_INTEGRATION.md) for the full controlled-action flow.
- [DelegationReceipt Guide](DELEGATION_RECEIPT.md) for delegation issuance and offline verification.
- [Registration & Verification](REGISTRATION.md) for agent identity setup.
- [Error Handling](ERRORS.md) for SDK exception and verifier error patterns.
