# DelegationReceipt Guide

A DelegationReceipt is a signed authorization from a workflow owner or
principal to an agent. It says which agent may request a bounded class of
actions, for what purpose, and during which validity window. The receipt is
signed locally by the principal and can be verified offline.

Use a DelegationReceipt when an agent needs authority evidence for deployment,
infrastructure, financial, or other risky actions. The receipt does not execute
anything by itself; `controlled_action(...)` and the Runtime Gate still evaluate
the requested action, resource, environment, policy, and approval state.

## Issue

```python
def issue_delegation_receipt(
    self,
    *,
    agent_did: str,
    allowed_categories: list[str],
    valid_for: datetime.timedelta,
    max_spend: dict[str, object] | None = None,
    purpose: str = "Controlled-action delegation",
) -> dict[str, object]
```

Parameters:

| Parameter | Meaning |
|---|---|
| `agent_did` | `did:key` of the agent receiving delegated authority. |
| `allowed_categories` | One or more runtime categories, such as `deploy` or `infrastructure`. |
| `valid_for` | Positive `timedelta` validity window from issue time. |
| `max_spend` | Optional cap shaped as `{"currency": "USD", "amount": 100}`. |
| `purpose` | Human-readable audit note. It is signed, but not used as a policy rule. |

`issue_delegation_receipt(...)` raises `ValueError` for invalid scope values
and `TypeError` for unexpected arguments. Current v1 receipts support
`allowed_category` and optional `max_spend` predicates. Exact
`allowed_actions`, `allowed_resources`, and `allowed_environments` are supplied
to `controlled_action(...)` and checked there.

## Receipt Fields

The returned receipt is a W3C VC v2.0 dictionary:

| Field | Meaning |
|---|---|
| `@context` | Includes W3C VC v2 and AgentVeil delegation v1 contexts. |
| `type` | Includes `VerifiableCredential` and `AgentDelegation`. |
| `id` | Receipt identifier, usually `urn:uuid:...`. |
| `issuer` | Principal DID that signed the receipt. |
| `validFrom` / `validUntil` | UTC validity window. |
| `credentialSubject.id` | Agent DID receiving delegated authority. |
| `credentialSubject.scope` | Signed scope predicates. |
| `credentialSubject.purpose` | Signed human-readable purpose. |
| `proof` | `eddsa-jcs-2022` DataIntegrityProof over the canonical receipt body. |

## Verify

```python
verification = agent.verify_delegation_receipt(receipt)
```

On success, `verify_delegation_receipt(...)` returns:

```python
{
    "valid": True,
    "issuer": "did:key:...",
    "subject": "did:key:...",
    "scope": [...],
    "purpose": "...",
    "valid_from": datetime.datetime(...),
    "valid_until": datetime.datetime(...),
    "id": "urn:uuid:...",
}
```

The verifier is offline: it does not call the AgentVeil API. Invalid receipts
raise `agentveil.delegation.DelegationInvalid` with a `.reason` string such as
`delegation expired`, `signature verification failed`,
`verificationMethod does not match issuer`, or `invalid scope: ...`.

## Common Patterns

| Pattern | Scope shape | Notes |
|---|---|---|
| Short-lived deploy delegation | `allowed_categories=["deploy"]`, `valid_for=timedelta(minutes=15)` | Good default for release workflows and CI jobs. |
| Multi-resource delegation | `allowed_categories=["deploy", "infrastructure"]` | The receipt authorizes categories; exact action/resource/environment are checked by `controlled_action(...)`. |
| Approval-required delegation | `allowed_categories=["infrastructure"]`, short validity | Delegation supplies authority evidence; policy can still return `approval_required`. |
| Long-lived service delegation | `valid_for=timedelta(days=7)` or similar | Use sparingly. Prefer short windows and rotate receipts when automation allows. |

## File Persistence

DelegationReceipts are JSON-compatible dictionaries. Store the exact JSON object,
then reload it before calling `verify_delegation_receipt(...)` or
`controlled_action(...)`.

```python
import json
from pathlib import Path

path = Path("delegation-receipt.json")
path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

loaded = json.loads(path.read_text(encoding="utf-8"))
assert agent.verify_delegation_receipt(loaded)["valid"] is True
```

Do not store the principal private key with the receipt. The receipt is intended
to be shareable authority evidence; the key that issued it is not.

## Controlled Action Flow

After verification, pass the receipt to `controlled_action(...)`:

```python
outcome = agent.controlled_action(
    action="deploy.release",
    resource="service:billing-api",
    environment="production",
    delegation_receipt=receipt,
)
```

If `outcome.status == "executed"`, retain the signed receipt and export a proof
packet with `agent.build_proof_packet(...)`. If the status is
`approval_required`, route the approval to the principal and resume with
`execute_after_approval(...)`.

See [Customer Integration](CUSTOMER_INTEGRATION.md) for the full runtime path
and [examples/delegation](../examples/delegation/) for runnable offline
DelegationReceipt examples.
