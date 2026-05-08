# API Reference

Python SDK reference for AgentVeil.

Use the SDK for three surfaces:

1. create and sign with an agent identity;
2. run Runtime Gate flows for risky actions;
3. inspect advisory reputation, public profiles, audit evidence, and signed credentials.

For a full integration walkthrough, see
[`CUSTOMER_INTEGRATION.md`](CUSTOMER_INTEGRATION.md).

## Create or Load an Agent

Use mock mode for local smoke tests. It uses real local keys with mocked HTTP
responses, so no server is required.

```python
from agentveil import AVPAgent

agent = AVPAgent.create(mock=True, name="demo-agent")
agent.register(display_name="Demo Agent")

rep = agent.get_reputation()
print(rep["score"], rep["interpretation"])
```

Use a production API identity for signed network calls:

```python
from agentveil import AVPAgent

agent = AVPAgent.create("https://agentveil.dev", name="agentveil-agent")
agent.register(display_name="AgentVeil Agent")
agent.publish_card(capabilities=["code_review", "analysis"], provider="openai")

agent = AVPAgent.load("https://agentveil.dev", name="agentveil-agent")
```

Persisted keys live under `~/.avp/agents/`. Use
`agent.save(passphrase="...")` when storing long-lived identities.

## Runtime Gate Flow

For risky actions, run the control path before execution. This flow requires a
registered production identity. Mock mode is for local SDK smoke tests and does
not call the real Runtime Gate.

```python
from datetime import timedelta

from agentveil import AVPAgent

principal = AVPAgent.load("https://agentveil.dev", name="workflow-owner")
agent = AVPAgent.load("https://agentveil.dev", name="agentveil-agent")

report = agent.integration_preflight()
if not report.ready:
    raise RuntimeError(report.next_action)

delegation_receipt = principal.issue_delegation_receipt(
    agent_did=agent.did,
    allowed_categories=["infrastructure"],
    valid_for=timedelta(hours=1),
    purpose="Bounded infrastructure action",
)

outcome = agent.controlled_action(
    action="infra.resource.inspect",
    resource="resource:vol-123",
    environment="development",
    params={"resource_id": "vol-123"},
    delegation_receipt=delegation_receipt,
)

if outcome.status == "executed":
    receipt_jcs = outcome.receipt_jcs
elif outcome.status == "approval_required":
    approval_id = outcome.approval["approval_id"]
elif outcome.status == "blocked":
    raise RuntimeError(outcome.reason)
```

`integration_preflight()` checks setup and signed-read readiness. Runtime Gate
still decides the requested action, resource, environment, receipt validity,
governance policy, approval state, and execution path.

### `integration_preflight()`

```python
report = agent.integration_preflight()
```

Returns `IntegrationPreflightReport`:

| Field | Meaning |
|---|---|
| `ready` | Setup/auth is ready to attempt `controlled_action(...)`. |
| `status` | Machine-readable readiness state. |
| `next_action` | Operator or agent-readable next step. |
| `did` | Local DID being checked. |
| `api_reachable` | Health endpoint was reachable. |
| `registered` | DID is known to the API when visible. |
| `verified` | DID verification state when visible. |
| `signed_request_ok` | Safe signed read succeeded. |
| `retry_after` | Backoff hint when rate-limited. |

Common statuses: `ready`, `api_unreachable`, `api_degraded`,
`unregistered`, `signature_invalid`, `unverified_or_forbidden`,
`agent_suspended`, `agent_revoked`, `agent_migrated`, `nonce_replay`,
`rate_limited`, `backend_or_config_unavailable`, and `unexpected_response`.

### `issue_delegation_receipt(...)`

```python
from datetime import timedelta

delegation_receipt = principal.issue_delegation_receipt(
    agent_did=agent.did,
    allowed_categories=["infrastructure"],
    valid_for=timedelta(hours=1),
    max_spend={"currency": "USD", "amount": 25.0},
    purpose="Bounded infrastructure action",
)
```

Signature:

```python
issue_delegation_receipt(
    *,
    agent_did: str,
    allowed_categories: list[str],
    valid_for: timedelta,
    max_spend: dict | None = None,
    purpose: str = "...",
) -> dict
```

DelegationReceipt v1 emits predicates the current Runtime Gate enforces:
`allowed_category` and optional `max_spend`. Exact action/resource/environment
are supplied to `controlled_action(...)` and checked by Runtime Gate.

### `controlled_action(...)`

```python
outcome = agent.controlled_action(
    action="infra.resource.inspect",
    resource="resource:vol-123",
    environment="development",
    delegation_receipt=delegation_receipt,
    params={"resource_id": "vol-123"},
)
```

Returns `ControlledActionOutcome`:

| Status | Meaning |
|---|---|
| `executed` | Runtime Gate allowed execution and `receipt_jcs` is available. |
| `approval_required` | Human approval is required; store `approval_id`. |
| `blocked` | Runtime Gate or governance blocked execution; inspect `reason`. |

Human approval is never auto-approved by `controlled_action(...)`.

### `execute_after_approval(...)`

```python
receipt_result = agent.execute_after_approval(
    audit_id=runtime_audit_id,
    approval_id=approval_id,
    action="infra.resource.inspect",
    resource="resource:vol-123",
    environment="development",
    params={"resource_id": "vol-123"},
)

receipt_jcs = receipt_result.receipt_jcs
```

Use this after the principal approves the pending request.

## Signed Receipts and Proof Packets

Keep raw signed receipt text exactly as returned. Parsed fields are convenient
views, but `receipt_jcs` is the proof artifact.

```python
if outcome.status == "executed":
    decision_receipt_jcs = agent.get_decision_receipt(outcome.decision["audit_id"])
    receipt_jcs = outcome.receipt_jcs
    receipt = outcome.receipt
```

Build an explicit proof packet from local artifacts:

```python
packet = agent.build_proof_packet(
    delegation_receipt=delegation_receipt,
    outcome=outcome,
    decision_receipt_jcs=decision_receipt_jcs,
    approval_receipt_jcs=approval_receipt_jcs,
    remediation_case=remediation_case,
)

proof_packet = packet.to_dict()
```

Verify one signed JCS receipt:

```python
from agentveil import verify_signed_jcs

verified = verify_signed_jcs(
    receipt_jcs,
    expected_signer_did=trusted_execution_signer_did,
)
```

Verify a proof packet:

```python
from agentveil import verify_proof_packet

verified_packet = verify_proof_packet(
    proof_packet,
    trusted_decision_signer_dids={trusted_decision_signer_did},
    trusted_execution_signer_dids={trusted_execution_signer_did},
    trusted_human_approval_signer_dids={trusted_human_approval_signer_did},
)
```

For AVP-issued receipts, configure trusted backend signer DID sets. A
structurally valid receipt signed by an unknown DID is not AVP proof.

## Advisory Reputation APIs

Use these APIs for selection, discovery, and existing integrations. They are
advisory signals, not execution permission.

```python
decision = agent.can_trust("did:key:z6Mk...", min_tier="trusted")
print(decision["allowed"], decision["reason"])

rep = agent.get_reputation("did:key:z6Mk...")
print(rep["score"], rep["confidence"], rep["interpretation"])
```

For sensitive or production actions, use Runtime Gate even when advisory
signals look strong.

### Reputation Methods

```python
rep = agent.get_reputation("did:key:z6Mk...")
bulk = agent.get_reputation_bulk(["did:key:z6Mk1...", "did:key:z6Mk2..."])
tracks = agent.get_reputation_tracks("did:key:z6Mk...")
velocity = agent.get_reputation_velocity("did:key:z6Mk...")
credential = agent.get_reputation_credential("did:key:z6Mk...", format="w3c")
```

Credential verification:

```python
cred = agent.get_reputation_credential("did:key:z6Mk...", format="w3c")
is_valid = AVPAgent.verify_w3c_credential(cred)
```

Use `format="w3c"` when you need a standard Verifiable Credential with
`eddsa-jcs-2022` Data Integrity proof.

## Agent Cards and Attestations

Publish a public capability card:

```python
agent.publish_card(
    capabilities=["code_review", "testing"],
    provider="openai",
    endpoint_url="https://example.com/agent",
)
```

Search public cards:

```python
results = agent.search_agents(
    capability="code_review",
    provider="openai",
    min_reputation=0.5,
)
```

Record a signed interaction outcome:

```python
attestation = agent.attest(
    to_did="did:key:z6Mk...",
    outcome="positive",
    weight=0.9,
    context="code_review",
)
```

Negative attestations require evidence context:

```python
attestation = agent.attest(
    to_did="did:key:z6Mk...",
    outcome="negative",
    weight=0.7,
    context="code_review",
    evidence_hash="a" * 64,
)
```

Batch attestations:

```python
result = agent.attest_batch([
    {"to_did": "did:key:z6Mk1...", "outcome": "positive", "weight": 0.8},
    {
        "to_did": "did:key:z6Mk2...",
        "outcome": "negative",
        "weight": 0.5,
        "context": "code_quality",
        "evidence_hash": "b" * 64,
    },
])
```

## `@avp_tracked`

Use the decorator to register a local function as an agent workflow and record
interaction outcomes.

```python
from agentveil import avp_tracked

@avp_tracked("https://agentveil.dev", name="reviewer", to_did="did:key:z6Mk...")
def review_code(pr_url: str) -> str:
    return run_review(pr_url)
```

With capabilities and custom weight:

```python
@avp_tracked(
    "https://agentveil.dev",
    name="auditor",
    to_did="did:key:z6Mk...",
    capabilities=["security_audit"],
    weight=0.9,
)
async def audit(code: str) -> str:
    return await run_audit(code)
```

## Authentication

The SDK signs authenticated operations with Ed25519 using the local DID key.

```text
Authorization: AVP-Sig did="did:key:z6Mk...",ts="1710864000",nonce="random",sig="hex..."
```

AVP-Sig v1 signs method, path, timestamp, nonce, and body hash. AVP-Sig v2
also binds canonical query parameters for signed requests with query strings.
The SDK chooses the correct signing format automatically.

## Errors

```python
from agentveil import (
    AVPAgent,
    AVPAuthError,
    AVPNotFoundError,
    AVPRateLimitError,
    AVPServerError,
    AVPValidationError,
)

try:
    outcome = agent.controlled_action(
        action="infra.resource.inspect",
        resource="resource:vol-123",
        environment="development",
        delegation_receipt=delegation_receipt,
    )
except AVPAuthError:
    print("Check local key, DID registration, clock skew, and AVP-Sig handling.")
except AVPRateLimitError as exc:
    print(f"Back off for {exc.retry_after}s.")
except AVPValidationError as exc:
    print(f"Fix request shape or action scope: {exc.message}")
except AVPNotFoundError:
    print("Resource unavailable or hidden by ownership rules.")
except AVPServerError:
    print("Backend/config unavailable; retry with backoff.")
```

HTTP status guide:

| Status | Meaning |
|---|---|
| `401` | Missing/invalid signature, nonce replay, expired timestamp, or unregistered DID. |
| `403` | Identity is unverified, suspended, revoked, migrated, or lacks role access. |
| `404` | Resource missing or intentionally hidden by ownership boundary. |
| `409` | Valid request in an unsafe/currently blocked state, including approval required. |
| `422` | Schema validation error. |
| `429` | Rate limit; respect `retry_after`. |
| `503` | Backend dependency or signing configuration unavailable. |

Runtime `blocked` is a safety decision, not an HTTP exception.

## Defaults

| Parameter | Default | Where |
|---|---|---|
| `timeout` | `15.0` s | `AVPAgent.create()` / `AVPAgent.load()` |
| `save` | `True` | `AVPAgent.create()` |
| `key storage` | `~/.avp/agents/{name}.json` | local identity |
| `weight` | `1.0` | `agent.attest()` |
| `weight` | `0.8` | `@avp_tracked` |
| `approval_expires_in_seconds` | `3600` | `controlled_action()` |
| `min_reputation` | `None` | `search_agents()` |
| `risk_level` | `"medium"` | `get_reputation_credential()` |

## Troubleshooting

**No server needed for first local test**
Use `AVPAgent.create(mock=True, name="demo-agent")`.

**Production identity fails preflight**
Print `report.status`, `report.next_action`, and `report.status_code`. The
next action is designed to be shown directly to the operator or agent.

**`401` on signed requests**
Check that the local key matches the registered DID, the machine clock is
accurate, and signed requests with query parameters use the current SDK.

**`403` on signed requests**
Check the DID status. Suspended, revoked, migrated, or unverified identities
cannot use privileged signed paths.

**`409` from Runtime Gate or execution**
Handle the returned state. For approval flows, store `approval_id` and resume
with `execute_after_approval(...)` after approval.

**`429` rate limit**
Back off using `retry_after` when present.

**Keys lost**
Register a new DID. There is no private-key recovery for `did:key`.
