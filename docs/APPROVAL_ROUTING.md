# Approval Routing

Approval routing is the human-in-the-loop path for a controlled action. The
Runtime Gate can decide that an action is valid but too sensitive to execute
without a principal decision. The SDK surfaces that state as
`outcome.status == "approval_required"`.

Use approval routing when an action has a valid DelegationReceipt but still
needs case-by-case review, such as production deploys, infrastructure changes,
data deletion, or financial operations.

## Lifecycle

```text
controlled_action(...)
  -> Runtime Gate returns WAITING_FOR_HUMAN_APPROVAL
  -> SDK creates an approval request
  -> outcome.status == "approval_required"
  -> principal approves or denies
  -> execute_after_approval(...) resumes only after approval
```

Typical states are:

| State | Meaning | Next step |
|---|---|---|
| `pending` | Approval request exists and is waiting for the principal. | Show it to the approver, poll, or wait for a webhook. |
| `approved` | Principal granted the request. | Call `execute_after_approval(...)`. |
| `denied` | Principal rejected the request. | Do not execute. Surface the reason and stop. |
| `expired` | Approval was not granted before `expires_at`. | Create a fresh controlled action or ask for a new approval. |

Delegation and approval are separate controls. A DelegationReceipt proves the
agent has scoped authority from the owner. Approval is a case-by-case grant for
one sensitive action.

## API Reference

### `controlled_action(...)`

When the Runtime Gate returns `WAITING_FOR_HUMAN_APPROVAL`, the SDK calls
`create_approval(...)` and returns:

```python
ControlledActionOutcome(
    status="approval_required",
    decision=decision,
    approval=approval,
)
```

Use `outcome.approval["approval_id"]` as the approval identifier. The initial
`approval_required` outcome does not populate `outcome.approval_id`.

### `create_approval(...)`

```python
agent.create_approval(
    audit_id: str,
    delegation_receipt: dict,
    expires_in_seconds: int = 3600,
) -> dict
```

Creates or fetches a human approval request for a waiting Runtime Gate
decision. `controlled_action(...)` calls this automatically for the common
path. Use it directly only when your application owns lower-level orchestration.

### `get_approval(...)`

```python
agent.get_approval(approval_id: str) -> dict
```

Fetches the approval request visible to this agent. Use it for polling,
displaying state, or confirming that the principal has acted.

### `approve(...)`

```python
agent.approve(approval_id: str) -> str
```

Approves a request as the principal and returns the exact signed
HumanApprovalReceipt JSON text. Preserve that string if you will build a
Proof Packet.

### `deny(...)`

```python
agent.deny(approval_id: str, reason: Optional[str] = None) -> str
```

Denies a request as the principal and returns the exact signed denial receipt
JSON text. Do not call `execute_after_approval(...)` after denial.

### `execute_after_approval(...)`

```python
agent.execute_after_approval(
    audit_id: str,
    approval_id: str,
    action: str,
    resource: str,
    environment: str,
    params: Optional[dict] = None,
) -> ControlledActionOutcome
```

Resumes a controlled action after the principal approves it. Pass the original
`audit_id`, `action`, `resource`, `environment`, and params from the waiting
decision. The backend checks the approval against that original action before
execution.

## Approval Object Fields

Exact backend responses can include additional metadata, but customer code
should expect these core fields when present:

| Field | Meaning |
|---|---|
| `id` | Approval request identifier. Use this for `get_approval`, `approve`, `deny`, and `execute_after_approval`. |
| `status` | Current approval state, such as `pending`, `approved`, `denied`, or `expired`. |
| `audit_id` | Runtime Gate audit identifier for the waiting decision. |
| `action` | Action name requested by the agent. |
| `resource` | Resource identifier for the action. |
| `environment` | Environment the action targets, such as `production`. |
| `expires_at` | Time after which the approval can no longer be used. |
| `delegation_receipt_hash` | Hash linking the request to the DelegationReceipt evidence. |
| `reason` | Optional denial or failure reason. |

## Common Patterns

| Pattern | Shape | Notes |
|---|---|---|
| Interactive approval | Show the pending request to the principal, then call `approve(...)` or `deny(...)`. | Best for consoles, chatops, and admin tools. |
| Async polling | Call `get_approval(...)` until status is terminal or timeout expires. | Use bounded polling and fail closed on timeout. |
| Webhook-driven approval | External system grants approval, worker resumes with `execute_after_approval(...)`. | Store `audit_id`, `approval_id`, action, resource, environment, and params together. |
| Batch approval | Queue several requests for one review session. | Each action still needs its own approval receipt. |
| CI auto-approval | Principal-controlled CI calls `approve(...)` for explicitly scoped low-risk categories. | Use narrow DelegationReceipts and short approval windows. |

## Minimal Polling Pattern

```python
deadline = time.monotonic() + 300
while time.monotonic() < deadline:
    approval = agent.get_approval(approval_id)
    if approval["status"] == "approved":
        break
    if approval["status"] in {"denied", "expired"}:
        raise RuntimeError(f"approval terminal: {approval['status']}")
    time.sleep(5)
else:
    raise TimeoutError("approval timed out")
```

After approval:

```python
final = agent.execute_after_approval(
    audit_id=runtime_audit_id,
    approval_id=approval_id,
    action=action,
    resource=resource,
    environment=environment,
    params=params,
)
```

## Error Cases

| Case | Signal | Recovery |
|---|---|---|
| Approval expired before grant | `AVPValidationError` with conflict-style message or approval `status="expired"`. | Start a fresh controlled action with a new approval request. |
| Approval denied | Signed denial receipt or approval `status="denied"`. | Do not execute. Surface the denial reason. |
| Network failure during approval call | `httpx.RequestError`. | Retry transport after checking base URL and TLS. |
| Approval not ready | `AVPValidationError` when resuming too early. | Poll or wait for webhook, then retry. |
| Stale or mismatched `approval_id` | `AVPValidationError` or `AVPAuthError`. | Re-fetch the approval and confirm it matches the original action. |

## Evidence Retention

For an approved action, retain:

- DelegationReceipt.
- Runtime Gate DecisionReceipt.
- HumanApprovalReceipt returned by `approve(...)`.
- ExecutionReceipt returned by `execute_after_approval(...)`.

Those artifacts can be bundled with
[`build_proof_packet(...)`](PROOF_PACKET.md) for offline verification.

## Related Guides

- [Customer Integration](CUSTOMER_INTEGRATION.md) for the full controlled-action flow.
- [DelegationReceipt Guide](DELEGATION_RECEIPT.md) for owner-to-agent authority.
- [Error Handling](ERRORS.md) for SDK exception types and recovery.
- [Proof Packet Guide](PROOF_PACKET.md) for preserving approval evidence.
