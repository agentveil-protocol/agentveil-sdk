# Mode A Quickstart

Mode A is the Project Owner path for AgentVeil. It is for teams using Cursor,
Claude, MCP servers, CrewAI, GitHub Actions, or similar automation inside a
project and asking: what can these tools do, which actions are risky, and what
should be allowed?

AgentVeil is one Action Control system. Reputation, identity, delegation,
approvals, and receipts are decision inputs and evidence mechanisms, not
separate products.

## Step 1 — Scan Your Project For Risky Capabilities (planned after Phase 1 acceptance)

Posture v0.1 launches as a standalone OSS package (planned after Phase 1
acceptance). It is the first Project Owner entry point.

```bash
pip install agentveil-posture  # (planned after Phase 1 acceptance)
agentveil-posture scan ./your-project
```

The scanner reports risky agent and automation surfaces such as deploy actions,
shell execution, credential access, and missing approval boundaries. Treat the
report as a triage input before wiring runtime controls.

## Step 2 — Define Local Policy (planned for v0.8 / Phase 3)

Local policy initialization is planned for v0.8 / Phase 3.

```bash
agentveil policy init  # (planned for v0.8 / Phase 3)
```

Expected starter policy shape:

```json
{
  "version": "agentveil.policy/v1",
  "defaults": {
    "unknown": "approval_required",
    "production": "approval_required"
  },
  "rules": [
    {
      "action": "deploy.release",
      "resource": "service:*",
      "environment": "production",
      "decision": "approval_required"
    },
    {
      "action": "read.files",
      "resource": "repo:*",
      "environment": "development",
      "decision": "allow"
    }
  ]
}
```

## Step 3 — Evaluate Actions Before Execution (planned for v0.8 / Phase 3)

Pure local evaluation is planned for v0.8 / Phase 3. It will let a project
owner check an action against local policy without registration or backend
connectivity.

```python
from agentveil import evaluate_action  # (planned for v0.8 / Phase 3)

decision = evaluate_action(
    action="deploy.release",
    resource="service:critical",
    environment="production",
    policy_file="./.agentveil/policy.json",
)

print(decision.status)  # allow / approval_required / block
```

Until that ships, use the backend-connected `controlled_action(...)` path for
runtime decisions and signed evidence.

## Step 4 — Produce Signed Evidence (works today)

The backend-connected SDK path works today:

1. Register or load an agent identity.
2. Receive a DelegationReceipt from the workflow owner.
3. Call `controlled_action(...)`.
4. If approval is required, route through `approve(...)` and
   `execute_after_approval(...)`.
5. Export a Proof Packet and verify it offline.

Relevant guides:

- [Customer Integration](CUSTOMER_INTEGRATION.md)
- [DelegationReceipt Guide](DELEGATION_RECEIPT.md)
- [Approval Routing](APPROVAL_ROUTING.md)
- [Proof Packet Guide](PROOF_PACKET.md)
- [Error Handling](ERRORS.md)

## End-State Roadmap

| Milestone | Status |
|---|---|
| Mode A v0.1: Posture scan as project entry point | Built; public launch planned after Phase 1 acceptance |
| Mode A v0.8: local policy file and `evaluate_action(...)` | (planned for v0.8 / Phase 3) |
| Mode A CLI: `agentveil policy init` and `agentveil check-action` | (planned for Phase 4) |
| MCP proxy and signed local receipts | (planned for Phase 4) |
| Managed or customer-hosted gateway enforcement | (planned for Phase 5) |

Public claims should track this table. If a capability is listed as planned, do
not treat it as shipped behavior.

## Advanced Agent Network Features

Agent identity, reputation, attestations, W3C credentials, and agent discovery
remain available as advanced features and decision inputs. See
[Agent Network (Advanced)](ADVANCED_AGENT_NETWORK.md) when you need those
primitives directly.
