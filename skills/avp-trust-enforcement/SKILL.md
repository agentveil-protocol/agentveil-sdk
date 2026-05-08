---
name: avp-trust-enforcement
description: >
  AgentVeil action-control workflows for AI agent systems. Evaluate risky
  actions with Runtime Gate, route human approvals, resume approved execution,
  fetch signed receipts, inspect agent public profiles, check advisory
  reputation, submit signed attestations, discover agents by capability, and
  verify audit evidence through the AgentVeil MCP server and Python SDK.
version: 1.3.0
author: AgentVeil
license: MIT
metadata:
  hermes:
    tags: [agents, identity, reputation, audit, attestations, runtime-gate, signed-receipts]
    related_skills: []
    category: agent-infrastructure
    fallback_for_toolsets: []
    requires_toolsets: [mcp]
    config:
      - key: avp.base_url
        description: AgentVeil API endpoint URL
        default: "https://agentveil.dev"
        prompt: AgentVeil API base URL
      - key: avp.min_reputation_tier
        description: Minimum advisory tier for delegation checks
        default: "basic"
        prompt: Minimum advisory tier for delegation
      - key: avp.agent_name
        description: Default local agent name used by AgentVeil MCP write tools
        default: "agentveil-agent"
        prompt: AgentVeil local agent name
---

# AgentVeil — Action-Control MCP Workflows

AgentVeil helps agents evaluate risky actions, route approvals, fetch signed
receipts, inspect public profiles, make advisory reputation checks, record
signed interaction outcomes, and verify audit evidence.

This skill is for the AgentVeil MCP server and Python SDK. Local/full MCP mode
exposes explicit Runtime Gate, approval, approved execution, and receipt
workflows alongside profile, advisory reputation, attestation, and audit
tools. Hosted/read-only MCP deployments expose only public inspection tools.

For direct Python integrations, use the SDK Runtime Gate flow:

```text
integration_preflight() -> controlled_action() -> signed receipts
```

## When to Use

- Inspect an agent's public profile or capability card.
- Check advisory reputation before delegation.
- Search for agents by capability, provider, or minimum reputation.
- Read attestations and audit history for an agent.
- Verify audit-chain integrity.
- Register a local AgentVeil identity when using full local MCP mode.
- Submit a signed attestation after an interaction.
- Evaluate a risky action with Runtime Gate from local/full MCP mode.
- Route human approval and resume approved execution.
- Fetch signed DecisionReceipt and ExecutionReceipt artifacts.

For risky actions such as deployments, data writes, payments, tool execution,
or production changes, use Runtime Gate and retain the signed receipts.

## Configuration

Configure the AgentVeil API URL and local agent name in your MCP client or skill
configuration:

```yaml
skills:
  config:
    avp:
      base_url: https://agentveil.dev
      min_reputation_tier: basic
      agent_name: agentveil-agent
```

## Prerequisites

Install and run the canonical MCP server:

```bash
pip install 'agentveil[mcp]'
agentveil-mcp
```

Example MCP client config:

```json
{
  "mcpServers": {
    "agentveil": {
      "command": "agentveil-mcp",
      "env": {
        "AVP_BASE_URL": "https://agentveil.dev",
        "AVP_AGENT_NAME": "agentveil-agent"
      }
    }
  }
}
```

Hosted/read-only deployments expose public inspection tools. Local/full mode
adds identity-backed tools that create local keys, sign write operations, run
Runtime Gate workflows, route approvals, resume approved execution, and fetch
signed receipts.

## Available MCP Tools

Hosted/read-only mode exposes 8 public inspection tools:

| Tool | Purpose |
|---|---|
| `check_reputation` | Advisory reputation profile for a DID. |
| `check_trust` | Advisory yes/no delegation check. |
| `get_agent_info` | Public agent profile and capability card. |
| `search_agents` | Discover agents by capability, provider, or reputation. |
| `get_attestations_received` | Inspect peer ratings received by an agent. |
| `get_audit_trail` | Read an agent's audit history. |
| `verify_audit_chain` | Verify audit-chain integrity. |
| `get_protocol_stats` | Network-level counters. |

Local/full mode includes 20 total tools by adding 4 identity-backed tools and
8 action-control tools:

| Tool | Purpose |
|---|---|
| `register_agent` | Create a local Ed25519 identity and register it. |
| `submit_attestation` | Record a signed interaction outcome. |
| `publish_agent_card` | Publish capabilities for discovery. |
| `get_my_agent_info` | Inspect the local configured identity. |
| `runtime_evaluate_action` | Ask Runtime Gate for ALLOW, WAITING_FOR_HUMAN_APPROVAL, or BLOCK. |
| `controlled_action` | Run the SDK controlled-action flow and return the outcome. |
| `get_approval_request` | Fetch a human approval request. |
| `approve_action` | Approve a pending request and return signed receipt JCS plus sha256. |
| `deny_action` | Deny a pending request and return signed receipt JCS plus sha256. |
| `execute_after_approval` | Resume execution after approval using `approval_id`. |
| `get_decision_receipt` | Fetch exact signed DecisionReceipt JCS plus sha256. |
| `get_execution_receipt` | Fetch exact signed ExecutionReceipt JCS plus sha256. |

## Advisory Selection Pattern

Use this pattern when an agent needs to choose another agent for a task:

1. Inspect the candidate with `get_agent_info`.
2. Use `check_reputation` or `check_trust` as advisory input.
3. Review attestations with `get_attestations_received` when the decision is
   borderline or high-impact.
4. For low-risk delegation, proceed in your own workflow and record the result
   with `submit_attestation`.
5. For risky actions, use Runtime Gate before execution.
6. Retain audit/proof references when the user needs evidence.

## Runtime Gate Path

For action control, use the Python SDK:

```python
from agentveil import AVPAgent

agent = AVPAgent.load("https://agentveil.dev", name="agentveil-agent")
report = agent.integration_preflight()
if not report.ready:
    raise RuntimeError(report.next_action)

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

MCP and SDK Runtime Gate workflows control the execution boundary and produce
signed receipts.

## Boundaries

- Do not treat advisory reputation as execution permission.
- Do not use MCP inspection tools as a substitute for Runtime Gate.
- Do not send private keys, cloud credentials, raw private logs, or secrets to
  AgentVeil.
- Hosted/read-only mode cannot register agents, submit attestations, or expose
  action-control workflows.
- Identity-backed MCP local/full tools create local key files under
  `~/.avp/agents/`.
- Controlled execution evidence should retain raw signed receipt text, not only
  parsed fields.

## Score and Tier Guidance

Use advisory reputation as one input, not as the sole decision rule.

| Signal | Suggested handling |
|---|---|
| High score and sufficient confidence | Candidate is suitable for normal low-risk delegation. |
| Moderate score or low confidence | Use smaller tasks, inspect attestations, and verify output. |
| Low score, blocked status, or suspicious history | Do not delegate without additional controls. |

For sensitive or production actions, use Runtime Gate even when advisory signals
look strong.

## Audit and Evidence

Use `get_audit_trail` to inspect an agent's history and `verify_audit_chain` to
check audit-chain integrity. For execution evidence, retain signed receipts from
the SDK Runtime Gate flow and verify proof packets when available.

## Verification

The skill is working correctly if:

1. `check_reputation` returns a reputation object for a known DID.
2. `check_trust` returns an advisory allow/deny result with a reason.
3. `search_agents` returns matching public capability cards.
4. `verify_audit_chain` returns a valid chain result.
5. In local/full mode, `get_my_agent_info` returns the configured local DID.
6. In local/full mode, `submit_attestation` records a signed interaction outcome.
