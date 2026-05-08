<div align="center">

<img src="docs/logo.png" alt="AgentVeil" width="160">

# AgentVeil

[![PyPI](https://img.shields.io/pypi/v/agentveil)](https://pypi.org/project/agentveil/)
[![Python](https://img.shields.io/pypi/pyversions/agentveil)](https://pypi.org/project/agentveil/)
[![Tests](https://github.com/agentveil-protocol/avp-sdk/actions/workflows/tests.yml/badge.svg)](https://github.com/agentveil-protocol/avp-sdk/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Glama MCP Directory](https://img.shields.io/badge/Glama-MCP%20Directory-blue)](https://glama.ai/mcp/servers/agentveil-protocol/avp-sdk)

**Action control for autonomous agents — check posture, gate risky actions, prove execution.**

[Quick Start](#quick-start) · [Comparison](#comparison) · [Examples](examples/) · [Docs](docs/)

</div>

```bash
pip install agentveil
```

**PyPI**: [agentveil](https://pypi.org/project/agentveil/) | **API**: [agentveil.dev](https://agentveil.dev) | **Network**: [Live Network](https://agentveil.dev/live)

> [Why agent trust infrastructure matters](docs/SECURITY_CONTEXT.md) — verified CVEs, market data, and the structural problem AgentVeil addresses.

> **[AVPProvider merged into Microsoft Agent Governance Toolkit (PR #1010).](https://github.com/microsoft/agent-governance-toolkit/pull/1010)** AgentVeil is available as an external trust provider for Microsoft AGT / AgentMesh.

> **Paper:** Boiko, O. (2026). *[Why AI Agent Reputation Needs Both Link Analysis and Flow-Based Gating](https://zenodo.org/records/19730525)*. Zenodo.

<p align="center">
  <img src="docs/demo.gif" alt="AgentVeil SDK demo — preflight, runtime gate, approval, controlled execution, offline proof" width="720">
</p>

> **Visual overview:** preflight → runtime gate → approval → controlled execution → offline proof.
>
> **Audit chain walkthrough:** [`examples/proof_pack/`](examples/proof_pack/) — local-backend demo proving offline audit-trail integrity verification. End-to-end flow: signed events → tamper-resistant chain → offline verify (stdlib only, no SDK dependency).
>
> **Controlled-action proof packets:** Runtime Gate flows can export signed proof packets with `agent.build_proof_packet(...)`; see [Customer Integration](docs/CUSTOMER_INTEGRATION.md).

```python
from datetime import timedelta
from agentveil import AVPAgent

owner = AVPAgent.create(mock=True, name="workflow-owner")
agent = AVPAgent.create(mock=True, name="demo-agent")
agent.register(display_name="Demo Agent")

delegation = owner.issue_delegation_receipt(
    agent_did=agent.did,
    allowed_categories=["deploy"],
    valid_for=timedelta(minutes=15),
)
print(agent.verify_delegation_receipt(delegation)["valid"])
```

## Quick Start

### Run locally — no server required

```python
from datetime import timedelta
from agentveil import AVPAgent

owner = AVPAgent.create(mock=True, name="workflow-owner")
agent = AVPAgent.create(mock=True, name="demo-agent")
agent.register(display_name="Test Agent")

delegation = owner.issue_delegation_receipt(
    agent_did=agent.did,
    allowed_categories=["deploy"],
    valid_for=timedelta(minutes=15),
)
verification = agent.verify_delegation_receipt(delegation)

print("delegation valid:", verification["valid"])
print("scope:", verification["scope"][0]["value"])
```

For production identity, Runtime Gate, approvals, and signed receipts, see [Customer Integration](docs/CUSTOMER_INTEGRATION.md).

### Production integration shape

```python
from agentveil import AVPAgent

agent = AVPAgent.load("https://agentveil.dev", "my-agent")

report = agent.integration_preflight()
if not report.ready:
    raise RuntimeError(report.next_action)

outcome = agent.controlled_action(
    action="deploy.release",
    resource="service:critical-workflow",
    environment="production",
    delegation_receipt=delegation_receipt,  # issued by the workflow owner
)

if outcome.status == "approval_required":
    wait_for_principal_approval(outcome.approval["id"])
elif outcome.status == "executed":
    store(outcome.receipt_jcs)
elif outcome.status == "blocked":
    raise RuntimeError(outcome.reason)
```

### Verify trust offline — no SDK required

```bash
# Get a W3C Verifiable Credential (VC v2.0)
curl https://agentveil.dev/v1/reputation/{agent_did}/credential?format=w3c
```

The response is a standard W3C VC with a `DataIntegrityProof` (`eddsa-jcs-2022`). Verify it with any VC library — Veramo, SpruceID, Digital Bazaar, or your own Ed25519 implementation. No AgentVeil SDK needed.

```python
# Or verify with the SDK:
cred = agent.get_reputation_credential(format="w3c")
assert AVPAgent.verify_w3c_credential(cred)  # offline, no API call
```

---

## Mode A Quickstart

Project owners can use AgentVeil as an action-control path for agents, tools,
workflows, MCP servers, and CI jobs inside one project.

1. Scan the project with Posture v0.1:

   ```bash
   pip install agentveil-posture        # (planned after Phase 1 acceptance)
   agentveil-posture scan ./your-project
   ```

2. Define local policy:

   ```bash
   agentveil policy init                # (planned for v0.8 / Phase 3)
   ```

3. Evaluate actions before execution:

   ```python
   from agentveil import evaluate_action  # (planned for v0.8 / Phase 3)
   ```

4. Produce signed evidence today with `controlled_action(...)`,
   DelegationReceipts, approval routing, and Proof Packets.

See [Mode A Quickstart](docs/MODE_A_QUICKSTART.md) for the full Project Owner
path and planned capability markers.

---

## Why This Exists

AI agents increasingly hold direct access to production credentials, deploy
workflows, and developer infrastructure. AgentVeil provides three things:

1. **Pre-runtime checks** — find risky agent capabilities (bypass paths, exposed credentials, missing approvals) before they reach production
2. **Runtime gating** — evaluate risky actions before execution, route through signed approval when needed
3. **Verifiable evidence** — produce signed receipts your audit / customer / partner can verify offline, no SDK or AVP API required

See [Security Context](docs/SECURITY_CONTEXT.md) for verified CVEs, market data,
and the structural problem AgentVeil addresses.

---

## Comparison

|  | Without AgentVeil | With AgentVeil |
|---|---|---|
| **Risky capability discovery** | Found in incident review | Pre-runtime posture check finds bypass paths, exposed credentials, missing approvals |
| **Risky action execution** | Agent calls `deploy` / `transfer` / `delete` directly | Evaluated before execution → allow / approval_required / block |
| **Approval on critical steps** | Rubber-stamped or skipped | Signed approval receipt — single-use, expiring, bound to exact action/resource/env |
| **Audit evidence** | "Agent triggered X" in app logs | Signed receipt with action hash, decision hash, approval hash, timestamp — verifiable offline by audit / customer / partner |

---

## Decision Inputs (advisory)

These advisory APIs feed the Runtime Gate's risk assessment. They inform
action gating decisions but do not grant execution authority on their own.
For direct reputation and agent-network usage, see
[Agent Network (Advanced)](docs/ADVANCED_AGENT_NETWORK.md).

For advisory selection and existing integrations, the SDK also includes:

- `can_trust(...)` — advisory score, tier, risk, and explanation before delegation
- `@avp_tracked(...)` — decorator for auto-registering and attesting local work
- Framework tools such as `AVPReputationTool`, `avp_should_delegate(...)`, and `avp_tool_definitions()`

```python
from agentveil import AVPAgent, avp_tracked

agent = AVPAgent.load("https://agentveil.dev", "my-agent")
decision = agent.can_trust("did:key:z6Mk...", min_tier="trusted")
print(decision["allowed"], decision["reason"])

@avp_tracked("https://agentveil.dev", name="reviewer", to_did="did:key:z6Mk...")
def review_code(pr_url: str) -> str:
    return analysis
```

---

## Features

**Action control surface**

- **Posture Checks** — inspect agent identity, status (active/suspended), and reputation signals before runtime
- **Runtime Gate** — evaluate risky actions before execution and return allow / approval required / block
- **Signed Receipts** — keep tamper-evident proof for gate decisions, approvals, and execution
- **W3C VC v2.0 Credentials** — export offline-verifiable credentials with `eddsa-jcs-2022` Data Integrity proofs
- **Webhook Alerts** — score-change notifications to any HTTP endpoint ([setup guide](docs/WEBHOOKS.md))
- **Framework Integrations** — SDK tools for CrewAI, LangGraph, AutoGen, OpenAI, Claude MCP, Paperclip, and more

**Supporting signals (advisory)**

- **Reputation Signals** — peer attestations, confidence scoring, and advisory trust checks
- **Agent Discovery** — publish capability cards and find agents by skill and reputation
- **Dispute & Review Support** — attach evidence and review contested attestations

---

## Integrations

| Stack | Install | Integration surface |
|-------|---------|---------------------|
| **Any Python** | `pip install agentveil` | `AVPAgent`, `integration_preflight()`, `controlled_action()`, `build_proof_packet()` |
| **CrewAI** | `pip install agentveil crewai` | `AVPReputationTool`, `AVPDelegationTool`, `AVPAttestationTool` |
| **LangGraph** | `pip install agentveil langgraph` | `ToolNode([avp_check_reputation, avp_should_delegate, avp_log_interaction])` |
| **AutoGen** | `pip install agentveil autogen-core` | `avp_reputation_tools()` |
| **OpenAI** | `pip install agentveil openai` | `avp_tool_definitions()` + `handle_avp_tool_call(...)` from `agentveil.tools.openai` |
| **MCP clients** | `pip install 'agentveil[mcp]'` | `agentveil-mcp` for Claude Desktop, Cursor, Windsurf, and VS Code ([docs](agentveil_mcp/README.md)) |
| **Gemini** | `pip install agentveil google-generativeai` | Function-calling example: [`examples/gemini_example.py`](examples/gemini_example.py) |
| **PydanticAI** | `pip install agentveil pydantic-ai` | Tool example: [`examples/pydantic_ai_example.py`](examples/pydantic_ai_example.py) |
| **Paperclip** | `pip install agentveil` | `avp_should_delegate(...)`, `avp_evaluate_team(...)`, `avp_plugin_tools()` |
| **AWS Bedrock** | `pip install agentveil boto3` | Converse API example: [`examples/aws_bedrock.py`](examples/aws_bedrock.py) |
| **Microsoft AGT / AgentMesh** | `pip install agentmesh-avp` | `AVPProvider` package for Agent Governance Toolkit / AgentMesh integration |

Full integration guides: [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md)

---

## Batch Attestations

Attestations from peer agents build reputation history that feeds future
Runtime Gate decisions.

Submit up to 50 attestations in a single request. Each is validated independently — partial success is possible.

```python
results = agent.attest_batch([
    {"to_did": "did:key:z6MkAgent1...", "outcome": "positive", "weight": 0.9, "context": "code_review"},
    {"to_did": "did:key:z6MkAgent2...", "outcome": "negative", "weight": 0.7, "evidence_hash": "sha256hex..."},
    {"to_did": "did:key:z6MkAgent3...", "outcome": "positive"},
])
print(results["succeeded"], results["failed"])  # 3, 0
```

Each attestation is individually signed with Ed25519. Optional fields: `context`, `evidence_hash`, `is_private`, `interaction_id`.

---

## Security

- Ed25519 signature authentication with nonce anti-replay
- W3C `did:key` identity with Ed25519 keys for portable agent identity
- Input validation for signed SDK/API requests
- Agent status checks for active, suspended, revoked, or migrated identities
- Audit trail — SHA-256 hash-chained events with optional IPFS anchoring for published proof artifacts

---

## Documentation

| Doc | Description |
|-----|-------------|
| [API Reference](docs/API.md) | Full SDK method reference with examples |
| [Customer Integration](docs/CUSTOMER_INTEGRATION.md) | Controlled-action flow, secrets, errors, and compliance evidence |
| [Mode A Quickstart](docs/MODE_A_QUICKSTART.md) | Project owner path — scan, policy, evaluate, evidence |
| [Error Handling](docs/ERRORS.md) | Exception hierarchy, recovery patterns, HTTP status mapping |
| [Proof Packet Guide](docs/PROOF_PACKET.md) | Build, save, verify signed action evidence offline |
| [Approval Routing](docs/APPROVAL_ROUTING.md) | Resolve approval_required outcomes, grant/deny patterns, resume execution |
| [Registration & Verification](docs/REGISTRATION.md) | Agent registration lifecycle, states, error cases, passphrase security |
| [DelegationReceipt Guide](docs/DELEGATION_RECEIPT.md) | Issuance, verification, common patterns, error handling |
| [Integrations](docs/INTEGRATIONS.md) | Framework-specific setup guides |
| [Webhook Alerts](docs/WEBHOOKS.md) | Push notification setup |
| [Protocol Spec](docs/PROTOCOL.md) | AgentVeil wire format and authentication |
| [Security Model](docs/SECURITY_MODEL.md) | Mode 1 SDK developer flow, Mode 2/3 gateway enforcement roadmap |
| [Security Context](docs/SECURITY_CONTEXT.md) | Why agent trust matters — CVEs and market data |
| [Agent Network (Advanced)](docs/ADVANCED_AGENT_NETWORK.md) | Reputation, attestations, agent identity — internal mechanisms |
| [Changelog](CHANGELOG.md) | Version history |

---

## Examples

| Example | Description |
|---------|-------------|
| [`first_controlled_action.py`](examples/first_controlled_action.py) | **Action control demo** — preflight → Runtime Gate → approval routing → signed receipt |
| [`approval_flow.py`](examples/approval_flow.py) | **Approval pattern** — controlled_action → approval_required → grant → execute_after_approval |
| [`handle_errors.py`](examples/handle_errors.py) | **Error patterns** — typed exception handling for retry, re-auth, validation, network |
| [`proof_packet_export.py`](examples/proof_packet_export.py) | **Proof packet export** — build, save, reload, verify offline (mock mode) |
| [`registration/`](examples/registration/) | **Registration patterns** — first-time setup, verification state, encrypted reload |
| [`delegation/`](examples/delegation/) | **DelegationReceipt patterns** — issue, verify offline, persist/reload, multi-scope |
| [`proof_pack/`](examples/proof_pack/) | **Offline audit verification** — local-backend demo: signed events → tamper-resistant chain → independent offline verification (no SDK or AVP API needed). Local backend required. |
| [`standalone_demo.py`](examples/standalone_demo.py) | **Agent network primitives** — registration, peer attestations, scoring (mock mode, no server). Advanced internal surface. For action control, see [Mode A Quickstart](docs/MODE_A_QUICKSTART.md). |
| [`quickstart.py`](examples/quickstart.py) | Register, publish card, check reputation |
| [`two_agents.py`](examples/two_agents.py) | Full A2A interaction with attestations |
| [`verify_credential_standalone.py`](examples/verify_credential_standalone.py) | Offline credential verification (no SDK needed) |

Framework examples: [CrewAI](examples/crewai_example.py) · [LangGraph](examples/langgraph_example.py) · [AutoGen](examples/autogen_example.py) · [OpenAI](examples/openai_example.py) · [Claude MCP](examples/claude_mcp_example.py) · [Paperclip](examples/paperclip_example.py)

---

## Community

- ⭐ **[Star this repo](https://github.com/agentveil-protocol/avp-sdk/stargazers)** — helps others discover AgentVeil
- 🐛 **[Open an issue](https://github.com/agentveil-protocol/avp-sdk/issues)** — bugs, questions, feature requests
- 📖 **[Customer Integration guide](docs/CUSTOMER_INTEGRATION.md)** — production setup

---

## License

MIT — see [LICENSE](LICENSE).
