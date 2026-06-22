<div align="center">

<img src="docs/logo.png" alt="AgentVeil" width="160">

# AgentVeil

[![PyPI](https://img.shields.io/pypi/v/agentveil)](https://pypi.org/project/agentveil/)
[![Python](https://img.shields.io/pypi/pyversions/agentveil)](https://pypi.org/project/agentveil/)
[![Tests](https://github.com/agentveil-protocol/agentveil-sdk/actions/workflows/tests.yml/badge.svg)](https://github.com/agentveil-protocol/agentveil-sdk/actions)
[![License](https://img.shields.io/badge/License-MIT%20%2B%20BUSL-informational)](LICENSING.md)
[![Glama MCP Directory](https://img.shields.io/badge/Glama-MCP%20Directory-blue)](https://glama.ai/mcp/servers/agentveil-protocol/avp-sdk)

**Routed action control for risky AI-agent actions.**

[Quick Start](#quick-start) · [Scope](#scope) · [Comparison](#comparison) · [Examples](examples/) · [Docs](docs/)

</div>

```bash
pip install agentveil
```

**PyPI**: [agentveil](https://pypi.org/project/agentveil/) | **Website**: [agentveil.dev](https://agentveil.dev) | **Proxy package**: [`agentveil-mcp-proxy`](packages/agentveil-mcp-proxy/)

> **MCP transport proxy:** route downstream MCP server calls (filesystem, github, shell) through AgentVeil policy, approval routing, and bounded local evidence. The proxy controls calls routed through it; actions outside the proxy are not classified or logged. It is a separately packaged source-available component under [`packages/agentveil-mcp-proxy/`](packages/agentveil-mcp-proxy/) and is not covered by the root MIT license. See [Licensing](LICENSING.md).

<p align="center">
  <img src="docs/routed-action-control.png" alt="AgentVeil routed action control flow" width="840">
</p>

> **Visual overview:** request → AgentVeil boundary → redirect / approval / block → bounded evidence. Enforcement applies only to actions routed through an AgentVeil boundary.
>
> **Audit chain walkthrough:** [`examples/proof_pack/`](examples/proof_pack/) — local-backend demo for offline audit-trail integrity checks. Flow: signed events → hash chain → offline verify (stdlib only, no SDK dependency).
>
> **Controlled-action proof packets:** Runtime Gate flows can export signed proof packets with `agent.build_proof_packet(...)`; see [Customer Integration](docs/CUSTOMER_INTEGRATION.md).
>
> **Data handling:** AgentVeil does not train models on customer data or sell customer data. Runtime Gate is designed for bounded metadata and hashes; MCP Proxy keeps raw MCP arguments local by default. See [Data Handling](docs/DATA_HANDLING.md).

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy init --quickstart-filesystem ./sandbox
agentveil-mcp-proxy doctor --full
agentveil-mcp-proxy run
```

## Scope

AgentVeil controls only actions that are explicitly routed through an AgentVeil
boundary.

- Available today: MCP Proxy for routed MCP tool calls.
- Preview/design-partner boundary patterns: credential custody, egress boundary,
  and API gate.
- Not host-wide: AgentVeil does not monitor or control your whole machine.
- Not a Cursor, Codex, or Claude host lock.
- MCP Proxy does not control IDE-native edits, direct shell commands, direct
  git/pip calls, or actions that bypass the proxy.
- Actions not routed through AgentVeil are not classified or logged.


## Quick Start

### Route one local MCP path

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy init --quickstart-filesystem ./sandbox
agentveil-mcp-proxy doctor --full
agentveil-mcp-proxy run
```

This starts with the public AgentVeil route available today: MCP tool calls that
are explicitly pointed at `agentveil-mcp-proxy`. See the
[MCP Proxy README](packages/agentveil-mcp-proxy/README.md) for client
configuration and local evidence export.

### Run SDK-only protocol primitives locally

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

For hosted Runtime Gate, approvals, and receipt records, see [Customer Integration](docs/CUSTOMER_INTEGRATION.md).

### Integrated application shape

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
    wait_for_principal_approval(outcome.approval["approval_id"])
elif outcome.status == "executed":
    store(outcome.receipt_jcs)
elif outcome.status == "blocked":
    raise RuntimeError(outcome.reason)
```

### Verify advanced credentials offline

```bash
# Get a W3C Verifiable Credential (VC v2.0)
curl https://agentveil.dev/v1/reputation/{agent_did}/credential?format=w3c
```

The response is a verifiable credential. This is an advanced protocol primitive; check it with a VC library or your own Ed25519 implementation when you use the identity/reputation layer directly.

```python
# Or verify with the SDK:
cred = agent.get_reputation_credential(format="w3c")
assert AVPAgent.verify_w3c_credential(cred)  # offline, no API call
```

---

## Mode A Quickstart

Project owners can use AgentVeil as a routed action-control path for agents,
tools, workflows, MCP servers, and CI jobs inside one project.

1. Check the agent project with Lurkr before deployment:

   ```bash
   pip install lurkr
   lurkr scan --path ./your-agent-project
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

AgentVeil does not claim to solve the general access-control safety problem.
Instead, it makes agent actions constrained, auditable, and reversible within a
declared action vocabulary and policy subset: each gated decision is bound to
explicit risk, resource, environment, and payload evidence.

See [Security Context](docs/SECURITY_CONTEXT.md) for background on agent action-control risk.

---

## Comparison

|  | Without AgentVeil | With AgentVeil |
|---|---|---|
| **Risky capability discovery** | Found in incident review | Pre-runtime posture check finds bypass paths, exposed credentials, missing approvals |
| **Risky action execution** | Agent calls `deploy` / `transfer` / `delete` directly | Routed action is evaluated before execution → allow / approval_required / block |
| **Approval on critical steps** | Rubber-stamped or skipped | Signed approval receipt — single-use, expiring, bound to exact action/resource/env |
| **Audit evidence** | "Agent triggered X" in app logs | Receipt record with action hash, decision hash, approval hash, timestamp — checkable offline by audit / customer / partner |

---

## Capability Tokens

AVP approvals are capability tokens, not flat permissions. A Runtime Gate
decision or approval grant is signed by the AVP backend, scoped to concrete
action context (`client_risk_class`, `client_policy_context_hash`, and
`payload_hash`), time-bounded by grant expiry, replay-resistant at the proxy
boundary, and attenuatable through narrower follow-on grants such as
`similar_5m`. Downstream tools receive only the authority needed for the
approved action, not broad standing permission.

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

- **Pre-runtime Checks** — inspect agent identity, status, delegation evidence, and risk signals before runtime
- **Runtime Gate** — evaluate routed risky actions and return allow / approval required / block
- **Receipt records** — keep evidence for gate decisions, approvals, and routed actions
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
| **MCP clients** | `pip install 'agentveil[mcp]'` | `agentveil-mcp` toolbox for explicit Runtime Gate evaluation, approvals, receipts, reputation, identity lookup, and audit. It does not intercept or gate other MCP tools. ([docs](agentveil_mcp/README.md)) |
| **MCP transport proxy** | `pip install agentveil-mcp-proxy` | `agentveil-mcp-proxy` gates downstream MCP calls routed through the proxy with approval routing and bounded local evidence for MCP clients ([docs](packages/agentveil-mcp-proxy/README.md)) |
| **Gemini** | `pip install agentveil google-generativeai` | Function-calling example: [`examples/gemini_example.py`](examples/gemini_example.py) |
| **PydanticAI** | `pip install agentveil pydantic-ai` | Tool example: [`examples/pydantic_ai_example.py`](examples/pydantic_ai_example.py) |
| **Paperclip** | `pip install agentveil` | `avp_should_delegate(...)`, `avp_evaluate_team(...)`, `avp_plugin_tools()` |
| **AWS Bedrock** | `pip install agentveil boto3` | Converse API example: [`examples/aws_bedrock.py`](examples/aws_bedrock.py) |
| **Microsoft AGT / AgentMesh** | `pip install agentmesh-avp` | External/community adapter path for Agent Governance Toolkit / AgentMesh |

Full integration guides: [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md)

---

## Batch Attestations

Attestations from peer agents build reputation history that feeds future
Runtime Gate decisions.

Submit up to 50 attestations in a single request. Each is validated independently — partial success is possible.

```python
results = agent.attest_batch([
    {"to_did": "did:key:z6MkAgent1...", "outcome": "positive", "weight": 0.9, "context": "code_review"},
    {
        "to_did": "did:key:z6MkAgent2...",
        "outcome": "negative",
        "weight": 0.7,
        "context": "failed_security_review",
        "evidence_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
    {"to_did": "did:key:z6MkAgent3...", "outcome": "positive"},
])
print(results["succeeded"], results["failed"])  # 3, 0
```

Each attestation is individually signed with Ed25519. Optional fields: `context`, `evidence_hash`, `is_private`, `interaction_id`.
Negative attestations require both `context` and a 64-character lowercase hex
`evidence_hash`.

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
| [Data Handling](docs/DATA_HANDLING.md) | Local tools, hosted proof ledger, customer evidence stores, hosted content surfaces, and privacy guardrails |
| [Customer Integration](docs/CUSTOMER_INTEGRATION.md) | Controlled-action flow, secrets, errors, and compliance evidence |
| [Mode A Quickstart](docs/MODE_A_QUICKSTART.md) | Project owner path — scan, policy, evaluate, evidence |
| [Error Handling](docs/ERRORS.md) | Exception hierarchy, recovery patterns, HTTP status mapping |
| [Proof Packet Guide](docs/PROOF_PACKET.md) | Build, save, verify signed action evidence offline |
| [Live Developer Adoption Smoke](docs/LIVE_DEVELOPER_ADOPTION_SMOKE.md) | Production validation for Runtime Gate, approval, proof packets, typed errors |
| [Approval Routing](docs/APPROVAL_ROUTING.md) | Resolve approval_required outcomes, grant/deny patterns, resume execution |
| [Registration & Verification](docs/REGISTRATION.md) | Agent registration lifecycle, states, error cases, passphrase security |
| [DelegationReceipt Guide](docs/DELEGATION_RECEIPT.md) | Issuance, verification, common patterns, error handling |
| [Integrations](docs/INTEGRATIONS.md) | Framework-specific setup guides |
| [Webhook Alerts](docs/WEBHOOKS.md) | Push notification setup |
| [Protocol Spec](docs/PROTOCOL.md) | AgentVeil wire format and authentication |
| [Security Model](docs/SECURITY_MODEL.md) | Mode 1 SDK developer flow, Mode 2/3 gateway enforcement roadmap |
| [MCP Proxy Operations](docs/MCP_PROXY_OPERATIONS.md) | Downstream lifecycle behavior and response timeout configuration |
| [MCP Proxy Design Principles](docs/MCP_PROXY_DESIGN_PRINCIPLES.md) | Saltzer-Schroeder mapping, HRU-aware framing, and capability-token discipline |
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
| [`proof_pack/`](examples/proof_pack/) | **Offline audit verification** — local-backend demo: signed events → hash chain → independent offline verification (no SDK or AVP API needed). Local backend required. |
| [`standalone_demo.py`](examples/standalone_demo.py) | **Agent network primitives** — registration, peer attestations, scoring (mock mode, no server). Advanced internal surface. For action control, see [Mode A Quickstart](docs/MODE_A_QUICKSTART.md). |
| [`quickstart.py`](examples/quickstart.py) | Register, publish card, check reputation |
| [`two_agents.py`](examples/two_agents.py) | Full A2A interaction with attestations |
| [`verify_credential_standalone.py`](examples/verify_credential_standalone.py) | Offline credential verification (no SDK needed) |

Framework examples: [CrewAI](examples/crewai_example.py) · [LangGraph](examples/langgraph_example.py) · [AutoGen](examples/autogen_example.py) · [OpenAI](examples/openai_example.py) · [Claude MCP](examples/claude_mcp_example.py) · [Paperclip](examples/paperclip_example.py)

---

## Advanced Protocol Primitives

The public SDK also includes protocol primitives that can support custom
integrations: local `did:key` identity, delegation receipts, credential
helpers, reputation credential access, receipt helpers, and optional
framework adapter modules under `agentveil.tools.*` when their framework
dependencies are installed.

These primitives are not the main product path in this README. For direct use,
start with [Agent Network (Advanced)](docs/ADVANCED_AGENT_NETWORK.md),
[DelegationReceipt Guide](docs/DELEGATION_RECEIPT.md), and
[Proof Packet Guide](docs/PROOF_PACKET.md).

Microsoft AGT / AgentMesh support is presented as an external/community adapter
path, not as an endorsement claim. Research background remains available in
[Security Context](docs/SECURITY_CONTEXT.md).

---

## Community

- ⭐ **[Star this repo](https://github.com/agentveil-protocol/agentveil-sdk/stargazers)** — helps others discover AgentVeil
- 🐛 **[Open an issue](https://github.com/agentveil-protocol/agentveil-sdk/issues)** — bugs, questions, feature requests
- 📖 **[Customer Integration guide](docs/CUSTOMER_INTEGRATION.md)** — production setup

---

## License

This is a multi-license repository.

The public `agentveil` SDK package and explicit `agentveil-mcp` toolbox are MIT
licensed under [LICENSE](LICENSE). The separately packaged MCP transport proxy
under [`packages/agentveil-mcp-proxy/`](packages/agentveil-mcp-proxy/) is
source-available under the Business Source License 1.1, not MIT. See
[LICENSING.md](LICENSING.md) for the package boundary.
