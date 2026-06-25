## Python SDK and advanced protocol primitives

<!-- claim-check: allow advanced SDK reference material moved from the former root README; detailed status and evidence live in the linked docs/examples for each primitive. -->

Advanced Python SDK package: agentveil

The public SDK also includes protocol primitives that can support custom
integrations: local `did:key` identity, delegation receipts, credential
helpers, reputation credential access, receipt helpers, and optional
framework adapter modules under `agentveil.tools.*` when their framework
dependencies are installed.

These primitives are not the main product path in this README. For direct use,
start with [Agent Network (Advanced)](ADVANCED_AGENT_NETWORK.md),
[DelegationReceipt Guide](DELEGATION_RECEIPT.md), and
[Proof Packet Guide](PROOF_PACKET.md).

### Capability Tokens

AVP approvals are capability tokens, not flat permissions. A Runtime Gate
decision or approval grant is signed by the AVP backend, scoped to concrete
action context (`client_risk_class`, `client_policy_context_hash`, and
`payload_hash`), time-bounded by grant expiry, checked against replay at the
proxy boundary, and attenuatable through narrower follow-on grants such as
`similar_5m`. Downstream tools receive only the authority needed for the
approved action, not broad standing permission.

---

### Decision Inputs (advisory)

These advisory APIs feed the Runtime Gate's risk assessment. They inform
action gating decisions but do not grant execution authority on their own.
For direct reputation and agent-network usage, see
[Agent Network (Advanced)](ADVANCED_AGENT_NETWORK.md).

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

### Features

**Action control surface**

- **Pre-runtime Checks** — inspect agent identity, status, delegation evidence, and risk signals before runtime
- **Runtime Gate** — evaluate routed risky actions and return allow / approval required / block
- **Receipt records** — keep evidence for gate decisions, approvals, and routed actions
<!-- claim-check: allow VC standard reference; API details are documented in API.md and PROTOCOL.md. -->
- **W3C VC v2.0 Credentials** — export credentials with `eddsa-jcs-2022` Data Integrity proofs
- **Webhook Alerts** — score-change notifications to any HTTP endpoint ([setup guide](WEBHOOKS.md))
- **Framework Integrations** — SDK tools for CrewAI, LangGraph, AutoGen, OpenAI, Claude MCP, Paperclip, and more

**Supporting signals (advisory)**

- **Reputation Signals** — peer attestations, confidence scoring, and advisory trust checks
- **Agent Discovery** — publish capability cards and find agents by skill and reputation
- **Dispute & Review Support** — attach evidence and review contested attestations

---

### Integrations

| Stack | Install | Integration surface |
|-------|---------|---------------------|
| **Any Python** | `pip install agentveil` | `AVPAgent`, `integration_preflight()`, `controlled_action()`, `build_proof_packet()` |
| **CrewAI** | `pip install agentveil crewai` | `AVPReputationTool`, `AVPDelegationTool`, `AVPAttestationTool` |
| **LangGraph** | `pip install agentveil langgraph` | `ToolNode([avp_check_reputation, avp_should_delegate, avp_log_interaction])` |
| **AutoGen** | `pip install agentveil autogen-core` | `avp_reputation_tools()` |
| **OpenAI** | `pip install agentveil openai` | `avp_tool_definitions()` + `handle_avp_tool_call(...)` from `agentveil.tools.openai` |
| **MCP clients** | `pip install 'agentveil[mcp]'` | `agentveil-mcp` toolbox for explicit Runtime Gate evaluation, approvals, receipts, reputation, identity lookup, and audit. It does not intercept or gate other MCP tools. ([docs](../agentveil_mcp/README.md)) |
| **MCP transport proxy** | `pip install agentveil-mcp-proxy` | `agentveil-mcp-proxy` gates downstream MCP calls routed through the proxy with approval routing and bounded local evidence for MCP clients ([docs](../packages/agentveil-mcp-proxy/README.md)) |
| **Gemini** | `pip install agentveil google-generativeai` | Function-calling example: [`examples/gemini_example.py`](../examples/gemini_example.py) |
| **PydanticAI** | `pip install agentveil pydantic-ai` | Tool example: [`examples/pydantic_ai_example.py`](../examples/pydantic_ai_example.py) |
| **Paperclip** | `pip install agentveil` | `avp_should_delegate(...)`, `avp_evaluate_team(...)`, `avp_plugin_tools()` |
| **AWS Bedrock** | `pip install agentveil boto3` | Converse API example: [`examples/aws_bedrock.py`](../examples/aws_bedrock.py) |
| **Microsoft AGT / AgentMesh** | `pip install agentmesh-avp` | External/community adapter path for Agent Governance Toolkit / AgentMesh |

Full integration guides: [docs/INTEGRATIONS.md](INTEGRATIONS.md)

---

### Batch Attestations

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

### Security

- Ed25519 signature authentication with nonce anti-replay
- `did:key` identity with Ed25519 keys for portable agent identity
- Input validation for signed SDK/API requests
- Agent status checks for active, suspended, revoked, or migrated identities
- Audit trail — SHA-256 hash-chained events with optional IPFS anchoring for published proof artifacts

---

### Documentation

| Doc | Description |
|-----|-------------|
| [API Reference](API.md) | Full SDK method reference with examples |
| [Data Handling](DATA_HANDLING.md) | Local tools, hosted proof ledger, evidence stores, hosted content surfaces, and privacy guardrails |
| [Customer Integration](CUSTOMER_INTEGRATION.md) | Controlled-action flow, secrets, errors, and compliance evidence |
| [Mode A Quickstart](MODE_A_QUICKSTART.md) | Project owner path — scan, policy, evaluate, evidence |
| [Error Handling](ERRORS.md) | Exception hierarchy, recovery patterns, HTTP status mapping |
| [Proof Packet Guide](PROOF_PACKET.md) | Build, save, verify signed action evidence offline |
| [Live Developer Adoption Smoke](LIVE_DEVELOPER_ADOPTION_SMOKE.md) | Runtime Gate, approval, proof packet, and typed-error validation |
| [Approval Routing](APPROVAL_ROUTING.md) | Resolve approval_required outcomes, grant/deny patterns, resume execution |
| [Registration & Verification](REGISTRATION.md) | Agent registration lifecycle, states, error cases, passphrase security |
| [DelegationReceipt Guide](DELEGATION_RECEIPT.md) | Issuance, verification, common patterns, error handling |
| [Integrations](INTEGRATIONS.md) | Framework-specific setup guides |
| [Webhook Alerts](WEBHOOKS.md) | Push notification setup |
| [Protocol Spec](PROTOCOL.md) | AgentVeil wire format and authentication |
| [Security Model](SECURITY_MODEL.md) | Mode 1 SDK developer flow, Mode 2/3 gateway enforcement roadmap |
| [MCP Proxy Operations](MCP_PROXY_OPERATIONS.md) | Downstream lifecycle behavior and response timeout configuration |
| [MCP Proxy Design Principles](MCP_PROXY_DESIGN_PRINCIPLES.md) | Saltzer-Schroeder mapping, HRU-aware framing, and capability-token discipline |
| [Security Context](SECURITY_CONTEXT.md) | Why agent trust matters — CVEs and market data |
| [Agent Network (Advanced)](ADVANCED_AGENT_NETWORK.md) | Reputation, attestations, agent identity — internal mechanisms |
| [Changelog](../CHANGELOG.md) | Version history |

---

### Examples

| Example | Description |
|---------|-------------|
| [`first_controlled_action.py`](../examples/first_controlled_action.py) | **Action control demo** — preflight → Runtime Gate → approval routing → receipt |
| [`approval_flow.py`](../examples/approval_flow.py) | **Approval pattern** — controlled_action → approval_required → grant → execute_after_approval |
| [`handle_errors.py`](../examples/handle_errors.py) | **Error patterns** — typed exception handling for retry, re-auth, validation, network |
| [`proof_packet_export.py`](../examples/proof_packet_export.py) | **Proof packet export** — build, save, reload, verify offline (mock mode) |
| [`registration/`](../examples/registration/) | **Registration patterns** — first-time setup, verification state, encrypted reload |
| [`delegation/`](../examples/delegation/) | **DelegationReceipt patterns** — issue, verify offline, persist/reload, multi-scope |
| [`proof_pack/`](../examples/proof_pack/) | **Offline audit verification** — local-backend demo: signed events → hash chain → independent offline verification (no SDK or AVP API needed). Local backend required. |
| [`standalone_demo.py`](../examples/standalone_demo.py) | **Agent network primitives** — registration, peer attestations, scoring (mock mode, no server). Advanced internal surface. For action control, see [Mode A Quickstart](MODE_A_QUICKSTART.md). |
| [`quickstart.py`](../examples/quickstart.py) | Register, publish card, check reputation |
| [`two_agents.py`](../examples/two_agents.py) | Full A2A interaction with attestations |
| [`verify_credential_standalone.py`](../examples/verify_credential_standalone.py) | Offline credential verification (no SDK needed) |

Framework examples: [CrewAI](../examples/crewai_example.py) · [LangGraph](../examples/langgraph_example.py) · [AutoGen](../examples/autogen_example.py) · [OpenAI](../examples/openai_example.py) · [Claude MCP](../examples/claude_mcp_example.py) · [Paperclip](../examples/paperclip_example.py)

---

### Audit chain and proof packets

**Audit chain walkthrough:** [`examples/proof_pack/`](../examples/proof_pack/) —
local-backend demo for offline audit-trail integrity checks. Flow: signed
events -> hash chain -> offline verify (stdlib only, no SDK dependency).

**Controlled-action proof packets:** Runtime Gate flows can export signed proof
packets with `agent.build_proof_packet(...)`; see
[Customer Integration](CUSTOMER_INTEGRATION.md).

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

For hosted Runtime Gate, approvals, and receipt records, see
[Customer Integration](CUSTOMER_INTEGRATION.md).

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
    environment="staging",
    delegation_receipt=delegation_receipt,  # issued by the workflow owner
)

if outcome.status == "approval_required":
    wait_for_principal_approval(outcome.approval["approval_id"])
elif outcome.status == "executed":
    store(outcome.receipt_jcs)
elif outcome.status == "requires_review":
    raise RuntimeError(outcome.reason)
```

### Verify advanced credentials locally

<!-- claim-check: allow credential API reference; see API.md and PROTOCOL.md for the underlying verification contract and status. -->

```bash
# Get an AVP-native reputation credential
curl https://agentveil.dev/v1/reputation/{agent_did}/credential?format=avp
```

The response is an advanced protocol primitive; check it with the SDK when you
use the identity/reputation layer directly.

```python
# Or verify with the SDK:
cred = agent.get_reputation_credential(format="avp")
assert AVPAgent.verify_credential(cred)  # local check, no API call
```

Microsoft AGT / AgentMesh support is presented as an external/community adapter
path, not as an endorsement claim. Research background remains available in
[Security Context](SECURITY_CONTEXT.md).

---

### Mode A Quickstart

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

See [Mode A Quickstart](MODE_A_QUICKSTART.md) for the full Project Owner
path and planned capability markers.

---
