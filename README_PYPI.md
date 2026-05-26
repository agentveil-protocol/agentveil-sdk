# AgentVeil

**Action control for autonomous agents — check posture, gate risky actions, prove execution.**

AgentVeil is the Python SDK for agent action control: posture checks, Runtime Gate decisions, signed receipts, W3C verifiable credentials, plus DID identity, reputation signals, and MCP integrations.

```bash
pip install agentveil
```

## Quick Start

Run locally with real cryptography and mocked HTTP. No server is required.

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
verification = agent.verify_delegation_receipt(delegation)

print("delegation valid:", verification["valid"])
print("scope:", verification["scope"][0]["value"])
```

For production setup, see the [Customer Integration guide](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/CUSTOMER_INTEGRATION.md).

## What AgentVeil Provides

- **Posture checks** before risky agent actions reach production.
- **Runtime Gate decisions** for allow, approval required, or block outcomes.
- **Signed receipts and proof packets** for audit and offline verification.
- **W3C VC v2.0 credentials** with `eddsa-jcs-2022` Data Integrity proofs.
- **DID identity** with portable `did:key` Ed25519 keys.
- **Framework integrations** for CrewAI, LangGraph, AutoGen, OpenAI, Claude MCP, Gemini, PydanticAI, Paperclip, and AWS Bedrock.
- **MCP transport proxy** for IDE clients (Claude Desktop, Cursor, Cline, Windsurf, VS Code) - wrap downstream MCP servers with Action Control Plane gating via the `agentveil-mcp-proxy` console script.

AgentVeil makes agent actions constrained, auditable, and reversible within a
declared action vocabulary and policy subset. It does not claim to solve the
general access-control safety problem; it produces bounded decisions and signed
evidence that operators can review.

## Offline Verification

Fetch a W3C Verifiable Credential:

```bash
curl https://agentveil.dev/v1/reputation/{agent_did}/credential?format=w3c
```

Verify it with any VC library, or with the SDK:

```python
cred = agent.get_reputation_credential(format="w3c")
assert AVPAgent.verify_w3c_credential(cred)
```

## AgentVeil MCP Toolbox

The base install includes the MCP runtime dependency:

```bash
pip install agentveil
agentveil-mcp
```

Local/full MCP mode exposes Runtime Gate evaluation, human approval routing,
approved execution, signed receipt retrieval, reputation checks, identity
lookup, and audit verification. Hosted read-only mode exposes public
inspection tools only.

This server is an explicit toolbox. It does not intercept, monitor, or gate
other MCP tools; MCP clients must call these AVP tools directly.

The compatibility extra `agentveil[mcp]` still works for legacy setups. MCP setup details are in the [MCP README](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/agentveil_mcp/README.md).

## MCP Transport Proxy

The `agentveil-mcp-proxy` console script wraps a downstream MCP server with
runtime decision gating, human approval routing, durable signed evidence, and
replay defense. Point your IDE at `agentveil-mcp-proxy` instead of directly at
the downstream server; the proxy applies AVP policy before forwarding.

```bash
agentveil-mcp-proxy init
agentveil-mcp-proxy doctor
agentveil-mcp-proxy run
```

AVP approvals are capability tokens, not flat permissions. They are signed,
scoped to action context and payload hash, time-bounded by expiry, guarded
against replay at the proxy boundary, and attenuated when follow-on grants such
as `similar_5m` narrow the original approval scope.

See the [MCP Proxy README](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/agentveil_mcp_proxy/README.md)
for the full quick start and IDE configuration examples.

## Resources

- [Full GitHub README and demo](https://github.com/agentveil-protocol/agentveil-sdk#readme)
- [API reference](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/API.md)
- [Customer integration guide](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/CUSTOMER_INTEGRATION.md)
- [Framework integrations](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/INTEGRATIONS.md)
- [Security context](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/SECURITY_CONTEXT.md)
- [Examples](https://github.com/agentveil-protocol/agentveil-sdk/tree/main/examples)
- [AgentVeil API](https://agentveil.dev)
- [Live Network](https://agentveil.dev/live)

## License

MIT. See the [license](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/LICENSE).
