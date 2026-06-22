# Mode A Quickstart

Mode A is the project-owner path for AgentVeil. It is for teams using Cursor,
Claude, MCP servers, CrewAI, GitHub Actions, or similar automation inside a
project and asking: what can these tools do, which actions are risky, and which
paths should be routed through AgentVeil?

AgentVeil is one action-control system. Identity, delegation, approvals,
receipts, and reputation signals are decision inputs and evidence mechanisms,
not separate public product promises.

## Step 1 - Check Agent Capabilities Before Deployment

Lurkr is a local pre-runtime scanner for risky AI-agent capabilities.

```bash
pip install lurkr
lurkr scan --path ./your-agent-project
```

Treat the report as a triage input before wiring runtime controls.

## Step 2 - Route One Action Path

The public routed path available today is MCP Proxy:

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy init --quickstart-filesystem ./sandbox
agentveil-mcp-proxy doctor --full
agentveil-mcp-proxy run
```

MCP Proxy controls only MCP calls routed through the proxy. Actions outside the
proxy are not classified or logged.

## Step 3 - Produce Evidence For The Routed Path

For backend-connected SDK paths:

1. Register or load an agent identity.
2. Receive a delegation receipt from the workflow owner.
3. Call `controlled_action(...)` before the sensitive action.
4. If approval is required, route approval to the principal and resume after
   approval.
5. Store receipt text or a proof packet for later review.

Relevant guides:

- [Customer Integration](CUSTOMER_INTEGRATION.md)
- [DelegationReceipt Guide](DELEGATION_RECEIPT.md)
- [Approval Routing](APPROVAL_ROUTING.md)
- [Proof Packet Guide](PROOF_PACKET.md)
- [Error Handling](ERRORS.md)

## Current / Preview Status

| Capability | Status |
|---|---|
| Lurkr pre-runtime check | Available as `lurkr` |
| MCP Proxy routed MCP calls | Available as `agentveil-mcp-proxy` |
| SDK controlled-action calls | Available for integrated application paths |
| Local policy CLI | Planned |
| Credential custody boundary | Preview/design-partner pattern |
| Egress boundary | Preview/design-partner pattern |
| API gate boundary | Preview/design-partner pattern |

Public claims should track this table. If a capability is listed as planned or
preview, do not treat it as shipped behavior.

## Advanced Protocol Primitives

Agent identity, reputation credentials, delegation receipts, credential
helpers, and optional framework adapter modules remain available as advanced protocol
primitives when their framework dependencies are installed. See [Agent Network (Advanced)](ADVANCED_AGENT_NETWORK.md) when you
need those primitives directly.
