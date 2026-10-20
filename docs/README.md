# AgentVeil Documentation

Start with the existing product README; use this index to find the appropriate
route without repeating setup.

## Start here

- [Console and project connector setup](../README.md#start-from-the-console)
- [MCP Proxy package and CLI scope](../packages/agentveil-mcp-proxy/README.md)
- [Manual Core MCP Proxy quickstart](MCP_PROXY_QUICKSTART.md)
- [Connector mechanisms and coverage](../README.md#connectors-available-today)
- [Product scope and availability](../README.md#scope)

## Operations and integrations

- [MCP Proxy operations](MCP_PROXY_OPERATIONS.md)
- [Approval routing](APPROVAL_ROUTING.md)
- [Customer integration](CUSTOMER_INTEGRATION.md)
- [Integration examples](INTEGRATIONS.md)

Framework examples and SDK helpers are not interchangeable with project hook
connectors. Choose the documented integration boundary for your application.

## Security and data handling

- [Security model and bypass boundaries](SECURITY_MODEL.md)
- [Data handling by workflow](DATA_HANDLING.md)
- [MCP Proxy design principles](MCP_PROXY_DESIGN_PRINCIPLES.md)
- [Security reporting](../SECURITY.md)
- [SDK, proxy and hosted licensing boundaries](../LICENSING.md)

## Evidence and advanced SDK APIs

- [Local evidence inspection and export](../packages/agentveil-mcp-proxy/README.md#local-evidence)
- [Proof packets](PROOF_PACKET.md)
- [Delegation receipts](DELEGATION_RECEIPT.md)
- [Advanced Python SDK](PYTHON_SDK_ADVANCED.md)
- [Advanced agent network primitives](ADVANCED_AGENT_NETWORK.md)
- [API reference](API.md)
- [Protocol reference](PROTOCOL.md)

API/reference documentation describes the relevant primitives; it is not a
promise that an equivalent hosted UI or connector workflow is generally available.

## Releases and historical notes

- [Release history](../CHANGELOG.md)
- [Current roadmap](../ROADMAP.md)
- [Release provenance](RELEASE_PROVENANCE.md)

The dated notes below describe specific historical changes, not current setup
instructions. They remain at their existing paths:

- [Runtime Gate wire contract, 2026-07-28](runtime_gate_public_wire_contract_corrective_2026-07-28.md)
- [Runtime Gate privacy/action wire, 2026-07-29](runtime_gate_privacy_action_wire_corrective_2026-07-29.md)
- [Risk compatibility contract, 2026-07-29](production_risk_compatibility_public_contract_2026-07-29.md)
- [Downstream EOF/approval retirement, 2026-07-30](downstream_eof_approval_retirement_2026-07-30.md)

For onboarding, follow Start here above rather than replaying historical change notes.
