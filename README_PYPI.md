# AgentVeil

**Routed action control for risky AI-agent actions.**

AgentVeil's public product path is action control for AI-agent workflows:
project connectors, MCP Proxy routing, approval / redirect / block decisions,
and bounded local evidence.

For the action-control path, install the MCP Proxy package:

```bash
pip install agentveil-mcp-proxy
```

## Quick Start

For a project connector, start at the [Console](https://agentveil.dev/console/auth)
and follow the command for your agent, or use the
[connector instructions](https://github.com/agentveil-protocol/agentveil-sdk#start-from-the-console).
Console pairing is optional for local connector/proxy control. Connector
setup/status can also attempt browser pairing and, for eligible workspaces,
install an additional provider; see the
[package scope](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/packages/agentveil-mcp-proxy/README.md#connect-to-agentveil-console-optional).

For manual routing of one downstream MCP server, use the Core MCP Proxy path:

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy init --quickstart-filesystem ./sandbox
agentveil-mcp-proxy doctor --full
agentveil-mcp-proxy run
```

MCP Proxy gates only tool calls routed through the proxy. It does not control
host shell, IDE-native edits, direct git/pip commands, or other actions that
bypass the proxy. Actions not routed through AgentVeil are not classified or
logged by that proxy. Project hooks add only their documented native-tool coverage.
Backend-backed actions still require the configured service; see the
[manual quickstart](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/MCP_PROXY_QUICKSTART.md).

Console summaries and direct hosted SDK/API calls have different data boundaries;
see [Data Handling](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/DATA_HANDLING.md).

## Python SDK and advanced protocol primitives

Advanced Python SDK package: `agentveil`.

The root Python SDK remains available for advanced protocol primitives: local
DID identity, delegation receipts, receipt helpers, credential checks, advisory
reputation, and optional framework adapter modules when their framework
dependencies are installed.

Run a local SDK-only identity and delegation check with no server required:

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

## What AgentVeil Provides

- routed action decisions for allow, approval-required, or block outcomes;
- approval routing for sensitive routed requests;
- bounded evidence for local review and offline checks;
- local privacy defaults for MCP Proxy;
- protocol primitives for DID identity, delegation receipts, receipt
  helpers, credential checks, and optional framework adapter modules when their framework dependencies are installed.

## Resources

- [Full GitHub README](https://github.com/agentveil-protocol/agentveil-sdk#readme)
- [MCP Proxy README](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/packages/agentveil-mcp-proxy/README.md)
- [Security Model](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/SECURITY_MODEL.md)
- [Data Handling](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/DATA_HANDLING.md)
- [Customer Integration guide](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/docs/CUSTOMER_INTEGRATION.md)
- [AgentVeil website](https://agentveil.dev)

## License

The `agentveil` package is MIT licensed. The separate `agentveil-mcp-proxy`
package is source-available under Business Source License 1.1. See the
[licensing boundary](https://github.com/agentveil-protocol/agentveil-sdk/blob/main/LICENSING.md).
Hosted Console and additional capabilities have separate availability and terms;
see [plans and pricing](https://agentveil.dev/#pricing).
