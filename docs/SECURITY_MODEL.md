# Security Model

> **Status:** the public SDK and MCP Proxy are early-stage routed action-control
> components. They control only paths that are explicitly integrated or routed
> through AgentVeil. Credential custody, egress boundaries, and API gates are
> preview/design-partner boundary patterns.

AgentVeil separates decision logic from enforcement. The SDK can request
decisions and preserve signed evidence. Technical enforcement depends on where
credentials, network access, and execution authority live.

## Routed SDK Mode

Use SDK mode when the host application already controls the action path and can
call AgentVeil before executing a sensitive action.

SDK mode supports:

- `integration_preflight()` setup and signed-read readiness checks;
- delegation receipt issuance and offline verification;
- Runtime Gate calls with action, resource, environment, and receipt context;
- human approval orchestration;
- signed receipts and proof packets for audit and review.

SDK mode is not full enforcement if the agent process still holds direct
provider credentials or can call the risky tool outside `controlled_action(...)`.
In that setup, AgentVeil can evaluate, record, and retain evidence for the
controlled path, but the application owner must still remove or block bypass
paths.

## MCP Proxy Mode

MCP Proxy is the available public routed path today for MCP tool calls. It can
apply policy to calls routed through `agentveil-mcp-proxy` and keep bounded
local evidence.

MCP Proxy does not control host shell commands, IDE-native edits, direct git or
pip commands, or calls made to tools outside the proxy. Actions not routed
through the proxy are not classified or logged.

## Boundary Patterns

Credential custody, egress boundaries, and API gates are stronger boundary
patterns because the agent does not hold the credential or network path needed
to perform the sensitive action directly. These patterns are preview and
design-partner work, not general public release paths in this SDK.

The security requirement is the same in each pattern: the risky credential or
external effect must be reachable only by the boundary that performs AgentVeil
checks, not by the agent runtime.

## Receipt And Evidence Strength

Receipt records are evidence of the routed path that produced them. They are
strongest when emitted by the component that actually controls execution.

- SDK mode receipts cover the SDK-controlled path.
- MCP Proxy records cover routed MCP calls.
- Boundary receipts cover actions where the boundary owns the credential or
  external effect.
- Re-serializing signed receipt JSON can change bytes; keep raw signed receipt
  text when offline checking matters.

## Minimum Guidance

- Use `integration_preflight()` before Runtime Gate calls.
- Issue delegation receipts from the principal or workflow owner, not from the
  acting agent.
- Route production/destructive/financial tools through a boundary that owns the
  risky credential when hard enforcement is required.
- Treat direct provider credentials inside the agent runtime as a bypass risk.
- Store delegation receipts, Runtime Gate audit IDs, approval receipts,
  execution receipts, and proof packets for later review.
