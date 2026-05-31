# Licensing

This is a multi-license repository. The top-level MIT license applies to the
public SDK surfaces listed below. It does not apply to the separately packaged
MCP transport proxy under `packages/agentveil-mcp-proxy/`.

## MIT-Licensed Public SDK Surfaces

The following repository surfaces are licensed under the root [MIT License](LICENSE):

- `agentveil`: the public Python SDK, protocol helpers, identity helpers,
  proof helpers, Runtime Gate client wrappers, and framework integration helpers.
- `agentveil_mcp`: the explicit AgentVeil MCP toolbox. This server exposes
  AgentVeil tools directly; it does not intercept, monitor, or gate unrelated
  downstream MCP tools.
- Public examples, public documentation, and verification helpers unless a file
  or package states a different license.

These surfaces are intended for public developer adoption and integration.

## Source-Available MCP Proxy

The MCP transport proxy is a separate package under
[`packages/agentveil-mcp-proxy/`](packages/agentveil-mcp-proxy/) and is licensed
under the [Business Source License 1.1](packages/agentveil-mcp-proxy/LICENSE).
It is not MIT licensed.

This package includes the runtime MCP proxy surface for downstream tool-call
gating, policy enforcement, approval routing, local evidence/audit behavior, and
replay defense. Its PyPI package name is `agentveil-mcp-proxy`.

## Commercial And Hosted Surfaces

Hosted services, managed dashboards, organization policy administration,
commercial risk scoring, billing, private customer integrations, and other
AgentVeil commercial control-plane services are not included in the MIT SDK
license unless explicitly stated in a separate written license.

## Packaging Boundary

The `agentveil` PyPI package is MIT licensed and must not ship the
`agentveil_mcp_proxy` package. The `agentveil-mcp-proxy` PyPI package carries
its own Business Source License 1.1 license file and package metadata.

When adding new public code, classify it before publication:

- `public`: SDK/API helpers, docs, examples, and verification utilities that can
  safely be MIT licensed.
- `source-available`: local adapters or enforcement components that should be
  inspectable but commercially restricted.
- `private`: hosted backend, proprietary decisioning, customer-private
  integrations, deployment logic, billing, or enterprise control-plane logic.
