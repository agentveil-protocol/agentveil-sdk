# AVP Roadmap

## Source Of Truth

- Current public Python SDK package: `agentveil 0.7.23`.
- Current public MCP Proxy package: `agentveil-mcp-proxy 0.7.49`.
- Package metadata and PyPI are the version source of truth. This roadmap tracks
  product direction only; release history belongs in `CHANGELOG.md`.
- Versions above were checked against PyPI on 2026-10-20; consult package
  metadata for later releases. Planned items have no promised dates.
- A shipped command does not establish that a workspace has the optional
  provider, entitlement or configuration. See [product scope](README.md#scope).

## Available Today

- [x] Public Python SDK on PyPI: `pip install agentveil`
- [x] Public MCP Proxy on PyPI: `pip install agentveil-mcp-proxy`
- [x] Project connector setup for Cursor, Claude Code, Codex, and Gemini CLI
- [x] Hermes CLI controlled MCP launch profile
- [x] Core MCP Proxy route for configured downstream MCP tool calls
- [x] Advanced SDK identity and request-signing primitives; see the
  [SDK section](README.md#python-sdk-and-advanced-protocol-primitives)
- [x] Posture/setup readiness checks with `integration_preflight()`
- [x] Runtime Gate controlled-action flow with `controlled_action(...)`
- [x] Local DelegationReceipt v1 issuance with `issue_delegation_receipt(...)`
- [x] Signed runtime receipts and proof packet verification
- [x] MCP Proxy evidence export and offline verification:
  `agentveil-mcp-proxy export-evidence` and `agentveil-mcp-proxy verify`

- [x] Console sign-in and machine pairing with `agentveil-mcp-proxy login`
- [x] Bounded project connection and decision/approval summary reporting
- [x] Explicit filesystem CA policy preview/apply with `upgrade-ca-policy`;
  execution still requires the configured controlled path and available provider

## Preview / Active Rollout

- [ ] Broader controlled-action rollout for customer workflows
- [ ] Operator-facing documentation for production adoption
- [ ] Deployment documentation for approved customer environments

## Planned

- [ ] Expanded Runtime Gate examples for common agent stacks
- [ ] Dedicated root SDK CLI demo command: `agentveil demo controlled-action`
- [ ] Dedicated root SDK proof commands:
  `agentveil proof export` and `agentveil proof verify --offline`
