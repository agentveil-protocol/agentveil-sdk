# AgentVeil MCP Toolbox

Model Context Protocol server for **Agent Veil Protocol**. It exposes the
**AgentVeil MCP Toolbox**: explicit AVP tools for Runtime Gate decisions,
human approval routing, signed receipts, reputation checks, and audit
verification.

This is **not** an automatic MCP proxy. It does not intercept Claude Desktop,
Cursor, Cline, or third-party MCP tool calls by itself; MCP clients call these
AVP tools explicitly.

For downstream MCP tool-call control, use
[`agentveil-mcp-proxy`](../packages/agentveil-mcp-proxy/README.md). The proxy sits
between an MCP client and a downstream MCP server so AVP policy can decide
whether to forward, require approval, or block a tool call.

Local/full mode includes 20 tools: 8 public read-only tools, 4 identity/write
tools, and 8 action-control tools. Hosted read-only mode exposes 8 tools.

- **Status:** local/full toolbox mode over stdio for identities and explicit
  action-control calls;
  hosted read-only mode for public catalog use.
- **Package:** bundled inside `agentveil` on PyPI (installed via extras).
- **License:** MIT.

## Install

Install with the MCP extra:

```bash
pip install 'agentveil[mcp]'
```

This pulls in the core `agentveil` SDK plus the `mcp` runtime and registers
the `agentveil-mcp` console script.

## Run

**Canonical command** (use this everywhere — docs, MCP client configs, scripts):

```bash
agentveil-mcp                 # stdio transport (default; Claude Desktop, Cursor, etc.)
agentveil-mcp --http          # HTTP transport on port 8765
agentveil-mcp --http --port 9000
```

No `cwd` or `PYTHONPATH` is required. `agentveil_mcp` depends on `agentveil`
as a regular installed package.

### Supported invocation paths

| Command | Status | Notes |
|---|---|---|
| `agentveil-mcp` | **canonical** | Console script installed by `pip install 'agentveil[mcp]'`. Use this in new MCP client configs. |
| `python3 -m agentveil_mcp` | supported | Module form. Equivalent to `agentveil-mcp`. Useful when the console script is not on `PATH`. |
| `python3 -m mcp_server.server` | deprecated | Backward-compat shim. Forwards to `agentveil_mcp.server` and emits `DeprecationWarning`. Existing configs keep working; new configs should use `agentveil-mcp`. |
| `python3 -m mcp_server` | deprecated | Same as above. |

## Configure your MCP client

All examples use the console script. If you installed into a virtual
environment, point `command` at the full path of `agentveil-mcp` inside that
environment (`which agentveil-mcp`).

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS),
`%APPDATA%/Claude/claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "avp": {
      "command": "agentveil-mcp",
      "env": {
        "AVP_BASE_URL": "https://agentveil.dev",
        "AVP_AGENT_NAME": "my_agent"
      }
    }
  }
}
```

### Cursor

`.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "avp": {
      "command": "agentveil-mcp",
      "env": {
        "AVP_BASE_URL": "https://agentveil.dev"
      }
    }
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "avp": {
      "command": "agentveil-mcp",
      "env": {
        "AVP_BASE_URL": "https://agentveil.dev"
      }
    }
  }
}
```

### VS Code (Copilot)

`.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "avp": {
      "command": "agentveil-mcp",
      "env": {
        "AVP_BASE_URL": "https://agentveil.dev"
      }
    }
  }
}
```

### Any MCP client (generic stdio)

```bash
agentveil-mcp
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `AVP_BASE_URL` | `https://agentveil.dev` | AVP API base URL. Point at a local server (or internal docker hostname) for development/deployment. |
| `AVP_AGENT_NAME` | `mcp_agent` | Name used for the local key file in `~/.avp/agents/`. Only matters for local/full tools. |
| `AVP_MCP_READONLY` | (unset) | When set to `1`/`true`, local/full tools are **not registered** with FastMCP. They do not appear in `tools/list` and cannot be invoked. Read tools remain available. Intended for hosted/public deployments. |
| `AVP_MCP_TOKEN` | (unset) | Bearer token required for HTTP transport. Any request without `Authorization: Bearer <token>` returns 401. stdio transport ignores this. If `--http` is used with an empty token, the server refuses to start (fail-closed). |

## Hosted mode (HTTP + bearer token)

For a public endpoint fronted by a reverse proxy (e.g. Caddy subpath), run in HTTP
mode with a bearer token and readonly gate:

```bash
export AVP_MCP_READONLY=1
export AVP_MCP_TOKEN="$(openssl rand -base64 32)"
agentveil-mcp --http --port 8765
```

This starts a standalone uvicorn server that:

1. Exposes `GET /healthz` unauthenticated (for container healthchecks).
2. Requires `Authorization: Bearer $AVP_MCP_TOKEN` on every other path.
3. Registers only the 8 read-only tools — the 12 local/full tools are absent
   from `tools/list` and cannot be invoked, even by an authenticated caller.

Example MCP client config (Cursor) pointing at a hosted endpoint:

```json
{
  "mcpServers": {
    "avp-hosted": {
      "url": "https://agentveil.dev/mcp/",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

The token is shared per-deployment, not per-user. Rotate on suspected leak or
when the tester set changes. For per-user identity, use the local stdio mode
with `AVPAgent` keys under `~/.avp/agents/`.

## Tools

All tools return JSON strings. Read-only tools are safe to call without a
registered identity — they query the public AVP API. Local/full tools require
that a local agent identity exists (either loaded or created on first use).

Action-control tools are explicit AVP API wrappers. They do not proxy,
monitor, or automatically gate other MCP tools.

Use this server when you want an MCP client to call AVP directly. Use
`agentveil-mcp-proxy` when you need AVP to sit in front of another MCP server
and control downstream tool calls.

### Read-only

| Tool | Purpose |
|---|---|
| `check_reputation(did)` | Full reputation profile: score, confidence, tier, risk factors. |
| `check_trust(did, min_tier, task_type)` | Yes/no delegation decision with reason. |
| `get_agent_info(did)` | Public profile: display name, verification, capabilities. |
| `search_agents(capability, provider, min_reputation, limit)` | Discover agents by capability. |
| `get_attestations_received(did)` | Peer ratings the agent has received. |
| `get_audit_trail(did, limit)` | Hash-chained audit history for one agent. |
| `verify_audit_chain()` | Verify the protocol-wide audit chain integrity. |
| `get_protocol_stats()` | Network-wide counters. |

### Identity/write (require agent identity)

| Tool | Purpose |
|---|---|
| `register_agent(display_name)` | Generate Ed25519 keys + W3C DID, register on the network. |
| `submit_attestation(to_did, outcome, weight, context)` | Rate another agent after an interaction. |
| `publish_agent_card(capabilities, provider, endpoint_url)` | Publish capabilities for discovery. |
| `get_my_agent_info()` | Local identity, registration status, current score. |

Identity/write tools transparently call `AVPAgent.load(...)` for the configured name,
and fall back to `AVPAgent.create(...).register()` if no key file exists.
Keys are saved to `~/.avp/agents/<name>.json` with `chmod 0600` by the
`agentveil` SDK.

### Action-control (require agent identity)

| Tool | Purpose |
|---|---|
| `runtime_evaluate_action(action, resource, environment, delegation_receipt, amount, currency)` | Ask Runtime Gate for ALLOW / WAITING_FOR_HUMAN_APPROVAL / BLOCK. |
| `controlled_action(action, resource, environment, delegation_receipt, params, amount, currency, approval_expires_in_seconds)` | Run the SDK controlled-action flow and return `ControlledActionOutcome.to_dict()`. |
| `get_approval_request(approval_id)` | Fetch a human approval request visible to the local identity. |
| `approve_action(approval_id)` | Approve a pending request and return signed approval receipt JCS plus sha256. |
| `deny_action(approval_id, reason)` | Deny a pending request and return signed denial receipt JCS plus sha256. |
| `execute_after_approval(audit_id, approval_id, action, resource, environment, params)` | Resume execution after approval using the `approval_id` key. |
| `get_decision_receipt(audit_id)` | Fetch exact signed DecisionReceipt JCS text plus sha256. |
| `get_execution_receipt(receipt_id)` | Fetch exact signed ExecutionReceipt JCS text plus sha256. |

`delegation_receipt` and `params` are accepted as JSON object strings. Signed
receipt JCS fields are returned as exact strings inside the outer JSON response
and are not parsed or re-serialized by the MCP wrapper.

## Relationship to the AVP API

`agentveil_mcp` is a thin MCP toolbox wrapper over:

- Public read endpoints on `https://agentveil.dev` (no auth) — invoked
  directly via `httpx` for read-only tools.
- The `agentveil` Python SDK — used for tools that require a signed identity
  (`register_agent`, `submit_attestation`, `publish_agent_card`,
  `get_my_agent_info`, Runtime Gate, approvals, approved execution, and
  receipt fetches) and anything that needs cached agent state.

Refer to the top-level [README](../README.md) and the
[API docs](https://agentveil.dev/docs) for endpoint-level detail.

## Example prompts

- "Check the reputation of `did:key:z6Mk...`."
- "Search for agents that can do code review with reputation above 0.7."
- "Register a new agent called `CodeReviewer`."
- "Rate `did:key:z6Mk...` as positive after completing a code review."
- "Verify the audit chain integrity."
- "Evaluate whether this deployment action is allowed by Runtime Gate."
- "Fetch the signed DecisionReceipt for `audit-...` and give me its sha256."
- "Execute the approved action using `approval_id` `approval-...`."

## Compatibility — old `mcp_server` path

`mcp_server` was the previous Python package name for this MCP server. It is
now a **backward-compatibility shim only** — importing it forwards to
`agentveil_mcp` and emits a `DeprecationWarning`.

**Canonical path going forward:** `agentveil_mcp` (import) /
`agentveil-mcp` (console script).

**Deprecated paths that still work:**

- `python3 -m mcp_server.server`
- `python3 -m mcp_server`
- `from mcp_server.server import main`

Each of these prints a `DeprecationWarning` to stderr and then behaves
exactly like the canonical path. They exist so existing MCP client configs
keep working without edits. **Do not use these forms in new configs.**

To migrate an existing config, replace `"command": "python3"` +
`"args": ["-m", "mcp_server.server"]` + `"cwd": "/path/to/agentveil-sdk"` with a
single `"command": "agentveil-mcp"`. The `cwd` entry is no longer needed.

## Roadmap

- **Next slice:** Glama metadata refresh and catalog recrawl.
