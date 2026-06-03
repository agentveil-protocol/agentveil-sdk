# agentveil-mcp-proxy

MCP transport proxy for **AgentVeil Protocol** - Action Control Plane that
wraps a downstream MCP server with runtime decision gating, human approval
routing, durable signed evidence, and replay defense. It is the intercepting
transport adapter for IDE MCP clients such as Claude Desktop, Cursor, Cline,
Windsurf, and VS Code.

This is one integration adapter for AVP. The trust/control/evidence engine and
identity foundation live in the core `agentveil` SDK; this package is the
MCP-transport adapter.

- **Status:** stdio passthrough for one downstream MCP server per proxy
  instance. Encrypted identity by default, durable approval evidence, signed
  receipts, offline bundle verification.
- **Package:** distributed separately as `agentveil-mcp-proxy`. Console script
  `agentveil-mcp-proxy` is preserved.
- **License:** source-available under the Business Source License 1.1. See
  [`LICENSE`](LICENSE).

## Install

```bash
pip install agentveil-mcp-proxy
```

This installs the separately packaged `agentveil-mcp-proxy` console script.
The core `agentveil` SDK is installed automatically as a dependency. If your
environment already pins `agentveil`, keep that pin and install
`agentveil-mcp-proxy` alongside it.

## Quick Start

For the full step-by-step customer cold path (install → init → doctor →
configure downstream → run → export evidence → offline verify) and the
honest list of what the bundle currently does and does not prove, see
[`docs/MCP_PROXY_QUICKSTART.md`](../../docs/MCP_PROXY_QUICKSTART.md).

The short form is:

Create a local proxy identity, config, and control grant:

```bash
agentveil-mcp-proxy init
```

By default `init` creates an encrypted identity. Provide a passphrase
interactively, via `--passphrase-file`, or via the `AVP_PROXY_PASSPHRASE`
environment variable. See
[Operations: Security trade-offs by passphrase source][ops-passphrase].

Validate the local setup:

```bash
agentveil-mcp-proxy doctor
```

For a local first-run without installing another MCP server, configure the
built-in sandboxed filesystem downstream:

```bash
agentveil-mcp-proxy init --quickstart-filesystem ./sandbox
agentveil-mcp-proxy doctor --full
agentveil-mcp-proxy smoke
```

For a real downstream server, write `downstream.command` and `downstream.args`
with the helper:

```bash
agentveil-mcp-proxy downstream set \
  --name filesystem \
  --command npx \
  --arg -y \
  --arg @modelcontextprotocol/server-filesystem \
  --arg /Users/me/work
```

Then run:

```bash
agentveil-mcp-proxy run
```

The proxy reads stdio from your MCP client, classifies tool calls, evaluates
them through AVP Runtime Gate, routes approval prompts to a local browser UI
when needed, persists durable signed evidence, and forwards approved calls to
the downstream server. Raw MCP arguments, prompts, outputs, tokens, source code,
secrets, and private logs remain local by default; Runtime Gate receives only
privacy-filtered metadata and hashes needed for the decision. See
[Data Handling](../../docs/DATA_HANDLING.md).

### Supported invocation paths

| Command | Status |
|---|---|
| `agentveil-mcp-proxy run` | **canonical** - console script passthrough mode |
| `python3 -m agentveil_mcp_proxy run` | supported - module form |

## Configure Your MCP Client

Instead of pointing your IDE directly at a downstream MCP server, point the IDE
at `agentveil-mcp-proxy`. The proxy reads the actual downstream command from
`~/.avp/mcp-proxy/config.json` and wraps that server with Runtime Control Layer
checks.

If you installed into a virtual environment, point `command` at the full path of
`agentveil-mcp-proxy` inside that environment (`which agentveil-mcp-proxy`).

To print copy-pasteable client config without editing IDE files:

```bash
agentveil-mcp-proxy client-config print
agentveil-mcp-proxy client-config print --client cursor --proxy-command "$(which agentveil-mcp-proxy)"
agentveil-mcp-proxy client-config print --json
```

This is dry-run only: it writes to stdout, not `~/.cursor`, Claude Desktop, or
other application config directories.

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, or
`%APPDATA%/Claude/claude_desktop_config.json` on Windows:

```json
{
  "mcpServers": {
    "filesystem-gated": {
      "command": "agentveil-mcp-proxy",
      "args": ["run"]
    }
  }
}
```

The proxy reads downstream server config from
`~/.avp/mcp-proxy/config.json`:

```json
{
  "downstream": {
    "name": "filesystem",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/work"]
  }
}
```

### Cursor

`.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "github-gated": {
      "command": "agentveil-mcp-proxy",
      "args": ["run"]
    }
  }
}
```

`~/.avp/mcp-proxy/config.json`:

```json
{
  "downstream": {
    "name": "github",
    "command": "github-mcp-server",
    "args": []
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "filesystem-gated": {
      "command": "agentveil-mcp-proxy",
      "args": ["run"]
    }
  }
}
```

`~/.avp/mcp-proxy/config.json`:

```json
{
  "downstream": {
    "name": "filesystem",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/work"]
  }
}
```

### VS Code (Copilot)

`.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "filesystem-gated": {
      "command": "agentveil-mcp-proxy",
      "args": ["run"]
    }
  }
}
```

`~/.avp/mcp-proxy/config.json`:

```json
{
  "downstream": {
    "name": "filesystem",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/work"]
  }
}
```

### Any MCP Client (generic stdio)

```bash
agentveil-mcp-proxy run
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AVP_HOME` | `~/.avp` | Override the proxy home directory. Identity, config, control grant, and evidence DB live here. |
| `AVP_PROXY_PASSPHRASE` | (unset) | Encrypted-identity passphrase. **See [Security trade-offs by passphrase source][ops-passphrase]** - env vars can leak through `/proc/<pid>/environ` and `ps eww`; prefer `--passphrase-file` for automated and CI setups. |

## Built-In Policy Packs

`init --policy-pack <name>` selects a starter pack:

| Pack | Default behavior |
|---|---|
| `default` | All tool calls forwarded to AVP Runtime Gate. |
| `github` | Reads allowed; writes forwarded to Runtime Gate; destructive verbs (`delete_*`, `revoke_*`, `destroy_*`, `drop_*`, `purge_*`, `remove_*`) require approval. |
| `filesystem` | Reads allowed; writes require approval; destructive verbs (`delete_*`, `purge_*`, `truncate_*`, `wipe_*`, `format_*`, `rm`, `rmdir_*`, `unlink_*`, `clean_*`) blocked. |
| `shell` | All shell tool calls require approval. |

Customize via the `policy.rules[]` field in
`~/.avp/mcp-proxy/config.json`. Built-in packs are starter templates, not
exhaustive; review patterns for your specific downstream server.

## CLI Commands

| Command | Purpose |
|---|---|
| `init` | Create encrypted identity, config, and control grant. |
| `init --quickstart-filesystem <path>` | Configure the built-in sandboxed filesystem downstream for local first-run. |
| `doctor` | Validate local files and control grant. |
| `doctor --check-backend` | Add a read-only preflight that the backend is reachable and the proxy identity is registered. |
| `doctor --full` | Launch downstream and verify MCP `initialize` / `tools/list`. |
| `downstream set` | Write downstream MCP server config without hand-editing JSON. |
| `configure-downstream` | Backward-compatible alias for `downstream set`. |
| `register` | Register the existing proxy identity with the configured backend. |
| `smoke` | Launch downstream and run the local MCP smoke check. |
| `run` | Run stdio passthrough, the proxy mode used by MCP clients. |
| `reissue-grant` | Refresh the local control grant before expiry. |
| `export-evidence <path>` | Export durable evidence bundle for offline verification. |
| `verify <bundle.json>` | Verify a previously exported bundle. |
| `events list --limit 20` | Print recent privacy-safe evidence records. |
| `events tail --follow` | Follow privacy-safe evidence records. |
| `evidence-summary` | Print aggregate local evidence counts. |
| `events vacuum` / `events --vacuum` | Prune old terminal evidence records. |

See [Operations][ops] for full flag reference and headless/CI patterns.

Before tagging or publishing MCP Proxy behavior changes, run the release
acceptance path from [`docs/MCP_PROXY_RELEASE_ACCEPTANCE.md`][release-acceptance].
It installs the wheel into a clean venv and verifies setup, backend
registration, stdio passthrough, local approval/retry UX, events, export, and
offline verification.

Setup, registration, doctor, smoke, and event-list commands support
machine-readable output:

```bash
agentveil-mcp-proxy init --quickstart-filesystem ./sandbox --json
agentveil-mcp-proxy register --json
agentveil-mcp-proxy doctor --full --json
agentveil-mcp-proxy smoke --json
agentveil-mcp-proxy events list --json
```

## Evidence And Proof

Every approval-gated tool call writes a durable record to a local SQLite
evidence store (`~/.avp/mcp-proxy/evidence.sqlite`, owner-only). Records are
hash-chained, fsync'd on write, and reference signed AVP DecisionReceipt
digests when Runtime Gate authorized the action.

Export an evidence bundle for offline verification:

```bash
agentveil-mcp-proxy export-evidence ./bundle.json
agentveil-mcp-proxy verify ./bundle.json --trusted-signer-did did:key:...
```

The verifier validates chain integrity, receipt signature against pinned signer
DIDs, schema, `audit_id` binding, `payload_hash` binding, risk class, and policy
context hash. See [Operations: Evidence][ops-evidence].

## Headless Mode

For automation and CI, run without a browser approval UI. Either auto-deny every
approval-required action, or load a bounded headless policy that pre-approves
specific `(server, tool, risk_class, payload_hash)` tuples.

```bash
agentveil-mcp-proxy run --headless --auto-deny
agentveil-mcp-proxy run --headless --headless-policy ./headless.json
```

See [Operations: Headless][ops-headless].

## Operations And Security

For full operational depth - passphrase handling, policy override semantics,
multi-instance deployment, evidence vacuum, identity migration, and security
trade-offs - see [`docs/MCP_PROXY_OPERATIONS.md`][ops].

## Relationship To AVP

`agentveil-mcp-proxy` is one integration adapter for Agent Veil Protocol. The
core trust/control/evidence primitives - Runtime Gate, DecisionReceipt
verification, controlled-action flow, identity, and audit chain - live in the
[`agentveil`](../../README.md) SDK. This package is the MCP-transport adapter for
IDE clients; other adapters exist for direct SDK use, framework integrations
(CrewAI, LangGraph, AutoGen, OpenAI), AWS Bedrock, and Microsoft AgentMesh.

See the top-level [README](../../README.md) for the full integration matrix and
the [API docs](https://agentveil.dev/docs) for endpoint-level detail.

## Roadmap

v0.1 ships with these documented limitations targeted for v0.1.1:

- **Backend protocol nonce/freshness:** local replay cache mitigates
  same-process replays within a 5-minute window; full protocol fix adds
  backend-issued nonce plus `issued_at` and `expires_at` to
  `decision_receipt/3`.
- **Windows orphan process containment:** Linux and macOS handle downstream
  orphan cleanup correctly; Windows Job Object assignment has a narrow race
  window during `start()`. Run under a supervisor on Windows in production for
  now.
- **OS keychain identity storage:** v0.1 uses passphrase-encrypted Argon2id
  identity files. v0.1.1+ adds opt-in macOS Keychain, Linux Secret Service, and
  Windows Credential Manager integration.

[ops]: ../../docs/MCP_PROXY_OPERATIONS.md
[ops-passphrase]: ../../docs/MCP_PROXY_OPERATIONS.md#security-trade-offs-by-passphrase-source
[ops-evidence]: ../../docs/MCP_PROXY_OPERATIONS.md#local-evidence-storage
[ops-headless]: ../../docs/MCP_PROXY_OPERATIONS.md#headless-approval-mode
[release-acceptance]: docs/MCP_PROXY_RELEASE_ACCEPTANCE.md
