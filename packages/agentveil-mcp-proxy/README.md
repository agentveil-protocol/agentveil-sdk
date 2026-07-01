# agentveil-mcp-proxy

`agentveil-mcp-proxy` is the public AgentVeil package for project connector
setup and routed MCP action control. It works alongside agent runtimes and
applies the same proof + redirect loop to configured action paths: attempt,
decision, controlled path when available, local proof.

It includes two public surfaces:

1. **Project connector setup** for supported agent clients such as Cursor,
   Claude Code, Codex, and Gemini CLI. Connectors install managed project-local
   hooks and MCP route config so supported native agent mutations can be
   blocked with redirect guidance toward the AgentVeil MCP route. Hermes CLI is
   supported as a controlled MCP launch profile.
2. **Core MCP Proxy**, which wraps a downstream MCP server and applies
   AgentVeil policy to calls that pass through the proxy: allow,
   approval-required, redirect, hard-block, with bounded local evidence.

This package is source-available under the Business Source License 1.1. See
[`LICENSE`](LICENSE).

## Scope

AgentVeil control is scoped to configured project connectors and routed MCP
calls.

- Project connectors can control supported native agent mutation tools only
  inside configured projects and supported client hook paths.
- The Core MCP Proxy controls only MCP tool calls that are explicitly routed
  through `agentveil-mcp-proxy`.
- The Core MCP Proxy alone does not control host shell commands or IDE-native
  file edits.
- AgentVeil does not control direct human terminal commands, direct git, pip,
  deploy, or package-manager commands outside configured AgentVeil paths.
- It does not create a Cursor, Claude Code, Codex, Gemini CLI, Hermes, or
  desktop-wide lock.
- Actions outside configured connectors and routed proxy calls are not
  classified or logged.

Use credential custody, egress boundaries, or API gates when an action must be
controlled below the agent process. Those boundary patterns are preview and
design-partner work, not general public release paths in this package.

## What This Package Adds

Agent runtimes execute agents and expose tools. `agentveil-mcp-proxy` adds a
local action-control layer around configured paths:

- project connectors for supported runtime hooks;
- routed MCP policy and approval;
- bounded local evidence;
- starter policy packs for common routed action types.

It does not replace Cursor, Claude Code, Codex, autonomous frameworks, or custom
MCP clients.

## Install

```bash
pip install agentveil-mcp-proxy
```

This installs the `agentveil-mcp-proxy` console script. The core `agentveil`
SDK is installed as a dependency.

## Quick Start

### Cursor project connector

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy setup cursor --choose-folder
```

Choose the project folder to protect, then reopen / reload Cursor for that
project. See [Cursor project-local hooks](docs/CURSOR_HOOKS.md).

Some Cursor versions may require enabling the managed `agentveil-mcp-proxy` MCP
server once in **Tools & MCPs** after reload.

### Claude Code project connector

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy setup claude-code --choose-folder --yes
```

Choose the project folder to protect, then reopen / reload Claude Code for that
project. See [Claude Code Connector — Scope and Quickstart](docs/CLAUDE_CODE_SCOPE.md).

### Codex project connector

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy setup codex --choose-folder --yes
```

Choose the project folder to protect, then open / restart Codex for that
project. Codex asks you to trust the AgentVeil project hook once; until hook
evidence is observed, `setup status --client codex` remains advisory, not
protected.

### Gemini CLI project connector

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy setup gemini-cli --choose-folder --yes
```

Choose the project folder to protect, then open / restart Gemini CLI for that
project. Gemini CLI asks you to trust the project folder before it loads local
settings, hooks, and MCP servers.

### Hermes CLI controlled MCP profile

Hermes CLI is launched through AgentVeil rather than installed as a persistent
project hook:

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy launch --profile hermes-cli --choose-folder -- \
  hermes chat -q "Create a project note"
```

This configures a project-local Hermes home and routes Hermes to the AgentVeil
MCP tools. Routed reads, writes, approval, sandbox boundaries, redirect
guidance, and local proof use the shared AgentVeil control layer. Native Hermes
tools are limited by profile settings; AgentVeil does not claim host-wide
control of Hermes or the machine.

### Walkable example after setup

In the configured project:

1. Ask the agent to read project files. Routed reads should allow.
2. Ask the agent to write a file. The configured connector should stop the
   native mutation with redirect guidance; the agent should then use the
   controlled MCP route, where risky writes require approval.
3. Open the approval page and review bounded proof details.
4. Confirm local proof:

```bash
agentveil-mcp-proxy events show --last
```

### Core MCP Proxy

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

For a local first run without installing another MCP server, configure the
built-in sandboxed filesystem downstream:

```bash
agentveil-mcp-proxy init --quickstart-filesystem ./sandbox
agentveil-mcp-proxy doctor --full
agentveil-mcp-proxy smoke
```

Then run the proxy:

```bash
agentveil-mcp-proxy run
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

## Configure An MCP Client

Point your MCP client at `agentveil-mcp-proxy run` instead of directly at the
downstream MCP server. The proxy reads downstream server config from
`~/.avp/mcp-proxy/config.json`.

If you installed into a virtual environment, point `command` at the full path of
`agentveil-mcp-proxy` inside that environment.

To print copy-pasteable client config without editing application files:

```bash
agentveil-mcp-proxy client-config print
agentveil-mcp-proxy client-config print --client cursor --proxy-command "$(which agentveil-mcp-proxy)"
agentveil-mcp-proxy client-config print --json
```

This is dry-run only: it writes to stdout, not `~/.cursor`, Claude Desktop, or
other application config directories.

Any MCP-speaking client can use this route when it is explicitly configured to
call `agentveil-mcp-proxy run`. That is routed MCP control, not global control
of the client or host.

### Generic stdio configuration

```json
{
  "mcpServers": {
    "agentveil-mcp-proxy": {
      "command": "agentveil-mcp-proxy",
      "args": ["run"]
    }
  }
}
```

## Local Evidence

Approval-gated routed tool calls write durable local records to the MCP
Proxy evidence store under the configured AVP home directory.

Inspect recent bounded decisions:

```bash
agentveil-mcp-proxy events show --last
agentveil-mcp-proxy events show --last --json
agentveil-mcp-proxy events show --last --verify
```

Export an evidence bundle for offline checks:

```bash
agentveil-mcp-proxy export-evidence ./bundle.json
agentveil-mcp-proxy verify ./bundle.json --trusted-signer-did did:key:...
```

Raw MCP arguments, prompts, outputs, tokens, source code, secrets, and private
logs remain local by default. Runtime decisions should use bounded metadata and
hashes. See [Data Handling](../../docs/DATA_HANDLING.md).

## Built-In Policy Packs

`init --policy-pack <name>` selects a starter pack:

| Pack | Default behavior |
|---|---|
| `default` | Tool calls are forwarded to the Runtime Gate path. |
| `github` | Reads allowed; writes forwarded to Runtime Gate; destructive verbs require approval. |
| `filesystem` | Reads allowed; writes require approval; destructive verbs are denied. |
| `shell` | Shell tool calls require approval when routed through the proxy. |

Built-in packs are starter templates, not exhaustive policies. Review patterns
for your specific downstream server.

## CLI Commands

| Command | Purpose |
|---|---|
| `init` | Create encrypted identity, config, and control grant. |
| `init --quickstart-filesystem <path>` | Configure the built-in filesystem downstream for local first run. |
| `doctor` | Validate local files and control grant. |
| `doctor --full` | Launch downstream and verify MCP `initialize` / `tools/list`. |
| `downstream set` | Write downstream MCP server config without hand-editing JSON. |
| `client-config print` | Print MCP client config snippets. |
| `smoke` | Launch downstream and run a local MCP smoke check. |
| `run` | Run stdio passthrough for MCP clients. |
| `export-evidence <path>` | Export a local evidence bundle. |
| `verify <bundle.json>` | Verify a previously exported bundle. |
| `events show --last` | Show recent bounded evidence in human-readable form. |
| `events show --last --json` | Show recent bounded evidence as JSON. |
| `evidence-summary` | Print local evidence counts. |
| `events list --limit 20` | Lower-level record listing for debugging or export prep. |
| `setup cursor --choose-folder` | Configure a project-local Cursor connector. |
| `setup claude-code --choose-folder --yes` | Configure a project-local Claude Code connector. |
| `setup codex --choose-folder --yes` | Configure a project-local Codex connector. |
| `setup gemini-cli --choose-folder --yes` | Configure a project-local Gemini CLI connector. |
| `launch --profile hermes-cli --choose-folder -- hermes chat -q "..."` | Launch Hermes CLI with the AgentVeil controlled MCP profile. |
| `setup status --json` | Print bounded connector/proxy status. |
| `setup remove <cursor|claude-code|codex|gemini-cli>` | Preview managed connector removal. |
| `setup remove <cursor|claude-code|codex|gemini-cli> --yes` | Remove only AgentVeil-managed connector entries. |

## Relationship To AgentVeil

`agentveil-mcp-proxy` is the public package for AgentVeil project connectors
and the routed MCP action-control path. The root `agentveil` SDK contains
identity, delegation, Runtime Gate client helpers, receipt helpers, and
framework adapters.

[ops-passphrase]: ../../docs/MCP_PROXY_OPERATIONS.md#security-trade-offs-by-passphrase-source
