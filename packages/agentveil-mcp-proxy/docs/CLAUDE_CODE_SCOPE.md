# Claude Code Connector — Scope and Quickstart

The AgentVeil MCP Proxy can be installed as a project-local connector for
Claude Code. The connector routes selected Claude Code actions through an
AgentVeil control boundary: native mutations are denied with a redirect, and
the AgentVeil controlled MCP route owns approval and bounded evidence.

This document describes only the public connector path. It does not describe
policy-pack internals, guided remediation, or product methodology.

## What the connector controls

- A project-local Claude Code `PreToolUse` hook installed into
  `./.claude/settings.json`.
- Native Claude Code mutation tools (`Write`, `Edit`, `MultiEdit`,
  `NotebookEdit`, mutating `Bash`) are denied **before** the mutation, with a
  generic redirect to the AgentVeil controlled MCP route.
- MCP tool calls routed to the `agentveil-mcp-proxy` server pass through the
  hook and are governed by the MCP Proxy itself (classification, approval,
  evidence).
- Bounded JSONL evidence for hook decisions under
  `./.claude/agentveil/evidence.jsonl`. Evidence rows carry hashes and bounded
  references only — no raw prompt, file content, shell command body, tokens, or
  full tool payload.

## Setup UX

The intended product setup is one project command after package install:

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy setup claude-code --yes
```

That one-command setup is the target public UX. Until that command lands, the
same connector can be configured with the lower-level primitives below. Do not
treat the lower-level sequence as the final product setup shape.

## Current lower-level setup

```bash
pip install agentveil-mcp-proxy

# initialize a local proxy with a sandboxed filesystem downstream
agentveil-mcp-proxy init --quickstart-filesystem ./sandbox

# install the project-local Claude Code PreToolUse hook
agentveil-mcp-proxy install-claude-hook --project --yes

# write the project-local Claude Code MCP route (.mcp.json)
agentveil-mcp-proxy connect claude_code --write

# show bounded connector status
agentveil-mcp-proxy status-claude-hook --project --json
```

Both setup shapes require restarting / reloading Claude Code for the project so
it loads the hook and the MCP route. To remove the connector with the current
lower-level command:

```bash
agentveil-mcp-proxy uninstall-claude-hook --project --yes
```

`uninstall-claude-hook` removes only the AgentVeil-managed hook entry and
preserves unrelated Claude Code settings and hooks. Restart Claude Code after
removal.

## Expected flow

1. The agent attempts a native mutation (for example `Write`). The project hook
   denies it before the mutation and returns a generic redirect telling the
   agent to use the AgentVeil controlled MCP route for the same intent.
2. The agent calls the controlled MCP write tool
   (`mcp__agentveil-mcp-proxy__*`). The hook passes that call through; the MCP
   Proxy classifies it and requires approval for a write.
3. An approval is surfaced through the MCP Proxy approval path. The target file
   is not written before approval.
4. After approval, a retry of the same controlled MCP call writes the file into
   the configured quickstart sandbox, and the MCP Proxy records bounded
   evidence for the routed decision.

The MCP Proxy — not the hook — owns approval and evidence for routed MCP calls.
The hook's role is to deny native mutations and redirect to that route.

## Status meaning (connector-local only)

`status-claude-hook` reports connector-local truth about the project hook:

- `unsafe` — no managed hook, missing settings, or unparseable settings.
- `advisory` — the managed hook is installed and points at the installed
  module, but it has not been proven to fire yet (restart/reload likely
  required).
- `protected` — the managed hook is installed **and** local evidence shows it
  has fired after the current install.

This status is scoped to the project Claude Code hook only. It is not a
host-wide or machine-wide protection signal.

## Limits

The connector is deliberately narrow. It does **not** claim host-wide control.

- **Project-local only.** The hook and MCP route apply to the project where you
  installed them. The connector does not modify user/global Claude Code config
  and does not protect other projects.
- **Not host-wide.** The connector controls only Claude Code tool calls in the
  configured project. It does not monitor or control the machine.
- **`claude --bare` bypasses the hook.** Claude Code's `--bare` mode skips
  hooks; actions run under `--bare` are not governed by the connector.
- **Out-of-band actions are outside control.** Manual edits in an IDE, external
  terminals, and direct filesystem changes are not Claude Code tool calls and
  are not controlled.
- **Only configured/routed calls are controlled.** Native mutation tools are
  denied; the controlled MCP route is governed by the proxy. Calls that are not
  routed through the connector are not classified or logged by it.
- **Quickstart writes stay under the sandbox root.** The
  `--quickstart-filesystem ./sandbox` downstream writes within the configured
  sandbox path.
- **Claude Code may prompt first.** Claude Code can show its own MCP tool
  permission prompt before the AgentVeil approval step.
- **Exact approval scope.** Approval is bound to the exact action payload, so a
  retry whose content differs from what was approved may require a fresh
  approval. This protects against approving one action and executing a
  different one.

## Not in this connector

This connector is the minimal public path. It does not include guided
remediation logic, policy-pack content, acceptance methodology, or any
host-wide, all-terminal, or hosted-custody capability. <!-- claim-check: allow negative boundary; this disclaims host-wide/all-terminal/hosted claims, it does not assert them. -->

See [MCP Proxy Operations](../../../docs/MCP_PROXY_OPERATIONS.md) for downstream
lifecycle and [Data Handling](../../../docs/DATA_HANDLING.md) for the evidence
privacy model.
