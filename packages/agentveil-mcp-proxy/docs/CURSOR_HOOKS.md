# Cursor project-local hooks (public SDK)

AgentVeil MCP Proxy can install a project-local Cursor connector with:

```bash
pip install agentveil-mcp-proxy
agentveil-mcp-proxy setup cursor
```

Interactive mode asks which project folder to protect (current folder, another path, or cancel). Non-interactive automation uses:

```bash
agentveil-mcp-proxy setup cursor --choose-folder
agentveil-mcp-proxy setup cursor --workspace ~/Desktop/my-app --yes
```

Broad folders (home, Desktop, Downloads, `.worktrees` containers, and similar) are rejected with a clear message instead of silently installing.

Setup opens Cursor for the selected workspace when supported. Then enable
`agentveil-mcp-proxy` under **Settings → Tools & MCPs** if Cursor leaves it off.

## What setup writes

- `.cursor/hooks.json` — merge-preserving hooks for `preToolUse`, `beforeShellExecution`, and `beforeMCPExecution`
- `.cursor/mcp.json` — merge-preserving `agentveil-mcp-proxy` MCP server entry for the workspace
- `User/settings.json` → `mcp.servers.agentveil-mcp-proxy` — managed user-level wrapper (`python -m agentveil_mcp_proxy.cursor_user_mcp`) so Home/User MCP panels can see AgentVeil without pointing a raw global proxy at one stale workspace
- `.agentveil/` — workspace-scoped proxy home, product route profile, and passphrase
- local Approval Center process tied to the same `.agentveil` home

The user-level wrapper resolves a prepared workspace at runtime (walks up from the MCP process cwd, with optional `AVP_CURSOR_WORKSPACE`) and execs `agentveil-mcp-proxy run` for that workspace's `.agentveil` home. If no prepared workspace is found, it fails closed.

## Status

```bash
agentveil-mcp-proxy setup status --json
```

Reports bounded `protected`, `advisory`, or `unsafe` status, hook/MCP/proxy route state, `user_mcp_route` / `user_mcp_route_managed`, and `approval_center: running / down / stale`.

After setup, status stays `advisory` with next step `installed; waiting for Cursor reload / MCP confirmation` until bounded evidence shows a fresh observed MCP route action — not native hook activity alone, and not stale evidence from before the latest hook install.

Setup does not claim `protected` unless the Approval Center health probe passes, the managed user MCP route is present, and bounded evidence shows an observed MCP route (not native hook activity alone).

## Remove

```bash
agentveil-mcp-proxy setup remove cursor --yes
```

Removes only AgentVeil-managed hook entries, project MCP entries, and the managed user-level MCP wrapper. Unrelated Cursor hooks, MCP servers, and legacy raw user MCP entries are preserved unless they were replaced during setup.

## Scope

This connector guards configured Cursor workspaces by redirecting native mutations toward the routed AgentVeil MCP path with approval and bounded evidence. It does not claim host-wide Cursor control, protection without reload, or protection for direct terminal/IDE edits outside routed MCP tools.
