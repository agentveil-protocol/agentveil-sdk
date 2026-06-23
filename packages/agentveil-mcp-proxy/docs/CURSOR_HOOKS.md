# Cursor Hooks (Project-Local)

AgentVeil MCP Proxy can install **project-local** Cursor hooks for configured
workspaces. This is a guided boundary wedge for native Cursor agent tools. It
does **not** provide host-wide control, a universal Cursor lock, or governance
for actions outside the configured workspace hook path.

## Commands

```bash
agentveil-mcp-proxy setup cursor --yes
agentveil-mcp-proxy setup status
agentveil-mcp-proxy setup remove cursor --yes
agentveil-mcp-proxy hook cursor
```

- `setup cursor --yes` writes only project-local files under `.cursor/` in the
  current workspace (or `--workspace`).
- `setup status` without `--home` reports Cursor hook install state for the
  workspace.
- `setup remove cursor --yes` deletes only files created by AgentVeil setup.
- `hook cursor` reads one Cursor hook JSON payload from stdin and returns a
  Cursor-compatible allow/deny response on stdout.

## Installed Files

Setup embeds the absolute path to the `agentveil-mcp-proxy` executable used
during `setup cursor --yes` into `.cursor/hooks/agentveil-cursor-hook.sh`. The
shim does not rely on Cursor GUI `PATH`. If the CLI moves or changes, rerun
`agentveil-mcp-proxy setup cursor --yes`.

`setup status --json` reports `hook_cli_resolved` and a bounded `hook_cli_ref`
(basename + hash), not the raw CLI path.

Setup creates or merges:

- `.cursor/hooks.json` (created when missing, otherwise merged additively)
- `.cursor/hooks/agentveil-cursor-hook.sh`
- `.cursor/.agentveil-cursor-hooks.json` (managed-file manifest)

Existing unrelated Cursor hook entries in `hooks.json` are preserved. Setup is
idempotent and does not duplicate AgentVeil entries. Remove deletes only
AgentVeil-managed hook entries plus the shim and manifest.

Setup does **not** modify global Cursor config such as `~/.cursor/mcp.json` or
Cursor user settings.

## Hook Coverage

The shim routes risky native agent actions through `hook cursor`:

- `preToolUse` for `Shell`, `Write`, `Delete`, `StrReplace`, `ApplyPatch`, `Edit`
- `beforeShellExecution`
- `beforeMCPExecution`

Configured risky classes are denied before mutation unless an explicit safe
review marker is present. Safe read-only MCP tools such as `list_workspace`
continue when allowed by policy.

## Reload Required

Cursor may cache hook configuration. After setup or remove, reload or restart
Cursor (`Developer -> Reload Window`) so changes take effect.

## Evidence

Hook decisions append bounded JSONL rows to
`.cursor/agentveil-hook-evidence.jsonl`. Rows record decision metadata only.
They do not store raw paths, prompts, secrets, tokens, stdout/stderr, or full
tool payloads.

## Limits

- Workspace-scoped project hooks only
- No Codex or Claude hook support in this release
- No claim of cannot-bypass or host-wide enforcement
- MCP Proxy remains the product path for routed MCP tool calls; hooks cover
  native Cursor agent tools in the configured workspace
