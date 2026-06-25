"""Tests for agentveil_mcp_proxy.cursor_hooks."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from agentveil_mcp_proxy import cursor_hooks


def test_native_write_denied_with_generic_redirect(tmp_path: Path) -> None:
    payload = {
        "hook_event": "preToolUse",
        "tool_name": "Write",
        "tool_input": {"path": "foo.txt", "contents": "secret"},
    }
    out = StringIO()
    decision = cursor_hooks.process_hook(
        payload,
        workspace=tmp_path,
        evidence_path=tmp_path / "evidence.jsonl",
        out=out,
    )
    assert decision.hook_action == "deny"
    response = json.loads(out.getvalue())
    assert response["permission"] == "deny"
    assert "write_file" in response["agent_message"]
    assert cursor_hooks.NATIVE_REDIRECT_INSTRUCTION in response["agent_message"]


def test_shell_readonly_allowed(tmp_path: Path) -> None:
    payload = {"hook_event": "beforeShellExecution", "command": "ls -la"}
    out = StringIO()
    decision = cursor_hooks.process_hook(payload, workspace=tmp_path, out=out)
    assert decision.hook_action == "allow"
    assert json.loads(out.getvalue())["permission"] == "allow"


def test_agentveil_mcp_route_passthrough(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"agentveil-mcp-proxy": {"command": "agentveil-mcp-proxy"}}}),
        encoding="utf-8",
    )
    payload = {
        "hook_event": "beforeMCPExecution",
        "tool_name": "write_file",
        "arguments": {"path": "foo.txt"},
    }
    out = StringIO()
    decision = cursor_hooks.process_hook(payload, workspace=tmp_path, out=out)
    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"


def test_agentveil_mcp_prefixed_pretooluse_passthrough(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"agentveil-mcp-proxy": {"command": "agentveil-mcp-proxy"}}}),
        encoding="utf-8",
    )
    payload = {
        "hook_event": "preToolUse",
        "tool_name": "MCP:write_file",
        "tool_input": {"path": "foo.txt", "content": "hello"},
    }
    out = StringIO()
    decision = cursor_hooks.process_hook(payload, workspace=tmp_path, out=out)
    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"
    assert json.loads(out.getvalue())["permission"] == "allow"


def test_evidence_is_bounded(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence.jsonl"
    payload = {
        "hook_event": "preToolUse",
        "tool_name": "Write",
        "tool_input": {"path": "secret-path.txt", "contents": "TOP_SECRET_VALUE"},
    }
    cursor_hooks.process_hook(payload, workspace=tmp_path, evidence_path=evidence_path, out=StringIO())
    line = evidence_path.read_text(encoding="utf-8").strip()
    assert "TOP_SECRET_VALUE" not in line
    assert "secret-path.txt" not in line
    record = json.loads(line)
    assert "input_ref" in record
    assert "input_hash" in record["input_ref"]
