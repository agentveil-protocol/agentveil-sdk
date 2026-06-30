"""Tests for Codex PreToolUse hook containment."""

from __future__ import annotations

import io
import json

from agentveil_mcp_proxy import codex_hook


def _payload(tool_name: str, tool_input: dict | None = None) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "sess-test",
        "cwd": "/private/customer/workspace",
        "tool_name": tool_name,
        "tool_input": tool_input or {},
    }


def _deny_reason(raw: str) -> str:
    payload = json.loads(raw)
    return payload["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_hook_denies_native_bash_write_with_redirect(tmp_path):
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Bash", {"command": "python3 -c \"open('owned.txt','w').write('x')\""}),
        evidence_path=tmp_path / "evidence.jsonl",
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    # claim-check: allow hook unit test asserts the local deny output string.
    assert "Direct native tool use was blocked before mutation" in reason
    assert "target_reached=false" in reason
    record = json.loads((tmp_path / "evidence.jsonl").read_text(encoding="utf-8"))
    assert record["server"] == "codex"
    assert record["tool"] == "Bash"
    assert record["hook_action"] == "deny"
    assert record["target_reached"] is False
    assert "/private/customer/workspace" not in json.dumps(record)


def test_codex_hook_denies_apply_patch_as_native_write():
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("apply_patch", {"patch": "*** Begin Patch\n*** End Patch"}),
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "denied apply_patch" in reason
    assert "Use an AgentVeil controlled MCP tool" in reason


def test_codex_hook_allows_read_only_bash():
    out = io.StringIO()
    decision = codex_hook.process_hook(_payload("Bash", {"command": "ls -la"}), out=out)

    assert decision.hook_action == "allow"
    assert out.getvalue() == ""


def test_codex_hook_passes_agentveil_controlled_mcp_route():
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload(
            "mcp__agentveil-mcp-proxy__write_file",
            {"path": "config.py", "content": "FEATURE_X = True\n"},
        ),
        out=out,
    )

    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"
    assert out.getvalue() == ""


def test_codex_hook_passes_agentveil_controlled_mcp_route_underscore_server():
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload(
            "mcp__agentveil_mcp_proxy__write_file",
            {"path": "config.py", "content": "FEATURE_X = True\n"},
        ),
        out=out,
    )

    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"
    assert decision.context.server == "agentveil_mcp_proxy"
    assert out.getvalue() == ""


def test_codex_hook_still_denies_non_agentveil_mcp_write():
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload(
            "mcp__filesystem__write_file",
            {"path": "config.py", "content": "FEATURE_X = True\n"},
        ),
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "denied write_file" in reason
    # claim-check: allow negative assertion that non-native MCP deny omits native-block wording.
    assert "Direct native tool use was blocked before mutation" not in reason


def test_codex_hook_accepts_camel_case_payload_shape():
    out = io.StringIO()
    decision = codex_hook.process_hook(
        {
            "hookEventName": "PreToolUse",
            "sessionId": "sess-test",
            "toolName": "Write",
            "toolInput": {"file_path": "config.py", "content": "SECRET_CONTENT"},
        },
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "SECRET_CONTENT" not in reason
    # claim-check: allow hook unit test asserts bounded local deny output.
    assert "Direct native tool use was blocked before mutation" in reason
