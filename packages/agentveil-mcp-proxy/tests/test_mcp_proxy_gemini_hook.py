"""Tests for Gemini CLI BeforeTool hook containment."""

from __future__ import annotations

import io
import json

from agentveil_mcp_proxy import gemini_hook


def _payload(tool_name: str, tool_input: dict | None = None) -> dict:
    return {
        "hook_event_name": "BeforeTool",
        "session_id": "sess-test",
        "cwd": "/private/customer/workspace",
        "tool_name": tool_name,
        "tool_input": tool_input or {},
    }


def _deny_reason(raw: str) -> str:
    payload = json.loads(raw)
    return payload["reason"]


def test_gemini_hook_denies_write_file_with_redirect(tmp_path):
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("write_file", {"path": "owned.txt", "content": "SECRET_CONTENT"}),
        evidence_path=tmp_path / "evidence.jsonl",
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    # claim-check: allow assertion of bounded hook denial text in unit test.
    assert "Direct native tool use was blocked before mutation" in reason
    assert "target_reached=false" in reason
    assert "SECRET_CONTENT" not in reason
    record = json.loads((tmp_path / "evidence.jsonl").read_text(encoding="utf-8"))
    assert record["server"] == "gemini_cli"
    assert record["tool"] == "write_file"
    assert record["hook_action"] == "deny"
    assert record["target_reached"] is False
    assert "/private/customer/workspace" not in json.dumps(record)


def test_gemini_hook_denies_replace_as_native_write():
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("replace", {"path": "owned.txt", "old_string": "a", "new_string": "b"}),
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "denied replace" in reason
    assert "Use an AgentVeil controlled MCP tool" in reason


def test_gemini_hook_denies_write_capable_run_shell_command():
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("run_shell_command", {"command": "python3 -c \"open('owned.txt','w').write('x')\""}),
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    # claim-check: allow assertion of bounded hook denial text in unit test.
    assert "Direct native tool use was blocked before mutation" in reason


def test_gemini_hook_allows_read_tools():
    for tool_name in ("read_file", "read_many_files", "list_directory", "glob", "grep_search"):
        out = io.StringIO()
        decision = gemini_hook.process_hook(_payload(tool_name, {"path": "README.md"}), out=out)
        assert decision.hook_action == "allow"
        assert json.loads(out.getvalue())["decision"] == "allow"


def test_gemini_hook_passes_agentveil_controlled_mcp_route():
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload(
            "mcp_agentveil-mcp-proxy_write_file",
            {"path": "config.py", "content": "FEATURE_X = True\n"},
        ),
        out=out,
    )

    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"
    assert json.loads(out.getvalue())["decision"] == "allow"


def test_gemini_hook_passes_agentveil_controlled_mcp_route_underscore_server():
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload(
            "mcp_agentveil_mcp_proxy_write_file",
            {"path": "config.py", "content": "FEATURE_X = True\n"},
        ),
        out=out,
    )

    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"
    assert decision.context.server == "agentveil_mcp_proxy"
    assert json.loads(out.getvalue())["decision"] == "allow"


def test_gemini_hook_still_denies_non_agentveil_mcp_write():
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload(
            "mcp_filesystem_write_file",
            {"path": "config.py", "content": "FEATURE_X = True\n"},
        ),
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "denied write_file" in reason
    # claim-check: allow assertion that non-AgentVeil MCP path lacks native-redirect copy.
    assert "Direct native tool use was blocked before mutation" not in reason


def test_gemini_hook_does_not_leak_raw_command_in_evidence(tmp_path):
    secret_command = "python3 -c \"open('secret.txt','w').write('TOP_SECRET')\""
    gemini_hook.process_hook(
        _payload("run_shell_command", {"command": secret_command}),
        evidence_path=tmp_path / "evidence.jsonl",
        out=io.StringIO(),
    )
    record = json.loads((tmp_path / "evidence.jsonl").read_text(encoding="utf-8"))
    assert "TOP_SECRET" not in json.dumps(record)
    assert secret_command not in json.dumps(record)


from agentveil_mcp_proxy.client_guidance import parse_redirect_context_from_gemini_hook_output
from redirect_hook_contract_fixtures import (
    durable_original_metadata,
    init_redirect_contract_home,
    publish_live_hook_binding,
)


def test_gemini_native_write_file_registers_durable_origin_and_agent_surface_context(tmp_path):
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = io.StringIO()
        gemini_hook.process_hook(
            _payload("write_file", {"path": "note.txt", "content": "hello"}),
            home=home,
            out=out,
        )
        payload = json.loads(out.getvalue())
        redirect_context = parse_redirect_context_from_gemini_hook_output(payload)
        assert redirect_context is not None
        meta = durable_original_metadata(home, redirect_context["original_request_id"])
        assert meta is not None
        assert meta["redirect_role"] == "original"
        assert meta["redirect_playbook_id"] == "request_approval"
        assert "hello" not in json.dumps(payload)
    finally:
        fixture.lease.close()


def test_gemini_replace_has_no_verified_redirect_context(tmp_path):
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = io.StringIO()
        gemini_hook.process_hook(
            _payload("replace", {"path": "note.txt", "old_string": "a", "new_string": "b"}),
            home=home,
            out=out,
        )
        payload = json.loads(out.getvalue())
        assert parse_redirect_context_from_gemini_hook_output(payload) is None
    finally:
        fixture.lease.close()


def test_gemini_native_write_file_without_live_binding_has_no_verified_context(tmp_path):
    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path)
    out = io.StringIO()
    gemini_hook.process_hook(
        _payload("write_file", {"path": "note.txt", "content": "hello"}),
        home=home,
        out=out,
    )
    payload = json.loads(out.getvalue())
    assert parse_redirect_context_from_gemini_hook_output(payload) is None
