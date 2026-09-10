"""Tests for Gemini CLI BeforeTool hook containment."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from agentveil_mcp_proxy import gemini_hook
from agentveil_mcp_proxy.client_guidance import parse_redirect_context_from_gemini_hook_output
from agentveil_mcp_proxy.gemini_hook import classify_gemini_tool
from agentveil_mcp_proxy.policy import RiskClass
from redirect_hook_contract_fixtures import (
    durable_original_metadata,
    init_redirect_contract_home,
    publish_live_hook_binding,
)
from test_mcp_proxy_classification import NATIVE_SHELL_COMMAND_MATRIX


@pytest.fixture(autouse=True)
def _reset_hook_denied_upload_dedupe() -> None:
    from agentveil_mcp_proxy.console_decision_summary_client import (
        reset_hook_denied_upload_dedupe_for_tests,
    )

    reset_hook_denied_upload_dedupe_for_tests()


def _payload(tool_name: str, tool_input: dict | None = None) -> dict:
    return {
        "hook_event_name": "BeforeTool",
        "session_id": "sess-test",
        "cwd": "/private/customer/workspace",
        "tool_name": tool_name,
        "tool_input": tool_input or {},
    }


def test_detached_hook_refreshes_gemini_console_status(tmp_path, monkeypatch) -> None:
    calls = []
    home = tmp_path / ".avp"
    monkeypatch.setattr(
        gemini_hook,
        "best_effort_spawn_hook_project_status",
        lambda **kwargs: calls.append(kwargs),
    )

    decision = gemini_hook.process_hook(
        _payload(
            "run_shell_command",
            {
                "command": "agentveil-mcp-proxy --version && "
                "agentveil-mcp-proxy setup status --client gemini-cli --json"
            },
        ),
        home=home,
        out=io.StringIO(),
        detached_upload=True,
    )

    assert decision.hook_action == "allow"
    assert calls == [{
        "connector": "gemini-cli",
        "project_dir": tmp_path,
        "runtime_home": home,
    }]


def _deny_reason(raw: str) -> str:
    payload = json.loads(raw)
    return payload["reason"]


def test_gemini_main_allows_bounded_local_git_command() -> None:
    stdin = io.StringIO(json.dumps(_payload("run_shell_command", {"command": "git status --short"})))
    stdout = io.StringIO()

    assert gemini_hook.main(stdin=stdin, stdout=stdout) == 0
    assert json.loads(stdout.getvalue())["decision"] == "allow"


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
    assert "Direct native file mutation was blocked before mutation" in reason
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
    assert "managed AgentVeil write route is not currently available" in reason
    assert "write_file" not in reason


def test_gemini_hook_denies_write_capable_run_shell_command():
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("run_shell_command", {"command": "python3 -c \"open('owned.txt','w').write('x')\""}),
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "Direct native shell use was blocked" in reason  # claim-check: allow tested hook copy.
    assert "write_file" not in reason


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


def test_gemini_hook_allows_local_git_add_and_commit():
    out = io.StringIO()
    for command in (
        "git add agentveil_mcp_proxy/classification.py",
        "git commit -m 'fix: local dev policy'",
    ):
        decision = gemini_hook.process_hook(
            _payload("run_shell_command", {"command": command}),
            out=out,
        )
        assert decision.hook_action == "allow", command
        payload = json.loads(out.getvalue())
        assert payload["decision"] == "allow"
        out.truncate(0)
        out.seek(0)


def test_gemini_hook_denies_broad_git_add_without_write_file_redirect():
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("run_shell_command", {"command": "git add ."}),
        out=out,
    )
    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "write_file" not in reason
    assert "No controlled MCP route exists for this shell action" in reason


def test_gemini_hook_denies_secret_env_with_hard_block_copy():
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("run_shell_command", {"command": "AWS_SECRET_ACCESS_KEY=x pytest -q t"}),
        out=out,
    )
    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "bounded security reason" in reason
    assert "write_file" not in reason
    assert "AWS_SECRET_ACCESS_KEY" not in reason


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


def test_gemini_native_write_file_registers_durable_origin_and_agent_surface_context(tmp_path):
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = io.StringIO()
        decision = gemini_hook.process_hook(
            _payload("write_file", {"path": "note.txt", "content": "hello"}),
            home=home,
            out=out,
        )
        payload = json.loads(out.getvalue())
        redirect_context = parse_redirect_context_from_gemini_hook_output(payload)
        assert redirect_context is not None
        assert decision.disposition.value == "redirect"
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
        decision = gemini_hook.process_hook(
            _payload("replace", {"path": "note.txt", "old_string": "a", "new_string": "b"}),
            home=home,
            out=out,
        )
        payload = json.loads(out.getvalue())
        assert parse_redirect_context_from_gemini_hook_output(payload) is None
        assert decision.disposition.value == "hard_block"
    finally:
        fixture.lease.close()


def test_gemini_native_write_file_without_live_binding_has_no_verified_context(tmp_path):
    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path)
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("write_file", {"path": "note.txt", "content": "hello"}),
        home=home,
        out=out,
    )
    payload = json.loads(out.getvalue())
    assert parse_redirect_context_from_gemini_hook_output(payload) is None
    assert decision.disposition.value == "hard_block"


def test_gemini_hook_denied_uploads_bounded_decision_summary(monkeypatch):
    from agentveil_mcp_proxy.console_credentials import CREDENTIAL_SCOPE, StoredCredential
    from agentveil_mcp_proxy.console_decision_summary_client import (
        payload_to_request_body,
        wait_for_hook_denied_uploads_for_tests,
    )

    uploads = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_decision_summary_client.load_credential",
        lambda home=None: StoredCredential(
            scope=CREDENTIAL_SCOPE,
            token="hook-upload-token-secret",
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_decision_summary_client.sync_decision_summary",
        lambda payload, **kwargs: uploads.append(payload) or "accepted",
    )
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("write_file", {"path": "owned.txt", "content": "SECRET_CONTENT"}),
        out=out,
    )

    assert decision.hook_action == "deny"
    assert wait_for_hook_denied_uploads_for_tests()
    assert len(uploads) == 1
    encoded = json.dumps(payload_to_request_body(uploads[0]))
    assert "SECRET_CONTENT" not in encoded
    assert "owned.txt" not in encoded


def test_gemini_hook_redirect_does_not_upload_decision_summary(monkeypatch, tmp_path: Path) -> None:
    from agentveil_mcp_proxy.console_credentials import CREDENTIAL_SCOPE, StoredCredential
    from agentveil_mcp_proxy.console_decision_summary_client import (
        wait_for_hook_denied_uploads_for_tests,
    )

    uploads = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_decision_summary_client.load_credential",
        lambda home=None: StoredCredential(
            scope=CREDENTIAL_SCOPE,
            token="hook-upload-token-secret",
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_decision_summary_client.sync_decision_summary",
        lambda payload, **kwargs: uploads.append(payload) or "accepted",
    )
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = io.StringIO()
        decision = gemini_hook.process_hook(
            _payload("write_file", {"path": "note.txt", "content": "hello"}),
            home=home,
            out=out,
        )
        assert decision.reason_code == "managed_route_redirect"
        assert wait_for_hook_denied_uploads_for_tests()
        assert uploads == []
    finally:
        fixture.lease.close()


@pytest.mark.parametrize("command,expected", NATIVE_SHELL_COMMAND_MATRIX)
def test_gemini_shell_classifier_matches_shared_matrix(command: str, expected: RiskClass) -> None:
    assert classify_gemini_tool("run_shell_command", {"command": command}) is expected


def test_gemini_exact_shell_delete_hard_block_has_null_alternative() -> None:
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("run_shell_command", {"command": "rm notes.txt"}),
        out=out,
    )
    reason = _deny_reason(out.getvalue())
    assert decision.hook_action == "deny"
    assert decision.disposition.value == "hard_block"
    assert "alternative=null" in reason
    assert "filesystem.stage_delete.v1" not in reason


def test_gemini_write_file_does_not_select_stage_delete() -> None:
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("write_file", {"path": "notes.txt", "content": "x"}),
        out=out,
    )
    reason = _deny_reason(out.getvalue())
    assert decision.hook_action == "deny"
    assert "alternative=null" in reason
    assert "filesystem.stage_delete.v1" not in reason


def test_gemini_renderer_matches_shared_unavailable_envelope_for_hard_block() -> None:
    from agentveil_mcp_proxy.client_guidance import (
        build_native_controlled_guidance_envelope,
        format_native_controlled_guidance_text,
    )

    envelope = build_native_controlled_guidance_envelope(
        native_tool="run_shell_command",
        tool_input={"command": "rm notes.txt"},
        redirect_route_ready=False,
    )
    shared = format_native_controlled_guidance_text(envelope)
    out = io.StringIO()
    gemini_hook.process_hook(_payload("run_shell_command", {"command": "rm notes.txt"}), out=out)
    assert shared in _deny_reason(out.getvalue())
    assert "alternative=null" in shared


def test_gemini_trusted_static_exact_delete_is_hard_block_with_available_suggestion(tmp_path: Path) -> None:
    home, sandbox, _downstream = init_redirect_contract_home(tmp_path)
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("run_shell_command", {"command": "rm notes.txt"}),
        home=home,
        out=out,
    )
    payload = json.loads(out.getvalue())
    reason = _deny_reason(out.getvalue())
    assert decision.hook_action == "deny"
    assert decision.disposition.value == "hard_block"
    assert parse_redirect_context_from_gemini_hook_output(payload) is None
    assert "suggestion_status=available" in reason
    assert "alternative.tool_contract=agentveil_stage_delete" in reason
    assert "alternative.input.path=notes.txt" in reason
    assert "alternative.id=" not in reason
    assert "alternative.input.path=notes.txt" in reason
    assert "not currently available" not in reason
    assert str(home) not in reason
    assert str(sandbox) not in reason


def test_gemini_allow_does_not_read_static_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path)
    calls: list[object] = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.gemini_hook.trusted_static_controlled_route_ready",
        lambda **kwargs: calls.append(kwargs) or True,
    )
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("read_file", {"path": "notes.txt"}),
        home=home,
        out=out,
    )
    assert decision.hook_action == "allow"
    assert calls == []


_SEMANTIC_TOOL_INPUTS = {
    "agentveil_stage_delete": {"path": "notes.txt"},
    "agentveil_restore_staged": {"quarantine_entry_id": "a" * 32},
    "agentveil_cleanup_staged": {"quarantine_entry_id": "a" * 32},
    "agentveil_prepare_patch": {"path": "notes.txt", "patch": "diff"},
    "agentveil_apply_prepared_patch": {
        "prepared_artifact_ref": "a" * 32,
        "prepared_artifact_hash": "ab" * 32,
    },
    "agentveil_prepare_git_change": {"worktree_path": "."},
    "agentveil_git_operation": {"worktree_path": ".", "operation": "prepare_for_review"},
    "agentveil_write_file": {"path": "todo.txt", "content": "done\n"},
}


@pytest.mark.parametrize(
    "tool_name,arguments",
    [
        ("mcp_agentveil_agentveil_stage_delete", {"path": "notes.txt"}),
        ("mcp_agentveil_agentveil_restore_staged", {"quarantine_entry_id": "a" * 32}),
        ("mcp_agentveil_agentveil_cleanup_staged", {"quarantine_entry_id": "a" * 32}),
        ("mcp_agentveil_agentveil_prepare_patch", {"path": "notes.txt", "patch": "diff"}),
        (
            "mcp_agentveil_agentveil_apply_prepared_patch",
            {"prepared_artifact_ref": "a" * 32, "prepared_artifact_hash": "ab" * 32},
        ),
        ("mcp_agentveil_agentveil_prepare_git_change", {"worktree_path": "."}),
        (
            "mcp_agentveil_agentveil_git_operation",
            {"worktree_path": ".", "operation": "prepare_for_review"},
        ),
        ("mcp_agentveil_agentveil_write_file", {"path": "todo.txt", "content": "done\n"}),
    ],
)
def test_gemini_hook_does_not_deny_agentveil_owned_semantic_mcp_tools(
    tool_name: str,
    arguments: dict,
) -> None:
    out = io.StringIO()
    decision = gemini_hook.process_hook(_payload(tool_name, arguments), out=out)
    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"
    assert json.loads(out.getvalue())["decision"] == "allow"


def test_gemini_hook_cleanup_passes_to_proxy_and_is_not_approved() -> None:
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload(
            "mcp_agentveil_agentveil_cleanup_staged",
            _SEMANTIC_TOOL_INPUTS["agentveil_cleanup_staged"],
        ),
        out=out,
    )
    response = json.loads(out.getvalue())
    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"
    assert response == {"decision": "allow"}
    assert "approved" not in json.dumps(response)


def test_gemini_hook_still_denies_native_destructive_actions() -> None:
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("run_shell_command", {"command": "rm notes.txt"}),
        out=out,
    )
    assert decision.hook_action == "deny"
    assert json.loads(out.getvalue())["decision"] == "deny"
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("write_file", {"path": "notes.txt", "content": "x"}),
        out=out,
    )
    assert decision.hook_action == "deny"


def test_gemini_hook_rejects_lookalike_and_shell_text_as_controlled_tool() -> None:
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("mcp_filesystem_agentveil_stage_delete", {"path": "notes.txt"}),
        out=out,
    )
    assert decision.hook_action == "deny"
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        _payload("run_shell_command", {"command": "agentveil_stage_delete notes.txt"}),
        out=out,
    )
    assert decision.hook_action == "deny"


def test_gemini_hook_does_not_passthrough_whitespace_or_non_string_tool_name() -> None:
    for tool_name in (
        " agentveil_stage_delete",
        "agentveil_stage_delete ",
        "\tagentveil_stage_delete",
        "mcp__agentveil__agentveil_stage_delete ",
        "MCP:agentveil_stage_delete ",
    ):
        out = io.StringIO()
        decision = gemini_hook.process_hook(_payload(tool_name, {"path": "notes.txt"}), out=out)
        assert decision.reason_code != "controlled_route_passthrough", repr(tool_name)
    for tool_name in (None, 123, True, ["agentveil_stage_delete"], {"tool": "agentveil_stage_delete"}):
        out = io.StringIO()
        decision = gemini_hook.process_hook(
            {
                "hook_event_name": "BeforeTool",
                "session_id": "sess-test",
                "cwd": "/private/customer/workspace",
                "tool_name": tool_name,
                "tool_input": {"path": "notes.txt"},
            },
            out=out,
        )
        assert decision.reason_code != "controlled_route_passthrough", repr(tool_name)
