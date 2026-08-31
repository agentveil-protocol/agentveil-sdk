"""Tests for Codex PreToolUse hook containment."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from agentveil_mcp_proxy import codex_hook
from agentveil_mcp_proxy.client_guidance import parse_redirect_context_from_codex_hook_output
from agentveil_mcp_proxy.codex_hook import classify_codex_tool
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
        "hook_event_name": "PreToolUse",
        "session_id": "sess-test",
        "cwd": "/private/customer/workspace",
        "tool_name": tool_name,
        "tool_input": tool_input or {},
    }


def test_detached_hook_refreshes_codex_console_status(tmp_path, monkeypatch) -> None:
    calls = []
    home = tmp_path / ".avp"
    monkeypatch.setattr(
        codex_hook,
        "best_effort_spawn_hook_project_status",
        lambda **kwargs: calls.append(kwargs),
    )

    decision = codex_hook.process_hook(
        _payload(
            "Bash",
            {
                "command": "agentveil-mcp-proxy --version && "
                "agentveil-mcp-proxy setup status --client codex --json"
            },
        ),
        home=home,
        out=io.StringIO(),
        detached_upload=True,
    )

    assert decision.hook_action == "allow"
    assert calls == [{
        "connector": "codex",
        "project_dir": tmp_path,
        "runtime_home": home,
    }]


def _deny_reason(raw: str) -> str:
    payload = json.loads(raw)
    return payload["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_main_allows_bounded_local_git_command() -> None:
    stdin = io.StringIO(json.dumps(_payload("Bash", {"command": "git status --short"})))
    stdout = io.StringIO()

    assert codex_hook.main(stdin=stdin, stdout=stdout) == 0
    assert stdout.getvalue() == ""


def test_codex_hook_allows_local_git_add_and_commit():
    out = io.StringIO()
    for command in (
        "git add agentveil_mcp_proxy/classification.py",
        "git commit -m 'fix: local dev policy'",
    ):
        decision = codex_hook.process_hook(_payload("Bash", {"command": command}), out=out)
        assert decision.hook_action == "allow", command
        assert out.getvalue() == ""


def test_codex_hook_denies_broad_git_add():
    out = io.StringIO()
    decision = codex_hook.process_hook(_payload("Bash", {"command": "git add ."}), out=out)
    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "write_file" not in reason
    assert "No controlled MCP route exists for this shell action" in reason


def test_codex_hook_denies_destructive_shell_with_hard_block_copy():
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Bash", {"command": "rm -rf /tmp/workspace"}),
        out=out,
    )
    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "bounded security reason" in reason
    assert "write_file" not in reason
    assert "controlled MCP tool" not in reason
    assert "/tmp/workspace" not in reason


def test_codex_hook_denies_native_bash_write_with_redirect(tmp_path):
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Bash", {"command": "python3 -c \"open('owned.txt','w').write('x')\""}),
        evidence_path=tmp_path / "evidence.jsonl",
        out=out,
    )

    assert decision.hook_action == "deny"
    reason = _deny_reason(out.getvalue())
    assert "Direct native shell use was blocked" in reason  # claim-check: allow tested hook copy.
    assert "write_file" not in reason
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
    assert "managed AgentVeil write route is not currently available" in reason
    assert "write_file" not in reason


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
    assert "Direct native file mutation was blocked before mutation" in reason


def test_codex_native_write_registers_durable_origin_and_agent_surface_context(tmp_path):
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = io.StringIO()
        decision = codex_hook.process_hook(
            _payload("Write", {"file_path": "note.txt", "content": "hello"}),
            home=home,
            out=out,
        )
        payload = json.loads(out.getvalue())
        redirect_context = parse_redirect_context_from_codex_hook_output(payload)
        assert redirect_context is not None
        assert decision.disposition.value == "redirect"
        meta = durable_original_metadata(home, redirect_context["original_request_id"])
        assert meta is not None
        assert meta["redirect_role"] == "original"
        assert meta["redirect_playbook_id"] == "request_approval"
        assert "hello" not in json.dumps(payload)
    finally:
        fixture.lease.close()


def test_codex_apply_patch_registers_verified_redirect_context(tmp_path):
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = io.StringIO()
        decision = codex_hook.process_hook(
            _payload(
                "apply_patch",
                {
                    "patch": (
                        "*** Begin Patch\n"
                        "*** Update File: note.txt\n"
                        "@@\n-old\n+new\n"
                        "*** End Patch"
                    )
                },
            ),
            home=home,
            out=out,
        )
        payload = json.loads(out.getvalue())
        redirect_context = parse_redirect_context_from_codex_hook_output(payload)
        assert redirect_context is not None
        assert decision.disposition.value == "redirect"
        reason = _deny_reason(out.getvalue())
        assert "MCP tool apply_patch" in reason
        meta = durable_original_metadata(home, redirect_context["original_request_id"])
        assert meta is not None
        assert meta["follow_up_tool"] == "apply_patch"
    finally:
        fixture.lease.close()


def test_codex_multi_file_apply_patch_fails_closed_without_redirect(tmp_path):
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = io.StringIO()
        decision = codex_hook.process_hook(
            _payload(
                "apply_patch",
                {
                    "patch": (
                        "*** Begin Patch\n"
                        "*** Add File: one.txt\n+one\n"
                        "*** Add File: two.txt\n+two\n"
                        "*** End Patch"
                    )
                },
            ),
            home=home,
            out=out,
        )
        assert parse_redirect_context_from_codex_hook_output(json.loads(out.getvalue())) is None
        assert decision.disposition.value == "hard_block"
    finally:
        fixture.lease.close()


def test_codex_native_write_without_live_binding_has_no_verified_context(tmp_path):
    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path)
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Write", {"file_path": "note.txt", "content": "hello"}),
        home=home,
        out=out,
    )
    payload = json.loads(out.getvalue())
    assert parse_redirect_context_from_codex_hook_output(payload) is None
    assert decision.disposition.value == "hard_block"


def _install_hook_upload_capture(monkeypatch):
    from agentveil_mcp_proxy.console_credentials import CREDENTIAL_SCOPE, StoredCredential
    from agentveil_mcp_proxy.console_decision_summary_client import (
        DecisionSummaryPayload,
        payload_to_request_body,
    )

    uploads: list[DecisionSummaryPayload] = []

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
    return uploads, payload_to_request_body


def test_codex_hook_denied_uploads_bounded_decision_summary(monkeypatch):
    from agentveil_mcp_proxy.console_decision_summary_client import (
        wait_for_hook_denied_uploads_for_tests,
    )

    uploads, payload_to_request_body = _install_hook_upload_capture(monkeypatch)
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Bash", {"command": "git add ."}),
        out=out,
    )

    assert decision.hook_action == "deny"
    assert wait_for_hook_denied_uploads_for_tests()
    assert len(uploads) == 1
    assert uploads[0].decision == "denied"
    encoded = json.dumps(payload_to_request_body(uploads[0]))
    assert "git add ." not in encoded
    assert "/private/customer/workspace" not in encoded
    assert "hook-upload-token-secret" not in encoded


def test_codex_hook_allow_does_not_upload_decision_summary(monkeypatch):
    uploads, _payload_to_request_body = _install_hook_upload_capture(monkeypatch)
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Bash", {"command": "git status --short"}),
        out=out,
    )

    assert decision.hook_action == "allow"
    assert uploads == []


def test_codex_hook_redirect_does_not_upload_decision_summary(monkeypatch, tmp_path: Path) -> None:
    from agentveil_mcp_proxy.console_decision_summary_client import (
        wait_for_hook_denied_uploads_for_tests,
    )

    uploads, _payload_to_request_body = _install_hook_upload_capture(monkeypatch)
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = io.StringIO()
        decision = codex_hook.process_hook(
            _payload("Write", {"file_path": "note.txt", "content": "hello"}),
            home=home,
            out=out,
        )
        assert decision.reason_code == "managed_route_redirect"
        assert wait_for_hook_denied_uploads_for_tests()
        assert uploads == []
    finally:
        fixture.lease.close()


def test_codex_hook_denied_remains_denied_when_upload_fails(monkeypatch):
    from agentveil_mcp_proxy.console_decision_summary_client import (
        DecisionSummaryClientError,
        wait_for_hook_denied_uploads_for_tests,
    )

    def _fail_upload(**kwargs):
        raise DecisionSummaryClientError("transport_failed")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_decision_summary_client.sync_decision_summary",
        _fail_upload,
    )
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Bash", {"command": "git add ."}),
        out=out,
    )

    assert decision.hook_action == "deny"
    assert wait_for_hook_denied_uploads_for_tests()
    assert _deny_reason(out.getvalue())


@pytest.mark.parametrize("command,expected", NATIVE_SHELL_COMMAND_MATRIX)
def test_codex_shell_classifier_matches_shared_matrix(command: str, expected: RiskClass) -> None:
    assert classify_codex_tool("Bash", {"command": command}) is expected


def test_codex_exact_delete_patch_renders_common_stage_delete_and_stays_deny(tmp_path) -> None:
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = io.StringIO()
        decision = codex_hook.process_hook(
            _payload(
                "apply_patch",
                {"patch": "*** Begin Patch\n*** Delete File: notes.txt\n*** End Patch"},
            ),
            home=home,
            out=out,
        )
        reason = _deny_reason(out.getvalue())
        assert decision.hook_action == "deny"
        assert decision.disposition.value == "redirect"
        assert decision.reason_code == "managed_route_redirect"
        assert "suggestion_status=available" in reason
        assert "alternative.tool_contract=agentveil_stage_delete" in reason
        assert "alternative.input.path=notes.txt" in reason
        assert "alternative.id=" not in reason
        assert "redirect_context=" in reason
        assert "controlled_stage_delete" in reason
        assert "agentveil_stage_delete" in reason
        assert "target_reached=false" in reason
    finally:
        fixture.lease.close()


def test_codex_exact_delete_patch_without_binding_is_hard_block_unavailable() -> None:
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Delete File: notes.txt\n*** End Patch"},
        ),
        out=out,
    )
    reason = _deny_reason(out.getvalue())
    assert decision.hook_action == "deny"
    assert decision.disposition.value == "hard_block"
    assert "alternative=null" in reason
    assert "filesystem.stage_delete.v1" not in reason
    assert "managed AgentVeil write route is not currently available" in reason
    out = io.StringIO()
    decision = codex_hook.process_hook(_payload("Bash", {"command": "rm notes.txt"}), out=out)
    reason = _deny_reason(out.getvalue())
    assert decision.hook_action == "deny"
    assert decision.disposition.value == "hard_block"
    assert "alternative=null" in reason
    assert "filesystem.stage_delete.v1" not in reason


def test_codex_ambiguous_delete_is_unavailable_and_does_not_leak(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.jsonl"
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Bash", {"command": "rm -rf /tmp/workspace"}),
        evidence_path=evidence,
        out=out,
    )
    reason = _deny_reason(out.getvalue())
    dumped = evidence.read_text(encoding="utf-8")
    assert decision.hook_action == "deny"
    assert "alternative=null" in reason
    assert "filesystem.stage_delete.v1" not in reason
    assert "/tmp/workspace" not in reason
    assert "/tmp/workspace" not in dumped
    assert "rm -rf" not in dumped


def test_codex_controlled_mcp_route_still_allows_without_guidance() -> None:
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload(
            "mcp__agentveil-mcp-proxy__agentveil_controlled_alternative",
            {"alternative_id": "filesystem.stage_delete.v1", "input": {"path": "notes.txt"}},
        ),
        out=out,
    )
    assert decision.hook_action == "allow"
    assert out.getvalue() == ""


def test_codex_trusted_static_exact_delete_is_hard_block_with_available_suggestion(tmp_path: Path) -> None:
    home, sandbox, _downstream = init_redirect_contract_home(tmp_path)
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Delete File: notes.txt\n*** End Patch"},
        ),
        home=home,
        out=out,
    )
    payload = json.loads(out.getvalue())
    reason = _deny_reason(out.getvalue())
    assert decision.hook_action == "deny"
    assert decision.disposition.value == "hard_block"
    assert decision.reason_code == "risky_blocked"
    assert parse_redirect_context_from_codex_hook_output(payload) is None
    assert "suggestion_status=available" in reason
    assert "alternative.tool_contract=agentveil_stage_delete" in reason
    assert "alternative.input.path=notes.txt" in reason
    assert "alternative.id=" not in reason
    assert "alternative.input.path=notes.txt" in reason
    assert "not currently available" not in reason
    assert "redirect_context=" not in reason
    assert str(home) not in reason
    assert str(sandbox) not in reason


def test_codex_trusted_static_ambiguous_stays_unavailable_without_broken_route_copy(tmp_path: Path) -> None:
    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path)
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Bash", {"command": "rm notes.txt extra.txt"}),
        home=home,
        out=out,
    )
    reason = _deny_reason(out.getvalue())
    assert decision.hook_action == "deny"
    assert decision.disposition.value == "hard_block"
    assert "alternative=null" in reason
    assert "filesystem.stage_delete.v1" not in reason
    assert "not currently available" not in reason


def test_codex_allow_does_not_read_static_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path)
    calls: list[object] = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.codex_hook.trusted_static_controlled_route_ready",
        lambda **kwargs: calls.append(kwargs) or True,
    )
    out = io.StringIO()
    decision = codex_hook.process_hook(
        _payload("Bash", {"command": "git status --short"}),
        home=home,
        out=out,
    )
    assert decision.hook_action == "allow"
    assert calls == []
    assert out.getvalue() == ""
