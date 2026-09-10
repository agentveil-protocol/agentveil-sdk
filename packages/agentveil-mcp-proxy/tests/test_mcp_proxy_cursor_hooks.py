"""Tests for agentveil_mcp_proxy.cursor_hooks."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest

from agentveil_mcp_proxy import cursor_hooks
from agentveil_mcp_proxy.cursor_hooks import classify_cursor_tool
from agentveil_mcp_proxy.policy import RiskClass
from test_mcp_proxy_classification import NATIVE_SHELL_COMMAND_MATRIX
from agentveil_mcp_proxy.client_guidance import (
    parse_redirect_context_from_cursor_hook_output,
)
from redirect_hook_contract_fixtures import (
    durable_original_metadata,
    init_redirect_contract_home,
    publish_live_hook_binding,
)


def _trusted_cursor_mcp_entry(tmp_path: Path, *, workspace: Path | None = None) -> dict:
    from agentveil_mcp_proxy.cursor_setup import build_mcp_server_entry, setup_home

    ws = workspace or tmp_path
    home = setup_home(ws)
    proxy = tmp_path / "bin" / "agentveil-mcp-proxy"
    proxy.parent.mkdir(parents=True, exist_ok=True)
    proxy.write_text("#!/bin/sh\n", encoding="utf-8")
    return build_mcp_server_entry(
        proxy_command=str(proxy),
        home=home,
        config_path=home / "mcp-proxy" / "config.json",
        passphrase_file=home / "passphrase",
        profile=home / "product-profile",
        workspace=ws,
    )


def _write_cursor_mcp_config(workspace: Path, servers: dict) -> None:
    (workspace / ".cursor").mkdir(exist_ok=True)
    (workspace / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": servers}),
        encoding="utf-8",
    )


@pytest.fixture(autouse=True)
def _reset_hook_denied_upload_dedupe() -> None:
    from agentveil_mcp_proxy.console_decision_summary_client import (
        reset_hook_denied_upload_dedupe_for_tests,
    )

    reset_hook_denied_upload_dedupe_for_tests()


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
    assert "write_file" not in response["agent_message"]
    assert "managed AgentVeil write route is not currently available" in response["agent_message"]


def test_shell_python_m_pytest_allowed_end_to_end(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {
            "hook_event": "beforeShellExecution",
            "command": "python3 -m pytest -q packages/agentveil-mcp-proxy/tests",
        },
        workspace=tmp_path,
        out=out,
    )
    assert decision.hook_action == "allow"
    assert json.loads(out.getvalue())["permission"] == "allow"


def test_detached_hook_refreshes_cursor_console_status(tmp_path, monkeypatch) -> None:
    calls = []
    home = tmp_path / ".agentveil"
    monkeypatch.setattr(
        cursor_hooks,
        "best_effort_spawn_hook_project_status",
        lambda **kwargs: calls.append(kwargs),
    )

    decision = cursor_hooks.process_hook(
        {
            "hook_event": "beforeShellExecution",
            "command": "agentveil-mcp-proxy --version && "
            "agentveil-mcp-proxy setup status --client cursor --json",
        },
        workspace=tmp_path,
        home=home,
        out=StringIO(),
        detached_upload=True,
    )

    assert decision.hook_action == "allow"
    assert calls == [{
        "connector": "cursor",
        "project_dir": tmp_path,
        "runtime_home": home,
    }]


def test_cursor_main_allows_bounded_local_git_command(tmp_path: Path) -> None:
    stdin = StringIO(json.dumps({"command": "git status --short"}))
    stdout = StringIO()

    assert cursor_hooks.main(
        ["--workspace", str(tmp_path), "--hook-event", "beforeShellExecution"],
        stdin=stdin,
        stdout=stdout,
    ) == 0
    assert json.loads(stdout.getvalue())["permission"] == "allow"


def test_shell_git_checkout_path_restore_denied_end_to_end(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {"hook_event": "beforeShellExecution", "command": "git checkout -- file.txt"},
        workspace=tmp_path,
        out=out,
    )
    assert decision.hook_action == "deny"


def test_shell_local_git_add_and_commit_allowed(tmp_path: Path) -> None:
    for command in (
        "git add packages/agentveil-mcp-proxy/agentveil_mcp_proxy/classification.py",
        "git commit -m 'fix: local dev policy'",
    ):
        out = StringIO()
        decision = cursor_hooks.process_hook(
            {"hook_event": "beforeShellExecution", "command": command},
            workspace=tmp_path,
            out=out,
        )
        assert decision.hook_action == "allow", command
        assert json.loads(out.getvalue())["permission"] == "allow"


def test_shell_broad_git_add_denied_without_write_file_redirect(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {"hook_event": "beforeShellExecution", "command": "git add ."},
        workspace=tmp_path,
        out=out,
    )
    assert decision.hook_action == "deny"
    response = json.loads(out.getvalue())
    assert "write_file" not in response["agent_message"]
    assert "No controlled MCP route exists for this shell action" in response["agent_message"]


def test_non_cursor_server_deny_has_no_native_write_redirect() -> None:
    from agentveil_mcp_proxy.cursor_hooks import HookDecision, format_cursor_hook_response
    from agentveil_mcp_proxy.policy import PolicyDecision, PolicyEvaluation, RiskClass, ToolCallContext

    decision = HookDecision(
        "deny",
        "risky_blocked",
        ToolCallContext(
            server="probe",
            tool="write_note",
            action="probe.write_note",
            risk_class=RiskClass.WRITE,
            action_family="write",
        ),
        PolicyEvaluation(
            decision=PolicyDecision.APPROVAL,
            risk_class=RiskClass.WRITE,
            policy_id="cursor_hook_default",
            policy_rule_id="cursor-write-approval",
            policy_context_hash="abc123",
            matched_rule_ids=("cursor-write-approval",),
        ),
    )
    response = format_cursor_hook_response(decision)
    assert response["permission"] == "deny"
    assert "write_file" not in response["agent_message"]
    assert "controlled MCP tool" not in response["agent_message"]
    assert "denied write_note" in response["agent_message"]


def test_shell_destructive_command_uses_hard_block_copy(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {"hook_event": "beforeShellExecution", "command": "rm -rf /tmp/workspace"},
        workspace=tmp_path,
        out=out,
    )
    assert decision.hook_action == "deny"
    response = json.loads(out.getvalue())
    message = response["agent_message"]
    assert "bounded security reason" in message
    assert "write_file" not in message
    assert "controlled MCP tool" not in message


def test_shell_readonly_allowed(tmp_path: Path) -> None:
    payload = {"hook_event": "beforeShellExecution", "command": "ls -la"}
    out = StringIO()
    decision = cursor_hooks.process_hook(payload, workspace=tmp_path, out=out)
    assert decision.hook_action == "allow"
    assert json.loads(out.getvalue())["permission"] == "allow"


def test_agentveil_mcp_route_passthrough(tmp_path: Path) -> None:
    _write_cursor_mcp_config(
        tmp_path,
        {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: _trusted_cursor_mcp_entry(tmp_path)},
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
    _write_cursor_mcp_config(
        tmp_path,
        {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: _trusted_cursor_mcp_entry(tmp_path)},
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


def test_non_agentveil_mcp_write_denied_with_multi_server_config(tmp_path: Path) -> None:
    _write_cursor_mcp_config(
        tmp_path,
        {
            cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: _trusted_cursor_mcp_entry(tmp_path),
            "filesystem": {"command": "filesystem-mcp"},
        },
    )
    payload = {
        "hook_event": "beforeMCPExecution",
        "tool_name": "filesystem:write_file",
        "arguments": {"path": "foo.txt", "content": "secret"},
    }
    out = StringIO()
    decision = cursor_hooks.process_hook(payload, workspace=tmp_path, out=out)
    assert decision.hook_action == "deny"
    response = json.loads(out.getvalue())
    assert response["permission"] == "deny"
    assert "secret" not in json.dumps(response)
    assert "foo.txt" not in json.dumps(response)


def test_third_party_mcp_mentioning_agentveil_in_args_denied(tmp_path: Path) -> None:
    _write_cursor_mcp_config(
        tmp_path,
        {"filesystem": {"command": "filesystem-mcp", "args": ["--label", "agentveil"]}},
    )
    payload = {
        "hook_event": "beforeMCPExecution",
        "tool_name": "filesystem:write_file",
        "arguments": {"path": "foo.txt", "content": "secret"},
    }
    out = StringIO()
    decision = cursor_hooks.process_hook(payload, workspace=tmp_path, out=out)
    assert decision.hook_action == "deny"
    assert decision.reason_code != "controlled_route_passthrough"


def test_empty_exact_key_agentveil_entry_denied(tmp_path: Path) -> None:
    _write_cursor_mcp_config(tmp_path, {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: {}})
    payload = {
        "hook_event": "beforeMCPExecution",
        "tool_name": "write_file",
        "arguments": {"path": "foo.txt"},
    }
    out = StringIO()
    decision = cursor_hooks.process_hook(payload, workspace=tmp_path, out=out)
    assert decision.hook_action == "deny"
    assert decision.reason_code != "controlled_route_passthrough"


def test_fake_command_under_exact_key_denied(tmp_path: Path) -> None:
    _write_cursor_mcp_config(
        tmp_path,
        {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: {"command": "not-agentveil"}},
    )
    payload = {
        "hook_event": "beforeMCPExecution",
        "tool_name": "write_file",
        "arguments": {"path": "foo.txt"},
    }
    out = StringIO()
    decision = cursor_hooks.process_hook(payload, workspace=tmp_path, out=out)
    assert decision.hook_action == "deny"
    assert decision.reason_code != "controlled_route_passthrough"


def _mcp_write_payload() -> dict:
    return {
        "hook_event": "beforeMCPExecution",
        "tool_name": "write_file",
        "arguments": {"path": "foo.txt"},
    }


def _assert_managed_entry_denied(tmp_path: Path, entry: dict) -> None:
    _write_cursor_mcp_config(tmp_path, {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: entry})
    out = StringIO()
    decision = cursor_hooks.process_hook(_mcp_write_payload(), workspace=tmp_path, out=out)
    assert decision.hook_action == "deny"
    assert decision.reason_code != "controlled_route_passthrough"


def test_wrong_workspace_managed_entry_denied(tmp_path: Path) -> None:
    other = tmp_path / "other"
    current = tmp_path / "current"
    other.mkdir()
    current.mkdir()
    entry = _trusted_cursor_mcp_entry(tmp_path, workspace=other)
    _write_cursor_mcp_config(current, {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: entry})
    out = StringIO()
    decision = cursor_hooks.process_hook(_mcp_write_payload(), workspace=current, out=out)
    assert decision.hook_action == "deny"
    assert decision.reason_code != "controlled_route_passthrough"


def test_missing_proxy_binary_denied(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    Path(entry["command"]).unlink()
    _write_cursor_mcp_config(tmp_path, {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: entry})
    out = StringIO()
    decision = cursor_hooks.process_hook(_mcp_write_payload(), workspace=tmp_path, out=out)
    assert decision.hook_action == "deny"
    assert decision.reason_code != "controlled_route_passthrough"


def test_tampered_config_path_denied(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    config_idx = entry["args"].index("--config") + 1
    entry["args"][config_idx] = str(tmp_path / "evil-config.json")
    _write_cursor_mcp_config(tmp_path, {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: entry})
    out = StringIO()
    decision = cursor_hooks.process_hook(_mcp_write_payload(), workspace=tmp_path, out=out)
    assert decision.hook_action == "deny"
    assert decision.reason_code != "controlled_route_passthrough"


def test_tampered_profile_path_denied(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    entry["env"]["PRODUCT_ROUTE_PROFILE_ROOT"] = str(tmp_path / "evil-profile")
    _write_cursor_mcp_config(tmp_path, {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: entry})
    out = StringIO()
    decision = cursor_hooks.process_hook(_mcp_write_payload(), workspace=tmp_path, out=out)
    assert decision.hook_action == "deny"
    assert decision.reason_code != "controlled_route_passthrough"


def test_agentveil_mcp_exe_basename_passthrough(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    proxy_dir = Path(entry["command"]).parent
    exe = proxy_dir / "agentveil-mcp-proxy.exe"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    Path(entry["command"]).unlink()
    entry["command"] = str(exe)
    _write_cursor_mcp_config(tmp_path, {cursor_hooks.AGENTVEIL_MCP_SERVER_KEY: entry})
    out = StringIO()
    decision = cursor_hooks.process_hook(_mcp_write_payload(), workspace=tmp_path, out=out)
    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"


def test_duplicate_home_arg_denied(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    entry["args"] = [*entry["args"], "--home", entry["env"]["AVP_HOME"]]
    _assert_managed_entry_denied(tmp_path, entry)


def test_duplicate_config_arg_denied(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    entry["args"] = [*entry["args"], "--config", str(tmp_path / "evil.json")]
    _assert_managed_entry_denied(tmp_path, entry)


def test_duplicate_passphrase_arg_denied(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    entry["args"] = [*entry["args"], "--passphrase-file", str(tmp_path / "evil-passphrase")]
    _assert_managed_entry_denied(tmp_path, entry)


def test_trailing_unknown_arg_denied(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    entry["args"] = [*entry["args"], "--evil-flag"]
    _assert_managed_entry_denied(tmp_path, entry)


def test_missing_type_field_denied(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    del entry["type"]
    _assert_managed_entry_denied(tmp_path, entry)


def test_extra_top_level_execution_field_denied(tmp_path: Path) -> None:
    entry = _trusted_cursor_mcp_entry(tmp_path)
    entry["cwd"] = str(tmp_path)
    _assert_managed_entry_denied(tmp_path, entry)


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


def test_native_write_deny_registers_durable_origin_and_agent_surface_context(tmp_path: Path) -> None:
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = StringIO()
        decision = cursor_hooks.process_hook(
            {
                "hook_event": "preToolUse",
                "tool_name": "Write",
                "tool_input": {"path": "note.txt", "contents": "hello"},
            },
            workspace=tmp_path,
            home=home,
            evidence_path=tmp_path / "hook-evidence.jsonl",
            out=out,
        )
        payload = json.loads(out.getvalue())
        redirect_context = parse_redirect_context_from_cursor_hook_output(payload)
        assert redirect_context is not None
        assert decision.disposition.value == "redirect"
        original_id = redirect_context["original_request_id"]
        meta = durable_original_metadata(home, original_id)
        assert meta is not None
        assert meta["redirect_role"] == "original"
        assert meta["redirect_playbook_id"] == "request_approval"
        assert "hello" not in json.dumps(meta)
        assert "note.txt" not in json.dumps(meta)
        assert "redirect_context=" in payload["agent_message"]
    finally:
        fixture.lease.close()


def test_native_edit_deny_has_no_verified_redirect_context(tmp_path: Path) -> None:
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = StringIO()
        decision = cursor_hooks.process_hook(
            {
                "hook_event": "preToolUse",
                "tool_name": "Edit",
                "tool_input": {"path": "note.txt", "old_string": "a", "new_string": "b"},
            },
            workspace=tmp_path,
            home=home,
            out=out,
        )
        payload = json.loads(out.getvalue())
        assert parse_redirect_context_from_cursor_hook_output(payload) is None
        assert decision.disposition.value == "hard_block"
    finally:
        fixture.lease.close()


def test_native_write_deny_without_live_binding_has_no_verified_context(tmp_path: Path) -> None:
    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path)
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {
            "hook_event": "preToolUse",
            "tool_name": "Write",
            "tool_input": {"path": "note.txt", "contents": "hello"},
        },
        workspace=tmp_path,
        home=home,
        out=out,
    )
    payload = json.loads(out.getvalue())
    assert parse_redirect_context_from_cursor_hook_output(payload) is None
    assert decision.disposition.value == "hard_block"


def test_cursor_hook_denied_uploads_bounded_decision_summary(monkeypatch, tmp_path: Path) -> None:
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
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {
            "hook_event": "preToolUse",
            "tool_name": "Write",
            "tool_input": {"path": "foo.txt", "contents": "secret"},
        },
        workspace=tmp_path,
        out=out,
    )

    assert decision.hook_action == "deny"
    assert wait_for_hook_denied_uploads_for_tests()
    assert len(uploads) == 1
    encoded = json.dumps(payload_to_request_body(uploads[0]))
    assert "secret" not in encoded
    assert "foo.txt" not in encoded


def test_cursor_hook_redirect_does_not_upload_decision_summary(monkeypatch, tmp_path: Path) -> None:
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
        out = StringIO()
        decision = cursor_hooks.process_hook(
            {
                "hook_event": "preToolUse",
                "tool_name": "Write",
                "tool_input": {"path": "note.txt", "contents": "hello"},
            },
            workspace=tmp_path,
            home=home,
            out=out,
        )
        assert decision.reason_code == "managed_route_redirect"
        assert wait_for_hook_denied_uploads_for_tests()
        assert uploads == []
    finally:
        fixture.lease.close()


def test_cursor_hook_hard_block_still_uploads_with_live_binding(
    monkeypatch,
    tmp_path: Path,
) -> None:
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
        out = StringIO()
        decision = cursor_hooks.process_hook(
            {
                "hook_event": "preToolUse",
                "tool_name": "Delete",
                "tool_input": {"path": "note.txt"},
            },
            workspace=tmp_path,
            home=home,
            out=out,
        )
        assert decision.reason_code == "risky_blocked"
        assert decision.disposition.value == "hard_block"
        assert wait_for_hook_denied_uploads_for_tests()
        assert len(uploads) == 1
        assert uploads[0].decision == "denied"
    finally:
        fixture.lease.close()


@pytest.mark.parametrize("command,expected", NATIVE_SHELL_COMMAND_MATRIX)
def test_cursor_shell_classifier_matches_shared_matrix(command: str, expected: RiskClass) -> None:
    assert (
        classify_cursor_tool(
            "",
            hook_event="beforeShellExecution",
            command=command,
        )
        is expected
    )


def test_cursor_exact_delete_tool_hard_block_has_null_alternative(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {"hook_event": "preToolUse", "tool_name": "Delete", "tool_input": {"path": "notes.txt"}},
        workspace=tmp_path,
        out=out,
    )
    response = json.loads(out.getvalue())
    assert decision.hook_action == "deny"
    assert decision.disposition.value == "hard_block"
    assert response["permission"] == "deny"
    assert "alternative=null" in response["agent_message"]
    assert "filesystem.stage_delete.v1" not in response["agent_message"]


def test_cursor_apply_patch_delete_with_binding_is_redirect_and_available(tmp_path: Path) -> None:
    home, _sandbox, downstream = init_redirect_contract_home(tmp_path)
    fixture = publish_live_hook_binding(home, downstream=downstream)
    try:
        out = StringIO()
        decision = cursor_hooks.process_hook(
            {
                "hook_event": "preToolUse",
                "tool_name": "ApplyPatch",
                "tool_input": {"patch": "*** Begin Patch\n*** Delete File: notes.txt\n*** End Patch"},
            },
            workspace=tmp_path,
            home=home,
            out=out,
        )
        response = json.loads(out.getvalue())
        assert decision.hook_action == "deny"
        assert decision.disposition.value == "redirect"
        assert decision.reason_code == "managed_route_redirect"
        assert "suggestion_status=available" in response["agent_message"]
        assert "alternative.tool_contract=agentveil_stage_delete" in response["agent_message"]
        assert "alternative.input.path=notes.txt" in response["agent_message"]
        assert "alternative.id=" not in response["agent_message"]
        assert "alternative.input.path=notes.txt" in response["agent_message"]
    finally:
        fixture.lease.close()


def test_cursor_exact_shell_delete_uses_shell_canonicalize_but_stays_unavailable(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {"hook_event": "beforeShellExecution", "command": "rm notes.txt"},
        workspace=tmp_path,
        out=out,
    )
    response = json.loads(out.getvalue())
    assert decision.hook_action == "deny"
    assert decision.disposition.value == "hard_block"
    assert "alternative=null" in response["agent_message"]
    assert "filesystem.stage_delete.v1" not in response["agent_message"]


def test_cursor_ambiguous_shell_stays_deny_without_alternative(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {"hook_event": "beforeShellExecution", "command": "rm -rf /tmp/workspace"},
        workspace=tmp_path,
        evidence_path=tmp_path / "evidence.jsonl",
        out=out,
    )
    response = json.loads(out.getvalue())
    dumped = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8")
    assert decision.hook_action == "deny"
    assert "alternative=null" in response["agent_message"]
    assert "filesystem.stage_delete.v1" not in response["agent_message"]
    assert "/tmp/workspace" not in response["agent_message"]
    assert "/tmp/workspace" not in dumped


def test_cursor_trusted_static_exact_delete_is_hard_block_with_available_suggestion(tmp_path: Path) -> None:
    home, sandbox, _downstream = init_redirect_contract_home(tmp_path)
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {
            "hook_event": "preToolUse",
            "tool_name": "ApplyPatch",
            "tool_input": {"patch": "*** Begin Patch\n*** Delete File: notes.txt\n*** End Patch"},
        },
        workspace=tmp_path,
        home=home,
        out=out,
    )
    response = json.loads(out.getvalue())
    message = response["agent_message"]
    assert decision.hook_action == "deny"
    assert decision.disposition.value == "hard_block"
    assert parse_redirect_context_from_cursor_hook_output(response) is None
    assert "suggestion_status=available" in message
    assert "alternative.tool_contract=agentveil_stage_delete" in message
    assert "alternative.input.path=notes.txt" in message
    assert "alternative.id=" not in message
    assert "alternative.input.path=notes.txt" in message
    assert "not currently available" not in message
    assert str(home) not in message
    assert str(sandbox) not in message


def test_cursor_allow_does_not_read_static_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, _sandbox, _downstream = init_redirect_contract_home(tmp_path)
    calls: list[object] = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cursor_hooks.trusted_static_controlled_route_ready",
        lambda **kwargs: calls.append(kwargs) or True,
    )
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {"hook_event": "preToolUse", "tool_name": "Read", "tool_input": {"path": "notes.txt"}},
        workspace=tmp_path,
        home=home,
        out=out,
    )
    assert decision.hook_action == "allow"
    assert calls == []
    assert json.loads(out.getvalue()) == {"permission": "allow"}


def test_cursor_hook_does_not_deny_agentveil_owned_semantic_mcp_tools(tmp_path: Path) -> None:
    for tool_name, arguments in (
        ("agentveil_stage_delete", {"path": "notes.txt"}),
        ("agentveil_restore_staged", {"quarantine_entry_id": "a" * 32}),
        ("agentveil_cleanup_staged", {"quarantine_entry_id": "a" * 32}),
        ("agentveil_prepare_patch", {"path": "notes.txt", "patch": "diff"}),
        (
            "agentveil_apply_prepared_patch",
            {"prepared_artifact_ref": "a" * 32, "prepared_artifact_hash": "ab" * 32},
        ),
        ("agentveil_prepare_git_change", {"worktree_path": "."}),
        ("agentveil_git_operation", {"worktree_path": ".", "operation": "prepare_for_review"}),
        ("agentveil_write_file", {"path": "todo.txt", "content": "done\n"}),
        ("MCP:agentveil_stage_delete", {"path": "notes.txt"}),
        ("agentveil:agentveil_restore_staged", {"quarantine_entry_id": "a" * 32}),
        ("agentveil:agentveil_prepare_patch", {"path": "notes.txt", "patch": "diff"}),
        (
            "agentveil:agentveil_apply_prepared_patch",
            {"prepared_artifact_ref": "a" * 32, "prepared_artifact_hash": "ab" * 32},
        ),
        ("agentveil:agentveil_prepare_git_change", {"worktree_path": "."}),
        ("agentveil:agentveil_git_operation", {"worktree_path": ".", "operation": "prepare_for_review"}),
        ("agentveil:agentveil_write_file", {"path": "todo.txt", "content": "done\n"}),
    ):
        out = StringIO()
        decision = cursor_hooks.process_hook(
            {
                "hook_event": "beforeMCPExecution",
                "tool_name": tool_name,
                "arguments": arguments,
            },
            workspace=tmp_path,
            out=out,
        )
        assert decision.hook_action == "allow", tool_name
        assert decision.reason_code == "controlled_route_passthrough", tool_name
        assert json.loads(out.getvalue()) == {"permission": "allow"}


def test_cursor_hook_cleanup_passes_to_proxy_and_is_not_approved(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {
            "hook_event": "beforeMCPExecution",
            "tool_name": "agentveil_cleanup_staged",
            "arguments": {"quarantine_entry_id": "a" * 32},
        },
        workspace=tmp_path,
        out=out,
    )
    response = json.loads(out.getvalue())
    assert decision.hook_action == "allow"
    assert decision.reason_code == "controlled_route_passthrough"
    assert response == {"permission": "allow"}
    assert "approved" not in json.dumps(response)


def test_cursor_hook_still_denies_native_destructive_actions(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {
            "hook_event": "preToolUse",
            "tool_name": "Delete",
            "tool_input": {"path": "notes.txt"},
        },
        workspace=tmp_path,
        out=out,
    )
    assert decision.hook_action == "deny"
    assert json.loads(out.getvalue())["permission"] == "deny"
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {"hook_event": "beforeShellExecution", "command": "rm notes.txt"},
        workspace=tmp_path,
        out=out,
    )
    assert decision.hook_action == "deny"
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {
            "hook_event": "preToolUse",
            "tool_name": "ApplyPatch",
            "tool_input": {"patch": "*** Begin Patch\n*** Delete File: notes.txt\n*** End Patch"},
        },
        workspace=tmp_path,
        out=out,
    )
    assert decision.hook_action == "deny"


def test_cursor_hook_rejects_lookalike_and_shell_text_as_controlled_tool(tmp_path: Path) -> None:
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {
            "hook_event": "beforeMCPExecution",
            "tool_name": "filesystem:agentveil_stage_delete",
            "arguments": {"path": "notes.txt"},
        },
        workspace=tmp_path,
        out=out,
    )
    assert decision.hook_action == "deny"
    out = StringIO()
    decision = cursor_hooks.process_hook(
        {
            "hook_event": "beforeShellExecution",
            "command": "agentveil_stage_delete notes.txt",
        },
        workspace=tmp_path,
        out=out,
    )
    assert decision.hook_action == "deny"


def test_cursor_hook_does_not_passthrough_whitespace_or_non_string_tool_name(tmp_path: Path) -> None:
    for tool_name in (
        " agentveil_stage_delete",
        "agentveil_stage_delete ",
        "\tagentveil_stage_delete",
        "mcp__agentveil__agentveil_stage_delete ",
        "MCP:agentveil_stage_delete ",
    ):
        out = StringIO()
        decision = cursor_hooks.process_hook(
            {
                "hook_event": "beforeMCPExecution",
                "tool_name": tool_name,
                "arguments": {"path": "notes.txt"},
            },
            workspace=tmp_path,
            out=out,
        )
        assert decision.reason_code != "controlled_route_passthrough", repr(tool_name)
    for tool_name in (None, 123, True, ["agentveil_stage_delete"], {"tool": "agentveil_stage_delete"}):
        out = StringIO()
        decision = cursor_hooks.process_hook(
            {
                "hook_event": "beforeMCPExecution",
                "tool_name": tool_name,
                "arguments": {"path": "notes.txt"},
            },
            workspace=tmp_path,
            out=out,
        )
        assert decision.reason_code != "controlled_route_passthrough", repr(tool_name)
