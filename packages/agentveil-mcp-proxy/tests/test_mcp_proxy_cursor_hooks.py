"""Unit tests for Cursor hook stdin handling and bounded evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentveil_mcp_proxy.cli import main, run_cursor_hook_cli
from agentveil_mcp_proxy.cursor_hooks import (
    CursorHookError,
    RISKY_MARKER,
    SAFE_MARKER,
    assert_cursor_hook_output_is_bounded,
    assert_evidence_row_is_bounded,
    build_evidence_row,
    classify_cursor_hook,
    format_cursor_hook_response,
    infer_hook_event,
    parse_cursor_hook_input,
    run_cursor_hook,
)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    return root


def test_infer_hook_event_from_payload_shapes() -> None:
    assert infer_hook_event({"command": "echo ok"}) == "beforeShellExecution"
    assert infer_hook_event({"tool_name": "Write", "tool_input": {}}) == "preToolUse"
    assert infer_hook_event({"tool_name": "list_workspace", "arguments": {}}) == "beforeMCPExecution"


def test_risky_pre_tool_use_is_denied_before_mutation(workspace: Path) -> None:
    decision = classify_cursor_hook(
        {"tool_name": "Write", "tool_input": {"path": "target.txt", "contents": RISKY_MARKER}},
        hook_event="preToolUse",
    )
    response = format_cursor_hook_response(decision)
    assert decision.permission == "deny"
    assert decision.target_reached is False
    assert response["permission"] == "deny"
    assert "user_message" in response
    assert "agent_message" in response
    assert "/users/" not in json.dumps(response).lower()


def test_safe_marker_allows_write(workspace: Path) -> None:
    decision = classify_cursor_hook(
        {
            "tool_name": "Write",
            "tool_input": {"path": "safe.txt", "contents": f"ok {SAFE_MARKER}"},
        },
        hook_event="preToolUse",
    )
    assert decision.permission == "allow"
    assert decision.reason_code == "safe_marker"


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("Delete", {"path": "delete-me.txt"}),
        ("StrReplace", {"path": "x.txt", "old_string": "a", "new_string": "b"}),
        ("ApplyPatch", {"patch": "patch"}),
    ],
)
def test_risky_tool_classes_are_denied(tool_name: str, tool_input: dict) -> None:
    decision = classify_cursor_hook(
        {"tool_name": tool_name, "tool_input": tool_input},
        hook_event="preToolUse",
    )
    assert decision.permission == "deny"
    assert decision.target_reached is False


def test_safe_shell_is_allowed() -> None:
    decision = classify_cursor_hook(
        {"command": f"echo {SAFE_MARKER} > safe.txt"},
        hook_event="beforeShellExecution",
    )
    assert decision.permission == "allow"


def test_risky_shell_is_denied() -> None:
    decision = classify_cursor_hook(
        {"command": f"echo {RISKY_MARKER} > shell-risk.txt"},
        hook_event="beforeShellExecution",
    )
    assert decision.permission == "deny"


def test_mcp_read_is_allowed_and_write_is_denied() -> None:
    safe = classify_cursor_hook(
        {"tool_name": "list_workspace", "arguments": {}},
        hook_event="beforeMCPExecution",
    )
    risky = classify_cursor_hook(
        {"tool_name": "write_file", "arguments": {"path": "x", "content": RISKY_MARKER}},
        hook_event="beforeMCPExecution",
    )
    assert safe.permission == "allow"
    assert risky.permission == "deny"


def test_run_cursor_hook_writes_bounded_evidence(workspace: Path) -> None:
    response, evidence = run_cursor_hook(
        stdin_text=json.dumps({"tool_name": "Delete", "tool_input": {"path": "x.txt"}}),
        workspace=workspace,
        hook_event="preToolUse",
    )
    assert response["permission"] == "deny"
    assert_evidence_row_is_bounded(evidence)
    evidence_path = workspace / ".cursor" / "agentveil-hook-evidence.jsonl"
    row = json.loads(evidence_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["decision"] == "deny"
    assert row["target_reached"] is False
    assert row["safe_first_step_id"] == "request_human_review"
    assert "/users/" not in json.dumps(row).lower()


def test_hook_cli_reads_stdin_and_returns_json(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(workspace)
    payload = {"tool_name": "Write", "tool_input": {"path": "risk.txt", "contents": "x"}}
    out = run_cursor_hook_cli(
        workspace=workspace,
        stdin_text=json.dumps(payload),
        out=__import__("io").StringIO(),
    )
    assert out == 0


def test_deny_response_is_bounded() -> None:
    decision = classify_cursor_hook(
        {"tool_name": "Shell", "tool_input": {"command": RISKY_MARKER}},
        hook_event="preToolUse",
    )
    response = format_cursor_hook_response(decision)
    evidence = build_evidence_row(decision)
    assert_evidence_row_is_bounded(evidence)
    assert_cursor_hook_output_is_bounded(json.dumps(response), json.dumps(evidence))


def test_parse_cursor_hook_input_rejects_invalid_json() -> None:
    with pytest.raises(CursorHookError):
        parse_cursor_hook_input("not-json")


def test_cli_hook_cursor_command(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    payload = json.dumps({"tool_name": "Write", "tool_input": {"path": "x", "contents": "y"}})
    proc = __import__("subprocess").run(
        [
            __import__("sys").executable,
            "-m",
            "agentveil_mcp_proxy.cli",
            "hook",
            "cursor",
            "--workspace",
            str(workspace),
        ],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    body = json.loads(proc.stdout)
    assert body["permission"] == "deny"
    assert_cursor_hook_output_is_bounded(proc.stdout, proc.stderr)
