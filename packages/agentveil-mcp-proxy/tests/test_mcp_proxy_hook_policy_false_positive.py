"""Regression tests for hook-policy false positives found by audit."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Callable

import pytest

from agentveil_mcp_proxy import claude_hook, codex_hook, cursor_hooks, gemini_hook


@pytest.fixture(autouse=True)
def _reset_hook_denied_upload_dedupe() -> None:
    from agentveil_mcp_proxy.console_decision_summary_client import (
        reset_hook_denied_upload_dedupe_for_tests,
    )

    reset_hook_denied_upload_dedupe_for_tests()


def _claude(command: str, tmp_path: Path) -> str:
    _ = tmp_path
    out = io.StringIO()
    decision = claude_hook.process_hook(
        {
            "session_id": "sess-test",
            "cwd": "/private/customer/workspace",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        out=out,
    )
    return decision.hook_action


def _codex(command: str, tmp_path: Path) -> str:
    _ = tmp_path
    out = io.StringIO()
    decision = codex_hook.process_hook(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "sess-test",
            "cwd": "/private/customer/workspace",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        out=out,
    )
    return decision.hook_action


def _cursor(command: str, tmp_path: Path) -> str:
    out = io.StringIO()
    decision = cursor_hooks.process_hook(
        {"hook_event": "beforeShellExecution", "command": command},
        workspace=tmp_path,
        out=out,
    )
    return decision.hook_action


def _gemini(command: str, tmp_path: Path) -> str:
    _ = tmp_path
    out = io.StringIO()
    decision = gemini_hook.process_hook(
        {
            "hook_event_name": "BeforeTool",
            "session_id": "sess-test",
            "cwd": "/private/customer/workspace",
            "tool_name": "run_shell_command",
            "tool_input": {"command": command},
        },
        out=out,
    )
    return decision.hook_action


@pytest.mark.parametrize("hook_runner", [_claude, _codex, _cursor, _gemini])
@pytest.mark.parametrize(
    "command",
    [
        'git commit -m "rm dead code"',
        'git commit -m "touch base case"',
        'git commit -m "cp utils helper"',
        'git commit -m "fix -i option docs"',
        'git commit -m "a > b"',
        "git log -i --grep=foo",
        "rg token app.py",
        "grep secret app.py",
    ],
)
def test_hook_allows_audited_local_dev_false_positive_cases(
    hook_runner: Callable[[str, Path], str],
    command: str,
    tmp_path: Path,
) -> None:
    assert hook_runner(command, tmp_path) == "allow"
