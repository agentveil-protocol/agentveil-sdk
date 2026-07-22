"""Installed hook command shape proves connector redirect without manual home=."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

from agentveil_mcp_proxy import claude_hook_setup, codex_setup, cursor_setup, gemini_setup
from agentveil_mcp_proxy.approval.server import build_owner_client_id, publish_owner_claim
from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream
from agentveil_mcp_proxy.client_guidance import (
    build_hook_runtime_binding,
    parse_redirect_context_from_claude_hook_output,
    parse_redirect_context_from_codex_hook_output,
    parse_redirect_context_from_cursor_hook_output,
    parse_redirect_context_from_gemini_hook_output,
    write_hook_runtime_binding,
)
from redirect_hook_contract_fixtures import durable_original_metadata


@dataclass(frozen=True)
class InstalledHookCase:
    connector_id: str
    home_for: Callable[[Path], Path]
    install_command: Callable[[Path, Path], str]
    hook_payload: dict[str, Any]
    parse_context: Callable[[dict[str, Any]], dict[str, str] | None]


def _publish_live_binding(home: Path, sandbox: Path) -> object:
    downstream = quickstart_filesystem_downstream(sandbox)
    lease = publish_owner_claim(
        home / "mcp-proxy" / "owner_claims",
        pid=os.getpid(),
        instance_token="installed-hook-inst",
        session_id="installed-hook-session",
    )
    binding = build_hook_runtime_binding(
        owner_pid=os.getpid(),
        instance_token="installed-hook-inst",
        session_id="installed-hook-session",
        client_id=build_owner_client_id("filesystem", instance_token="installed-hook-inst"),
        downstream=downstream,
    )
    assert binding is not None
    write_hook_runtime_binding(home, binding)
    return lease


def _init_proxy_home(home: Path, sandbox: Path) -> None:
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="implementer")
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = quickstart_filesystem_downstream(sandbox)
    init.config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def _install_cursor_command(project: Path, home: Path) -> str:
    cursor_setup.install_hooks(project, home=home)
    payload = json.loads(cursor_setup.hooks_config_path(project).read_text(encoding="utf-8"))
    for event in cursor_setup.AGENTVEIL_HOOK_EVENTS:
        for item in payload.get("hooks", {}).get(event, []) or []:
            if not isinstance(item, dict):
                continue
            command = str(item.get("command") or "")
            if cursor_setup.is_managed_hook_command(command):
                return command
    raise AssertionError("managed cursor hook command not found")


def _install_claude_command(project: Path, _home: Path) -> str:
    claude_hook_setup.install_hook(project)
    settings = json.loads(claude_hook_setup.project_settings_path(project).read_text(encoding="utf-8"))
    for group in settings.get("hooks", {}).get("PreToolUse", []):
        if not isinstance(group, dict):
            continue
        for hook in group.get("hooks", []) or []:
            if not isinstance(hook, dict):
                continue
            command = str(hook.get("command") or "")
            if claude_hook_setup.AGENTVEIL_HOOK_MARKER in command:
                return command
    raise AssertionError("managed claude hook command not found")


def _install_codex_command(project: Path, _home: Path) -> str:
    codex_setup.install_hook(project_dir=project, python=sys.executable)
    hooks = json.loads(codex_setup.hooks_path(project).read_text(encoding="utf-8"))
    for group in hooks.get("hooks", {}).get("PreToolUse", []):
        for hook in group.get("hooks", []) or []:
            command = str(hook.get("command") or "")
            if codex_setup.command_invokes_managed_hook(command):
                return command
    raise AssertionError("managed codex hook command not found")


def _install_gemini_command(project: Path, _home: Path) -> str:
    gemini_setup.install_hook(project_dir=project, python=sys.executable)
    settings = json.loads(gemini_setup.settings_path(project).read_text(encoding="utf-8"))
    for group in settings.get("hooks", {}).get("BeforeTool", []):
        for hook in group.get("hooks", []) or []:
            command = str(hook.get("command") or "")
            if gemini_setup.command_invokes_managed_hook(command):
                return command
    raise AssertionError("managed gemini hook command not found")


INSTALLED_HOOK_CASES = (
    InstalledHookCase(
        "cursor",
        cursor_setup.setup_home,
        _install_cursor_command,
        {
            "hook_event": "preToolUse",
            "tool_name": "Write",
            "tool_input": {"path": "note.txt", "contents": "hello"},
        },
        parse_redirect_context_from_cursor_hook_output,
    ),
    InstalledHookCase(
        "claude_code",
        claude_hook_setup.setup_home,
        _install_claude_command,
        {
            "tool_name": "Write",
            "tool_input": {"file_path": "note.txt", "content": "hello"},
        },
        parse_redirect_context_from_claude_hook_output,
    ),
    InstalledHookCase(
        "codex",
        codex_setup.setup_home,
        _install_codex_command,
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "note.txt", "content": "hello"},
        },
        parse_redirect_context_from_codex_hook_output,
    ),
    InstalledHookCase(
        "gemini_cli",
        gemini_setup.setup_home,
        _install_gemini_command,
        {
            "hook_event_name": "BeforeTool",
            "tool_name": "write_file",
            "tool_input": {"path": "note.txt", "content": "hello"},
        },
        parse_redirect_context_from_gemini_hook_output,
    ),
)


@pytest.mark.parametrize("case", INSTALLED_HOOK_CASES, ids=lambda case: case.connector_id)
def test_installed_hook_command_includes_home_and_registers_durable_origin(
    tmp_path: Path,
    case: InstalledHookCase,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    sandbox = project / "sandbox"
    sandbox.mkdir()
    home = case.home_for(project)
    _init_proxy_home(home, sandbox)
    lease = _publish_live_binding(home, sandbox)
    try:
        command = case.install_command(project, home)
        assert "--home" in command
        assert str(home.resolve()) in command or str(home) in command
        proc = subprocess.run(
            command,
            shell=True,
            input=json.dumps(case.hook_payload),
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        hook_output = json.loads(proc.stdout)
        redirect_context = case.parse_context(hook_output)
        assert redirect_context is not None
        assert redirect_context["redirect_playbook_id"] == "request_approval"
        meta = durable_original_metadata(home, redirect_context["original_request_id"])
        assert meta is not None
        assert meta["redirect_role"] == "original"
        assert "hello" not in json.dumps(meta)
    finally:
        lease.close()
