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


@dataclass(frozen=True)
class ProcessScenario:
    scenario_id: str
    payload: dict[str, Any] | None
    publish_binding: bool
    install_cursor_mcp: bool
    cursor_hook_event: str | None = None
    expect_allow: bool = False
    expect_redirect_context: bool = False
    expect_hard_block_copy: bool = False
    expect_playbook_id: str | None = None
    connector_ids: tuple[str, ...] | None = None


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


def _install_cursor_command(
    project: Path,
    home: Path,
    *,
    hook_event: str | None = None,
) -> str:
    cursor_setup.install_hooks(project, home=home)
    payload = json.loads(cursor_setup.hooks_config_path(project).read_text(encoding="utf-8"))
    events = (hook_event,) if hook_event else cursor_setup.AGENTVEIL_HOOK_EVENTS
    for event in events:
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


SAFE_ALLOW_PAYLOADS = {
    "cursor": {
        "hook_event": "preToolUse",
        "tool_name": "Read",
        "tool_input": {"path": "note.txt"},
    },
    "claude_code": {"tool_name": "Bash", "tool_input": {"command": "git status --short"}},
    "codex": {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status --short"},
    },
    "gemini_cli": {
        "hook_event_name": "BeforeTool",
        "tool_name": "run_shell_command",
        "tool_input": {"command": "git status --short"},
    },
}

MCP_PASSTHROUGH_PAYLOADS = {
    "cursor": {
        "hook_event": "beforeMCPExecution",
        "tool_name": "agentveil-mcp-proxy:write_file",
        "arguments": {"path": "note.txt", "content": "hello"},
    },
    "claude_code": {
        "tool_name": "mcp__agentveil-mcp-proxy__list_workspace",
        "tool_input": {},
    },
    "codex": {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__agentveil-mcp-proxy__list_workspace",
        "tool_input": {},
    },
    "gemini_cli": {
        "hook_event_name": "BeforeTool",
        "tool_name": "mcp_agentveil-mcp-proxy_list_workspace",
        "tool_input": {},
    },
}

RECOVERABLE_DELETE_PAYLOADS = {
    "cursor": {
        "hook_event": "preToolUse",
        "tool_name": "Delete",
        "tool_input": {"path": "note.txt"},
    },
}

DESTRUCTIVE_PAYLOADS = {
    "cursor": {
        "hook_event": "beforeShellExecution",
        "command": "rm -rf /tmp/workspace",
    },
    "claude_code": {"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/workspace"}},
    "codex": {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /tmp/workspace"},
    },
    "gemini_cli": {
        "hook_event_name": "BeforeTool",
        "tool_name": "run_shell_command",
        "tool_input": {"command": "rm -rf /tmp/workspace"},
    },
}

PROCESS_SCENARIOS = (
    ProcessScenario(
        "safe_allow",
        payload=None,
        publish_binding=False,
        install_cursor_mcp=False,
        expect_allow=True,
        expect_redirect_context=False,
    ),
    ProcessScenario(
        "ready_redirect",
        payload=None,
        publish_binding=True,
        install_cursor_mcp=False,
        expect_allow=False,
        expect_redirect_context=True,
    ),
    ProcessScenario(
        "route_unavailable_hard_block",
        payload=None,
        publish_binding=False,
        install_cursor_mcp=False,
        expect_allow=False,
        expect_redirect_context=False,
    ),
    ProcessScenario(
        "controlled_mcp_passthrough",
        payload=None,
        publish_binding=False,
        install_cursor_mcp=True,
        cursor_hook_event="beforeMCPExecution",
        expect_allow=True,
        expect_redirect_context=False,
    ),
    ProcessScenario(
        "recoverable_exact_delete",
        payload=None,
        publish_binding=True,
        install_cursor_mcp=False,
        expect_allow=False,
        expect_redirect_context=True,
        expect_playbook_id="controlled_stage_delete",
        connector_ids=("cursor",),
    ),
    ProcessScenario(
        "destructive_hard_block",
        payload=None,
        publish_binding=True,
        install_cursor_mcp=False,
        cursor_hook_event="beforeShellExecution",
        expect_allow=False,
        expect_redirect_context=False,
        expect_hard_block_copy=True,
    ),
)


def _scenario_payload(case: InstalledHookCase, scenario: ProcessScenario) -> dict[str, Any]:
    if scenario.scenario_id == "safe_allow":
        return SAFE_ALLOW_PAYLOADS[case.connector_id]
    if scenario.scenario_id == "controlled_mcp_passthrough":
        return MCP_PASSTHROUGH_PAYLOADS[case.connector_id]
    if scenario.scenario_id == "recoverable_exact_delete":
        return RECOVERABLE_DELETE_PAYLOADS[case.connector_id]
    if scenario.scenario_id == "destructive_hard_block":
        return DESTRUCTIVE_PAYLOADS[case.connector_id]
    return case.hook_payload


def _install_cursor_trusted_mcp_route(project: Path, home: Path, tmp_path: Path) -> None:
    from agentveil_mcp_proxy.cursor_setup import build_mcp_server_entry

    proxy = tmp_path / "bin" / "agentveil-mcp-proxy"
    proxy.parent.mkdir(parents=True, exist_ok=True)
    proxy.write_text("#!/bin/sh\n", encoding="utf-8")
    entry = build_mcp_server_entry(
        proxy_command=str(proxy),
        home=home,
        config_path=home / "mcp-proxy" / "config.json",
        passphrase_file=home / "passphrase",
        profile=home / "product-profile",
        workspace=project,
    )
    cursor_dir = project / ".cursor"
    cursor_dir.mkdir(exist_ok=True)
    (cursor_dir / "mcp.json").write_text(
        json.dumps({"mcpServers": {cursor_setup.AGENTVEIL_MCP_SERVER_KEY: entry}}),
        encoding="utf-8",
    )


def _run_installed_hook(command: str, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        shell=True,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _parse_hook_output(case: InstalledHookCase, proc: subprocess.CompletedProcess[str]) -> dict[str, Any] | None:
    stdout = proc.stdout.strip()
    if not stdout:
        return None
    return json.loads(stdout)


def _hook_output_allows(case: InstalledHookCase, proc: subprocess.CompletedProcess[str]) -> bool:
    if proc.returncode != 0:
        return False
    payload = _parse_hook_output(case, proc)
    if case.connector_id == "cursor":
        return payload is not None and payload.get("permission") == "allow"
    if case.connector_id == "gemini_cli":
        return payload is not None and payload.get("decision") == "allow"
    return payload is None


def _deny_message(case: InstalledHookCase, proc: subprocess.CompletedProcess[str]) -> str:
    payload = _parse_hook_output(case, proc)
    if payload is None:
        return proc.stdout + proc.stderr
    if case.connector_id == "cursor":
        return str(payload.get("agent_message") or "")
    if case.connector_id == "gemini_cli":
        return str(payload.get("reason") or "")
    hook_specific = payload.get("hookSpecificOutput") or {}
    return str(hook_specific.get("permissionDecisionReason") or "")


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


@pytest.mark.parametrize("case", INSTALLED_HOOK_CASES, ids=lambda case: case.connector_id)
@pytest.mark.parametrize("scenario", PROCESS_SCENARIOS, ids=lambda scenario: scenario.scenario_id)
def test_installed_hook_process_truth_table(
    tmp_path: Path,
    case: InstalledHookCase,
    scenario: ProcessScenario,
) -> None:
    if scenario.connector_ids is not None and case.connector_id not in scenario.connector_ids:
        pytest.skip(f"{scenario.scenario_id} applies to {scenario.connector_ids}")
    project = tmp_path / "project"
    project.mkdir()
    sandbox = project / "sandbox"
    sandbox.mkdir()
    home = case.home_for(project)
    _init_proxy_home(home, sandbox)
    lease = _publish_live_binding(home, sandbox) if scenario.publish_binding else None
    try:
        if case.connector_id == "cursor":
            command = _install_cursor_command(
                project,
                home,
                hook_event=scenario.cursor_hook_event,
            )
        else:
            command = case.install_command(project, home)
        assert "--home" in command
        if scenario.install_cursor_mcp and case.connector_id == "cursor":
            _install_cursor_trusted_mcp_route(project, home, tmp_path)
        payload = _scenario_payload(case, scenario)
        proc = _run_installed_hook(command, payload)
        assert proc.returncode == 0, proc.stderr
        assert _hook_output_allows(case, proc) is scenario.expect_allow
        hook_output = _parse_hook_output(case, proc)
        redirect_context = case.parse_context(hook_output or {}) if hook_output else None
        if scenario.expect_redirect_context:
            assert redirect_context is not None
            expected_playbook = scenario.expect_playbook_id or "request_approval"
            assert redirect_context["redirect_playbook_id"] == expected_playbook
            meta = durable_original_metadata(home, redirect_context["original_request_id"])
            assert meta is not None
            assert meta["redirect_role"] == "original"
        else:
            assert redirect_context is None
        if scenario.expect_hard_block_copy:
            assert "bounded security reason" in _deny_message(case, proc)
    finally:
        if lease is not None:
            lease.close()
