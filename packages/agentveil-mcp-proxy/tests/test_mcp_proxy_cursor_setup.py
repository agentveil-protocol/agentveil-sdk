"""Tests for agentveil_mcp_proxy.cursor_setup."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import main
from agentveil_mcp_proxy import cursor_setup
from agentveil_mcp_proxy.cursor_setup import (
    AGENTVEIL_HOOK_MARKER,
    BROAD_FOLDER_MESSAGE,
    CursorSetupError,
    MCP_ROUTE_ENV_KEYS,
    SETUP_ADVISORY_NEXT_STEP,
    build_mcp_server_entry,
    connector_status,
    format_setup_success_message,
    hooks_config_path,
    install_hooks,
    install_mcp_route,
    is_broad_workspace,
    is_managed_hook_command,
    load_project_mcp_server_entry,
    mcp_config_path,
    mcp_route_entry_has_private_parity,
    neutralize_competing_global_route,
    remove_hooks,
    remove_mcp_route,
    setup_home,
)

USER_AGENTVEIL_HOOK = "echo user-agentveil-not-managed"


@pytest.fixture(autouse=True)
def _fast_cursor_center_lifecycle(monkeypatch):
    """Keep cursor setup unit tests deterministic; avoid real center spawn waits."""
    monkeypatch.setattr(cursor_setup, "_START_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(cursor_setup, "_POLL_INTERVAL_SECONDS", 0.001)


@pytest.fixture(autouse=True)
def _isolated_cursor_user_settings(tmp_path: Path, monkeypatch) -> None:
    """Use isolated Cursor User/settings.json in unit tests."""
    user_data = tmp_path / "cursor-user-data"
    user_data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CURSOR_USER_DATA_DIR", str(user_data))


def _managed_hook_commands(payload: dict) -> list[str]:
    hooks = payload.get("hooks", {})
    commands: list[str] = []
    for event in cursor_setup.AGENTVEIL_HOOK_EVENTS:
        for item in hooks.get(event, []) or []:
            if isinstance(item, dict):
                commands.append(str(item.get("command") or ""))
    return commands


def test_install_hooks_merge_preserves_unrelated_entries(tmp_path: Path) -> None:
    hooks_path = hooks_config_path(tmp_path)
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text(json.dumps({
        "version": 1,
        "hooks": {
            "afterFileEdit": [{"command": ".cursor/hooks/format.sh"}],
            "preToolUse": [{"command": "echo user-hook"}],
        },
    }), encoding="utf-8")
    install_hooks(tmp_path)
    payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert payload["hooks"]["afterFileEdit"][0]["command"] == ".cursor/hooks/format.sh"
    assert payload["hooks"]["preToolUse"][0]["command"] == "echo user-hook"
    assert any(AGENTVEIL_HOOK_MARKER in cmd for cmd in _managed_hook_commands(payload))


def test_user_agentveil_substring_hook_not_treated_as_managed() -> None:
    assert is_managed_hook_command(USER_AGENTVEIL_HOOK) is False
    assert is_managed_hook_command(
        "python -m agentveil_mcp_proxy.cursor_hooks --workspace ."
    ) is True


def test_install_and_remove_preserve_unrelated_agentveil_substring_hook(tmp_path: Path) -> None:
    hooks_path = hooks_config_path(tmp_path)
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text(json.dumps({
        "version": 1,
        "hooks": {"preToolUse": [{"command": USER_AGENTVEIL_HOOK}]},
    }), encoding="utf-8")

    install_hooks(tmp_path)
    after_install = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert USER_AGENTVEIL_HOOK in json.dumps(after_install["hooks"]["preToolUse"])
    assert any(AGENTVEIL_HOOK_MARKER in cmd for cmd in _managed_hook_commands(after_install))

    removed = remove_hooks(tmp_path)
    assert removed >= 1
    assert hooks_path.is_file(), "hooks.json must survive when unrelated user hooks remain"
    after_remove = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert USER_AGENTVEIL_HOOK in json.dumps(after_remove["hooks"]["preToolUse"])
    assert not any(AGENTVEIL_HOOK_MARKER in cmd for cmd in _managed_hook_commands(after_remove))


def test_install_hooks_idempotent(tmp_path: Path) -> None:
    install_hooks(tmp_path)
    install_hooks(tmp_path)
    payload = json.loads(hooks_config_path(tmp_path).read_text(encoding="utf-8"))
    managed = [cmd for cmd in _managed_hook_commands(payload) if AGENTVEIL_HOOK_MARKER in cmd]
    assert len(managed) == len(cursor_setup.AGENTVEIL_HOOK_EVENTS)


def test_install_mcp_merge_preserves_unrelated_servers(tmp_path: Path) -> None:
    mcp_path = mcp_config_path(tmp_path)
    mcp_path.parent.mkdir(parents=True)
    mcp_path.write_text(json.dumps({
        "mcpServers": {"other-server": {"command": "other"}},
    }), encoding="utf-8")
    proxy = tmp_path / "bin" / "agentveil-mcp-proxy"
    proxy.parent.mkdir(parents=True)
    proxy.write_text("#!/bin/sh\n", encoding="utf-8")
    install_mcp_route(tmp_path, proxy_command=str(proxy))
    payload = json.loads(mcp_path.read_text(encoding="utf-8"))
    assert "other-server" in payload["mcpServers"]
    assert cursor_setup.AGENTVEIL_MCP_SERVER_KEY in payload["mcpServers"]


def test_build_mcp_server_entry_matches_private_route_parity(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    home = setup_home(workspace)
    proxy = tmp_path / "bin" / "agentveil-mcp-proxy"
    proxy.parent.mkdir(parents=True)
    proxy.write_text("#!/bin/sh\n", encoding="utf-8")
    entry = build_mcp_server_entry(
        proxy_command=str(proxy),
        home=home,
        config_path=home / "mcp-proxy" / "config.json",
        passphrase_file=home / "passphrase",
        profile=home / "product-profile",
        workspace=workspace,
    )
    assert entry["type"] == "stdio"
    assert Path(entry["command"]).is_absolute()
    assert set(entry["env"].keys()) == set(MCP_ROUTE_ENV_KEYS)
    assert entry["env"]["AVP_HOME"] == str(home.resolve())
    assert entry["env"]["MCP_CONTENT_ROOT"] == str(workspace.resolve())
    assert entry["env"]["AVP_CURSOR_WORKSPACE"] == str(workspace.resolve())
    assert mcp_route_entry_has_private_parity(entry) is True


def test_neutralize_competing_global_route_preserves_unrelated_servers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    user_mcp = tmp_path / "user-cursor" / "mcp.json"
    user_mcp.parent.mkdir(parents=True)
    user_mcp.write_text(json.dumps({
        "mcpServers": {
            "agentveil-mcp-proxy": {"command": "/old/agentveil-mcp-proxy"},
            "other-server": {"command": "other"},
        }
    }), encoding="utf-8")
    monkeypatch.setattr(
        cursor_setup,
        "resolve_cursor_global_mcp_json_path",
        lambda: user_mcp,
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    result = neutralize_competing_global_route(workspace)
    assert result.changed is True
    assert result.removed_server_keys == ("agentveil-mcp-proxy",)
    payload = json.loads(user_mcp.read_text(encoding="utf-8"))
    assert "agentveil-mcp-proxy" not in payload["mcpServers"]
    assert payload["mcpServers"]["other-server"]["command"] == "other"
    backup_dir = setup_home(workspace) / "cursor-setup" / "user-mcp-backups"
    assert any(backup_dir.glob("user-mcp.json.*.backup"))


def test_install_mcp_route_writes_private_parity_entry(tmp_path: Path) -> None:
    proxy = tmp_path / "bin" / "agentveil-mcp-proxy"
    proxy.parent.mkdir(parents=True)
    proxy.write_text("#!/bin/sh\n", encoding="utf-8")
    install_mcp_route(tmp_path, proxy_command=str(proxy))
    entry = load_project_mcp_server_entry(tmp_path)
    assert entry is not None
    assert mcp_route_entry_has_private_parity(entry) is True


def test_install_fails_closed_on_invalid_hooks_json(tmp_path: Path) -> None:
    hooks_path = hooks_config_path(tmp_path)
    hooks_path.parent.mkdir(parents=True)
    garbage = "{ not json"
    hooks_path.write_text(garbage, encoding="utf-8")
    with pytest.raises(CursorSetupError):
        install_hooks(tmp_path)
    assert hooks_path.read_text(encoding="utf-8") == garbage


def test_remove_only_managed_entries(tmp_path: Path) -> None:
    install_hooks(tmp_path)
    mcp_path = mcp_config_path(tmp_path)
    mcp_path.write_text(json.dumps({
        "mcpServers": {"other-server": {"command": "other"}},
    }), encoding="utf-8")
    install_mcp_route(tmp_path, proxy_command="agentveil-mcp-proxy")
    hooks_path = hooks_config_path(tmp_path)
    payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    payload["hooks"]["afterFileEdit"] = [{"command": "echo keep"}]
    hooks_path.write_text(json.dumps(payload), encoding="utf-8")

    assert remove_hooks(tmp_path) >= 1
    assert remove_mcp_route(tmp_path) is True

    remaining = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert remaining["hooks"]["afterFileEdit"][0]["command"] == "echo keep"
    assert not any(AGENTVEIL_HOOK_MARKER in cmd for cmd in _managed_hook_commands(remaining))
    mcp_payload = json.loads(mcp_path.read_text(encoding="utf-8"))
    assert cursor_setup.AGENTVEIL_MCP_SERVER_KEY not in mcp_payload.get("mcpServers", {})
    assert "other-server" in mcp_payload.get("mcpServers", {})


def test_connector_status_bounded_no_absolute_paths(tmp_path: Path) -> None:
    install_hooks(tmp_path)
    install_mcp_route(tmp_path, proxy_command="agentveil-mcp-proxy")
    status = connector_status(tmp_path)
    text = json.dumps(status)
    assert str(tmp_path) not in text
    assert "/Users/" not in text
    assert "/private/" not in text
    assert set(status.keys()) >= {
        "status", "hook", "mcp_route", "proxy_route", "approval_center", "next_step",
    }


def _prepare_status_ready_workspace(tmp_path: Path, monkeypatch) -> Path:
    home = setup_home(tmp_path)
    (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
    install_hooks(tmp_path)
    install_mcp_route(tmp_path, proxy_command=str(tmp_path / "agentveil-mcp-proxy"))
    monkeypatch.setattr(
        cursor_setup,
        "check_approval_center_status",
        lambda _home: cursor_setup.CenterStatus(state="running", pid=123, port=5678),
    )
    monkeypatch.setattr(cursor_setup, "detect_competing_global_route", lambda: False)
    return cursor_setup.project_evidence_path(tmp_path)


def test_connector_status_native_hook_observed_is_not_protected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence = _prepare_status_ready_workspace(tmp_path, monkeypatch)
    time.sleep(0.01)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(
        json.dumps({
            "hook_event": "preToolUse",
            "tool_name": "Write",
            "decision": "deny",
            "reason_code": "risky_blocked",
        }) + "\n",
        encoding="utf-8",
    )

    status = connector_status(tmp_path)

    assert status["status"] == "advisory"
    assert status["hook_observed"] is True
    assert status["mcp_route_observed"] is False
    assert status["next_step"] == SETUP_ADVISORY_NEXT_STEP


def test_connector_status_mcp_route_observed_is_protected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence = _prepare_status_ready_workspace(tmp_path, monkeypatch)
    time.sleep(0.01)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(
        json.dumps({
            "hook_event": "preToolUse",
            "tool_name": "MCP:write_file",
            "server": "agentveil-mcp-proxy",
            "decision": "allow",
            "reason_code": "controlled_route_passthrough",
        }) + "\n",
        encoding="utf-8",
    )

    status = connector_status(tmp_path)

    assert status["status"] == "protected"
    assert status["hook_observed"] is True
    assert status["mcp_route_observed"] is True
    assert status["restart_required"] is False


def test_stop_does_not_kill_unhealthy_manifest(tmp_path: Path, monkeypatch) -> None:
    from agentveil_mcp_proxy.approval.persistent import (
        ApprovalCenterManifest,
        save_manifest,
        token_hash_for,
    )

    home = cursor_setup.setup_home(tmp_path)
    proxy_dir = home / "mcp-proxy"
    token = "session-token"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=43210,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="internal",
            pid=12345,
            started_at=1,
        ),
    )
    monkeypatch.setattr(cursor_setup, "is_process_alive", lambda _pid: True)
    monkeypatch.setattr(cursor_setup, "_center_health", lambda _manifest: False)

    def fail_kill(_pid, _signal):
        raise AssertionError("must not kill an unhealthy/non-AgentVeil manifest pid")

    monkeypatch.setattr("agentveil_mcp_proxy.cursor_setup.os.kill", fail_kill)
    result = cursor_setup.stop_managed_approval_center(home)
    assert result["stopped"] is False
    assert "not a healthy AgentVeil Approval Center" in result["reason"]


def test_ensure_approval_center_spawn_failure_returns_without_long_wait(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = cursor_setup.setup_home(tmp_path)
    (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    def fail_spawn(**_kwargs):
        raise OSError("spawn unavailable in unit test")

    monkeypatch.setattr(cursor_setup, "_spawn_approval_center", fail_spawn)
    monkeypatch.setattr(cursor_setup, "check_approval_center_status", lambda _home: cursor_setup.CenterStatus(
        state="down", pid=None, port=None,
    ))

    result = cursor_setup.ensure_approval_center_running(
        home=home,
        proxy_command="agentveil-mcp-proxy",
    )
    assert result.started is False
    assert result.status.state == "down"
    assert "spawn" in result.reason


def test_cli_setup_cursor_interactive_cancel_exits_without_writes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        proxy_cli,
        "_prompt_cursor_setup_workspace",
        lambda *, cwd, input_fn: None,
    )

    assert main(["setup", "cursor"]) == 0
    captured = capsys.readouterr()
    assert "cancelled" in captured.out.lower()
    assert not (tmp_path / ".cursor" / "hooks.json").exists()
    assert not (tmp_path / ".cursor" / "mcp.json").exists()


def _mock_successful_setup(monkeypatch, tmp_path):
    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    def fake_prepare(_workspace, *, force=False):
        home = cursor_setup.setup_home(_workspace)
        home.mkdir(parents=True, exist_ok=True)
        (home / "passphrase").write_text("secret\n", encoding="utf-8")
        return home

    def fake_ensure_running(**_kwargs):
        return SimpleNamespace(
            status=SimpleNamespace(state="running"),
            started=True,
            reused=False,
            restarted=False,
            reason="center started",
        )

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(cursor_setup, "prepare_proxy_home", fake_prepare)
    monkeypatch.setattr(proxy_cli, "initialize_product_route_profile", lambda _prof: None)
    monkeypatch.setattr(cursor_setup, "ensure_approval_center_running", fake_ensure_running)
    monkeypatch.setattr(
        cursor_setup,
        "neutralize_competing_global_route",
        lambda _w: cursor_setup.NeutralizeGlobalRouteResult(changed=False),
    )
    monkeypatch.setattr("shutil.which", lambda _name: str(tmp_path / "agentveil-mcp-proxy"))


def test_cli_setup_cursor_interactive_current_folder(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _mock_successful_setup(monkeypatch, tmp_path)
    (tmp_path / "agentveil-mcp-proxy").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        proxy_cli,
        "_prompt_cursor_setup_workspace",
        lambda *, cwd, input_fn: cwd,
    )

    assert main(["setup", "cursor"]) == 0
    assert (tmp_path / ".cursor" / "hooks.json").is_file()
    out = capsys.readouterr().out
    assert "AgentVeil is installed for:" in out


def test_cli_setup_cursor_interactive_choose_other_folder(tmp_path, monkeypatch, capsys):
    project = tmp_path / "my-project"
    project.mkdir()
    monkeypatch.chdir(tmp_path)
    _mock_successful_setup(monkeypatch, tmp_path)
    (tmp_path / "agentveil-mcp-proxy").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(
        proxy_cli,
        "_prompt_cursor_setup_workspace",
        lambda *, cwd, input_fn: project,
    )

    assert main(["setup", "cursor"]) == 0
    assert (project / ".cursor" / "hooks.json").is_file()
    out = capsys.readouterr().out
    assert "AgentVeil is installed for:" in out
    assert "Tools & MCPs" in out


def test_prompt_cursor_setup_workspace_uses_native_picker_on_macos(tmp_path, monkeypatch):
    project = tmp_path / "chosen-project"
    project.mkdir()
    monkeypatch.setattr(proxy_cli.sys, "platform", "darwin")
    monkeypatch.setattr(
        proxy_cli,
        "_choose_folder_with_system_picker",
        lambda *, cwd: project,
    )

    result = proxy_cli._prompt_cursor_setup_workspace(
        cwd=tmp_path,
        input_fn=lambda _prompt: "2",
    )

    assert result == project


def test_prompt_cursor_setup_workspace_uses_native_picker_on_windows(tmp_path, monkeypatch):
    project = tmp_path / "chosen-project"
    project.mkdir()
    monkeypatch.setattr(proxy_cli.sys, "platform", "win32")
    monkeypatch.setattr(
        proxy_cli,
        "_choose_folder_with_system_picker",
        lambda *, cwd: project,
    )

    result = proxy_cli._prompt_cursor_setup_workspace(
        cwd=tmp_path,
        input_fn=lambda _prompt: "2",
    )

    assert result == project


def test_prompt_cursor_setup_workspace_non_native_path_fallback(tmp_path, monkeypatch):
    project = tmp_path / "typed-project"
    project.mkdir()
    answers = iter(["2", str(project)])
    monkeypatch.setattr(proxy_cli.sys, "platform", "linux")
    monkeypatch.setattr(
        proxy_cli,
        "_choose_folder_with_system_picker",
        lambda *, cwd: None,
    )

    result = proxy_cli._prompt_cursor_setup_workspace(
        cwd=tmp_path,
        input_fn=lambda _prompt: next(answers),
    )

    assert result == project


def test_cli_setup_cursor_choose_folder_opens_cursor(tmp_path, monkeypatch, capsys):
    project = tmp_path / "my-project"
    project.mkdir()
    monkeypatch.chdir(tmp_path)
    _mock_successful_setup(monkeypatch, tmp_path)
    opened: list[Path] = []
    monkeypatch.setattr(
        proxy_cli,
        "_prompt_cursor_setup_workspace",
        lambda *, cwd, input_fn: project,
    )
    monkeypatch.setattr(
        proxy_cli,
        "_open_cursor_workspace",
        lambda workspace: (opened.append(workspace), (True, "Cursor is opening this project folder."))[1],
    )

    assert main(["setup", "cursor", "--choose-folder"]) == 0

    assert opened == [project.resolve()]
    out = capsys.readouterr().out
    assert "Cursor is opening this project folder." in out


def test_cursor_open_command_prefers_cursor_cli_on_macos(tmp_path, monkeypatch):
    cursor_cli = "/Applications/Cursor.app/Contents/Resources/app/bin/cursor"
    monkeypatch.setattr(proxy_cli.sys, "platform", "darwin")
    monkeypatch.setattr(Path, "is_file", lambda self: self.as_posix() == cursor_cli)

    command = proxy_cli._cursor_open_command(tmp_path)

    assert command is not None
    assert Path(command[0]).as_posix() == cursor_cli
    assert command[1] == str(tmp_path)


def test_cli_setup_cursor_no_open_suppresses_cursor_open(tmp_path, monkeypatch, capsys):
    project = tmp_path / "my-project"
    project.mkdir()
    monkeypatch.chdir(tmp_path)
    _mock_successful_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        proxy_cli,
        "_prompt_cursor_setup_workspace",
        lambda *, cwd, input_fn: project,
    )

    def fail_open(_workspace):
        raise AssertionError("Cursor must not open with --no-open")

    monkeypatch.setattr(proxy_cli, "_open_cursor_workspace", fail_open)

    assert main(["setup", "cursor", "--choose-folder", "--no-open"]) == 0
    assert "Cursor is opening" not in capsys.readouterr().out


def test_cli_setup_cursor_yes_does_not_open_cursor(tmp_path, monkeypatch, capsys):
    _mock_successful_setup(monkeypatch, tmp_path)

    def fail_open(_workspace):
        raise AssertionError("Cursor must not open in --yes mode")

    monkeypatch.setattr(proxy_cli, "_open_cursor_workspace", fail_open)

    assert main(["setup", "cursor", "--workspace", str(tmp_path), "--yes"]) == 0
    assert "Cursor is opening" not in capsys.readouterr().out


def test_home_folder_guard_blocks_home(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(home)

    assert main(["setup", "cursor", "--yes"]) == 1
    assert BROAD_FOLDER_MESSAGE.splitlines()[0] in capsys.readouterr().err
    assert not (home / ".cursor").exists()


def test_broad_folder_guard_blocks_desktop_and_downloads(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    desktop = home / "Desktop"
    downloads = home / "Downloads"
    desktop.mkdir(parents=True)
    downloads.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))

    monkeypatch.chdir(desktop)
    assert main(["setup", "cursor", "--yes"]) == 1
    capsys.readouterr()

    monkeypatch.chdir(downloads)
    assert main(["setup", "cursor", "--yes"]) == 1
    assert not (desktop / ".cursor").exists()
    assert not (downloads / ".cursor").exists()


def test_yes_mode_works_for_explicit_project_workspace(tmp_path, monkeypatch, capsys):
    _mock_successful_setup(monkeypatch, tmp_path)
    (tmp_path / "agentveil-mcp-proxy").write_text("#!/bin/sh\n", encoding="utf-8")

    assert main(["setup", "cursor", "--workspace", str(tmp_path), "--yes"]) == 0
    out = capsys.readouterr().out
    assert "AgentVeil is installed for:" in out
    assert (tmp_path / ".cursor" / "hooks.json").is_file()


def test_setup_success_output_includes_next_steps(tmp_path):
    status = {"status": "advisory", "mcp_route_observed": False}
    message = format_setup_success_message(tmp_path, status=status)
    assert "Reopen Cursor in this folder." in message
    assert "Tools & MCPs" in message
    assert "avp-test.txt" in message
    assert "fully protected" not in message.lower()


def test_is_broad_workspace_detects_worktrees_container(tmp_path):
    worktrees = tmp_path / ".worktrees"
    worktrees.mkdir()
    assert is_broad_workspace(worktrees) is True
    project = worktrees / "my-repo"
    project.mkdir()
    (project / ".git").mkdir()
    assert is_broad_workspace(project) is False


def test_connector_status_advisory_before_live_mcp_proof(tmp_path, monkeypatch):
    evidence = _prepare_status_ready_workspace(tmp_path, monkeypatch)
    status = connector_status(tmp_path)
    assert status["status"] == "advisory"
    assert status["mcp_route_observed"] is False
    assert status["next_step"] == SETUP_ADVISORY_NEXT_STEP

    time.sleep(0.01)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(
        json.dumps({
            "hook_event": "preToolUse",
            "tool_name": "Write",
            "decision": "deny",
        }) + "\n",
        encoding="utf-8",
    )
    stale_native = connector_status(tmp_path)
    assert stale_native["status"] == "advisory"
    assert stale_native["mcp_route_observed"] is False


def test_cli_setup_cursor_json_requires_yes(tmp_path, capsys):
    assert main(["setup", "cursor", "--workspace", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["applied"] is False
    assert not (tmp_path / ".cursor" / "hooks.json").exists()


def test_cli_setup_remove_cursor_apply(tmp_path, capsys):
    cursor_setup.install_hooks(tmp_path)
    cursor_setup.install_mcp_route(tmp_path, proxy_command="agentveil-mcp-proxy")
    (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "agentveil-mcp-proxy": {"command": "agentveil-mcp-proxy", "args": ["run"]},
            "other-server": {"command": "other"},
        }
    }), encoding="utf-8")

    assert main(["setup", "remove", "cursor", "--workspace", str(tmp_path), "--yes", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["hook_entries_removed"] >= 1
    assert payload["mcp_route_removed"] is True

    hooks = json.loads((tmp_path / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
    assert not any(
        AGENTVEIL_HOOK_MARKER in json.dumps(item)
        for items in hooks.get("hooks", {}).values()
        for item in (items if isinstance(items, list) else [])
    )
    mcp = json.loads((tmp_path / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
    assert "agentveil-mcp-proxy" not in mcp.get("mcpServers", {})
    assert "other-server" in mcp.get("mcpServers", {})


def test_cli_setup_status_bounded_no_paths(tmp_path, capsys):
    cursor_setup.install_hooks(tmp_path)
    assert main(["setup", "status", "--workspace", str(tmp_path), "--json"]) == 0
    text = capsys.readouterr().out
    assert str(tmp_path) not in text
    assert "/Users/" not in text and "/private/" not in text


def test_cli_setup_cursor_fails_when_center_not_running(tmp_path, monkeypatch, capsys):
    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    def fake_prepare(_workspace, *, force=False):
        home = cursor_setup.setup_home(_workspace)
        home.mkdir(parents=True, exist_ok=True)
        (home / "passphrase").write_text("secret\n", encoding="utf-8")
        return home

    def fake_ensure_running(**_kwargs):
        return SimpleNamespace(
            status=SimpleNamespace(state="stale"),
            started=False,
            reused=False,
            restarted=False,
            reason="approval-center did not become healthy",
        )

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(cursor_setup, "prepare_proxy_home", fake_prepare)
    monkeypatch.setattr(proxy_cli, "initialize_product_route_profile", lambda _prof: None)
    monkeypatch.setattr(cursor_setup, "ensure_approval_center_running", fake_ensure_running)
    monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")

    rc = main(["setup", "cursor", "--workspace", str(tmp_path), "--yes", "--json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["approval_center"]["state"] == "stale"
    assert "not ready/protected" in payload["errors"][0]


def test_cli_setup_cursor_json_does_not_leak_approval_url(tmp_path, monkeypatch, capsys):
    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    def fake_prepare(_workspace, *, force=False):
        home = cursor_setup.setup_home(_workspace)
        home.mkdir(parents=True, exist_ok=True)
        (home / "passphrase").write_text("secret\n", encoding="utf-8")
        return home

    def fake_ensure_running(**_kwargs):
        return SimpleNamespace(
            status=SimpleNamespace(state="running", url="http://127.0.0.1:1/approval/SECRET"),
            started=True,
            reused=False,
            restarted=False,
            reason="center started",
        )

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(cursor_setup, "prepare_proxy_home", fake_prepare)
    monkeypatch.setattr(proxy_cli, "initialize_product_route_profile", lambda _prof: None)
    monkeypatch.setattr(cursor_setup, "ensure_approval_center_running", fake_ensure_running)
    monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")

    rc = main(["setup", "cursor", "--workspace", str(tmp_path), "--yes", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["approval_center"]["state"] == "running"
    assert "url" not in payload["approval_center"]
    assert "SECRET" not in json.dumps(payload)


def test_setup_proxy_command_falls_back_to_invoked_console_script(tmp_path, monkeypatch):
    script = tmp_path / "agentveil-mcp-proxy"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.setattr(sys, "argv", [str(script), "setup", "cursor"])

    assert proxy_cli._resolve_setup_proxy_command() == str(script.resolve())


def test_install_mcp_route_writes_managed_user_settings_entry(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.cursor_user_mcp import (
        USER_MCP_MARKER_ENV,
        USER_MCP_MARKER_VALUE,
        USER_MCP_MODULE,
        USER_MCP_PROXY_COMMAND_ENV,
        cursor_settings_path,
        user_mcp_route_is_managed,
    )

    proxy = tmp_path / "bin" / "agentveil-mcp-proxy"
    proxy.parent.mkdir(parents=True)
    proxy.write_text("#!/bin/sh\n", encoding="utf-8")
    install_mcp_route(tmp_path, proxy_command=str(proxy))

    settings = json.loads(cursor_settings_path().read_text(encoding="utf-8"))
    entry = settings["mcp"]["servers"]["agentveil-mcp-proxy"]
    assert entry["args"] == ["-m", USER_MCP_MODULE]
    assert entry["env"][USER_MCP_MARKER_ENV] == USER_MCP_MARKER_VALUE
    assert entry["env"][USER_MCP_PROXY_COMMAND_ENV] == str(proxy.resolve())
    assert entry["env"]["AVP_CURSOR_WORKSPACE"] == str(tmp_path.resolve())
    assert user_mcp_route_is_managed() is True


def test_user_mcp_wrapper_prefers_pinned_proxy_over_path(tmp_path: Path, monkeypatch) -> None:
    from agentveil_mcp_proxy import cursor_user_mcp
    from agentveil_mcp_proxy.cursor_user_mcp import USER_MCP_PROXY_COMMAND_ENV

    pinned = tmp_path / "venv" / "bin" / "agentveil-mcp-proxy"
    pinned.parent.mkdir(parents=True)
    pinned.write_text("#!/bin/sh\n", encoding="utf-8")
    old_global = tmp_path / "old" / "agentveil-mcp-proxy"
    old_global.parent.mkdir(parents=True)
    old_global.write_text("#!/bin/sh\n", encoding="utf-8")
    home = setup_home(tmp_path)
    (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv(USER_MCP_PROXY_COMMAND_ENV, str(pinned))
    monkeypatch.setattr(cursor_user_mcp.shutil, "which", lambda _name: str(old_global))

    executable, argv, _env = cursor_user_mcp.build_proxy_exec_argv(tmp_path)

    assert executable == str(pinned.resolve())
    assert argv[0] == str(pinned.resolve())


def test_remove_mcp_route_removes_only_managed_user_entry(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.cursor_user_mcp import (
        USER_MCP_MODULE,
        cursor_settings_path,
        is_managed_user_mcp_entry,
    )

    proxy = tmp_path / "bin" / "agentveil-mcp-proxy"
    proxy.parent.mkdir(parents=True)
    proxy.write_text("#!/bin/sh\n", encoding="utf-8")
    settings_path = cursor_settings_path()
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps({
        "mcp": {
            "servers": {
                "agentveil-mcp-proxy": {
                    "command": "echo",
                    "args": ["legacy-user-mcp"],
                },
                "other-server": {"command": "other", "args": ["stay"]},
            }
        }
    }), encoding="utf-8")

    install_mcp_route(tmp_path, proxy_command=str(proxy))
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    managed = settings["mcp"]["servers"]["agentveil-mcp-proxy"]
    assert managed["args"] == ["-m", USER_MCP_MODULE]
    assert is_managed_user_mcp_entry(managed) is True

    assert remove_mcp_route(tmp_path) is True
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    assert "agentveil-mcp-proxy" not in settings["mcp"]["servers"]
    assert settings["mcp"]["servers"]["other-server"]["args"] == ["stay"]


def test_user_mcp_wrapper_fails_closed_without_prepared_workspace(tmp_path: Path) -> None:
    from agentveil_mcp_proxy import cursor_user_mcp

    assert cursor_user_mcp.find_prepared_workspace(tmp_path / "empty") is None
    assert cursor_user_mcp.main([]) == 1


def test_user_mcp_wrapper_resolves_prepared_workspace(tmp_path: Path, monkeypatch) -> None:
    from agentveil_mcp_proxy import cursor_user_mcp

    home = setup_home(tmp_path)
    (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
    (home / "passphrase").write_text("secret\n", encoding="utf-8")
    mcp_path = mcp_config_path(tmp_path)
    mcp_path.parent.mkdir(parents=True, exist_ok=True)
    mcp_path.write_text(json.dumps({
        "mcpServers": {"agentveil-mcp-proxy": {"command": "x", "args": ["run"]}},
    }), encoding="utf-8")

    assert cursor_user_mcp.find_prepared_workspace(tmp_path / "nested") == tmp_path.resolve()

    captured: dict[str, object] = {}

    def fake_execvpe(executable, argv, env):
        captured["executable"] = executable
        captured["argv"] = argv
        captured["env"] = env
        raise SystemExit(0)

    monkeypatch.setattr("agentveil_mcp_proxy.cursor_user_mcp.os.execvpe", fake_execvpe)
    monkeypatch.setattr(cursor_user_mcp.shutil, "which", lambda _name: "/usr/bin/agentveil-mcp-proxy")
    monkeypatch.setattr(cursor_user_mcp, "find_prepared_workspace", lambda start=None: tmp_path.resolve())

    with pytest.raises(SystemExit) as exc:
        cursor_user_mcp.main([])
    assert exc.value.code == 0
    assert captured["env"]["AVP_CURSOR_WORKSPACE"] == str(tmp_path.resolve())
    assert captured["env"]["MCP_CONTENT_ROOT"] == str(tmp_path.resolve())
