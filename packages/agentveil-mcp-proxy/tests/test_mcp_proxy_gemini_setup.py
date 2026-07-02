"""Tests for the public Gemini CLI one-command connector setup."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

from agentveil_mcp_proxy import cli as proxy_cli
from agentveil_mcp_proxy.cli import main
from agentveil_mcp_proxy.client_config import DEFAULT_SERVER_NAME


def _make_proxy_command(tmp_path: Path) -> str:
    command = tmp_path / "bin" / "agentveil-mcp-proxy"
    command.parent.mkdir(parents=True)
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    return str(command)


def _gemini_settings(project: Path) -> Path:
    return project / ".gemini" / "settings.json"


def _install_fast_gemini_setup_fakes(monkeypatch, *, proxy_command: str) -> None:
    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(proxy_cli, "_resolve_setup_proxy_command", lambda: proxy_command)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
        lambda **_kwargs: SimpleNamespace(
            status=SimpleNamespace(state="running", url="http://127.0.0.1/approval/SECRET"),
            started=True,
            reused=False,
            restarted=False,
            reason="center started",
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.inspect_managed_approval_center",
        lambda _home: SimpleNamespace(state="running", url="http://127.0.0.1/approval/SECRET"),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.stop_managed_approval_center",
        lambda _home, **_kwargs: {"stopped": True, "reason": "stopped"},
    )


def test_setup_gemini_cli_writes_merge_safe_settings_and_is_idempotent(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    settings = _gemini_settings(project)
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps({
            "model": "gemini-pro",
            "mcpServers": {
                "other": {"command": "other", "args": ["run"]},
            },
            "hooks": {
                "AfterTool": [{"matcher": "read_file", "hooks": [{"type": "command", "command": "echo after"}]}],
            },
        }, indent=2)
        + "\n",
        encoding="utf-8",
    )

    for _ in range(2):
        assert main(["setup", "gemini-cli", "--project-dir", str(project), "--yes", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is True
        assert payload["action"] == "setup-gemini-cli"
        assert payload["approval_center"]["state"] == "running"
        assert "url" not in payload["approval_center"]
        assert str(project) not in json.dumps(payload)
        assert str(isolated_home) not in json.dumps(payload)

    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["model"] == "gemini-pro"
    assert "other" in data["mcpServers"]
    assert list(data["mcpServers"].keys()).count(DEFAULT_SERVER_NAME) == 1
    assert data["mcpServers"][DEFAULT_SERVER_NAME]["trust"] is True
    before = data["hooks"]["BeforeTool"]
    assert len(before) == 1
    assert before[0]["matcher"] == (
        "write_file|replace|run_shell_command|read_file|read_many_files|"
        "list_directory|glob|grep_search|mcp_.*"
    )
    command = before[0]["hooks"][0]["command"]
    assert "-m agentveil_mcp_proxy.gemini_hook" in command
    assert "--evidence-path" in command
    assert data["hooks"]["AfterTool"][0]["hooks"][0]["command"] == "echo after"


def test_setup_gemini_cli_status_is_bounded_and_advisory_without_runtime_proof(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    assert main(["setup", "gemini-cli", "--project-dir", str(project), "--yes", "--json"]) == 0
    capsys.readouterr()

    assert main(["setup", "status", "--client", "gemini-cli", "--project-dir", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["connector"] == "gemini-cli"
    assert payload["mcp_route"] == "present"
    assert payload["hook"] == "present"
    assert payload["hook_state"] == "advisory"
    assert payload["hook_evidence_observed"] is False
    assert payload["proxy_route"] == "present"
    assert payload["approval_center"] == "running"
    assert payload["status"] == "advisory"
    assert payload["hook_trust_required"] is True
    assert "trust" in payload["next_step"].lower()
    assert "trust" in payload["hook_trust_message"].lower()
    assert str(project) not in json.dumps(payload)
    assert str(isolated_home) not in json.dumps(payload)


def test_setup_gemini_cli_status_becomes_protected_only_after_hook_evidence(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    assert main(["setup", "gemini-cli", "--project-dir", str(project), "--yes", "--json"]) == 0
    capsys.readouterr()

    evidence = project / ".gemini" / "agentveil" / "evidence.jsonl"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"hook_action":"deny"}\n', encoding="utf-8")
    settings_mtime = _gemini_settings(project).stat().st_mtime
    os.utime(evidence, (settings_mtime + 10, settings_mtime + 10))

    assert main(["setup", "status", "--client", "gemini-cli", "--project-dir", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == "protected"
    assert payload["hook_state"] == "protected"
    assert payload["hook_evidence_observed"] is True
    assert payload["hook_trust_required"] is False
    assert payload["restart_required"] is False


def test_setup_gemini_cli_human_output_mentions_folder_trust(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    assert main(["setup", "gemini-cli", "--project-dir", str(project), "--yes"]) == 0
    output = capsys.readouterr().out

    assert "folder trust:" in output
    assert "status remains advisory, not protected" in output
    assert str(project) not in output
    assert str(isolated_home) not in output


def test_setup_remove_gemini_cli_preserves_unrelated_config(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    assert main(["setup", "gemini-cli", "--project-dir", str(project), "--yes", "--json"]) == 0
    capsys.readouterr()
    settings_path = _gemini_settings(project)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["hooks"]["BeforeTool"][0]["hooks"].append({
        "type": "command",
        "command": "echo user-hook",
    })
    settings["hooks"]["BeforeTool"].append({
        "matcher": "write_file",
        "hooks": [
            {
                "type": "command",
                "command": "echo mentions agentveil_mcp_proxy.gemini_hook but is user-owned",
            }
        ],
    })
    settings["skills"] = ["custom-skill"]
    settings_path.write_text(json.dumps(settings), encoding="utf-8")

    assert main(["setup", "remove", "gemini-cli", "--project-dir", str(project), "--yes", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is True
    assert payload["hook_entries_removed"] == 1
    assert payload["mcp_route_removed"] is True
    assert payload["approval_center_stopped"] is True
    after = json.loads(settings_path.read_text(encoding="utf-8"))
    assert DEFAULT_SERVER_NAME not in after.get("mcpServers", {})
    assert after["skills"] == ["custom-skill"]
    assert after["hooks"]["BeforeTool"][0]["hooks"] == [{
        "type": "command",
        "command": "echo user-hook",
    }]
    assert after["hooks"]["BeforeTool"][1]["hooks"] == [{
        "type": "command",
        "command": "echo mentions agentveil_mcp_proxy.gemini_hook but is user-owned",
    }]


def test_setup_gemini_cli_preview_does_not_write(tmp_path, monkeypatch, capsys):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    project = tmp_path / "project"
    project.mkdir()

    assert main(["setup", "gemini-cli", "--project-dir", str(project)]) == 0
    capsys.readouterr()

    assert not (project / ".avp").exists()
    assert not _gemini_settings(project).exists()


def test_setup_gemini_cli_choose_folder_uses_selected_project(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)

    selected_project = tmp_path / "selected project"
    selected_project.mkdir()
    monkeypatch.setattr(proxy_cli, "_choose_setup_project_folder", lambda: selected_project)

    assert main(["setup", "gemini-cli", "--choose-folder", "--yes", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is True
    assert payload["action"] == "setup-gemini-cli"
    assert payload["approval_center"]["state"] == "running"
    assert str(selected_project) not in json.dumps(payload)
    assert str(isolated_home) not in json.dumps(payload)
    assert (selected_project / ".avp" / "mcp-proxy" / "config.json").exists()
    assert _gemini_settings(selected_project).exists()


def test_setup_gemini_cli_fails_closed_on_invalid_settings_json(tmp_path, monkeypatch):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    settings_path = _gemini_settings(project)
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text("{not-json", encoding="utf-8")

    assert main(["setup", "gemini-cli", "--project-dir", str(project), "--yes"]) == 2
    assert settings_path.read_text(encoding="utf-8") == "{not-json"
    assert not (project / ".avp").exists()


def test_command_ownership_requires_exact_module_invocation():
    from agentveil_mcp_proxy import gemini_setup

    assert gemini_setup.command_invokes_managed_hook(
        "/usr/bin/python3 -m agentveil_mcp_proxy.gemini_hook --evidence-path /tmp/e.jsonl"
    )
    assert not gemini_setup.command_invokes_managed_hook(
        "echo mentions agentveil_mcp_proxy.gemini_hook but is user-owned"
    )
    assert not gemini_setup.command_invokes_managed_hook(
        "/usr/bin/python3 -m other.module agentveil_mcp_proxy.gemini_hook"
    )
