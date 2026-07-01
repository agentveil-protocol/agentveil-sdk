"""Tests for the public Codex one-command connector setup."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

from agentveil_mcp_proxy import cli as proxy_cli
from agentveil_mcp_proxy.cli import main
from agentveil_mcp_proxy.client_config import DEFAULT_SERVER_NAME, parse_codex_mcp_server_entry


def _make_proxy_command(tmp_path: Path) -> str:
    command = tmp_path / "bin" / "agentveil-mcp-proxy"
    command.parent.mkdir(parents=True)
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(0o755)
    return str(command)


def _codex_config(home: Path) -> Path:
    return home / ".codex" / "config.toml"


def _codex_hooks(project: Path) -> Path:
    return project / ".codex" / "hooks.json"


def _isolate_cli_home(monkeypatch, home: Path) -> None:
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def _install_fast_codex_setup_fakes(monkeypatch, *, proxy_command: str) -> None:
    from agentveil_mcp_proxy import claude_center_lifecycle

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(proxy_cli, "_resolve_setup_proxy_command", lambda: proxy_command)
    monkeypatch.setattr(
        claude_center_lifecycle,
        "ensure_running",
        lambda **_kwargs: SimpleNamespace(
            status=SimpleNamespace(state="running", url="http://127.0.0.1/approval/SECRET"),
            started=True,
            reused=False,
            restarted=False,
            reason="center started",
        ),
    )
    monkeypatch.setattr(
        claude_center_lifecycle,
        "check_status",
        lambda _home: SimpleNamespace(state="running", url="http://127.0.0.1/approval/SECRET"),
    )
    monkeypatch.setattr(
        claude_center_lifecycle,
        "stop_if_managed",
        lambda _home: {"stopped": True, "reason": "stopped"},
    )


def test_setup_codex_writes_merge_safe_toml_and_is_idempotent(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    codex_config = _codex_config(isolated_home)
    codex_config.parent.mkdir(parents=True)
    codex_config.write_text(
        '\n'.join([
            'model = "gpt-5"',
            "",
            "[mcp_servers.other]",
            'command = "other"',
            'args = ["run"]',
            "",
        ]),
        encoding="utf-8",
    )

    for _ in range(2):
        assert main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is True
        assert payload["action"] == "setup-codex"
        assert payload["approval_center"]["state"] == "running"
        assert "url" not in payload["approval_center"]
        assert str(project) not in json.dumps(payload)
        assert str(isolated_home) not in json.dumps(payload)

    text = codex_config.read_text(encoding="utf-8")
    assert 'model = "gpt-5"' in text
    assert "[mcp_servers.other]" in text
    assert text.count(f"[mcp_servers.{DEFAULT_SERVER_NAME}]") == 1
    assert 'default_tools_approval_mode = "approve"' in text
    assert "AVP_HOME" in text
    hooks = json.loads(_codex_hooks(project).read_text(encoding="utf-8"))
    pre = hooks["hooks"]["PreToolUse"]
    assert len(pre) == 1
    assert pre[0]["matcher"] == "Bash|apply_patch|Edit|Write|mcp__.*"
    command = pre[0]["hooks"][0]["command"]
    assert "-m agentveil_mcp_proxy.codex_hook" in command
    assert "--evidence-path" in command


def test_setup_codex_status_is_bounded_and_advisory_without_runtime_proof(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    assert main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"]) == 0
    capsys.readouterr()

    assert main(["setup", "status", "--client", "codex", "--project-dir", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["connector"] == "codex"
    assert payload["mcp_route"] == "present"
    assert payload["hook"] == "present"
    assert payload["hook_state"] == "advisory"
    assert payload["hook_evidence_observed"] is False
    assert payload["proxy_route"] == "present"
    assert payload["approval_center"] == "running"
    assert payload["status"] == "advisory"
    assert payload["hook_trust_required"] is True
    assert "trust the AgentVeil hook" in payload["next_step"]
    assert "trust" in payload["hook_trust_message"].lower()
    assert str(project) not in json.dumps(payload)
    assert str(isolated_home) not in json.dumps(payload)


def test_setup_codex_status_becomes_protected_only_after_hook_evidence(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    assert main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"]) == 0
    capsys.readouterr()

    evidence = project / ".codex" / "agentveil" / "evidence.jsonl"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"hook_action":"deny"}\n', encoding="utf-8")
    hooks_mtime = _codex_hooks(project).stat().st_mtime
    os.utime(evidence, (hooks_mtime + 10, hooks_mtime + 10))

    assert main(["setup", "status", "--client", "codex", "--project-dir", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == "protected"
    assert payload["hook_state"] == "protected"
    assert payload["hook_evidence_observed"] is True
    assert payload["hook_trust_required"] is False
    assert payload["restart_required"] is False


def test_setup_codex_human_output_mentions_one_time_hook_trust(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    assert main(["setup", "codex", "--project-dir", str(project), "--yes"]) == 0
    output = capsys.readouterr().out

    assert "hook trust:" in output
    assert "trust the AgentVeil project hook once" in output
    assert "status remains advisory, not protected" in output
    assert str(project) not in output
    assert str(isolated_home) not in output


def test_setup_remove_codex_preserves_unrelated_config(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    assert main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"]) == 0
    capsys.readouterr()
    hooks_path = _codex_hooks(project)
    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    hooks["hooks"]["PreToolUse"][0]["hooks"].append({
        "type": "command",
        "command": "echo user-hook",
    })
    hooks["hooks"]["PreToolUse"].append({
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": "echo mentions agentveil_mcp_proxy.codex_hook but is user-owned",
            }
        ],
    })
    hooks_path.write_text(json.dumps(hooks), encoding="utf-8")
    codex_config = _codex_config(isolated_home)
    codex_config.write_text(
        codex_config.read_text(encoding="utf-8")
        + '\n[tools.shell]\nenabled = "ask"\n',
        encoding="utf-8",
    )

    assert main(["setup", "remove", "codex", "--project-dir", str(project), "--yes", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is True
    assert payload["hook_entries_removed"] == 1
    assert payload["mcp_route_removed"] is True
    assert payload["approval_center_stopped"] is True
    text = codex_config.read_text(encoding="utf-8")
    assert f"[mcp_servers.{DEFAULT_SERVER_NAME}]" not in text
    assert "[tools.shell]" in text
    hooks_after = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert hooks_after["hooks"]["PreToolUse"][0]["hooks"] == [{
        "type": "command",
        "command": "echo user-hook",
    }]
    assert hooks_after["hooks"]["PreToolUse"][1]["hooks"] == [{
        "type": "command",
        "command": "echo mentions agentveil_mcp_proxy.codex_hook but is user-owned",
    }]


def test_setup_codex_preview_does_not_write(tmp_path, monkeypatch, capsys):
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    project = tmp_path / "project"
    project.mkdir()

    assert main(["setup", "codex", "--project-dir", str(project)]) == 0
    capsys.readouterr()

    assert not (project / ".avp").exists()
    assert not _codex_config(isolated_home).exists()
    assert not _codex_hooks(project).exists()


def test_setup_codex_choose_folder_uses_selected_project(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)

    selected_project = tmp_path / "selected project"
    selected_project.mkdir()
    monkeypatch.setattr(proxy_cli, "_choose_setup_project_folder", lambda: selected_project)

    assert main(["setup", "codex", "--choose-folder", "--yes", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is True
    assert payload["action"] == "setup-codex"
    assert payload["approval_center"]["state"] == "running"
    assert str(selected_project) not in json.dumps(payload)
    assert str(isolated_home) not in json.dumps(payload)
    assert (selected_project / ".avp" / "mcp-proxy" / "config.json").exists()
    assert _codex_hooks(selected_project).exists()
    config = _codex_config(isolated_home).read_text(encoding="utf-8")
    assert "AVP_HOME" in config
    entry = parse_codex_mcp_server_entry(config, server_name=DEFAULT_SERVER_NAME)
    assert entry is not None
    assert str(selected_project / ".avp") in entry["args"]
    assert entry["env"]["AVP_HOME"] == str(selected_project / ".avp")


def test_setup_codex_fails_closed_on_invalid_hooks_json(tmp_path, monkeypatch):
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    hooks_path = _codex_hooks(project)
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text("{not-json", encoding="utf-8")

    assert main(["setup", "codex", "--project-dir", str(project), "--yes"]) == 2
    assert hooks_path.read_text(encoding="utf-8") == "{not-json"
    assert not _codex_config(isolated_home).exists()
    assert not (project / ".avp").exists()


def test_command_ownership_requires_exact_module_invocation():
    from agentveil_mcp_proxy import codex_setup

    assert codex_setup.command_invokes_managed_hook(
        "/usr/bin/python3 -m agentveil_mcp_proxy.codex_hook --evidence-path /tmp/e.jsonl"
    )
    assert not codex_setup.command_invokes_managed_hook(
        "echo mentions agentveil_mcp_proxy.codex_hook but is user-owned"
    )
    assert not codex_setup.command_invokes_managed_hook(
        "/usr/bin/python3 -m other.module agentveil_mcp_proxy.codex_hook"
    )
