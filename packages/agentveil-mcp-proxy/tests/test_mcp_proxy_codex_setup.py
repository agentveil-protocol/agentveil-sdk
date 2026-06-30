"""Tests for the public Codex one-command connector setup."""

from __future__ import annotations

import json
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


def _codex_config(home: Path) -> Path:
    return home / ".codex" / "config.toml"


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
    monkeypatch.setenv("HOME", str(isolated_home))
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


def test_setup_codex_status_is_bounded_and_advisory_without_runtime_proof(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
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
    assert payload["proxy_route"] == "present"
    assert payload["approval_center"] == "running"
    assert payload["status"] in {"advisory", "protected"}
    assert str(project) not in json.dumps(payload)
    assert str(isolated_home) not in json.dumps(payload)


def test_setup_remove_codex_preserves_unrelated_config(
    tmp_path,
    monkeypatch,
    capsys,
):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)

    project = tmp_path / "project"
    project.mkdir()
    assert main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"]) == 0
    capsys.readouterr()
    codex_config = _codex_config(isolated_home)
    codex_config.write_text(
        codex_config.read_text(encoding="utf-8")
        + '\n[tools.shell]\nenabled = "ask"\n',
        encoding="utf-8",
    )

    assert main(["setup", "remove", "codex", "--project-dir", str(project), "--yes", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is True
    assert payload["mcp_route_removed"] is True
    assert payload["approval_center_stopped"] is True
    text = codex_config.read_text(encoding="utf-8")
    assert f"[mcp_servers.{DEFAULT_SERVER_NAME}]" not in text
    assert "[tools.shell]" in text


def test_setup_codex_preview_does_not_write(tmp_path, monkeypatch, capsys):
    isolated_home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(isolated_home))
    project = tmp_path / "project"
    project.mkdir()

    assert main(["setup", "codex", "--project-dir", str(project)]) == 0
    capsys.readouterr()

    assert not (project / ".avp").exists()
    assert not _codex_config(isolated_home).exists()
