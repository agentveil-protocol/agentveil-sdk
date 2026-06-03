"""Onboarding tests for dry-run MCP client config rendering."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from agentveil_mcp_proxy.client_config import (
    ClientConfigError,
    assert_rendered_config_is_privacy_safe,
    build_mcp_servers_document,
    build_run_args,
    render_client_configs,
    resolve_proxy_command,
)
from agentveil_mcp_proxy.cli import main, print_client_configs


SECRET_PASSPHRASE = "super-secret-passphrase-value"
PRIVATE_KEY_HEX = "aa" * 32


def test_build_run_args_includes_home_config_and_passphrase_file(tmp_path):
    home = tmp_path / "avp-home"
    config_path = home / "mcp-proxy" / "config.json"
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(SECRET_PASSPHRASE + "\n", encoding="utf-8")

    args = build_run_args(
        home=home,
        config_path=config_path,
        passphrase_file=passphrase_file,
    )

    assert args == [
        "run",
        "--home",
        str(home),
        "--config",
        str(config_path),
        "--passphrase-file",
        str(passphrase_file),
    ]


def test_render_cursor_and_claude_desktop_mcp_servers_shape(tmp_path):
    proxy_command = tmp_path / "bin" / "agentveil-mcp-proxy"
    proxy_command.parent.mkdir(parents=True)
    proxy_command.write_text("#!/bin/sh\n", encoding="utf-8")

    rendered = render_client_configs(
        clients=["cursor", "claude_desktop"],
        command=str(proxy_command),
        server_name="github-gated",
    )

    for client_id in ("cursor", "claude_desktop"):
        document = rendered[client_id]
        assert set(document) == {"mcpServers"}
        entry = document["mcpServers"]["github-gated"]
        assert entry["command"] == str(proxy_command)
        assert entry["args"] == ["run"]
        assert "env" not in entry


def test_custom_home_adds_avp_home_env_without_secrets(tmp_path):
    home = tmp_path / "custom-avp-home"
    rendered = render_client_configs(
        clients=["cursor"],
        command="/usr/local/bin/agentveil-mcp-proxy",
        home=home,
    )
    entry = rendered["cursor"]["mcpServers"]["agentveil-mcp-proxy"]
    assert entry["env"] == {"AVP_HOME": str(home)}

    serialized = json.dumps(rendered)
    assert SECRET_PASSPHRASE not in serialized
    assert PRIVATE_KEY_HEX not in serialized
    assert_rendered_config_is_privacy_safe(
        rendered,
        forbidden_substrings=(SECRET_PASSPHRASE, PRIVATE_KEY_HEX),
    )


def test_render_rejects_missing_passphrase_file(tmp_path):
    missing = tmp_path / "missing-passphrase.txt"
    with pytest.raises(ClientConfigError, match="passphrase file does not exist"):
        render_client_configs(
            clients=["claude_desktop"],
            passphrase_file=missing,
        )


def test_cli_client_config_print_human_output(tmp_path, capsys):
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")

    exit_code = main([
        "client-config",
        "print",
        "--client",
        "cursor",
        "--proxy-command",
        str(proxy_command),
        "--server-name",
        "filesystem-gated",
    ])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Cursor" in captured.out
    assert ".cursor/mcp.json" in captured.out
    assert '"mcpServers"' in captured.out
    json_start = captured.out.index("{")
    document = json.loads(captured.out[json_start:])
    entry = document["mcpServers"]["filesystem-gated"]
    assert entry["command"] == str(proxy_command)
    assert entry["args"] == ["run"]
    assert SECRET_PASSPHRASE not in captured.out


def test_cli_client_config_print_json_output(tmp_path, capsys):
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(SECRET_PASSPHRASE + "\n", encoding="utf-8")

    exit_code = main([
        "client-config",
        "print",
        "--client",
        "claude_desktop",
        "--json",
        "--proxy-command",
        str(proxy_command),
        "--passphrase-file",
        str(passphrase_file),
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["dry_run"] is True
    assert payload["writes_user_config"] is False
    assert payload["privacy"]["includes_passphrase"] is False
    assert payload["args"] == [
        "run",
        "--passphrase-file",
        str(passphrase_file),
    ]
    assert "claude_desktop" in payload["clients"]
    assert payload["command"] == str(proxy_command)
    assert SECRET_PASSPHRASE not in captured.out
    assert str(passphrase_file) in payload["args"]
    claude_entry = payload["clients"]["claude_desktop"]["document"]["mcpServers"]["agentveil-mcp-proxy"]
    assert claude_entry["command"] == str(proxy_command)


def test_print_client_configs_does_not_write_user_config_dirs(tmp_path, monkeypatch):
    cursor_config = tmp_path / ".cursor" / "mcp.json"
    claude_config = tmp_path / "claude_desktop_config.json"
    monkeypatch.setenv("HOME", str(tmp_path))

    print_client_configs(
        clients=["cursor", "claude_desktop"],
        command=str(tmp_path / "agentveil-mcp-proxy"),
        out=io.StringIO(),
    )

    assert not cursor_config.exists()
    assert not claude_config.exists()


def test_resolve_proxy_command_falls_back_to_default_name(monkeypatch):
    monkeypatch.setattr("agentveil_mcp_proxy.client_config.shutil.which", lambda _name: None)
    assert resolve_proxy_command(None) == "agentveil-mcp-proxy"


def test_resolve_proxy_command_uses_path_when_installed(monkeypatch, tmp_path):
    executable = tmp_path / "agentveil-mcp-proxy"
    executable.write_text("", encoding="utf-8")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.client_config.shutil.which",
        lambda name: str(executable) if name == "agentveil-mcp-proxy" else None,
    )

    assert resolve_proxy_command(None) == str(executable)


def test_build_mcp_servers_document_requires_server_name():
    with pytest.raises(ClientConfigError, match="server name"):
        build_mcp_servers_document(
            server_name="   ",
            command="agentveil-mcp-proxy",
            run_args=["run"],
        )
