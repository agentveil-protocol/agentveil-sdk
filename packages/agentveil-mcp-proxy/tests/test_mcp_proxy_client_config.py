"""Onboarding tests for dry-run MCP client config rendering."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from agentveil_mcp_proxy.client_config import (
    ClientConfigError,
    assert_client_config_summary_is_privacy_safe,
    assert_mcp_client_document_is_runnable,
    assert_rendered_config_is_privacy_safe,
    build_mcp_servers_document,
    build_run_args,
    format_client_config_json_payload,
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
    assert "local runnable client config" in captured.out
    assert "Cursor" in captured.out
    assert "~/.cursor/mcp.json" in captured.out
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
    assert payload["summary"]["command"] == proxy_command.name
    assert "claude_desktop" in payload["clients"]
    claude_entry = payload["clients"]["claude_desktop"]["local_client_config"]["mcpServers"]["agentveil-mcp-proxy"]
    assert claude_entry["command"] == str(proxy_command)
    args = claude_entry["args"]
    assert args[:2] == ["run", "--passphrase-file"]
    assert args[2] == str(passphrase_file)
    # claim-check: allow Python all() type guard; not a coverage claim.
    assert all(isinstance(item, str) for item in args)
    assert SECRET_PASSPHRASE not in captured.out


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


def test_setup_client_config_path_is_bounded(tmp_path):
    from agentveil_mcp_proxy.client_config import setup_client_config_path

    path = setup_client_config_path(tmp_path / "home", "cursor")
    assert path == tmp_path / "home" / "mcp-proxy" / "clients" / "cursor-mcp.json"


def test_render_cursor_claude_code_and_codex_shapes(tmp_path):
    proxy_command = tmp_path / "bin" / "agentveil-mcp-proxy"
    proxy_command.parent.mkdir(parents=True)
    proxy_command.write_text("#!/bin/sh\n", encoding="utf-8")

    rendered = render_client_configs(
        clients=["cursor", "claude_code", "codex"],
        command=str(proxy_command),
    )

    cursor = rendered["cursor"]
    assert "mcpServers" in cursor
    claude_code = rendered["claude_code"]
    assert "mcpServers" in claude_code
    codex = rendered["codex"]
    assert "manual_config_toml" in codex
    assert "run" in codex["manual_config_toml"]
    assert 'default_tools_approval_mode = "approve"' in codex["manual_config_toml"]


def test_format_client_config_json_payload_includes_pack_metadata(tmp_path):
    home = tmp_path / "avp-home"
    config_path = home / "mcp-proxy" / "config.json"
    rendered = render_client_configs(clients=["codex"], home=home, config_path=config_path)
    payload = format_client_config_json_payload(
        rendered,
        command="agentveil-mcp-proxy",
        run_args=build_run_args(home=home, config_path=config_path),
        home=home,
    )
    codex = payload["clients"]["codex"]
    assert codex["surface"] == "local_manual_config"
    assert codex["pack"]["support_status"] == "supported"
    assert_client_config_summary_is_privacy_safe(payload["summary"])


def test_format_client_config_json_payload_separates_summary_and_runnable_config(tmp_path):
    home = tmp_path / "avp-home"
    config_path = home / "mcp-proxy" / "config.json"
    rendered = render_client_configs(
        clients=["cursor"],
        home=home,
        config_path=config_path,
    )
    payload = format_client_config_json_payload(
        rendered,
        command="agentveil-mcp-proxy",
        run_args=build_run_args(home=home, config_path=config_path),
        config_path=config_path,
        home=home,
        role_preset="reviewer",
    )
    assert "config_path" not in payload
    assert "summary" in payload
    assert_client_config_summary_is_privacy_safe(payload["summary"])
    cursor = payload["clients"]["cursor"]
    assert cursor["surface"] == "local_client_config"
    document = cursor["local_client_config"]
    assert_mcp_client_document_is_runnable(document)
    entry = next(iter(document["mcpServers"].values()))
    args = entry["args"]
    # claim-check: allow Python all() type guard; not a coverage claim.
    assert all(isinstance(item, str) for item in args)
    assert str(home) in args
    assert str(config_path) in args
    env = entry.get("env", {})
    # claim-check: allow Python all() type guard; not a coverage claim.
    assert all(isinstance(value, str) for value in env.values())
    summary_text = json.dumps(payload["summary"])
    assert str(home) not in summary_text
    assert "/private/" not in summary_text


def test_format_client_config_json_payload_includes_bounded_downstream_startup_preview(tmp_path):
    home = tmp_path / "avp-home"
    config_path = home / "mcp-proxy" / "config.json"
    rendered = render_client_configs(clients=["cursor"], home=home, config_path=config_path)
    downstream = {
        "name": "package",
        "command": sys.executable,
        "args": ["-u", "/tmp/example_downstream.py", str(home / "project")],
        "env": {"LOCAL_DIST_DIR": "/tmp/dist", "PACKAGE_OUTCOME_LOG": "/tmp/outcome.jsonl"},
    }
    payload = format_client_config_json_payload(
        rendered,
        command="agentveil-mcp-proxy",
        run_args=build_run_args(home=home, config_path=config_path),
        config_path=config_path,
        home=home,
        downstream=downstream,
    )
    preview = payload["summary"]["downstream_startup_preview"]
    assert preview["configured"] is True
    assert preview["command_category"] == "python"
    assert preview["env_key_count"] == 2
    assert "LOCAL_DIST_DIR" in preview["env_keys"]
    preview_text = json.dumps(preview)
    assert "/tmp/example_downstream.py" not in preview_text
    assert "/tmp/dist" not in preview_text
    assert str(home) not in preview_text


def test_merge_codex_mcp_server_preserves_unrelated_toml(tmp_path):
    from agentveil_mcp_proxy.client_config import (
        DEFAULT_SERVER_NAME,
        merge_codex_mcp_server_into_text,
        parse_codex_mcp_server_entry,
        remove_codex_mcp_server_section,
    )

    original = '[profile]\nname = "team"\n\n[tools.shell]\nenabled = true\n'
    merged = merge_codex_mcp_server_into_text(
        original,
        server_name=DEFAULT_SERVER_NAME,
        command="agentveil-mcp-proxy",
        run_args=["run", "--home", "home-ref"],
    )
    assert '[profile]\nname = "team"' in merged
    assert "[tools.shell]" in merged
    entry = parse_codex_mcp_server_entry(merged, server_name=DEFAULT_SERVER_NAME)
    assert entry is not None
    assert entry["command"] == "agentveil-mcp-proxy"
    assert entry["default_tools_approval_mode"] == "approve"
    cleaned = remove_codex_mcp_server_section(merged, server_name=DEFAULT_SERVER_NAME)
    assert cleaned.strip() == original.strip()


def test_codex_mcp_server_match_requires_tool_approval_mode():
    from agentveil_mcp_proxy.client_config import (
        DEFAULT_SERVER_NAME,
        codex_mcp_server_entry_matches_launch_spec,
        merge_codex_mcp_server_into_text,
        parse_codex_mcp_server_entry,
    )

    launch_spec = {
        "command": "agentveil-mcp-proxy",
        "args": ["run", "--home", "home-ref"],
        "env": {},
    }
    merged = merge_codex_mcp_server_into_text(
        "",
        server_name=DEFAULT_SERVER_NAME,
        command="agentveil-mcp-proxy",
        run_args=["run", "--home", "home-ref"],
    )
    entry = parse_codex_mcp_server_entry(merged, server_name=DEFAULT_SERVER_NAME)
    assert entry is not None
    assert codex_mcp_server_entry_matches_launch_spec(entry, launch_spec) is True

    legacy_entry = dict(entry)
    legacy_entry.pop("default_tools_approval_mode")
    assert codex_mcp_server_entry_matches_launch_spec(legacy_entry, launch_spec) is False
