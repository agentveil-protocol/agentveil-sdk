"""Unit tests for MCP Proxy acceptance helper assertions."""

from __future__ import annotations

import sys
from pathlib import Path, PureWindowsPath

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from mcp_proxy_acceptance_lib import AcceptanceError, assert_client_config_print_payload


def _new_shape_payload(*, home: Path, passphrase_file: Path, proxy_command: Path) -> dict:
    run_args = [
        "run",
        "--home",
        str(home),
        "--passphrase-file",
        str(passphrase_file),
    ]
    server_entry = {
        "command": str(proxy_command),
        "args": run_args,
        "env": {"AVP_HOME": str(home)},
    }
    document = {"mcpServers": {"agentveil-mcp-proxy": server_entry}}
    return {
        "ok": True,
        "dry_run": True,
        "writes_user_config": False,
        "summary": {
            "command": proxy_command.name,
            "client_count": 2,
            "privacy_bounded": True,
            "home_ref": {"basename": home.name, "ref": "abc123"},
        },
        "clients": {
            "cursor": {
                "surface": "local_client_config",
                "local_client_config": document,
            },
            "claude_desktop": {
                "surface": "local_client_config",
                "local_client_config": document,
            },
        },
        "privacy": {
            "includes_secrets": False,
            "includes_passphrase": False,
            "includes_private_key": False,
            "summary_is_privacy_bounded": True,
            "local_client_config_may_include_local_paths": True,
        },
    }


def test_assert_client_config_print_payload_accepts_client_matrix_shape(tmp_path: Path) -> None:
    home = tmp_path / "avp-home"
    passphrase_file = tmp_path / "passphrase.txt"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    passphrase_file.write_text("gate-secret\n", encoding="utf-8")
    proxy_command.write_text("", encoding="utf-8")

    assert_client_config_print_payload(
        _new_shape_payload(
            home=home,
            passphrase_file=passphrase_file,
            proxy_command=proxy_command,
        ),
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=proxy_command,
        secret_values=("gate-secret",),
    )


def test_assert_client_config_print_payload_accepts_legacy_top_level_shape(tmp_path: Path) -> None:
    home = tmp_path / "avp-home"
    passphrase_file = tmp_path / "passphrase.txt"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    passphrase_file.write_text("gate-secret\n", encoding="utf-8")
    proxy_command.write_text("", encoding="utf-8")
    run_args = ["run", "--home", str(home), "--passphrase-file", str(passphrase_file)]
    server_entry = {"command": str(proxy_command), "args": run_args, "env": {"AVP_HOME": str(home)}}

    payload = {
        "ok": True,
        "dry_run": True,
        "writes_user_config": False,
        "command": str(proxy_command),
        "args": run_args,
        "summary": {"command": proxy_command.name, "client_count": 2, "privacy_bounded": True},
        "clients": {
            "cursor": {"document": {"mcpServers": {"agentveil-mcp-proxy": server_entry}}},
            "claude_desktop": {"document": {"mcpServers": {"agentveil-mcp-proxy": server_entry}}},
        },
        "privacy": {
            "includes_secrets": False,
            "includes_passphrase": False,
            "includes_private_key": False,
            "summary_is_privacy_bounded": True,
        },
    }

    assert_client_config_print_payload(
        payload,
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=proxy_command,
        secret_values=("gate-secret",),
    )


def test_assert_client_config_print_payload_rejects_missing_run_args(tmp_path: Path) -> None:
    home = tmp_path / "avp-home"
    passphrase_file = tmp_path / "passphrase.txt"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    payload = _new_shape_payload(
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=proxy_command,
    )
    entry = payload["clients"]["cursor"]["local_client_config"]["mcpServers"]["agentveil-mcp-proxy"]
    entry["args"] = ["doctor", "--home", str(home)]

    with pytest.raises(AcceptanceError, match="runnable config must invoke proxy run"):
        assert_client_config_print_payload(
            payload,
            home=home,
            passphrase_file=passphrase_file,
            proxy_command=proxy_command,
        )


def test_assert_client_config_print_payload_rejects_passphrase_in_summary(tmp_path: Path) -> None:
    home = tmp_path / "avp-home"
    passphrase_file = tmp_path / "passphrase.txt"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    payload = _new_shape_payload(
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=proxy_command,
    )
    payload["summary"]["note"] = str(passphrase_file)

    with pytest.raises(AcceptanceError, match="summary must not include raw passphrase file path"):
        assert_client_config_print_payload(
            payload,
            home=home,
            passphrase_file=passphrase_file,
            proxy_command=proxy_command,
        )


def test_assert_client_config_print_payload_rejects_json_escaped_windows_path() -> None:
    home = PureWindowsPath("C:/Users/runneradmin/AppData/Local/Temp/avp-home")
    passphrase_file = PureWindowsPath(
        "C:/Users/runneradmin/AppData/Local/Temp/passphrase.txt",
    )
    proxy_command = PureWindowsPath("C:/agentveil/agentveil-mcp-proxy.exe")
    payload = _new_shape_payload(
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=proxy_command,
    )
    payload["summary"]["note"] = str(passphrase_file)

    with pytest.raises(AcceptanceError, match="summary must not include raw passphrase file path"):
        assert_client_config_print_payload(
            payload,
            home=home,
            passphrase_file=passphrase_file,
            proxy_command=proxy_command,
        )
