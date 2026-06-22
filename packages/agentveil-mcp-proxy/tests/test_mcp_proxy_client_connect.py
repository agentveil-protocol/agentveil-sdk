"""Tests for guided MCP client auto-connect."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from agentveil_mcp_proxy.client_config import (
    DEFAULT_SERVER_NAME,
    assert_proxy_cli_json_is_privacy_safe,
    assert_proxy_cli_output_is_privacy_safe,
    build_run_args,
)
from agentveil_mcp_proxy.client_connect import (
    ALL_CLIENTS_TARGET,
    CONNECT_ADAPTERS,
    ClientConnectError,
    build_connect_all_payload,
    build_connect_payload,
    build_connect_status_all_payload,
    build_connect_status_payload,
    build_disconnect_all_payload,
    build_disconnect_payload,
    format_connect_payload,
    get_connect_adapter,
    normalize_connect_client_id,
    normalize_connect_target,
    resolve_client_config_location,
)
from agentveil_mcp_proxy.client_packs import CLIENT_PACK_IDS
from agentveil_mcp_proxy.cli import init_proxy, main, quickstart_filesystem_downstream


PASSPHRASE = "client-connect-test-passphrase"
LOCAL_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/")


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    return tmp_path / "project"


@pytest.fixture
def avp_home(tmp_path: Path) -> Path:
    return tmp_path / "avp-home"


@pytest.fixture
def proxy_command(tmp_path: Path) -> Path:
    command = tmp_path / "bin" / "agentveil-mcp-proxy"
    command.parent.mkdir(parents=True)
    command.write_text("#!/bin/sh\n", encoding="utf-8")
    command.chmod(0o755)
    return command


@pytest.fixture
def initialized_proxy(avp_home: Path, tmp_path: Path) -> Path:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(PASSPHRASE + "\n", encoding="utf-8")
    os.chmod(passphrase_file, 0o600)
    init_proxy(
        home=avp_home,
        agent_name="proxy",
        passphrase_file=passphrase_file,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )
    return passphrase_file


def _assert_no_local_path_leaks(text: str) -> None:
    for marker in LOCAL_PATH_MARKERS:
        assert marker not in text, f"unexpected local path marker {marker!r}"
    assert PASSPHRASE not in text


def _cursor_global_mcp_json_path() -> Path:
    from agentveil_mcp_proxy.client_connect import resolve_cursor_global_mcp_json_path

    return resolve_cursor_global_mcp_json_path()


def _cursor_settings_path() -> Path:
    from agentveil_mcp_proxy.client_connect import resolve_cursor_user_data_dir

    return resolve_cursor_user_data_dir() / "User" / "settings.json"


def _cursor_project_mcp_json_path(project_root: Path) -> Path:
    return project_root / ".cursor" / "mcp.json"


def _cursor_mcp_servers(mcp_json_path: Path | None = None) -> dict:
    path = mcp_json_path or _cursor_global_mcp_json_path()
    if not path.exists():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    servers = document.get("mcpServers")
    return servers if isinstance(servers, dict) else {}


def _write_cursor_global_mcp(document: dict, mcp_json_path: Path | None = None) -> Path:
    path = mcp_json_path or _cursor_global_mcp_json_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_cursor_settings(document: dict, settings_path: Path | None = None) -> Path:
    path = settings_path or _cursor_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _cursor_native_settings(
    *,
    servers: dict | None = None,
    extra: dict | None = None,
) -> dict:
    document: dict = {"editor.fontSize": 14}
    if extra:
        document.update(extra)
    if servers is not None:
        document["mcp"] = {"servers": servers}
    return document


def _cursor_global_mcp_document(*, servers: dict | None = None) -> dict:
    document: dict = {}
    if servers is not None:
        document["mcpServers"] = servers
    return document


def test_connect_adapter_registry_covers_all_client_packs():
    assert set(CONNECT_ADAPTERS) == set(CLIENT_PACK_IDS)
    for client_id in CLIENT_PACK_IDS:
        adapter = get_connect_adapter(client_id)
        assert adapter.client_id == client_id


def test_connect_adapter_support_levels():
    assert get_connect_adapter("cursor").support_level == "auto_write"
    assert get_connect_adapter("claude_code").support_level == "auto_write"
    assert get_connect_adapter("codex").support_level == "auto_write"


def test_normalize_connect_client_id_rejects_unknown():
    with pytest.raises(ClientConnectError, match="unsupported client"):
        normalize_connect_client_id("unknown-client")


def _claude_code_config_path(project_root: Path) -> Path:
    return project_root / ".mcp.json"


def _codex_config_path(isolated_home: Path) -> Path:
    return isolated_home / ".codex" / "config.toml"


def test_claude_code_connect_write_launch_proved(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
):
    project_root.mkdir()
    payload = build_connect_payload(
        client_id="claude_code",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    assert payload["mode"] == "auto_connect"
    assert payload["wrote"] is True
    assert payload["connected"] is True
    assert payload["doctor_status"] == "ok"
    assert DEFAULT_SERVER_NAME in json.loads(_claude_code_config_path(project_root).read_text())["mcpServers"]


def test_codex_connect_write_launch_proved(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
    isolated_home: Path,
):
    project_root.mkdir()
    payload = build_connect_payload(
        client_id="codex",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    assert payload["mode"] == "auto_connect"
    assert payload["wrote"] is True
    assert payload["connected"] is True
    assert payload["doctor_status"] == "ok"
    codex_config = _codex_config_path(isolated_home)
    assert codex_config.exists()
    codex_text = codex_config.read_text(encoding="utf-8")
    assert f"[mcp_servers.{DEFAULT_SERVER_NAME}]" in codex_text
    assert 'default_tools_approval_mode = "approve"' in codex_text


def test_connect_dry_run_does_not_write(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    payload = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=False,
    )
    config_path = _cursor_global_mcp_json_path()
    assert payload["dry_run"] is True
    assert payload["wrote"] is False
    assert not config_path.exists()


def test_connect_write_creates_config_and_backup(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    config_path = _cursor_global_mcp_json_path()
    _write_cursor_global_mcp(
        _cursor_global_mcp_document(
            servers={"other-server": {"command": "echo", "args": []}},
        )
    )

    payload = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )

    assert payload["wrote"] is True
    assert config_path.exists()
    assert payload["backup_ref"] is not None
    backup_dir = config_path.parent / ".agentveil-connect-backups"
    assert any(backup_dir.iterdir())


def test_connect_write_preserves_unrelated_mcp_server(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    config_path = _cursor_global_mcp_json_path()
    _write_cursor_global_mcp(
        _cursor_global_mcp_document(
            servers={"other-server": {"command": "echo", "args": []}},
        )
    )

    build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )

    document = json.loads(config_path.read_text(encoding="utf-8"))
    servers = document["mcpServers"]
    assert "other-server" in servers
    assert DEFAULT_SERVER_NAME in servers


def test_connect_write_is_idempotent(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    first = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    config_path = _cursor_global_mcp_json_path()
    first_text = config_path.read_text(encoding="utf-8")

    second = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    second_text = config_path.read_text(encoding="utf-8")

    assert first["wrote"] is True
    assert second["wrote"] is True
    assert json.loads(first_text) == json.loads(second_text)


def test_disconnect_removes_only_agentveil_entry(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    config_path = _cursor_global_mcp_json_path()
    document = json.loads(config_path.read_text(encoding="utf-8"))
    document.setdefault("mcpServers", {})["other-server"] = {
        "command": "echo",
        "args": [],
    }
    config_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    payload = build_disconnect_payload(
        client_id="cursor",
        home=avp_home,
        project_root=project_root,
        write=True,
    )

    updated = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["removed_entry"] is True
    assert DEFAULT_SERVER_NAME not in updated["mcpServers"]
    assert "other-server" in updated["mcpServers"]


def test_missing_generated_command_does_not_claim_connected(project_root: Path, avp_home: Path):
    project_root.mkdir()
    missing_command = project_root / "missing-proxy"
    payload = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(missing_command),
        project_root=project_root,
        write=False,
    )
    assert payload["connected"] is False
    assert payload["ok"] is False
    assert "generated proxy command is not available" in payload["errors"][0]


def test_connect_payload_json_and_human_output_are_privacy_bounded(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    payload = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=False,
    )
    serialized = json.dumps(payload)
    assert_proxy_cli_json_is_privacy_safe(payload)
    _assert_no_local_path_leaks(serialized)

    human = format_connect_payload(payload)
    assert_proxy_cli_output_is_privacy_safe(human)
    _assert_no_local_path_leaks(human)


def test_doctor_failure_is_bounded_without_overclaim(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    failed_report = {
        "ok": False,
        "diagnostic_status": "failed",
        "proof_mode": "generated_config_proxy_path",
        "provider_native_client_proof": False,
    }
    with patch(
        "agentveil_mcp_proxy.client_connect.build_client_doctor_report",
        return_value=failed_report,
    ):
        payload = build_connect_payload(
            client_id="cursor",
            home=avp_home,
            proxy_command=str(proxy_command),
            passphrase_file=initialized_proxy,
            project_root=project_root,
            write=True,
        )

    assert payload["doctor_status"] == "failed"
    assert payload["connected"] is False
    assert payload["ok"] is False
    assert payload["doctor_summary"]["provider_native_client_proof"] is False
    assert "client-doctor" in payload["next_step"]


def test_connect_status_not_connected_when_launch_probe_fails(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    # Dummy executable exists and matches config, but is not AgentVeil.
    # Status must not claim connected just because the config entry is present.
    project_root.mkdir()
    build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    status = build_connect_status_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
    )
    assert status["config_entry_present"] is True
    assert status["doctor_status"] == "failed"
    assert status["connected"] is False


def test_connect_status_connected_requires_launch_proof(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
):
    project_root.mkdir()
    write = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    assert write["doctor_status"] == "ok"
    assert write["connected"] is True

    status = build_connect_status_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
    )
    assert status["config_entry_present"] is True
    assert status["doctor_status"] == "ok"
    assert status["connected"] is True


def test_connect_status_not_present_before_write(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    status = build_connect_status_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
    )
    assert status["config_entry_present"] is False
    assert status["connected"] is False
    assert status["doctor_status"] == "skipped"
    assert "connect cursor --write" in status["next_step"]


def test_connect_status_before_write_points_to_connect_write(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
    isolated_home: Path,
):
    project_root.mkdir()
    for client_id in ("claude_code", "codex"):
        status = build_connect_status_payload(
            client_id=client_id,
            home=avp_home,
            proxy_command=str(proxy_command),
            passphrase_file=initialized_proxy,
            project_root=project_root,
        )
        assert status["support_status"] == "auto_write"
        assert status["connected"] is False
        assert f"connect {client_id} --write" in status["next_step"]
        assert "config_via" not in status


def test_connect_status_all_before_write_points_to_connect_write(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
    isolated_home: Path,
):
    project_root.mkdir()
    payload = build_connect_status_all_payload(
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
    )
    rows = {row["client_id"]: row for row in payload["clients"]}
    for client_id in ("claude_code", "codex"):
        assert rows[client_id]["support_status"] == "auto_write"
        assert f"connect {client_id} --write" in rows[client_id]["next_step"]
        assert "config_via" not in rows[client_id]


def test_resolve_client_config_location_uses_adapter(project_root: Path):
    project_root.mkdir()
    location = resolve_client_config_location("cursor", project_root=project_root)
    assert location.client_id == "cursor"
    assert location.config_path == _cursor_global_mcp_json_path()
    assert location.auto_connect_supported is True


def test_cli_connect_cursor_dry_run_json(project_root: Path, avp_home: Path, proxy_command: Path, capsys):
    project_root.mkdir()
    exit_code = main([
        "connect",
        "cursor",
        "--home",
        str(avp_home),
        "--proxy-command",
        str(proxy_command),
        "--project-root",
        str(project_root),
        "--json",
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["dry_run"] is True
    assert payload["wrote"] is False
    _assert_no_local_path_leaks(captured.out)


def test_cli_disconnect_cursor_write(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
    capsys,
):
    project_root.mkdir()
    main([
        "connect",
        "cursor",
        "--write",
        "--home",
        str(avp_home),
        "--proxy-command",
        str(proxy_command),
        "--passphrase-file",
        str(initialized_proxy),
        "--project-root",
        str(project_root),
        "--json",
    ])
    capsys.readouterr()

    exit_code = main([
        "disconnect",
        "cursor",
        "--write",
        "--project-root",
        str(project_root),
        "--json",
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["removed_entry"] is True
    config_path = _cursor_global_mcp_json_path()
    document = json.loads(config_path.read_text(encoding="utf-8"))
    assert DEFAULT_SERVER_NAME not in document.get("mcpServers", {})


def test_cli_connect_status_via_status_subcommand(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
    capsys,
):
    project_root.mkdir()
    main([
        "connect",
        "cursor",
        "--write",
        "--home",
        str(avp_home),
        "--proxy-command",
        runnable_proxy_command,
        "--passphrase-file",
        str(initialized_proxy),
        "--project-root",
        str(project_root),
        "--json",
    ])
    capsys.readouterr()

    exit_code = main([
        "connect",
        "status",
        "cursor",
        "--home",
        str(avp_home),
        "--proxy-command",
        runnable_proxy_command,
        "--passphrase-file",
        str(initialized_proxy),
        "--project-root",
        str(project_root),
        "--json",
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["connected"] is True
    assert payload["config_entry_present"] is True
    assert payload["doctor_status"] == "ok"
    _assert_no_local_path_leaks(captured.out)


def test_connect_dry_run_emits_agent_assist_fields(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    payload = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=False,
    )
    assert payload["support_status"] == "auto_write"
    assert payload["write_required"] is True
    assert payload["will_write"] is False
    assert payload["backup_planned"] is False
    assert payload["restart_required"] is True
    assert "rollback_command" not in payload


def test_connect_write_includes_rollback_command(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    with patch(
        "agentveil_mcp_proxy.client_connect.build_client_doctor_report",
        return_value={"ok": True, "diagnostic_status": "ok", "provider_native_client_proof": False},
    ):
        payload = build_connect_payload(
            client_id="cursor",
            home=avp_home,
            proxy_command=str(proxy_command),
            passphrase_file=initialized_proxy,
            project_root=project_root,
            write=True,
        )
    assert payload["wrote"] is True
    assert payload["rollback_command"] == "agentveil-mcp-proxy disconnect cursor --write"


def test_auto_write_emits_agent_assist_fields_on_write(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
    isolated_home: Path,
):
    project_root.mkdir()
    payload = build_connect_payload(
        client_id="codex",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    assert payload["support_status"] == "auto_write"
    assert payload["will_write"] is True
    assert payload["rollback_command"] == "agentveil-mcp-proxy disconnect codex --write"


def test_written_entry_matches_generated_launch_spec(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    config_path = _cursor_global_mcp_json_path()
    document = json.loads(config_path.read_text(encoding="utf-8"))
    entry = _cursor_mcp_servers(config_path)[DEFAULT_SERVER_NAME]
    expected_args = build_run_args(
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
    )
    assert entry["command"] == str(proxy_command)
    assert entry["args"] == expected_args


def test_normalize_connect_target_all():
    assert normalize_connect_target(ALL_CLIENTS_TARGET) == list(CLIENT_PACK_IDS)


def test_connect_all_dry_run_matrix(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    payload = build_connect_all_payload(
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=False,
    )
    assert payload["mode"] == "matrix"
    assert payload["ok"] is True
    assert "connected" not in payload
    assert payload["any_connected"] is False
    assert len(payload["clients"]) == len(CLIENT_PACK_IDS)
    rows = {row["client_id"]: row for row in payload["clients"]}
    assert rows["cursor"]["support_status"] == "auto_write"
    assert rows["cursor"]["will_write"] is False
    assert rows["cursor"]["connected"] is False
    assert rows["claude_code"]["support_status"] == "auto_write"
    assert rows["claude_code"]["connected"] is False
    assert rows["claude_code"]["will_write"] is False
    assert rows["codex"]["support_status"] == "auto_write"
    assert payload["summary"]["connected_count"] == 0
    assert payload["summary"]["manual_fallback_count"] == 0


def test_connect_all_write_auto_write_clients_connected(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
    isolated_home: Path,
):
    project_root.mkdir()
    payload = build_connect_all_payload(
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    rows = {row["client_id"]: row for row in payload["clients"]}
    for client_id in CLIENT_PACK_IDS:
        assert rows[client_id]["wrote"] is True
        assert rows[client_id]["connected"] is True
        assert rows[client_id]["doctor_status"] == "ok"
    assert payload["summary"]["connected_count"] == len(CLIENT_PACK_IDS)
    assert payload["summary"]["manual_fallback_count"] == 0
    assert payload["any_connected"] is True
    assert "connected" not in payload


def test_connect_status_all_matrix(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
    isolated_home: Path,
):
    project_root.mkdir()
    build_connect_all_payload(
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    payload = build_connect_status_all_payload(
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
    )
    rows = {row["client_id"]: row for row in payload["clients"]}
    for client_id in CLIENT_PACK_IDS:
        assert rows[client_id]["connected"] is True
    assert payload["summary"]["connected_count"] == len(CLIENT_PACK_IDS)
    assert payload["any_connected"] is True
    assert "connected" not in payload


def test_connect_all_write_with_dummy_command_does_not_overclaim(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
    isolated_home: Path,
):
    project_root.mkdir()
    payload = build_connect_all_payload(
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    rows = {row["client_id"]: row for row in payload["clients"]}
    assert rows["cursor"]["connected"] is False
    assert rows["cursor"]["doctor_status"] == "failed"
    assert payload["summary"]["connected_count"] == 0
    assert payload["ok"] is False


def test_disconnect_dry_run_does_not_claim_connected_without_launch_proof(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    _write_cursor_global_mcp(
        _cursor_global_mcp_document(
            servers={
                DEFAULT_SERVER_NAME: {
                    "command": "/definitely/missing/agentveil-mcp-proxy",
                    "args": ["run"],
                }
            },
        )
    )
    payload = build_disconnect_payload(
        client_id="cursor",
        home=avp_home,
        project_root=project_root,
        write=False,
    )
    assert payload["config_entry_present"] is True
    assert payload["connected"] is False
    assert payload["doctor_status"] == "skipped"
    assert payload["summary"]["would_remove_entry"] is True
    assert payload["summary"]["connected"] is False


def test_claude_code_write_preserves_unrelated_mcp_server(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
):
    project_root.mkdir()
    config_path = _claude_code_config_path(project_root)
    config_path.write_text(
        json.dumps({"mcpServers": {"other-server": {"command": "echo", "args": []}}}) + "\n",
        encoding="utf-8",
    )
    build_connect_payload(
        client_id="claude_code",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    document = json.loads(config_path.read_text(encoding="utf-8"))
    assert "other-server" in document["mcpServers"]
    assert DEFAULT_SERVER_NAME in document["mcpServers"]


def test_codex_disconnect_removes_only_agentveil_entry(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
    isolated_home: Path,
):
    project_root.mkdir()
    build_connect_payload(
        client_id="codex",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    codex_config = _codex_config_path(isolated_home)
    codex_config.write_text(
        codex_config.read_text(encoding="utf-8")
        + '\n[tools.shell]\nenabled = true\n',
        encoding="utf-8",
    )
    payload = build_disconnect_payload(
        client_id="codex",
        home=avp_home,
        project_root=project_root,
        write=True,
    )
    assert payload["removed_entry"] is True
    text = codex_config.read_text(encoding="utf-8")
    assert f"[mcp_servers.{DEFAULT_SERVER_NAME}]" not in text
    assert "[tools.shell]" in text


def test_connect_preview_declares_no_client_config_mutation(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    payload = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=False,
    )
    assert payload["will_write"] is False
    assert payload["client_config_mutation"] is False
    assert payload["route_launch_proved"] is False
    assert payload["connected"] is False
    assert "--write" in payload["next_step"]


def test_connect_write_sets_client_config_mutation_and_launch_proof(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
):
    project_root.mkdir()
    payload = build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    assert payload["client_config_mutation"] is True
    assert payload["route_launch_proved"] is True
    assert payload["connected"] is True


def test_connect_status_separates_entry_launch_and_connected(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
):
    project_root.mkdir()
    build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    status = build_connect_status_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
    )
    assert status["config_entry_present"] is True
    assert status["route_launch_proved"] is True
    assert status["connected"] is True
    assert status["client_config_mutation"] is False


def test_connect_all_preview_matrix_declares_no_mutation(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    payload = build_connect_all_payload(
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=False,
    )
    assert payload["client_config_mutation"] is False
    for row in payload["clients"]:
        assert row["client_config_mutation"] is False
        assert row["will_write"] is False


def test_disconnect_all_dry_run_matrix(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
    isolated_home: Path,
):
    project_root.mkdir()
    build_connect_all_payload(
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    payload = build_disconnect_all_payload(
        home=avp_home,
        project_root=project_root,
        write=False,
    )
    assert payload["mode"] == "matrix"
    assert payload["target"] == ALL_CLIENTS_TARGET
    assert payload["dry_run"] is True
    assert payload["client_config_mutation"] is False
    assert payload["any_connected"] is False
    assert "connected" not in payload
    rows = {row["client_id"]: row for row in payload["clients"]}
    for client_id in CLIENT_PACK_IDS:
        assert rows[client_id]["connected"] is False
        assert rows[client_id]["wrote"] is False
        assert rows[client_id]["config_entry_present"] is True
        assert rows[client_id]["support_status"] == "auto_write"


def test_disconnect_all_empty_config_dry_run_support_status(
    project_root: Path,
    avp_home: Path,
):
    project_root.mkdir()
    payload = build_disconnect_all_payload(
        home=avp_home,
        project_root=project_root,
        write=False,
    )
    assert "connected" not in payload
    rows = {row["client_id"]: row for row in payload["clients"]}
    for client_id in CLIENT_PACK_IDS:
        assert rows[client_id]["support_status"] == "auto_write"
        assert rows[client_id]["will_write"] is False
        assert rows[client_id]["client_config_mutation"] is False


def test_disconnect_all_write_removes_agentveil_entries(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
    isolated_home: Path,
):
    project_root.mkdir()
    build_connect_all_payload(
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    payload = build_disconnect_all_payload(
        home=avp_home,
        project_root=project_root,
        write=True,
    )
    assert payload["ok"] is True
    assert payload["client_config_mutation"] is True
    assert payload["summary"]["removed_count"] == len(CLIENT_PACK_IDS)
    rows = {row["client_id"]: row for row in payload["clients"]}
    for client_id in CLIENT_PACK_IDS:
        assert rows[client_id]["removed_entry"] is True
        assert rows[client_id]["connected"] is False
        assert rows[client_id]["support_status"] == "auto_write"
    assert DEFAULT_SERVER_NAME not in _cursor_mcp_servers(_cursor_global_mcp_json_path())
    assert DEFAULT_SERVER_NAME not in json.loads(_claude_code_config_path(project_root).read_text())["mcpServers"]
    codex_config = _codex_config_path(isolated_home)
    if codex_config.exists():
        assert f"[mcp_servers.{DEFAULT_SERVER_NAME}]" not in codex_config.read_text(encoding="utf-8")


def test_cli_disconnect_all_write_json(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
    isolated_home: Path,
    capsys,
):
    project_root.mkdir()
    main([
        "connect",
        ALL_CLIENTS_TARGET,
        "--write",
        "--home",
        str(avp_home),
        "--proxy-command",
        runnable_proxy_command,
        "--passphrase-file",
        str(initialized_proxy),
        "--project-root",
        str(project_root),
        "--json",
    ])
    capsys.readouterr()
    exit_code = main([
        "disconnect",
        ALL_CLIENTS_TARGET,
        "--write",
        "--home",
        str(avp_home),
        "--project-root",
        str(project_root),
        "--json",
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["mode"] == "matrix"
    assert payload["summary"]["removed_count"] == len(CLIENT_PACK_IDS)
    assert "connected" not in payload
    for row in payload["clients"]:
        assert row["support_status"] == "auto_write"
    _assert_no_local_path_leaks(captured.out)


def test_cursor_connect_writes_native_mcp_json_shape(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    document = json.loads(_cursor_global_mcp_json_path().read_text(encoding="utf-8"))
    assert isinstance(document.get("mcpServers"), dict)
    assert DEFAULT_SERVER_NAME in document["mcpServers"]
    assert not _cursor_project_mcp_json_path(project_root).exists()


def test_cursor_connect_preserves_unrelated_settings_and_servers(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    _write_cursor_settings(
        _cursor_native_settings(extra={"workbench.colorTheme": "Default Dark Modern"})
    )
    _write_cursor_global_mcp(
        _cursor_global_mcp_document(
            servers={"other-server": {"command": "echo", "args": ["hi"]}},
        )
    )
    build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    settings = json.loads(_cursor_settings_path().read_text(encoding="utf-8"))
    assert settings["workbench.colorTheme"] == "Default Dark Modern"
    global_document = json.loads(_cursor_global_mcp_json_path().read_text(encoding="utf-8"))
    assert "other-server" in global_document["mcpServers"]
    assert DEFAULT_SERVER_NAME in global_document["mcpServers"]


def test_cursor_connect_cleans_legacy_settings_entry(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    settings_path = _cursor_settings_path()
    _write_cursor_settings(
        _cursor_native_settings(
            servers={
                DEFAULT_SERVER_NAME: {
                    "command": "echo",
                    "args": ["legacy"],
                }
            },
            extra={"workbench.colorTheme": "Default Dark Modern"},
        )
    )
    build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=str(proxy_command),
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    assert settings["workbench.colorTheme"] == "Default Dark Modern"
    legacy_servers = (settings.get("mcp") or {}).get("servers") or {}
    assert DEFAULT_SERVER_NAME not in legacy_servers
    global_document = json.loads(_cursor_global_mcp_json_path().read_text(encoding="utf-8"))
    assert DEFAULT_SERVER_NAME in global_document["mcpServers"]
    settings_backup_dir = settings_path.parent / ".agentveil-connect-backups"
    assert any(settings_backup_dir.iterdir())


def test_cursor_invalid_mcp_json_is_fail_closed_on_write(
    project_root: Path,
    avp_home: Path,
    proxy_command: Path,
    initialized_proxy: Path,
):
    project_root.mkdir()
    mcp_path = _cursor_global_mcp_json_path()
    mcp_path.parent.mkdir(parents=True, exist_ok=True)
    mcp_path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ClientConnectError, match="not valid JSON"):
        build_connect_payload(
            client_id="cursor",
            home=avp_home,
            proxy_command=str(proxy_command),
            passphrase_file=initialized_proxy,
            project_root=project_root,
            write=True,
        )
    assert mcp_path.read_text(encoding="utf-8") == "{not-json"


def test_cursor_status_uses_mcp_servers_not_project_mcp_json(
    project_root: Path,
    avp_home: Path,
    initialized_proxy: Path,
    runnable_proxy_command: str,
):
    project_root.mkdir()
    legacy_path = _cursor_project_mcp_json_path(project_root)
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_text(
        json.dumps({DEFAULT_SERVER_NAME: {"command": "echo", "args": ["run"]}}) + "\n",
        encoding="utf-8",
    )
    status = build_connect_status_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
    )
    assert status["config_entry_present"] is False
    build_connect_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
        write=True,
    )
    status_after = build_connect_status_payload(
        client_id="cursor",
        home=avp_home,
        proxy_command=runnable_proxy_command,
        passphrase_file=initialized_proxy,
        project_root=project_root,
    )
    assert status_after["config_entry_present"] is True
    assert status_after["route_launch_proved"] is True
    assert status_after["connected"] is True
