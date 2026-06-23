"""Tests for non-invasive client runtime attach planning."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

from agentveil_mcp_proxy.client_config import assert_proxy_cli_json_is_privacy_safe
from agentveil_mcp_proxy.client_packs import CLIENT_PACK_IDS
from agentveil_mcp_proxy.client_runtime import (
    CODEX_MCP_OVERRIDE_METHOD,
    REASON_CODEX_AGENT_TOOL_CALL_UNVERIFIED,
    REASON_CODEX_CLI_UNAVAILABLE,
    REASON_CODEX_MCP_OVERRIDE_UNRECOGNIZED,
    REASON_NON_INVASIVE_ATTACH_UNAVAILABLE,
    RUNTIME_ATTACH_ADAPTERS,
    build_client_runtime_payload,
    format_client_runtime_payload,
    normalize_runtime_client_id,
)
from agentveil_mcp_proxy.cli import init_proxy, main, quickstart_filesystem_downstream

PASSPHRASE = "client-runtime-test-passphrase"
LOCAL_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/")
CODEX_REASON_CODES = {
    REASON_CODEX_AGENT_TOOL_CALL_UNVERIFIED,
    REASON_CODEX_CLI_UNAVAILABLE,
    REASON_CODEX_MCP_OVERRIDE_UNRECOGNIZED,
}


@pytest.fixture
def avp_home(tmp_path: Path) -> Path:
    return tmp_path / "avp-home"


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    return tmp_path / "project"


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "user-home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    return home


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


def _client_config_paths(project_root: Path, isolated_home: Path) -> tuple[Path, Path, Path]:
    return (
        project_root / ".cursor" / "mcp.json",
        project_root / ".mcp.json",
        isolated_home / ".codex" / "config.toml",
    )


def _assert_no_client_config_mutation(
    project_root: Path,
    isolated_home: Path,
) -> None:
    cursor_config, claude_config, codex_config = _client_config_paths(project_root, isolated_home)
    assert not cursor_config.exists()
    assert not claude_config.exists()
    assert not codex_config.exists()
    assert not (cursor_config.parent / ".agentveil-connect-backups").exists()
    assert not (claude_config.parent / ".agentveil-connect-backups").exists()
    assert not (codex_config.parent / ".agentveil-connect-backups").exists()


@pytest.mark.parametrize("client_id", CLIENT_PACK_IDS)
def test_primary_clients_return_explicit_unsupported_runtime_attach(
    client_id: str,
    avp_home: Path,
    initialized_proxy: Path,
    project_root: Path,
    isolated_home: Path,
):
    project_root.mkdir()
    payload = build_client_runtime_payload(
        client_id=client_id,
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
        proxy_command="agentveil-mcp-proxy",
    )
    adapter = RUNTIME_ATTACH_ADAPTERS[client_id]
    assert payload["ok"] is False
    assert payload["runtime_attach_supported"] is False
    if client_id == "codex":
        assert payload["reason_code"] in CODEX_REASON_CODES
    else:
        assert payload["reason_code"] == REASON_NON_INVASIVE_ATTACH_UNAVAILABLE
    assert payload["generic_route_available"] is True
    assert payload["client_config_mutation"] is False
    assert payload["provider_native_client_proof"] is False
    assert payload["dry_run"] is True
    assert payload["executed"] is False
    assert payload["route_via"] == f"agentveil-mcp-proxy client-config print --client {client_id}"
    assert payload["adapter"]["client_id"] == adapter.client_id
    assert payload["adapter"]["runtime_attach_supported"] is False
    assert_proxy_cli_json_is_privacy_safe(payload)
    _assert_no_local_path_leaks(json.dumps(payload))
    _assert_no_client_config_mutation(project_root, isolated_home)


def _write_fake_codex(directory: Path) -> Path:
    script = directory / "codex.py"
    script.write_text(
        "import json, pathlib, sys\n"
        "if 'exec' in sys.argv:\n"
        "    prompt = sys.argv[-1]\n"
        "    tool = 'write_file' if 'write' in prompt.lower() else 'list_workspace'\n"
        "    pathlib.Path('agentveil-evidence-marker.json').write_text(tool)\n"
        "    print(json.dumps({'type':'item.started','item':{'type':'mcp_tool_call','server':'agentveil','tool':tool}}))\n"
        "    raise SystemExit(0)\n"
        "command = None\n"
        "args = None\n"
        "items = sys.argv[1:]\n"
        "for index, item in enumerate(items):\n"
        "    if item == '-c' and index + 1 < len(items):\n"
        "        raw = items[index + 1]\n"
        "        if raw.startswith('mcp_servers.agentveil.command='):\n"
        "            command = json.loads(raw.split('=', 1)[1])\n"
        "        if raw.startswith('mcp_servers.agentveil.args='):\n"
        "            args = json.loads(raw.split('=', 1)[1])\n"
        "if items[:3] != ['mcp', 'list', '--json'] or command is None or args is None:\n"
        "    raise SystemExit(2)\n"
        "print(json.dumps([{'name':'agentveil','transport':{'type':'stdio','command':command,'args':args}}]))\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        command = directory / "codex.cmd"
        command.write_text(f"@echo off\r\n\"{sys.executable}\" \"{script}\" %*\r\n", encoding="utf-8")
        return command
    command = directory / "codex"
    command.write_text(f"#!{sys.executable}\n" + script.read_text(encoding="utf-8"), encoding="utf-8")
    command.chmod(0o755)
    return command


def _write_fake_proxy(directory: Path) -> Path:
    script = directory / "agentveil_mcp_proxy_fake.py"
    script.write_text(
        "import json, pathlib, sys\n"
        "if sys.argv[1:4] == ['events', 'list', '--home'] or sys.argv[1:3] == ['events', 'list']:\n"
        "    marker = pathlib.Path('agentveil-evidence-marker.json')\n"
        "    events = []\n"
        "    if marker.exists():\n"
        "        tool = marker.read_text().strip()\n"
        "        if tool == 'write_file':\n"
        "            events = [{'tool':'write_file','status':'rejected','policy_rule':'standard_safe_autopilot_write_not_reached'}]\n"
        "        else:\n"
        "            events = [{'tool':'list_workspace','status':'executed','target_reached':True}]\n"
        "    print(json.dumps({'ok': True, 'events': events, 'evidence_count': len(events)}))\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(2)\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        command = directory / "agentveil-mcp-proxy.cmd"
        command.write_text(f"@echo off\r\n\"{sys.executable}\" \"{script}\" %*\r\n", encoding="utf-8")
        return command
    command = directory / "agentveil-mcp-proxy"
    command.write_text(f"#!{sys.executable}\n" + script.read_text(encoding="utf-8"), encoding="utf-8")
    command.chmod(0o755)
    return command


def test_codex_runtime_probe_recognizes_non_invasive_mcp_override(
    avp_home: Path,
    initialized_proxy: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    _write_fake_codex(fake_bin)
    monkeypatch.setenv("PATH", str(fake_bin))

    payload = build_client_runtime_payload(
        client_id="codex",
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
        proxy_command="agentveil-mcp-proxy",
    )

    assert payload["runtime_attach_supported"] is False
    assert payload["runtime_attach_method"] == CODEX_MCP_OVERRIDE_METHOD
    assert payload["codex_cli_available"] is True
    assert payload["codex_mcp_override_supported"] is True
    assert payload["codex_mcp_override_status"] == "recognized"
    assert payload["codex_mcp_override_probe"] == "codex mcp list --json"
    assert payload["reason_code"] == REASON_CODEX_AGENT_TOOL_CALL_UNVERIFIED
    assert payload["provider_native_client_proof"] is False
    assert payload["client_config_mutation"] is False
    assert_proxy_cli_json_is_privacy_safe(payload)


def test_codex_runtime_probe_fails_closed_when_codex_cli_missing(
    avp_home: Path,
    initialized_proxy: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))

    payload = build_client_runtime_payload(
        client_id="codex",
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
    )

    assert payload["runtime_attach_supported"] is False
    assert payload["codex_cli_available"] is False
    assert payload["codex_mcp_override_supported"] is False
    assert payload["codex_mcp_override_status"] == "codex_cli_unavailable"
    assert payload["reason_code"] == REASON_CODEX_CLI_UNAVAILABLE
    assert payload["client_config_mutation"] is False
    assert_proxy_cli_json_is_privacy_safe(payload)


def test_codex_launch_requires_prompt_before_running(
    avp_home: Path,
    initialized_proxy: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    _write_fake_codex(fake_bin)
    fake_proxy = _write_fake_proxy(fake_bin)
    monkeypatch.setenv("PATH", str(fake_bin))

    payload = build_client_runtime_payload(
        client_id="codex",
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
        proxy_command=str(fake_proxy),
        launch=True,
        cwd=tmp_path,
    )

    assert payload["executed"] is False
    assert payload["routed_action_reached"] is False
    assert payload["reason_code"] == REASON_CODEX_AGENT_TOOL_CALL_UNVERIFIED
    assert "errors" in payload
    assert not (tmp_path / "agentveil-evidence-marker.json").exists()


def test_codex_launch_reaches_routed_action_with_ephemeral_override(
    avp_home: Path,
    initialized_proxy: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    _write_fake_codex(fake_bin)
    fake_proxy = _write_fake_proxy(fake_bin)
    monkeypatch.setenv("PATH", str(fake_bin))

    payload = build_client_runtime_payload(
        client_id="codex",
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
        proxy_command=str(fake_proxy),
        launch=True,
        prompt="List the protected workspace through AgentVeil.",
        cwd=tmp_path,
    )

    assert payload["ok"] is True
    assert payload["runtime_attach_supported"] is True
    assert payload["executed"] is True
    assert payload["agentveil_tool_call_seen"] is True
    assert payload["agentveil_tool_names"] == ["list_workspace"]
    assert payload["routed_action_reached"] is True
    assert payload["evidence_count_delta"] == 1
    assert payload["target_reached_values"] == [True]
    assert payload["blocked_or_denied_action_seen"] is False
    assert payload["bounded_evidence"] == [
        {"tool": "list_workspace", "status": "executed", "target_reached": True}
    ]
    assert payload["client_config_mutation"] is False
    assert_proxy_cli_json_is_privacy_safe(payload)


def test_codex_launch_summarizes_standard_write_block_without_target_reach(
    avp_home: Path,
    initialized_proxy: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    _write_fake_codex(fake_bin)
    fake_proxy = _write_fake_proxy(fake_bin)
    monkeypatch.setenv("PATH", str(fake_bin))

    payload = build_client_runtime_payload(
        client_id="codex",
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
        proxy_command=str(fake_proxy),
        launch=True,
        prompt="Write a file through AgentVeil.",
        cwd=tmp_path,
    )

    assert payload["ok"] is False
    assert payload["runtime_attach_supported"] is True
    assert payload["executed"] is True
    assert payload["agentveil_tool_call_seen"] is True
    assert payload["agentveil_tool_names"] == ["write_file"]
    assert payload["routed_action_reached"] is False
    assert payload["evidence_count_delta"] == 1
    assert payload["target_reached_values"] == [False]
    assert payload["blocked_or_denied_action_seen"] is True
    assert payload["bounded_evidence"] == [
        {
            "tool": "write_file",
            "status": "rejected",
            "policy_rule": "standard_safe_autopilot_write_not_reached",
            "target_reached": False,
        }
    ]
    assert payload["client_config_mutation"] is False
    assert_proxy_cli_json_is_privacy_safe(payload)


def test_unknown_client_returns_generic_route_without_fake_support(
    avp_home: Path,
    initialized_proxy: Path,
    project_root: Path,
    isolated_home: Path,
):
    project_root.mkdir()
    payload = build_client_runtime_payload(
        client_id="some_unknown_client",
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
    )
    assert payload["client_id"] == "some_unknown_client"
    assert payload["runtime_attach_supported"] is False
    assert payload["generic_route_available"] is True
    assert payload["route_via"] == "agentveil-mcp-proxy client-config print"
    assert payload["adapter"]["doctor_supported"] is False
    assert payload["client_config_mutation"] is False
    assert payload["provider_native_client_proof"] is False
    assert_proxy_cli_json_is_privacy_safe(payload)
    _assert_no_client_config_mutation(project_root, isolated_home)


def test_client_config_mutation_false_everywhere(
    avp_home: Path,
    initialized_proxy: Path,
):
    for client_id in (*CLIENT_PACK_IDS, "unknown-client"):
        payload = build_client_runtime_payload(
            client_id=client_id,
            home=avp_home,
            config_path=avp_home / "mcp-proxy" / "config.json",
            passphrase_file=initialized_proxy,
        )
        assert payload["client_config_mutation"] is False


def test_launch_is_not_default_and_reports_error_for_unsupported_client(
    avp_home: Path,
    initialized_proxy: Path,
):
    dry = build_client_runtime_payload(
        client_id="codex",
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
        launch=False,
    )
    assert dry["executed"] is False
    assert dry["dry_run"] is True
    assert "errors" not in dry

    attempted = build_client_runtime_payload(
        client_id="codex",
        home=avp_home,
        config_path=avp_home / "mcp-proxy" / "config.json",
        passphrase_file=initialized_proxy,
        launch=True,
    )
    assert attempted["executed"] is False
    assert attempted["dry_run"] is False
    assert attempted["errors"]


def test_cli_client_run_json_is_privacy_bounded(
    avp_home: Path,
    initialized_proxy: Path,
    project_root: Path,
    isolated_home: Path,
    capsys,
):
    project_root.mkdir()
    assert (
        main([
            "client-run",
            "codex",
            "--home",
            str(avp_home),
            "--passphrase-file",
            str(initialized_proxy),
            "--json",
        ])
        == 0
    )
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["mode"] == "runtime_attach"
    assert payload["client_config_mutation"] is False
    assert_proxy_cli_json_is_privacy_safe(payload)
    _assert_no_local_path_leaks(json.dumps(payload))
    _assert_no_client_config_mutation(project_root, isolated_home)


def test_format_client_runtime_payload_is_privacy_bounded():
    payload = build_client_runtime_payload(
        client_id="cursor",
        home=Path("/Users/example/.avp"),
        config_path=Path("/Users/example/.avp/mcp-proxy/config.json"),
    )
    text = format_client_runtime_payload(payload)
    _assert_no_local_path_leaks(text)


def test_normalize_runtime_client_id_rejects_empty():
    with pytest.raises(ValueError, match="client id required"):
        normalize_runtime_client_id("   ")
