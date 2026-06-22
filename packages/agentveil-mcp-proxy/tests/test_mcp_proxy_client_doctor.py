"""Tests for optional client-pack doctor health checks."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest
import webbrowser

from agentveil_mcp_proxy.cli import init_proxy, main, quickstart_filesystem_downstream, run_client_doctor_cli
from agentveil_mcp_proxy.client_doctor import (
    assert_client_doctor_output_is_privacy_safe,
    build_client_doctor_report,
)
from agentveil_mcp_proxy.client_guidance import build_client_guidance_payload


PASSPHRASE = "client-doctor-test-passphrase"
LOCAL_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/", "/tmp/")


@pytest.fixture(autouse=True)
def _suppress_browser_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webbrowser, "open", lambda *_args, **_kwargs: False)


def _init_quickstart(home: Path, sandbox: Path, passphrase_file: Path) -> None:
    init_proxy(
        home=home,
        agent_name="proxy",
        passphrase_file=passphrase_file,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )


def _assert_no_local_path_leaks(text: str) -> None:
    for marker in LOCAL_PATH_MARKERS:
        assert marker not in text, f"unexpected local path marker {marker!r}"
    assert PASSPHRASE not in text


def test_client_guidance_payload_is_privacy_bounded():
    payload = build_client_guidance_payload(client_id="cursor")
    assert payload["privacy_bounded"] is True
    assert "choose role" not in json.dumps(payload).lower()
    _assert_no_local_path_leaks(json.dumps(payload))


def test_client_doctor_full_path_reaches_routed_read(tmp_path, runnable_proxy_command: str):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(PASSPHRASE + "\n", encoding="utf-8")
    os.chmod(passphrase_file, 0o600)
    _init_quickstart(home, sandbox, passphrase_file)

    payload = build_client_doctor_report(
        client_id="cursor",
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=runnable_proxy_command,
    )
    assert payload["ok"] is True
    assert payload["diagnostic_status"] == "ok"
    assert payload["proof_mode"] == "generated_config_proxy_path"
    assert payload["provider_native_client_proof"] is False
    assert payload["checks"]["generated_command_available"]["ok"] is True
    assert payload["checks"]["generated_command_probe"]["ok"] is True
    assert payload["checks"]["tools_list_reachable"]["ok"] is True
    assert payload["checks"]["routed_read_action"]["target_reached"] is True
    assert_client_doctor_output_is_privacy_safe(payload)
    _assert_no_local_path_leaks(json.dumps(payload))


def test_client_doctor_runnable_source_command_is_cwd_independent(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    runnable_proxy_command: str,
):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    unrelated_cwd = tmp_path / "other-cwd"
    sandbox.mkdir()
    unrelated_cwd.mkdir()
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(PASSPHRASE + "\n", encoding="utf-8")
    os.chmod(passphrase_file, 0o600)
    _init_quickstart(home, sandbox, passphrase_file)

    monkeypatch.chdir(unrelated_cwd)
    payload = build_client_doctor_report(
        client_id="codex",
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=runnable_proxy_command,
    )

    assert payload["ok"] is True
    assert payload["diagnostic_status"] == "ok"
    assert payload["checks"]["tools_list_reachable"]["ok"] is True
    assert payload["checks"]["routed_read_action"]["target_reached"] is True
    _assert_no_local_path_leaks(json.dumps(payload))


def test_client_doctor_list_only_returns_bounded_diagnostic(tmp_path, runnable_proxy_command: str):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(PASSPHRASE + "\n", encoding="utf-8")
    os.chmod(passphrase_file, 0o600)
    _init_quickstart(home, sandbox, passphrase_file)

    payload = build_client_doctor_report(
        client_id="claude_code",
        home=home,
        passphrase_file=passphrase_file,
        list_only=True,
        proxy_command=runnable_proxy_command,
    )
    assert payload["ok"] is True
    assert payload["diagnostic_status"] == "tools_list_only"
    assert payload["checks"]["tools_list_reachable"]["ok"] is True
    assert payload["checks"]["routed_read_action"]["skipped"] is True
    assert "routed action" in payload["next_step"].lower()
    _assert_no_local_path_leaks(json.dumps(payload))


def test_client_doctor_rejects_missing_generated_command(tmp_path):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(PASSPHRASE + "\n", encoding="utf-8")
    os.chmod(passphrase_file, 0o600)
    _init_quickstart(home, sandbox, passphrase_file)

    payload = build_client_doctor_report(
        client_id="cursor",
        home=home,
        passphrase_file=passphrase_file,
        proxy_command="/definitely/missing/agentveil-mcp-proxy",
    )
    assert payload["ok"] is False
    assert payload["diagnostic_status"] == "config_command_unavailable"
    assert payload["checks"]["generated_command_available"]["ok"] is False
    assert "generated_command_probe" not in payload["checks"]
    _assert_no_local_path_leaks(json.dumps(payload))


def test_cli_client_doctor_json_for_codex_manual_pack(tmp_path, capsys, runnable_proxy_command: str):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(PASSPHRASE + "\n", encoding="utf-8")
    os.chmod(passphrase_file, 0o600)
    _init_quickstart(home, sandbox, passphrase_file)

    code = run_client_doctor_cli(
        client_id="codex",
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=runnable_proxy_command,
        output_json=True,
        out=io.StringIO(),
    )
    assert code == 0
    assert main([
        "client-doctor",
        "--client",
        "codex",
        "--home",
        str(home),
        "--passphrase-file",
        str(passphrase_file),
        "--proxy-command",
        runnable_proxy_command,
        "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["support_status"] == "supported"
    assert payload["checks"]["config_generated"]["config_surface"] == "codex_config_toml"
    _assert_no_local_path_leaks(json.dumps(payload))
