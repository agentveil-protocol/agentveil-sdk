"""P10A.4 role preset init/client-config/run path without hand-edited JSON."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import init_proxy, main, print_client_configs, proxy_paths, run_proxy
from agentveil_mcp_proxy.client_config import build_run_args, read_role_preset_from_config
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata
from agentveil_mcp_proxy.role_presets import (
    ROLE_PRESET_ENV_VAR,
    apply_role_preset_to_config_payload,
    resolve_role_preset,
    role_authority_dict_for_preset,
)

from mcp_fake_downstream import fake_target_reached, tool_entry, write_downstream


SECRET = "SECRET_ROLE_PRESET_PAYLOAD"


@pytest.fixture(autouse=True)
def _suppress_browser_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webbrowser, "open", lambda *_args, **_kwargs: False)


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _tool_call(tool: str) -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "role-preset-call",
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"path": "workspace/note.txt", "secret": SECRET},
        },
    })


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)


def _configure_downstream(
    config_path: Path,
    *,
    downstream: Path,
    log_path: Path,
    outcome_path: Path,
    fixture_id: str,
    tool: str,
) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "fake-downstream",
        "command": sys.executable,
        "args": ["-u", str(downstream)],
        "env": {
            "DOWNSTREAM_LOG": str(log_path),
            "FAKE_TARGET_OUTCOME_LOG": str(outcome_path),
            "FAKE_TARGET_FIXTURE": fixture_id,
        },
    }
    config["policy"] = {
        "id": "role-preset-policy",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": fixture_id,
            "source": "user",
            "decision": "allow",
            "risk_class": "write" if tool == "write_file" else "read",
            "match": {"server": "fake-downstream", "tool": tool},
        }],
    }
    _write_json(config_path, config)


@pytest.mark.parametrize(
    ("preset_name", "expected_role", "expected_authority"),
    [
        ("reviewer", "reviewer", "review_only"),
        ("readonly", "readonly", "read_only"),
        ("implementer", "implementer", "implement"),
        ("build", "build", "build"),
    ],
)
def test_init_role_preset_writes_role_authority(tmp_path, preset_name, expected_role, expected_authority):
    home = tmp_path / "home"
    result = init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        role_preset=preset_name,
    )
    config = json.loads(result.config_path.read_text(encoding="utf-8"))
    assert config["role_preset"] == preset_name
    assert config["role_authority"] == role_authority_dict_for_preset(preset_name)
    assert config["role_authority"]["role"] == expected_role
    assert config["role_authority"]["authority"] == expected_authority
    assert SECRET not in result.config_path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("preset_name", "expected_role", "expected_authority"),
    [
        ("reviewer", "reviewer", "review_only"),
        ("readonly", "readonly", "read_only"),
        ("implementer", "implementer", "implement"),
        ("build", "build", "build"),
    ],
)
def test_main_init_role_flag_writes_expected_preset_config(
    tmp_path,
    preset_name,
    expected_role,
    expected_authority,
):
    home = tmp_path / "home"
    assert main([
        "init",
        "--role", preset_name,
        "--home", str(home),
        "--agent-name", "proxy",
        "--plaintext",
    ]) == 0

    config = json.loads(proxy_paths(home).config_path.read_text(encoding="utf-8"))
    assert config["role_preset"] == preset_name
    assert config["role_authority"]["role"] == expected_role
    assert config["role_authority"]["authority"] == expected_authority


def test_main_init_requires_role_flag(tmp_path, capsys):
    home = tmp_path / "home"
    with pytest.raises(SystemExit):
        main([
            "init",
            "--home", str(home),
            "--agent-name", "proxy",
            "--plaintext",
        ])
    err = capsys.readouterr().err
    assert "--role" in err


def test_client_config_points_at_generated_preset_config(tmp_path, capsys):
    home = tmp_path / "home"
    result = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    out = io.StringIO()
    print_client_configs(
        clients=["cursor"],
        home=home,
        config_path=result.config_path,
        output_json=True,
        out=out,
    )
    payload = json.loads(out.getvalue())
    assert payload["config_path"] == str(result.config_path)
    assert payload["role_preset"] == "reviewer"
    run_args = payload["args"]
    assert "--config" in run_args
    assert str(result.config_path) in run_args
    rendered = json.dumps(payload)
    assert SECRET not in rendered


def test_reviewer_preset_denies_write_before_fake_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(tmp_path, tools=[tool_entry("write_file")], controlled_path=True)
    _configure_downstream(
        init.config_path,
        downstream=downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="preset-reviewer-write",
        tool="write_file",
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("reviewer preset must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    assert _responses(client_out.getvalue())[0]["error"]["data"]["reason"] == "role_authority_denied"
    assert not fake_target_reached(outcome_path)


def test_readonly_preset_denies_write_before_fake_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="readonly")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(tmp_path, tools=[tool_entry("write_file")], controlled_path=True)
    _configure_downstream(
        init.config_path,
        downstream=downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="preset-readonly-write",
        tool="write_file",
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("readonly preset must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    assert _responses(client_out.getvalue())[0]["error"]["data"]["reason"] == "role_authority_denied"
    assert not fake_target_reached(outcome_path)


@pytest.mark.parametrize("preset_name", ["implementer", "build"])
def test_write_capable_preset_reaches_fake_target(tmp_path, monkeypatch, preset_name):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset=preset_name)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("write_file")],
        call_result_text=f"{preset_name}-ok",
        controlled_path=True,
    )
    _configure_downstream(
        init.config_path,
        downstream=downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id=f"preset-{preset_name}-write",
        tool="write_file",
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError(f"{preset_name} preset must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    assert _responses(client_out.getvalue())[0]["result"]["content"][0]["text"] == f"{preset_name}-ok"
    assert fake_target_reached(outcome_path)


def test_avp_proxy_role_env_override_blocks_write_for_reviewer(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="implementer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(tmp_path, tools=[tool_entry("write_file")], controlled_path=True)
    _configure_downstream(
        init.config_path,
        downstream=downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="preset-env-reviewer",
        tool="write_file",
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("env reviewer override must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    monkeypatch.setenv(ROLE_PRESET_ENV_VAR, "reviewer")
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    assert _responses(client_out.getvalue())[0]["error"]["data"]["reason"] == "role_authority_denied"
    assert not fake_target_reached(outcome_path)


def test_read_role_preset_from_config_reads_init_output(tmp_path):
    home = tmp_path / "home"
    result = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="build")
    assert read_role_preset_from_config(result.config_path) == "build"


def test_apply_role_preset_to_config_payload_matches_resolver():
    payload = apply_role_preset_to_config_payload({}, preset_name="reviewer")
    assert payload["role_authority"] == resolve_role_preset("reviewer").to_role_authority_dict()
    assert payload["role_preset"] == "reviewer"
