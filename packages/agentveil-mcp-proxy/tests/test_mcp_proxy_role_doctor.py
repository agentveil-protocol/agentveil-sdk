"""P10A.5 explain/redirect guidance and role doctor CLI proof."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import explain_role_proxy, init_proxy, main, run_proxy
from agentveil_mcp_proxy.role_doctor import (
    MUTATION_ACTION_FAMILIES,
    READ_ACTION_FAMILIES,
    build_role_doctor_report,
    build_role_preset_guide,
)
from agentveil_mcp_proxy.role_presets import ROLE_PRESET_NAMES

from mcp_fake_downstream import fake_target_reached, tool_entry, write_downstream


SECRET = "SECRET_ROLE_DOCTOR_PAYLOAD"


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
        "id": "role-doctor-call",
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
    decision: str = "allow",
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
        "id": "role-doctor-policy",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": fixture_id,
            "source": "user",
            "decision": decision,
            "risk_class": "write" if tool == "write_file" else "read",
            "match": {"server": "fake-downstream", "tool": tool},
        }],
    }
    _write_json(config_path, config)


def _privacy_clean(response_text: str) -> None:
    assert SECRET not in response_text


def _assert_redirect_fields(data: dict, *, call_id: str | None = None) -> None:
    assert isinstance(data.get("next_step"), str) and data["next_step"]
    assert isinstance(data.get("suggested_next_step_id"), str) and data["suggested_next_step_id"]
    assert isinstance(data.get("redirect_playbook_id"), str) and data["redirect_playbook_id"]
    assert data["suggested_next_step_id"] == data["redirect_playbook_id"]
    original_request_id = data.get("original_request_id")
    assert isinstance(original_request_id, str) and original_request_id
    if call_id is not None and data.get("status") != "approval_required":
        assert original_request_id == call_id
    if data.get("status") == "approval_required":
        assert original_request_id == data.get("record_id")
    redirect_context = data.get("redirect_context")
    assert isinstance(redirect_context, dict)
    assert redirect_context["original_request_id"] == original_request_id
    assert redirect_context["redirect_playbook_id"] == data["redirect_playbook_id"]
    redirect_automation = data.get("redirect_automation")
    assert isinstance(redirect_automation, dict)
    assert redirect_automation["original_executed"] is False
    assert redirect_automation["follow_up_required"] is (
        data["redirect_playbook_id"] != "stop_and_classify_unknown_action"
    )


@pytest.mark.parametrize("preset_name", ROLE_PRESET_NAMES)
def test_role_preset_guide_lists_action_families(preset_name: str):
    guide = build_role_preset_guide(preset_name)
    assert guide.preset == preset_name
    assert guide.allowed_action_families
    assert guide.approval_required_action_families
    if preset_name in {"reviewer", "readonly"}:
        assert guide.blocked_action_families == MUTATION_ACTION_FAMILIES
        assert READ_ACTION_FAMILIES[0] in guide.allowed_action_families
    else:
        assert guide.blocked_action_families == ()


def test_explain_role_cli_all_presets(tmp_path, capsys):
    assert main(["explain", "role", "--preset", "reviewer"]) == 0
    output = capsys.readouterr().out
    assert "Allowed action families" in output
    # claim-check: allow "Blocked" is the literal bounded role-doctor label.
    assert "Blocked action families" in output
    assert SECRET not in output


@pytest.mark.parametrize("preset_name", ROLE_PRESET_NAMES)
def test_explain_role_cli_each_preset(preset_name: str, capsys):
    assert explain_role_proxy(preset=preset_name) == 0
    output = capsys.readouterr().out
    assert f"Preset: {preset_name}" in output
    assert "Approval-required action families" in output


def test_explain_role_cli_reads_config_preset(tmp_path, capsys):
    home = tmp_path / "home"
    result = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="build")
    assert main(["explain", "role", "--home", str(home), "--config", str(result.config_path)]) == 0
    output = capsys.readouterr().out
    assert "Preset: build" in output


def test_explain_role_json_output(capsys):
    assert main(["explain", "role", "--preset", "implementer", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["role_doctor"]["preset"] == "implementer"
    assert "allowed_action_families" in payload["role_doctor"]


def test_reviewer_write_deny_is_human_readable_with_redirect(tmp_path, monkeypatch):
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
        fixture_id="doctor-reviewer-write",
        tool="write_file",
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("redirect guidance must not execute downstream target")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response_text = client_out.getvalue()
    response = _responses(response_text)[0]
    data = response["error"]["data"]
    assert data["reason"] == "role_authority_denied"
    assert "Review Agent cannot write files" in data["explanation"]
    assert "Review Agent cannot write files" in response["error"]["message"]
    _assert_redirect_fields(data, call_id="role-doctor-call")
    assert data["redirect_playbook_id"] == "create_implementer_task"
    assert not fake_target_reached(outcome_path)
    _privacy_clean(response_text)


def test_readonly_mutation_deny_is_human_readable_with_redirect(tmp_path, monkeypatch):
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
        fixture_id="doctor-readonly-write",
        tool="write_file",
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("redirect guidance must not execute downstream target")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response_text = client_out.getvalue()
    response = _responses(response_text)[0]
    data = response["error"]["data"]
    assert data["reason"] == "role_authority_denied"
    assert "Read-only Agent cannot modify files" in data["explanation"]
    _assert_redirect_fields(data, call_id="role-doctor-call")
    assert data["redirect_playbook_id"] == "use_read_only_tool"
    assert not fake_target_reached(outcome_path)
    _privacy_clean(response_text)


def test_approval_required_includes_request_approval_redirect(tmp_path, monkeypatch):
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
        fixture_id="doctor-approval-write",
        tool="write_file",
        decision="approval",
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("approval redirect must not execute downstream target")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response_text = client_out.getvalue()
    response = _responses(response_text)[0]
    data = response["error"]["data"]
    assert data["status"] == "approval_required"
    assert "Approval is required" in data["explanation"]
    _assert_redirect_fields(data)
    assert data["redirect_playbook_id"] == "request_approval"
    assert not fake_target_reached(outcome_path)
    _privacy_clean(response_text)


def test_unknown_high_risk_block_maps_to_stop_and_classify(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="implementer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(tmp_path, tools=[tool_entry("mystery_action")], controlled_path=True)
    _configure_downstream(
        init.config_path,
        downstream=downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="doctor-unknown-action",
        tool="mystery_action",
        decision="block",
    )
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["policy"]["default_decision"] = "block"
    config["policy"]["default_risk_class"] = "unknown"
    config["policy"]["rules"][0]["risk_class"] = "unknown"
    _write_json(init.config_path, config)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("unknown action redirect must not execute downstream target")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("mystery_action")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response_text = client_out.getvalue()
    response = _responses(response_text)[0]
    data = response["error"]["data"]
    assert "Unknown action denied" in data["explanation"]
    _assert_redirect_fields(data, call_id="role-doctor-call")
    assert data["redirect_playbook_id"] == "stop_and_classify_unknown_action"
    assert not fake_target_reached(outcome_path)
    _privacy_clean(response_text)


def test_build_role_doctor_report_all_presets():
    report = build_role_doctor_report()
    assert len(report["presets"]) == len(ROLE_PRESET_NAMES)
