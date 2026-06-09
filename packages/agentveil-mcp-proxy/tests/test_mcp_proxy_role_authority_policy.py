"""P10A.3 role/authority policy gate proof for brokered MCP tools/call."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys

import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import init_proxy, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, build_evidence_bundle
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata
from agentveil_mcp_proxy.evidence.proof import EvidenceVerificationError, verify_evidence_bundle

from mcp_fake_downstream import fake_target_reached, tool_entry, write_downstream


SECRET = "SECRET_ROLE_AUTHORITY_PAYLOAD"


@pytest.fixture(autouse=True)
def _suppress_browser_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webbrowser, "open", lambda *_args, **_kwargs: False)


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)


def _tool_call(tool: str) -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "role-authority-call",
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"path": "workspace/note.txt", "secret": SECRET},
        },
    })


def _configure_proxy(
    config_path: Path,
    *,
    downstream: Path,
    log_path: Path,
    outcome_path: Path,
    fixture_id: str,
    role: str,
    authority: str,
    tool: str,
    decision: str,
    rule_id: str,
) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["role_authority"] = {
        "mode": "enforce",
        "role": role,
        "authority": authority,
    }
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
        "id": "role-authority-policy",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": rule_id,
            "source": "user",
            "decision": decision,
            "risk_class": "write" if tool == "write_file" else "read",
            "match": {"server": "fake-downstream", "tool": tool},
        }],
    }
    _write_json(config_path, config)


def _evidence_store(home: Path) -> ApprovalEvidenceStore:
    return ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite")


def _privacy_clean(*, outcome_path: Path, evidence_text: str, response_text: str) -> None:
    outcome_blob = outcome_path.read_text(encoding="utf-8") if outcome_path.exists() else ""
    assert SECRET not in outcome_blob
    assert SECRET not in evidence_text
    assert SECRET not in response_text


def test_reviewer_write_blocked_before_fake_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    fixture_id = "reviewer-write-denied"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("write_file")],
        controlled_path=True,
    )
    _configure_proxy(
        init.config_path,
        downstream=downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id=fixture_id,
        role="reviewer",
        authority="review_only",
        tool="write_file",
        decision="allow",
        rule_id=fixture_id,
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("reviewer write must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["data"]["reason"] == "role_authority_denied"
    assert not fake_target_reached(outcome_path)
    assert "tools/call" not in log_path.read_text(encoding="utf-8")

    with _evidence_store(home) as store:
        records = store.list_records()
        assert len(records) == 1
        metadata = parse_controlled_path_metadata(records[0])
        assert metadata["role"] == "reviewer"
        assert metadata["authority"] == "review_only"
        assert metadata["action_family"] == "write"
        assert metadata["target_reached"] is False
        bundle = build_evidence_bundle(store, proxy_identity_did=None, trusted_signer_dids=[])
        verify_evidence_bundle(bundle, trusted_signer_dids=[], strict=True)
        _privacy_clean(
            outcome_path=outcome_path,
            evidence_text=json.dumps(bundle),
            response_text=client_out.getvalue(),
        )


def test_reviewer_read_allowed_reaches_fake_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    fixture_id = "reviewer-read-allowed"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("read_file")],
        call_result_text="role-authority-read-ok",
        controlled_path=True,
    )
    _configure_proxy(
        init.config_path,
        downstream=downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id=fixture_id,
        role="reviewer",
        authority="review_only",
        tool="read_file",
        decision="allow",
        rule_id=fixture_id,
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("reviewer read must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("read_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["result"]["content"][0]["text"] == "role-authority-read-ok"
    assert fake_target_reached(outcome_path)

    with _evidence_store(home) as store:
        metadata = parse_controlled_path_metadata(store.list_records()[0])
        assert metadata["target_reached"] is True
        assert metadata["role"] == "reviewer"
        assert metadata["action_family"] == "read"


def test_implementer_write_allowed_reaches_fake_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    fixture_id = "implementer-write-allowed"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("write_file")],
        call_result_text="role-authority-write-ok",
        controlled_path=True,
    )
    _configure_proxy(
        init.config_path,
        downstream=downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id=fixture_id,
        role="implementer",
        authority="implement",
        tool="write_file",
        decision="allow",
        rule_id=fixture_id,
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("implementer write must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["result"]["content"][0]["text"] == "role-authority-write-ok"
    assert fake_target_reached(outcome_path)

    with _evidence_store(home) as store:
        metadata = parse_controlled_path_metadata(store.list_records()[0])
        assert metadata["target_reached"] is True
        assert metadata["role"] == "implementer"
        assert metadata["action_family"] == "write"


def test_strict_verifier_rejects_tampered_role_authority_metadata(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    fixture_id = "tamper-role-authority"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("read_file")],
        call_result_text="ok",
        controlled_path=True,
    )
    _configure_proxy(
        init.config_path,
        downstream=downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id=fixture_id,
        role="reviewer",
        authority="review_only",
        tool="read_file",
        decision="allow",
        rule_id=fixture_id,
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("tamper test must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("read_file")),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0

    with _evidence_store(home) as store:
        bundle = build_evidence_bundle(store, proxy_identity_did=None, trusted_signer_dids=[])
        verify_evidence_bundle(bundle, trusted_signer_dids=[], strict=True)
        bundle["records"][0]["action_gate_metadata"]["role"] = "implementer"
        with pytest.raises(EvidenceVerificationError, match="action_gate_metadata does not match"):
            verify_evidence_bundle(bundle, trusted_signer_dids=[], strict=True)
