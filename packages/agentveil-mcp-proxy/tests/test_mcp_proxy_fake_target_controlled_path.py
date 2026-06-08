"""P10A.2 fake-target controlled-path proof for brokered MCP tools/call."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

import httpx
import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus, build_evidence_bundle
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata
from agentveil_mcp_proxy.cli import init_proxy, run_proxy

from mcp_fake_downstream import (
    fake_target_reached,
    read_outcome_log,
    tool_entry,
    write_downstream,
)


SECRET = "SECRET_FAKE_TARGET_PAYLOAD"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


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


def _set_downstream(
    config_path: Path,
    script: Path,
    *,
    log_path: Path,
    outcome_path: Path,
    fixture_id: str,
) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "fake-downstream",
        "command": sys.executable,
        "args": ["-u", str(script)],
        "env": {
            "DOWNSTREAM_LOG": str(log_path),
            "FAKE_TARGET_OUTCOME_LOG": str(outcome_path),
            "FAKE_TARGET_FIXTURE": fixture_id,
        },
    }
    _write_json(config_path, config)


def _set_allow_policy(config_path: Path, *, server: str, tool: str, rule_id: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "fake-target-allow",
        "policy_schema_version": 1,
        "default_decision": "block",
        "default_risk_class": "read",
        "rules": [{
            "id": rule_id,
            "source": "user",
            "decision": "allow",
            "risk_class": "read",
            "match": {"server": server, "tool": tool},
        }],
    }
    _write_json(config_path, config)


def _set_block_policy(config_path: Path, *, server: str, tool: str, rule_id: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "fake-target-block",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": rule_id,
            "source": "user",
            "decision": "block",
            "risk_class": "write",
            "match": {"server": server, "tool": tool},
        }],
    }
    _write_json(config_path, config)


def _set_approval_policy(config_path: Path, *, server: str, tool: str, rule_id: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "fake-target-approval",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": rule_id,
            "source": "user",
            "decision": "approval",
            "risk_class": "write",
            "match": {"server": server, "tool": tool},
        }],
    }
    _write_json(config_path, config)


def _tool_call(tool: str, *, call_id: str = "call-1") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"path": "workspace/note.txt", "secret": SECRET},
        },
    })


def _evidence_store(home: Path) -> ApprovalEvidenceStore:
    return ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite")


def _privacy_clean(*, outcome_path: Path, evidence_text: str, response_text: str) -> None:
    outcome_blob = outcome_path.read_text(encoding="utf-8") if outcome_path.exists() else ""
    assert SECRET not in outcome_blob
    assert SECRET not in evidence_text
    assert SECRET not in response_text


class _StagedStdin(io.TextIOBase):
    """Char-oriented stdin that gates each line after the first."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = [
            line if line.endswith("\n") else f"{line}\n"
            for line in lines
        ]
        self._line_index = 0
        self._char_index = 0
        self._gate = threading.Event()
        self._gate.set()

    def read(self, size: int = -1) -> str:
        if size not in (-1, 1):
            raise io.UnsupportedOperation("only single-character reads are supported")
        if self._line_index >= len(self._lines):
            return ""
        self._gate.wait(timeout=30)
        if self._line_index >= len(self._lines):
            return ""
        line = self._lines[self._line_index]
        char = line[self._char_index]
        self._char_index += 1
        if self._char_index >= len(line):
            self._line_index += 1
            self._char_index = 0
            self._gate.clear()
        return char

    def release_next(self) -> None:
        self._gate.set()


def test_allow_reaches_fake_target_and_records_metadata(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    fixture_id = "allow-read-file"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("read_file")],
        call_result_text="fake-target-ok",
        controlled_path=True,
    )
    _set_downstream(init.config_path, downstream, log_path=log_path, outcome_path=outcome_path, fixture_id=fixture_id)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="read_file", rule_id=fixture_id)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("allow path must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("read_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response_text = client_out.getvalue()
    responses = _responses(response_text)
    assert responses[0]["result"]["content"][0]["text"] == "fake-target-ok"
    assert fake_target_reached(outcome_path)
    assert "tools/call" in log_path.read_text(encoding="utf-8")

    with _evidence_store(home) as store:
        records = store.list_records()
        assert len(records) == 1
        metadata = parse_controlled_path_metadata(records[0])
        assert metadata is not None
        assert metadata["fixture_id"] == fixture_id
        assert metadata["policy_decision"] == "allow"
        assert metadata["approval_status"] == ApprovalStatus.EXECUTED.value
        assert metadata["execution_status"] == ApprovalStatus.EXECUTED.value
        assert metadata["target_reached"] is True
        bundle = build_evidence_bundle(store, proxy_identity_did=None, trusted_signer_dids=[])
        _privacy_clean(
            outcome_path=outcome_path,
            evidence_text=json.dumps(bundle),
            response_text=response_text,
        )


def test_block_does_not_reach_fake_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    fixture_id = "block-write-file"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("write_file")],
        controlled_path=True,
    )
    _set_downstream(init.config_path, downstream, log_path=log_path, outcome_path=outcome_path, fixture_id=fixture_id)
    _set_block_policy(init.config_path, server="fake-downstream", tool="write_file", rule_id=fixture_id)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("block path must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response_text = client_out.getvalue()
    assert _responses(response_text)[0]["error"]["data"]["reason"] == "local_policy_block"
    assert not fake_target_reached(outcome_path)
    assert "tools/call" not in log_path.read_text(encoding="utf-8")

    with _evidence_store(home) as store:
        records = store.list_records()
        assert len(records) == 1
        metadata = parse_controlled_path_metadata(records[0])
        assert metadata["policy_decision"] == "block"
        assert metadata["target_reached"] is False
        assert metadata["execution_status"] == "not_reached"
        _privacy_clean(
            outcome_path=outcome_path,
            evidence_text=json.dumps(build_evidence_bundle(store, proxy_identity_did=None, trusted_signer_dids=[])),
            response_text=response_text,
        )


def test_approval_pending_does_not_reach_fake_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    fixture_id = "approval-write-file"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("write_file")],
        controlled_path=True,
    )
    _set_downstream(init.config_path, downstream, log_path=log_path, outcome_path=outcome_path, fixture_id=fixture_id)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file", rule_id=fixture_id)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("approval pending must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file")),
        out=client_out,
        approval_ui_mode="none",
    ) == 0

    response_text = client_out.getvalue()
    error = _responses(response_text)[0]["error"]
    assert error["data"]["status"] == "approval_required"
    assert not fake_target_reached(outcome_path)
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]

    with _evidence_store(home) as store:
        records = store.list_records()
        assert len(records) == 1
        metadata = parse_controlled_path_metadata(records[0])
        assert metadata["policy_decision"] == "approval"
        assert metadata["approval_status"] == ApprovalStatus.PENDING.value
        assert metadata["target_reached"] is False
        _privacy_clean(
            outcome_path=outcome_path,
            evidence_text=json.dumps(build_evidence_bundle(store, proxy_identity_did=None, trusted_signer_dids=[])),
            response_text=response_text,
        )


def test_approval_retry_reaches_fake_target_after_approve(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    fixture_id = "approval-retry-write-file"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("write_file")],
        call_result_text="fake-target-approved",
        controlled_path=True,
    )
    _set_downstream(init.config_path, downstream, log_path=log_path, outcome_path=outcome_path, fixture_id=fixture_id)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file", rule_id=fixture_id)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("approval retry must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    staged_in = _StagedStdin([
        _tool_call("write_file", call_id="call-pending"),
        _tool_call("write_file", call_id="call-retry"),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=staged_in,
            out=client_out,
            approval_ui_mode="none",
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if client_out.getvalue().strip():
                break
            time.sleep(0.02)
        first_response = _responses(client_out.getvalue())[0]
        approval_url = first_response["error"]["data"]["approval_url"]
        assert first_response["error"]["data"]["status"] == "approval_required"
        assert not fake_target_reached(outcome_path)

        with httpx.Client() as client:
            page = client.get(approval_url)
            page.raise_for_status()
            match = CSRF_RE.search(page.text)
            assert match is not None
            client.post(approval_url, data={
                "decision": "approve",
                "approval_scope": "exact",
                "csrf_token": match.group(1),
            }).raise_for_status()

        approved_deadline = time.monotonic() + 5
        with _evidence_store(home) as store:
            pending_id = first_response["error"]["data"]["record_id"]
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < approved_deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
            assert record.status == ApprovalStatus.APPROVED.value

        staged_in.release_next()
        worker.join(timeout=10)
        assert not worker.is_alive()

        responses = _responses(client_out.getvalue())
        assert len(responses) == 2
        retry_response = responses[1]
        assert retry_response["result"]["content"][0]["text"] == "fake-target-approved"
        assert fake_target_reached(outcome_path)
        reached_rows = [
            row for row in read_outcome_log(outcome_path)
            if row.get("method") == "tools/call" and row.get("outcome") == "reached"
        ]
        assert len(reached_rows) == 1

        with _evidence_store(home) as store:
            executed = [
                record for record in store.list_records()
                if record.status == ApprovalStatus.EXECUTED.value
            ]
            assert len(executed) == 1
            metadata = parse_controlled_path_metadata(executed[0])
            assert metadata["target_reached"] is True
            assert metadata["execution_status"] == ApprovalStatus.EXECUTED.value
            _privacy_clean(
                outcome_path=outcome_path,
                evidence_text=json.dumps(build_evidence_bundle(store, proxy_identity_did=None, trusted_signer_dids=[])),
                response_text=client_out.getvalue(),
            )
    finally:
        staged_in.release_next()
        worker.join(timeout=1)
