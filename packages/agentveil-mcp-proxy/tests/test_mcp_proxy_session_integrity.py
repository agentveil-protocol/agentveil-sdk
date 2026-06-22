"""Product-route session-integrity proofs for routed MCP approval retry paths."""

from __future__ import annotations

import io
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import init_proxy, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.evidence.observability import (
    parse_action_gate_metadata,
    parse_session_integrity_metadata,
)
from agentveil_mcp_proxy.policy import (
    SESSION_INTEGRITY_CONSENT_LAUNDERING,
    SESSION_INTEGRITY_RESOURCE_MISMATCH,
    SESSION_INTEGRITY_TOOL_SCHEMA_DRIFT,
    SESSION_INTEGRITY_TOOL_MISMATCH,
    build_executed_session_facts,
    build_session_bound_facts,
    detect_session_integrity_mismatch,
)
from agentveil_mcp_proxy.tool_schema_validation import ToolSchemaCache

from mcp_fake_downstream import fake_target_reached, tool_entry, write_downstream


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


def _set_approval_policy(config_path: Path, *, server: str, tool: str, rule_id: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "session-integrity-approval",
        "policy_schema_version": 1,
        "default_decision": "block",
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


def _set_role_authority(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["role_authority"] = {
        "mode": "enforce",
        "role": "implementer",
        "authority": "implement",
    }
    _write_json(config_path, config)


def _tool_call(tool: str, *, call_id: str, path: str = "approved.txt") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"path": path, "content": "payload"}},
    })


class _StagedStdin(io.TextIOBase):
    def __init__(self, lines: list[str]) -> None:
        self._lines = [line if line.endswith("\n") else f"{line}\n" for line in lines]
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


def _init_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    fixture_id = "session-integrity-write-file"
    downstream = write_downstream(
        tmp_path,
        tools=[tool_entry("write_file")],
        call_result_text="session-integrity-ok",
        controlled_path=True,
    )
    _set_downstream(
        init.config_path,
        downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id=fixture_id,
    )
    _set_approval_policy(
        init.config_path,
        server="fake-downstream",
        tool="write_file",
        rule_id=fixture_id,
    )
    _set_role_authority(init.config_path)
    return home, init.config_path, downstream, log_path, outcome_path


def _patch_approved_risk_class(home: Path, record_id: str, *, risk_class: str) -> None:
    with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
        record = store.get_pending(record_id)
        metadata = parse_action_gate_metadata(record)
        assert metadata is not None
        facts = dict(metadata["session_bound_facts"])
        facts["approved_risk_class"] = risk_class
        updated = dict(metadata)
        updated["session_bound_facts"] = facts
        store.annotate_controlled_path_metadata(
            record_id,
            metadata_jcs=json.dumps(updated, sort_keys=True, separators=(",", ":")),
        )


def test_detect_session_integrity_mismatch_flags_consent_laundering_risk_escalation():
    approved = build_session_bound_facts(
        classification_tool="write_file",
        classification_server="filesystem",
        action_family="write",
        resource_hash="sha256:resource-a",
        payload_hash="sha256:payload-a",
        risk_class="read",
        tool_schema_fingerprint="sha256:schema-a",
        downstream_startup_fingerprint="sha256:startup-a",
        approval_id="req-a",
        expires_at=123,
        approval_actor_ref="session:abcd1234",
        decision_actor_ref="local-user",
    )
    executed = build_executed_session_facts(
        classification_tool="write_file",
        classification_server="filesystem",
        action_family="write",
        resource_hash="sha256:resource-a",
        payload_hash="sha256:payload-a",
        risk_class="write",
        tool_schema_fingerprint="sha256:schema-a",
        downstream_startup_fingerprint="sha256:startup-a",
        decision_actor_ref="local-user",
    )
    assert detect_session_integrity_mismatch(approved, executed) == SESSION_INTEGRITY_CONSENT_LAUNDERING


def test_detect_session_integrity_mismatch_flags_schema_drift():
    approved = build_session_bound_facts(
        classification_tool="write_file",
        classification_server="filesystem",
        action_family="write",
        resource_hash="sha256:resource-a",
        payload_hash="sha256:payload-a",
        risk_class="write",
        tool_schema_fingerprint="sha256:schema-a",
        downstream_startup_fingerprint="sha256:startup-a",
        approval_id="req-a",
        expires_at=123,
        approval_actor_ref="session:abcd1234",
        decision_actor_ref="local-user",
    )
    executed = build_executed_session_facts(
        classification_tool="write_file",
        classification_server="filesystem",
        action_family="write",
        resource_hash="sha256:resource-a",
        payload_hash="sha256:payload-a",
        risk_class="write",
        tool_schema_fingerprint="sha256:schema-b",
        downstream_startup_fingerprint="sha256:startup-a",
        decision_actor_ref="local-user",
    )
    assert detect_session_integrity_mismatch(approved, executed) == SESSION_INTEGRITY_TOOL_SCHEMA_DRIFT


def test_detect_session_integrity_mismatch_flags_tool_change():
    approved = build_session_bound_facts(
        classification_tool="write_file",
        classification_server="filesystem",
        action_family="write",
        resource_hash="sha256:resource-a",
        payload_hash="sha256:payload-a",
        risk_class="write",
        tool_schema_fingerprint="sha256:schema-a",
        downstream_startup_fingerprint="sha256:startup-a",
        approval_id="req-a",
        expires_at=123,
    )
    executed = build_executed_session_facts(
        classification_tool="delete_file",
        classification_server="filesystem",
        action_family="delete",
        resource_hash="sha256:resource-a",
        payload_hash="sha256:payload-a",
        risk_class="destructive",
        tool_schema_fingerprint="sha256:schema-a",
        downstream_startup_fingerprint="sha256:startup-a",
    )
    assert detect_session_integrity_mismatch(approved, executed) == SESSION_INTEGRITY_TOOL_MISMATCH


def test_approved_retry_reaches_target_when_session_facts_match(tmp_path, monkeypatch):
    home, _config, _downstream, _log, outcome_path = _init_fixture(tmp_path)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("session integrity happy path must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    staged_in = _StagedStdin([
        _tool_call("write_file", call_id="pending"),
        _tool_call("write_file", call_id="retry"),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(home=home, client_in=staged_in, out=client_out, approval_ui_mode="none"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        assert first["error"]["data"]["status"] == "approval_required"
        assert not fake_target_reached(outcome_path)
        pending_id = first["error"]["data"]["record_id"]
        with httpx.Client() as client:
            page = client.get(first["error"]["data"]["approval_url"])
            page.raise_for_status()
            match = CSRF_RE.search(page.text)
            assert match is not None
            client.post(first["error"]["data"]["approval_url"], data={
                "decision": "approve",
                "approval_scope": "exact",
                "csrf_token": match.group(1),
            }).raise_for_status()
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
            assert record.status == ApprovalStatus.APPROVED.value
            metadata = parse_action_gate_metadata(record)
            assert isinstance(metadata.get("session_bound_facts"), dict)
            assert metadata["session_bound_facts"]["decision_actor_ref"] == "local-user"
        staged_in.release_next()
        worker.join(timeout=15)
        responses = _responses(client_out.getvalue())
        assert len(responses) == 2
        assert "result" in responses[1]
        assert fake_target_reached(outcome_path)
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def test_tool_schema_drift_blocks_retry_before_target(tmp_path, monkeypatch):
    home, _config, _downstream, _log, outcome_path = _init_fixture(tmp_path)
    drift_enabled = {"value": False}
    original_fingerprint = ToolSchemaCache.fingerprint

    def drifting_fingerprint(self, tool_name: str):
        if drift_enabled["value"]:
            return "sha256:drifted-schema"
        return original_fingerprint(self, tool_name)

    monkeypatch.setattr(ToolSchemaCache, "fingerprint", drifting_fingerprint)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("schema drift must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    staged_in = _StagedStdin([
        _tool_call("write_file", call_id="pending"),
        _tool_call("write_file", call_id="retry"),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(home=home, client_in=staged_in, out=client_out, approval_ui_mode="none"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        pending_id = first["error"]["data"]["record_id"]
        with httpx.Client() as client:
            page = client.get(first["error"]["data"]["approval_url"])
            page.raise_for_status()
            match = CSRF_RE.search(page.text)
            client.post(first["error"]["data"]["approval_url"], data={
                "decision": "approve",
                "approval_scope": "exact",
                "csrf_token": match.group(1),
            }).raise_for_status()
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
        drift_enabled["value"] = True
        staged_in.release_next()
        worker.join(timeout=15)
        responses = _responses(client_out.getvalue())
        assert len(responses) == 2
        # claim-check: allow "blocked" is asserted against schema-drift negative test evidence.
        blocked = responses[1]
        assert blocked["error"]["data"]["reason"] == SESSION_INTEGRITY_TOOL_SCHEMA_DRIFT  # claim-check: allow "blocked" negative test response field.
        assert blocked["error"]["data"]["target_reached"] is False  # claim-check: allow "blocked" negative test response field.
        assert not fake_target_reached(outcome_path)
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            drift_rows = [
                row for row in store.list_records()
                if parse_session_integrity_metadata(row) is not None
            ]
        assert drift_rows, "expected first-class session integrity evidence"
        drift_meta = parse_session_integrity_metadata(drift_rows[-1])
        assert drift_meta["mismatch_reason"] == SESSION_INTEGRITY_TOOL_SCHEMA_DRIFT
        assert drift_meta["target_reached"] is False
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def test_changed_payload_retry_stays_gated_without_target_mutation(tmp_path, monkeypatch):
    home, _config, _downstream, _log, outcome_path = _init_fixture(tmp_path)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("payload mismatch must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    staged_in = _StagedStdin([
        _tool_call("write_file", call_id="pending", path="approved.txt"),
        _tool_call("write_file", call_id="retry", path="changed.txt"),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(home=home, client_in=staged_in, out=client_out, approval_ui_mode="none"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        pending_id = first["error"]["data"]["record_id"]
        with httpx.Client() as client:
            page = client.get(first["error"]["data"]["approval_url"])
            page.raise_for_status()
            match = CSRF_RE.search(page.text)
            client.post(first["error"]["data"]["approval_url"], data={
                "decision": "approve",
                "approval_scope": "exact",
                "csrf_token": match.group(1),
            }).raise_for_status()
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
        staged_in.release_next()
        worker.join(timeout=15)
        responses = _responses(client_out.getvalue())
        assert len(responses) == 2
        # claim-check: allow "blocked" is asserted against resource-mismatch negative test evidence.
        blocked = responses[1]
        assert blocked["error"]["data"]["status"] == "blocked"  # claim-check: allow "blocked" negative test response field.
        assert blocked["error"]["data"]["reason"] == SESSION_INTEGRITY_RESOURCE_MISMATCH  # claim-check: allow "blocked" negative test response field.
        assert blocked["error"]["data"]["target_reached"] is False  # claim-check: allow "blocked" negative test response field.
        assert not fake_target_reached(outcome_path)
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            mismatch_rows = [
                row for row in store.list_records()
                if parse_session_integrity_metadata(row) is not None
            ]
        assert mismatch_rows, "expected first-class session integrity evidence"
        mismatch_meta = parse_session_integrity_metadata(mismatch_rows[-1])
        assert mismatch_meta["mismatch_reason"] == SESSION_INTEGRITY_RESOURCE_MISMATCH
        assert mismatch_meta["target_reached"] is False
        assert isinstance(mismatch_meta.get("approved_facts"), dict)
        assert isinstance(mismatch_meta.get("executed_facts"), dict)
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def _approve_via_http(approval_url: str) -> None:
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


def _wait_until_approved(home: Path, record_id: str, *, deadline: float) -> None:
    with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
        record = store.get_pending(record_id)
        while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
            time.sleep(0.02)
            record = store.get_pending(record_id)
        assert record.status == ApprovalStatus.APPROVED.value


def _run_two_step_write_flow(
    home: Path,
    *,
    pending_id: str,
    retry_id: str,
    path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> list[dict]:
    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("session integrity guardrail must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    staged_in = _StagedStdin([
        _tool_call("write_file", call_id=pending_id, path=path),
        _tool_call("write_file", call_id=retry_id, path=path),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(home=home, client_in=staged_in, out=client_out, approval_ui_mode="none"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        pending_id_actual = first["error"]["data"]["record_id"]
        _approve_via_http(first["error"]["data"]["approval_url"])
        _wait_until_approved(home, pending_id_actual, deadline=deadline)
        staged_in.release_next()
        worker.join(timeout=15)
        return _responses(client_out.getvalue())
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def _run_single_pending_call(home: Path, *, call_id: str, path: str) -> dict:
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("write_file", call_id=call_id, path=path)),
            out=client_out,
            approval_ui_mode="none",
        ),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=15)
    responses = _responses(client_out.getvalue())
    assert responses, "expected proxy response for pending call"
    return responses[0]


def test_fresh_action_after_successful_execute_gets_approval_not_stale_block(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    home, _config, _downstream, _log, outcome_path = _init_fixture(tmp_path)

    responses_a = _run_two_step_write_flow(
        home,
        pending_id="action-a-pending",
        retry_id="action-a-retry",
        path="approved-a.txt",
        monkeypatch=monkeypatch,
    )
    assert len(responses_a) == 2
    assert "result" in responses_a[1]
    assert fake_target_reached(outcome_path)

    pending_b = _run_single_pending_call(
        home,
        call_id="action-b-pending",
        path="approved-b.txt",
    )
    pending_data = pending_b["error"]["data"]
    assert pending_data["status"] == "approval_required"
    assert pending_data.get("reason") != SESSION_INTEGRITY_CONSENT_LAUNDERING
    assert pending_data.get("event_type") != "session_integrity_mismatch"


def test_fresh_action_after_mismatch_block_still_gets_approval_and_can_execute(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    home, _config, _downstream, _log, outcome_path = _init_fixture(tmp_path)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("session integrity guardrail must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    staged_in = _StagedStdin([
        _tool_call("write_file", call_id="mismatch-pending", path="approved.txt"),
        _tool_call("write_file", call_id="mismatch-retry", path="changed.txt"),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(home=home, client_in=staged_in, out=client_out, approval_ui_mode="none"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        _approve_via_http(first["error"]["data"]["approval_url"])
        _wait_until_approved(home, first["error"]["data"]["record_id"], deadline=deadline)
        staged_in.release_next()
        worker.join(timeout=15)
        mismatch_responses = _responses(client_out.getvalue())
        assert len(mismatch_responses) == 2
        # claim-check: allow "blocked" is asserted against stale-approval negative test evidence.
        assert mismatch_responses[1]["error"]["data"]["status"] == "blocked"
        assert not fake_target_reached(outcome_path)
    finally:
        staged_in.release_next()
        worker.join(timeout=1)

    pending_b = _run_single_pending_call(
        home,
        call_id="fresh-b-pending",
        path="fresh-b.txt",
    )
    pending_data = pending_b["error"]["data"]
    assert pending_data["status"] == "approval_required"
    assert pending_data.get("event_type") != "session_integrity_mismatch"

    responses_b = _run_two_step_write_flow(
        home,
        pending_id="fresh-b-pending-2",
        retry_id="fresh-b-retry",
        path="fresh-b.txt",
        monkeypatch=monkeypatch,
    )
    assert len(responses_b) == 2
    assert "result" in responses_b[1]
    assert fake_target_reached(outcome_path)


def test_consent_laundering_blocks_risk_escalation_retry(tmp_path, monkeypatch):
    home, _config, _downstream, _log, outcome_path = _init_fixture(tmp_path)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("consent laundering must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    staged_in = _StagedStdin([
        _tool_call("write_file", call_id="pending", path="approved.txt"),
        _tool_call("write_file", call_id="retry", path="approved.txt"),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(home=home, client_in=staged_in, out=client_out, approval_ui_mode="none"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        pending_id = first["error"]["data"]["record_id"]
        with httpx.Client() as client:
            page = client.get(first["error"]["data"]["approval_url"])
            page.raise_for_status()
            match = CSRF_RE.search(page.text)
            client.post(first["error"]["data"]["approval_url"], data={
                "decision": "approve",
                "approval_scope": "exact",
                "csrf_token": match.group(1),
            }).raise_for_status()
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
        _patch_approved_risk_class(home, pending_id, risk_class="read")
        staged_in.release_next()
        worker.join(timeout=15)
        responses = _responses(client_out.getvalue())
        assert len(responses) == 2
        # claim-check: allow "blocked" is asserted against consent-laundering negative test evidence.
        blocked = responses[1]
        assert blocked["error"]["data"]["reason"] == SESSION_INTEGRITY_CONSENT_LAUNDERING  # claim-check: allow "blocked" negative test response field.
        assert blocked["error"]["data"]["target_reached"] is False  # claim-check: allow "blocked" negative test response field.
        assert not fake_target_reached(outcome_path)
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            laundering_rows = [
                row for row in store.list_records()
                if parse_session_integrity_metadata(row) is not None
            ]
        assert laundering_rows, "expected consent laundering session integrity evidence"
        laundering_meta = parse_session_integrity_metadata(laundering_rows[-1])
        assert laundering_meta["mismatch_reason"] == SESSION_INTEGRITY_CONSENT_LAUNDERING
        assert laundering_meta["approved_facts"]["approved_risk_class"] == "read"
        assert laundering_meta["executed_facts"]["executed_risk_class"] == "write"
    finally:
        staged_in.release_next()
        worker.join(timeout=1)
