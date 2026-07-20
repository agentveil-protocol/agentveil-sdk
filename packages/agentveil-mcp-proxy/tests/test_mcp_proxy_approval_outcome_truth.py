"""AV-03/AV-06: truthful approval outcome and target_reached contract.

Regression matrix + process-level E2E. Approve ≠ executed. Timeout ≠ allowed.
Missing target_reached must not invent success.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentveil_mcp_proxy.approval.manager import ApprovalManager
from agentveil_mcp_proxy.approval.persistent import load_manifest
from agentveil_mcp_proxy.approval.server import (
    ApprovalServer,
    ApprovalServerDecision,
    _proxy_cli_child_env,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.evidence.events_show import (
    build_event_show_entry,
)
from agentveil_mcp_proxy.evidence.summary import (
    evidence_summary_record,
    privacy_markers_in_text,
)
from agentveil_mcp_proxy.policy import ProxyConfig


class NoopNotifier:
    def notify(self, prompt) -> Any:
        from agentveil_mcp_proxy.approval.notification import NotificationResult

        return NotificationResult("test", attempted=True, delivered=True)


def _classify_downstream_response(response, *, downstream_tool_call_seen: bool):
    from agentveil_mcp_proxy.evidence import observability

    return observability.classify_downstream_response(
        response,
        downstream_tool_call_seen=downstream_tool_call_seen,
    )


def _target_reached_for_evidence_record(record):
    from agentveil_mcp_proxy.evidence import observability

    return observability.target_reached_for_evidence_record(record)

SECRET = "super-secret-token-value"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _config(
    *,
    approval_timeout_seconds: int = 300,
    on_timeout: str = "deny",
    wait_for_decision: bool = True,
    policy_rule: dict[str, Any] | None = None,
) -> ProxyConfig:
    rule = policy_rule or {
        "id": "write-approval",
        "source": "user",
        "decision": "approval",
        "risk_class": "write",
        "match": {"server": "github", "tool": "create_issue"},
    }
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
        },
        "mode": "protect",
        "privacy": {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "fallback": {
            "read": "allow",
            "write": "approval",
            "destructive": "block",
            # claim-check: allow "production" is a ProxyConfig risk_class enum key in fixtures
            "production": "block",
            "financial": "block",
            "unknown": "approval",
        },
        "approval": {
            "approval_timeout_seconds": approval_timeout_seconds,
            "on_timeout": on_timeout,
            "ui_open_mode": "none",
            "wait_for_decision": wait_for_decision,
        },
        "policy": {
            "id": "outcome-truth",
            "policy_schema_version": 1,
            "default_decision": "approval",
            "default_risk_class": "write",
            "rules": [rule],
        },
        "downstream": {},
    })


def _classification(config: ProxyConfig):
    return ToolCallClassifier(config, server_name="github").classify(
        tool="create_issue",
        arguments={"owner": "acme", "repo": "private", "title": SECRET},
    )


def _manager(tmp_path: Path, *, config: ProxyConfig | None = None):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer()
    server.start()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=config or _config(),
        client_id=f"outcome-truth:pid:{os.getpid()}",
        session_id="session-outcome-truth-1",
        headless=False,
        auto_deny=False,
        cli_out=None,
        browser_open=lambda _url: True,
        notifier=NoopNotifier(),
        wait_for_decision=True,
    )
    return manager, store, server


def _pending_record(
    *,
    request_id: str,
    status: str,
    result_status: str | None = None,
    error_class: str | None = None,
    metadata: dict[str, Any] | None = None,
    tool_name: str = "write_file",
) -> Any:
    from agentveil_mcp_proxy.evidence.store import PendingApproval

    return PendingApproval(
        request_id=request_id,
        session_id="session-a",
        client_id="generic-client",
        downstream_server="filesystem",
        tool_name=tool_name,
        action_class="write",
        risk_class="write",
        resource_hash="sha256:" + "a" * 64,
        payload_hash="sha256:" + "b" * 64,
        policy_id="filesystem",
        policy_rule_id="write-approval",
        policy_context_hash="c" * 64,
        status=status,
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        result_status=result_status,
        error_class=error_class,
        action_gate_metadata_jcs=(
            json.dumps(metadata, separators=(",", ":")) if metadata is not None else None
        ),
    )


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _set_approval_timeout(config_path: Path, *, seconds: int, wait_for_decision: bool) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    approval = config.setdefault("approval", {})
    approval["approval_timeout_seconds"] = seconds
    approval["on_timeout"] = "deny"
    approval["wait_for_decision"] = wait_for_decision
    approval["ui_open_mode"] = "none"
    config_path.write_text(json.dumps(config), encoding="utf-8")


def _evidence_rows(home: Path) -> list[dict[str, Any]]:
    path = home / "mcp-proxy" / "evidence.sqlite"
    if not path.exists():
        return []
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT request_id, status, result_status, error_class, "
            "action_gate_metadata_jcs, tool_name FROM pending_approvals "
            "ORDER BY created_at"
        ).fetchall()
    return [dict(row) for row in rows]


def _metadata_of(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("action_gate_metadata_jcs")
    if not isinstance(raw, str) or not raw:
        return {}
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else {}


class _StdoutCollector:
    def __init__(self, stream) -> None:
        self._responses: list[dict] = []
        self._thread = threading.Thread(target=self._run, args=(stream,), daemon=True)
        self._thread.start()

    def _run(self, stream) -> None:
        for line in stream:
            line = line.strip()
            if line:
                self._responses.append(json.loads(line))

    def response_by_id(self, request_id) -> dict | None:
        for item in self._responses:
            if item.get("id") == request_id:
                return item
        return None

    @property
    def responses(self) -> list[dict]:
        return list(self._responses)


class _TextCollector:
    def __init__(self, stream) -> None:
        self._lines: list[str] = []
        self._thread = threading.Thread(target=self._run, args=(stream,), daemon=True)
        self._thread.start()

    def _run(self, stream) -> None:
        for line in stream:
            self._lines.append(line)

    def tail(self, limit: int = 4000) -> str:
        return "".join(self._lines)[-limit:]


def _get_csrf(client: httpx.Client, url: str) -> str:
    page = client.get(url)
    page.raise_for_status()
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None, page.text
    return match.group(1)


def _post_decision(client: httpx.Client, url: str, *, decision: str, csrf: str) -> httpx.Response:
    return client.post(
        url,
        data={"decision": decision, "approval_scope": "exact", "csrf_token": csrf},
    )


def _approval_url(home: Path, request_id: str) -> str | None:
    manifest = load_manifest(home / "mcp-proxy")
    if manifest is None:
        return None
    return f"{manifest.approval_center_url()}/pending/{request_id}"


def _assert_managed_center_reused(home: Path, *, expected_pid: int) -> None:
    manifest = load_manifest(home / "mcp-proxy")
    assert manifest is not None
    assert manifest.pid == expected_pid


def _assert_privacy_clean(text: str) -> None:
    assert SECRET not in text
    assert "/Users/" not in text
    assert "/tmp/" not in text
    assert "TOKEN" not in text
    assert "PASSWORD" not in text
    markers = privacy_markers_in_text(text)
    assert not markers, markers


# ---------------------------------------------------------------------------
# Unit matrix: surface truth (red before fix)
# ---------------------------------------------------------------------------


def test_matrix_timeout_surface_is_not_allowed():
    """Timeout/expired must not render as allowed success.

    claim-check: allow "never" restates the outcome-truth acceptance criterion.
    """
    record = _pending_record(
        request_id="req-timeout",
        status=ApprovalStatus.EXPIRED.value,
        error_class="approval_timeout",
        metadata={
            "approval_status": "expired",
            "execution_status": "not_reached",
            "target_reached": False,
            "policy_decision": "approval",
        },
    )
    entry = build_event_show_entry(record)
    summary = evidence_summary_record(record)

    assert entry["decision"] == "timed_out"
    assert entry.get("target_reached") is False
    assert summary["target_reached"] is False
    assert summary["decision"] == ApprovalStatus.EXPIRED.value
    assert summary.get("reason") == "approval_timeout"
    assert entry["decision"] != "allowed"
    assert "executed" not in entry["decision"]
    _assert_privacy_clean(json.dumps({"entry": entry, "summary": summary}))


def test_matrix_historical_executed_without_target_reached_is_not_success():
    """Old EXECUTED rows without target_reached must not invent success."""
    record = _pending_record(
        request_id="req-legacy",
        status=ApprovalStatus.EXECUTED.value,
        result_status="executed",
        metadata=None,
    )
    assert _target_reached_for_evidence_record(record) is False
    summary = evidence_summary_record(record)
    entry = build_event_show_entry(record)

    assert summary["target_reached"] is False
    assert entry.get("target_reached") is not True
    assert entry["decision"] != "allowed"
    assert entry["decision"] != "target_reached"


def test_matrix_approve_without_downstream_is_not_executed_success():
    """Human approved alone is not execution success."""
    record = _pending_record(
        request_id="req-approved",
        status=ApprovalStatus.APPROVED.value,
        metadata={
            "approval_status": "approved",
            "execution_status": "not_reached",
            "target_reached": False,
            "policy_decision": "approval",
        },
    )
    entry = build_event_show_entry(record)
    summary = evidence_summary_record(record)
    assert entry["decision"] == "approved"
    assert entry.get("target_reached") is False
    assert summary["target_reached"] is False
    assert summary["decision"] == ApprovalStatus.APPROVED.value


def test_matrix_classifier_is_error_is_not_executed():
    """MCP tool-level isError must classify as downstream failure, not executed."""
    response = {
        "jsonrpc": "2.0",
        "id": "1",
        "result": {
            "content": [{"type": "text", "text": "write failed"}],
            "isError": True,
        },
    }
    classified = _classify_downstream_response(
        response,
        downstream_tool_call_seen=True,
    )
    assert classified.execution_status != ApprovalStatus.EXECUTED.value
    assert classified.target_reached is False
    assert classified.error_class == "downstream_error"
    assert classified.store_status in {
        ApprovalStatus.BLOCKED.value,  # claim-check: allow enum status in assertion
        ApprovalStatus.ERROR.value,
    }


def test_matrix_classifier_jsonrpc_error_is_not_executed():
    response = {
        "jsonrpc": "2.0",
        "id": "1",
        "error": {"code": -32000, "message": "boom"},
    }
    classified = _classify_downstream_response(
        response,
        downstream_tool_call_seen=True,
    )
    assert classified.target_reached is False
    assert classified.error_class == "downstream_error"
    assert classified.store_status == ApprovalStatus.BLOCKED.value  # claim-check: allow enum status


def test_matrix_classifier_success_requires_downstream_seen():
    response = {
        "jsonrpc": "2.0",
        "id": "1",
        "result": {"content": [{"type": "text", "text": "ok"}]},
    }
    ok = _classify_downstream_response(response, downstream_tool_call_seen=True)
    assert ok.execution_status == ApprovalStatus.EXECUTED.value
    assert ok.target_reached is True
    assert ok.error_class is None
    assert ok.store_status == ApprovalStatus.EXECUTED.value

    missing = _classify_downstream_response(response, downstream_tool_call_seen=False)
    assert missing.target_reached is False
    assert missing.store_status != ApprovalStatus.EXECUTED.value
    assert missing.error_class == "downstream_error"


@pytest.mark.parametrize(
    "response",
    [
        {"jsonrpc": "2.0", "id": "x"},
        {"jsonrpc": "2.0", "id": "x", "result": None},
        {"jsonrpc": "2.0", "id": "x", "result": "ok"},
        {"jsonrpc": "2.0", "id": "x", "result": 1},
        {"jsonrpc": "2.0", "id": "x", "result": ["ok"]},
    ],
)
def test_matrix_classifier_malformed_result_is_not_executed(response):
    classified = _classify_downstream_response(
        response,
        downstream_tool_call_seen=True,
    )
    assert classified.store_status != ApprovalStatus.EXECUTED.value
    assert classified.execution_status != ApprovalStatus.EXECUTED.value
    assert classified.target_reached is False
    assert classified.error_class == "downstream_error"


def test_regression_prior_forward_counter_cannot_elevate_current_no_forward(tmp_path):
    """Cumulative forward count must not mark a later no-forward call as executed."""

    config = _config()
    manager, store, server = _manager(tmp_path, config=config)

    def wait_for_decision(request_id, *, timeout):
        return ApprovalServerDecision(
            request_id=request_id,
            decision="approve",
            approval_scope="exact",
        )

    server.wait_for_decision = wait_for_decision  # type: ignore[method-assign]
    try:
        outcome = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert outcome.approved
        # Simulate a prior successful tools/call on the same passthrough instance.
        # Request-local seen=False must still refuse executed for this response.
        # claim-check: allow "fail closed" restates the classifier contract under test.
        success_shaped = {
            "jsonrpc": "2.0",
            "id": "later",
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }
        manager.record_execution_result(
            outcome,
            success_shaped,
            downstream_tool_call_seen=False,
        )
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.status != ApprovalStatus.EXECUTED.value
        assert record.error_class == "downstream_error"
        assert _target_reached_for_evidence_record(record) is False

        classified = _classify_downstream_response(
            success_shaped,
            downstream_tool_call_seen=False,
        )
        assert classified.store_status != ApprovalStatus.EXECUTED.value
        assert classified.target_reached is False

        malformed = _classify_downstream_response(
            {"jsonrpc": "2.0", "id": "later"},
            downstream_tool_call_seen=True,
        )
        assert malformed.store_status != ApprovalStatus.EXECUTED.value
        assert malformed.target_reached is False
    finally:
        server.stop()
        store.close()


def test_matrix_deny_cancel_hard_block_target_reached_false():
    cases = [
        (ApprovalStatus.DENIED.value, "user_denied", "hard_blocked"),
        (ApprovalStatus.CANCELLED.value, "client_cancelled", "cancelled"),
        (ApprovalStatus.BLOCKED.value, "local_policy_block", "hard_blocked"),  # claim-check: allow enum status fixture
    ]
    for status, error_class, expected_decision in cases:
        record = _pending_record(
            request_id=f"req-{status}",
            status=status,
            error_class=error_class,
            metadata={
                "approval_status": status,
                "execution_status": "not_reached",
                "target_reached": False,
                # claim-check: allow BLOCKED enum comparison in fixture metadata
                "policy_decision": "block" if status == ApprovalStatus.BLOCKED.value else "approval",
            },
        )
        entry = build_event_show_entry(record)
        summary = evidence_summary_record(record)
        assert entry["decision"] == expected_decision
        assert entry.get("target_reached") is False
        assert summary["target_reached"] is False
        assert summary.get("reason") == error_class


def test_record_execution_result_is_error_does_not_mark_executed(tmp_path):
    """Durable evidence must not claim EXECUTED for MCP isError results."""
    config = _config()
    manager, store, server = _manager(tmp_path, config=config)

    def wait_for_decision(request_id, *, timeout):
        return ApprovalServerDecision(
            request_id=request_id,
            decision="approve",
            approval_scope="exact",
        )

    server.wait_for_decision = wait_for_decision  # type: ignore[method-assign]
    try:
        outcome = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert outcome.approved
        manager.record_execution_result(
            outcome,
            {
                "jsonrpc": "2.0",
                "id": "call-1",
                "result": {
                    "content": [{"type": "text", "text": "disk full"}],
                    "isError": True,
                },
            },
            downstream_tool_call_seen=True,
        )
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.status != ApprovalStatus.EXECUTED.value
        assert record.error_class == "downstream_error"
        assert _target_reached_for_evidence_record(record) is False
        summary = evidence_summary_record(record)
        assert summary["target_reached"] is False
    finally:
        server.stop()
        store.close()


def test_await_decision_deadline_respects_already_approved(tmp_path):
    """Approve landing at the deadline must not be reported as timeout."""
    config = _config(approval_timeout_seconds=60)
    manager, store, server = _manager(tmp_path, config=config)

    def wait_for_decision(request_id, *, timeout):
        return ApprovalServerDecision(
            request_id=request_id,
            decision="approve",
            approval_scope="exact",
        )

    server.wait_for_decision = wait_for_decision  # type: ignore[method-assign]
    try:
        outcome = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert outcome.approved
        # Simulate deadline race: record is already APPROVED, expire transition fails,
        # waiter must re-read evidence instead of returning approval_timeout.
        raced = manager._await_decision(outcome.request_id, timeout=0)
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.status == ApprovalStatus.APPROVED.value
        assert raced.status == ApprovalStatus.APPROVED.value
        assert raced.reason != "approval_timeout"
    finally:
        server.stop()
        store.close()


# ---------------------------------------------------------------------------
# Process-level E2E A–D
# ---------------------------------------------------------------------------


def _start_managed_proxy(home: Path, isolated_home: Path) -> tuple[subprocess.Popen, _StdoutCollector]:
    parent_env = os.environ.copy()
    parent_env["HOME"] = str(isolated_home)
    env = _proxy_cli_child_env(parent_env=parent_env)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agentveil_mcp_proxy.cli",
            "run",
            "--home",
            str(home),
            "--approval-ui-mode",
            "none",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None
    collector = _StdoutCollector(proc.stdout)
    stderr_collector = _TextCollector(proc.stderr)
    startup_deadline = time.monotonic() + 15.0
    while time.monotonic() < startup_deadline:
        if proc.poll() is not None:
            raise AssertionError(
                "run_proxy exited early with code "
                f"{proc.returncode}: {stderr_collector.tail().strip()}"
            )
        if (home / "mcp-proxy" / "approval-center.manifest.json").exists():
            break
        time.sleep(0.05)
    else:
        raise AssertionError(
            "run_proxy did not start managed center: "
            f"{stderr_collector.tail().strip()}"
        )
    return proc, collector


def _send_init_and_list(proc: subprocess.Popen, collector: _StdoutCollector) -> None:
    assert proc.stdin is not None
    for message in (
        {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "outcome-truth-e2e", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}},
    ):
        proc.stdin.write(_json_line(message))
        proc.stdin.flush()
        time.sleep(0.05)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if collector.response_by_id("list-1") is not None:
            return
        time.sleep(0.05)
    raise AssertionError("tools/list did not respond")


@pytest.mark.allow_demo_managed_approval_center
def test_process_e2e_a_timeout_truth(tmp_path, managed_approval_center_server):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    isolated_home = tmp_path / "isolated-home"
    isolated_home.mkdir()
    init = init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )
    _set_approval_timeout(init.config_path, seconds=1, wait_for_decision=True)
    target = sandbox / "timeout-target.txt"
    managed_center = managed_approval_center_server(home=home)
    proc, collector = _start_managed_proxy(home, isolated_home)
    try:
        _assert_managed_center_reused(home, expected_pid=managed_center.pid)
        _send_init_and_list(proc, collector)
        assert proc.stdin is not None
        proc.stdin.write(_json_line({
            "jsonrpc": "2.0",
            "id": "e2e-timeout-write",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "timeout-target.txt", "content": "must-not-exist"},
            },
        }))
        proc.stdin.flush()
        deadline = time.monotonic() + 10.0
        response = None
        while time.monotonic() < deadline:
            response = collector.response_by_id("e2e-timeout-write")
            if response is not None:
                break
            time.sleep(0.05)
        proc.stdin.close()
        assert proc.wait(timeout=30) == 0
        assert response is not None
        error = response.get("error") or {}
        data = error.get("data") or {}
        assert data.get("reason") == "approval_timeout"
        assert data.get("status") in {"timeout", "expired"}
        assert data.get("target_reached") is False
        assert "allowed" not in json.dumps(data).lower()

        rows = _evidence_rows(home)
        write_rows = [row for row in rows if row["tool_name"] == "write_file"]
        assert write_rows
        row = write_rows[-1]
        assert row["status"] == ApprovalStatus.EXPIRED.value
        assert row["error_class"] == "approval_timeout"
        meta = _metadata_of(row)
        assert meta.get("target_reached") is False
        assert not target.exists()

        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(row["request_id"])
            assert record is not None
            entry = build_event_show_entry(record)
            summary = evidence_summary_record(record)
        assert entry["decision"] != "allowed"
        assert entry.get("target_reached") is False
        assert summary["target_reached"] is False
        assert summary.get("reason") == "approval_timeout"
        _assert_privacy_clean(json.dumps({"mcp": response, "entry": entry, "summary": summary}))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


@pytest.mark.allow_demo_managed_approval_center
def test_process_e2e_b_approve_downstream_success(
    tmp_path,
    managed_approval_center_server,
):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    isolated_home = tmp_path / "isolated-home"
    isolated_home.mkdir()
    init = init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )
    _set_approval_timeout(init.config_path, seconds=60, wait_for_decision=True)
    target = sandbox / "approve-ok.txt"
    body = "approve-success-body"
    managed_center = managed_approval_center_server(home=home)
    proc, collector = _start_managed_proxy(home, isolated_home)
    try:
        _assert_managed_center_reused(home, expected_pid=managed_center.pid)
        _send_init_and_list(proc, collector)
        assert proc.stdin is not None
        proc.stdin.write(_json_line({
            "jsonrpc": "2.0",
            "id": "e2e-approve-ok",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "approve-ok.txt", "content": body},
            },
        }))
        proc.stdin.flush()

        deadline = time.monotonic() + 15.0
        request_id = None
        while time.monotonic() < deadline:
            rows = [
                row for row in _evidence_rows(home)
                if row["tool_name"] == "write_file" and row["status"] == "pending"
            ]
            if rows:
                request_id = rows[-1]["request_id"]
                break
            time.sleep(0.05)
        assert request_id is not None
        url = _approval_url(home, request_id)
        assert url is not None
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            assert _post_decision(client, url, decision="approve", csrf=csrf).status_code == 200

        response = None
        while time.monotonic() < deadline + 20.0:
            response = collector.response_by_id("e2e-approve-ok")
            if response is not None:
                break
            time.sleep(0.05)
        proc.stdin.close()
        assert proc.wait(timeout=30) == 0
        assert response is not None
        assert "result" in response
        assert target.exists()
        assert target.read_text(encoding="utf-8") == body

        rows = [row for row in _evidence_rows(home) if row["tool_name"] == "write_file"]
        executed = [row for row in rows if row["status"] == ApprovalStatus.EXECUTED.value]
        assert executed
        row = executed[-1]
        meta = _metadata_of(row)
        assert meta.get("target_reached") is True
        assert meta.get("execution_status") == ApprovalStatus.EXECUTED.value

        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(row["request_id"])
            assert record is not None
            entry = build_event_show_entry(record)
            summary = evidence_summary_record(record)
        assert entry["decision"] == "target_reached"
        assert entry.get("target_reached") is True
        assert summary["target_reached"] is True
        _assert_privacy_clean(json.dumps({"mcp": response, "entry": entry, "summary": summary}))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def _is_error_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "is_error_downstream.py"
    script.write_text(
        """
import json
import sys

TOOLS = [
    {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
    {"name": "list_workspace", "description": "List", "inputSchema": {"type": "object"}},
]
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    if "id" not in msg:
        continue
    if method == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "is-error-downstream", "version": "0"},
        }}), flush=True)
    elif method == "tools/list":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}}), flush=True)
    elif method == "tools/call":
        name = (msg.get("params") or {}).get("name")
        if name == "list_workspace":
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
                "content": [{"type": "text", "text": "[]"}],
            }}), flush=True)
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
                "content": [{"type": "text", "text": "downstream failed"}],
                "isError": True,
            }}), flush=True)
""",
        encoding="utf-8",
    )
    return script


@pytest.mark.allow_demo_managed_approval_center
def test_process_e2e_c_approve_downstream_failure(
    tmp_path,
    managed_approval_center_server,
):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    isolated_home = tmp_path / "isolated-home"
    isolated_home.mkdir()
    script = _is_error_downstream(tmp_path)
    init = init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config={
            "name": "is-error-downstream",
            "command": sys.executable,
            "args": ["-u", str(script)],
            "env": {},
        },
    )
    # Keep filesystem-style write approval rule by rewriting policy match server.
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "outcome-truth-iserror",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [
            {
                "id": "write-approval",
                "source": "user",
                "decision": "approval",
                "risk_class": "write",
                "match": {"server": "is-error-downstream", "tool": "write_file"},
            }
        ],
    }
    config["downstream"] = {
        "name": "is-error-downstream",
        "command": sys.executable,
        "args": ["-u", str(script)],
        "env": {},
    }
    init.config_path.write_text(json.dumps(config), encoding="utf-8")
    _set_approval_timeout(init.config_path, seconds=60, wait_for_decision=True)
    target = sandbox / "should-not-exist.txt"

    managed_center = managed_approval_center_server(home=home)
    proc, collector = _start_managed_proxy(home, isolated_home)
    try:
        _assert_managed_center_reused(home, expected_pid=managed_center.pid)
        _send_init_and_list(proc, collector)
        assert proc.stdin is not None
        proc.stdin.write(_json_line({
            "jsonrpc": "2.0",
            "id": "e2e-approve-fail",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "should-not-exist.txt", "content": "nope"},
            },
        }))
        proc.stdin.flush()

        deadline = time.monotonic() + 15.0
        request_id = None
        while time.monotonic() < deadline:
            rows = [
                row for row in _evidence_rows(home)
                if row["tool_name"] == "write_file" and row["status"] == "pending"
            ]
            if rows:
                request_id = rows[-1]["request_id"]
                break
            time.sleep(0.05)
        assert request_id is not None
        url = _approval_url(home, request_id)
        assert url is not None
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            assert _post_decision(client, url, decision="approve", csrf=csrf).status_code == 200

        response = None
        while time.monotonic() < deadline + 20.0:
            response = collector.response_by_id("e2e-approve-fail")
            if response is not None:
                break
            time.sleep(0.05)
        proc.stdin.close()
        assert proc.wait(timeout=30) == 0
        assert response is not None
        # MCP tool errors arrive as result.isError, not JSON-RPC error.
        result = response.get("result") or {}
        assert result.get("isError") is True
        assert not target.exists()

        rows = [row for row in _evidence_rows(home) if row["tool_name"] == "write_file"]
        assert rows
        # Prefer the execution-linked / terminal failure row.
        terminal = [
            row for row in rows
            if row["status"] in {
                ApprovalStatus.BLOCKED.value,  # claim-check: allow enum status filter
                ApprovalStatus.ERROR.value,
                ApprovalStatus.EXECUTED.value,
            }
        ]
        assert terminal
        row = terminal[-1]
        assert row["status"] != ApprovalStatus.EXECUTED.value
        assert row["error_class"] == "downstream_error"
        meta = _metadata_of(row)
        assert meta.get("target_reached") is False

        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(row["request_id"])
            assert record is not None
            # Approval fact may live on parent; execution outcome on this row.
            summary = evidence_summary_record(record)
            entry = build_event_show_entry(record)
        assert summary["target_reached"] is False
        assert entry.get("target_reached") is not True
        assert entry["decision"] != "target_reached"
        assert entry["decision"] != "allowed"
        _assert_privacy_clean(json.dumps({"mcp": response, "entry": entry, "summary": summary}))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


@pytest.mark.allow_demo_managed_approval_center
def test_process_e2e_d_deny_and_cancel_regression(
    tmp_path,
    managed_approval_center_server,
):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    isolated_home = tmp_path / "isolated-home"
    isolated_home.mkdir()
    init = init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )
    # Fail-soft so cancel notifications can be read while a pending approval exists.
    _set_approval_timeout(init.config_path, seconds=60, wait_for_decision=False)
    deny_target = sandbox / "deny-target.txt"
    cancel_target = sandbox / "cancel-target.txt"
    managed_center = managed_approval_center_server(home=home)
    proc, collector = _start_managed_proxy(home, isolated_home)
    try:
        _assert_managed_center_reused(home, expected_pid=managed_center.pid)
        _send_init_and_list(proc, collector)
        assert proc.stdin is not None

        # Deny path (fail-soft: pending response, then POST deny, then retry)
        proc.stdin.write(_json_line({
            "jsonrpc": "2.0",
            "id": "e2e-deny-write",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "deny-target.txt", "content": "deny-body"},
            },
        }))
        proc.stdin.flush()
        deadline = time.monotonic() + 15.0
        deny_pending = None
        while time.monotonic() < deadline:
            deny_pending = collector.response_by_id("e2e-deny-write")
            if deny_pending is not None:
                break
            time.sleep(0.05)
        assert deny_pending is not None
        assert (deny_pending.get("error") or {}).get("data", {}).get("status") == "approval_required"
        assert (deny_pending.get("error") or {}).get("data", {}).get("target_reached") is False

        deny_request_id = None
        while time.monotonic() < deadline:
            pending = [
                row for row in _evidence_rows(home)
                if row["tool_name"] == "write_file" and row["status"] == "pending"
            ]
            if pending:
                deny_request_id = pending[-1]["request_id"]
                break
            time.sleep(0.05)
        assert deny_request_id is not None
        url = _approval_url(home, deny_request_id)
        assert url is not None
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            assert _post_decision(client, url, decision="deny", csrf=csrf).status_code == 200

        proc.stdin.write(_json_line({
            "jsonrpc": "2.0",
            "id": "e2e-deny-retry",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "deny-target.txt", "content": "deny-body"},
            },
        }))
        proc.stdin.flush()
        deny_response = None
        while time.monotonic() < deadline + 20.0:
            deny_response = collector.response_by_id("e2e-deny-retry")
            if deny_response is not None:
                break
            time.sleep(0.05)
        assert deny_response is not None
        deny_data = (deny_response.get("error") or {}).get("data") or {}
        assert deny_data.get("reason") == "user_denied"
        assert deny_data.get("target_reached") is False
        assert not deny_target.exists()

        # Cancel path
        proc.stdin.write(_json_line({
            "jsonrpc": "2.0",
            "id": "e2e-cancel-write",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "cancel-target.txt", "content": "cancel-body"},
            },
        }))
        proc.stdin.flush()
        cancel_request_id = None
        cancel_deadline = time.monotonic() + 15.0
        while time.monotonic() < cancel_deadline:
            pending = [
                row for row in _evidence_rows(home)
                if row["tool_name"] == "write_file" and row["status"] == "pending"
            ]
            if pending:
                cancel_request_id = pending[-1]["request_id"]
                break
            time.sleep(0.05)
        assert cancel_request_id is not None
        proc.stdin.write(_json_line({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "e2e-cancel-write", "reason": "user cancelled"},
        }))
        proc.stdin.flush()

        cancelled_row = None
        while time.monotonic() < cancel_deadline + 10.0:
            rows = [
                row for row in _evidence_rows(home)
                if row["request_id"] == cancel_request_id
            ]
            if rows and rows[-1]["status"] == ApprovalStatus.CANCELLED.value:
                cancelled_row = rows[-1]
                break
            time.sleep(0.05)
        assert cancelled_row is not None
        assert cancelled_row["error_class"] == "client_cancelled"
        assert not cancel_target.exists()

        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            deny_record = store.get_pending(deny_request_id)
            cancel_record = store.get_pending(cancel_request_id)
            assert deny_record is not None
            assert cancel_record is not None
            deny_summary = evidence_summary_record(deny_record)
            cancel_summary = evidence_summary_record(cancel_record)
            deny_entry = build_event_show_entry(deny_record)
            cancel_entry = build_event_show_entry(cancel_record)
        assert deny_summary["target_reached"] is False
        assert cancel_summary["target_reached"] is False
        assert deny_entry["decision"] != "allowed"
        assert cancel_entry["decision"] == "cancelled"
        assert cancel_entry.get("target_reached") is False

        proc.stdin.close()
        assert proc.wait(timeout=30) == 0
        _assert_privacy_clean(json.dumps({
            "deny": deny_response,
            "deny_entry": deny_entry,
            "cancel_entry": cancel_entry,
        }))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
