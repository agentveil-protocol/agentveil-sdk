"""Generic run_proxy stdio proofs for approval fail-soft delivery."""

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

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.approval.persistent import (
    ApprovalCenterManifest,
    load_manifest,
    save_manifest,
    token_hash_for,
)
from agentveil_mcp_proxy.approval.server import ApprovalServer
from agentveil_mcp_proxy.cli import init_proxy, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.passthrough import JSONRPC_APPROVAL_REQUIRED


def _pending_approval_count(home: Path) -> int:
    import sqlite3

    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    if not evidence_path.exists():
        return 0
    with sqlite3.connect(evidence_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending'"
        ).fetchone()
    return int(row[0])


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _install_operator_browser_capture(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Capture tokenized pending URLs from the operator browser delivery path.

    Returns False so fail-soft wait_for_decision configs still emit
    ``approval_required`` promptly. The captured URL remains available for
    operator-side Approve/Deny without reading agent-visible MCP payloads.
    """

    opened: list[str] = []

    def capture_open(url: str) -> bool:
        opened.append(url)
        return False

    monkeypatch.setattr("webbrowser.open", capture_open)
    return opened


def _wait_operator_pending_url(opened: list[str], request_id: str, *, deadline: float) -> str:
    while time.monotonic() < deadline:
        for url in opened:
            if request_id in url and "/pending/" in url:
                return url
        time.sleep(0.02)
    assert opened, "expected operator browser opener to receive a pending URL"
    raise AssertionError(f"pending URL for {request_id} not opened; saw={opened!r}")


def _assert_mcp_fail_soft_has_no_capability_token(response: dict, *, session_token: str | None = None) -> None:
    """Agent-visible fail-soft must omit tokenized approval surfaces."""

    error = response["error"]
    data = error["data"]
    serialized = json.dumps(response)
    assert data["status"] == "approval_required"
    assert data["record_id"]
    assert data["record_status"] == "pending"
    assert "approval_url" not in data
    assert "csrf_token" not in serialized
    assert "/approval/" not in serialized
    if session_token is not None:
        assert session_token not in serialized
        assert f"/approval/{session_token}" not in serialized
    message = error.get("message", "")
    assert "http://127.0.0.1" not in message
    assert "http://localhost" not in message


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _set_downstream(config_path: Path, script: Path, *, log_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "generic-downstream",
        "command": sys.executable,
        "args": ["-u", str(script)],
        "env": {"DOWNSTREAM_LOG": str(log_path)},
    }
    _write_json(config_path, config)


def _set_approval_policy(config_path: Path, *, server: str, tool: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "approval-e2e",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [
            {
                "id": "approval-tool",
                "source": "user",
                "decision": "approval",
                "risk_class": "write",
                "match": {"server": server, "tool": tool},
            }
        ],
    }
    _write_json(config_path, config)


def _set_wait_for_decision(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    approval = config.get("approval")
    if not isinstance(approval, dict):
        approval = {}
        config["approval"] = approval
    approval["wait_for_decision"] = True
    _write_json(config_path, config)


def _generic_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "generic_downstream.py"
    script.write_text(
        """
import json
import os
import sys

TOOLS = [
    {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
]
log_path = os.environ.get("DOWNSTREAM_LOG")

def log(method):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(method + "\\n")

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    log(method)
    if "id" not in msg:
        continue
    if method == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "generic-downstream", "version": "0"},
        }}), flush=True)
    elif method == "tools/list":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}}), flush=True)
    elif method == "tools/call":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "content": [{"type": "text", "text": "downstream-ok"}],
        }}), flush=True)
""",
        encoding="utf-8",
    )
    return script


class _StagedStdin(io.TextIOBase):
    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self._line_index = 0
        self._char_index = 0
        self._gate = threading.Event()
        self._gate.set()

    def read(self, size: int = -1) -> str:
        if size == 0:
            return ""
        if self._line_index >= len(self._lines):
            return ""
        if self._char_index == 0:
            self._gate.wait(timeout=30)
        if self._line_index >= len(self._lines):
            return ""
        line = self._lines[self._line_index]
        if size < 0:
            chunk = line[self._char_index :]
            self._line_index += 1
            self._char_index = 0
            if self._line_index < len(self._lines):
                self._gate.clear()
            return chunk
        chunk = line[self._char_index : self._char_index + size]
        self._char_index += len(chunk)
        if self._char_index >= len(line):
            self._line_index += 1
            self._char_index = 0
            if self._line_index < len(self._lines):
                self._gate.clear()
        return chunk

    def release_next(self) -> None:
        self._gate.set()


def _tool_call(tool: str, *, call_id: str, path: str = "proof.txt") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"path": path, "content": "proof"}},
    })


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


def _init_run_proxy_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _generic_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="generic-downstream", tool="write_file")
    _set_wait_for_decision(init.config_path)
    return home, init.config_path, log_path


def _exploding_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("approval e2e must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)


def test_run_proxy_fail_soft_delivery_prompts_approval_without_downstream(
    tmp_path,
    monkeypatch,
):
    home, _config_path, log_path = _init_run_proxy_fixture(tmp_path)
    _exploding_agent(monkeypatch)

    client_out = io.StringIO()
    started = time.monotonic()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file", call_id="call-1")),
        out=client_out,
        approval_ui_mode="browser",
    ) == 0
    elapsed = time.monotonic() - started

    response = _responses(client_out.getvalue())[0]
    assert elapsed < 10.0
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    _assert_mcp_fail_soft_has_no_capability_token(response)
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_run_proxy_headless_skips_managed_approval_center_reconcile(
    tmp_path,
    monkeypatch,
):
    """Headless/auto-deny must not spawn or reconcile an interactive managed AC."""

    home, _config_path, log_path = _init_run_proxy_fixture(tmp_path)
    _exploding_agent(monkeypatch)
    calls: list[str] = []

    def forbid_reconcile(**_kwargs):
        calls.append("reconcile")
        raise AssertionError("headless must not reconcile managed Approval Center")

    def forbid_spawn(**_kwargs):
        calls.append("spawn")
        raise AssertionError("headless must not spawn managed Approval Center")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.reconcile_managed_approval_center_for_runtime",
        forbid_reconcile,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.client.spawn_managed_approval_center_process",
        forbid_spawn,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.spawn_managed_approval_center_process",
        forbid_spawn,
    )

    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("write_file", call_id="headless-1")),
        out=client_out,
        headless=True,
        auto_deny=True,
    ) == 0
    response = _responses(client_out.getvalue())[0]
    assert "error" in response
    assert response["error"]["data"]["reason"] in {
        "headless_auto_deny",
        "user_denied",
        "local_approval_required",
    }
    assert calls == []
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_run_proxy_fail_soft_approve_then_retry_executes_once(
    tmp_path,
    monkeypatch,
):
    home, _config_path, log_path = _init_run_proxy_fixture(tmp_path)
    _exploding_agent(monkeypatch)
    opened = _install_operator_browser_capture(monkeypatch)

    staged_in = _StagedStdin([
        _tool_call("write_file", call_id="pending"),
        _tool_call("write_file", call_id="retry"),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=staged_in,
            out=client_out,
            approval_ui_mode="browser",
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        assert first["error"]["data"]["status"] == "approval_required"
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]
        pending_id = first["error"]["data"]["record_id"]
        _assert_mcp_fail_soft_has_no_capability_token(first)
        approval_url = _wait_operator_pending_url(opened, pending_id, deadline=deadline)
        assert pending_id in approval_url
        assert "/pending/" in approval_url
        assert approval_url not in json.dumps(first)
        with httpx.Client() as client:
            csrf = _get_csrf(client, approval_url)
            _post_decision(client, approval_url, decision="approve", csrf=csrf).raise_for_status()
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
            assert record.status == ApprovalStatus.APPROVED.value
        staged_in.release_next()
        worker.join(timeout=15)
        responses = _responses(client_out.getvalue())
        assert len(responses) == 2
        assert "result" in responses[1]
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def test_run_proxy_fail_soft_deny_retry_does_not_execute(
    tmp_path,
    monkeypatch,
):
    home, _config_path, log_path = _init_run_proxy_fixture(tmp_path)
    _exploding_agent(monkeypatch)
    opened = _install_operator_browser_capture(monkeypatch)

    staged_in = _StagedStdin([
        _tool_call("write_file", call_id="pending"),
        _tool_call("write_file", call_id="retry"),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=staged_in,
            out=client_out,
            approval_ui_mode="browser",
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        pending_id = first["error"]["data"]["record_id"]
        _assert_mcp_fail_soft_has_no_capability_token(first)
        approval_url = _wait_operator_pending_url(opened, pending_id, deadline=deadline)
        with httpx.Client() as client:
            csrf = _get_csrf(client, approval_url)
            _post_decision(client, approval_url, decision="deny", csrf=csrf).raise_for_status()
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.DENIED.value and time.monotonic() < deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
            assert record.status == ApprovalStatus.DENIED.value
            assert record.error_class == "user_denied"
        staged_in.release_next()
        worker.join(timeout=15)
        responses = _responses(client_out.getvalue())
        assert len(responses) == 2
        assert responses[1]["error"]["data"]["reason"] == "user_denied"
        assert _pending_approval_count(home) == 0
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            records = store.list_records()
            assert len(records) == 1
            assert records[0].request_id == pending_id
            assert records[0].status == ApprovalStatus.DENIED.value
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def test_run_proxy_fail_soft_response_has_no_sensitive_leaks(
    tmp_path,
    monkeypatch,
):
    home, _config_path, log_path = _init_run_proxy_fixture(tmp_path)
    _exploding_agent(monkeypatch)
    foreign_pid = os.getpid()
    proxy_dir = home / "mcp-proxy"
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    foreign_server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-register-token-not-real",
    )
    foreign_server.start()
    other_pending_url = foreign_server.approval_url("other-request-id")
    secret_internal = foreign_server.internal_register_token
    secret_session = "fixture-foreign-session-token-not-real"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host=foreign_server.host,
            port=foreign_server.port,
            session_token=secret_session,
            token_hash=token_hash_for(secret_session),
            internal_register_token=secret_internal,
            pid=99999999,
            started_at=int(time.time()),
            runtime_identity="sha256:" + ("c" * 64),
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: True,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_cmdline_owns_pid",
        lambda _home, _pid: False,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_owns_pid",
        lambda _home, _pid: False,
    )
    opened = _install_operator_browser_capture(monkeypatch)
    try:
        client_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("write_file", call_id="privacy-1")),
            out=client_out,
            approval_ui_mode="browser",
        ) == 0
        response = _responses(client_out.getvalue())[0]
        data = response["error"]["data"]
        serialized = json.dumps(response)
        _assert_mcp_fail_soft_has_no_capability_token(response)
        assert secret_internal not in serialized
        assert secret_session not in serialized
        assert other_pending_url not in serialized
        assert "internal_register_token" not in serialized
        assert "approval_url" not in data
        assert "csrf_token" not in serialized
        # Stale foreign manifest cleared; ephemeral in-process center may leave no manifest.
        live_manifest = load_manifest(proxy_dir)
        assert live_manifest is None or live_manifest.session_token != secret_session
        assert opened, "operator browser delivery must receive the tokenized pending URL"
        assert any(data["record_id"] in url for url in opened)
        assert len([url for url in opened if "/pending/" in url]) == len(opened)  # claim-check: allow pending-path assertion
        assert len([url for url in opened if url not in serialized]) == len(opened)  # claim-check: allow privacy assertion
        for url in opened:
            token_part = url.split("/approval/", 1)[1].split("/", 1)[0]
            assert token_part
            assert token_part not in serialized
            assert f"/approval/{token_part}" not in serialized
        assert os.getpid() == foreign_pid
        assert data["record_id"]
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]
    finally:
        foreign_server.stop()
        store.close()
