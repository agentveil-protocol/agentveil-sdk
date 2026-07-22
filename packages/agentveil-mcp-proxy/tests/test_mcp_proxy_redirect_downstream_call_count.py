"""Orthogonal subprocess proof: downstream write_file executes at most once."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx
import pytest

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import init_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from test_mcp_proxy_redirect_lineage import (
    _QueuedStdin,
    _get_csrf,
    _install_operator_browser_capture,
    _json_line,
    _live_binding_exists,
    _post_decision,
    _run_installed_cursor_hook,
    _set_wait_for_decision,
    _start_live_product_route_proxy,
    _tool_call_args,
    _wait_for_response_count,
    _wait_operator_pending_url,
)


_PROBE_PATH = "downstream-once.txt"
_PROBE_CONTENT = "downstream-once-body"


def _logging_downstream(tmp_path: Path) -> tuple[Path, Path]:
    log_path = tmp_path / "downstream.log"
    script = tmp_path / "test_quickstart_filesystem_logger.py"
    script.write_text(
        """
import json
import os
import sys

LOG = os.environ["DOWNSTREAM_LOG"]
TOOLS = [{"name": "write_file", "inputSchema": {"type": "object"}}]

def log(method):
    with open(LOG, "a", encoding="utf-8") as fh:
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
            "serverInfo": {"name": "logging-downstream", "version": "0"},
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
    return script, log_path


def _tools_call_count(log_path: Path) -> int:
    if not log_path.is_file():
        return 0
    return sum(
        1 for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip() == "tools/call"
    )


def _patch_no_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("downstream call-count path must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)


def _init_redirect_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    project = tmp_path / "project"
    sandbox = project / "sandbox"
    sandbox.mkdir(parents=True)
    script, log_path = _logging_downstream(tmp_path)
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="implementer")
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "filesystem",
        "command": sys.executable,
        "args": [str(script), str(sandbox.resolve())],
        "env": {"DOWNSTREAM_LOG": str(log_path)},
    }
    config["policy"] = {
        "id": "redirect-downstream-once",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": "write-approval",
            "source": "user",
            "decision": "approval",
            "risk_class": "write",
            "match": {"server": "filesystem", "tool": "write_file"},
        }],
    }
    init.config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    _patch_no_agent(monkeypatch)
    _set_wait_for_decision(home)
    return home, project, log_path


def test_approve_retry_executes_downstream_write_file_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, project, log_path = _init_redirect_home(tmp_path, monkeypatch)
    workspace = project / "workspace"
    workspace.mkdir(parents=True)
    evidence_path = project / ".cursor" / "agentveil" / "evidence.jsonl"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    opened = _install_operator_browser_capture(monkeypatch)
    queued_in = _QueuedStdin(_json_line({
        "jsonrpc": "2.0",
        "id": "tools-list",
        "method": "tools/list",
        "params": {},
    }))
    worker, client_out = _start_live_product_route_proxy(
        home,
        queued_in,
        approval_ui_mode="browser",
    )
    deadline = time.monotonic() + 20.0
    try:
        _wait_for_response_count(client_out, 1, deadline=deadline)
        assert _live_binding_exists(home)
        redirect_context = _run_installed_cursor_hook(
            home=home,
            workspace=workspace,
            evidence_path=evidence_path,
            target_path=_PROBE_PATH,
            content=_PROBE_CONTENT,
        )
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PROBE_PATH,
                "content": _PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-write",
        ))
        follow_response = _wait_for_response_count(client_out, 2, deadline=deadline)[1]
        pending_id = follow_response["error"]["data"]["record_id"]
        approval_url = _wait_operator_pending_url(opened, pending_id, deadline=deadline)
        with httpx.Client() as client:
            csrf = _get_csrf(client, approval_url)
            _post_decision(client, approval_url, decision="approve", csrf=csrf).raise_for_status()
        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            record = store.get_pending(pending_id)
            while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
                time.sleep(0.02)
                record = store.get_pending(pending_id)
            assert record.status == ApprovalStatus.APPROVED.value
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {"path": _PROBE_PATH, "content": _PROBE_CONTENT},
            call_id="retry-write",
        ))
        retry_response = _wait_for_response_count(client_out, 3, deadline=deadline)[2]
        assert "result" in retry_response
        assert _tools_call_count(log_path) == 1
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PROBE_PATH,
                "content": _PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-replay",
        ))
        _wait_for_response_count(client_out, 4, deadline=deadline)
        assert _tools_call_count(log_path) == 1
    finally:
        queued_in.close_writer()
        worker.join(timeout=15)


def test_deny_retry_executes_downstream_zero_times(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, project, log_path = _init_redirect_home(tmp_path, monkeypatch)
    workspace = project / "workspace"
    workspace.mkdir(parents=True)
    evidence_path = project / ".cursor" / "agentveil" / "evidence.jsonl"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    opened = _install_operator_browser_capture(monkeypatch)
    queued_in = _QueuedStdin(_json_line({
        "jsonrpc": "2.0",
        "id": "tools-list",
        "method": "tools/list",
        "params": {},
    }))
    worker, client_out = _start_live_product_route_proxy(
        home,
        queued_in,
        approval_ui_mode="browser",
    )
    deadline = time.monotonic() + 20.0
    try:
        _wait_for_response_count(client_out, 1, deadline=deadline)
        assert _live_binding_exists(home)
        redirect_context = _run_installed_cursor_hook(
            home=home,
            workspace=workspace,
            evidence_path=evidence_path,
            target_path=_PROBE_PATH,
            content=_PROBE_CONTENT,
        )
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {
                "path": _PROBE_PATH,
                "content": _PROBE_CONTENT,
                "redirect_context": redirect_context,
            },
            call_id="follow-write",
        ))
        follow_response = _wait_for_response_count(client_out, 2, deadline=deadline)[1]
        pending_id = follow_response["error"]["data"]["record_id"]
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
        assert _tools_call_count(log_path) == 0
        queued_in.queue_line(_tool_call_args(
            "write_file",
            {"path": _PROBE_PATH, "content": _PROBE_CONTENT},
            call_id="retry-write",
        ))
        retry_response = _wait_for_response_count(client_out, 3, deadline=deadline)[2]
        assert retry_response["error"]["data"]["reason"] == "user_denied"
        assert _tools_call_count(log_path) == 0
    finally:
        queued_in.close_writer()
        worker.join(timeout=15)
