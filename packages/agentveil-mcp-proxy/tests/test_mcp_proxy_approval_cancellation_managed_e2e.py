"""Process-level stdio E2E for managed Approval Center cancellation UI."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import pytest

from agentveil_mcp_proxy.approval.persistent import load_manifest
from agentveil_mcp_proxy.approval.server import (
    _proxy_cli_child_env,
    scan_cmdline_proven_managed_center_pids,
    stop_managed_approval_center,
)
from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream
from agentveil_mcp_proxy.evidence import ApprovalStatus


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _pending_count(home: Path) -> int:
    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    if not evidence_path.exists():
        return 0
    with sqlite3.connect(evidence_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending'"
        ).fetchone()
    return int(row[0])


def _cancelled_write_record(home: Path) -> dict | None:
    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    if not evidence_path.exists():
        return None
    with sqlite3.connect(evidence_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT request_id, status, error_class, tool_name FROM pending_approvals "
            "WHERE tool_name = 'write_file' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    return None if row is None else dict(row)


def _approval_url(home: Path, request_id: str) -> str | None:
    manifest = load_manifest(home / "mcp-proxy")
    if manifest is None:
        return None
    return f"{manifest.approval_center_url()}/pending/{request_id}"


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


def _wait_for_managed_center_start(
    proc: subprocess.Popen,
    home: Path,
    stderr_collector: _TextCollector,
    *,
    timeout: float,
) -> None:
    startup_deadline = time.monotonic() + timeout
    while time.monotonic() < startup_deadline:
        if proc.poll() is not None:
            raise AssertionError(
                "run_proxy exited early with code "
                f"{proc.returncode}: {stderr_collector.tail().strip()}"
            )
        if (home / "mcp-proxy" / "approval-center.manifest.json").exists():
            return
        time.sleep(0.05)
    raise AssertionError(
        "run_proxy did not start managed center: "
        f"{stderr_collector.tail().strip()}"
    )


def test_managed_center_startup_timeout_does_not_wait_for_child_stderr_eof(tmp_path):
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys,time; print('still-running', file=sys.stderr, flush=True); time.sleep(30)",
        ],
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stderr is not None
    stderr_collector = _TextCollector(proc.stderr)
    started = time.monotonic()
    try:
        with pytest.raises(AssertionError, match="did not start managed center"):
            _wait_for_managed_center_start(
                proc,
                tmp_path / "missing-home",
                stderr_collector,
                timeout=0.2,
            )
        assert time.monotonic() - started < 2.0
    finally:
        proc.kill()
        proc.wait(timeout=5)


@pytest.mark.allow_demo_managed_approval_center
def test_run_proxy_cancelled_request_shows_terminal_managed_center_page(
    tmp_path,
    managed_approval_center_process,
):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    isolated_home = tmp_path / "isolated-home"
    isolated_home.mkdir()
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )
    target = sandbox / "cancel-target.txt"
    parent_env = os.environ.copy()
    parent_env["HOME"] = str(isolated_home)
    open_sentinel = tmp_path / "unexpected-browser-open.txt"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    if os.name != "nt":
        fake_browser = fake_bin / "avp-fake-browser"
        fake_browser.write_text(
            "#!/bin/sh\n"
            f"printf called > {json.dumps(str(open_sentinel))}\n",
            encoding="utf-8",
        )
        fake_browser.chmod(0o755)
        parent_env["BROWSER"] = str(fake_browser)
        fake_open = fake_bin / "open"
        fake_open.write_text(fake_browser.read_text(encoding="utf-8"), encoding="utf-8")
        fake_open.chmod(0o755)
        parent_env["PATH"] = os.pathsep.join(
            (str(fake_bin), parent_env.get("PATH", ""))
        )
    env = _proxy_cli_child_env(parent_env=parent_env)

    managed_center = managed_approval_center_process(
        home=home,
        isolated_home=isolated_home,
    )

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
    try:
        manifest = load_manifest(home / "mcp-proxy")
        assert manifest is not None
        assert manifest.pid == managed_center.pid
        _wait_for_managed_center_start(
            proc,
            home,
            stderr_collector,
            timeout=15.0,
        )
        messages = [
            {"jsonrpc": "2.0", "id": "init-1", "method": "initialize", "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "cancel-managed-e2e", "version": "0"},
            }},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": "e2e-cancel-write", "method": "tools/call", "params": {
                "name": "write_file",
                "arguments": {"path": "cancel-target.txt", "content": "cancel-e2e-body"},
            }},
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {
                "requestId": "e2e-cancel-write",
                "reason": "user cancelled",
            }},
            {"jsonrpc": "2.0", "id": "read-1", "method": "tools/call", "params": {
                "name": "list_workspace",
                "arguments": {},
            }},
        ]
        for message in messages[:4]:
            proc.stdin.write(_json_line(message))
            proc.stdin.flush()
            if message.get("id") == "e2e-cancel-write":
                break
            time.sleep(0.05)

        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline and _pending_count(home) == 0:
            time.sleep(0.05)
        assert _pending_count(home) > 0

        proc.stdin.write(_json_line(messages[4]))
        proc.stdin.flush()
        record = None
        while time.monotonic() < deadline:
            record = _cancelled_write_record(home)
            if record is not None and record.get("status") == ApprovalStatus.CANCELLED.value:
                break
            time.sleep(0.05)
        assert record is not None
        assert record["error_class"] == "client_cancelled"

        proc.stdin.write(_json_line(messages[5]))
        proc.stdin.flush()
        read_deadline = time.monotonic() + 10.0
        read_response = None
        while time.monotonic() < read_deadline:
            read_response = collector.response_by_id("read-1")
            if read_response is not None:
                break
            time.sleep(0.05)
        proc.stdin.close()
        assert proc.wait(timeout=30) == 0
        assert read_response is not None
        assert "result" in read_response
        assert _pending_count(home) == 0
        assert not target.exists()

        approval_url = _approval_url(home, str(record["request_id"]))
        assert approval_url is not None
        with httpx.Client() as client:
            page = client.get(approval_url, follow_redirects=False)
            assert page.status_code == 410
            assert "<title>Cancelled</title>" in page.text
            assert "cancelled by the client" in page.text
            assert "<form" not in page.text.lower()
            assert 'name="csrf_token"' not in page.text

            match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
            csrf = match.group(1) if match else "invalid"
            post = client.post(
                approval_url,
                data={
                    "decision": "approve",
                    "approval_scope": "exact",
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            assert post.status_code == 410
        assert not target.exists()
        refreshed = _cancelled_write_record(home)
        assert refreshed is not None
        assert refreshed["status"] == ApprovalStatus.CANCELLED.value
        assert refreshed["error_class"] == "client_cancelled"
        assert not open_sentinel.exists(), (
            "approval-ui-mode none must not invoke browser/native open in the child proxy"
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        stop_managed_approval_center(home, require_healthy=False)
    cleanup_deadline = time.monotonic() + 5.0
    while (
        scan_cmdline_proven_managed_center_pids(home)
        and time.monotonic() < cleanup_deadline
    ):
        time.sleep(0.05)
    assert scan_cmdline_proven_managed_center_pids(home) == ()
    assert not open_sentinel.exists()
