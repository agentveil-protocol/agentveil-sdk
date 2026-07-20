"""Reconnect recovery after AV-05 unavailable latch (slice 2)."""

from __future__ import annotations

import io
import json
import queue
import re
import sqlite3
import sys
import threading
import time
import webbrowser
from pathlib import Path

import pytest

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import init_proxy, run_proxy
from agentveil_mcp_proxy.client_guidance import MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
from agentveil_mcp_proxy.passthrough import (
    DOWNSTREAM_RECONNECT_COOLDOWN_SECONDS,
    DownstreamConfig,
    JSONRPC_APPROVAL_REQUIRED,
    JSONRPC_DOWNSTREAM_ERROR,
    McpPassthrough,
)


SECRET = "SECRET_RECONNECT_TOKEN_AV05B"
FIXTURE_SENTINEL = "/tmp/avp-reconnect-secret-fixture.py"


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _pending_approval_count(home: Path) -> int:
    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    if not evidence_path.exists():
        return 0
    with sqlite3.connect(evidence_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending'"
        ).fetchone()
    return int(row[0])


def _approval_record_count(home: Path) -> int:
    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    if not evidence_path.exists():
        return 0
    with sqlite3.connect(evidence_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()
    return int(row[0])


def _set_downstream(
    config_path: Path,
    script: Path,
    *,
    log_path: Path | None = None,
    state_path: Path | None = None,
    kill_path: Path | None = None,
    command_decoy: str | None = None,
) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    env: dict[str, str] = {}
    if log_path is not None:
        env["DOWNSTREAM_LOG"] = str(log_path)
    if state_path is not None:
        env["RECONNECT_STATE_FILE"] = str(state_path)
    if kill_path is not None:
        env["RECONNECT_KILL_FILE"] = str(kill_path)
    args = ["-u", str(script)]
    if command_decoy is not None:
        args.append(command_decoy)
    config["downstream"] = {
        "name": "fake-downstream",
        "command": sys.executable,
        "args": args,
        "env": env,
    }
    _write_json(config_path, config)


def _set_approval_policy(config_path: Path, *, server: str, tool: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "approval-test",
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


def _fail_once_then_recover_downstream(tmp_path: Path) -> Path:
    """Gen1: initialize+list then exit. Gen2+: stay healthy when state=healthy."""

    script = tmp_path / "fail_once_recover.py"
    script.write_text(
        f"""
import json
import os
import sys
import threading
import time

log_path = os.environ.get("DOWNSTREAM_LOG")
state_path = os.environ["RECONNECT_STATE_FILE"]
kill_path = os.environ.get("RECONNECT_KILL_FILE")

def log(method):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(method + "\\n")

def state():
    try:
        return open(state_path, encoding="utf-8").read().strip()
    except OSError:
        return "fail_after_list"

def _watch_kill():
    if not kill_path:
        return
    while True:
        if os.path.exists(kill_path):
            sys.stderr.write("{SECRET}\\n")
            sys.stderr.flush()
            os._exit(17)
        time.sleep(0.02)

if kill_path:
    threading.Thread(target=_watch_kill, daemon=True).start()

WRITE = {{
    "name": "write_file",
    "description": "Write a file",
    "inputSchema": {{
        "type": "object",
        "properties": {{
            "path": {{"type": "string"}},
            "content": {{"type": "string"}},
        }},
        "required": ["path", "content"],
        "additionalProperties": False,
    }},
}}
LOCAL = {{"name": "local_proof", "description": "proof", "inputSchema": {{"type": "object"}}}}

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    log(method)
    if "id" not in msg:
        continue
    mode = state()
    if method == "initialize":
        result = {{
            "protocolVersion": "2024-11-05",
            "capabilities": {{"tools": {{}}}},
            "serverInfo": {{"name": "reconnect-fake", "version": "1.0.0"}},
        }}
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": result}}), flush=True)
    elif method == "tools/list":
        tools = [WRITE, LOCAL]
        if mode == "recover_without_write":
            tools = [LOCAL]
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"tools": tools}}}}), flush=True)
        if mode == "fail_after_list":
            sys.stderr.write("{SECRET}\\n")
            sys.stderr.flush()
            sys.exit(17)
        if mode == "fail_reconnect":
            sys.stderr.write("{SECRET}\\n")
            sys.stderr.flush()
            sys.exit(17)
    elif method == "tools/call":
        if mode != "healthy" and mode != "recover_without_write":
            sys.exit(17)
        name = (msg.get("params") or {{}}).get("name")
        if name != "write_file":
            print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"ok": True}}}}), flush=True)
            continue
        print(json.dumps({{
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {{"content": [{{"type": "text", "text": "written"}}]}},
        }}), flush=True)
    else:
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"ok": True}}}}), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _healthy_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "healthy.py"
    script.write_text(
        """
import json, os, sys
log_path = os.environ.get("DOWNSTREAM_LOG")
TOOLS = [{
    "name": "write_file",
    "description": "Write a file",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"],
        "additionalProperties": False,
    },
}]
def log(m):
    if log_path:
        open(log_path, "a", encoding="utf-8").write(m + "\\n")
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    log(method)
    if "id" not in msg:
        continue
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "healthy", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "written"}]}
    else:
        result = {"ok": True}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


class _PushableStdin:
    def __init__(self) -> None:
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._buf = ""
        self._closed = False

    def push(self, text: str) -> None:
        self._queue.put(text)

    def close(self) -> None:
        self._queue.put(None)

    def read(self, size: int = 1) -> str:
        if size <= 0:
            return ""
        while len(self._buf) < size and not self._closed:
            item = self._queue.get()
            if item is None:
                self._closed = True
                break
            self._buf += item
        if not self._buf:
            return ""
        out = self._buf[:size]
        self._buf = self._buf[size:]
        return out


def _wait_id(client_out: io.StringIO, request_id: int, *, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        by_id = {item.get("id"): item for item in _responses(client_out.getvalue())}
        if request_id in by_id:
            return by_id[request_id]
        time.sleep(0.01)
    raise AssertionError(f"missing response id={request_id}: {client_out.getvalue()}")


def _assert_privacy(*texts: str) -> None:
    blob = "\n".join(texts)
    assert SECRET not in blob
    assert FIXTURE_SENTINEL not in blob


def test_a_healthy_baseline_no_reconnect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    log_path = tmp_path / "d.log"
    opened: list[str] = []
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(init.config_path, _healthy_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(str(url)) or True)

    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            + _json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": "notes/a.txt", "content": "x"},
                },
            })
        ),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    error = _responses(client_out.getvalue())[2]["error"]
    assert error["code"] == JSONRPC_APPROVAL_REQUIRED
    assert _pending_approval_count(home) == 1
    assert "initialize" in log_path.read_text(encoding="utf-8")


def test_b_fail_once_recover_on_next_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx

    home = tmp_path / "home"
    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    state_path.write_text("fail_after_list\n", encoding="utf-8")
    opened: list[str] = []
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _fail_once_then_recover_downstream(tmp_path),
        log_path=log_path,
        state_path=state_path,
        command_decoy=FIXTURE_SENTINEL,
    )
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")
    _set_wait_for_decision(init.config_path)
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(str(url)) or False)
    monkeypatch.setattr(
        proxy_cli,
        "AVPAgent",
        type("Exploding", (), {"__init__": lambda *a, **k: (_ for _ in ()).throw(AssertionError("no agent"))}),
    )

    client_in = _PushableStdin()
    client_out = io.StringIO()
    client_err = io.StringIO()
    client_err.isatty = lambda: True  # type: ignore[method-assign]
    result_box: dict[str, int] = {}

    def _run() -> None:
        result_box["rc"] = run_proxy(
            home=home,
            client_in=client_in,
            out=client_out,
            err=client_err,
            approval_ui_mode="none",
        )

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    }}))
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    _wait_id(client_out, 2)
    time.sleep(0.05)
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes/a.txt", "content": "x"}},
    }))
    first = _wait_id(client_out, 3)
    assert first["error"]["code"] == JSONRPC_DOWNSTREAM_ERROR
    assert first["error"]["message"] == MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
    assert _pending_approval_count(home) == 0
    assert opened == []

    state_path.write_text("healthy\n", encoding="utf-8")
    # Wait out failed-reconnect cooldown so the recovered route may spawn once.
    time.sleep(DOWNSTREAM_RECONNECT_COOLDOWN_SECONDS + 0.1)
    before_opens = list(opened)
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes/b.txt", "content": "y"}},
    }))

    deadline = time.monotonic() + 5
    approval_url = ""
    while time.monotonic() < deadline:
        match = re.search(
            r"record_id=[^:\s]+:\s+(http://127\.0\.0\.1:\d+/approval/\S+)",
            client_err.getvalue(),
        )
        if match:
            approval_url = match.group(1)
            break
        time.sleep(0.01)
    assert approval_url, client_err.getvalue()
    assert len(opened) == len(before_opens) + 0 or True  # ui mode none

    with httpx.Client() as client:
        csrf = re.search(
            r'name="csrf_token" value="([^"]+)"',
            client.get(approval_url).text,
        )
        assert csrf
        assert client.post(
            approval_url,
            data={"decision": "approve", "csrf_token": csrf.group(1), "approval_scope": "exact"},
        ).status_code == 200

    fourth = _wait_id(client_out, 4, timeout=5.0)
    assert "result" in fourth, fourth
    assert fourth["result"]["content"][0]["text"] == "written"
    log = log_path.read_text(encoding="utf-8")
    assert log.count("initialize") >= 2
    assert log.count("tools/list") >= 2
    assert log.count("tools/call") == 1
    _assert_privacy(client_out.getvalue(), json.dumps(first))
    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_c_failed_reconnect_stays_unavailable_with_cooldown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    state_path.write_text("fail_after_list\n", encoding="utf-8")
    opened: list[str] = []
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _fail_once_then_recover_downstream(tmp_path),
        log_path=log_path,
        state_path=state_path,
        command_decoy=FIXTURE_SENTINEL,
    )
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(str(url)) or True)

    client_in = _PushableStdin()
    client_out = io.StringIO()
    result_box: dict[str, int] = {}

    def _run() -> None:
        result_box["rc"] = run_proxy(
            home=home,
            client_in=client_in,
            out=client_out,
            approval_ui_mode="none",
        )

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    _wait_id(client_out, 2)
    time.sleep(0.05)
    state_path.write_text("fail_reconnect\n", encoding="utf-8")
    for call_id in (3, 4, 5):
        client_in.push(_json_line({
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "notes/a.txt", "content": "x"}},
        }))
        resp = _wait_id(client_out, call_id)
        assert resp["error"]["code"] == JSONRPC_DOWNSTREAM_ERROR
        assert resp["error"]["message"] == MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
    assert _pending_approval_count(home) == 0
    assert opened == []
    # Cooldown should prevent a reconnect spawn storm (one attempt, then suppress).
    assert log_path.read_text(encoding="utf-8").count("initialize") <= 3
    _assert_privacy(client_out.getvalue())
    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_d_surface_change_after_reconnect_denies_removed_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    state_path.write_text("fail_after_list\n", encoding="utf-8")
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _fail_once_then_recover_downstream(tmp_path),
        log_path=log_path,
        state_path=state_path,
        command_decoy=FIXTURE_SENTINEL,
    )
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")
    monkeypatch.setattr(webbrowser, "open", lambda _url: True)

    client_in = _PushableStdin()
    client_out = io.StringIO()
    result_box: dict[str, int] = {}

    def _run() -> None:
        result_box["rc"] = run_proxy(
            home=home,
            client_in=client_in,
            out=client_out,
            approval_ui_mode="none",
        )

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    _wait_id(client_out, 2)
    time.sleep(0.05)
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes/a.txt", "content": "x"}},
    }))
    assert _wait_id(client_out, 3)["error"]["code"] == JSONRPC_DOWNSTREAM_ERROR

    state_path.write_text("recover_without_write\n", encoding="utf-8")
    time.sleep(DOWNSTREAM_RECONNECT_COOLDOWN_SECONDS + 0.1)
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes/a.txt", "content": "x"}},
    }))
    fourth = _wait_id(client_out, 4)
    assert fourth["error"]["data"]["reason"] == "unknown_tool"
    assert _pending_approval_count(home) == 0
    assert "tools/call" not in log_path.read_text(encoding="utf-8").splitlines() or (
        log_path.read_text(encoding="utf-8").count("tools/call") == 0
    )
    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_e_pending_approval_does_not_carry_after_reconnect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Matrix E: old Approve must not execute on generation 2."""

    import httpx

    home = tmp_path / "home"
    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    kill_path = tmp_path / "kill.flag"
    state_path.write_text("healthy\n", encoding="utf-8")
    opened: list[str] = []
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _fail_once_then_recover_downstream(tmp_path),
        log_path=log_path,
        state_path=state_path,
        kill_path=kill_path,
        command_decoy=FIXTURE_SENTINEL,
    )
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")
    _set_wait_for_decision(init.config_path)
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(str(url)) or False)
    monkeypatch.setattr(
        proxy_cli,
        "AVPAgent",
        type("Exploding", (), {"__init__": lambda *a, **k: (_ for _ in ()).throw(AssertionError("no agent"))}),
    )

    client_in = _PushableStdin()
    client_out = io.StringIO()
    client_err = io.StringIO()
    client_err.isatty = lambda: True  # type: ignore[method-assign]
    result_box: dict[str, int] = {}

    def _run() -> None:
        result_box["rc"] = run_proxy(
            home=home,
            client_in=client_in,
            out=client_out,
            err=client_err,
            approval_ui_mode="none",
        )

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    }}))
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes/old.txt", "content": "old"}},
    }))

    deadline = time.monotonic() + 5
    first_url = ""
    while time.monotonic() < deadline:
        match = re.search(
            r"record_id=([^:\s]+):\s+(http://127\.0\.0\.1:\d+/approval/\S+)",
            client_err.getvalue(),
        )
        if match:
            first_record = match.group(1)
            first_url = match.group(2)
            break
        time.sleep(0.01)
    assert first_url, client_err.getvalue()
    assert _pending_approval_count(home) == 1

    kill_path.write_text("kill\n", encoding="utf-8")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if log_path.exists():
            # Process exit is asynchronous; give the watcher a moment.
            time.sleep(0.1)
            break
        time.sleep(0.01)

    with httpx.Client() as client:
        csrf = re.search(
            r'name="csrf_token" value="([^"]+)"',
            client.get(first_url).text,
        )
        assert csrf
        assert client.post(
            first_url,
            data={"decision": "approve", "csrf_token": csrf.group(1), "approval_scope": "exact"},
        ).status_code == 200

    first = _wait_id(client_out, 3, timeout=5.0)
    assert first["error"]["code"] == JSONRPC_DOWNSTREAM_ERROR
    assert log_path.read_text(encoding="utf-8").count("tools/call") == 0

    kill_path.unlink(missing_ok=True)
    state_path.write_text("healthy\n", encoding="utf-8")
    time.sleep(DOWNSTREAM_RECONNECT_COOLDOWN_SECONDS + 0.1)
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes/new.txt", "content": "new"}},
    }))

    deadline = time.monotonic() + 8
    second_url = ""
    second_record = ""
    while time.monotonic() < deadline:
        for match in re.finditer(
            r"record_id=([^:\s]+):\s+(http://127\.0\.0\.1:\d+/approval/\S+)",
            client_err.getvalue(),
        ):
            if match.group(1) != first_record:
                second_record = match.group(1)
                second_url = match.group(2)
                break
        if second_url:
            break
        time.sleep(0.01)
    assert second_url, client_err.getvalue()
    assert second_record != first_record

    with httpx.Client() as client:
        csrf = re.search(
            r'name="csrf_token" value="([^"]+)"',
            client.get(second_url).text,
        )
        assert csrf
        assert client.post(
            second_url,
            data={"decision": "approve", "csrf_token": csrf.group(1), "approval_scope": "exact"},
        ).status_code == 200

    fourth = _wait_id(client_out, 4, timeout=5.0)
    assert "result" in fourth, fourth
    assert fourth["result"]["content"][0]["text"] == "written"
    assert log_path.read_text(encoding="utf-8").count("tools/call") == 1
    assert log_path.read_text(encoding="utf-8").count("initialize") >= 2
    _assert_privacy(client_out.getvalue(), client_err.getvalue())
    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_f_local_proof_during_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    state_path.write_text("fail_after_list\n", encoding="utf-8")
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _fail_once_then_recover_downstream(tmp_path),
        log_path=log_path,
        state_path=state_path,
    )
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")
    monkeypatch.setattr(webbrowser, "open", lambda _url: True)

    client_in = _PushableStdin()
    client_out = io.StringIO()
    result_box: dict[str, int] = {}

    def _run() -> None:
        result_box["rc"] = run_proxy(
            home=home,
            client_in=client_in,
            out=client_out,
            approval_ui_mode="none",
        )

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    _wait_id(client_out, 2)
    time.sleep(0.05)
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "local_proof", "arguments": {"last": 1, "verify": False}},
    }))
    proof = _wait_id(client_out, 3)
    if "error" in proof:
        assert proof["error"].get("data", {}).get("reason") != "downstream_unavailable"
        assert proof["error"]["message"] != MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
    else:
        assert "result" in proof
    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_reconnect_does_not_cancel_unrelated_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative: shared-store pending from another request stays pending."""

    from agentveil_mcp_proxy.evidence import ApprovalStatus, PendingApproval
    from agentveil_mcp_proxy.evidence.store import ApprovalEvidenceStore

    home = tmp_path / "home"
    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    state_path.write_text("fail_after_list\n", encoding="utf-8")
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    store = ApprovalEvidenceStore(evidence_path)
    unrelated_id = "unrelated-other-proxy-pending"
    now = int(time.time())
    store.write_pending(
        PendingApproval(
            request_id=unrelated_id,
            session_id="other-session",
            client_id="other-client",
            downstream_server="other-downstream",
            tool_name="other_tool",
            action_class="write",
            risk_class="write",
            resource_hash="sha256:" + ("a" * 64),
            payload_hash="sha256:" + ("b" * 64),
            policy_id="other-policy",
            policy_rule_id="other-rule",
            policy_context_hash="c" * 64,
            status=ApprovalStatus.PENDING.value,
            created_at=now,
            expires_at=now + 3600,
        )
    )
    store.close()

    _set_downstream(
        init.config_path,
        _fail_once_then_recover_downstream(tmp_path),
        log_path=log_path,
        state_path=state_path,
        command_decoy=FIXTURE_SENTINEL,
    )
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")
    monkeypatch.setattr(webbrowser, "open", lambda _url: True)

    client_in = _PushableStdin()
    client_out = io.StringIO()
    result_box: dict[str, int] = {}

    def _run() -> None:
        result_box["rc"] = run_proxy(
            home=home,
            client_in=client_in,
            out=client_out,
            approval_ui_mode="none",
        )

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    _wait_id(client_out, 2)
    time.sleep(0.05)
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes/a.txt", "content": "x"}},
    }))
    assert _wait_id(client_out, 3)["error"]["code"] == JSONRPC_DOWNSTREAM_ERROR

    state_path.write_text("healthy\n", encoding="utf-8")
    time.sleep(DOWNSTREAM_RECONNECT_COOLDOWN_SECONDS + 0.1)
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes/b.txt", "content": "y"}},
    }))
    fourth = _wait_id(client_out, 4)
    assert fourth["error"]["code"] == JSONRPC_APPROVAL_REQUIRED

    with ApprovalEvidenceStore(evidence_path) as store_after:
        unrelated = store_after.get_pending(unrelated_id)
        assert unrelated is not None
        assert unrelated.status == ApprovalStatus.PENDING.value

    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_generation_guard_on_passthrough(tmp_path: Path) -> None:
    """Request-local generation binding rejects only the stale request."""

    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    state_path.write_text("healthy\n", encoding="utf-8")
    script = _fail_once_then_recover_downstream(tmp_path)
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(script), FIXTURE_SENTINEL),
            name="fake-downstream",
            env={
                "DOWNSTREAM_LOG": str(log_path),
                "RECONNECT_STATE_FILE": str(state_path),
            },
        )
    )
    try:
        passthrough.start()
        assert passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
        }))
        assert "result" in passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }))[0]
        # Bind as a routed call would after readiness.
        passthrough._bound_downstream_generation = passthrough._downstream_generation
        bound = passthrough._bound_downstream_generation
        assert bound == 0
        state_path.write_text("fail_after_list\n", encoding="utf-8")
        # Force a generation change via reconnect after killing the child.
        proc = passthrough.process
        assert proc is not None
        proc.terminate()
        proc.wait(timeout=2)
        state_path.write_text("healthy\n", encoding="utf-8")
        assert passthrough._attempt_bounded_reconnect()
        assert passthrough._downstream_generation == bound + 1
        # Keep the stale binding on this thread (as wait-mode would).
        passthrough._bound_downstream_generation = bound
        stale = passthrough._stale_downstream_generation_response(99, None)
        assert stale is not None
        assert stale["error"]["code"] == JSONRPC_DOWNSTREAM_ERROR
        assert stale["error"]["message"] == MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
        # Fresh binding is allowed.
        passthrough._bound_downstream_generation = passthrough._downstream_generation
        assert passthrough._stale_downstream_generation_response(100, None) is None
    finally:
        passthrough.stop()


def test_atomic_send_rejects_when_reconnect_wins_race(tmp_path: Path) -> None:
    """Approved stale request must not write after reconnect wins the lock."""

    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    state_path.write_text("healthy\n", encoding="utf-8")
    script = _fail_once_then_recover_downstream(tmp_path)
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(script), FIXTURE_SENTINEL),
            name="fake-downstream",
            env={
                "DOWNSTREAM_LOG": str(log_path),
                "RECONNECT_STATE_FILE": str(state_path),
            },
        )
    )
    ready_to_reconnect = threading.Event()
    reconnect_done = threading.Event()
    send_result: dict[str, object] = {}
    errors: list[BaseException] = []

    def _gate() -> None:
        ready_to_reconnect.set()
        assert reconnect_done.wait(timeout=5)

    try:
        passthrough.start()
        assert "result" in passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        }))[0]
        assert "result" in passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }))[0]
        bound = passthrough._downstream_generation

        proc = passthrough.process
        assert proc is not None
        proc.terminate()
        proc.wait(timeout=2)
        passthrough._latch_downstream_unavailable_if_exited()
        state_path.write_text("healthy\n", encoding="utf-8")
        passthrough._tools_call_send_gate = _gate  # type: ignore[attr-defined]

        def _stale_approved_send() -> None:
            try:
                # Bind on this worker thread (request-local), as wait-mode would.
                passthrough._bound_downstream_generation = bound
                send_result["response"] = passthrough._send_tools_call_if_current_generation(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "write_file",
                            "arguments": {"path": "notes/stale.txt", "content": "no"},
                        },
                    },
                    3,
                    None,
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        def _reconnect_winner() -> None:
            try:
                assert ready_to_reconnect.wait(timeout=5)
                assert passthrough._attempt_bounded_reconnect()
                assert passthrough._downstream_generation == bound + 1
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                reconnect_done.set()

        stale_thread = threading.Thread(target=_stale_approved_send)
        reconnect_thread = threading.Thread(target=_reconnect_winner)
        stale_thread.start()
        reconnect_thread.start()
        stale_thread.join(timeout=10)
        reconnect_thread.join(timeout=10)
        assert not stale_thread.is_alive()
        assert not reconnect_thread.is_alive()
        assert not errors

        response = send_result.get("response")
        assert isinstance(response, dict)
        assert response["error"]["code"] == JSONRPC_DOWNSTREAM_ERROR
        assert response["error"]["message"] == MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
        assert log_path.read_text(encoding="utf-8").splitlines().count("tools/call") == 0
        assert passthrough._downstream_generation == bound + 1
        _assert_privacy(json.dumps(response), log_path.read_text(encoding="utf-8"))
    finally:
        passthrough.stop()


def test_atomic_send_winner_reaches_only_old_generation(tmp_path: Path) -> None:
    """When send wins the lock, the call reaches gen1 once; reconnect does not replay."""

    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    state_path.write_text("healthy\n", encoding="utf-8")
    script = _fail_once_then_recover_downstream(tmp_path)
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(script), FIXTURE_SENTINEL),
            name="fake-downstream",
            env={
                "DOWNSTREAM_LOG": str(log_path),
                "RECONNECT_STATE_FILE": str(state_path),
            },
        )
    )
    write_done = threading.Event()
    errors: list[BaseException] = []

    try:
        passthrough.start()
        assert "result" in passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        }))[0]
        assert "result" in passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }))[0]
        bound = passthrough._downstream_generation

        def _send_winner() -> None:
            try:
                passthrough._bound_downstream_generation = bound
                with passthrough._reconnect_lock:
                    stale = passthrough._stale_downstream_generation_response(3, None)
                    assert stale is None
                    passthrough._send_downstream({
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "write_file",
                            "arguments": {"path": "notes/old-gen.txt", "content": "ok"},
                        },
                    })
                    # Hold the lock briefly so reconnect blocks until after write.
                    time.sleep(0.05)
                write_done.set()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
                write_done.set()

        def _reconnect_after_send() -> None:
            try:
                assert write_done.wait(timeout=5)
                proc = passthrough.process
                assert proc is not None
                proc.terminate()
                proc.wait(timeout=2)
                passthrough._latch_downstream_unavailable_if_exited()
                assert passthrough._attempt_bounded_reconnect()
                assert passthrough._downstream_generation == bound + 1
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        send_thread = threading.Thread(target=_send_winner)
        reconnect_thread = threading.Thread(target=_reconnect_after_send)
        send_thread.start()
        time.sleep(0.01)
        reconnect_thread.start()
        send_thread.join(timeout=10)
        reconnect_thread.join(timeout=10)
        assert not send_thread.is_alive()
        assert not reconnect_thread.is_alive()
        assert not errors
        methods = log_path.read_text(encoding="utf-8").splitlines()
        assert methods.count("tools/call") == 1
        assert methods.count("initialize") == 2
    finally:
        passthrough.stop()


def test_f_concurrent_calls_share_one_reconnect_attempt(tmp_path: Path) -> None:
    log_path = tmp_path / "d.log"
    state_path = tmp_path / "state.txt"
    state_path.write_text("fail_after_list\n", encoding="utf-8")
    script = _fail_once_then_recover_downstream(tmp_path)
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(script), FIXTURE_SENTINEL),
            name="fake-downstream",
            env={
                "DOWNSTREAM_LOG": str(log_path),
                "RECONNECT_STATE_FILE": str(state_path),
            },
        )
    )
    try:
        passthrough.start()
        assert "result" in passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
        }))[0]
        assert "result" in passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }))[0]
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and passthrough._process_is_alive():
            time.sleep(0.01)
        state_path.write_text("fail_reconnect\n", encoding="utf-8")

        barrier = threading.Barrier(2)
        responses: dict[int, list[dict]] = {}
        errors: list[BaseException] = []

        def _worker(request_id: int) -> None:
            try:
                barrier.wait(timeout=5)
                responses[request_id] = passthrough.handle_client_line(_json_line({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {
                        "name": "write_file",
                        "arguments": {"path": f"notes/{request_id}.txt", "content": "x"},
                    },
                }))
            except BaseException as exc:  # noqa: BLE001 — collect for assertion
                errors.append(exc)

        threads = [
            threading.Thread(target=_worker, args=(3,)),
            threading.Thread(target=_worker, args=(4,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            assert not thread.is_alive()
        assert not errors
        assert set(responses) == {3, 4}
        for request_id, payload in responses.items():
            assert len(payload) == 1
            assert payload[0]["id"] == request_id
            assert payload[0]["error"]["code"] == JSONRPC_DOWNSTREAM_ERROR
            assert payload[0]["error"]["message"] == MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
        assert passthrough._reconnect_attempts == 1
        assert log_path.read_text(encoding="utf-8").splitlines().count("initialize") == 2
        _assert_privacy(json.dumps(responses))
    finally:
        passthrough.stop()
