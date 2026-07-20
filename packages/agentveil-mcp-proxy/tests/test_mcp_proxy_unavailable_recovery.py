"""AV-05: bounded recovery when the controlled MCP route/downstream is unavailable."""

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
from agentveil_mcp_proxy import claude_hook, codex_hook, cursor_hooks, gemini_hook
from agentveil_mcp_proxy.cli import init_proxy, run_proxy
from agentveil_mcp_proxy.client_guidance import (
    MCP_ROUTE_UNAVAILABLE_NEXT_STEP,
    MCP_ROUTE_UNAVAILABLE_USER_MESSAGE,
    NATIVE_CONTROLLED_MCP_REDIRECT_INSTRUCTION,
)
from agentveil_mcp_proxy.passthrough import (
    DownstreamConfig,
    JSONRPC_APPROVAL_REQUIRED,
    JSONRPC_DOWNSTREAM_ERROR,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_POLICY_BLOCKED,
    McpPassthrough,
)


SECRET = "SECRET_DOWNSTREAM_TOKEN_AV05"
HOME_SENTINEL = "/Users/secret-home-av05"
FIXTURE_SENTINEL = "/tmp/avp-av05-secret-fixture.py"


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
    command_decoy: str | None = None,
) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    env = {}
    if log_path is not None:
        env["DOWNSTREAM_LOG"] = str(log_path)
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


def _list_then_die_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "list_then_die.py"
    script.write_text(
        f"""
import json
import os
import sys

log_path = os.environ.get("DOWNSTREAM_LOG")

def log(method):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(method + "\\n")

TOOLS = [
    {{"name": "write_file", "description": "Write a file", "inputSchema": {{
        "type": "object",
        "properties": {{
            "path": {{"type": "string"}},
            "content": {{"type": "string"}},
        }},
        "required": ["path", "content"],
        "additionalProperties": False,
    }}}},
    {{"name": "read_file", "description": "Read a file", "inputSchema": {{"type": "object"}}}},
    {{"name": "local_proof", "description": "Show local proof", "inputSchema": {{"type": "object"}}}},
]

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    log(method)
    if "id" not in msg:
        continue
    if method == "initialize":
        result = {{
            "protocolVersion": "2024-11-05",
            "capabilities": {{"tools": {{}}}},
            "serverInfo": {{"name": "list-then-die", "version": "1.0.0"}},
        }}
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": result}}), flush=True)
    elif method == "tools/list":
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"tools": TOOLS}}}}), flush=True)
        sys.stderr.write("{SECRET}\\n")
        sys.stderr.flush()
        sys.exit(17)
    else:
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"ok": True}}}}), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _die_on_tools_call_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "die_on_tools_call.py"
    script.write_text(
        f"""
import json
import os
import sys

log_path = os.environ.get("DOWNSTREAM_LOG")

def log(method):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(method + "\\n")

TOOLS = [
    {{"name": "write_file", "description": "Write a file", "inputSchema": {{"type": "object"}}}},
]

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    log(method)
    if "id" not in msg:
        continue
    if method == "initialize":
        result = {{
            "protocolVersion": "2024-11-05",
            "capabilities": {{"tools": {{}}}},
            "serverInfo": {{"name": "die-on-call", "version": "1.0.0"}},
        }}
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": result}}), flush=True)
    elif method == "tools/list":
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"tools": TOOLS}}}}), flush=True)
    elif method == "tools/call":
        sys.stderr.write("{SECRET}\\n")
        sys.stderr.flush()
        sys.exit(17)
    else:
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"ok": True}}}}), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _die_after_initialize_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "die_after_initialize.py"
    script.write_text(
        f"""
import json
import sys

line = sys.stdin.readline()
msg = json.loads(line)
print(json.dumps({{
    "jsonrpc": "2.0",
    "id": msg["id"],
    "result": {{
        "protocolVersion": "2024-11-05",
        "capabilities": {{"tools": {{}}}},
        "serverInfo": {{"name": "die-after-init", "version": "1.0.0"}},
    }},
}}), flush=True)
sys.stderr.write("{SECRET}\\n")
sys.stderr.flush()
sys.exit(17)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _healthy_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "healthy_downstream.py"
    script.write_text(
        """
import json
import os
import sys

log_path = os.environ.get("DOWNSTREAM_LOG")
TOOLS = [
    {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
]

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
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "healthy", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "called"}]}
    else:
        result = {"ok": True}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _assert_connector_visible_unavailable(error: dict) -> None:
    message = error["message"]
    assert message == MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
    assert "Stop this action" in message
    assert "tell the user" in message
    assert "Do not retry" in message
    assert "request another approval" in message
    assert "inspect raw configuration" in message
    assert "bypass" in message.lower()
    assert "then retry the same protected action" not in message.lower()
    data = error["data"]
    assert data["reason"] == "downstream_unavailable"
    assert data["reason_code"] == "downstream_unavailable"
    assert data["target_reached"] is False
    assert data["approval_possible"] is False
    assert data["retry_after_approval"] is False
    assert data["next_step"] == MCP_ROUTE_UNAVAILABLE_NEXT_STEP
    assert data.get("status") != "approval_required"


def _assert_privacy_clean(*texts: str) -> None:
    blob = "\n".join(texts)
    assert SECRET not in blob
    assert HOME_SENTINEL not in blob
    assert FIXTURE_SENTINEL not in blob
    assert "http://" not in blob
    assert "https://" not in blob
    assert "manifest" not in blob.lower()


class _PushableStdin:
    """Character-at-a-time stdin that accepts lines from a producer thread."""

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


def test_approval_enabled_known_unavailable_skips_pending_and_ac(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Approval policy + dead downstream: unavailable before pending/AC."""

    home = tmp_path / "avp-home"
    log_path = tmp_path / "downstream.log"
    opened: list[str] = []
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _list_then_die_downstream(tmp_path),
        log_path=log_path,
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

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        by_id = {item.get("id"): item for item in _responses(client_out.getvalue())}
        if 2 in by_id and "result" in by_id[2]:
            break
        time.sleep(0.01)
    else:
    raise AssertionError(f"no tools/list response before deadline: {client_out.getvalue()}")

    # Wait until the downstream exit is observable before the mutation call.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if log_path.exists() and "tools/list" in log_path.read_text(encoding="utf-8"):
            time.sleep(0.05)
            break
        time.sleep(0.01)

    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "notes/av05.txt",
                "content": "should-not-reach",
            },
        },
    }))

    deadline = time.monotonic() + 5
    error = None
    while time.monotonic() < deadline:
        by_id = {item.get("id"): item for item in _responses(client_out.getvalue())}
        if 3 in by_id and "error" in by_id[3]:
            error = by_id[3]["error"]
            break
        time.sleep(0.01)
    assert error is not None, client_out.getvalue()
    assert error["code"] == JSONRPC_DOWNSTREAM_ERROR
    _assert_connector_visible_unavailable(error)
    assert _pending_approval_count(home) == 0
    assert _approval_record_count(home) == 0
    assert opened == []
    assert log_path.read_text(encoding="utf-8").splitlines() == ["initialize", "tools/list"]
    _assert_privacy_clean(client_out.getvalue(), json.dumps(error))

    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_unavailable_after_approve_blocks_second_approval_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Race: die after Approve → first unavailable; retry skips new AC."""

    import httpx

    home = tmp_path / "avp-home"
    log_path = tmp_path / "downstream.log"
    opened: list[str] = []
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _die_on_tools_call_downstream(tmp_path),
        log_path=log_path,
        command_decoy=FIXTURE_SENTINEL,
    )
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")
    _set_wait_for_decision(init.config_path)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("wait-mode must not construct AVPAgent before approve")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(str(url)) or False)

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
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "notes/av05.txt", "content": "x", "token": SECRET},
        },
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
    first_opened = list(opened)

    with httpx.Client() as client:
        csrf_match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            client.get(approval_url).text,
        )
        assert csrf_match
        approve = client.post(
            approval_url,
            data={
                "decision": "approve",
                "csrf_token": csrf_match.group(1),
                "approval_scope": "exact",
            },
        )
    assert approve.status_code == 200

    deadline = time.monotonic() + 5
    first_error = None
    while time.monotonic() < deadline:
        responses = _responses(client_out.getvalue())
        by_id = {item.get("id"): item for item in responses}
        if 3 in by_id and "error" in by_id[3]:
            first_error = by_id[3]["error"]
            break
        time.sleep(0.01)
    assert first_error is not None
    _assert_connector_visible_unavailable(first_error)
    records_after_first = _approval_record_count(home)
    assert records_after_first >= 1
    pending_after_first = _pending_approval_count(home)

    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "notes/av05.txt", "content": "x", "token": SECRET},
        },
    }))
    deadline = time.monotonic() + 5
    second_error = None
    while time.monotonic() < deadline:
        responses = _responses(client_out.getvalue())
        by_id = {item.get("id"): item for item in responses}
        if 4 in by_id and "error" in by_id[4]:
            second_error = by_id[4]["error"]
            break
        time.sleep(0.01)
    assert second_error is not None
    _assert_connector_visible_unavailable(second_error)
    assert second_error["code"] == JSONRPC_DOWNSTREAM_ERROR
    assert _approval_record_count(home) == records_after_first
    assert _pending_approval_count(home) == pending_after_first
    assert opened == first_opened
    assert "tools/call" in log_path.read_text(encoding="utf-8")
    # Second call must not reach a live downstream mutation after latch.
    assert log_path.read_text(encoding="utf-8").count("tools/call") == 1
    _assert_privacy_clean(client_out.getvalue(), json.dumps(first_error), json.dumps(second_error))

    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_passthrough_tools_list_unavailable_includes_contract(tmp_path: Path) -> None:
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_die_after_initialize_downstream(tmp_path)), FIXTURE_SENTINEL),
        name="die-after-init",
    ))
    client_out = io.StringIO()
    assert passthrough.run_stdio(
        io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            + _json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        ),
        client_out,
    ) == 0
    responses = _responses(client_out.getvalue())
    assert responses[1]["error"]["code"] == JSONRPC_DOWNSTREAM_ERROR
    _assert_connector_visible_unavailable(responses[1]["error"])
    _assert_privacy_clean(client_out.getvalue())


def test_connector_visible_message_does_not_require_error_data() -> None:
    """Guidance must be in error.message without reading error.data."""

    message = MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
    assert "Stop this action" in message
    assert "tell the user" in message
    assert "Do not retry" in message
    assert "request another approval" in message
    assert "inspect raw configuration" in message
    assert "bypass" in message.lower()
    assert "then retry" not in message.lower()


def _extract_deny_text(module, rendered: str) -> str:
    body = json.loads(rendered)
    if module is cursor_hooks:
        return str(body["agent_message"])
    if module is gemini_hook:
        return str(body["reason"])
    return str(body["hookSpecificOutput"]["permissionDecisionReason"])


@pytest.mark.parametrize(
    "module,payload",
    [
        (
            claude_hook,
            {
                "session_id": "s",
                "cwd": "/tmp/av05",
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": "notes/a.txt", "content": "x"},
            },
        ),
        (
            cursor_hooks,
            {
                "hook_event": "preToolUse",
                "tool_name": "Write",
                "tool_input": {"path": "notes/a.txt", "contents": "x"},
            },
        ),
        (
            codex_hook,
            {
                "hook_event_name": "PreToolUse",
                "session_id": "s",
                "cwd": "/tmp/av05",
                "tool_name": "apply_patch",
                "tool_input": {"path": "notes/a.txt", "content": "x"},
            },
        ),
        (
            gemini_hook,
            {
                "hook_event_name": "BeforeTool",
                "session_id": "s",
                "cwd": "/tmp/av05",
                "tool_name": "write_file",
                "tool_input": {"path": "notes/a.txt", "content": "x"},
            },
        ),
    ],
)
def test_native_deny_uses_common_unavailable_recovery_guidance(
    module,
    payload,
    tmp_path: Path,
) -> None:
    out = io.StringIO()
    kwargs: dict = {"out": out}
    if module is cursor_hooks:
        kwargs["workspace"] = tmp_path
        kwargs["evidence_path"] = tmp_path / "evidence.jsonl"
    else:
        kwargs["evidence_path"] = tmp_path / "evidence.jsonl"

    decision = module.process_hook(payload, **kwargs)
    assert decision.hook_action == "deny"
    reason = _extract_deny_text(module, out.getvalue())
    assert NATIVE_CONTROLLED_MCP_REDIRECT_INSTRUCTION in reason
    lowered = reason.lower()
    assert "stop and tell the user" in lowered
    assert "do not retry" in lowered
    assert "request another approval" in lowered
    assert "inspect raw configuration" in lowered
    assert "bypass through native tools" in lowered
    assert "then retry the same protected action" not in lowered
    assert "after approval, retry the same mcp tool call once" not in lowered
    _assert_privacy_clean(reason)


def test_healthy_approval_flow_still_creates_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Healthy downstream keeps routed approval behavior."""

    home = tmp_path / "avp-home"
    log_path = tmp_path / "downstream.log"
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
                    "arguments": {"path": "notes/ok.txt", "content": "hello"},
                },
            })
        ),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    responses = _responses(client_out.getvalue())
    error = responses[2]["error"]
    assert error["code"] == JSONRPC_APPROVAL_REQUIRED
    assert error["data"]["status"] == "approval_required"
    assert error["data"]["approval_possible"] is True
    assert _pending_approval_count(home) == 1
    assert log_path.read_text(encoding="utf-8").splitlines() == ["initialize", "tools/list"]


def _wait_for_list_then_push_call(
    *,
    client_in: _PushableStdin,
    client_out: io.StringIO,
    log_path: Path,
    call_id: int,
    tool: str,
    arguments: dict,
) -> dict:
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
    client_in.push(_json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        by_id = {item.get("id"): item for item in _responses(client_out.getvalue())}
        if 2 in by_id and "result" in by_id[2]:
            break
        time.sleep(0.01)
    else:
    raise AssertionError(f"no tools/list response before deadline: {client_out.getvalue()}")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if log_path.exists() and "tools/list" in log_path.read_text(encoding="utf-8"):
            time.sleep(0.05)
            break
        time.sleep(0.01)
    client_in.push(_json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        by_id = {item.get("id"): item for item in _responses(client_out.getvalue())}
        if call_id in by_id:
            return by_id[call_id]
        time.sleep(0.01)
    raise AssertionError(
        f"no tools/call response for {call_id} before deadline: {client_out.getvalue()}"
    )


def test_dead_downstream_local_proof_is_not_downstream_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Local diagnostics must survive a known-dead downstream."""

    home = tmp_path / "avp-home"
    log_path = tmp_path / "downstream.log"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _list_then_die_downstream(tmp_path),
        log_path=log_path,
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
    response = _wait_for_list_then_push_call(
        client_in=client_in,
        client_out=client_out,
        log_path=log_path,
        call_id=3,
        tool="local_proof",
        arguments={"last": 1, "verify": False},
    )
    if "error" in response:
        data = response["error"].get("data") or {}
        assert data.get("reason") != "downstream_unavailable"
        assert response["error"]["message"] != MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
        assert data.get("reason") == "local_proof_unavailable"
    else:
        assert "result" in response
    assert _pending_approval_count(home) == 0
    _assert_privacy_clean(client_out.getvalue())
    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_dead_downstream_control_path_keeps_security_deny(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control-path hard deny must not be relabeled as downstream_unavailable."""

    home = tmp_path / "avp-home"
    log_path = tmp_path / "downstream.log"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _list_then_die_downstream(tmp_path),
        log_path=log_path,
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
    response = _wait_for_list_then_push_call(
        client_in=client_in,
        client_out=client_out,
        log_path=log_path,
        call_id=3,
        tool="write_file",
        arguments={"path": ".avp/mcp-proxy/config.json", "content": "x"},
    )
    error = response["error"]
    assert error["code"] == JSONRPC_POLICY_BLOCKED
    assert error["data"]["reason"] == "agentveil_control_path_blocked"
    assert error["message"] != MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
    assert _pending_approval_count(home) == 0
    _assert_privacy_clean(client_out.getvalue())
    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_dead_downstream_malformed_args_keep_invalid_params(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schema/argument validation must win over known-unavailable."""

    home = tmp_path / "avp-home"
    log_path = tmp_path / "downstream.log"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _list_then_die_downstream(tmp_path),
        log_path=log_path,
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
    response = _wait_for_list_then_push_call(
        client_in=client_in,
        client_out=client_out,
        log_path=log_path,
        call_id=3,
        tool="write_file",
        arguments={"file_path": "notes/a.txt", "content": "x"},
    )
    error = response["error"]
    assert error["code"] == JSONRPC_INVALID_PARAMS
    assert error["message"] == "invalid tool arguments"
    assert error["data"]["status"] == "invalid_tool_arguments"
    assert error["message"] != MCP_ROUTE_UNAVAILABLE_USER_MESSAGE
    assert _pending_approval_count(home) == 0
    _assert_privacy_clean(client_out.getvalue())
    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0


def test_dead_downstream_valid_mutation_is_unavailable_without_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid routed mutation still hits unavailable before approval."""

    home = tmp_path / "avp-home"
    log_path = tmp_path / "downstream.log"
    opened: list[str] = []
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(
        init.config_path,
        _list_then_die_downstream(tmp_path),
        log_path=log_path,
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
    response = _wait_for_list_then_push_call(
        client_in=client_in,
        client_out=client_out,
        log_path=log_path,
        call_id=3,
        tool="write_file",
        arguments={"path": "notes/av05.txt", "content": "should-not-reach"},
    )
    error = response["error"]
    assert error["code"] == JSONRPC_DOWNSTREAM_ERROR
    _assert_connector_visible_unavailable(error)
    assert _pending_approval_count(home) == 0
    assert opened == []
    client_in.close()
    worker.join(timeout=5)
    assert result_box.get("rc") == 0
