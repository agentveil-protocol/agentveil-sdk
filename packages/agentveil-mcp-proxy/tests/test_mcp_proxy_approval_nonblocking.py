"""AV-02 / AV-12: diagnostics and read-only tools during pending approval."""

from __future__ import annotations

import io
import json
import os
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.passthrough import (
    DownstreamConfig,
    McpPassthrough,
    STDIO_REQUEST_QUEUE_MAXSIZE,
    STDIO_REQUEST_WORKERS,
)
from agentveil_mcp_proxy.policy import build_redirect_automation_metadata

from mcp_fake_downstream import seed_tool_schemas, tool_entry, write_downstream
from test_mcp_proxy_approval import (
    _get_csrf,
    _manager,
    _post_decision,
)


def _json_line(message: dict[str, Any]) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _allow_diagnostic_rules() -> list[dict[str, Any]]:
    return [
        {
            "id": "allow-local-proof",
            "source": "user",
            "decision": "allow",
            "risk_class": "read",
            "match": {"tool": "local_proof"},
        },
        {
            "id": "allow-get-file-info",
            "source": "user",
            "decision": "allow",
            "risk_class": "read",
            "match": {"tool": "get_file_info"},
        },
        {
            "id": "allow-read-file",
            "source": "user",
            "decision": "allow",
            "risk_class": "read",
            "match": {"tool": "read_file"},
        },
    ]


def _mutation_rule() -> dict[str, Any]:
    return {
        "id": "write-file-approval",
        "source": "user",
        "decision": "approval",
        "risk_class": "write",
        "match": {"server": "filesystem", "tool": "write_file"},
    }


def _nonblocking_config(*, approval_timeout_seconds: int = 300):
    from agentveil_mcp_proxy.policy import ProxyConfig

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
            "production": "block",  # claim-check: allow fallback risk_class enum value
            "financial": "block",
            "unknown": "approval",
        },
        "approval": {
            "approval_timeout_seconds": approval_timeout_seconds,
            "on_timeout": "deny",
            "ui_open_mode": "browser",
        },
        "policy": {
            "id": "nonblocking-diagnostics",
            "policy_schema_version": 1,
            "default_decision": "approval",
            "default_risk_class": "write",
            "rules": [_mutation_rule(), *_allow_diagnostic_rules()],
        },
        "downstream": {},
    })


def _write_file_call(*, call_id: str = "write-1", path: str = "pending.txt") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": path, "content": "pending-body"},
        },
    })


def _local_proof_call(*, call_id: str = "proof-1") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": "local_proof", "arguments": {"last": 1, "verify": False}},
    })


def _get_file_info_call(*, call_id: str = "info-1", path: str = "notes.txt") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": "get_file_info", "arguments": {"path": path}},
    })


def _read_file_call(*, call_id: str = "read-1", path: str = "notes.txt") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": path}},
    })


def _approval_downstream(tmp_path: Path) -> Path:
    return write_downstream(
        tmp_path,
        filename="nonblocking_approval_downstream.py",
        tools=[
            tool_entry(
                "write_file",
                {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                    "additionalProperties": False,
                },
            ),
            tool_entry(
                "get_file_info",
                {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            tool_entry(
                "read_file",
                {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
        ],
        call_result_text="downstream-ok",
    )


class _TrackingTextIO(io.TextIOBase):
    """Line-oriented stdin that records how many parsed lines the dispatcher read."""

    def __init__(self) -> None:
        super().__init__()
        self._cond = threading.Condition()
        self._buffer = ""
        self._closed = False
        self.lines_consumed = 0

    def write_line(self, line: str) -> None:
        if not line.endswith("\n"):
            line = line + "\n"
        with self._cond:
            self._buffer += line
            self._cond.notify_all()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def read(self, size: int = 1) -> str:  # type: ignore[override]
        if size is None or size < 0:
            size = 1
        with self._cond:
            while not self._buffer and not self._closed:
                self._cond.wait(timeout=0.05)
            if not self._buffer:
                return ""
            chunk = self._buffer[:size]
            self._buffer = self._buffer[size:]
            if "\n" in chunk:
                self.lines_consumed += chunk.count("\n")
            return chunk


class _ThreadSafeClientOut:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._chunks: list[str] = []

    def write(self, value: str) -> int:
        with self._lock:
            self._chunks.append(value)
        return len(value)

    def flush(self) -> None:
        return None

    def responses(self) -> list[dict[str, Any]]:
        with self._lock:
            text = "".join(self._chunks)
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def response_by_id(self, request_id: Any) -> dict[str, Any] | None:
        for response in self.responses():
            if response.get("id") == request_id:
                return response
        return None


def _wait_until(predicate, *, timeout: float = 2.0, interval: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _path_logging_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "path_logging_downstream.py"
    script.write_text(
        """
import json
import os
import sys

TOOLS = [
    {"name": "write_file", "description": "write", "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"],
        "additionalProperties": False,
    }},
    {"name": "get_file_info", "description": "info", "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
        "additionalProperties": False,
    }},
    {"name": "read_file", "description": "read", "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
        "additionalProperties": False,
    }},
]
log_path = os.environ.get("DOWNSTREAM_LOG")

def _log(payload):
    if not log_path:
        return
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, separators=(",", ":")) + "\\n")

for raw in sys.stdin:
    message = json.loads(raw)
    method = message.get("method")
    request_id = message.get("id")
    if method == "tools/list":
        _log({"method": "tools/list", "id": request_id})
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}, separators=(",", ":")), flush=True)
        continue
    if method == "tools/call":
        params = message.get("params") or {}
        args = params.get("arguments") or {}
        _log({
            "method": "tools/call",
            "id": request_id,
            "tool": params.get("name"),
            "path": args.get("path"),
            "content": args.get("content"),
            "has_redirect_context": "redirect_context" in args,
        })
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": "downstream-ok"}]},
        }, separators=(",", ":")), flush=True)
        continue
    if "id" in message:
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {}}, separators=(",", ":")), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _build_passthrough(
    tmp_path: Path,
    *,
    wait_for_decision: bool = True,
    approval_timeout_seconds: int = 300,
    log_path: Path | None = None,
    downstream_script: Path | None = None,
):
    config = _nonblocking_config(approval_timeout_seconds=approval_timeout_seconds)
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=wait_for_decision,
    )
    env = {"DOWNSTREAM_LOG": str(log_path)} if log_path is not None else None
    script = downstream_script or _approval_downstream(tmp_path)
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(script)),
            name="filesystem",
            env=env,
        ),
        classifier=ToolCallClassifier(config, server_name="filesystem"),
        approval_manager=manager,
    )
    seed_tool_schemas(
        passthrough,
        [
            tool_entry("write_file"),
            tool_entry("get_file_info"),
            tool_entry("read_file"),
            tool_entry("local_proof"),
        ],
    )
    return passthrough, manager, store, server


def _seed_redirect_original(store, *, request_id: str, playbook_id: str = "use_read_only_tool") -> None:
    metadata = build_redirect_automation_metadata(
        fixture_id="nonblocking.redirect",
        tool_name="write_file",
        policy_decision="block",
        policy_rule_id="seed-redirect",
        approval_status=ApprovalStatus.BLOCKED.value,  # claim-check: allow tested status enum
        execution_status="not_reached",
        target_reached=False,
        request_id=request_id,
        redirect_role="original",
        redirect_playbook_id=playbook_id,
        original_request_id=request_id,
    )
    now = int(time.time())
    store.write_pending(
        PendingApproval(
            request_id=request_id,
            session_id="session-1234567890",
            client_id=f"cursor:pid:{os.getpid()}",
            downstream_server="filesystem",
            tool_name="write_file",
            action_class="write",
            risk_class="write",
            resource_hash="sha256:" + ("a" * 64),
            payload_hash="sha256:" + ("b" * 64),
            policy_id="nonblocking-diagnostics",
            policy_rule_id="seed-redirect",
            policy_context_hash="c" * 64,
            status=ApprovalStatus.PENDING.value,
            created_at=now,
            expires_at=now + 300,
            action_gate_metadata_jcs=json.dumps(metadata, separators=(",", ":"), sort_keys=True),
        )
    )


def _approve(server, request_id: str) -> None:
    with httpx.Client() as client:
        url = server.approval_url(request_id)
        csrf = _get_csrf(client, url)
        response = _post_decision(client, url, decision="approve", csrf=csrf)
        assert response.status_code == 200


def _deny(server, request_id: str) -> None:
    with httpx.Client() as client:
        url = server.approval_url(request_id)
        csrf = _get_csrf(client, url)
        response = _post_decision(client, url, decision="deny", csrf=csrf)
        assert response.status_code == 200


def _run_stdio_session(passthrough: McpPassthrough, client_in: _TrackingTextIO, client_out):
    return threading.Thread(
        target=lambda: passthrough.run_stdio(client_in, client_out),
        daemon=True,
    )


def test_pending_write_does_not_block_local_proof_on_run_stdio(tmp_path):
    passthrough, _manager_obj, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-1"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        lines_at_pending = client_in.lines_consumed
        assert lines_at_pending >= 1

        client_in.write_line(_local_proof_call(call_id="proof-1"))
        assert _wait_until(
            lambda: client_out.response_by_id("proof-1") is not None,
            timeout=2.0,
        ), (
            "local_proof must finish while write approval is still pending; "
            f"lines_consumed={client_in.lines_consumed} responses={client_out.responses()}"
        )
        proof = client_out.response_by_id("proof-1")
        assert proof is not None
        assert proof["id"] == "proof-1"
        assert "result" in proof
        assert client_out.response_by_id("write-1") is None
        assert server.pending_prompts()

        _approve(server, prompt.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-1") is not None,
            timeout=3.0,
        )
        write_response = client_out.response_by_id("write-1")
        assert write_response is not None
        assert write_response["id"] == "write-1"
        assert write_response["result"]["content"][0]["text"] == "downstream-ok"
        record = store.get_pending(prompt.request_id)
        assert record.status == ApprovalStatus.EXECUTED.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_pending_write_does_not_block_get_file_info_on_run_stdio(tmp_path):
    passthrough, _manager_obj, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-2"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]

        client_in.write_line(_get_file_info_call(call_id="info-1"))
        assert _wait_until(
            lambda: client_out.response_by_id("info-1") is not None,
            timeout=2.0,
        )
        info = client_out.response_by_id("info-1")
        assert info is not None
        assert info["id"] == "info-1"
        assert info["result"]["content"][0]["text"] == "downstream-ok"
        assert client_out.response_by_id("write-2") is None

        _approve(server, prompt.request_id)
        assert _wait_until(lambda: client_out.response_by_id("write-2") is not None, timeout=3.0)
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_pending_write_does_not_block_independent_read_file_on_run_stdio(tmp_path):
    passthrough, _manager_obj, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-3"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]

        client_in.write_line(_read_file_call(call_id="read-1"))
        assert _wait_until(
            lambda: client_out.response_by_id("read-1") is not None,
            timeout=2.0,
        )
        read_response = client_out.response_by_id("read-1")
        assert read_response is not None
        assert read_response["id"] == "read-1"
        assert read_response["result"]["content"][0]["text"] == "downstream-ok"
        assert client_out.response_by_id("write-3") is None

        _deny(server, prompt.request_id)
        assert _wait_until(lambda: client_out.response_by_id("write-3") is not None, timeout=3.0)
        write_response = client_out.response_by_id("write-3")
        assert write_response is not None
        assert write_response["error"]["data"]["reason"] == "user_denied"
        record = store.get_pending(prompt.request_id)
        assert record.status == ApprovalStatus.DENIED.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_pre_fix_serial_run_stdio_held_second_line_until_decision(tmp_path, monkeypatch):
    """Prove the historical failure mode: stdin dispatcher HOL behind approval."""

    from agentveil_mcp_proxy import passthrough as passthrough_module

    def serial_run_stdio(self, client_in, client_out):
        self._notification_writer = lambda message: self._write_client(client_out, message)
        self.start()
        try:
            while True:
                raw_line, rejected = passthrough_module._read_bounded_line(
                    client_in,
                    passthrough_module.MAX_CLIENT_MESSAGE_BYTES,
                )
                if rejected:
                    continue
                if raw_line is None:
                    break
                if not raw_line.strip():
                    continue
                responses = self.handle_client_line(raw_line)
                for response in responses:
                    self._write_client(client_out, response)
            return 0
        finally:
            self.stop()

    monkeypatch.setattr(McpPassthrough, "run_stdio", serial_run_stdio)
    passthrough, _manager_obj, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="serial-write"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        assert client_in.lines_consumed == 1

        client_in.write_line(_local_proof_call(call_id="serial-proof"))
        time.sleep(0.2)
        assert client_in.lines_consumed == 1, (
            "serial run_stdio must not read the diagnostic line while approval waits"
        )
        assert client_out.response_by_id("serial-proof") is None

        _approve(server, server.pending_prompts()[0].request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("serial-proof") is not None
            and client_out.response_by_id("serial-write") is not None,
            timeout=3.0,
        )
        assert client_in.lines_consumed >= 2
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_approval_timeout_still_returns_expired_for_mutation(tmp_path):
    passthrough, _manager_obj, store, server = _build_passthrough(
        tmp_path,
        approval_timeout_seconds=1,
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="timeout-write"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        client_in.write_line(_local_proof_call(call_id="timeout-proof"))
        assert _wait_until(lambda: client_out.response_by_id("timeout-proof") is not None, timeout=2.0)
        assert _wait_until(
            lambda: client_out.response_by_id("timeout-write") is not None,
            timeout=3.0,
        )
        write_response = client_out.response_by_id("timeout-write")
        assert write_response is not None
        assert write_response["error"]["data"]["reason"] == "approval_timeout"
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_concurrent_downstream_responses_are_not_swapped(tmp_path):
    passthrough, _manager_obj, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="swap-write"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        client_in.write_line(_get_file_info_call(call_id="swap-info", path="a.txt"))
        client_in.write_line(_read_file_call(call_id="swap-read", path="b.txt"))
        assert _wait_until(
            lambda: (
                client_out.response_by_id("swap-info") is not None
                and client_out.response_by_id("swap-read") is not None
            ),
            timeout=2.0,
        )
        assert client_out.response_by_id("swap-info")["id"] == "swap-info"
        assert client_out.response_by_id("swap-read")["id"] == "swap-read"
        _approve(server, prompt.request_id)
        assert _wait_until(lambda: client_out.response_by_id("swap-write") is not None, timeout=3.0)
        assert client_out.response_by_id("swap-write")["id"] == "swap-write"
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_client_stdout_lines_remain_complete_json_under_concurrency(tmp_path):
    passthrough, _manager_obj, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="json-write"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        for index in range(3):
            client_in.write_line(_local_proof_call(call_id=f"json-proof-{index}"))
        assert _wait_until(
            lambda: len([  # claim-check: allow waits for every queued proof response
                index
                for index in range(3)
                if client_out.response_by_id(f"json-proof-{index}") is not None
            ]) == 3,
            timeout=2.0,
        )
        raw = "".join(client_out._chunks)
        for line in raw.splitlines():
            parsed = json.loads(line)
            assert isinstance(parsed, dict)
        _deny(server, server.pending_prompts()[0].request_id)
        assert _wait_until(lambda: client_out.response_by_id("json-write") is not None, timeout=3.0)
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_tool_arguments_and_redirect_context_are_request_local_via_handle_client_line(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, _manager_obj, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    _seed_redirect_original(store, request_id="orig-a", playbook_id="use_read_only_tool")
    _seed_redirect_original(store, request_id="orig-b", playbook_id="use_read_only_tool")

    observed: dict[str, dict[str, Any]] = {}
    errors: list[BaseException] = []
    original_send = passthrough._send_downstream
    ready_to_send = threading.Barrier(2)

    def observing_send(message):
        request_id = str(message.get("id"))
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        redirect = passthrough._active_redirect_context
        observed[request_id] = {
            "tool_args": dict(passthrough._current_tool_arguments or {}),
            "redirect_original": None if redirect is None else redirect.original_request_id,
            "redirect_playbook": None if redirect is None else redirect.redirect_playbook_id,
            "downstream_path": arguments.get("path"),
            "downstream_has_redirect": "redirect_context" in arguments,
        }
        # tools/call send is serialized under the reconnect lock; capture
        # request-local state here without barrier-waiting while holding it.
        observed[request_id]["tool_args_after"] = dict(passthrough._current_tool_arguments or {})
        redirect_after = passthrough._active_redirect_context
        observed[request_id]["redirect_original_after"] = (
            None if redirect_after is None else redirect_after.original_request_id
        )
        return original_send(message)

    def _coordinate_before_send_lock() -> None:
        # Both concurrent calls reach the pre-lock gate together so the test
        # still stresses overlapping handle_client_line work before serialized send.
        ready_to_send.wait(timeout=2.0)

    passthrough._send_downstream = observing_send  # type: ignore[method-assign]
    passthrough._tools_call_send_gate = _coordinate_before_send_lock  # type: ignore[attr-defined]
    passthrough.start()
    try:
        def run_read(request_id: str, path: str, original_id: str) -> None:
            try:
                line = _json_line({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": {
                            "path": path,
                            "redirect_context": {
                                "original_request_id": original_id,
                                "redirect_playbook_id": "use_read_only_tool",
                            },
                        },
                    },
                })
                responses = passthrough.handle_client_line(line)
                assert responses[0]["id"] == request_id
                assert "result" in responses[0]
                assert passthrough._current_tool_arguments is None
                assert passthrough._active_redirect_context is None
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=run_read, args=("read-a", "a.txt", "orig-a")),
            threading.Thread(target=run_read, args=("read-b", "b.txt", "orig-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)
        assert not errors
        assert observed["read-a"]["tool_args"]["path"] == "a.txt"
        assert observed["read-b"]["tool_args"]["path"] == "b.txt"
        assert observed["read-a"]["redirect_original"] == "orig-a"
        assert observed["read-b"]["redirect_original"] == "orig-b"
        assert observed["read-a"]["tool_args_after"]["path"] == "a.txt"
        assert observed["read-b"]["tool_args_after"]["path"] == "b.txt"
        assert observed["read-a"]["redirect_original_after"] == "orig-a"
        assert observed["read-b"]["redirect_original_after"] == "orig-b"
        assert observed["read-a"]["downstream_path"] == "a.txt"
        assert observed["read-b"]["downstream_path"] == "b.txt"
        assert observed["read-a"]["downstream_has_redirect"] is False
        assert observed["read-b"]["downstream_has_redirect"] is False

        follow_a = store.get_pending("read-a")
        follow_b = store.get_pending("read-b")
        # Controlled-path annotation is best-effort; when present it must stay attributed.
        if follow_a is not None and follow_a.action_gate_metadata_jcs:
            assert "orig-a" in follow_a.action_gate_metadata_jcs
            assert "orig-b" not in follow_a.action_gate_metadata_jcs
        if follow_b is not None and follow_b.action_gate_metadata_jcs:
            assert "orig-b" in follow_b.action_gate_metadata_jcs
            assert "orig-a" not in follow_b.action_gate_metadata_jcs

        rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        calls = [row for row in rows if row.get("method") == "tools/call"]
        by_id = {row["id"]: row for row in calls}
        assert by_id["read-a"]["path"] == "a.txt"
        assert by_id["read-b"]["path"] == "b.txt"
        assert by_id["read-a"]["has_redirect_context"] is False
        assert by_id["read-b"]["has_redirect_context"] is False
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_worker_exception_returns_jsonrpc_error_without_closing_stdin(tmp_path):
    passthrough, _manager_obj, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    boom = RuntimeError("injected worker failure")

    original_local_proof = passthrough._local_proof_tool_response

    def exploding_local_proof(message, request_id):
        params = message.get("params") if isinstance(message, dict) else None
        tool = params.get("name") if isinstance(params, dict) else None
        if tool == "local_proof" and request_id == "boom-1":
            raise boom
        return original_local_proof(message, request_id)

    passthrough._local_proof_tool_response = exploding_local_proof  # type: ignore[method-assign]
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_local_proof_call(call_id="boom-1"))
        assert _wait_until(
            lambda: client_out.response_by_id("boom-1") is not None,
            timeout=2.0,
        ), "request must get an immediate JSON-RPC error while stdin stays open"
        response = client_out.response_by_id("boom-1")
        assert response is not None
        assert response["id"] == "boom-1"
        assert response["error"]["data"]["reason"] == "internal_error"
        assert worker.is_alive()
        assert client_in.lines_consumed >= 1

        # Connection remains usable for a later diagnostic without EOF.
        client_in.write_line(_local_proof_call(call_id="after-boom"))
        assert _wait_until(
            lambda: client_out.response_by_id("after-boom") is not None,
            timeout=2.0,
        )
        assert "result" in client_out.response_by_id("after-boom")
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_mutations_preserve_arrival_order_while_diagnostics_proceed(tmp_path):
    log_path = tmp_path / "mutation-order.log"
    passthrough, _manager_obj, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-a", path="a.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt_a = server.pending_prompts()[0]

        client_in.write_line(_write_file_call(call_id="write-b", path="b.txt"))
        client_in.write_line(_local_proof_call(call_id="proof-order"))
        assert _wait_until(
            lambda: client_out.response_by_id("proof-order") is not None,
            timeout=2.0,
        )
        # Serial mutation lane: B must not become pending until A finishes.
        assert len(server.pending_prompts()) == 1
        assert server.pending_prompts()[0].request_id == prompt_a.request_id
        assert client_out.response_by_id("write-a") is None
        assert client_out.response_by_id("write-b") is None

        _approve(server, prompt_a.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-a") is not None
            and bool(server.pending_prompts()),
            timeout=3.0,
        )
        prompt_b = server.pending_prompts()[0]
        assert prompt_b.request_id != prompt_a.request_id
        # Approving A must not release or decide B.
        assert client_out.response_by_id("write-b") is None
        record_a = store.get_pending(prompt_a.request_id)
        assert record_a.status == ApprovalStatus.EXECUTED.value

        _deny(server, prompt_b.request_id)
        assert _wait_until(lambda: client_out.response_by_id("write-b") is not None, timeout=3.0)
        write_b = client_out.response_by_id("write-b")
        assert write_b is not None
        assert write_b["error"]["data"]["reason"] == "user_denied"
        record_b = store.get_pending(prompt_b.request_id)
        assert record_b.status == ApprovalStatus.DENIED.value

        rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        calls = [row for row in rows if row.get("method") == "tools/call"]
        assert [row["id"] for row in calls] == ["write-a"]
        assert calls[0]["path"] == "a.txt"
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_bounded_stdio_queue_applies_backpressure(tmp_path):
    passthrough, _manager_obj, store, server = _build_passthrough(tmp_path)
    passthrough._stdio_queue_maxsize = 1
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="bp-write"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        assert _wait_until(lambda: passthrough._stdio_mutation_queue is not None, timeout=1.0)
        mutation_queue = passthrough._stdio_mutation_queue
        assert mutation_queue is not None

        client_in.write_line(_write_file_call(call_id="bp-queued", path="queued.txt"))
        assert _wait_until(lambda: mutation_queue.qsize() >= 1, timeout=2.0)

        queue_full = threading.Event()
        released = threading.Event()

        def try_put() -> None:
            try:
                mutation_queue.put(
                    _write_file_call(call_id="bp-overflow", path="overflow.txt"),
                    timeout=0.2,
                )
            except queue.Full:
                queue_full.set()
                mutation_queue.put(
                    _write_file_call(call_id="bp-overflow", path="overflow.txt"),
                    timeout=5.0,
                )
                released.set()

        putter = threading.Thread(target=try_put, daemon=True)
        putter.start()
        assert queue_full.wait(timeout=2.0), "full bounded mutation queue must raise queue.Full"
        _approve(server, server.pending_prompts()[0].request_id)
        assert released.wait(timeout=5.0)
        putter.join(timeout=2.0)
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_eof_shutdown_does_not_corrupt_completed_responses(tmp_path):
    passthrough, _manager_obj, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_local_proof_call(call_id="eof-proof"))
        assert _wait_until(lambda: client_out.response_by_id("eof-proof") is not None, timeout=2.0)
        client_in.close()
        worker.join(timeout=5.0)
        assert not worker.is_alive()
        proof = client_out.response_by_id("eof-proof")
        assert proof is not None
        assert proof["id"] == "eof-proof"
        assert "result" in proof
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_stdio_worker_defaults_are_bounded():
    assert STDIO_REQUEST_WORKERS >= 2
    assert STDIO_REQUEST_QUEUE_MAXSIZE >= 1
    assert STDIO_REQUEST_WORKERS <= 16
    assert STDIO_REQUEST_QUEUE_MAXSIZE <= 64
