"""Concurrent mutation approval registration on one stdio connection."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from agentveil_mcp_proxy.approval.manager import normalize_client_request_id
from agentveil_mcp_proxy.evidence import ApprovalStatus
from agentveil_mcp_proxy.passthrough import (
    STDIO_MUTATION_PENDING_WORKERS,
    STDIO_REQUEST_WORKERS,
)

from test_mcp_proxy_approval import _get_csrf, _post_decision
from test_mcp_proxy_approval_cancellation import (
    _build_passthrough,
    _cancel_notification,
    _downstream_writes,
)
from test_mcp_proxy_approval_nonblocking import (
    _TrackingTextIO,
    _ThreadSafeClientOut,
    _approve,
    _deny,
    _get_file_info_call,
    _local_proof_call,
    _path_logging_downstream,
    _run_stdio_session,
    _wait_until,
    _write_file_call,
)


def _approval_request_id(manager, call_id: str) -> str:
    key = normalize_client_request_id(call_id)
    assert key is not None
    request_id = manager._client_request_bindings.get(key)
    assert request_id is not None, f"missing approval binding for {call_id!r}"
    return request_id


def _prompt_for_call(server, manager, call_id: str):
    request_id = _approval_request_id(manager, call_id)
    for prompt in server.pending_prompts():
        if prompt.request_id == request_id:
            return prompt
    raise AssertionError(f"pending prompt not found for {call_id!r}")


def _send_ab_and_wait_both_pending(client_in, server, manager) -> tuple[Any, Any]:
    client_in.write_line(_write_file_call(call_id="write-a", path="a.txt"))
    assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
    client_in.write_line(_write_file_call(call_id="write-b", path="b.txt"))
    assert _wait_until(lambda: len(server.pending_prompts()) == 2, timeout=3.0)
    return _prompt_for_call(server, manager, "write-a"), _prompt_for_call(
        server,
        manager,
        "write-b",
    )


def _gate_await_decision(
    manager,
    *,
    entered: threading.Event,
    release: threading.Event,
) -> None:
    original = manager._await_decision

    def gated(*args, **kwargs):
        entered.set()
        release.wait(timeout=5.0)
        return original(*args, **kwargs)

    manager._await_decision = gated  # type: ignore[method-assign]


class _ExecutionLockProbe:
    """Observes a second mutation worker blocking on downstream execution."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.second_waiting = threading.Event()

    def __enter__(self):
        if self._lock.locked():
            self.second_waiting.set()
        self._lock.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._lock.release()
        return False


def _mutation_worker_threads() -> list[threading.Thread]:
    return [
        thread
        for thread in threading.enumerate()
        if thread.name.startswith("mcp-stdio-mutation-worker-")
    ]


def _selective_fail_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "selective_fail_downstream.py"
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
]

log_path = os.environ.get("DOWNSTREAM_LOG")
fh = open(log_path, "a", encoding="utf-8") if log_path else None

def _log(payload):
    if fh is not None:
        fh.write(json.dumps(payload, separators=(",", ":")) + "\\n")
        fh.flush()

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
        path = args.get("path")
        _log({"method": "tools/call", "id": request_id, "path": path})
        if path == "fail-a.txt":
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": "injected downstream failure"},
            }, separators=(",", ":")), flush=True)
            continue
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


def _start_session(
    tmp_path: Path,
    *,
    log_path: Path | None = None,
    downstream_script: Path | None = None,
    approval_timeout_seconds: int = 300,
    mutation_pending_workers: int | None = None,
    execution_lock: threading.Lock | _ExecutionLockProbe | None = None,
):
    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=downstream_script,
        approval_timeout_seconds=approval_timeout_seconds,
    )
    if mutation_pending_workers is not None:
        passthrough._stdio_mutation_pending_workers = mutation_pending_workers
    if execution_lock is not None:
        passthrough._mutation_execution_lock = execution_lock
    class _SessionTrackingTextIO(_TrackingTextIO):
        def close(self) -> None:
            for prompt in server.pending_prompts():
                manager.cancel_approval(prompt.request_id)
            super().close()

    client_in = _SessionTrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    return passthrough, manager, store, server, client_in, client_out, worker


def test_serial_mutation_lane_head_of_line_with_single_worker(tmp_path):
    """Pre-fix reproduction: one pending worker blocks B until A leaves approval wait."""

    log_path = tmp_path / "hol.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
        mutation_pending_workers=1,
    )
    a_waiting = threading.Event()
    release_a = threading.Event()
    _gate_await_decision(manager, entered=a_waiting, release=release_a)
    try:
        client_in.write_line(_write_file_call(call_id="write-a", path="a.txt"))
        assert _wait_until(a_waiting.is_set, timeout=3.0)
        assert _wait_until(lambda: len(server.pending_prompts()) == 1, timeout=2.0)
        prompt_a = server.pending_prompts()[0]

        client_in.write_line(_write_file_call(call_id="write-b", path="b.txt"))
        assert _wait_until(lambda: client_in.lines_consumed >= 2, timeout=2.0)
        assert len(server.pending_prompts()) == 1
        assert server.pending_prompts()[0].request_id == prompt_a.request_id

        release_a.set()
        assert _wait_until(lambda: a_waiting.is_set, timeout=3.0)
        assert len(server.pending_prompts()) == 1

        _deny(server, prompt_a.request_id)
        assert _wait_until(lambda: len(server.pending_prompts()) == 1, timeout=3.0)
        prompt_b = server.pending_prompts()[0]
        assert prompt_b.request_id != prompt_a.request_id
    finally:
        release_a.set()
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_two_mutations_reach_pending_concurrently(tmp_path):
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(tmp_path)
    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        assert prompt_a.request_id != prompt_b.request_id
        assert store.get_pending(prompt_a.request_id).status == ApprovalStatus.PENDING.value
        assert store.get_pending(prompt_b.request_id).status == ApprovalStatus.PENDING.value
        assert client_out.response_by_id("write-a") is None
        assert client_out.response_by_id("write-b") is None
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_approve_b_while_a_pending_executes_only_b(tmp_path):
    log_path = tmp_path / "ab-order.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        _approve(server, prompt_b.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-b") is not None,
            timeout=3.0,
        )
        assert client_out.response_by_id("write-a") is None
        writes = _downstream_writes(log_path)
        assert len(writes) == 1
        assert writes[0]["id"] == "write-b"
        assert writes[0]["path"] == "b.txt"
        assert store.get_pending(prompt_b.request_id).status == ApprovalStatus.EXECUTED.value
        assert store.get_pending(prompt_a.request_id).status == ApprovalStatus.PENDING.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_deny_a_after_b_executed_leaves_a_target_absent(tmp_path):
    log_path = tmp_path / "deny-a.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        _approve(server, prompt_b.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-b") is not None,
            timeout=3.0,
        )
        _deny(server, prompt_a.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-a") is not None,
            timeout=3.0,
        )
        denied = client_out.response_by_id("write-a")
        assert denied is not None
        assert denied["error"]["data"]["reason"] == "user_denied"
        writes = _downstream_writes(log_path)
        assert len(writes) == 1
        assert writes[0]["path"] == "b.txt"
        assert store.get_pending(prompt_a.request_id).status == ApprovalStatus.DENIED.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_approve_a_deny_b_reverse_order(tmp_path):
    log_path = tmp_path / "approve-a-deny-b.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        _approve(server, prompt_a.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-a") is not None,
            timeout=3.0,
        )
        _deny(server, prompt_b.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-b") is not None,
            timeout=3.0,
        )
        writes = _downstream_writes(log_path)
        assert len(writes) == 1
        assert writes[0]["id"] == "write-a"
        assert store.get_pending(prompt_a.request_id).status == ApprovalStatus.EXECUTED.value
        assert store.get_pending(prompt_b.request_id).status == ApprovalStatus.DENIED.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_cancel_a_does_not_affect_pending_b(tmp_path):
    log_path = tmp_path / "cancel-a.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        client_in.write_line(_cancel_notification(request_id="write-a"))
        assert _wait_until(
            lambda: store.get_pending(prompt_a.request_id).status
            == ApprovalStatus.CANCELLED.value,
            timeout=3.0,
        )
        assert store.get_pending(prompt_b.request_id).status == ApprovalStatus.PENDING.value
        assert client_out.response_by_id("write-a") is None
        _approve(server, prompt_b.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-b") is not None,
            timeout=3.0,
        )
        writes = _downstream_writes(log_path)
        assert len(writes) == 1
        assert writes[0]["path"] == "b.txt"
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_timeout_a_does_not_affect_pending_b(tmp_path):
    log_path = tmp_path / "timeout-a.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
        approval_timeout_seconds=1,
    )
    b_waiting = threading.Event()
    release_b = threading.Event()
    await_calls = {"count": 0}
    original_await = manager._await_decision

    def gated_await(*args, **kwargs):
        await_calls["count"] += 1
        if await_calls["count"] == 2:
            b_waiting.set()
            release_b.wait(timeout=5.0)
        return original_await(*args, **kwargs)

    manager._await_decision = gated_await  # type: ignore[method-assign]
    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        assert b_waiting.is_set()
        assert _wait_until(
            lambda: client_out.response_by_id("write-a") is not None,
            timeout=4.0,
        )
        timed_out = client_out.response_by_id("write-a")
        assert timed_out is not None
        assert timed_out["error"]["data"]["reason"] == "approval_timeout"
        assert store.get_pending(prompt_a.request_id).status == ApprovalStatus.EXPIRED.value
        assert store.get_pending(prompt_b.request_id).status == ApprovalStatus.PENDING.value
        assert client_out.response_by_id("write-b") is None
        release_b.set()
        _approve(server, prompt_b.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-b") is not None,
            timeout=3.0,
        )
        assert len(_downstream_writes(log_path)) == 1
    finally:
        release_b.set()
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_downstream_failure_a_does_not_break_pending_b(tmp_path):
    log_path = tmp_path / "fail-a.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_selective_fail_downstream(tmp_path),
    )
    try:
        client_in.write_line(_write_file_call(call_id="write-a", path="fail-a.txt"))
        client_in.write_line(_write_file_call(call_id="write-b", path="b.txt"))
        assert _wait_until(lambda: len(server.pending_prompts()) == 2, timeout=3.0)
        prompt_a = _prompt_for_call(server, manager, "write-a")
        prompt_b = _prompt_for_call(server, manager, "write-b")
        _approve(server, prompt_a.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-a") is not None,
            timeout=3.0,
        )
        failed = client_out.response_by_id("write-a")
        assert failed is not None
        assert "error" in failed
        assert store.get_pending(prompt_b.request_id).status == ApprovalStatus.PENDING.value
        _approve(server, prompt_b.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-b") is not None,
            timeout=3.0,
        )
        assert "result" in client_out.response_by_id("write-b")
        writes = _downstream_writes(log_path)
        assert len(writes) == 2
        assert writes[0]["path"] == "fail-a.txt"
        assert writes[1]["path"] == "b.txt"
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_concurrent_decisions_do_not_mix_evidence(tmp_path):
    log_path = tmp_path / "concurrent-decisions.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    ready = threading.Barrier(2)

    def decide(request_id: str, decision: str) -> None:
        ready.wait(timeout=3.0)
        with httpx.Client() as client:
            url = server.approval_url(request_id)
            csrf = _get_csrf(client, url)
            response = _post_decision(client, url, decision=decision, csrf=csrf)
            assert response.status_code == 200

    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        record_a_before = store.get_pending(prompt_a.request_id)
        record_b_before = store.get_pending(prompt_b.request_id)
        assert record_a_before.payload_hash != record_b_before.payload_hash

        threads = [
            threading.Thread(target=decide, args=(prompt_a.request_id, "approve")),
            threading.Thread(target=decide, args=(prompt_b.request_id, "deny")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)

        assert _wait_until(
            lambda: client_out.response_by_id("write-a") is not None
            and client_out.response_by_id("write-b") is not None,
            timeout=4.0,
        )
        record_a = store.get_pending(prompt_a.request_id)
        record_b = store.get_pending(prompt_b.request_id)
        assert record_a.status == ApprovalStatus.EXECUTED.value
        assert record_b.status == ApprovalStatus.DENIED.value
        assert record_a.payload_hash == record_a_before.payload_hash
        assert record_b.payload_hash == record_b_before.payload_hash
        assert record_a.request_id != record_b.request_id
        writes = _downstream_writes(log_path)
        assert len(writes) == 1
        assert writes[0]["id"] == "write-a"
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_multiple_pending_visible_in_approval_center(tmp_path):
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(tmp_path)
    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        payload = server.pending_approvals_api_payload()
        assert payload["ok"] is True
        ids = {row["request_id"] for row in payload["approvals"]}
        assert prompt_a.request_id in ids
        assert prompt_b.request_id in ids
        assert len(ids) == 2
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_local_proof_completes_with_multiple_pending(tmp_path):
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(tmp_path)
    try:
        _send_ab_and_wait_both_pending(client_in, server, manager)
        client_in.write_line(_local_proof_call(call_id="proof-multi"))
        assert _wait_until(
            lambda: client_out.response_by_id("proof-multi") is not None,
            timeout=3.0,
        )
        proof = client_out.response_by_id("proof-multi")
        assert proof is not None
        assert "result" in proof
        assert len(server.pending_prompts()) == 2
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_get_file_info_completes_with_multiple_pending_mutations(tmp_path):
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(tmp_path)
    try:
        _send_ab_and_wait_both_pending(client_in, server, manager)
        client_in.write_line(_get_file_info_call(call_id="info-multi", path="notes.txt"))
        assert _wait_until(
            lambda: client_out.response_by_id("info-multi") is not None,
            timeout=3.0,
        )
        info = client_out.response_by_id("info-multi")
        assert info is not None
        assert "result" in info
        assert len(server.pending_prompts()) == 2
        assert client_out.response_by_id("write-a") is None
        assert client_out.response_by_id("write-b") is None
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_mutation_arguments_stay_request_local_on_concurrent_execution(tmp_path):
    log_path = tmp_path / "redirect-args.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    observed: dict[str, dict[str, Any]] = {}
    original_send = passthrough._send_downstream

    def observing_send(message):
        request_id = str(message.get("id"))
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        observed[request_id] = {
            "tool_args": dict(passthrough._current_tool_arguments or {}),
            "downstream_path": arguments.get("path"),
        }
        return original_send(message)

    passthrough._send_downstream = observing_send  # type: ignore[method-assign]
    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        _approve(server, prompt_b.request_id)
        _approve(server, prompt_a.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-a") is not None
            and client_out.response_by_id("write-b") is not None,
            timeout=4.0,
        )
        assert observed["write-a"]["tool_args"]["path"] == "a.txt"
        assert observed["write-b"]["tool_args"]["path"] == "b.txt"
        assert observed["write-a"]["downstream_path"] == "a.txt"
        assert observed["write-b"]["downstream_path"] == "b.txt"
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_each_approved_request_executes_downstream_at_most_once(tmp_path):
    log_path = tmp_path / "once.log"
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    call_ids = [f"write-{index}" for index in range(4)]
    try:
        for call_id in call_ids:
            client_in.write_line(
                _write_file_call(call_id=call_id, path=f"{call_id}.txt")
            )

        approved_ids: set[str] = set()
        deadline = time.monotonic() + 8.0
        while len(approved_ids) < 4 and time.monotonic() < deadline:
            for prompt in server.pending_prompts():
                if prompt.request_id in approved_ids:
                    continue
                _approve(server, prompt.request_id)
                approved_ids.add(prompt.request_id)
            if len(approved_ids) < 4:
                time.sleep(0.01)
        assert len(approved_ids) == 4

        assert _wait_until(
            lambda: all(  # claim-check: allow bounded to the four declared call_ids.
                client_out.response_by_id(call_id) is not None for call_id in call_ids
            ),
            timeout=8.0,
        )
        writes = _downstream_writes(log_path)
        assert len(writes) == 4
        assert len({row["id"] for row in writes}) == 4
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_downstream_execution_stays_serialized(tmp_path):
    log_path = tmp_path / "serialize.log"
    execution_probe = _ExecutionLockProbe()
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
        execution_lock=execution_probe,
    )
    release_first = threading.Event()
    first_waiting = threading.Event()
    forwarded_ids: list[Any] = []
    original_send = passthrough._send_downstream
    original_wait = passthrough._wait_downstream_response

    def tracking_send(message):
        forwarded_ids.append(message.get("id"))
        return original_send(message)

    def holding_wait(expected_id):
        if expected_id == "write-a":
            first_waiting.set()
            release_first.wait(timeout=5.0)
        return original_wait(expected_id)

    passthrough._send_downstream = tracking_send  # type: ignore[method-assign]
    passthrough._wait_downstream_response = holding_wait  # type: ignore[method-assign]
    try:
        prompt_a, prompt_b = _send_ab_and_wait_both_pending(client_in, server, manager)
        _approve(server, prompt_a.request_id)
        assert first_waiting.wait(timeout=3.0), "first approved mutation must reach downstream wait"
        assert forwarded_ids == ["write-a"]

        _approve(server, prompt_b.request_id)
        assert execution_probe.second_waiting.wait(timeout=3.0), (
            "second approved worker must attempt execution while first response is held"
        )
        assert forwarded_ids == ["write-a"], "second mutation must not forward until first completes"
        assert client_out.response_by_id("write-b") is None

        release_first.set()
        assert _wait_until(
            lambda: client_out.response_by_id("write-a") is not None
            and client_out.response_by_id("write-b") is not None,
            timeout=5.0,
        )
        assert forwarded_ids == ["write-a", "write-b"]
        assert len(_downstream_writes(log_path)) == 2
    finally:
        release_first.set()
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_eof_shutdown_reaps_mutation_workers_without_response_corruption(tmp_path):
    before_workers = set(_mutation_worker_threads())
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(tmp_path)
    try:
        assert _wait_until(
            lambda: len(_mutation_worker_threads()) >= len(before_workers) + STDIO_MUTATION_PENDING_WORKERS,
            timeout=3.0,
        )
        session_workers = [
            thread
            for thread in _mutation_worker_threads()
            if thread not in before_workers
        ]
        assert len(session_workers) == STDIO_MUTATION_PENDING_WORKERS
        for index in range(STDIO_MUTATION_PENDING_WORKERS):
            assert any(
                thread.name == f"mcp-stdio-mutation-worker-{index}"
                for thread in session_workers
            )

        client_in.write_line(_local_proof_call(call_id="eof-proof"))
        assert _wait_until(
            lambda: client_out.response_by_id("eof-proof") is not None,
            timeout=3.0,
        )
        proof_before = client_out.response_by_id("eof-proof")
        assert proof_before is not None
        assert "result" in proof_before

        client_in.close()
        worker.join(timeout=5.0)
        assert not worker.is_alive(), "run_stdio thread must exit after EOF"
        for mutation_worker in session_workers:
            assert not mutation_worker.is_alive(), (
                f"{mutation_worker.name} must terminate during shutdown"
            )

        proof_after = client_out.response_by_id("eof-proof")
        assert proof_after == proof_before
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_mutation_pending_workers_stay_bounded(tmp_path):
    passthrough, manager, store, server, client_in, client_out, worker = _start_session(tmp_path)
    try:
        worker_count = max(2, int(passthrough._stdio_worker_count))
        expected = max(
            1,
            min(int(passthrough._stdio_mutation_pending_workers), worker_count - 1),
        )
        assert expected == STDIO_MUTATION_PENDING_WORKERS
        assert expected <= STDIO_REQUEST_WORKERS - 1
        assert int(passthrough._stdio_mutation_pending_workers) == STDIO_MUTATION_PENDING_WORKERS
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()
