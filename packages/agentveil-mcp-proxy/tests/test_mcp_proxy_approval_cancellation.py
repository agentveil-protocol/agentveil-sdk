"""AV-11: client cancellation and terminal approval outcomes."""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentveil_mcp_proxy.approval.manager import ApprovalFlowError, normalize_client_request_id
from agentveil_mcp_proxy.approval.server import TERMINAL_CANCELLED, enrich_owner_client_id
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.evidence.observability import mcp_error_user_message
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough

from mcp_fake_downstream import seed_tool_schemas, tool_entry, write_downstream
from test_mcp_proxy_approval import _get_csrf, _manager, _post_decision
from test_mcp_proxy_approval_nonblocking import (
    _TrackingTextIO,
    _ThreadSafeClientOut,
    _approve,
    _build_passthrough as _build_passthrough_raw,
    _deny,
    _json_line,
    _local_proof_call,
    _nonblocking_config,
    _path_logging_downstream,
    _run_stdio_session,
    _wait_until,
    _write_file_call,
)
import os


def _build_passthrough(*args, **kwargs):
    """Bind approvals to this process so dead-owner retirement stays accurate."""

    passthrough, manager, store, server = _build_passthrough_raw(*args, **kwargs)
    manager.client_id = enrich_owner_client_id(
        f"cursor:pid:{os.getpid()}",
        instance_token=manager._instance_token,
    )
    return passthrough, manager, store, server


def _cancel_notification(*, request_id: Any, reason: str = "user cancelled") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": request_id, "reason": reason},
    })


def _write_file_call_with_id(
    *,
    call_id: Any,
    path: str = "pending.txt",
) -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": path, "content": "pending-body"},
        },
    })


def _downstream_writes(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_cancel_pending_mutation_blocks_late_approve_and_downstream(tmp_path):
    """Pre-fix repro: cancel must atomically retire pending approval and block execution."""

    log_path = tmp_path / "downstream.log"
    passthrough, _manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="write-cancel", path="cancel-target.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        assert store.get_pending(prompt.request_id).status == ApprovalStatus.PENDING.value

        client_in.write_line(_cancel_notification(request_id="write-cancel"))
        assert _wait_until(
            lambda: store.get_pending(prompt.request_id).status
            == ApprovalStatus.CANCELLED.value,
            timeout=2.0,
        )
        assert store.list_pending() == []
        assert client_out.response_by_id("write-cancel") is None

        with httpx.Client() as client:
            url = server.approval_url(prompt.request_id)
            late_page = client.get(url, follow_redirects=False)
            assert late_page.status_code == 410
            assert "Cancelled" in late_page.text
            assert TERMINAL_CANCELLED in late_page.text or "cancelled by the client" in late_page.text
        assert _downstream_writes(log_path) == []
        assert client_out.response_by_id("write-cancel") is None
        assert store.get_pending(prompt.request_id).status == ApprovalStatus.CANCELLED.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_cancel_before_approve_never_reaches_downstream(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, _manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="cancel-first"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]

        client_in.write_line(_cancel_notification(request_id="cancel-first"))
        assert _wait_until(
            lambda: store.get_pending(prompt.request_id).status
            == ApprovalStatus.CANCELLED.value,
            timeout=2.0,
        )
        assert client_out.response_by_id("cancel-first") is None
        assert _downstream_writes(log_path) == []
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_approve_before_cancel_does_not_falsely_cancel(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, _manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="approve-first"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]

        _approve(server, prompt.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("approve-first") is not None,
            timeout=3.0,
        )
        client_in.write_line(_cancel_notification(request_id="approve-first"))
        time.sleep(0.2)
        record = store.get_pending(prompt.request_id)
        assert record.status == ApprovalStatus.EXECUTED.value
        writes = _downstream_writes(log_path)
        assert len(writes) == 1
        assert writes[0]["method"] == "tools/call"
        assert writes[0]["path"] == "pending.txt"
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_concurrent_cancel_and_approve_has_single_winner(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, _manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="race-1"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]

        barrier = threading.Barrier(2)

        def cancel_worker() -> None:
            barrier.wait(timeout=2.0)
            client_in.write_line(_cancel_notification(request_id="race-1"))

        def approve_worker() -> None:
            barrier.wait(timeout=2.0)
            with httpx.Client() as client:
                url = server.approval_url(prompt.request_id)
                response = client.get(url, follow_redirects=False)
                if response.status_code != 200:
                    return
                csrf = _get_csrf(client, url)
                _post_decision(client, url, decision="approve", csrf=csrf)

        threads = [
            threading.Thread(target=cancel_worker, daemon=True),
            threading.Thread(target=approve_worker, daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)

        assert _wait_until(
            lambda: store.get_pending(prompt.request_id).status
            in {
                ApprovalStatus.CANCELLED.value,
                ApprovalStatus.EXECUTED.value,
            },
            timeout=5.0,
        )
        record = store.get_pending(prompt.request_id)
        writes = _downstream_writes(log_path)
        if record.status == ApprovalStatus.CANCELLED.value:
            assert writes == []
            assert client_out.response_by_id("race-1") is None
        else:
            assert record.status == ApprovalStatus.EXECUTED.value
            assert len(writes) == 1
            assert client_out.response_by_id("race-1") is not None
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_cancel_request_a_does_not_affect_request_b(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, _manager, store, server = _build_passthrough(
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
        assert _wait_until(lambda: len(server.pending_prompts()) == 1, timeout=2.0)
        prompt_a = server.pending_prompts()[0]

        client_in.write_line(_cancel_notification(request_id="write-a"))
        assert _wait_until(
            lambda: store.get_pending(prompt_a.request_id).status
            == ApprovalStatus.CANCELLED.value,
            timeout=2.0,
        )
        assert client_out.response_by_id("write-a") is None

        client_in.write_line(_write_file_call(call_id="write-b", path="b.txt"))
        assert _wait_until(lambda: len(server.pending_prompts()) == 1, timeout=2.0)
        prompt_b = server.pending_prompts()[0]
        assert prompt_b.request_id != prompt_a.request_id
        assert store.get_pending(prompt_b.request_id).status == ApprovalStatus.PENDING.value

        _approve(server, prompt_b.request_id)
        assert _wait_until(
            lambda: client_out.response_by_id("write-b") is not None,
            timeout=3.0,
        )
        writes = _downstream_writes(log_path)
        assert len(writes) == 1
        assert writes[0]["path"] == "b.txt"
        assert store.get_pending(prompt_a.request_id).status == ApprovalStatus.CANCELLED.value
        assert store.get_pending(prompt_b.request_id).status == ApprovalStatus.EXECUTED.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_local_proof_continues_while_mutation_cancelled(tmp_path):
    passthrough, _manager, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="cancelled-write"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]

        client_in.write_line(_cancel_notification(request_id="cancelled-write"))
        client_in.write_line(_local_proof_call(call_id="proof-during-cancel"))
        assert _wait_until(
            lambda: client_out.response_by_id("proof-during-cancel") is not None,
            timeout=2.0,
        )
        proof = client_out.response_by_id("proof-during-cancel")
        assert proof is not None
        assert "result" in proof
        assert store.get_pending(prompt.request_id).status == ApprovalStatus.CANCELLED.value
        assert client_out.response_by_id("cancelled-write") is None
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_explicit_deny_retry_returns_exact_user_denied_message(tmp_path):
    passthrough, _manager, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="deny-1"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        _deny(server, prompt.request_id)
        assert _wait_until(lambda: client_out.response_by_id("deny-1") is not None, timeout=3.0)
        first = client_out.response_by_id("deny-1")
        assert first is not None
        assert first["error"]["data"]["reason"] == "user_denied"

        client_in.write_line(_write_file_call(call_id="deny-retry"))
        assert _wait_until(lambda: client_out.response_by_id("deny-retry") is not None, timeout=3.0)
        retry = client_out.response_by_id("deny-retry")
        assert retry is not None
        assert retry["error"]["data"]["reason"] == "user_denied"
        message = retry["error"]["message"]
        assert "Stopped by policy" not in message
        assert "Denied by user" in message
        assert message == mcp_error_user_message(retry["error"]["data"])
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_deny_without_cancel_still_works(tmp_path):
    passthrough, _manager, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="plain-deny"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        _deny(server, prompt.request_id)
        assert _wait_until(lambda: client_out.response_by_id("plain-deny") is not None, timeout=3.0)
        response = client_out.response_by_id("plain-deny")
        assert response is not None
        assert response["error"]["data"]["reason"] == "user_denied"
        assert store.get_pending(prompt.request_id).status == ApprovalStatus.DENIED.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_approval_timeout_not_regressed_by_cancel_support(tmp_path):
    passthrough, _manager, store, server = _build_passthrough(
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
        prompt = server.pending_prompts()[0]
        assert _wait_until(
            lambda: client_out.response_by_id("timeout-write") is not None,
            timeout=5.0,
        )
        response = client_out.response_by_id("timeout-write")
        assert response is not None
        assert response["error"]["data"]["reason"] == "approval_timeout"
        assert store.get_pending(prompt.request_id).status == ApprovalStatus.EXPIRED.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_back_to_back_tools_call_and_cancel_before_binding(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    approval_entered = threading.Event()
    approval_release = threading.Event()
    original_request_approval = manager.request_approval

    def gated_request_approval(*args, **kwargs):
        approval_entered.set()
        approval_release.wait(timeout=3.0)
        return original_request_approval(*args, **kwargs)

    manager.request_approval = gated_request_approval  # type: ignore[method-assign]
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="early-cancel"))
        assert _wait_until(
            lambda: manager.is_client_request_tracked("early-cancel"),
            timeout=3.0,
        )
        client_in.write_line(_cancel_notification(request_id="early-cancel"))
        assert _wait_until(
            lambda: manager.is_client_request_pre_cancelled("early-cancel"),
            timeout=3.0,
        )
        approval_release.set()
        assert _wait_until(approval_entered.is_set, timeout=3.0)
        assert _wait_until(
            lambda: not manager.is_client_request_tracked("early-cancel"),
            timeout=3.0,
        )
        assert not server.pending_prompts()
        assert store.list_pending() == []
        assert _downstream_writes(log_path) == []
        assert client_out.response_by_id("early-cancel") is None
    finally:
        approval_release.set()
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_cancel_between_bind_and_register_skips_actionable_prompt(tmp_path, monkeypatch):
    log_path = tmp_path / "downstream.log"
    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    finalize_gate = threading.Event()
    finalize_release = threading.Event()
    real_lock = manager._finalize_lock

    class _GateBeforeFinalizeLock:
        def __init__(self) -> None:
            self._gate_armed = True

        def __enter__(self):
            if self._gate_armed:
                finalize_gate.set()
                finalize_release.wait(timeout=3.0)
                self._gate_armed = False
            real_lock.acquire()
            return self

        def __exit__(self, exc_type, exc, tb):
            real_lock.release()
            return False

    monkeypatch.setattr(manager, "_finalize_lock", _GateBeforeFinalizeLock())
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="bind-gap"))
        assert _wait_until(finalize_gate.is_set, timeout=3.0)
        client_in.write_line(_cancel_notification(request_id="bind-gap"))
        finalize_release.set()
        assert _wait_until(
            lambda: not manager.is_client_request_tracked("bind-gap"),
            timeout=3.0,
        )
        assert store.list_pending() == []
        assert _downstream_writes(log_path) == []
        assert client_out.response_by_id("bind-gap") is None
        assert not server.pending_prompts()
    finally:
        finalize_release.set()
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_numeric_and_string_jsonrpc_ids_cancel_independently(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, _manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call_with_id(call_id=1, path="numeric.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt_numeric = server.pending_prompts()[0]

        client_in.write_line(_cancel_notification(request_id=1))
        assert _wait_until(
            lambda: store.get_pending(prompt_numeric.request_id).status
            == ApprovalStatus.CANCELLED.value,
            timeout=2.0,
        )
        assert client_out.response_by_id(1) is None

        client_in.write_line(_write_file_call_with_id(call_id="1", path="string.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt_string = server.pending_prompts()[0]
        assert prompt_string.request_id != prompt_numeric.request_id
        assert store.get_pending(prompt_string.request_id).status == ApprovalStatus.PENDING.value
        assert client_out.response_by_id("1") is None
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_cancel_instruction_gate_does_not_create_second_prompt(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, _manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="agents-write", path="AGENTS.md"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        assert len(store.list_pending()) == 1

        client_in.write_line(_cancel_notification(request_id="agents-write"))
        assert _wait_until(
            lambda: store.get_pending(prompt.request_id).status
            == ApprovalStatus.CANCELLED.value,
            timeout=3.0,
        )
        assert store.list_pending() == []
        assert not server.pending_prompts()
        assert client_out.response_by_id("agents-write") is None
        assert _downstream_writes(log_path) == []
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_cancelled_terminal_page_shows_cancelled_title(tmp_path):
    passthrough, _manager, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="terminal-page"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=2.0)
        prompt = server.pending_prompts()[0]
        client_in.write_line(_cancel_notification(request_id="terminal-page"))
        assert _wait_until(
            lambda: store.get_pending(prompt.request_id).status
            == ApprovalStatus.CANCELLED.value,
            timeout=2.0,
        )
        with httpx.Client() as client:
            page = client.get(server.approval_url(prompt.request_id), follow_redirects=False)
        assert page.status_code == 410
        assert "<title>Cancelled</title>" in page.text
        assert "cancelled by the client" in page.text
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_unknown_cancel_does_not_poison_future_request_id_reuse(tmp_path):
    passthrough, manager, store, server = _build_passthrough(tmp_path)
    assert manager.cancel_by_client_request_id(42) is None
    assert not manager.is_client_request_pre_cancelled(42)

    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call_with_id(call_id=42, path="reuse.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=3.0)
        prompt = server.pending_prompts()[0]
        assert store.get_pending(prompt.request_id).status == ApprovalStatus.PENDING.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_late_cancel_after_completed_request_allows_id_reuse(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call_with_id(call_id=7, path="first.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=3.0)
        prompt = server.pending_prompts()[0]
        _deny(server, prompt.request_id)
        assert _wait_until(lambda: client_out.response_by_id(7) is not None, timeout=3.0)
        assert not manager.is_client_request_tracked(7)

        assert manager.cancel_by_client_request_id(7) is None
        client_in.write_line(_write_file_call_with_id(call_id=7, path="second.txt"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=3.0)
        second = server.pending_prompts()[0]
        assert second.request_id != prompt.request_id
        assert store.get_pending(second.request_id).status == ApprovalStatus.PENDING.value
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_malformed_cancel_request_id_does_not_break_stdio(tmp_path):
    passthrough, manager, store, server = _build_passthrough(tmp_path)
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_json_line({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": {"bad": "object"}},
        }))
        client_in.write_line(_local_proof_call(call_id="after-bad-cancel"))
        assert _wait_until(
            lambda: client_out.response_by_id("after-bad-cancel") is not None,
            timeout=3.0,
        )
        proof = client_out.response_by_id("after-bad-cancel")
        assert proof is not None
        assert "result" in proof
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_cancel_persistence_gate_does_not_create_second_prompt(tmp_path):
    log_path = tmp_path / "downstream.log"
    passthrough, _manager, store, server = _build_passthrough(
        tmp_path,
        log_path=log_path,
        downstream_script=_path_logging_downstream(tmp_path),
    )
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_write_file_call(call_id="persist-cancel", path=".cursor/rules/rule.mdc"))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=3.0)
        prompt = server.pending_prompts()[0]
        client_in.write_line(_cancel_notification(request_id="persist-cancel"))
        assert _wait_until(
            lambda: store.get_pending(prompt.request_id).status
            == ApprovalStatus.CANCELLED.value,
            timeout=3.0,
        )
        assert store.list_pending() == []
        assert not server.pending_prompts()
        assert _downstream_writes(log_path) == []
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_cancel_package_manager_gate_does_not_create_second_prompt(tmp_path):
    log_path = tmp_path / "downstream.log"
    config = _nonblocking_config()
    manager, store, server, _cli = _manager(tmp_path, config=config)
    script = write_downstream(
        tmp_path,
        filename="package_cancel_downstream.py",
        tools=[tool_entry("pip_install")],
        call_result_text="downstream-ok",
    )
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(script)),
            name="filesystem",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="filesystem"),
        approval_manager=manager,
    )
    seed_tool_schemas(passthrough, [tool_entry("pip_install")])
    client_in = _TrackingTextIO()
    client_out = _ThreadSafeClientOut()
    worker = _run_stdio_session(passthrough, client_in, client_out)
    worker.start()
    try:
        client_in.write_line(_json_line({
            "jsonrpc": "2.0",
            "id": "pkg-cancel",
            "method": "tools/call",
            "params": {"name": "pip_install", "arguments": {"package": "leftpad"}},
        }))
        assert _wait_until(lambda: bool(server.pending_prompts()), timeout=3.0)
        prompt = server.pending_prompts()[0]
        client_in.write_line(_cancel_notification(request_id="pkg-cancel"))
        assert _wait_until(
            lambda: store.get_pending(prompt.request_id).status
            == ApprovalStatus.CANCELLED.value,
            timeout=3.0,
        )
        assert store.list_pending() == []
        assert not server.pending_prompts()
        assert _downstream_writes(log_path) == []
    finally:
        client_in.close()
        worker.join(timeout=5.0)
        passthrough.stop()
        server.stop()
        store.close()


def test_cancel_approval_locked_under_finalize_lock_does_not_deadlock(tmp_path):
    config = _nonblocking_config()
    manager, store, server, _ = _manager(tmp_path, config=config)
    now = int(time.time())
    request_id = str(uuid.uuid4())
    store.write_pending(
        PendingApproval(
            request_id=request_id,
            session_id="session-1234567890",
            client_id=enrich_owner_client_id(
                f"cursor:pid:{os.getpid()}",
                instance_token=manager._instance_token,
            ),
            downstream_server="filesystem",
            tool_name="write_file",
            action_class="write",
            risk_class="write",
            resource_hash="sha256:" + ("a" * 64),
            payload_hash="sha256:" + ("b" * 64),
            policy_id="nonblocking-diagnostics",
            policy_rule_id="write-file-approval",
            policy_context_hash="c" * 64,
            status=ApprovalStatus.PENDING.value,
            created_at=now,
            expires_at=now + 300,
        )
    )
    manager._bind_client_request("lock-test", request_id)
    key = normalize_client_request_id("lock-test")
    assert key is not None
    with manager._bindings_lock:
        manager._prebind_cancellations[key] = time.monotonic() + 300.0

    completed = threading.Event()

    def worker() -> None:
        with manager._finalize_lock:
            if manager.consume_prebind_cancellation("lock-test"):
                manager._cancel_approval_locked(request_id, reason="client_cancelled")
        completed.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=2.0)
    assert completed.is_set()
    assert not thread.is_alive()
    assert store.get_pending(request_id).status == ApprovalStatus.CANCELLED.value
    server.stop()
    store.close()


def test_missing_evidence_before_register_raises_approval_flow_error(
    tmp_path,
    monkeypatch,
):
    config = _nonblocking_config()
    manager, store, server, _ = _manager(tmp_path, config=config)
    classification = ToolCallClassifier(config, server_name="filesystem").classify(
        tool="write_file",
        arguments={"path": "missing-evidence.txt", "content": "x"},
    )
    monkeypatch.setattr(store, "write_pending", lambda record: record)
    with pytest.raises(ApprovalFlowError, match="approval evidence record missing"):
        manager.request_approval(
            classification,
            reason="local_approval_required",
            client_request_id="missing-evidence",
        )
    assert server.pending_prompts() == []
    server.stop()
    store.close()
