# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Tests for bounded Console decision-summary upload client."""

from __future__ import annotations

import io
import json
import queue
import threading
import time
from dataclasses import replace

import pytest

from agentveil_mcp_proxy.approval.manager import ApprovalManager, ApprovalOutcome
from agentveil_mcp_proxy.approval.server import ApprovalServer
from agentveil_mcp_proxy.classification import ClassifiedToolCall, infer_action_family, sha256_text
from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCOPE,
    CredentialError,
    StoredCredential,
    console_credential_home_for_runtime,
)
from agentveil_mcp_proxy.console_decision_summary_client import (
    CONSOLE_ORIGIN,
    ConsoleDecisionSummaryClient,
    ConsoleDecisionSummaryDispatcher,
    DecisionSummaryClientError,
    DecisionSummaryPayload,
    RawResponse,
    TransportError,
    _REQUEST_TIMEOUT_SECONDS,
    _SHUTDOWN_JOIN_TIMEOUT_SECONDS,
    attach_terminal_evidence_observer,
    best_effort_spawn_hook_denied_summary,
    best_effort_upload_hook_denied_summary,
    build_decision_summary_payload,
    build_hook_denied_decision_summary_payload,
    payload_to_request_body,
    run_hook_denied_upload_worker,
    sync_decision_summary,
    wait_for_hook_denied_uploads_for_tests,
)
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.policy import (
    PolicyDecision,
    PolicyEvaluation,
    ProxyConfig,
    RiskClass,
)
from agentveil_mcp_proxy.runtime_gate import RuntimeGateDecision


@pytest.fixture(autouse=True)
def _reset_hook_denied_upload_dedupe() -> None:
    from agentveil_mcp_proxy.console_decision_summary_client import (
        reset_hook_denied_upload_dedupe_for_tests,
    )

    reset_hook_denied_upload_dedupe_for_tests()


TOKEN = "console-device-token-secret-canary"
SECRET = "SECRET_DECISION_SUMMARY_CANARY"
EVENT_ID = "canary-event-id-001"
PROOF_HASH = "a" * 64
PAYLOAD_HASH = "sha256:" + "a" * 64
RESOURCE_HASH = "sha256:" + "b" * 64
POLICY_CONTEXT_HASH = "c" * 64
APPROVAL_TOKEN_HASH = "sha256:" + "e" * 64


def _json_response(status, obj, *, content_type="application/json"):
    body = json.dumps(obj).encode("utf-8")
    content_types = () if content_type is None else (content_type,)
    return RawResponse(status=status, content_types=content_types, body=body)


def _backend_ack_for_request(body: bytes, *, status="accepted"):
    payload = json.loads(body.decode("utf-8"))
    return {
        "schema_version": payload["schema_version"],
        "decision": payload["decision"],
        "action_family": payload["action_family"],
        "occurred_at": payload["occurred_at"],
        "target_reached": payload["target_reached"],
        "proof_status": payload["proof_status"],
        "status": status,
    }


class FakeTransport:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, *, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            return item(body=body)
        return item


class BackendEchoTransport:
    def __init__(self, *, status="accepted"):
        self.status = status
        self.calls = []

    def __call__(self, method, url, *, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        return _json_response(
            200,
            _backend_ack_for_request(body, status=self.status),
        )


def _load_credential_ok(home=None):
    return StoredCredential(scope=CREDENTIAL_SCOPE, token=TOKEN)


def _record(**overrides) -> PendingApproval:
    base = PendingApproval(
        request_id=EVENT_ID,
        session_id="session-1",
        client_id="cursor:session-7",
        downstream_server="filesystem",
        tool_name="read_file",
        action_class="read",
        risk_class="read",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id="filesystem-read",
        policy_rule_id="filesystem-read",
        policy_context_hash=POLICY_CONTEXT_HASH,
        status=ApprovalStatus.EXECUTED.value,
        created_at=1_700_000_000,
        expires_at=None,
        approval_decided_at=1_700_000_010,
        decision_audit_id="audit-001",
        decision_receipt_sha256=PROOF_HASH,
    )
    if not overrides:
        return base
    return replace(base, **overrides)


def _metadata(**extra):
    payload = {
        "action_family": "read",
        "target_reached": True,
    }
    payload.update(extra)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _payload(**overrides) -> DecisionSummaryPayload:
    base = DecisionSummaryPayload(
        schema_version="1",
        event_id=EVENT_ID,
        action_family="read",
        decision="allowed",
        occurred_at="2024-11-14T22:13:20Z",
        target_reached=True,
        proof_status="intact",
        proof_hash=PROOF_HASH,
        idempotency_key=EVENT_ID,
    )
    if not overrides:
        return base
    return replace(base, **overrides)


def _config() -> ProxyConfig:
    return ProxyConfig.from_dict(
        {
            "proxy_config_schema_version": 1,
            "avp": {
                "agent_name": "proxy",
                "base_url": "https://agentveil.dev",
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
            "downstream": {"name": "filesystem", "command": "echo"},
            "policy": {
                "id": "approval-test",
                "policy_schema_version": 1,
                "default_decision": "approval",
                "default_risk_class": "read",
                "rules": [],
            },
            "approval": {
                "approval_timeout_seconds": 300,
                "on_timeout": "deny",
                "wait_for_decision": False,
                "ui_open_mode": "none",
            },
        }
    )


def _seed_approved_record(store: ApprovalEvidenceStore) -> None:
    store.write_pending(
        _record(
            status=ApprovalStatus.PENDING.value,
            approval_token_hash=None,
            approval_decided_at=None,
            decision_receipt_sha256=None,
        )
    )
    store.transition(
        EVENT_ID,
        ApprovalStatus.APPROVED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        approval_decided_by="local-user",
        approval_scope="exact",
        user_decision_timestamp=1_700_000_010,
    )


def _classification(*, tool: str = "read_file") -> ClassifiedToolCall:
    evaluation = PolicyEvaluation(
        decision=PolicyDecision.APPROVAL,
        risk_class=RiskClass.READ,
        policy_id="filesystem-pack",
        policy_rule_id="filesystem-read",
        matched_rule_ids=("filesystem-read",),
        policy_context_hash=POLICY_CONTEXT_HASH,
    )
    return ClassifiedToolCall(
        server="filesystem",
        tool=tool,
        action_plain=tool,
        action=tool,
        action_hash=sha256_text(tool),
        resource_plain="notes.txt",
        resource=RESOURCE_HASH,
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        risk_class=RiskClass.READ,
        policy_evaluation=evaluation,
        action_family=infer_action_family(tool),
    )


@pytest.mark.parametrize(
    ("status", "decision", "target_reached", "extra"),
    [
        (ApprovalStatus.EXECUTED.value, "allowed", True, {"action_gate_metadata_jcs": _metadata()}),
        (ApprovalStatus.EXECUTED.value, "allowed", None, {}),
        (
            ApprovalStatus.ERROR.value,
            "allowed",
            False,
            {
                "approval_decided_at": 1_700_000_010,
                "approval_grant_jcs": "{}",
            },
        ),
        (ApprovalStatus.DENIED.value, "denied", False, {}),
        (ApprovalStatus.BLOCKED.value, "denied", False, {}),  # claim-check: allow terminal evidence status enum value
    ],
)
def test_build_payload_for_uploadable_terminal_states(
    status,
    decision,
    target_reached,
    extra,
):
    payload = build_decision_summary_payload(_record(status=status, **extra))
    assert payload is not None
    assert payload.decision == decision
    assert payload.target_reached is target_reached
    assert payload.event_id == EVENT_ID
    body = payload_to_request_body(payload)
    assert body["decision"] == decision
    if payload.proof_status == "unavailable":
        assert "proof_hash" not in body
    else:
        assert body["proof_hash"] == PROOF_HASH


@pytest.mark.parametrize(
    "status",
    [
        ApprovalStatus.PENDING.value,
        ApprovalStatus.APPROVED.value,
        ApprovalStatus.EXPIRED.value,
        ApprovalStatus.CANCELLED.value,
        ApprovalStatus.INVALIDATED.value,
    ],
)
def test_build_payload_skips_non_uploadable_states(status):
    assert build_decision_summary_payload(_record(status=status)) is None


def test_build_payload_skips_secretish_event_id():
    assert build_decision_summary_payload(_record(request_id="token-leak-001")) is None


def test_build_payload_uses_unavailable_without_verified_receipt():
    payload = build_decision_summary_payload(
        _record(decision_receipt_sha256=None, decision_audit_id=None)
    )
    assert payload is not None
    body = payload_to_request_body(payload)
    assert body["proof_status"] == "unavailable"
    assert "proof_hash" not in body


def test_build_payload_uses_unavailable_when_receipt_digest_lacks_audit_binding():
    payload = build_decision_summary_payload(
        _record(decision_audit_id=None, decision_receipt_sha256=PROOF_HASH)
    )
    assert payload is not None
    body = payload_to_request_body(payload)
    assert body["proof_status"] == "unavailable"
    assert "proof_hash" not in body


def test_build_payload_uploads_runtime_gate_execution_error():
    payload = build_decision_summary_payload(
        _record(
            status=ApprovalStatus.ERROR.value,
            decision_audit_id="audit-gate-1",
            decision_receipt_sha256=PROOF_HASH,
            approval_decided_at=None,
            approval_grant_jcs=None,
        )
    )
    assert payload is not None
    assert payload.decision == "allowed"
    assert payload.target_reached is False
    assert payload.proof_status == "intact"
    assert payload.proof_hash == PROOF_HASH


def test_sync_without_credential_makes_zero_transport_calls():
    transport = BackendEchoTransport()
    result = sync_decision_summary(
        _payload(),
        load_credential_fn=lambda home=None: None,
        transport=transport,
    )
    assert result == "skipped_no_credential"
    assert transport.calls == []


def test_sync_with_unsafe_credential_makes_zero_transport_calls():
    transport = BackendEchoTransport()

    def _bad_load(home=None):
        raise CredentialError("credential_invalid")

    result = sync_decision_summary(
        _payload(),
        load_credential_fn=_bad_load,
        transport=transport,
    )
    assert result == "skipped_unsafe_credential"
    assert transport.calls == []


def test_sync_accepts_backend_shaped_response():
    transport = BackendEchoTransport()
    result = sync_decision_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "accepted"
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == f"{CONSOLE_ORIGIN}/console/decision-summaries/ingest"
    assert call["timeout"] == 3.0
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN}"
    payload = json.loads(call["body"].decode("utf-8"))
    assert set(payload.keys()) <= {
        "schema_version",
        "event_id",
        "action_family",
        "decision",
        "occurred_at",
        "target_reached",
        "proof_status",
        "proof_hash",
        "idempotency_key",
    }


def test_duplicate_ack_is_preserved():
    transport = BackendEchoTransport(status="duplicate")
    result = sync_decision_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "duplicate"


def test_project_runtime_uses_global_console_credential_home(monkeypatch, tmp_path):
    runtime_home = tmp_path / "project-home"
    monkeypatch.setenv("AVP_HOME", str(runtime_home))
    assert console_credential_home_for_runtime(runtime_home) == (
        tmp_path.home() / ".avp"
    )


def test_canonical_project_runtime_uses_global_credential_without_env(
    monkeypatch,
    tmp_path,
):
    monkeypatch.delenv("AVP_HOME", raising=False)
    runtime_home = tmp_path / "project" / ".avp"
    assert console_credential_home_for_runtime(runtime_home) == (
        tmp_path.home() / ".avp"
    )


def test_non_project_runtime_keeps_explicit_console_credential_home(
    monkeypatch,
    tmp_path,
):
    configured_home = tmp_path / "configured-home"
    explicit_home = tmp_path / "explicit-home"
    monkeypatch.setenv("AVP_HOME", str(configured_home))
    assert console_credential_home_for_runtime(explicit_home) == explicit_home


@pytest.mark.parametrize("status_code", [301, 401, 403, 404, 409, 429, 500])
def test_http_failures_return_unavailable(status_code):
    transport = FakeTransport([
        lambda body: _json_response(status_code, _backend_ack_for_request(body))
    ])
    result = sync_decision_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "unavailable"


def test_transport_error_returns_unavailable():
    transport = FakeTransport([TransportError()])
    result = sync_decision_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "unavailable"


@pytest.mark.parametrize(
    "content_type",
    [
        "text/plain",
        "application/json; charset=",
        "application/json; charset=latin1",
    ],
)
def test_malformed_content_type_fails_softly(content_type):
    transport = FakeTransport([
        RawResponse(status=200, content_types=(content_type,), body=b"{}"),
    ])
    result = sync_decision_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "rejected"


@pytest.mark.parametrize(
    "response",
    [
        _json_response(200, {}, content_type="text/plain"),
        RawResponse(status=200, content_types=("application/json", "application/json"), body=b"{}"),
        RawResponse(status=200, content_types=("application/json",), body=b"[]"),
        RawResponse(status=200, content_types=("application/json",), body=b"{\"extra\":1}"),
        RawResponse(status=200, content_types=("application/json",), body=b"x" * 17000),
    ],
)
def test_malformed_response_fails_softly(response):
    transport = FakeTransport([response])
    result = sync_decision_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "rejected"


_STRING_RESPONSE_FIELDS = (
    "schema_version",
    "decision",
    "action_family",
    "occurred_at",
    "proof_status",
    "status",
)
_NON_STRING_VALUES = (123, True, [], {})


@pytest.mark.parametrize("field", _STRING_RESPONSE_FIELDS)
@pytest.mark.parametrize("bad_value", _NON_STRING_VALUES)
def test_response_rejects_non_string_field_types(field, bad_value):
    transport = FakeTransport([
        lambda body: _json_response(
            200,
            {**_backend_ack_for_request(body), field: bad_value},
        )
    ])
    client = ConsoleDecisionSummaryClient(transport=transport)
    with pytest.raises(DecisionSummaryClientError, match="malformed_body"):
        client.upload(_payload(), bearer_token=TOKEN)


def test_response_rejects_mismatched_echo_fields():
    transport = FakeTransport([
        lambda body: _json_response(
            200,
            {**_backend_ack_for_request(body), "decision": "denied"},
        )
    ])
    client = ConsoleDecisionSummaryClient(transport=transport)
    with pytest.raises(DecisionSummaryClientError, match="malformed_body"):
        client.upload(_payload(), bearer_token=TOKEN)


def test_dispatcher_inactive_without_credential_makes_zero_queue_calls(tmp_path):
    uploads = []

    def _upload(*args, **kwargs):
        uploads.append(True)
        return "accepted"

    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=lambda home=None: None,
        upload_fn=_upload,
        queue_capacity=4,
    )
    dispatcher.start()
    assert dispatcher.is_active is False
    dispatcher.notify_terminal_record(_record())
    dispatcher.stop()
    assert uploads == []


def _alive_threads_created_since(baseline_idents: set[int]) -> list[tuple[str, bool, bool]]:
    return [
        (thread.name, thread.is_alive(), thread.daemon)
        for thread in threading.enumerate()
        if thread.ident not in baseline_idents and thread.is_alive()
    ]


def test_dispatcher_stop_drains_queue_within_budget(tmp_path):
    processed: list[str] = []
    done = threading.Event()

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        processed.append(payload.event_id)
        if len(processed) == 2:
            done.set()
        return "accepted"

    baseline = {t.ident for t in threading.enumerate()}
    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
        queue_capacity=4,
    )
    dispatcher.start()
    dispatcher.notify_terminal_record(_record(request_id="event-a"))
    dispatcher.notify_terminal_record(_record(request_id="event-b"))
    assert done.wait(timeout=1.0)
    dispatcher.stop()
    worker = dispatcher._worker
    assert worker is not None
    assert not worker.is_alive()
    assert processed == ["event-a", "event-b"]
    assert _alive_threads_created_since(baseline) == []


def test_dispatcher_stop_waits_for_transport_bounded_upload(tmp_path):
    started = threading.Event()
    release = threading.Event()

    def _blocking_transport(method, url, *, headers, body, timeout):
        started.set()
        release.wait(timeout=timeout)
        return _json_response(200, _backend_ack_for_request(body))

    baseline = {t.ident for t in threading.enumerate()}
    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        transport=_blocking_transport,
        queue_capacity=4,
    )
    dispatcher.start()
    dispatcher.notify_terminal_record(_record(request_id="slow-1"))
    assert started.wait(timeout=1.0)

    began = time.monotonic()
    dispatcher.stop()
    elapsed = time.monotonic() - began
    assert elapsed <= _SHUTDOWN_JOIN_TIMEOUT_SECONDS + 0.25
    assert dispatcher._worker is not None
    assert not dispatcher._worker.is_alive()
    assert _alive_threads_created_since(baseline) == []
    release.set()


def test_dispatcher_stop_drops_queued_events_when_shutdown_requested(tmp_path):
    gate = threading.Event()
    uploads: list[str] = []

    def _slow_first_upload(payload, *, home=None, load_credential_fn=None, transport=None):
        uploads.append(payload.event_id)
        if payload.event_id == "slow-1":
            gate.wait(timeout=_REQUEST_TIMEOUT_SECONDS)
        return "accepted"

    baseline = {t.ident for t in threading.enumerate()}
    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        upload_fn=_slow_first_upload,
        queue_capacity=4,
    )
    dispatcher.start()
    gate.clear()
    dispatcher.notify_terminal_record(_record(request_id="slow-1"))
    while "slow-1" not in uploads:
        time.sleep(0.001)
    dispatcher.notify_terminal_record(_record(request_id="queued-2"))

    began = time.monotonic()
    dispatcher.stop()
    elapsed = time.monotonic() - began
    assert elapsed <= _SHUTDOWN_JOIN_TIMEOUT_SECONDS + 0.25
    assert uploads == ["slow-1"]
    assert dispatcher._worker is not None
    assert not dispatcher._worker.is_alive()
    assert _alive_threads_created_since(baseline) == []
    gate.set()


@pytest.mark.parametrize("attempt", range(20))
def test_shutdown_leaves_no_dispatcher_or_helper_threads(tmp_path, attempt):
    started = threading.Event()
    release = threading.Event()

    def _blocking_transport(method, url, *, headers, body, timeout):
        started.set()
        release.wait(timeout=timeout)
        return _json_response(200, _backend_ack_for_request(body))

    baseline = {t.ident for t in threading.enumerate()}
    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        transport=_blocking_transport,
        queue_capacity=4,
    )
    dispatcher.start()
    dispatcher.notify_terminal_record(_record(request_id=f"evt-{attempt}"))
    assert started.wait(timeout=1.0)
    dispatcher.stop()
    assert dispatcher._worker is not None
    assert not dispatcher._worker.is_alive()
    assert _alive_threads_created_since(baseline) == []
    release.set()


def test_dispatcher_deduplicates_duplicate_notifications(tmp_path):
    uploads = []

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        uploads.append(payload.event_id)
        return "accepted"

    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
        queue_capacity=8,
    )
    dispatcher.start()
    try:
        record = _record()
        dispatcher.notify_terminal_record(record)
        dispatcher.notify_terminal_record(record)
        deadline = time.monotonic() + 2.0
        while len(uploads) < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert uploads == [EVENT_ID]
    finally:
        dispatcher.stop()


@pytest.mark.parametrize("first_outcome", ["unavailable", "rejected"])
def test_dispatcher_retries_same_event_after_unacked_upload(tmp_path, first_outcome):
    uploads: list[str] = []
    outcomes = iter([first_outcome, "accepted"])

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        uploads.append(payload.event_id)
        return next(outcomes)

    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
        queue_capacity=4,
    )
    dispatcher.start()
    try:
        record = _record(request_id=f"retry-after-{first_outcome}")
        dispatcher.notify_terminal_record(record)
        deadline = time.monotonic() + 2.0
        while len(uploads) < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        dispatcher.notify_terminal_record(record)
        deadline = time.monotonic() + 2.0
        while len(uploads) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        dispatcher.notify_terminal_record(record)
        time.sleep(0.1)
        assert uploads == [record.request_id, record.request_id]
    finally:
        dispatcher.stop()


def test_dispatcher_retries_same_event_after_upload_exception(tmp_path):
    uploads: list[str] = []

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        uploads.append(payload.event_id)
        if len(uploads) == 1:
            raise RuntimeError("bounded upload failure")
        return "duplicate"

    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
        queue_capacity=4,
    )
    dispatcher.start()
    try:
        record = _record(request_id="retry-after-exception")
        dispatcher.notify_terminal_record(record)
        deadline = time.monotonic() + 2.0
        while len(uploads) < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        dispatcher.notify_terminal_record(record)
        deadline = time.monotonic() + 2.0
        while len(uploads) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        dispatcher.notify_terminal_record(record)
        time.sleep(0.1)
        assert uploads == [record.request_id, record.request_id]
    finally:
        dispatcher.stop()


def test_dispatcher_queue_full_is_bounded(tmp_path):
    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        queue_capacity=1,
        upload_fn=lambda *args, **kwargs: "accepted",
    )
    dispatcher.start()
    try:
        record = _record(request_id="event-a")
        dispatcher.notify_terminal_record(record)
        dispatcher.notify_terminal_record(_record(request_id="event-b"))
        dispatcher.notify_terminal_record(_record(request_id="event-c"))
    finally:
        dispatcher.stop()


def test_dispatcher_worker_exception_is_bounded(tmp_path):
    def _explode(*args, **kwargs):
        raise RuntimeError(SECRET)

    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        upload_fn=_explode,
        queue_capacity=4,
    )
    dispatcher.start()
    try:
        dispatcher.notify_terminal_record(_record())
        time.sleep(0.2)
    finally:
        dispatcher.stop()


def test_manager_observer_receives_executed_terminal_record(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer()
    server.start()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_config(),
        client_id="pytest",
        wait_for_decision=False,
    )
    observed: list[PendingApproval] = []
    manager.terminal_evidence_observer = observed.append

    store.write_pending(
        _record(
            status=ApprovalStatus.PENDING.value,
            approval_token_hash=None,
            approval_decided_at=None,
            decision_receipt_sha256=None,
        )
    )
    store.transition(
        EVENT_ID,
        ApprovalStatus.APPROVED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        approval_decided_by="local-user",
        approval_scope="exact",
        user_decision_timestamp=1_700_000_010,
    )
    outcome = ApprovalOutcome(
        EVENT_ID,
        ApprovalStatus.APPROVED.value,
        "approved",
    )
    manager.record_execution_result(
        outcome,
        {"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
        downstream_tool_call_seen=True,
    )

    assert len(observed) == 1
    assert observed[0].status == ApprovalStatus.EXECUTED.value
    payload = build_decision_summary_payload(observed[0])
    assert payload is not None
    assert payload.decision == "allowed"
    server.stop()
    store.close()


def test_manager_observer_swallows_exceptions(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer()
    server.start()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_config(),
        client_id="pytest",
        wait_for_decision=False,
    )

    def _boom(_record):
        raise RuntimeError(SECRET)

    manager.terminal_evidence_observer = _boom
    store.write_pending(
        _record(
            status=ApprovalStatus.PENDING.value,
            approval_token_hash=None,
            approval_decided_at=None,
            decision_receipt_sha256=None,
        )
    )
    store.transition(
        EVENT_ID,
        ApprovalStatus.APPROVED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        approval_decided_by="local-user",
        approval_scope="exact",
        user_decision_timestamp=1_700_000_010,
    )
    outcome = ApprovalOutcome(EVENT_ID, ApprovalStatus.APPROVED.value, "approved")
    manager.record_execution_result(
        outcome,
        {"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
        downstream_tool_call_seen=True,
    )
    record = store.get_pending(EVENT_ID)
    assert record is not None
    assert record.status == ApprovalStatus.EXECUTED.value
    server.stop()
    store.close()


def test_manager_observer_receives_runtime_block(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer()
    server.start()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_config(),
        client_id="pytest",
        wait_for_decision=False,
    )
    observed: list[PendingApproval] = []
    manager.terminal_evidence_observer = observed.append
    runtime = RuntimeGateDecision(
        decision="BLOCK",
        audit_id="audit-1",
        approval_id=None,
        receipt_digest=PROOF_HASH,
        receipt_body={},
    )
    manager.record_runtime_block(_classification(), runtime_decision=runtime)
    assert len(observed) == 1
    payload = build_decision_summary_payload(observed[0])
    assert payload is not None
    assert payload.decision == "denied"
    server.stop()
    store.close()


def test_attach_terminal_evidence_observer_wires_dispatcher(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer()
    server.start()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_config(),
        client_id="pytest",
        wait_for_decision=False,
    )
    uploads: queue.Queue[str] = queue.Queue()

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        uploads.put_nowait(payload.event_id)
        return "accepted"

    dispatcher = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
        queue_capacity=4,
    )
    dispatcher.start()
    attach_terminal_evidence_observer(manager, dispatcher)
    try:
        _seed_approved_record(store)
        manager.record_execution_result(
            ApprovalOutcome(EVENT_ID, ApprovalStatus.APPROVED.value, "approved"),
            {"jsonrpc": "2.0", "id": 1, "result": {}},
            downstream_tool_call_seen=True,
        )
        deadline = time.monotonic() + 2.0
        while uploads.empty() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert uploads.get_nowait() == EVENT_ID
    finally:
        dispatcher.stop()
        server.stop()
        store.close()


def test_privacy_canaries_absent_from_request_json():
    transport = BackendEchoTransport()
    sync_decision_summary(
        _payload(),
        load_credential_fn=lambda home=None: StoredCredential(
            scope=CREDENTIAL_SCOPE,
            token=SECRET,
        ),
        transport=transport,
    )
    encoded = transport.calls[0]["body"].decode("utf-8")
    for forbidden in (
        SECRET,
        TOKEN,
        "/Users/",
        "read_file",
        "filesystem",
        "payload",
        "prompt",
        "command",
        "approval",
        "secret",
    ):
        assert forbidden not in encoded
    payload = json.loads(encoded)
    assert set(payload.keys()) <= {
        "schema_version",
        "event_id",
        "action_family",
        "decision",
        "occurred_at",
        "target_reached",
        "proof_status",
        "proof_hash",
        "idempotency_key",
    }


def _hook_denied_record(**overrides):
    record = {
        "ts": "2026-08-09T10:00:00Z",
        "session_id": "sess-hook-001",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "server": "codex",
        "tool": "Bash",
        "action_family": "shell_like",
        "hook_action": "deny",
        "reason_code": "risky_blocked",
        "input_ref": {"input_hash": "sha256:abc123def4567890", "input_keys": ["command"]},
    }
    record.update(overrides)
    return record


def _wait_hook_denied_uploads() -> None:
    assert wait_for_hook_denied_uploads_for_tests(timeout=2.0)


def test_build_hook_denied_decision_summary_payload_maps_denied_record():
    payload = build_hook_denied_decision_summary_payload(_hook_denied_record())
    assert payload is not None
    assert payload.decision == "denied"
    assert payload.target_reached is False
    assert payload.proof_status == "unavailable"
    assert payload.proof_hash is None
    assert payload.action_family == "shell_like"
    assert payload.event_id.startswith("hook.denied.")


def test_build_hook_denied_decision_summary_payload_skips_allow():
    assert (
        build_hook_denied_decision_summary_payload(
            _hook_denied_record(hook_action="allow")
        )
        is None
    )


def test_build_hook_denied_decision_summary_payload_infers_action_family_from_tool():
    payload = build_hook_denied_decision_summary_payload(
        _hook_denied_record(action_family="", tool="write_file", tool_name="write_file")
    )
    assert payload is not None
    assert payload.action_family == "write"


def test_build_hook_denied_decision_summary_payload_maps_bash_to_shell_like():
    payload = build_hook_denied_decision_summary_payload(
        _hook_denied_record(action_family="unknown", tool="Bash", tool_name="Bash")
    )
    assert payload is not None
    assert payload.action_family == "shell_like"


def test_hook_denied_upload_dedupes_same_event():
    calls: list[str] = []

    def _upload(payload, **kwargs):
        calls.append(payload.event_id)
        return "accepted"

    record = _hook_denied_record(session_id="dedupe-session")
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    assert len(calls) == 1


def test_hook_denied_upload_dedupes_after_duplicate_ack():
    calls: list[str] = []

    def _upload(payload, **kwargs):
        calls.append(payload.event_id)
        return "duplicate"

    record = _hook_denied_record(session_id="duplicate-ack-session")
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    assert len(calls) == 1


def test_hook_denied_upload_retries_after_transient_failure():
    calls: list[str] = []
    outcomes = iter(["unavailable", "accepted"])

    def _upload(payload, **kwargs):
        calls.append(payload.event_id)
        return next(outcomes)

    record = _hook_denied_record(session_id="retry-unavailable-session")
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    assert len(calls) == 2


def test_hook_denied_upload_retries_after_exception():
    calls: list[int] = []

    def _upload(payload, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise DecisionSummaryClientError("transport_failed")
        return "accepted"

    record = _hook_denied_record(session_id="retry-exception-session")
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    _wait_hook_denied_uploads()
    assert len(calls) == 2


def test_hook_denied_upload_does_not_cache_rejected_or_skipped():
    calls: list[str] = []
    outcomes = iter(["rejected", "skipped_no_credential", "accepted"])

    def _upload(payload, **kwargs):
        calls.append(payload.event_id)
        return next(outcomes)

    record = _hook_denied_record(session_id="retry-rejected-session")
    for _ in range(4):
        best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
        _wait_hook_denied_uploads()
    assert len(calls) == 3


def test_hook_denied_upload_returns_without_waiting_for_slow_upload():
    release = threading.Event()
    calls: list[str] = []

    def _upload(payload, **kwargs):
        calls.append(payload.event_id)
        release.wait(timeout=1.0)
        return "accepted"

    record = _hook_denied_record(session_id="slow-upload-session")
    started = time.monotonic()
    best_effort_upload_hook_denied_summary(record, upload_fn=_upload)
    elapsed = time.monotonic() - started
    assert elapsed < 0.1
    release.set()
    _wait_hook_denied_uploads()
    assert len(calls) == 1


def test_hook_denied_request_body_has_no_raw_command_or_path():
    payload = build_hook_denied_decision_summary_payload(
        _hook_denied_record(
            session_id="privacy-session",
            input_ref={
                "input_hash": "sha256:deadbeefdeadbeef",
                "input_keys": ["command"],
            },
        )
    )
    assert payload is not None
    encoded = json.dumps(payload_to_request_body(payload))
    for forbidden in (
        "git add .",
        "/private/customer/workspace",
        "sess-hook-001",
        "privacy-session",
        "command",
        "deadbeefdeadbeef",
    ):
        assert forbidden not in encoded


def test_hook_denied_worker_uploads_only_bounded_summary():
    payload = build_hook_denied_decision_summary_payload(_hook_denied_record())
    assert payload is not None
    encoded = json.dumps(payload_to_request_body(payload)).encode("utf-8")
    uploads = []

    result = run_hook_denied_upload_worker(
        stdin=io.BytesIO(encoded),
        upload_fn=lambda item: uploads.append(item) or "accepted",
    )

    assert result == 0
    assert uploads == [payload]


def test_hook_denied_worker_rejects_extra_raw_fields():
    payload = build_hook_denied_decision_summary_payload(_hook_denied_record())
    assert payload is not None
    body = payload_to_request_body(payload)
    body["command"] = "SECRET raw command"

    assert (
        run_hook_denied_upload_worker(
            stdin=io.BytesIO(json.dumps(body).encode("utf-8")),
            upload_fn=lambda _item: "accepted",
        )
        == 2
    )


def test_detached_hook_upload_drops_project_avp_home(monkeypatch, tmp_path):
    captured = {}

    class _Stdin:
        def write(self, value):
            captured["input"] = value

        def close(self):
            captured["closed"] = True

    class _Process:
        stdin = _Stdin()

        def wait(self):
            return 0

    def _popen(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        return _Process()

    def _load_credential(**kwargs):
        captured["credential_home"] = kwargs["home"]
        return StoredCredential(scope=CREDENTIAL_SCOPE, token=TOKEN)

    monkeypatch.setenv("AVP_HOME", str(tmp_path / "project-home"))
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_decision_summary_client.subprocess.Popen",
        _popen,
    )

    runtime_home = tmp_path / "project-home"
    best_effort_spawn_hook_denied_summary(
        _hook_denied_record(),
        runtime_home=runtime_home,
        load_credential_fn=_load_credential,
    )

    assert "AVP_HOME" not in captured["env"]
    assert captured["credential_home"] == (tmp_path.home() / ".avp")
    assert captured["command"][-1] == "--hook-denied-upload-worker"
    assert captured["closed"] is True
    encoded = captured["input"].decode("utf-8")
    assert "command" not in encoded
    assert "/Users/" not in encoded


def test_detached_hook_upload_without_console_credential_spawns_no_process(
    monkeypatch,
):
    popen_calls = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_decision_summary_client.subprocess.Popen",
        lambda *args, **kwargs: popen_calls.append((args, kwargs)),
    )

    best_effort_spawn_hook_denied_summary(
        _hook_denied_record(),
        load_credential_fn=lambda **_kwargs: None,
    )

    assert popen_calls == []
