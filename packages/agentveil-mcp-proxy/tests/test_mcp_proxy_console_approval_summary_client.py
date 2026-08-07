# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Tests for bounded Console approval-summary upload client."""

from __future__ import annotations

import json
import logging
import os
import threading
import time

import httpx
import pytest

from agentveil_mcp_proxy.approval.manager import ApprovalManager, ApprovalOutcome
from agentveil_mcp_proxy.approval.server import (
    ApprovalServer,
    build_owner_client_id,
    publish_owner_claim,
)
from agentveil_mcp_proxy.console_approval_summary_client import (
    CONSOLE_ORIGIN,
    ApprovalPendingItem,
    ApprovalSummaryClientError,
    ApprovalSummaryPayload,
    ConsoleApprovalSummaryDispatcher,
    RawResponse,
    TransportError,
    attach_approval_state_observer,
    build_approval_summary_snapshot,
    derive_approval_id,
    payload_to_request_body,
    sync_approval_summary,
    validate_target_basename,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCOPE,
    CredentialError,
    StoredCredential,
)
from agentveil_mcp_proxy.console_decision_summary_client import (
    ConsoleDecisionSummaryDispatcher,
    attach_terminal_evidence_observer,
)
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.evidence.observability import parse_action_gate_metadata
from agentveil_mcp_proxy.policy import ProxyConfig
from test_mcp_proxy_approval import _get_csrf, _post_decision

TOKEN = "console-device-token-secret-canary"
SECRET = "SECRET_APPROVAL_SUMMARY_CANARY"
CANARY = "CANARY_APPROVAL_PATH_/Users/dev/secret/token"
SESSION_ID = f"session-{CANARY}-console-summary"
INSTANCE_TOKEN = "console-summary-inst"
CLIENT_ID = build_owner_client_id("cursor", pid=os.getpid(), instance_token=INSTANCE_TOKEN)
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
        "observed_at": payload["observed_at"],
        "pending_count": len(payload["pending"]),
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
                "headers": headers,
                "body": body,
                "timeout": timeout,
            }
        )
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response(body)


class BackendEchoTransport:
    def __init__(self, *, status="accepted"):
        self.calls = []
        self.status = status

    def __call__(self, method, url, *, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
                "timeout": timeout,
            }
        )
        return _json_response(200, _backend_ack_for_request(body, status=self.status))


def _load_credential_ok(home=None):
    return StoredCredential(token=TOKEN, scope=CREDENTIAL_SCOPE)


def _metadata(*, basename="config.toml", action_family="write"):
    return json.dumps(
        {
            "action_family": action_family,
            "target_basename": basename,
            "policy_decision": "approval",
            "approval_status": "pending",
            "execution_status": "not_reached",
            "target_reached": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _record(
    request_id: str = "req-approval-1",
    *,
    status=ApprovalStatus.PENDING.value,
    metadata=_metadata(),
    granted_by_request_id=None,
    approval_token_hash=APPROVAL_TOKEN_HASH,
    created_at=1_700_000_000,
    approval_decided_at=None,
    user_decision_timestamp=None,
    tool_name="write_file",
):
    return PendingApproval(
        request_id=request_id,
        session_id="session-1",
        client_id="client-1",
        downstream_server="filesystem",
        tool_name=tool_name,
        action_class="write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id="policy-1",
        policy_rule_id="rule-1",
        policy_context_hash=POLICY_CONTEXT_HASH,
        status=status,
        created_at=created_at,
        expires_at=created_at + 300,
        approval_token_hash=approval_token_hash,
        action_gate_metadata_jcs=metadata,
        granted_by_request_id=granted_by_request_id,
        approval_decided_at=approval_decided_at,
        user_decision_timestamp=user_decision_timestamp,
    )


def _payload(**overrides):
    pending = overrides.pop("pending", ())
    resolutions = overrides.pop("resolutions", ())
    observed_at = overrides.pop("observed_at", "2026-08-07T09:00:00Z")
    from agentveil_mcp_proxy.console_approval_summary_client import _derive_payload_identity

    snapshot_id, idempotency_key = _derive_payload_identity(
        observed_at=observed_at,
        pending=pending,
        resolutions=resolutions,
    )
    defaults = {
        "schema_version": "1",
        "snapshot_id": snapshot_id,
        "observed_at": observed_at,
        "pending": pending,
        "resolutions": resolutions,
        "idempotency_key": idempotency_key,
    }
    defaults.update(overrides)
    return ApprovalSummaryPayload(**defaults)


def _wait_until(predicate, *, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def _manager_config(*, approval_timeout_seconds: int = 300):
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
            "downstream": {},
            "policy": {
                "id": "approval-test",
                "policy_schema_version": 1,
                "default_decision": "approval",
                "default_risk_class": "write",
                "rules": [],
            },
            "approval": {
                "approval_timeout_seconds": approval_timeout_seconds,
                "on_timeout": "deny",
                "ui_open_mode": "none",
            },
        }
    )


def _setup_manager(tmp_path, *, approval_timeout_seconds: int = 300):
    proxy_dir = tmp_path / "mcp-proxy"
    proxy_dir.mkdir(parents=True, exist_ok=True)
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    lease = publish_owner_claim(
        proxy_dir / "owner_claims",
        pid=os.getpid(),
        instance_token=INSTANCE_TOKEN,
        session_id=SESSION_ID,
    )
    server = ApprovalServer(evidence_store=store)
    server.start()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_manager_config(approval_timeout_seconds=approval_timeout_seconds),
        client_id=CLIENT_ID,
        session_id=SESSION_ID,
        wait_for_decision=False,
    )
    return store, server, manager, lease


def _write_classification(
    *,
    path: str = "file:project/config.toml",
    reason: str = "local_approval_required",
):
    return ToolCallClassifier(_manager_config(), server_name="filesystem").classify(
        tool="write_file",
        arguments={"path": path, "content": "x"},
    ), reason


def _approve_via_approval_center(server: ApprovalServer, request_id: str) -> None:
    with httpx.Client() as client:
        url = server.approval_url(request_id)
        csrf = _get_csrf(client, url)
        response = _post_decision(client, url, decision="approve", csrf=csrf)
        assert response.status_code == 200


def _deny_via_approval_center(server: ApprovalServer, request_id: str) -> None:
    with httpx.Client() as client:
        url = server.approval_url(request_id)
        csrf = _get_csrf(client, url)
        response = _post_decision(client, url, decision="deny", csrf=csrf)
        assert response.status_code == 200


def _snapshot_for_store(store: ApprovalEvidenceStore):
    snapshot = build_approval_summary_snapshot(store)
    assert snapshot is not None
    return snapshot


def test_derive_approval_id_is_stable_and_opaque():
    first = derive_approval_id("req-stable-1")
    second = derive_approval_id("req-stable-1")
    third = derive_approval_id("req-stable-2")
    assert first == second
    assert first != third
    assert first != "req-stable-1"


@pytest.mark.parametrize(
    "value",
    [
        "config.toml",
        "README",
        "a.b-c_1",
        None,
        "/Users/dev/config.toml",
        "../secret.toml",
        "token.toml",
    ],
)
def test_validate_target_basename(value):
    expected_ok = value in {"config.toml", "README", "a.b-c_1"}
    assert (validate_target_basename(value) is not None) is expected_ok


def test_build_snapshot_maps_pending_and_resolution_rows(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("pending-1"))
    store.write_pending(_record("resolved-deny-1"))
    store.transition(
        "resolved-deny-1",
        ApprovalStatus.DENIED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        user_decision_timestamp=1_700_000_010,
        error_class="user_denied",
    )
    snapshot = build_approval_summary_snapshot(store)
    assert snapshot is not None
    assert len(snapshot.pending) == 1
    assert snapshot.pending[0].target_basename == "config.toml"
    assert snapshot.pending[0].approval_id == derive_approval_id("pending-1")
    assert len(snapshot.resolutions) == 1
    assert snapshot.resolutions[0].status == "denied"
    store.close()


def test_build_snapshot_skips_when_more_than_100_pending(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    for idx in range(101):
        store.write_pending(_record(f"pending-{idx:03d}", created_at=1_700_000_000 + idx))
    assert build_approval_summary_snapshot(store) is None
    store.close()


def test_build_snapshot_skips_when_pending_row_lacks_safe_basename(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(
        _record("pending-unsafe", metadata=_metadata(basename="../secret.toml"))
    )
    assert build_approval_summary_snapshot(store) is None
    store.close()


def test_build_snapshot_excludes_runtime_only_and_exact_grant_children(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(
        _record(
            "runtime-only",
            approval_token_hash=None,
            metadata=None,
        )
    )
    store.write_pending(
        _record(
            "grant-child",
            granted_by_request_id="parent-1",
        )
    )
    snapshot = build_approval_summary_snapshot(store)
    assert snapshot is not None
    assert snapshot.pending == ()
    assert snapshot.resolutions == ()
    store.close()


def test_build_snapshot_preserves_approved_resolution_after_execution(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("approved-1"))
    store.transition(
        "approved-1",
        ApprovalStatus.APPROVED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        user_decision_timestamp=1_700_000_005,
    )
    store.transition(
        "approved-1",
        ApprovalStatus.EXECUTED.value,
        result_status="executed",
        result_hash=PAYLOAD_HASH,
    )
    snapshot = build_approval_summary_snapshot(store)
    assert snapshot is not None
    assert snapshot.pending == ()
    assert len(snapshot.resolutions) == 1
    assert snapshot.resolutions[0].status == "approved"
    store.close()


def test_sync_without_credential_makes_zero_transport_calls():
    transport = BackendEchoTransport()
    result = sync_approval_summary(
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

    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_bad_load,
        transport=transport,
    )
    assert result == "skipped_unsafe_credential"
    assert transport.calls == []


def test_sync_accepts_backend_shaped_response():
    transport = BackendEchoTransport()
    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "accepted"
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == f"{CONSOLE_ORIGIN}/console/approval-summaries/ingest"
    assert call["timeout"] == 3.0
    payload = json.loads(call["body"].decode("utf-8"))
    assert SECRET not in json.dumps(payload)
    assert "request_id" not in payload


@pytest.mark.parametrize("status_code", [301, 401, 403, 404, 409, 429, 500])
def test_http_failures_return_unavailable(status_code):
    transport = FakeTransport([
        lambda body: _json_response(status_code, _backend_ack_for_request(body))
    ])
    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "unavailable"


def test_response_pending_count_mismatch_is_rejected():
    transport = FakeTransport([
        lambda body: _json_response(
            200,
            {
                "schema_version": "1",
                "observed_at": json.loads(body.decode("utf-8"))["observed_at"],
                "pending_count": 99,
                "status": "accepted",
            },
        )
    ])
    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "rejected"


def _alive_threads_created_since(baseline_idents: set[int]) -> list[tuple[str, bool, bool]]:
    return [
        (thread.name, thread.is_alive(), thread.daemon)
        for thread in threading.enumerate()
        if thread.ident not in baseline_idents and thread.is_alive()
    ]


def test_dispatcher_without_credential_stays_inactive(tmp_path):
    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: _payload(),
        load_credential_fn=lambda home=None: None,
    )
    dispatcher.start()
    assert dispatcher.is_active is False
    assert dispatcher._worker is None


def test_dispatcher_uploads_snapshot_on_request(tmp_path):
    uploaded = []

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        uploaded.append(payload)
        return "accepted"

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("pending-upload-1"))
    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
    )
    dispatcher.start()
    dispatcher.request_snapshot()
    deadline = time.monotonic() + 1.0
    while not uploaded and time.monotonic() < deadline:
        time.sleep(0.01)
    dispatcher.stop()
    assert len(uploaded) == 1
    assert len(uploaded[0].pending) == 1
    store.close()


@pytest.mark.parametrize("attempt", range(20))
def test_shutdown_leaves_no_approval_dispatcher_threads(tmp_path, attempt):
    calls = 0
    first_started = threading.Event()
    first_release = threading.Event()
    second_started = threading.Event()
    second_release = threading.Event()

    def _blocking_transport(method, url, *, headers, body, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            first_started.set()
            first_release.wait(timeout=timeout)
        else:
            second_started.set()
            second_release.wait(timeout=timeout)
        return _json_response(200, _backend_ack_for_request(body))

    store = ApprovalEvidenceStore(tmp_path / f"evidence-{attempt}.sqlite")
    store.write_pending(_record(f"pending-{attempt}"))
    baseline = {t.ident for t in threading.enumerate()}
    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        transport=_blocking_transport,
    )
    dispatcher.start()
    dispatcher.request_snapshot()
    assert first_started.wait(timeout=1.0)
    first_release.set()
    store.write_pending(_record(f"pending-{attempt}-changed"))
    dispatcher.request_snapshot()
    assert second_started.wait(timeout=1.0)
    dispatcher.stop()
    assert dispatcher._worker is not None
    assert not dispatcher._worker.is_alive()
    assert _alive_threads_created_since(baseline) == []
    second_release.set()
    store.close()


def test_attach_observers_keep_decision_and_approval_separate(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer()
    server.start()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_manager_config(),
        client_id="pytest",
        wait_for_decision=False,
    )
    decision = ConsoleDecisionSummaryDispatcher(
        home=tmp_path,
        load_credential_fn=_load_credential_ok,
        upload_fn=lambda *args, **kwargs: "accepted",
    )
    approval = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        upload_fn=lambda *args, **kwargs: "accepted",
    )
    attach_terminal_evidence_observer(manager, decision)
    attach_approval_state_observer(manager, approval)
    assert manager.terminal_evidence_observer == decision.notify_terminal_record
    assert manager.approval_state_observer == approval.request_snapshot
    server.stop()
    store.close()


def test_payload_to_request_body_contains_only_contract_keys():
    payload = _payload(
        pending=(
            ApprovalPendingItem(
                approval_id=derive_approval_id("pending-1"),
                action_family="write",
                target_basename="config.toml",
                opened_at="2026-08-07T09:00:00Z",
            ),
        )
    )
    body = payload_to_request_body(payload)
    assert set(body.keys()) <= {
        "schema_version",
        "snapshot_id",
        "observed_at",
        "pending",
        "resolutions",
        "idempotency_key",
    }
    assert body["pending"][0]["target_basename"] == "config.toml"
    assert SECRET not in json.dumps(body)


def test_payload_to_request_body_rejects_unsafe_basename():
    pending = (
        ApprovalPendingItem(
            approval_id=derive_approval_id("pending-unsafe"),
            action_family="write",
            target_basename="/Users/canary/token.txt",
            opened_at="2026-08-07T09:00:00Z",
        ),
    )
    payload = ApprovalSummaryPayload(
        schema_version="1",
        snapshot_id="ignored",
        observed_at="2026-08-07T09:00:00Z",
        pending=pending,
        resolutions=(),
        idempotency_key=None,
    )
    with pytest.raises(ApprovalSummaryClientError):
        payload_to_request_body(payload)


def test_different_payloads_get_different_snapshot_ids():
    from agentveil_mcp_proxy.console_approval_summary_client import _derive_payload_identity

    observed_at = "2026-08-07T09:00:00Z"
    pending_a = (
        ApprovalPendingItem(
            approval_id=derive_approval_id("pending-a"),
            action_family="write",
            target_basename="config.toml",
            opened_at=observed_at,
        ),
    )
    pending_b = (
        ApprovalPendingItem(
            approval_id=derive_approval_id("pending-b"),
            action_family="write",
            target_basename="README",
            opened_at=observed_at,
        ),
    )
    first, _ = _derive_payload_identity(
        observed_at=observed_at,
        pending=pending_a,
        resolutions=(),
    )
    second, _ = _derive_payload_identity(
        observed_at=observed_at,
        pending=pending_b,
        resolutions=(),
    )
    assert first != second


def test_build_snapshot_uses_expires_at_for_expired_resolution(tmp_path):
    created_at = 1_700_000_000
    expires_at = created_at + 300
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(
        _record(
            "expired-1",
            created_at=created_at,
            metadata=_metadata(basename="config.toml"),
        )
    )
    store.transition(
        "expired-1",
        ApprovalStatus.EXPIRED.value,
        error_class="approval_timeout",
    )
    snapshot = build_approval_summary_snapshot(store)
    assert snapshot is not None
    assert len(snapshot.resolutions) == 1
    from agentveil_mcp_proxy.console_approval_summary_client import _canonical_timestamp

    assert snapshot.resolutions[0].resolved_at == _canonical_timestamp(expires_at)
    assert snapshot.resolutions[0].resolved_at != _canonical_timestamp(created_at)
    store.close()


def test_build_snapshot_excludes_cancelled_without_truthful_resolution_time(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("cancelled-1"))
    store.transition(
        "cancelled-1",
        ApprovalStatus.CANCELLED.value,
        error_class="client_cancelled",
    )
    snapshot = build_approval_summary_snapshot(store)
    assert snapshot is not None
    assert snapshot.resolutions == ()
    store.close()


def test_sync_with_wrong_scope_credential_makes_zero_transport_calls():
    transport = BackendEchoTransport()

    def _wrong_scope(home=None):
        return StoredCredential(token=TOKEN, scope="wrong_scope")

    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_wrong_scope,
        transport=transport,
    )
    assert result == "skipped_unsafe_credential"
    assert transport.calls == []


@pytest.mark.parametrize(
    "content_type",
    [
        "text/plain",
        "application/json; charset=",
        "application/json; charset=latin1",
        None,
    ],
)
def test_bad_response_content_type_is_rejected(content_type):
    transport = FakeTransport([
        lambda body: _json_response(
            200,
            _backend_ack_for_request(body),
            content_type=content_type,
        )
    ])
    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "rejected"


@pytest.mark.parametrize(
    "response_obj",
    [
        {"schema_version": "1", "observed_at": "2026-08-07T09:00:00Z", "status": "accepted"},
        {
            "schema_version": "1",
            "observed_at": "2026-08-07T09:00:00Z",
            "pending_count": True,
            "status": "accepted",
        },
        {
            "schema_version": "1",
            "observed_at": "2026-08-07T09:00:00Z",
            "pending_count": 0,
            "status": "accepted",
            "extra": "field",
        },
    ],
)
def test_malformed_response_objects_are_rejected(response_obj):
    transport = FakeTransport([
        lambda body: _json_response(200, response_obj),
    ])
    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "rejected"


def test_transport_error_returns_unavailable():
    transport = FakeTransport([TransportError()])
    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "unavailable"


def test_dispatcher_queue_full_does_not_raise(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("queue-full-1"))
    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        upload_fn=lambda *args, **kwargs: "accepted",
        queue_capacity=1,
    )
    dispatcher.start()
    dispatcher.request_snapshot()
    dispatcher.request_snapshot()
    dispatcher.stop()
    store.close()


def test_dispatcher_startup_uploads_from_durable_store(tmp_path):
    uploaded: list[ApprovalSummaryPayload] = []
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("startup-pending-1"))
    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        upload_fn=lambda payload, **kwargs: uploaded.append(payload) or "accepted",
    )
    dispatcher.start()
    assert dispatcher.is_active
    dispatcher.request_snapshot()
    assert _wait_until(lambda: len(uploaded) == 1)
    dispatcher.stop()
    assert len(uploaded[0].pending) == 1
    assert uploaded[0].pending[0].target_basename == "config.toml"
    store.close()


def test_dispatcher_uploads_unchanged_state_once_after_success(tmp_path):
    uploaded_ids: list[str] = []
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("dedup-unchanged-1"))

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        uploaded_ids.append(payload.snapshot_id)
        return "accepted"

    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
    )
    dispatcher.start()
    dispatcher.request_snapshot()
    assert _wait_until(lambda: len(uploaded_ids) == 1)
    first_id = uploaded_ids[0]
    dispatcher.request_snapshot()
    time.sleep(0.3)
    assert uploaded_ids == [first_id]
    dispatcher.stop()
    store.close()


def test_dispatcher_retries_unchanged_state_after_failed_upload(tmp_path):
    attempts = {"count": 0}
    uploaded_ids: list[str] = []
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("dedup-retry-1"))

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        attempts["count"] += 1
        if attempts["count"] == 1:
            return "unavailable"
        uploaded_ids.append(payload.snapshot_id)
        return "accepted"

    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
    )
    dispatcher.start()
    dispatcher.request_snapshot()
    assert _wait_until(lambda: attempts["count"] == 1)
    dispatcher.request_snapshot()
    assert _wait_until(lambda: len(uploaded_ids) == 1)
    assert attempts["count"] == 2
    dispatcher.stop()
    store.close()


def test_dispatcher_uploads_changed_state_after_success(tmp_path):
    uploaded: list[tuple[str, int, int]] = []
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("dedup-change-1"))

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        uploaded.append(
            (payload.snapshot_id, len(payload.pending), len(payload.resolutions))
        )
        return "accepted"

    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
    )
    dispatcher.start()
    dispatcher.request_snapshot()
    assert _wait_until(lambda: len(uploaded) == 1)
    assert uploaded[0][1:] == (1, 0)

    store.transition(
        "dedup-change-1",
        ApprovalStatus.DENIED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        user_decision_timestamp=1_700_000_010,
        error_class="user_denied",
    )
    dispatcher.request_snapshot()
    assert _wait_until(lambda: len(uploaded) == 2)
    assert uploaded[1][1:] == (0, 1)
    assert uploaded[0][0] != uploaded[1][0]
    dispatcher.stop()
    store.close()


def test_dispatcher_caches_fingerprint_after_duplicate_response(tmp_path):
    uploaded_ids: list[str] = []
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("dedup-backend-1"))

    def _upload(payload, *, home=None, load_credential_fn=None, transport=None):
        uploaded_ids.append(payload.snapshot_id)
        return "duplicate"

    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        upload_fn=_upload,
    )
    dispatcher.start()
    dispatcher.request_snapshot()
    assert _wait_until(lambda: len(uploaded_ids) == 1)
    dispatcher.request_snapshot()
    time.sleep(0.3)
    assert len(uploaded_ids) == 1
    dispatcher.stop()
    store.close()


def test_dispatcher_worker_exception_is_bounded(tmp_path):
    def _explode(*args, **kwargs):
        raise RuntimeError(SECRET)

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    store.write_pending(_record("worker-exception-1"))
    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=tmp_path,
        snapshot_source=lambda: build_approval_summary_snapshot(store),
        load_credential_fn=_load_credential_ok,
        upload_fn=_explode,
        queue_capacity=4,
    )
    dispatcher.start()
    try:
        dispatcher.request_snapshot()
        time.sleep(0.2)
        assert dispatcher.is_active
    finally:
        dispatcher.stop()
        assert not dispatcher._worker.is_alive()
    store.close()


@pytest.mark.parametrize("status_code", [301, 302, 307, 308])
def test_sync_rejects_redirect_responses(status_code):
    transport = FakeTransport([
        lambda body: _json_response(status_code, _backend_ack_for_request(body))
    ])
    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "unavailable"


def test_sync_rejects_oversized_response_body():
    from agentveil_mcp_proxy.console_approval_summary_client import _MAX_RESPONSE_BYTES

    oversized = b"x" * (_MAX_RESPONSE_BYTES + 1)
    transport = FakeTransport([
        lambda body: RawResponse(
            status=200,
            content_types=("application/json",),
            body=oversized,
        )
    ])
    result = sync_approval_summary(
        _payload(),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "rejected"


def test_failed_console_upload_preserves_durable_local_records(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path)
    try:
        classification, reason = _write_classification()
        outcome = manager.request_approval(classification, reason=reason)
        before = store.get_pending(outcome.request_id)
        assert before is not None
        snapshot = _snapshot_for_store(store)
        transport = FakeTransport([TransportError()])
        result = sync_approval_summary(
            snapshot,
            load_credential_fn=_load_credential_ok,
            transport=transport,
        )
        assert result == "unavailable"
        after = store.get_pending(outcome.request_id)
        assert after is not None
        assert after.status == before.status
        assert after.action_gate_metadata_jcs == before.action_gate_metadata_jcs
    finally:
        lease.close()
        server.stop()
        store.close()


def test_manager_pending_notifies_observer_and_maps_pending_snapshot(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path)
    observed: list[int] = []
    manager.approval_state_observer = lambda: observed.append(len(observed))
    try:
        classification, reason = _write_classification()
        outcome = manager.request_approval(classification, reason=reason)
        assert outcome.status == ApprovalStatus.PENDING.value
        assert len(observed) >= 1
        snapshot = _snapshot_for_store(store)
        assert len(snapshot.pending) == 1
        assert snapshot.pending[0].approval_id == derive_approval_id(outcome.request_id)
        assert snapshot.resolutions == ()
    finally:
        lease.close()
        server.stop()
        store.close()


def test_manager_approve_via_approval_center_notifies_observer(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path)
    observed: list[int] = []
    manager.approval_state_observer = lambda: observed.append(len(observed))
    try:
        classification, reason = _write_classification()
        outcome = manager.request_approval(classification, reason=reason)
        _approve_via_approval_center(server, outcome.request_id)
        assert _wait_until(lambda: len(observed) >= 2)
        snapshot = _snapshot_for_store(store)
        assert snapshot.pending == ()
        assert len(snapshot.resolutions) == 1
        assert snapshot.resolutions[0].status == "approved"
    finally:
        lease.close()
        server.stop()
        store.close()


def test_manager_deny_via_approval_center_notifies_observer(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path)
    observed: list[int] = []
    manager.approval_state_observer = lambda: observed.append(len(observed))
    try:
        classification, reason = _write_classification()
        outcome = manager.request_approval(classification, reason=reason)
        _deny_via_approval_center(server, outcome.request_id)
        assert _wait_until(lambda: len(observed) >= 2)
        snapshot = _snapshot_for_store(store)
        assert snapshot.pending == ()
        assert len(snapshot.resolutions) == 1
        assert snapshot.resolutions[0].status == "denied"
    finally:
        lease.close()
        server.stop()
        store.close()


def test_manager_expire_via_timeout_notifies_observer(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path, approval_timeout_seconds=1)
    observed: list[int] = []
    manager.approval_state_observer = lambda: observed.append(len(observed))
    try:
        classification, reason = _write_classification()
        outcome = manager.request_approval(classification, reason=reason)
        assert _wait_until(
            lambda: store.get_pending(outcome.request_id) is not None
            and store.get_pending(outcome.request_id).status == ApprovalStatus.EXPIRED.value,
            timeout=5.0,
        )
        assert _wait_until(lambda: len(observed) >= 2)
        snapshot = _snapshot_for_store(store)
        assert snapshot.pending == ()
        assert len(snapshot.resolutions) == 1
        assert snapshot.resolutions[0].status == "expired"
    finally:
        lease.close()
        server.stop()
        store.close()


def test_manager_cancel_notifies_observer(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path)
    observed: list[int] = []
    manager.approval_state_observer = lambda: observed.append(len(observed))
    try:
        classification, reason = _write_classification()
        outcome = manager.request_approval(classification, reason=reason)
        cancelled = manager.cancel_approval(outcome.request_id, reason="client_cancelled")
        assert cancelled.status == ApprovalStatus.CANCELLED.value
        assert len(observed) >= 2
        snapshot = _snapshot_for_store(store)
        assert snapshot.pending == ()
        assert snapshot.resolutions == ()
    finally:
        lease.close()
        server.stop()
        store.close()


def test_manager_invalidate_notifies_observer(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path)
    observed: list[int] = []
    manager.approval_state_observer = lambda: observed.append(len(observed))
    try:
        classification, reason = _write_classification()
        outcome = manager.request_approval(classification, reason=reason)
        invalidated = manager.invalidate_approval(
            outcome.request_id,
            reason="generation_changed",
        )
        assert invalidated.status == ApprovalStatus.INVALIDATED.value
        assert len(observed) >= 2
        snapshot = _snapshot_for_store(store)
        assert snapshot.pending == ()
        assert snapshot.resolutions == ()
    finally:
        lease.close()
        server.stop()
        store.close()


def test_manager_approve_then_execution_success_and_error_keep_approved_resolution(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path)
    try:
        classification, reason = _write_classification()
        pending = manager.request_approval(classification, reason=reason)
        _approve_via_approval_center(server, pending.request_id)
        approved = ApprovalOutcome(
            pending.request_id,
            ApprovalStatus.APPROVED.value,
            "user_approved",
        )
        manager.record_execution_result(
            approved,
            {"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
            downstream_tool_call_seen=True,
        )
        executed_snapshot = _snapshot_for_store(store)
        assert executed_snapshot.resolutions[0].status == "approved"

        classification_b, reason_b = _write_classification(path="file:project/README")
        pending_b = manager.request_approval(classification_b, reason=reason_b)
        _approve_via_approval_center(server, pending_b.request_id)
        approved_b = ApprovalOutcome(
            pending_b.request_id,
            ApprovalStatus.APPROVED.value,
            "user_approved",
        )
        manager.record_execution_error(approved_b, error_class="downstream_error")
        error_snapshot = _snapshot_for_store(store)
        approved_rows = [
            item
            for item in error_snapshot.resolutions
            if item.approval_id == derive_approval_id(pending_b.request_id)
        ]
        assert len(approved_rows) == 1
        assert approved_rows[0].status == "approved"
    finally:
        lease.close()
        server.stop()
        store.close()


def test_manager_produced_basename_matches_client_snapshot_contract(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path)
    try:
        classification, reason = _write_classification(path="file:project/config.toml")
        outcome = manager.request_approval(classification, reason=reason)
        record = store.get_pending(outcome.request_id)
        metadata = parse_action_gate_metadata(record)
        assert metadata is not None
        assert metadata.get("target_basename") == "config.toml"
        assert validate_target_basename(metadata.get("target_basename")) == "config.toml"
        snapshot = _snapshot_for_store(store)
        assert snapshot.pending[0].target_basename == "config.toml"
    finally:
        lease.close()
        server.stop()
        store.close()


def test_manager_rejects_secretish_basename_and_snapshot_skips(tmp_path):
    store, server, manager, lease = _setup_manager(tmp_path)
    try:
        classification, reason = _write_classification(path="file:project/my-token.toml")
        outcome = manager.request_approval(classification, reason=reason)
        record = store.get_pending(outcome.request_id)
        metadata = parse_action_gate_metadata(record)
        assert metadata is not None
        assert "target_basename" not in metadata
        assert build_approval_summary_snapshot(store) is None
    finally:
        lease.close()
        server.stop()
        store.close()


def test_privacy_canary_present_locally_absent_from_outbound_surfaces(tmp_path, caplog):
    store, server, manager, lease = _setup_manager(tmp_path)
    transport = BackendEchoTransport()
    try:
        classification, reason = _write_classification()
        outcome = manager.request_approval(classification, reason=reason)
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert CANARY in record.session_id

        snapshot = _snapshot_for_store(store)
        with caplog.at_level(logging.DEBUG):
            result = sync_approval_summary(
                snapshot,
                load_credential_fn=_load_credential_ok,
                transport=transport,
            )
        assert result == "accepted"
        assert len(transport.calls) == 1
        call = transport.calls[0]
        serialized_body = call["body"].decode("utf-8")
        headers_blob = json.dumps(call["headers"])
        assert CANARY not in serialized_body
        assert CANARY not in headers_blob
        assert "Bearer " in headers_blob
        assert CANARY not in caplog.text
        assert CANARY not in repr(snapshot)
        assert CANARY not in json.dumps(payload_to_request_body(snapshot))
        assert SECRET not in serialized_body
        assert outcome.request_id not in serialized_body
        assert "/Users/" not in serialized_body
    finally:
        lease.close()
        server.stop()
        store.close()
