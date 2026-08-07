"""Approval Center delivery + managed lifecycle corrective proofs."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import httpx

from agentveil_mcp_proxy.approval.client import (
    RemoteApprovalServer,
    reconcile_managed_approval_center_for_runtime,
    resolve_approval_server,
)
from agentveil_mcp_proxy.approval.manager import ApprovalManager
from agentveil_mcp_proxy.approval.notification import (
    deliver_approval_browser_url,
    open_approval_url_webbrowser,
)
from agentveil_mcp_proxy.approval.persistent import (
    ApprovalCenterManifest,
    _approval_center_code_fingerprint,
    current_approval_center_runtime_identity,
    load_manifest,
    manifest_runtime_matches_current,
    save_manifest,
    token_hash_for,
)
from agentveil_mcp_proxy.approval.server import (
    build_owner_client_id,
    clear_owner_claim,
    publish_owner_claim,
    ERROR_CLASS_GENERATION_CHANGED,
)
from agentveil_mcp_proxy.console_approval_summary_client import (
    ConsoleApprovalSummaryDispatcher,
    attach_approval_state_observer,
    build_approval_summary_snapshot,
    derive_approval_id,
)
from agentveil_mcp_proxy.console_credentials import CREDENTIAL_SCOPE, StoredCredential
from test_mcp_proxy_approval import _config as _approval_config, _get_csrf, _post_decision, _write_rule
from test_mcp_proxy_persistent_approval_center import _classification, _start_persistent_center
from agentveil_mcp_proxy.approval.server import (
    ApprovalServer,
    ensure_managed_approval_center_running,
    inspect_managed_approval_center,
    prepare_stale_managed_approval_center,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.policy import ProxyConfig


def _config(*, approval_timeout_seconds: int = 300) -> ProxyConfig:
    return ProxyConfig.from_dict(
        {
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
                "id": "delivery",
                "policy_schema_version": 1,
                "default_decision": "approval",
                "default_risk_class": "write",
                "rules": [
                    {
                        "id": "write",
                        "match": {"tool": "write_file"},
                        "decision": "approval",
                        "risk_class": "write",
                    }
                ],
            },
            "downstream": {},
        }
    )


def _manager(tmp_path: Path, *, browser_open, wait_for_decision: bool = True):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-token-not-real",
    )
    server.start()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_config(),
        client_id=f"cursor:pid:{os.getpid()}",
        session_id="session-delivery-123456",
        cli_out=io.StringIO(),
        browser_open=browser_open,
        wait_for_decision=wait_for_decision,
        notifier=SimpleNamespace(notify=lambda _prompt: None),
    )
    return manager, store, server


def _wait_until(predicate, *, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def _managed_production_stack(
    tmp_path: Path,
    *,
    browser_open,
    approval_timeout_seconds: int = 300,
    upload_hook=None,
    wait_for_decision: bool = False,
):
    """Managed center + RemoteApprovalServer + real Console dispatcher wiring."""

    home = tmp_path / "avp-home"
    config = _approval_config(
        policy_rule=_write_rule(),
        approval_timeout_seconds=approval_timeout_seconds,
        ui_open_mode="browser",
    )
    persistent_store, center_server, _center_manager, proxy_dir = _start_persistent_center(
        tmp_path,
        config=config,
    )
    run_store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    run_server = resolve_approval_server(
        proxy_dir,
        evidence_store=run_store,
        fallback_factory=lambda: (_ for _ in ()).throw(
            AssertionError("expected managed persistent Approval Center")
        ),
    )
    instance_token = "lifecycle-managed-inst"
    client_id = build_owner_client_id(
        "github",
        pid=os.getpid(),
        instance_token=instance_token,
    )
    lease = publish_owner_claim(
        proxy_dir / "owner_claims",
        pid=os.getpid(),
        instance_token=instance_token,
        session_id="session-delivery-123456",
    )
    manager = ApprovalManager(
        evidence_store=run_store,
        approval_server=run_server,
        config=config,
        client_id=client_id,
        session_id="session-delivery-123456",
        cli_out=io.StringIO(),
        browser_open=browser_open,
        wait_for_decision=wait_for_decision,
        notifier=SimpleNamespace(notify=lambda _prompt: None),
    )
    uploaded: list = []

    def _upload_fn(payload, **_kwargs):
        if upload_hook is not None:
            upload_hook(payload)
        uploaded.append(payload)
        return "accepted"

    dispatcher = ConsoleApprovalSummaryDispatcher(
        home=home,
        snapshot_source=lambda: build_approval_summary_snapshot(run_store),
        load_credential_fn=lambda home=None: StoredCredential(
            token="fixture-console-token-not-real",
            scope=CREDENTIAL_SCOPE,
        ),
        upload_fn=_upload_fn,
    )
    dispatcher.start()
    attach_approval_state_observer(manager, dispatcher)
    return SimpleNamespace(
        manager=manager,
        run_store=run_store,
        run_server=run_server,
        center_server=center_server,
        persistent_store=persistent_store,
        dispatcher=dispatcher,
        uploaded=uploaded,
        config=config,
        proxy_dir=proxy_dir,
        lease=lease,
    )


def _stop_managed_stack(stack: SimpleNamespace) -> None:
    stack.dispatcher.stop()
    clear_owner_claim(stack.lease)
    stack.run_server.stop()
    stack.center_server.stop()
    stack.run_store.close()
    stack.persistent_store.close()


def _latest_upload_snapshot(stack: SimpleNamespace):
    assert stack.uploaded, "expected at least one Console snapshot upload"
    return stack.uploaded[-1]


def _write_classification(config: ProxyConfig, *, path: str):
    return ToolCallClassifier(config, server_name="filesystem").classify(
        tool="write_file",
        arguments={"path": path, "content": "x"},
    )


def test_product_browser_delivery_pending_get_is_actionable_before_operator_action(tmp_path):
    """Real browser_open on managed center must GET HTTP 200 Approve/Deny before decision."""

    browser_get_statuses: list[int] = []

    def browser_open(url: str) -> bool:
        with httpx.Client() as client:
            response = client.get(url)
            browser_get_statuses.append(response.status_code)
            assert "Approve" in response.text
            assert "Deny" in response.text
        return True

    stack = _managed_production_stack(tmp_path, browser_open=browser_open)
    try:
        outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/pending-browser.json"),
            reason="local_approval_required",
        )
        assert outcome.status == ApprovalStatus.PENDING.value
        assert browser_get_statuses == [200]
        assert _wait_until(lambda: bool(stack.uploaded))
        snapshot = _latest_upload_snapshot(stack)
        assert len(snapshot.pending) == 1
        assert snapshot.pending[0].approval_id == derive_approval_id(outcome.request_id)
        assert snapshot.resolutions == ()
        assert stack.center_server.prompt_for(outcome.request_id) is not None
    finally:
        _stop_managed_stack(stack)


def test_first_console_upload_get_of_product_pending_url_is_actionable(tmp_path):
    """C7L-001 boundary: managed dispatcher GET returns 200 on the product URL."""

    upload_get_statuses: list[int] = []
    context: dict = {}

    def _get_product_url_at_upload(payload) -> None:
        if not payload.pending or "stack" not in context:
            return
        stack = context["stack"]
        for record in stack.run_store.list_records():
            if derive_approval_id(record.request_id) != payload.pending[0].approval_id:
                continue
            url = stack.run_server.approval_url(record.request_id)
            with httpx.Client() as client:
                response = client.get(url)
                upload_get_statuses.append(response.status_code)
                if response.status_code == 200:
                    assert "Approve" in response.text
                    assert "Deny" in response.text
            return

    stack = _managed_production_stack(
        tmp_path,
        browser_open=lambda _url: True,
        upload_hook=_get_product_url_at_upload,
    )
    context["stack"] = stack
    try:
        outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/upload-race.json"),
            reason="local_approval_required",
        )
        assert outcome.status == ApprovalStatus.PENDING.value
        assert _wait_until(lambda: bool(upload_get_statuses))
        assert upload_get_statuses == [200]
        assert outcome.approval_url == stack.run_server.approval_url(outcome.request_id)
    finally:
        _stop_managed_stack(stack)


def test_managed_center_denial_uploads_terminal_snapshot(tmp_path):
    """A remote Deny persisted before polling still notifies Console state."""

    def browser_open(url: str) -> bool:
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            response = _post_decision(
                client,
                url,
                decision="deny",
                csrf=csrf,
            )
            assert response.status_code == 200
        return True

    stack = _managed_production_stack(
        tmp_path,
        browser_open=browser_open,
        wait_for_decision=True,
    )
    try:
        outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/remote-deny.json"),
            reason="local_approval_required",
        )
        assert outcome.status == ApprovalStatus.DENIED.value
        assert _wait_until(
            lambda: bool(stack.uploaded)
            and stack.uploaded[-1].pending == ()
            and any(
                item.status == "denied"
                for item in stack.uploaded[-1].resolutions
            )
        )
    finally:
        _stop_managed_stack(stack)


def test_early_observer_get_of_product_pending_url_is_not_actionable(tmp_path, monkeypatch):
    """C7L-001 base reproducer: notify after write_pending probes unregistered product URL."""

    sync_get_statuses: list[int] = []
    stack = _managed_production_stack(tmp_path, browser_open=lambda _url: True)
    try:

        def _sync_observer() -> None:
            snapshot = build_approval_summary_snapshot(stack.run_store)
            if snapshot is None or not snapshot.pending:
                return
            for record in stack.run_store.list_records():
                if derive_approval_id(record.request_id) != snapshot.pending[0].approval_id:
                    continue
                url = stack.run_server.approval_url(record.request_id)
                with httpx.Client() as client:
                    sync_get_statuses.append(client.get(url).status_code)
                return

        stack.manager.approval_state_observer = _sync_observer
        original_write = stack.run_store.write_pending

        def _write_pending_with_early_notify(record):
            outcome = original_write(record)
            stack.manager._notify_approval_state()
            return outcome

        monkeypatch.setattr(stack.run_store, "write_pending", _write_pending_with_early_notify)

        outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/base-race.json"),
            reason="local_approval_required",
        )
        assert outcome.status == ApprovalStatus.PENDING.value
        assert sync_get_statuses[0] == 404
        assert sync_get_statuses[-1] == 200
    finally:
        _stop_managed_stack(stack)


def test_managed_approval_console_lifecycle_matrix(tmp_path):
    """Managed pending→terminal matrix with browser delivery and snapshots."""

    browser_get_statuses: list[int] = []
    approve_next_browser_delivery = False

    def browser_open(url: str) -> bool:
        nonlocal approve_next_browser_delivery
        with httpx.Client() as client:
            response = client.get(url)
            browser_get_statuses.append(response.status_code)
            if approve_next_browser_delivery:
                csrf = _get_csrf(client, url)
                assert (
                    _post_decision(client, url, decision="approve", csrf=csrf).status_code
                    == 200
                )
                approve_next_browser_delivery = False
        return True

    stack = _managed_production_stack(
        tmp_path,
        browser_open=browser_open,
        approval_timeout_seconds=2,
    )
    try:
        pending_outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/pending.json"),
            reason="local_approval_required",
        )
        assert pending_outcome.status == ApprovalStatus.PENDING.value
        assert browser_get_statuses[-1] == 200
        assert _wait_until(lambda: bool(stack.uploaded))
        pending_snapshot = build_approval_summary_snapshot(stack.run_store)
        assert pending_snapshot is not None
        assert len(pending_snapshot.pending) == 1
        assert pending_snapshot.resolutions == ()

        with httpx.Client() as client:
            url = pending_outcome.approval_url
            assert url is not None
            csrf = _get_csrf(client, url)
            assert _post_decision(client, url, decision="approve", csrf=csrf).status_code == 200
        assert _wait_until(
            lambda: stack.run_store.get_pending(pending_outcome.request_id) is not None
            and stack.run_store.get_pending(pending_outcome.request_id).status
            == ApprovalStatus.APPROVED.value
        )
        approved_snapshot = build_approval_summary_snapshot(stack.run_store)
        assert approved_snapshot is not None
        assert approved_snapshot.pending == ()
        assert any(item.status == "approved" for item in approved_snapshot.resolutions)

        deny_outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/deny.json"),
            reason="local_approval_required",
        )
        assert browser_get_statuses[-1] == 200
        with httpx.Client() as client:
            url = deny_outcome.approval_url
            assert url is not None
            csrf = _get_csrf(client, url)
            assert _post_decision(client, url, decision="deny", csrf=csrf).status_code == 200
        assert _wait_until(
            lambda: stack.run_store.get_pending(deny_outcome.request_id) is not None
            and stack.run_store.get_pending(deny_outcome.request_id).status
            == ApprovalStatus.DENIED.value
        )
        denied_snapshot = build_approval_summary_snapshot(stack.run_store)
        assert denied_snapshot is not None
        assert any(item.status == "denied" for item in denied_snapshot.resolutions)

        expire_outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/expire.json"),
            reason="local_approval_required",
        )
        assert browser_get_statuses[-1] == 200
        assert _wait_until(
            lambda: stack.run_store.get_pending(expire_outcome.request_id) is not None
            and stack.run_store.get_pending(expire_outcome.request_id).status
            == ApprovalStatus.EXPIRED.value,
            timeout=5.0,
        )
        expired_snapshot = build_approval_summary_snapshot(stack.run_store)
        assert expired_snapshot is not None
        assert any(item.status == "expired" for item in expired_snapshot.resolutions)

        cancel_outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/cancel.json"),
            reason="local_approval_required",
        )
        assert browser_get_statuses[-1] == 200
        cancelled = stack.manager.cancel_approval(
            cancel_outcome.request_id,
            reason="client_cancelled",
        )
        assert cancelled.status == ApprovalStatus.CANCELLED.value
        cancelled_snapshot = build_approval_summary_snapshot(stack.run_store)
        assert cancelled_snapshot is not None
        assert stack.run_store.get_pending(cancel_outcome.request_id).status == (
            ApprovalStatus.CANCELLED.value
        )
        assert not any(
            item.approval_id == derive_approval_id(cancel_outcome.request_id)
            for item in cancelled_snapshot.resolutions
        )

        stack.manager.note_downstream_generation(1)
        invalidate_outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/invalidate.json"),
            reason="local_approval_required",
            downstream_generation=0,
        )
        assert invalidate_outcome.status == ApprovalStatus.INVALIDATED.value
        assert invalidate_outcome.reason == ERROR_CLASS_GENERATION_CHANGED
        invalidated_snapshot = build_approval_summary_snapshot(stack.run_store)
        assert invalidated_snapshot is not None
        assert not any(
            item.approval_id == derive_approval_id(invalidate_outcome.request_id)
            for item in invalidated_snapshot.resolutions
        )
        with httpx.Client() as client:
            stale = client.get(stack.center_server.approval_url(invalidate_outcome.request_id))
        assert stale.status_code == 410

        stack.manager.wait_for_decision = True
        approve_next_browser_delivery = True
        block_outcome = stack.manager.request_approval(
            _write_classification(stack.config, path="ops/block.json"),
            reason="local_approval_required",
        )
        assert block_outcome.status == ApprovalStatus.APPROVED.value
        assert browser_get_statuses[-1] == 200
        uploads_before_block = len(stack.uploaded)
        stack.manager.record_execution_result(
            block_outcome,
            {
                "jsonrpc": "2.0",
                "id": "terminal-call",
                "error": {"code": -32000, "message": "bounded downstream failure"},
            },
            downstream_tool_call_seen=True,
        )
        assert _wait_until(lambda: len(stack.uploaded) > uploads_before_block)
        blocked_record = stack.run_store.get_pending(block_outcome.request_id)
        assert blocked_record is not None
        assert blocked_record.status == ApprovalStatus.BLOCKED.value  # claim-check: allow negative lifecycle enum assertion
        blocked_snapshot = build_approval_summary_snapshot(stack.run_store)
        assert blocked_snapshot is not None
        assert any(
            item.approval_id == derive_approval_id(block_outcome.request_id)
            and item.status == "resolved"
            for item in blocked_snapshot.resolutions
        )
    finally:
        _stop_managed_stack(stack)


def test_browser_opener_false_is_not_success_and_retries():
    calls: list[str] = []

    def opener(url: str) -> bool:
        calls.append(url)
        return False

    first = open_approval_url_webbrowser("http://127.0.0.1:9/approval/x", opener=opener)
    second = open_approval_url_webbrowser("http://127.0.0.1:9/approval/y", opener=opener)
    assert first.delivered is False
    assert second.delivered is False
    assert calls == [
        "http://127.0.0.1:9/approval/x",
        "http://127.0.0.1:9/approval/y",
    ]


def test_browser_opener_exception_is_not_success():
    def opener(_url: str) -> bool:
        raise RuntimeError("no display")

    result = open_approval_url_webbrowser("http://127.0.0.1:9/approval/x", opener=opener)
    assert result.attempted is True
    assert result.delivered is False


@pytest.mark.allow_approval_browser_delivery
def test_macos_native_fallback_used_when_webbrowser_fails(monkeypatch):
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.notification.shutil.which",
        lambda name: "/usr/bin/open" if name == "open" else None,
    )
    runs: list[list[str]] = []

    def runner(args, **_kwargs):
        runs.append(list(args))
        return SimpleNamespace(returncode=0)

    result = deliver_approval_browser_url(
        "http://127.0.0.1:9/approval/token",
        webbrowser_opener=lambda _url: False,
        native_runner=runner,
        platform="darwin",
    )
    assert result.delivered is True
    assert result.channel == "macos-open"
    assert runs == [["/usr/bin/open", "http://127.0.0.1:9/approval/token"]]


def test_failed_browser_delivery_returns_approval_required_without_full_timeout(tmp_path):
    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return False

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=True)
    try:
        started = time.monotonic()
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        elapsed = time.monotonic() - started
        assert elapsed < 5.0
        assert outcome.status == ApprovalStatus.PENDING.value
        assert outcome.approval_url is not None
        assert outcome.approval_url.startswith(f"http://{server.host}:{server.port}/")
        assert outcome.delivery_status == "not_delivered"
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.status == ApprovalStatus.PENDING.value
        assert record.delivery_status == "not_delivered"
        assert outcome.request_id not in manager._browser_opened_request_ids
        outcome2 = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert outcome2.status == ApprovalStatus.PENDING.value
        assert len(opened) >= 2
        assert outcome.request_id in opened[0]
        assert any(outcome2.request_id in url for url in opened)
        assert outcome2.request_id not in manager._browser_opened_request_ids
    finally:
        server.stop()
        store.close()


def test_per_request_browser_opens_distinct_pending_cards(tmp_path):
    """First and second pending approvals each open their own card URL."""

    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return True

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=False)
    try:
        first = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        second = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert first.request_id != second.request_id
        assert len(opened) == 2
        assert opened[0] == server.approval_url(first.request_id)
        assert opened[1] == server.approval_url(second.request_id)
        assert first.request_id in opened[0]
        assert second.request_id in opened[1]
        assert opened[0] != opened[1]
        assert "/pending/" in opened[0]
        assert "/pending/" in opened[1]
        assert server.approval_center_url() not in opened
        assert first.request_id in manager._browser_opened_request_ids
        assert second.request_id in manager._browser_opened_request_ids
        assert store.get_pending(first.request_id).delivery_status == "delivered"
        assert store.get_pending(second.request_id).delivery_status == "delivered"
    finally:
        server.stop()
        store.close()


def test_same_request_id_does_not_reopen_browser_after_successful_delivery(tmp_path):
    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return True

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=False)
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert len(opened) == 1
        again = manager._maybe_open_approval_browser(
            request_id=outcome.request_id,
            url=server.approval_url(outcome.request_id),
        )
        assert again is True
        assert len(opened) == 1
    finally:
        server.stop()
        store.close()


def test_non_tty_fallback_omits_session_token(tmp_path):
    opened: list[str] = []
    cli = io.StringIO()
    manager, store, server = _manager(
        tmp_path,
        browser_open=lambda url: opened.append(url) or True,
        wait_for_decision=False,
    )
    manager.cli_out = cli
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
            client_request_id="cli-1",
        )
        text = cli.getvalue()
        assert server.session_token not in text
        assert "session token omitted" in text
        assert outcome.approval_url is not None
        assert server.session_token in outcome.approval_url
        assert server.session_token in opened[0]
    finally:
        server.stop()
        store.close()


def test_successful_browser_delivery_keeps_synchronous_wait(tmp_path):
    """Truthy browser delivery must keep the synchronous wait path."""

    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return True

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=True)
    try:
        def approve_when_pending() -> None:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                rows = [
                    row
                    for row in store.list_records()
                    if row.status == ApprovalStatus.PENDING.value
                ]
                if rows:
                    server.submit_decision(rows[-1].request_id, "approve", "exact")
                    return
                time.sleep(0.02)

        threading.Thread(target=approve_when_pending, daemon=True).start()
        started = time.monotonic()
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        elapsed = time.monotonic() - started
        assert outcome.status == ApprovalStatus.APPROVED.value
        assert elapsed < 5.0
        assert outcome.request_id in manager._browser_opened_request_ids
        assert len(opened) == 1
        assert outcome.request_id in opened[0]
        assert "/pending/" in opened[0]
        assert opened[0] == server.approval_url(outcome.request_id)
    finally:
        server.stop()
        store.close()


def test_explicit_deny_is_user_denied_not_timeout(tmp_path):
    manager, store, server = _manager(
        tmp_path,
        browser_open=lambda _url: True,
        wait_for_decision=True,
    )
    try:
        def deny_when_pending() -> None:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                rows = [
                    row
                    for row in store.list_records()
                    if row.status == ApprovalStatus.PENDING.value
                ]
                if rows:
                    server.submit_decision(rows[-1].request_id, "deny", "exact")
                    return
                time.sleep(0.02)

        threading.Thread(target=deny_when_pending, daemon=True).start()
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert outcome.status == ApprovalStatus.DENIED.value
        assert outcome.reason == "user_denied"
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.status == ApprovalStatus.DENIED.value
        assert record.error_class != "approval_timeout"
    finally:
        server.stop()
        store.close()


def test_stale_foreign_runtime_manifest_is_not_reused(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    os.chmod(proxy_dir, 0o700)
    token = "fixture-session-token-not-real"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=9,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="fixture-internal-token-not-real",
            pid=os.getpid(),
            started_at=int(time.time()),
            runtime_identity="sha256:" + ("f" * 64),
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: True,
    )
    status = inspect_managed_approval_center(home)
    assert status.state == "stale"
    assert not manifest_runtime_matches_current(load_manifest(proxy_dir))


def test_matching_runtime_manifest_is_reused(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    os.chmod(proxy_dir, 0o700)
    token = "fixture-session-token-not-real"
    identity = current_approval_center_runtime_identity()
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=9,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="fixture-internal-token-not-real",
            pid=os.getpid(),
            started_at=int(time.time()),
            runtime_identity=identity,
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: True,
    )
    status = inspect_managed_approval_center(home)
    assert status.state == "running"
    assert manifest_runtime_matches_current(load_manifest(proxy_dir))


def test_runtime_identity_changes_when_version_or_code_drifts(monkeypatch):
    """Same interpreter/package root must still diverge after in-place upgrade."""

    baseline = current_approval_center_runtime_identity()
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent._package_version_token",
        lambda: "9.9.9-fixture-not-real",
    )
    version_drifted = current_approval_center_runtime_identity()
    assert version_drifted != baseline
    assert version_drifted.startswith("sha256:")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent._package_version_token",
        lambda: "0.0.0-fixture",
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent._approval_center_code_fingerprint",
        lambda _root: "a" * 64,
    )
    code_drifted = current_approval_center_runtime_identity()
    assert code_drifted != baseline
    assert code_drifted != version_drifted
    assert code_drifted.startswith("sha256:")
    assert len(code_drifted) == len("sha256:") + 64
    assert not any(marker in code_drifted for marker in ("/", "\\", "Users", "home"))


def test_runtime_fingerprint_changes_when_evidence_dependency_drifts(tmp_path):
    """A detached center must not survive an in-place evidence contract update."""

    package_root = tmp_path / "agentveil_mcp_proxy"
    approval = package_root / "approval"
    evidence = package_root / "evidence"
    approval.mkdir(parents=True)
    evidence.mkdir(parents=True)
    (approval / "server.py").write_text("SERVER = 1\n", encoding="utf-8")
    store = evidence / "store.py"
    store.write_text("SCHEMA = 5\n", encoding="utf-8")

    before = _approval_center_code_fingerprint(package_root)
    store.write_text("SCHEMA = 6\n", encoding="utf-8")
    after = _approval_center_code_fingerprint(package_root)

    assert before != after


def test_lifecycle_lock_serializes_concurrent_processes(tmp_path):
    home = tmp_path / "home"
    (home / "mcp-proxy").mkdir(parents=True)
    os.chmod(home / "mcp-proxy", 0o700)
    log_path = tmp_path / "lock-log.txt"
    log_path.write_text("", encoding="utf-8")
    worker = tmp_path / "lock_worker.py"
    worker.write_text(
        """
import sys
import time
from pathlib import Path

from agentveil_mcp_proxy.approval.server import _ManagedCenterLifecycleLock

home = Path(sys.argv[1])
log_path = Path(sys.argv[2])
slot = sys.argv[3]
hold_seconds = float(sys.argv[4])

with _ManagedCenterLifecycleLock(home, timeout_seconds=10.0):
    previous = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    log_path.write_text(previous + f"enter-{slot}\\n", encoding="utf-8")
    time.sleep(hold_seconds)
    previous = log_path.read_text(encoding="utf-8")
    log_path.write_text(previous + f"exit-{slot}\\n", encoding="utf-8")
""",
        encoding="utf-8",
    )

    command = [sys.executable, str(worker), str(home), str(log_path)]
    proc_a = subprocess.Popen([*command, "a", "0.4"])
    proc_b = subprocess.Popen([*command, "b", "0.4"])
    assert proc_a.wait(timeout=15) == 0
    assert proc_b.wait(timeout=15) == 0

    log = log_path.read_text(encoding="utf-8").splitlines()
    assert len(log) == 4
    assert log[0].startswith("enter-")
    assert log[1].startswith("exit-")
    assert log[2].startswith("enter-")
    assert log[3].startswith("exit-")
    lock_path = home / "mcp-proxy" / "approval-center.lifecycle.lock"
    assert lock_path.exists()


def test_stale_lifecycle_lock_recovers(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    os.chmod(proxy_dir, 0o700)
    lock_path = proxy_dir / "approval-center.lifecycle.lock"
    lock_path.write_text("99999999\n", encoding="utf-8")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.persistent.manifest_is_reachable",
        lambda _manifest: True,
    )

    spawned = {"count": 0}

    def spawn():
        spawned["count"] += 1
        token = "fixture-session-token-not-real"
        save_manifest(
            proxy_dir,
            ApprovalCenterManifest(
                schema_version=2,
                host="127.0.0.1",
                port=9,
                session_token=token,
                token_hash=token_hash_for(token),
                internal_register_token="fixture-internal-token-not-real",
                pid=os.getpid(),
                started_at=int(time.time()),
                runtime_identity=current_approval_center_runtime_identity(),
            ),
        )
        return SimpleNamespace(poll=lambda: None)

    def wait_for_running(home_path: Path, _deadline: float):
        return inspect_managed_approval_center(home_path)

    result = ensure_managed_approval_center_running(
        home=home,
        spawn=spawn,
        wait_for_running=wait_for_running,
    )
    assert result.started is True
    assert spawned["count"] == 1
    assert lock_path.exists()


def test_runtime_mismatch_reconcile_avoids_ephemeral_fallback(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    os.chmod(proxy_dir, 0o700)
    token = "fixture-session-token-not-real"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=9,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="fixture-internal-token-not-real",
            pid=99999999,
            started_at=int(time.time()),
            runtime_identity="sha256:" + ("f" * 64),
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
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    held_servers: list[ApprovalServer] = []

    def fake_spawn(**_kwargs):
        replacement = ApprovalServer(
            port=0,
            evidence_store=store,
            internal_register_token="fixture-internal-token-not-real",
        )
        replacement.start()
        save_manifest(
            proxy_dir,
            ApprovalCenterManifest(
                schema_version=2,
                host=replacement.host,
                port=replacement.port,
                session_token=replacement.session_token,
                token_hash=token_hash_for(replacement.session_token),
                internal_register_token=replacement.internal_register_token,
                pid=os.getpid(),
                started_at=int(time.time()),
                runtime_identity=current_approval_center_runtime_identity(),
            ),
        )
        held_servers.append(replacement)
        return SimpleNamespace(poll=lambda: None)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.client.spawn_managed_approval_center_process",
        fake_spawn,
    )

    fallback_calls = 0

    def fallback_factory() -> ApprovalServer:
        nonlocal fallback_calls
        fallback_calls += 1
        server = ApprovalServer(
            port=0,
            evidence_store=store,
            internal_register_token="fixture-internal-token-not-real",
        )
        server.start()
        held_servers.append(server)
        return server

    without_reconcile = resolve_approval_server(
        proxy_dir,
        evidence_store=store,
        fallback_factory=fallback_factory,
    )
    assert fallback_calls == 1
    assert isinstance(without_reconcile, ApprovalServer)
    assert not isinstance(without_reconcile, RemoteApprovalServer)
    without_reconcile.stop()

    fallback_calls = 0
    reconcile_managed_approval_center_for_runtime(
        home=home,
        proxy_command=sys.executable,
    )
    resolved = resolve_approval_server(
        proxy_dir,
        evidence_store=store,
        fallback_factory=fallback_factory,
    )
    assert fallback_calls == 0
    assert isinstance(resolved, RemoteApprovalServer)
    assert manifest_runtime_matches_current(load_manifest(proxy_dir))
    resolved.stop()
    for server in held_servers:
        if server is not resolved:
            server.stop()
    store.close()


def test_fail_soft_response_excludes_sensitive_fields(tmp_path):
    opened: list[str] = []

    def opener(url: str) -> bool:
        opened.append(url)
        return False

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=True)
    other_url = server.approval_url("other-request-id")
    secret_internal = server.internal_register_token
    assert secret_internal
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert outcome.approval_url is not None
        # Internal outcome may retain the operator URL for browser/TTY delivery.
        assert server.session_token in outcome.approval_url
        from agentveil_mcp_proxy.passthrough import _approval_required_error

        mcp_response = _approval_required_error(
            "call-1",
            reason="local_approval_required",
            approval_outcome=outcome,
        )
        serialized = json.dumps(mcp_response)
        assert "approval_url" not in mcp_response["error"]["data"]
        assert mcp_response["error"]["data"]["delivery_status"] == "not_delivered"
        assert "recovery_command" in mcp_response["error"]["data"]
        assert "approval-center open --record-id" in mcp_response["error"]["data"]["recovery_command"]
        assert server.session_token not in serialized
        assert f"/approval/{server.session_token}" not in serialized
        assert "csrf_token" not in serialized
        assert secret_internal not in serialized
        assert other_url not in serialized
        assert "internal_register_token" not in serialized
        assert opened
        assert server.session_token in opened[0]
        assert outcome.request_id in opened[0]
    finally:
        server.stop()
        store.close()


def test_unowned_pid_not_terminated_on_prepare(tmp_path, monkeypatch):
    home = tmp_path / "home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    os.chmod(proxy_dir, 0o700)
    foreign_pid = os.getpid()
    token = "fixture-session-token-not-real"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=9,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="fixture-internal-token-not-real",
            pid=foreign_pid,
            started_at=int(time.time()),
            runtime_identity="sha256:" + ("e" * 64),
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_cmdline_owns_pid",
        lambda _home, _pid: False,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.managed_center_owns_pid",
        lambda _home, _pid: False,
    )

    def forbid_terminate(*_args, **_kwargs):
        raise AssertionError("must not terminate unowned pid")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.terminate_managed_approval_center_pid",
        forbid_terminate,
    )
    prepared = prepare_stale_managed_approval_center(home)
    assert prepared["prepared"] is True
    assert prepared["stopped"] is False
    assert load_manifest(proxy_dir) is None
    assert os.getpid() == foreign_pid
