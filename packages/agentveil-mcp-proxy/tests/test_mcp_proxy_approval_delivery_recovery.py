"""Approval Center delivery_status recovery contract (A–I)."""

from __future__ import annotations

import io
import json
import os
import sqlite3
import time
from dataclasses import asdict, fields
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import httpx

from agentveil_mcp_proxy.approval.manager import ApprovalManager
from agentveil_mcp_proxy.approval.persistent import build_manifest_for_server, save_manifest
from agentveil_mcp_proxy.approval.server import ApprovalServer
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.cli import open_approval_center
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.evidence.events_show import build_event_show_entry
from agentveil_mcp_proxy.evidence.observability import (
    APPROVAL_NOT_DELIVERED_USER_MESSAGE,
    approval_center_open_recovery_command,
)
from agentveil_mcp_proxy.evidence.store import (
    DELIVERY_STATUS_DELIVERED,
    DELIVERY_STATUS_NOT_DELIVERED,
    DELIVERY_STATUS_QUEUED,
    DELIVERY_STATUS_VISIBLE,
    EVIDENCE_SCHEMA_VERSION,
    GENESIS_PREV_EVENT_HASH,
    PendingApproval,
    record_hash,
)
from agentveil_mcp_proxy.passthrough import _approval_required_error
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
                "production": "block",  # claim-check: allow fixture fallback classification key.
                "financial": "block",
                "unknown": "approval",
            },
            "approval": {
                "approval_timeout_seconds": approval_timeout_seconds,
                "on_timeout": "deny",
                "ui_open_mode": "browser",
            },
            "policy": {
                "id": "delivery-recovery",
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


def _classification(config: ProxyConfig):
    return ToolCallClassifier(config, server_name="filesystem").classify(
        tool="write_file",
        arguments={"path": "ops/canary.json", "content": "x"},
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
        client_id="cursor:pid:1",
        session_id="session-delivery-recovery-123456",
        cli_out=io.StringIO(),
        browser_open=browser_open,
        wait_for_decision=wait_for_decision,
        notifier=SimpleNamespace(notify=lambda _prompt: None),
    )
    return manager, store, server


def _assert_agent_visible_privacy(serialized: str, *, server: ApprovalServer, home: Path | None = None) -> None:
    assert server.session_token not in serialized
    assert f"/approval/{server.session_token}" not in serialized
    assert "csrf_token" not in serialized
    assert "internal_register_token" not in serialized
    assert server.internal_register_token not in serialized
    assert "approval_url" not in serialized
    if home is not None:
        assert str(home.resolve()) not in serialized


# ---------------------------------------------------------------------------
# A. opener=False → pending + not_delivered + recovery; no hang
# ---------------------------------------------------------------------------


def test_a_opener_false_fail_soft_not_delivered_with_recovery(tmp_path):
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
        assert outcome.delivery_status == DELIVERY_STATUS_NOT_DELIVERED
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.status == ApprovalStatus.PENDING.value
        assert record.delivery_status == DELIVERY_STATUS_NOT_DELIVERED

        mcp = _approval_required_error(
            "call-a",
            reason="local_approval_required",
            approval_outcome=outcome,
        )
        data = mcp["error"]["data"]
        assert data["record_id"] == outcome.request_id
        assert data["delivery_status"] == DELIVERY_STATUS_NOT_DELIVERED
        assert data["recovery_command"] == approval_center_open_recovery_command(outcome.request_id)
        assert "approval-center open --record-id" in data["recovery_command"]
        assert APPROVAL_NOT_DELIVERED_USER_MESSAGE in mcp["error"]["message"]
        assert "did not open automatically" in mcp["error"]["message"]
        serialized = json.dumps(mcp)
        _assert_agent_visible_privacy(serialized, server=server)
        assert opened and outcome.request_id in opened[0]
        # Fail-soft postcondition: status stays pending rather than executed.
        assert record.result_status is None
        assert record.status == ApprovalStatus.PENDING.value
    finally:
        server.stop()
        store.close()


# ---------------------------------------------------------------------------
# B. opener exception → same fail-soft, no hang
# ---------------------------------------------------------------------------


def test_b_opener_exception_fail_soft_without_hang(tmp_path):
    def opener(_url: str) -> bool:
        raise RuntimeError("no display")

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
        assert outcome.delivery_status == DELIVERY_STATUS_NOT_DELIVERED
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.delivery_status == DELIVERY_STATUS_NOT_DELIVERED
        mcp = _approval_required_error(
            "call-b",
            reason="local_approval_required",
            approval_outcome=outcome,
        )
        assert mcp["error"]["data"]["delivery_status"] == DELIVERY_STATUS_NOT_DELIVERED
        assert "recovery_command" in mcp["error"]["data"]
    finally:
        server.stop()
        store.close()


# ---------------------------------------------------------------------------
# C. opener=True → delivered (not not_delivered)
# ---------------------------------------------------------------------------


def test_c_opener_true_marks_delivered(tmp_path):
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
        assert outcome.status == ApprovalStatus.PENDING.value
        assert outcome.delivery_status == DELIVERY_STATUS_DELIVERED
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.delivery_status == DELIVERY_STATUS_DELIVERED
        assert record.delivery_status != DELIVERY_STATUS_NOT_DELIVERED
        mcp = _approval_required_error(
            "call-c",
            reason="local_approval_required",
            approval_outcome=outcome,
        )
        assert mcp["error"]["data"]["delivery_status"] == DELIVERY_STATUS_DELIVERED
        assert "recovery_command" not in mcp["error"]["data"]
        assert opened and "/pending/" in opened[0]
    finally:
        server.stop()
        store.close()


# ---------------------------------------------------------------------------
# D. authenticated GET pending → visible persisted
# ---------------------------------------------------------------------------


def test_d_authenticated_pending_get_marks_visible(tmp_path):
    manager, store, server = _manager(
        tmp_path,
        browser_open=lambda _url: True,
        wait_for_decision=False,
    )
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert store.get_pending(outcome.request_id).delivery_status == DELIVERY_STATUS_DELIVERED
        assert outcome.approval_url is not None
        with httpx.Client() as client:
            response = client.get(outcome.approval_url)
        assert response.status_code == 200
        assert "Approve" in response.text
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.status == ApprovalStatus.PENDING.value
        assert record.delivery_status == DELIVERY_STATUS_VISIBLE
        entry = build_event_show_entry(record)
        assert entry["delivery_status"] == DELIVERY_STATUS_VISIBLE
        assert entry["target_reached"] is False
    finally:
        server.stop()
        store.close()


# ---------------------------------------------------------------------------
# E. invalid/stale GET → visible not set
# ---------------------------------------------------------------------------


def test_e_invalid_and_stale_get_do_not_mark_visible(tmp_path):
    manager, store, server = _manager(
        tmp_path,
        browser_open=lambda _url: True,
        wait_for_decision=False,
    )
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert outcome.approval_url is not None
        before = store.get_pending(outcome.request_id).delivery_status
        assert before == DELIVERY_STATUS_DELIVERED

        wrong = outcome.approval_url.replace(server.session_token, "not-the-real-session-token")
        with httpx.Client(follow_redirects=False) as client:
            forbidden = client.get(wrong)
            assert forbidden.status_code == 403
            missing = client.get(
                f"{server.base_url}/approval/{server.session_token}/pending/does-not-exist"
            )
            assert missing.status_code in (404, 410)
            # List/center and API must not themselves mark visible (no follow to card).
            listing = client.get(server.approval_center_url())
            assert listing.status_code in (200, 302)
            api = client.get(f"{server.approval_center_url()}/api/approvals")
            assert api.status_code == 200

        after_invalid = store.get_pending(outcome.request_id)
        assert after_invalid is not None
        assert after_invalid.delivery_status == DELIVERY_STATUS_DELIVERED
        assert after_invalid.delivery_status != DELIVERY_STATUS_VISIBLE

        # Deny → terminal; subsequent GET must not set visible.
        server.submit_decision(outcome.request_id, "deny", "exact")
        with httpx.Client() as client:
            stale = client.get(outcome.approval_url)
        assert stale.status_code == 410
        terminal = store.get_pending(outcome.request_id)
        assert terminal is not None
        assert terminal.status == ApprovalStatus.DENIED.value
        assert terminal.delivery_status != DELIVERY_STATUS_VISIBLE
    finally:
        server.stop()
        store.close()


# ---------------------------------------------------------------------------
# F. CLI approval-center open --record-id privacy + exact card URL
# ---------------------------------------------------------------------------


def test_f_cli_open_record_id_exact_url_and_privacy(tmp_path):
    home = tmp_path / "avp-home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-token-not-real",
    )
    server.start()
    save_manifest(proxy_dir, build_manifest_for_server(server))
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_config(),
        client_id="cli:open",
        session_id="session-cli-open-123456",
        cli_out=io.StringIO(),
        browser_open=lambda _url: False,
        wait_for_decision=False,
        notifier=SimpleNamespace(notify=lambda _prompt: None),
    )
    out = io.StringIO()
    err = io.StringIO()
    opened: list[str] = []
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        encoded_id = quote(
            outcome.request_id,
            safe="",  # claim-check: allow urllib.parse.quote parameter syntax.
        )
        expected = f"{server.approval_center_url()}/pending/{encoded_id}"

        def opener(url: str) -> bool:
            opened.append(url)
            return True

        rc = open_approval_center(
            home=home,
            record_id=outcome.request_id,
            out=out,
            err=err,
            browser_open=opener,
        )
        assert rc == 0
        assert opened == [expected]
        assert outcome.request_id in opened[0]
        assert "/pending/" in opened[0]
        combined = out.getvalue() + err.getvalue()
        assert server.session_token not in combined
        assert f"/approval/{server.session_token}" not in combined
        assert server.internal_register_token not in combined
        assert "internal_register_token" not in combined
        assert str(home.resolve()) not in combined
        assert "http://" not in combined
        assert expected not in combined
        assert "delivered" in out.getvalue()
        assert store.get_pending(outcome.request_id).delivery_status == DELIVERY_STATUS_DELIVERED

        # Opener failure → nonzero, still no secret leakage.
        fail_out = io.StringIO()
        fail_err = io.StringIO()
        rc_fail = open_approval_center(
            home=home,
            record_id=outcome.request_id,
            out=fail_out,
            err=fail_err,
            browser_open=lambda _url: False,
        )
        assert rc_fail == 1
        fail_text = fail_out.getvalue() + fail_err.getvalue()
        assert server.session_token not in fail_text
        assert str(home.resolve()) not in fail_text
    finally:
        server.stop()
        store.close()


def test_f_cli_open_exception_is_nonzero(tmp_path):
    home = tmp_path / "avp-home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-token-not-real",
    )
    server.start()
    save_manifest(proxy_dir, build_manifest_for_server(server))
    try:
        err = io.StringIO()

        def boom(_url: str) -> bool:
            raise RuntimeError("browser boom")

        rc = open_approval_center(home=home, out=io.StringIO(), err=err, browser_open=boom)
        assert rc == 1
        assert "browser delivery failed" in err.getvalue()
        assert server.session_token not in err.getvalue()
    finally:
        server.stop()
        store.close()


def test_f_cli_open_json_is_bounded_and_private(tmp_path):
    home = tmp_path / "avp-home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-token-not-real",
    )
    server.start()
    save_manifest(proxy_dir, build_manifest_for_server(server))
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_config(),
        client_id="cli:open-json",
        session_id="session-cli-open-json-123456",
        cli_out=io.StringIO(),
        browser_open=lambda _url: False,
        wait_for_decision=False,
        notifier=SimpleNamespace(notify=lambda _prompt: None),
    )
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        out = io.StringIO()
        err = io.StringIO()
        rc = open_approval_center(
            home=home,
            record_id=outcome.request_id,
            out=out,
            err=err,
            browser_open=lambda _url: True,
            output_json=True,
        )
        assert rc == 0
        payload = json.loads(out.getvalue())
        assert payload == {
            "action": "open",
            "delivery_status": DELIVERY_STATUS_DELIVERED,
            "exit_code": 0,
            "ok": True,
            "record_id": outcome.request_id,
            "target": "pending",
        }
        serialized = out.getvalue() + err.getvalue()
        assert server.session_token not in serialized
        assert server.internal_register_token not in serialized
        assert str(home.resolve()) not in serialized
        assert "http://" not in serialized
        assert "/approval/" not in serialized
    finally:
        server.stop()
        store.close()


def test_f_cli_open_fail_closed_without_evidence_or_running_center(tmp_path):
    home = tmp_path / "avp-home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)

    # No manifest / center down.
    rc_down = open_approval_center(
        home=home,
        record_id="missing-record",
        out=io.StringIO(),
        err=io.StringIO(),
        browser_open=lambda _url: True,
        output_json=True,
    )
    assert rc_down == 2

    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-token-not-real",
    )
    server.start()
    save_manifest(proxy_dir, build_manifest_for_server(server))
    try:
        # Running center but missing evidence file for this record path:
        # delete evidence and refuse arbitrary record_id open.
        store.close()
        (proxy_dir / "evidence.sqlite").unlink()
        for suffix in ("-wal", "-shm"):
            path = Path(f"{proxy_dir / 'evidence.sqlite'}{suffix}")
            if path.exists():
                path.unlink()
        out = io.StringIO()
        rc_no_evidence = open_approval_center(
            home=home,
            record_id="any-record-id",
            out=out,
            err=io.StringIO(),
            browser_open=lambda _url: True,
            output_json=True,
        )
        assert rc_no_evidence == 2
        payload = json.loads(out.getvalue())
        assert payload["ok"] is False
        assert payload["reason"] == "evidence store not found"
        assert "http://" not in out.getvalue()
    finally:
        server.stop()


def test_f_cli_open_rejects_stale_manifest_and_terminal_record(tmp_path):
    home = tmp_path / "avp-home"
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-token-not-real",
    )
    server.start()
    manifest = build_manifest_for_server(server)
    # Foreign runtime identity must not be trusted.
    stale = type(manifest)(
        **{
            **manifest.__dict__,
            "runtime_identity": "sha256:" + ("0" * 64),
        }
    )
    save_manifest(proxy_dir, stale)
    try:
        out = io.StringIO()
        rc = open_approval_center(
            home=home,
            record_id="anything",
            out=out,
            err=io.StringIO(),
            browser_open=lambda _url: True,
            output_json=True,
        )
        assert rc == 2
        assert json.loads(out.getvalue())["ok"] is False
    finally:
        server.stop()
        store.close()

    # Fresh healthy center + terminal record.
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = ApprovalServer(
        port=0,
        evidence_store=store,
        internal_register_token="fixture-internal-token-not-real",
    )
    server.start()
    save_manifest(proxy_dir, build_manifest_for_server(server))
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=_config(),
        client_id="cli:terminal",
        session_id="session-cli-terminal-123456",
        cli_out=io.StringIO(),
        browser_open=lambda _url: True,
        wait_for_decision=False,
        notifier=SimpleNamespace(notify=lambda _prompt: None),
    )
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        server.submit_decision(outcome.request_id, "deny", "exact")
        deadline = time.monotonic() + 2.0
        record = store.get_pending(outcome.request_id)
        while (
            record is not None
            and record.status == ApprovalStatus.PENDING.value
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
            record = store.get_pending(outcome.request_id)
        out = io.StringIO()
        rc = open_approval_center(
            home=home,
            record_id=outcome.request_id,
            out=out,
            err=io.StringIO(),
            browser_open=lambda _url: True,
            output_json=True,
        )
        assert rc == 2
        payload = json.loads(out.getvalue())
        assert payload["ok"] is False
        assert payload["reason"] == "record is not pending"
    finally:
        server.stop()
        store.close()


# ---------------------------------------------------------------------------
# G. two pending requests → delivery state isolated
# ---------------------------------------------------------------------------


def test_g_delivery_status_isolated_per_request(tmp_path):
    results: dict[str, bool] = {}

    def opener(url: str) -> bool:
        # First open fails, second succeeds — keyed by which pending id appears.
        delivered = "/pending/" in url and results.get("phase") == "second"
        return delivered

    manager, store, server = _manager(tmp_path, browser_open=opener, wait_for_decision=False)
    try:
        results["phase"] = "first"
        first = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        results["phase"] = "second"
        second = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        assert first.request_id != second.request_id
        r1 = store.get_pending(first.request_id)
        r2 = store.get_pending(second.request_id)
        assert r1 is not None and r2 is not None
        assert r1.delivery_status == DELIVERY_STATUS_NOT_DELIVERED
        assert r2.delivery_status == DELIVERY_STATUS_DELIVERED
        assert r1.delivery_status != r2.delivery_status
    finally:
        server.stop()
        store.close()


# ---------------------------------------------------------------------------
# Extra contract: queued on register; visible does not regress; outcomes intact
# ---------------------------------------------------------------------------


def test_queued_then_delivery_transition_and_approve_semantics(tmp_path):
    manager, store, server = _manager(
        tmp_path,
        browser_open=lambda _url: True,
        wait_for_decision=False,
    )
    try:
        outcome = manager.request_approval(
            _classification(manager.config),
            reason="local_approval_required",
        )
        record = store.get_pending(outcome.request_id)
        assert record is not None
        assert record.delivery_status == DELIVERY_STATUS_DELIVERED
        # visible is terminal for delivery lifecycle; do not regress it.
        store.annotate_delivery_status(
            outcome.request_id,
            delivery_status=DELIVERY_STATUS_VISIBLE,
        )
        store.annotate_delivery_status(
            outcome.request_id,
            delivery_status=DELIVERY_STATUS_NOT_DELIVERED,
        )
        assert store.get_pending(outcome.request_id).delivery_status == DELIVERY_STATUS_VISIBLE

        server.submit_decision(outcome.request_id, "approve", "exact")
        # delivery_status is not a decision; approve still works.
        deadline = time.monotonic() + 2.0
        final = store.get_pending(outcome.request_id)
        while final is not None and final.status == ApprovalStatus.PENDING.value and time.monotonic() < deadline:
            time.sleep(0.02)
            final = store.get_pending(outcome.request_id)
        assert final is not None
        assert final.status == ApprovalStatus.APPROVED.value
        assert final.delivery_status == DELIVERY_STATUS_VISIBLE
    finally:
        server.stop()
        store.close()


def test_recovery_command_is_token_safe():
    cmd = approval_center_open_recovery_command("abc-123")
    assert cmd == "agentveil-mcp-proxy approval-center open --record-id abc-123"
    assert "http" not in cmd
    assert "token" not in cmd.lower()
    assert "/" not in cmd or "--record-id" in cmd


def test_delivery_status_transitions_are_monotonic(tmp_path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    try:
        record = PendingApproval(
            request_id="mono-1",
            session_id="session-mono",
            client_id="test",
            downstream_server="filesystem",
            tool_name="write_file",
            action_class="write",
            risk_class="write",
            resource_hash="sha256:" + "a" * 64,
            payload_hash="sha256:" + "b" * 64,
            policy_id="p",
            policy_rule_id="r",
            policy_context_hash="c" * 64,
            status=ApprovalStatus.PENDING.value,
            created_at=1_700_000_000,
            expires_at=1_700_000_300,
            delivery_status=DELIVERY_STATUS_QUEUED,
        )
        store.write_pending(record)
        store.annotate_delivery_status("mono-1", delivery_status=DELIVERY_STATUS_NOT_DELIVERED)
        assert store.get_pending("mono-1").delivery_status == DELIVERY_STATUS_NOT_DELIVERED
        store.annotate_delivery_status("mono-1", delivery_status=DELIVERY_STATUS_QUEUED)
        assert store.get_pending("mono-1").delivery_status == DELIVERY_STATUS_NOT_DELIVERED
        store.annotate_delivery_status("mono-1", delivery_status=DELIVERY_STATUS_DELIVERED)
        assert store.get_pending("mono-1").delivery_status == DELIVERY_STATUS_DELIVERED
        store.annotate_delivery_status("mono-1", delivery_status=DELIVERY_STATUS_NOT_DELIVERED)
        assert store.get_pending("mono-1").delivery_status == DELIVERY_STATUS_DELIVERED
        store.annotate_delivery_status("mono-1", delivery_status=DELIVERY_STATUS_VISIBLE)
        assert store.get_pending("mono-1").delivery_status == DELIVERY_STATUS_VISIBLE
        store.annotate_delivery_status("mono-1", delivery_status=DELIVERY_STATUS_DELIVERED)
        assert store.get_pending("mono-1").delivery_status == DELIVERY_STATUS_VISIBLE
    finally:
        store.close()


def _v4_hash_fields(record: PendingApproval) -> dict:
    """Return pre-slice v4 hash material without delivery_status."""

    data = asdict(record)
    data.pop("delivery_status", None)
    data.pop("prev_event_hash", None)
    data.pop("record_hash", None)
    return data


def _create_pre_slice_v4_evidence_db(db_path: Path) -> tuple[str, str]:
    """Build a real schema-v4 DB without delivery_status and with a linked chain."""

    base_a = PendingApproval(
        request_id="r1",
        session_id="session-v4",
        client_id="legacy",
        downstream_server="filesystem",
        tool_name="write_file",
        action_class="write",
        risk_class="write",
        resource_hash="sha256:" + "1" * 64,
        payload_hash="sha256:" + "2" * 64,
        policy_id="legacy",
        policy_rule_id="write",
        policy_context_hash="3" * 64,
        status=ApprovalStatus.PENDING.value,
        created_at=10,
        expires_at=310,
        prev_event_hash=GENESIS_PREV_EVENT_HASH,
    )
    hash_a = record_hash(_v4_hash_fields(base_a))
    base_b = PendingApproval(
        request_id="r2",
        session_id="session-v4",
        client_id="legacy",
        downstream_server="filesystem",
        tool_name="write_file",
        action_class="write",
        risk_class="write",
        resource_hash="sha256:" + "4" * 64,
        payload_hash="sha256:" + "5" * 64,
        policy_id="legacy",
        policy_rule_id="write",
        policy_context_hash="6" * 64,
        status=ApprovalStatus.EXECUTED.value,
        created_at=20,
        expires_at=320,
        prev_event_hash=hash_a,
        result_status=ApprovalStatus.EXECUTED.value,
        result_hash="sha256:" + "7" * 64,
    )
    v4_columns = [
        field.name
        for field in fields(PendingApproval)
        if field.name != "delivery_status"
    ]
    integer_columns = {
        "created_at",
        "expires_at",
        "approval_decided_at",
        "granted_scope_expires_at",
        "user_decision_timestamp",
    }
    column_defs = []
    for column in v4_columns:
        if column == "request_id":
            column_defs.append("request_id TEXT PRIMARY KEY")
        elif column in integer_columns:
            column_defs.append(f"{column} INTEGER NULL")
        else:
            column_defs.append(f"{column} TEXT NULL")

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE evidence_schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (4)")
        conn.execute("CREATE TABLE pending_approvals (" + ", ".join(column_defs) + ")")
        for record in (base_a, base_b):
            values = {column: getattr(record, column) for column in v4_columns}
            conn.execute(
                f"INSERT INTO pending_approvals ({', '.join(v4_columns)}) "
                f"VALUES ({', '.join('?' for _ in v4_columns)})",
                [values[column] for column in v4_columns],
            )
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, 0o600)
    return base_a.request_id, base_b.request_id


def test_pre_slice_v4_evidence_db_migrates_to_v5_without_chain_break(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    first_id, second_id = _create_pre_slice_v4_evidence_db(db_path)

    # Reproduce the Product Guard failure mode: open must not raise chain mismatch.
    with ApprovalEvidenceStore(db_path) as store:
        first = store.get_pending(first_id)
        second = store.get_pending(second_id)
        assert first is not None and second is not None
        assert first.request_id == "r1"
        assert second.request_id == "r2"
        assert first.prev_event_hash == GENESIS_PREV_EVENT_HASH
        assert second.prev_event_hash == record_hash(first)
        assert "delivery_status" in asdict(first)
        assert first.delivery_status is None
        assert second.delivery_status is None

    conn = sqlite3.connect(str(db_path))
    try:
        version = conn.execute("SELECT version FROM evidence_schema_version").fetchone()[0]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(pending_approvals)")}
        count = conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
    finally:
        conn.close()
    assert version == EVIDENCE_SCHEMA_VERSION == 5
    assert "delivery_status" in columns
    assert count == 2
