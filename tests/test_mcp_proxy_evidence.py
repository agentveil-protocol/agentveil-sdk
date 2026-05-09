"""P7a tests for durable approval/evidence storage."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time

import pytest

from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceCapacityError,
    ApprovalEvidenceDuplicateError,
    ApprovalEvidenceSchemaError,
    ApprovalEvidenceStore,
    ApprovalEvidenceTransitionError,
    ApprovalStatus,
    PendingApproval,
)


PAYLOAD_HASH = "sha256:" + "a" * 64
RESOURCE_HASH = "sha256:" + "b" * 64
POLICY_CONTEXT_HASH = "c" * 64
DECISION_RECEIPT_SHA256 = "d" * 64
APPROVAL_TOKEN_HASH = "sha256:" + "e" * 64
RESULT_HASH = "sha256:" + "f" * 64
SECRET = "SECRET_PAYLOAD_TOKEN"


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _record(
    request_id: str = "req-1",
    *,
    created_at: int = 1_700_000_000,
    expires_at: int | None = None,
    status: str = ApprovalStatus.PENDING.value,
    payload_hash: str = PAYLOAD_HASH,
    resource_hash: str | None = RESOURCE_HASH,
) -> PendingApproval:
    return PendingApproval(
        request_id=request_id,
        session_id="session-1",
        client_id="cursor:session-7",
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        action_class="write",
        risk_class="write",
        resource_hash=resource_hash,
        payload_hash=payload_hash,
        policy_id="github-default",
        policy_rule_id="rule-write",
        policy_context_hash=POLICY_CONTEXT_HASH,
        status=status,
        created_at=created_at,
        expires_at=created_at + 300 if expires_at is None else expires_at,
    )


def _store(tmp_path: Path, *, max_records: int = 10_000) -> ApprovalEvidenceStore:
    return ApprovalEvidenceStore(tmp_path / "evidence.sqlite", max_records=max_records)


def _dump_db_text(db_path: Path) -> str:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM pending_approvals").fetchall()
        return json.dumps([dict(row) for row in rows], sort_keys=True)
    finally:
        conn.close()


def test_write_pending_creates_durable_record_with_all_fields(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    record = _record("req-all")
    record = PendingApproval(
        **{
            **asdict(record),
            "decision_audit_id": "audit-1",
            "decision_receipt_sha256": DECISION_RECEIPT_SHA256,
        }
    )

    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(record)
        fetched = store.get_pending("req-all")

    assert fetched == record

    with ApprovalEvidenceStore(db_path) as reopened:
        assert reopened.get_pending("req-all") == record
        assert reopened.list_pending() == [record]


def test_write_pending_rejects_duplicate_request_id(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-dup"))

        with pytest.raises(ApprovalEvidenceDuplicateError):
            store.write_pending(_record("req-dup"))


def test_write_pending_is_durable_before_return(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    script_path = tmp_path / "write_and_die.py"
    record_json = json.dumps(asdict(_record("req-durable")))
    repo_root = Path(__file__).resolve().parents[1]
    script_path.write_text(
        "\n".join(
            [
                "import json, os, signal",
                "from pathlib import Path",
                "from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, PendingApproval",
                f"db_path = Path({str(db_path)!r})",
                f"record = PendingApproval(**json.loads({record_json!r}))",
                "store = ApprovalEvidenceStore(db_path)",
                "store.write_pending(record)",
                "if hasattr(signal, 'SIGKILL'):",
                "    os.kill(os.getpid(), signal.SIGKILL)",
                "os._exit(137)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{repo_root}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run([sys.executable, str(script_path)], env=env, check=False)

    assert result.returncode != 0
    with ApprovalEvidenceStore(db_path) as store:
        recovered = store.get_pending("req-durable")
    assert recovered is not None
    assert recovered.payload_hash == PAYLOAD_HASH
    assert recovered.status == ApprovalStatus.PENDING.value


def test_write_pending_does_not_store_raw_payload_args_or_secrets(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    raw_context = {
        "arguments": {"token": SECRET, "path": "/private/repo"},
        "prompt": "summarize this private document",
        "output": "private downstream output",
        "source_code": "print('do not persist')",
    }

    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(_record("req-private"))

    rendered = _dump_db_text(db_path)
    assert SECRET not in rendered
    assert "private/repo" not in rendered
    assert raw_context["prompt"] not in rendered
    assert raw_context["output"] not in rendered
    assert raw_context["source_code"] not in rendered


def test_transition_pending_to_approved_atomically_records_timestamp_and_token_hash(tmp_path):
    before = int(time.time())
    with _store(tmp_path) as store:
        store.write_pending(_record("req-approve"))
        updated = store.transition(
            "req-approve",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
        )

    assert updated.status == ApprovalStatus.APPROVED.value
    assert updated.approval_token_hash == APPROVAL_TOKEN_HASH
    assert updated.approval_decided_by == "local-user"
    assert updated.approval_decided_at is not None
    assert updated.approval_decided_at >= before


def test_transition_pending_to_denied_records_decision(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-deny"))
        updated = store.transition(
            "req-deny",
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            error_class="user_denied",
        )

    assert updated.status == ApprovalStatus.DENIED.value
    assert updated.error_class == "user_denied"
    assert updated.approval_token_hash == APPROVAL_TOKEN_HASH
    assert updated.approval_decided_at is not None


def test_transition_invalid_state_change_raises(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-denied"))
        store.transition(
            "req-denied",
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
        )

        with pytest.raises(ApprovalEvidenceTransitionError):
            store.transition(
                "req-denied",
                ApprovalStatus.APPROVED.value,
                approval_token_hash=APPROVAL_TOKEN_HASH,
            )

        store.write_pending(_record("req-executed"))
        store.transition(
            "req-executed",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
        )
        store.transition(
            "req-executed",
            ApprovalStatus.EXECUTED.value,
            result_hash=RESULT_HASH,
        )

        with pytest.raises(ApprovalEvidenceTransitionError):
            store.transition("req-executed", ApprovalStatus.PENDING.value)


def test_expire_overdue_marks_stale_pending_as_expired_in_bulk(tmp_path):
    now = 1_700_000_000
    with _store(tmp_path) as store:
        store.write_pending(_record("req-old", created_at=now - 600, expires_at=now - 1))
        store.write_pending(_record("req-fresh", created_at=now, expires_at=now + 300))

        expired = store.expire_overdue(now_timestamp=now)

        assert expired == ["req-old"]
        assert store.get_pending("req-old").status == ApprovalStatus.EXPIRED.value
        assert store.get_pending("req-old").error_class == "approval_expired"
        assert store.get_pending("req-fresh").status == ApprovalStatus.PENDING.value


def test_recover_on_startup_marks_stale_pending_as_expired_does_not_approve(tmp_path):
    now = int(time.time())
    db_path = tmp_path / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(_record("req-stale", created_at=now - 600, expires_at=now - 1))
        store.write_pending(_record("req-open", created_at=now, expires_at=now + 300))

    with ApprovalEvidenceStore(db_path) as reopened:
        report = reopened.recover_on_startup()
        stale = reopened.get_pending("req-stale")
        open_record = reopened.get_pending("req-open")

    assert report.pending_before == 2
    assert report.pending_after == 1
    assert report.expired_request_ids == ("req-stale",)
    assert stale.status == ApprovalStatus.EXPIRED.value
    assert open_record.status == ApprovalStatus.PENDING.value
    assert stale.status != ApprovalStatus.APPROVED.value


def test_recover_on_startup_leaves_in_window_pending_unchanged(tmp_path):
    now = int(time.time())
    db_path = tmp_path / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(_record("req-open", created_at=now, expires_at=now + 300))

    with ApprovalEvidenceStore(db_path) as reopened:
        report = reopened.recover_on_startup()
        record = reopened.get_pending("req-open")

    assert report.expired_request_ids == ()
    assert report.pending_before == 1
    assert report.pending_after == 1
    assert record.status == ApprovalStatus.PENDING.value


def test_evidence_db_file_has_0600_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX mode bits are not stable on Windows")

    db_path = tmp_path / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path):
        pass

    assert _mode(db_path) == 0o600


def test_schema_version_mismatch_refuses_to_open_for_forward_incompatible(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE evidence_schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (2)")
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, 0o600)

    with pytest.raises(ApprovalEvidenceSchemaError):
        ApprovalEvidenceStore(db_path)


def test_no_backend_construction_during_evidence_operations(tmp_path, monkeypatch):
    import agentveil.agent as agent_module
    import httpx

    class ExplodingAgent:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("evidence store must not construct AVPAgent")

    class ExplodingClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("evidence store must not construct an HTTP client")

    monkeypatch.setattr(agent_module, "AVPAgent", ExplodingAgent)
    monkeypatch.setattr(httpx, "Client", ExplodingClient)

    with _store(tmp_path) as store:
        store.write_pending(_record("req-local"))
        store.transition(
            "req-local",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
        )
        store.transition("req-local", ApprovalStatus.EXECUTED.value, result_hash=RESULT_HASH)

        assert store.get_pending("req-local").status == ApprovalStatus.EXECUTED.value


def test_max_records_cap_refuses_new_writes_with_explicit_error(tmp_path):
    with _store(tmp_path, max_records=1) as store:
        store.write_pending(_record("req-1"))

        with pytest.raises(ApprovalEvidenceCapacityError) as exc:
            store.write_pending(_record("req-2"))

    assert "record cap reached" in str(exc.value)
