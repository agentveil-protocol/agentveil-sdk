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

import agentveil_mcp_proxy.evidence.store as store_module
from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceCapacityError,
    ApprovalEvidenceDuplicateError,
    ApprovalEvidenceSchemaError,
    ApprovalEvidenceStore,
    ApprovalEvidenceTransitionError,
    ApprovalStatus,
    GENESIS_PREV_EVENT_HASH,
    PendingApproval,
    record_hash,
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


def _record_with_null_expires_at(
    request_id: str = "req-null",
    *,
    created_at: int = 1_700_000_000,
) -> PendingApproval:
    return PendingApproval(
        **{**asdict(_record(request_id, created_at=created_at)), "expires_at": None}
    )


def _chain_records(*records: PendingApproval) -> list[PendingApproval]:
    chained: list[PendingApproval] = []
    prev_hash = GENESIS_PREV_EVENT_HASH
    for record in records:
        chained_record = PendingApproval(**{**asdict(record), "prev_event_hash": prev_hash})
        chained.append(chained_record)
        prev_hash = record_hash(chained_record)
    return chained


def _create_v3_evidence_db(db_path: Path, records: list[PendingApproval]) -> None:
    columns = tuple(asdict(records[0]).keys())
    integer_columns = {
        "created_at",
        "approval_decided_at",
        "granted_scope_expires_at",
        "user_decision_timestamp",
    }
    column_defs = []
    for column in columns:
        if column == "request_id":
            column_defs.append("request_id TEXT PRIMARY KEY")
        elif column == "expires_at":
            column_defs.append("expires_at INTEGER NOT NULL")
        elif column == "created_at":
            column_defs.append("created_at INTEGER NOT NULL")
        elif column in integer_columns:
            column_defs.append(f"{column} INTEGER NULL")
        else:
            column_defs.append(f"{column} TEXT NULL")

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE evidence_schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (3)")
        conn.execute("CREATE TABLE pending_approvals (" + ", ".join(column_defs) + ")")
        for record in records:
            values = asdict(record)
            conn.execute(
                f"INSERT INTO pending_approvals ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _ in columns)})",
                [values[column] for column in columns],
            )
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, 0o600)


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


def test_require_prefixed_hash_rejects_non_hex_digest():
    with pytest.raises(ApprovalEvidenceTransitionError, match="64 hex chars"):
        store_module._require_prefixed_hash("payload_hash", "sha256:" + "g" * 64)


def test_require_prefixed_hash_rejects_wrong_length():
    with pytest.raises(ApprovalEvidenceTransitionError, match="64 hex chars"):
        store_module._require_prefixed_hash("payload_hash", "sha256:abc")


def test_require_prefixed_hash_accepts_lowercase_64_hex():
    store_module._require_prefixed_hash("payload_hash", "sha256:" + "a" * 64)


def test_require_prefixed_hash_accepts_uppercase_64_hex():
    store_module._require_prefixed_hash("payload_hash", "sha256:" + "A" * 64)


def test_require_hash_like_rejects_non_hex_chars():
    with pytest.raises(ApprovalEvidenceTransitionError, match="64-char hex"):
        store_module._require_hash_like("policy_context_hash", "g" * 64)


def test_require_hash_like_rejects_wrong_length():
    with pytest.raises(ApprovalEvidenceTransitionError, match="64-char hex"):
        store_module._require_hash_like("policy_context_hash", "abc")


def test_require_hash_like_accepts_64_hex():
    store_module._require_hash_like("policy_context_hash", "A" * 64)


def test_write_pending_rejects_record_with_malformed_payload_hash(tmp_path):
    with _store(tmp_path) as store:
        with pytest.raises(ApprovalEvidenceTransitionError, match="payload_hash"):
            store.write_pending(_record("req-bad-hash", payload_hash="sha256:not_hex"))


def test_transition_rejects_update_with_malformed_decision_receipt_sha256(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-bad-receipt-hash"))
        with pytest.raises(ApprovalEvidenceTransitionError, match="decision_receipt_sha256"):
            store.transition(
                "req-bad-receipt-hash",
                ApprovalStatus.APPROVED.value,
                approval_token_hash=APPROVAL_TOKEN_HASH,
                decision_receipt_sha256="not-hex",
            )


def test_transition_persists_signed_approval_grant_jcs(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-grant-jcs"))
        updated = store.transition(
            "req-grant-jcs",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_grant_jcs='{"schema_version":"proxy_approval_grant/1"}',
        )

    assert updated.approval_grant_jcs == '{"schema_version":"proxy_approval_grant/1"}'


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

    assert fetched == PendingApproval(**{**asdict(record), "prev_event_hash": GENESIS_PREV_EVENT_HASH})

    with ApprovalEvidenceStore(db_path) as reopened:
        expected = PendingApproval(**{**asdict(record), "prev_event_hash": GENESIS_PREV_EVENT_HASH})
        assert reopened.get_pending("req-all") == expected
        assert reopened.list_pending() == [expected]


def test_write_pending_rejects_duplicate_request_id(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-dup"))

        with pytest.raises(ApprovalEvidenceDuplicateError):
            store.write_pending(_record("req-dup"))


def test_write_pending_accepts_null_expires_at(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record_with_null_expires_at("req-hang"))
        record = store.get_pending("req-hang")

    assert record is not None
    assert record.expires_at is None
    assert record.status == ApprovalStatus.PENDING.value


def test_write_pending_rejects_non_null_expires_at_before_created_at(tmp_path):
    with _store(tmp_path) as store:
        with pytest.raises(ApprovalEvidenceTransitionError, match="expires_at must be after"):
            store.write_pending(_record("req-invalid-expiry", created_at=100, expires_at=100))


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


def test_expire_overdue_skips_records_with_null_expires_at(tmp_path):
    now = 1_700_000_000
    with _store(tmp_path) as store:
        store.write_pending(_record("req-deny", created_at=now - 600, expires_at=now - 1))
        store.write_pending(_record_with_null_expires_at("req-hang", created_at=now - 600))

        expired = store.expire_overdue(now_timestamp=now)

        assert expired == ["req-deny"]
        assert store.get_pending("req-deny").status == ApprovalStatus.EXPIRED.value
        hang_record = store.get_pending("req-hang")
        assert hang_record.status == ApprovalStatus.PENDING.value
        assert hang_record.expires_at is None


def test_expire_overdue_still_processes_records_with_concrete_expires_at(tmp_path):
    now = 1_700_000_000
    with _store(tmp_path) as store:
        store.write_pending(_record("req-concrete", created_at=now - 600, expires_at=now - 1))

        expired = store.expire_overdue(now_timestamp=now)

        assert expired == ["req-concrete"]
        assert store.get_pending("req-concrete").status == ApprovalStatus.EXPIRED.value


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


def test_recover_on_startup_does_not_expire_hang_pending_records(tmp_path):
    now = 1_700_000_000
    db_path = tmp_path / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(_record_with_null_expires_at("req-hang", created_at=now - 600))

    with ApprovalEvidenceStore(db_path) as reopened:
        report = reopened.recover_on_startup(now_timestamp=now)
        record = reopened.get_pending("req-hang")

    assert report.pending_before == 1
    assert report.pending_after == 1
    assert report.expired_request_ids == ()
    assert record.status == ApprovalStatus.PENDING.value
    assert record.expires_at is None


def test_recover_on_startup_still_expires_deny_overdue_records(tmp_path):
    now = 1_700_000_000
    db_path = tmp_path / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(_record("req-deny", created_at=now - 600, expires_at=now - 1))

    with ApprovalEvidenceStore(db_path) as reopened:
        report = reopened.recover_on_startup(now_timestamp=now)
        record = reopened.get_pending("req-deny")

    assert report.expired_request_ids == ("req-deny",)
    assert report.pending_after == 0
    assert record.status == ApprovalStatus.EXPIRED.value


def test_recover_on_startup_expires_stale_approved_records_past_grace_period(tmp_path):
    now = 1_700_010_000
    with _store(tmp_path) as store:
        store.write_pending(_record("req-stale-approved", created_at=now - 7_300, expires_at=now + 300))
        store.transition(
            "req-stale-approved",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_at=now - 7_200,
        )

        report = store.recover_on_startup(
            stale_approval_grace_seconds=3_600,
            now_timestamp=now,
        )
        record = store.get_pending("req-stale-approved")

    assert report.stale_approval_request_ids == ("req-stale-approved",)
    assert record.status == ApprovalStatus.INVALIDATED.value
    assert record.error_class == "approval_stale_no_execution"


def test_recover_on_startup_leaves_recent_approved_records_unchanged(tmp_path):
    now = 1_700_010_000
    with _store(tmp_path) as store:
        store.write_pending(_record("req-recent-approved", created_at=now - 600, expires_at=now + 300))
        store.transition(
            "req-recent-approved",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_at=now - 60,
        )

        report = store.recover_on_startup(
            stale_approval_grace_seconds=3_600,
            now_timestamp=now,
        )
        record = store.get_pending("req-recent-approved")

    assert report.stale_approval_request_ids == ()
    assert record.status == ApprovalStatus.APPROVED.value


def test_approved_to_invalidated_transition_allowed(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-approved-invalidated"))
        store.transition(
            "req-approved-invalidated",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
        )
        updated = store.transition(
            "req-approved-invalidated",
            ApprovalStatus.INVALIDATED.value,
            error_class="approval_stale_no_execution",
        )

    assert updated.status == ApprovalStatus.INVALIDATED.value
    assert updated.error_class == "approval_stale_no_execution"


def test_expire_stale_approvals_returns_request_ids(tmp_path):
    now = 1_700_010_000
    with _store(tmp_path) as store:
        store.write_pending(_record("req-old-approved", created_at=now - 7_300, expires_at=now + 300))
        store.write_pending(_record("req-new-approved", created_at=now - 600, expires_at=now + 300))
        store.transition(
            "req-old-approved",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_at=now - 7_200,
        )
        store.transition(
            "req-new-approved",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_at=now - 60,
        )

        stale = store.expire_stale_approvals(now_timestamp=now, grace_seconds=3_600)

    assert stale == ["req-old-approved"]


def test_recovery_report_contains_stale_approval_request_ids(tmp_path):
    with ApprovalEvidenceStore(tmp_path / "evidence.sqlite") as store:
        report = store.recover_on_startup(now_timestamp=1_700_010_000)

    assert report.stale_approval_request_ids == ()


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


def test_write_pending_does_not_full_chain_rebuild(tmp_path, monkeypatch):
    with _store(tmp_path) as store:
        calls = 0

        def spy_rebuild() -> None:
            nonlocal calls
            calls += 1

        monkeypatch.setattr(store, "_rebuild_chain_locked", spy_rebuild)

        store.write_pending(_record("req-fast-path", created_at=10))

    assert calls == 0


def test_write_pending_chain_invariant_preserved(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(_record("req-1", created_at=10))
        store.write_pending(_record("req-2", created_at=20))
        store.write_pending(_record("req-3", created_at=30))

    with ApprovalEvidenceStore(db_path) as reopened:
        records = reopened.list_records()

    assert records[0].prev_event_hash == GENESIS_PREV_EVENT_HASH
    assert records[1].prev_event_hash == record_hash(records[0])
    assert records[2].prev_event_hash == record_hash(records[1])


def test_write_pending_with_clock_skew_falls_back_to_full_rebuild(tmp_path, monkeypatch):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-later", created_at=20))
        calls = 0
        original_rebuild = store._rebuild_chain_locked

        def spy_rebuild() -> None:
            nonlocal calls
            calls += 1
            original_rebuild()

        monkeypatch.setattr(store, "_rebuild_chain_locked", spy_rebuild)

        store.write_pending(_record("req-earlier", created_at=10))
        records = store.list_records()

    assert calls == 1
    assert [record.request_id for record in records] == ["req-earlier", "req-later"]
    assert records[0].prev_event_hash == GENESIS_PREV_EVENT_HASH
    assert records[1].prev_event_hash == record_hash(records[0])


def test_transition_still_triggers_full_rebuild(tmp_path, monkeypatch):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-transition-rebuild"))
        calls = 0
        original_rebuild = store._rebuild_chain_locked

        def spy_rebuild() -> None:
            nonlocal calls
            calls += 1
            original_rebuild()

        monkeypatch.setattr(store, "_rebuild_chain_locked", spy_rebuild)
        store.transition(
            "req-transition-rebuild",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
        )

    assert calls == 1


def test_evidence_db_file_has_0600_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX mode bits are not stable on Windows")

    db_path = tmp_path / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path):
        pass

    assert _mode(db_path) == 0o600


def test_evidence_db_wal_file_has_0600_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX mode bits are not stable on Windows")

    db_path = tmp_path / "evidence.sqlite"
    old_umask = os.umask(0o022)
    try:
        with ApprovalEvidenceStore(db_path) as store:
            store.write_pending(_record("req-wal"))
            aux_paths = [Path(f"{db_path}-wal"), Path(f"{db_path}-shm")]
            existing = [path for path in aux_paths if path.exists()]
            assert existing
            assert all(_mode(path) == 0o600 for path in existing)
    finally:
        os.umask(old_umask)


def test_evidence_db_wal_permissions_preserved_across_reconnect(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX mode bits are not stable on Windows")

    db_path = tmp_path / "evidence.sqlite"
    old_umask = os.umask(0o022)
    try:
        with ApprovalEvidenceStore(db_path) as store:
            store.write_pending(_record("req-wal-reconnect"))

        with ApprovalEvidenceStore(db_path) as reopened:
            reopened.transition(
                "req-wal-reconnect",
                ApprovalStatus.APPROVED.value,
                approval_token_hash=APPROVAL_TOKEN_HASH,
            )
            aux_paths = [Path(f"{db_path}-wal"), Path(f"{db_path}-shm")]
            existing = [path for path in aux_paths if path.exists()]
            assert existing
            assert all(_mode(path) == 0o600 for path in existing)
    finally:
        os.umask(old_umask)


def test_schema_version_mismatch_refuses_to_open_for_forward_incompatible(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE evidence_schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (5)")
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, 0o600)

    with pytest.raises(ApprovalEvidenceSchemaError):
        ApprovalEvidenceStore(db_path)


def test_schema_v3_migrates_to_v4_preserving_records_and_chain(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    first, second = _chain_records(
        _record("req-v3-a", created_at=10, expires_at=310),
        _record("req-v3-b", created_at=20, expires_at=320),
    )
    _create_v3_evidence_db(db_path, [first, second])

    with ApprovalEvidenceStore(db_path) as store:
        migrated_first = store.get_pending("req-v3-a")
        migrated_second = store.get_pending("req-v3-b")

    assert migrated_first == first
    assert migrated_second == second
    conn = sqlite3.connect(str(db_path))
    try:
        version = conn.execute("SELECT version FROM evidence_schema_version").fetchone()[0]
        rows = conn.execute("PRAGMA table_info(pending_approvals)").fetchall()
        expires_at_notnull = next(row[3] for row in rows if row[1] == "expires_at")
        count = conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
    finally:
        conn.close()
    assert version == 4
    assert expires_at_notnull == 0
    assert count == 2


def test_schema_v3_to_v4_migration_preserves_non_null_expires_at(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    (record,) = _chain_records(_record("req-v3-expiry", created_at=10, expires_at=999))
    _create_v3_evidence_db(db_path, [record])

    with ApprovalEvidenceStore(db_path) as store:
        migrated = store.get_pending("req-v3-expiry")

    assert migrated is not None
    assert migrated.expires_at == 999


def test_fresh_v4_schema_allows_null_expires_at(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(_record_with_null_expires_at("req-null-fresh"))

    conn = sqlite3.connect(str(db_path))
    try:
        version = conn.execute("SELECT version FROM evidence_schema_version").fetchone()[0]
        expires_at = conn.execute(
            "SELECT expires_at FROM pending_approvals WHERE request_id = ?",
            ("req-null-fresh",),
        ).fetchone()[0]
    finally:
        conn.close()
    assert version == 4
    assert expires_at is None


def test_schema_v2_migrates_to_v4_with_new_nullable_columns_without_data_loss(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        columns = [
            column
            for column in asdict(_record()).keys()
            if column not in {"granted_by_request_id", "approval_grant_jcs"}
        ]
        conn.execute("CREATE TABLE evidence_schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (2)")
        conn.execute(
            "CREATE TABLE pending_approvals ("
            + ", ".join(f"{column} TEXT" for column in columns)
            + ", PRIMARY KEY(request_id))"
        )
        values = asdict(_record("req-v2", created_at=10))
        values.pop("granted_by_request_id")
        values.pop("approval_grant_jcs")
        conn.execute(
            f"INSERT INTO pending_approvals ({', '.join(columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})",
            [values[column] for column in columns],
        )
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, 0o600)

    with ApprovalEvidenceStore(db_path) as store:
        migrated = store.get_pending("req-v2")

    assert migrated is not None
    assert migrated.payload_hash == PAYLOAD_HASH
    assert migrated.granted_by_request_id is None
    assert migrated.approval_grant_jcs is None
    conn = sqlite3.connect(str(db_path))
    try:
        version = conn.execute("SELECT version FROM evidence_schema_version").fetchone()[0]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(pending_approvals)")}
    finally:
        conn.close()
    assert version == 4
    assert "granted_by_request_id" in columns
    assert "approval_grant_jcs" in columns


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
