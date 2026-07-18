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
from agentveil.delegation import _public_key_to_did
from agentveil_mcp_proxy.evidence.approval_grant import (
    APPROVAL_GRANT_SCHEMA,
    build_approval_grant,
)
from agentveil_mcp_proxy.evidence.proof import (
    EvidenceVerificationError,
    build_evidence_bundle,
    verify_evidence_bundle,
)
from nacl.signing import SigningKey


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


def test_find_active_similar_grant_rejects_policy_context_drift(tmp_path):
    # A live similar_5m grant is reusable only within the same policy context.
    # A hot-reload that changes policy_id or decision_mode shifts
    # policy_context_hash, after which the stale grant must no longer match.
    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        now_timestamp=1_700_000_000,
    )
    with _store(tmp_path) as store:
        store.write_pending(_record("req-similar"))
        store.transition(
            "req-similar",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="similar_5m",
            granted_scope_expires_at=1_700_000_300,
        )

        matched = store.find_active_similar_grant(
            policy_context_hash=POLICY_CONTEXT_HASH, **lookup
        )
        assert matched is not None and matched.request_id == "req-similar"

        drifted = store.find_active_similar_grant(
            policy_context_hash="a" * 64, **lookup
        )
        assert drifted is None


def test_find_active_exact_grant_rejects_policy_context_drift(tmp_path):
    # An approved exact grant is reusable only within the same policy context.
    # Policy drift (a hot-reload changing policy_id or decision_mode) shifts
    # policy_context_hash, after which the stale exact grant must not match an
    # identical retry.
    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        now_timestamp=1_700_000_000,
    )
    with _store(tmp_path) as store:
        store.write_pending(_record("req-exact"))
        store.transition(
            "req-exact",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="exact",
            user_decision_timestamp=1_700_000_000,
        )

        matched = store.find_active_exact_grant(
            policy_context_hash=POLICY_CONTEXT_HASH, **lookup
        )
        assert matched is not None and matched.request_id == "req-exact"

        drifted = store.find_active_exact_grant(
            policy_context_hash="a" * 64, **lookup
        )
        assert drifted is None


def test_find_active_exact_deny_matches_identical_retry(tmp_path):
    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        now_timestamp=1_700_000_100,
    )
    with _store(tmp_path) as store:
        store.write_pending(_record("req-deny"))
        store.transition(
            "req-deny",
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="exact",
            user_decision_timestamp=1_700_000_000,
            error_class="user_denied",
        )
        matched = store.find_active_exact_deny(
            policy_context_hash=POLICY_CONTEXT_HASH,
            **lookup,
        )
        assert matched is not None and matched.request_id == "req-deny"


def test_find_active_exact_deny_rejects_payload_drift(tmp_path):
    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        policy_context_hash=POLICY_CONTEXT_HASH,
        now_timestamp=1_700_000_100,
    )
    with _store(tmp_path) as store:
        store.write_pending(_record("req-deny"))
        store.transition(
            "req-deny",
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="exact",
            user_decision_timestamp=1_700_000_000,
            error_class="user_denied",
        )
        assert store.find_active_exact_deny(
            payload_hash=PAYLOAD_HASH,
            **lookup,
        ) is not None
        assert store.find_active_exact_deny(
            payload_hash="sha256:" + "9" * 64,
            **lookup,
        ) is None


def test_find_active_exact_deny_rejects_resource_drift(tmp_path):
    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        payload_hash=PAYLOAD_HASH,
        policy_context_hash=POLICY_CONTEXT_HASH,
        now_timestamp=1_700_000_100,
    )
    with _store(tmp_path) as store:
        store.write_pending(_record("req-deny"))
        store.transition(
            "req-deny",
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="exact",
            user_decision_timestamp=1_700_000_000,
            error_class="user_denied",
        )
        assert store.find_active_exact_deny(
            resource_hash=RESOURCE_HASH,
            **lookup,
        ) is not None
        assert store.find_active_exact_deny(
            resource_hash="sha256:" + "9" * 64,
            **lookup,
        ) is None


def test_find_active_exact_deny_rejects_policy_context_drift(tmp_path):
    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        now_timestamp=1_700_000_100,
    )
    with _store(tmp_path) as store:
        store.write_pending(_record("req-deny"))
        store.transition(
            "req-deny",
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="exact",
            user_decision_timestamp=1_700_000_000,
            error_class="user_denied",
        )
        assert store.find_active_exact_deny(
            policy_context_hash=POLICY_CONTEXT_HASH,
            **lookup,
        ) is not None
        assert store.find_active_exact_deny(
            policy_context_hash="a" * 64,
            **lookup,
        ) is None


def test_find_active_exact_deny_rejects_expired_deadline(tmp_path):
    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_context_hash=POLICY_CONTEXT_HASH,
        now_timestamp=1_700_000_500,
    )
    with _store(tmp_path) as store:
        store.write_pending(
            _record(
                "req-deny",
                created_at=1_700_000_000,
                expires_at=1_700_000_300,
            )
        )
        store.transition(
            "req-deny",
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="exact",
            user_decision_timestamp=1_700_000_100,
            error_class="user_denied",
        )
        assert store.find_active_exact_deny(**lookup) is None


def test_find_active_exact_deny_ignores_timeout_not_user_denied(tmp_path):
    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_context_hash=POLICY_CONTEXT_HASH,
        now_timestamp=1_700_000_100,
    )
    with _store(tmp_path) as store:
        store.write_pending(_record("req-expired"))
        store.transition(
            "req-expired",
            ApprovalStatus.EXPIRED.value,
            error_class="approval_timeout",
        )
        assert store.find_active_exact_deny(**lookup) is None


def test_find_active_exact_deny_does_not_match_similar_scope(tmp_path):
    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_context_hash=POLICY_CONTEXT_HASH,
        now_timestamp=1_700_000_100,
    )
    with _store(tmp_path) as store:
        store.write_pending(_record("req-similar", payload_hash="sha256:" + "8" * 64))
        store.transition(
            "req-similar",
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="similar_5m",
            user_decision_timestamp=1_700_000_000,
            error_class="user_denied",
        )
        assert store.find_active_exact_deny(**lookup) is None


def test_find_active_exact_deny_rejects_null_expiry_hang_mode(tmp_path):
    """HANG-mode denials (expires_at=NULL) must not suppress identical retries forever."""

    lookup = dict(
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        policy_rule_id="rule-write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_context_hash=POLICY_CONTEXT_HASH,
        now_timestamp=1_700_000_100,
    )
    with _store(tmp_path) as store:
        hang_record = _record("req-hang-deny", created_at=1_700_000_000)
        hang_record = PendingApproval(
            **{**asdict(hang_record), "expires_at": None}
        )
        store.write_pending(hang_record)
        store.transition(
            "req-hang-deny",
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="exact",
            user_decision_timestamp=1_700_000_000,
            error_class="user_denied",
        )
        denied = store.get_pending("req-hang-deny")
        assert denied is not None
        assert denied.expires_at is None
        assert store.find_active_exact_deny(**lookup) is None


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


def test_record_terminal_deny_writes_single_blocked_record(tmp_path):
    # Bug 3 regression coverage for terminal deny evidence and approval fields.
    # claim-check: allow tested terminal status and pending-count assertions
    with _store(tmp_path) as store:
        returned = store.record_terminal_deny(
            request_id="deny-1",
            session_id="session-1",
            client_id="cursor:session-7",
            downstream_server="filesystem",
            tool_name="read_file",
            risk_class="read",
            resource_hash=RESOURCE_HASH,
            payload_hash=PAYLOAD_HASH,
            policy_id="filesystem-read",
            policy_rule_id="filesystem-read",
            policy_context_hash=POLICY_CONTEXT_HASH,
            created_at=1_700_000_000,
            reason="secret_path_blocked",
        )

        assert returned.status == ApprovalStatus.BLOCKED.value  # claim-check: allow tested status
        assert returned.error_class == "secret_path_blocked"
        assert returned.result_status == ApprovalStatus.BLOCKED.value  # claim-check: allow tested status
        assert returned.expires_at is None
        # A hard-deny sets no approval-prompt fields.
        assert returned.approval_token_hash is None
        assert returned.approval_decided_by is None
        assert returned.decision_audit_id is None

        persisted = store.get_pending("deny-1")
        assert persisted is not None
        assert persisted.status == ApprovalStatus.BLOCKED.value  # claim-check: allow tested status

    with sqlite3.connect(tmp_path / "evidence.sqlite") as conn:
        total = conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
        pending = conn.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending'"
        ).fetchone()[0]
    assert total == 1
    assert pending == 0


def test_record_terminal_deny_persists_action_gate_metadata(tmp_path):
    metadata = {
        "declared_tool_surface": ["get_*"],
        "observed_tool_surface": ["delete_repo", "get_issue"],
        "action_family": "delete",
        "authority": "operator_declared_surface",
        "escalation_trigger": "extra_undeclared_downstream_tool",
        "policy_decision": "block",
        "policy_rule": "action_gate_extra_downstream_tool",
        # claim-check: allow BLOCKED as stored approval-status enum value.
        "approval_status": ApprovalStatus.BLOCKED.value,
        "execution_status": "not_reached",
        "request_id": "deny-gate-1",
        "request_chain": ["deny-gate-1"],
        "payload_hash": PAYLOAD_HASH,
    }
    with _store(tmp_path) as store:
        returned = store.record_terminal_deny(
            request_id="deny-gate-1",
            session_id="session-1",
            client_id="cursor:session-7",
            downstream_server="github-mcp",
            tool_name="delete_repo",
            risk_class="tool_surface_violation",
            resource_hash=None,
            payload_hash=PAYLOAD_HASH,
            policy_id="mcp_proxy_action_gate",
            policy_rule_id="action_gate_extra_downstream_tool",
            policy_context_hash=POLICY_CONTEXT_HASH,
            created_at=1_700_000_000,
            reason="extra_undeclared_downstream_tool",
            action_gate_metadata_jcs=json.dumps(metadata, sort_keys=True),
        )

        assert returned.action_gate_metadata_jcs is not None
        assert SECRET not in returned.action_gate_metadata_jcs
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did=None,
            trusted_signer_dids=[],
        )
        exported = bundle["records"][0]["action_gate_metadata"]
        assert exported["declared_tool_surface"] == ["get_*"]
        assert exported["execution_status"] == "not_reached"


def test_record_terminal_deny_rolls_back_on_transition_error(tmp_path, monkeypatch):
    # Regression coverage: transition failure rolls the evidence write back.
    # claim-check: allow pending-count assertion for rollback test
    with _store(tmp_path) as store:
        def fail_transition_fields(_updates):
            raise ApprovalEvidenceTransitionError("forced transition failure")

        monkeypatch.setattr(store, "_validate_transition_fields", fail_transition_fields)

        with pytest.raises(ApprovalEvidenceTransitionError, match="forced transition failure"):
            store.record_terminal_deny(
                request_id="deny-rollback",
                session_id="session-1",
                client_id="cursor:session-7",
                downstream_server="filesystem",
                tool_name="read_file",
                risk_class="read",
                resource_hash=RESOURCE_HASH,
                payload_hash=PAYLOAD_HASH,
                policy_id="filesystem-read",
                policy_rule_id="filesystem-read",
                policy_context_hash=POLICY_CONTEXT_HASH,
                created_at=1_700_000_000,
                reason="secret_path_blocked",
            )

    with sqlite3.connect(tmp_path / "evidence.sqlite") as conn:
        total = conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
    assert total == 0


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


def test_export_bundle_parent_includes_execution_record_id_for_executed_child(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-parent", created_at=10))
        store.transition(
            "req-parent",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_at=11,
        )
        store.write_pending(
            PendingApproval(
                request_id="req-child",
                session_id="session-1",
                client_id="cursor:session-7",
                downstream_server="github-mcp",
                tool_name="github.create_issue",
                action_class="write",
                risk_class="write",
                resource_hash=RESOURCE_HASH,
                payload_hash=PAYLOAD_HASH,
                policy_id="github-default",
                policy_rule_id="rule-write",
                policy_context_hash=POLICY_CONTEXT_HASH,
                status=ApprovalStatus.PENDING.value,
                created_at=12,
                expires_at=312,
                granted_by_request_id="req-parent",
            )
        )
        store.transition(
            "req-child",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_at=13,
        )
        store.transition(
            "req-child",
            ApprovalStatus.EXECUTED.value,
            result_status="executed",
            result_hash=RESULT_HASH,
        )
        store.annotate_linked_execution(
            "req-parent",
            result_status=ApprovalStatus.EXECUTED.value,
            result_hash=RESULT_HASH,
        )
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did=GRANT_DID,
            trusted_signer_dids=[GRANT_DID],
        )

    parent = next(item for item in bundle["records"] if item["request_id"] == "req-parent")
    child = next(item for item in bundle["records"] if item["request_id"] == "req-child")
    assert parent["execution_record_id"] == "req-child"
    assert child["granted_by_request_id"] == "req-parent"
    assert "execution_record_id" not in child
    assert verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID]).valid is True


def test_expire_stale_approvals_skips_parent_with_linked_execution_result(tmp_path):
    now = 1_700_010_000
    with _store(tmp_path) as store:
        store.write_pending(_record("req-parent", created_at=now - 7_300, expires_at=now + 300))
        store.write_pending(_record("req-child", created_at=now - 7_290, expires_at=now + 300))
        store.transition(
            "req-parent",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_at=now - 7_200,
        )
        store.transition(
            "req-child",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_at=now - 7_190,
        )
        store.transition(
            "req-child",
            ApprovalStatus.EXECUTED.value,
            result_status="executed",
            result_hash=RESULT_HASH,
        )
        store.annotate_linked_execution(
            "req-parent",
            result_status=ApprovalStatus.EXECUTED.value,
            result_hash=RESULT_HASH,
        )

        stale = store.expire_stale_approvals(now_timestamp=now, grace_seconds=3_600)
        parent = store.get_pending("req-parent")

    assert stale == []
    assert parent.status == ApprovalStatus.APPROVED.value
    assert parent.result_status == "executed"


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
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (6)")
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
    assert version == 5
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


def test_fresh_schema_allows_null_expires_at(tmp_path):
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
    assert version == 5
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
    assert version == 5
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


# --- SG-4: signed approval grant export / verification ---

GRANT_SEED = bytes.fromhex("33" * 32)
GRANT_DID = _public_key_to_did(bytes(SigningKey(GRANT_SEED).verify_key))
OTHER_GRANT_DID = _public_key_to_did(bytes(SigningKey(bytes.fromhex("44" * 32)).verify_key))


def _grant_body_for(record, *, scope="exact", decided_by="local-user", did=GRANT_DID, expires_at, **overrides):
    body = {
        "schema_version": APPROVAL_GRANT_SCHEMA,
        "agent_did": did,
        "request_id": record.request_id,
        "downstream_server": record.downstream_server,
        "tool_name": record.tool_name,
        "action_class": record.action_class,
        "risk_class": record.risk_class,
        "resource_hash": record.resource_hash,
        "payload_hash": None if scope == "similar_5m" else record.payload_hash,
        "policy_id": record.policy_id,
        "policy_rule_id": record.policy_rule_id,
        "policy_context_hash": record.policy_context_hash,
        "decision": "APPROVED",
        "approval_scope": scope,
        "decided_by": decided_by,
        "issued_at": record.created_at,
        "expires_at": expires_at,
        "decision_audit_id": record.decision_audit_id,
        "decision_receipt_sha256": record.decision_receipt_sha256,
        "granted_by_request_id": record.granted_by_request_id,
    }
    body.update(overrides)
    return body


def _approve_with_grant(
    store,
    *,
    request_id="req-grant",
    scope="exact",
    grant_jcs=None,
    decided_by="local-user",
    seed=GRANT_SEED,
    did=GRANT_DID,
):
    record = _record(request_id)
    store.write_pending(record)
    granted = record.expires_at if scope == "similar_5m" else None
    grant_expiry = granted if scope == "similar_5m" else record.expires_at
    if grant_jcs is None:
        grant_jcs = build_approval_grant(
            _grant_body_for(record, scope=scope, decided_by=decided_by, did=did, expires_at=grant_expiry),
            seed,
        )
    return store.transition(
        request_id,
        ApprovalStatus.APPROVED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        approval_decided_by=decided_by,
        approval_scope=scope,
        granted_scope_expires_at=granted,
        user_decision_timestamp=record.created_at,
        approval_grant_jcs=grant_jcs,
    )


def _approve_without_grant(store, *, request_id="req-no-grant"):
    record = _record(request_id)
    store.write_pending(record)
    store.transition(
        request_id,
        ApprovalStatus.APPROVED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        approval_decided_by="local-user",
        approval_scope="exact",
        user_decision_timestamp=record.created_at,
    )
    return record


def _bundle(store):
    return build_evidence_bundle(store, proxy_identity_did=GRANT_DID, trusted_signer_dids=[GRANT_DID])


def test_bundle_exports_and_verifies_signed_approval_grant(tmp_path):
    with _store(tmp_path) as store:
        _approve_with_grant(store, request_id="req-grant")
        bundle = _bundle(store)
        # Export is automatic: the persisted grant rides inside the record.
        assert bundle["records"][0]["approval_grant_jcs"] is not None
        result = verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True)
        assert result.valid
        assert result.verified_approval_grant_count == 1


def test_similar_5m_grant_exports_and_verifies(tmp_path):
    with _store(tmp_path) as store:
        _approve_with_grant(
            store, request_id="req-similar", scope="similar_5m", decided_by="scope-cache-hit"
        )
        bundle = _bundle(store)
        result = verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True)
        assert result.valid
        assert result.verified_approval_grant_count == 1


def test_strict_rejects_approved_record_missing_grant(tmp_path):
    with _store(tmp_path) as store:
        _approve_without_grant(store)
        bundle = _bundle(store)
        with pytest.raises(EvidenceVerificationError, match="missing approval_grant_jcs"):
            verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True)


def test_legacy_tolerates_approved_record_missing_grant(tmp_path):
    with _store(tmp_path) as store:
        _approve_without_grant(store)
        bundle = _bundle(store)
        result = verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=False)
        assert result.valid
        assert result.verified_approval_grant_count == 0
        assert any("no signed approval grant" in warning for warning in result.warnings)


def test_strict_grant_requires_external_signer_pins(tmp_path):
    with _store(tmp_path) as store:
        _approve_with_grant(store, request_id="req-grant")
        bundle = _bundle(store)  # carries an in-bundle trusted_signer_dids list
        # The in-bundle signer list must NOT be trusted for grant verification.
        with pytest.raises(EvidenceVerificationError, match="externally supplied trusted_signer_dids"):
            verify_evidence_bundle(bundle, trusted_signer_dids=None, strict=True)


def test_grant_wrong_signer_rejected(tmp_path):
    with _store(tmp_path) as store:
        _approve_with_grant(store, request_id="req-grant")
        bundle = _bundle(store)
        with pytest.raises(EvidenceVerificationError, match="approval grant verification failed"):
            verify_evidence_bundle(bundle, trusted_signer_dids=[OTHER_GRANT_DID], strict=True)


def test_grant_body_record_mismatch_rejected(tmp_path):
    with _store(tmp_path) as store:
        record = _record("req-grant")
        store.write_pending(record)
        # Validly signed grant, but it binds a different tool than the record.
        grant_jcs = build_approval_grant(
            _grant_body_for(record, expires_at=record.expires_at, tool_name="github.evil_tool"),
            GRANT_SEED,
        )
        store.transition(
            "req-grant",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            approval_decided_by="local-user",
            approval_scope="exact",
            user_decision_timestamp=record.created_at,
            approval_grant_jcs=grant_jcs,
        )
        bundle = _bundle(store)
        with pytest.raises(EvidenceVerificationError, match="tool_name mismatch with record"):
            verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True)


def _transition_with_grant(store, request_id, record, grant_jcs):
    store.transition(
        request_id,
        ApprovalStatus.APPROVED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        approval_decided_by="local-user",
        approval_scope="exact",
        user_decision_timestamp=record.created_at,
        approval_grant_jcs=grant_jcs,
    )


def test_tampered_grant_body_rejected(tmp_path):
    with _store(tmp_path) as store:
        record = _record("req-grant")
        store.write_pending(record)
        grant_jcs = build_approval_grant(_grant_body_for(record, expires_at=record.expires_at), GRANT_SEED)
        # Mutate a signed body field after signing: the 64-byte signature no
        # longer matches the document. record_hash is recomputed over this stored
        # value so the chain stays consistent -- the failure is the grant signature.
        doc = json.loads(grant_jcs)
        doc["tool_name"] = "github.mutated_tool"
        tampered = json.dumps(doc)
        _transition_with_grant(store, "req-grant", record, tampered)
        bundle = _bundle(store)
        with pytest.raises(EvidenceVerificationError, match="approval grant verification failed"):
            verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True)


def test_malformed_grant_signature_fails_closed(tmp_path):
    with _store(tmp_path) as store:
        record = _record("req-grant")
        store.write_pending(record)
        grant_jcs = build_approval_grant(_grant_body_for(record, expires_at=record.expires_at), GRANT_SEED)
        # Corrupt the proofValue length; the verifier must reject with a clean
        # EvidenceVerificationError, not leak a raw ValueError.
        malformed = grant_jcs.replace('"proofValue":"z', '"proofValue":"zA', 1)
        assert malformed != grant_jcs
        _transition_with_grant(store, "req-grant", record, malformed)
        bundle = _bundle(store)
        with pytest.raises(EvidenceVerificationError, match="approval grant verification failed"):
            verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True)


def test_expired_grant_rejected_when_now_supplied(tmp_path):
    with _store(tmp_path) as store:
        _approve_with_grant(store, request_id="req-grant")  # expires_at == created_at + 300
        bundle = _bundle(store)
        # Historical audit (no `now`) accepts the grant.
        assert verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True).valid
        # With a clock past expiry, the grant is rejected.
        with pytest.raises(EvidenceVerificationError, match="approval grant verification failed"):
            verify_evidence_bundle(
                bundle, trusted_signer_dids=[GRANT_DID], strict=True, now=1_700_001_000
            )


def _execute(store, request_id):
    """Carry a record into terminal EXECUTED without re-stamping approval fields,
    mirroring ApprovalManager.record_execution_result."""
    return store.transition(
        request_id,
        ApprovalStatus.EXECUTED.value,
        result_status="executed",
        result_hash=RESULT_HASH,
    )


def test_strict_rejects_executed_record_missing_grant(tmp_path):
    # SG-3a mint-failure path: a local approval persisted without a grant, then
    # actually executed. status is no longer "approved", but the local decision
    # (approval_decided_by/approval_scope) is retained, so strict must still
    # require the grant -- otherwise an executed grant-less approval slips past.
    with _store(tmp_path) as store:
        _approve_without_grant(store, request_id="req-exec-no-grant")
        _execute(store, "req-exec-no-grant")
        bundle = _bundle(store)
        exported = bundle["records"][0]
        assert exported["status"] == ApprovalStatus.EXECUTED.value
        assert exported["approval_decided_by"] is not None
        assert exported["approval_grant_jcs"] is None
        with pytest.raises(EvidenceVerificationError, match="missing approval_grant_jcs"):
            verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True)


def test_executed_record_with_grant_verifies(tmp_path):
    # The same approved-then-executed path, but the grant was minted at approval
    # and carried through execution: strict verification passes and counts it.
    with _store(tmp_path) as store:
        _approve_with_grant(store, request_id="req-exec-grant")
        _execute(store, "req-exec-grant")
        bundle = _bundle(store)
        exported = bundle["records"][0]
        assert exported["status"] == ApprovalStatus.EXECUTED.value
        assert exported["approval_grant_jcs"] is not None
        result = verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True)
        assert result.valid
        assert result.verified_approval_grant_count == 1


def test_runtime_gate_executed_record_without_local_grant_not_required(tmp_path):
    # Runtime Gate ALLOW / backend-only records mint no local approval grant:
    # _write_runtime_decision_record leaves approval_decided_by/approval_scope
    # unset. Such a record executing must NOT be required to carry a grant, even
    # in strict mode.
    with _store(tmp_path) as store:
        store.write_pending(_record("req-runtime-allow"))
        # No approval_decided_by / approval_scope: not a local approval decision.
        _execute(store, "req-runtime-allow")
        bundle = _bundle(store)
        exported = bundle["records"][0]
        assert exported["status"] == ApprovalStatus.EXECUTED.value
        assert exported["approval_decided_by"] is None
        assert exported["approval_scope"] is None
        assert exported["approval_grant_jcs"] is None
        result = verify_evidence_bundle(bundle, trusted_signer_dids=[GRANT_DID], strict=True)
        assert result.valid
        assert result.verified_approval_grant_count == 0


def test_redirect_automation_link_valid_requires_bounded_original_and_follow_up():
    from agentveil_mcp_proxy.evidence.observability import redirect_automation_link_valid
    from agentveil_mcp_proxy.policy import build_redirect_automation_metadata

    # claim-check: allow test status enum; this is negative evidence-link coverage.
    original_metadata = build_redirect_automation_metadata(
        fixture_id="redirect.original",
        tool_name="write_file",
        policy_decision="block",
        policy_rule_id="role_authority_reviewer_blocks_implementation",
        approval_status=ApprovalStatus.BLOCKED.value,  # claim-check: allow test enum; negative evidence coverage.
        execution_status="not_reached",
        target_reached=False,
        request_id="orig-write",
        redirect_role="original",
        redirect_playbook_id="create_implementer_task",
        original_request_id="orig-write",
    )
    follow_metadata = build_redirect_automation_metadata(
        fixture_id="redirect.follow",
        tool_name="read_file",
        policy_decision="allow",
        policy_rule_id=None,
        approval_status=ApprovalStatus.EXECUTED.value,
        execution_status=ApprovalStatus.EXECUTED.value,
        target_reached=True,
        request_id="follow-read",
        request_chain=["orig-write", "follow-read"],
        redirect_role="follow_up",
        redirect_playbook_id="create_implementer_task",
        redirect_parent_request_id="orig-write",
        original_request_id="orig-write",
    )
    original = PendingApproval(
        **{
            **asdict(_record("orig-write")),
            "action_gate_metadata_jcs": json.dumps(original_metadata, separators=(",", ":"), sort_keys=True),
            "status": ApprovalStatus.BLOCKED.value,  # claim-check: allow test enum; negative evidence coverage.
        }
    )
    follow_up = PendingApproval(
        **{
            **asdict(_record("follow-read", status=ApprovalStatus.EXECUTED.value)),
            "tool_name": "read_file",
            "action_gate_metadata_jcs": json.dumps(follow_metadata, separators=(",", ":"), sort_keys=True),
            "status": ApprovalStatus.EXECUTED.value,
        }
    )
    assert redirect_automation_link_valid(original, follow_up) is True
    broken = PendingApproval(
        **{
            **asdict(follow_up),
            "request_id": "follow-broken",
            "action_gate_metadata_jcs": json.dumps(
                {**follow_metadata, "redirect_parent_request_id": "other-id"},
                separators=(",", ":"),
                sort_keys=True,
            ),
        }
    )
    assert redirect_automation_link_valid(original, broken) is False


def test_redirect_original_record_valid_requires_original_role_and_playbook():
    from agentveil_mcp_proxy.evidence.observability import redirect_original_record_valid
    from agentveil_mcp_proxy.policy import (
        build_controlled_path_metadata,
        build_redirect_automation_metadata,
    )

    # claim-check: allow test status enum; this validates redirect parent bounds.
    original_metadata = build_redirect_automation_metadata(
        fixture_id="redirect.original",
        tool_name="write_file",
        policy_decision="block",
        policy_rule_id="role_authority_reviewer_blocks_implementation",
        approval_status=ApprovalStatus.BLOCKED.value,  # claim-check: allow test enum; redirect parent bounds.
        execution_status="not_reached",
        target_reached=False,
        request_id="orig-write",
        redirect_role="original",
        redirect_playbook_id="create_implementer_task",
        original_request_id="orig-write",
    )
    allow_metadata = build_controlled_path_metadata(
        fixture_id="allow.read",
        tool_name="read_file",
        policy_decision="allow",
        policy_rule_id="allow-read",
        approval_status=ApprovalStatus.EXECUTED.value,
        execution_status=ApprovalStatus.EXECUTED.value,
        target_reached=True,
        request_id="allow-baseline",
    )
    original = PendingApproval(
        **{
            **asdict(_record("orig-write")),
            "action_gate_metadata_jcs": json.dumps(original_metadata, separators=(",", ":"), sort_keys=True),
            "status": ApprovalStatus.BLOCKED.value,  # claim-check: allow test enum; redirect parent bounds.
        }
    )
    allow_record = PendingApproval(
        **{
            **asdict(_record("allow-baseline", status=ApprovalStatus.EXECUTED.value)),
            "tool_name": "read_file",
            "action_gate_metadata_jcs": json.dumps(allow_metadata, separators=(",", ":"), sort_keys=True),
            "status": ApprovalStatus.EXECUTED.value,
        }
    )
    assert redirect_original_record_valid(
        original,
        redirect_playbook_id="create_implementer_task",
    ) is True
    assert redirect_original_record_valid(
        original,
        redirect_playbook_id="use_read_only_tool",
    ) is False
    assert redirect_original_record_valid(
        allow_record,
        redirect_playbook_id="create_implementer_task",
    ) is False


def test_control_surface_summarize_evidence_uses_redirect_observability_parsers():
    from agentveil_mcp_proxy.control_surface import summarize_evidence
    from agentveil_mcp_proxy.policy import build_redirect_automation_metadata

    metadata = build_redirect_automation_metadata(
        fixture_id="redirect.original",
        tool_name="write_file",
        policy_decision="block",
        policy_rule_id="role_authority_reviewer_blocks_implementation",
        approval_status=ApprovalStatus.BLOCKED.value,  # claim-check: allow status enum in control-surface parser test.
        execution_status="not_reached",
        target_reached=False,
        request_id="orig-write",
        redirect_role="original",
        redirect_playbook_id="create_implementer_task",
        original_request_id="orig-write",
    )
    record = PendingApproval(
        **{
            **asdict(_record("orig-write")),
            "action_gate_metadata_jcs": json.dumps(metadata, separators=(",", ":"), sort_keys=True),
            "status": ApprovalStatus.BLOCKED.value,  # claim-check: allow status enum in control-surface parser test.
        }
    )
    summary = summarize_evidence([record])
    assert summary["redirect_original_count"] == 1
    assert summary["target_reached_false_count"] == 1
