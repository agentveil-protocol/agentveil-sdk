"""Durable local approval evidence store for MCP adapter approval flows.

P7a provides the gateway-agnostic storage primitive that P6 approval UI must
use before rendering any approval prompt. The contract is strict: callers write
the pending approval first, wait for `write_pending()` to return, and only then
show the user an approval surface. If the proxy process exits after the write,
SQLite WAL recovery preserves the pending approval for restart handling.

This module stores metadata and hashes only. It must not store raw MCP
arguments, prompts, outputs, tokens, source code, or private logs.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from enum import Enum
import hashlib
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterable, Mapping

import jcs


EVIDENCE_SCHEMA_VERSION = 4
DEFAULT_MAX_RECORDS = 10_000
GENESIS_PREV_EVENT_HASH = "sha256:" + hashlib.sha256(
    b"agentveil_mcp_proxy/evidence/genesis-v1"
).hexdigest()


class ApprovalEvidenceError(RuntimeError):
    """Base class for durable approval evidence failures."""


class ApprovalEvidenceSchemaError(ApprovalEvidenceError):
    """Raised when an evidence database schema cannot be used safely."""


class ApprovalEvidenceDuplicateError(ApprovalEvidenceError):
    """Raised when a pending approval request ID already exists."""


class ApprovalEvidenceNotFoundError(ApprovalEvidenceError):
    """Raised when a requested approval record is not present."""


class ApprovalEvidenceTransitionError(ApprovalEvidenceError):
    """Raised when an approval status transition is invalid."""


class ApprovalEvidenceCapacityError(ApprovalEvidenceError):
    """Raised when the local evidence store reaches its configured cap."""


class ApprovalStatus(str, Enum):
    """Approval status state machine values."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"
    EXECUTED = "executed"
    BLOCKED = "blocked"
    ERROR = "error"


TERMINAL_STATUSES = frozenset({
    ApprovalStatus.DENIED.value,
    ApprovalStatus.EXPIRED.value,
    ApprovalStatus.INVALIDATED.value,
    ApprovalStatus.EXECUTED.value,
    ApprovalStatus.BLOCKED.value,
    ApprovalStatus.ERROR.value,
})

_ALLOWED_TRANSITIONS = {
    ApprovalStatus.PENDING.value: {
        ApprovalStatus.APPROVED.value,
        ApprovalStatus.DENIED.value,
        ApprovalStatus.EXPIRED.value,
        ApprovalStatus.INVALIDATED.value,
        ApprovalStatus.EXECUTED.value,
        ApprovalStatus.BLOCKED.value,
        ApprovalStatus.ERROR.value,
    },
    ApprovalStatus.APPROVED.value: {
        ApprovalStatus.EXECUTED.value,
        ApprovalStatus.BLOCKED.value,
        ApprovalStatus.ERROR.value,
        ApprovalStatus.INVALIDATED.value,
    },
}


@dataclass(frozen=True)
class PendingApproval:
    """One durable approval/evidence record."""

    request_id: str
    session_id: str
    client_id: str | None
    downstream_server: str
    tool_name: str
    action_class: str
    risk_class: str
    resource_hash: str | None
    payload_hash: str
    policy_id: str
    policy_rule_id: str | None
    policy_context_hash: str
    status: str
    created_at: int
    expires_at: int | None
    prev_event_hash: str | None = None
    decision_audit_id: str | None = None
    decision_receipt_sha256: str | None = None
    approval_token_hash: str | None = None
    approval_decided_at: int | None = None
    approval_decided_by: str | None = None
    result_status: str | None = None
    result_hash: str | None = None
    error_class: str | None = None
    approval_scope: str | None = None
    granted_scope_expires_at: int | None = None
    matched_policy_rule: str | None = None
    user_decision_timestamp: int | None = None
    granted_by_request_id: str | None = None
    approval_grant_jcs: str | None = None
    action_gate_metadata_jcs: str | None = None


@dataclass(frozen=True)
class RecoveryReport:
    """Summary returned after startup recovery."""

    total_records: int
    pending_before: int
    pending_after: int
    expired_request_ids: tuple[str, ...]
    stale_approval_request_ids: tuple[str, ...] = ()


_COLUMNS = tuple(field.name for field in fields(PendingApproval))
_OPTIONAL_COLUMNS = {
    "client_id",
    "resource_hash",
    "expires_at",
    "prev_event_hash",
    "policy_rule_id",
    "decision_audit_id",
    "decision_receipt_sha256",
    "approval_token_hash",
    "approval_decided_at",
    "approval_decided_by",
    "result_status",
    "result_hash",
    "error_class",
    "approval_scope",
    "granted_scope_expires_at",
    "matched_policy_rule",
    "user_decision_timestamp",
    "granted_by_request_id",
    "approval_grant_jcs",
    "action_gate_metadata_jcs",
}
_TRANSITION_FIELDS = {
    "decision_audit_id",
    "decision_receipt_sha256",
    "approval_token_hash",
    "approval_decided_at",
    "approval_decided_by",
    "result_status",
    "result_hash",
    "error_class",
    "approval_scope",
    "granted_scope_expires_at",
    "matched_policy_rule",
    "user_decision_timestamp",
    "granted_by_request_id",
    "approval_grant_jcs",
}
_HASH_COLUMNS = {
    "resource_hash",
    "payload_hash",
    "prev_event_hash",
    "approval_token_hash",
    "result_hash",
}
_HEX_HASH_COLUMNS = {"policy_context_hash", "decision_receipt_sha256"}


class ApprovalEvidenceStore:
    """SQLite-backed durable store for local approval/evidence state."""

    def __init__(self, db_path: Path, *, max_records: int = DEFAULT_MAX_RECORDS):
        if max_records <= 0:
            raise ValueError("max_records must be positive")
        self.db_path = db_path.expanduser()
        self.max_records = max_records
        self._lock = threading.RLock()
        self._ensure_db_file()
        self._conn = sqlite3.connect(str(self.db_path), timeout=5.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._configure_connection()
        self._apply_schema()
        self._secure_auxiliary_files()

    def close(self) -> None:
        """Close the SQLite connection."""

        with self._lock:
            self._conn.close()

    def __enter__(self) -> "ApprovalEvidenceStore":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()

    def write_pending(self, record: PendingApproval) -> None:
        """Atomically persist a pending approval before any UI render."""

        self._validate_pending_record(record)
        with self._lock:
            self._begin()
            try:
                count = self._conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
                if count >= self.max_records:
                    raise ApprovalEvidenceCapacityError(
                        "approval evidence store record cap reached; operator pruning required"
                    )
                existing = self._conn.execute(
                    "SELECT 1 FROM pending_approvals WHERE request_id = ?",
                    (record.request_id,),
                ).fetchone()
                if existing is not None:
                    raise ApprovalEvidenceDuplicateError(
                        f"pending approval already exists: {record.request_id}"
                    )
                prev_event_hash, append_only = self._compute_chain_link_for_insert_locked(record)
                record = replace(record, prev_event_hash=prev_event_hash)
                values = _record_values(record)
                placeholders = ", ".join("?" for _ in _COLUMNS)
                # SQL is safe: _COLUMNS is static and values are bound.
                self._conn.execute(
                    f"INSERT INTO pending_approvals ({', '.join(_COLUMNS)}) VALUES ({placeholders})",  # nosec B608
                    values,
                )
                if not append_only:
                    self._rebuild_chain_locked()
                self._conn.commit()
                self._secure_auxiliary_files()
            except Exception:
                self._conn.rollback()
                raise

    def get_pending(self, request_id: str) -> PendingApproval | None:
        """Return the approval record for a request ID, if present."""

        with self._lock:
            # SQL is safe: _COLUMNS is static and request_id is bound.
            row = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE request_id = ?",  # nosec B608
                (request_id,),
            ).fetchone()
        return None if row is None else _row_to_record(row)

    def list_pending(self, *, since_timestamp: int | None = None) -> list[PendingApproval]:
        """List non-expired pending approvals, optionally filtered by creation time."""

        with self._lock:
            if since_timestamp is None:
                # SQL is safe: _COLUMNS is static and status is bound.
                rows = self._conn.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE status = ? "  # nosec B608
                    "ORDER BY created_at, request_id",
                    (ApprovalStatus.PENDING.value,),
                ).fetchall()
            else:
                # SQL is safe: _COLUMNS is static and filters are bound.
                rows = self._conn.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE status = ? "  # nosec B608
                    "AND created_at >= ? ORDER BY created_at, request_id",
                    (ApprovalStatus.PENDING.value, since_timestamp),
                ).fetchall()
        return [_row_to_record(row) for row in rows]

    def transition(self, request_id: str, new_status: str, **fields: Any) -> PendingApproval:
        """Atomically transition approval state with state-machine validation."""

        normalized = _normalize_status(new_status)
        unknown = sorted(set(fields) - _TRANSITION_FIELDS)
        if unknown:
            raise ApprovalEvidenceTransitionError(
                f"unknown transition field(s): {', '.join(unknown)}"
            )
        with self._lock:
            self._begin()
            try:
                # SQL is safe: _COLUMNS is static and request_id is bound.
                row = self._conn.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE request_id = ?",  # nosec B608
                    (request_id,),
                ).fetchone()
                if row is None:
                    raise ApprovalEvidenceNotFoundError(f"approval record not found: {request_id}")
                record = _row_to_record(row)
                self._validate_transition(record.status, normalized)
                updates = dict(fields)
                now_timestamp = int(time.time())
                if normalized in {ApprovalStatus.APPROVED.value, ApprovalStatus.DENIED.value}:
                    if not updates.get("approval_token_hash"):
                        raise ApprovalEvidenceTransitionError(
                            "approval_token_hash is required for approval decisions"
                        )
                    updates.setdefault("approval_decided_at", now_timestamp)
                if normalized in {
                    ApprovalStatus.EXECUTED.value,
                    ApprovalStatus.BLOCKED.value,  # claim-check: allow terminal enum vocabulary in transition guard
                    ApprovalStatus.ERROR.value,
                }:
                    updates.setdefault("result_status", normalized)
                if normalized == ApprovalStatus.EXPIRED.value:
                    updates.setdefault("error_class", "approval_expired")
                updates["status"] = normalized
                self._validate_transition_fields(updates)
                assignments = ", ".join(f"{column} = ?" for column in updates)
                # SQL is safe: assignment columns are restricted and values are bound.
                self._conn.execute(
                    f"UPDATE pending_approvals SET {assignments} WHERE request_id = ?",  # nosec B608
                    (*updates.values(), request_id),
                )
                self._rebuild_chain_locked()
                self._conn.commit()
                self._secure_auxiliary_files()
            except Exception:
                self._conn.rollback()
                raise
        updated = self.get_pending(request_id)
        if updated is None:
            raise ApprovalEvidenceNotFoundError(f"approval record not found: {request_id}")
        return updated

    def annotate_linked_execution(
        self,
        parent_request_id: str,
        *,
        result_status: str,
        result_hash: str | None = None,
    ) -> PendingApproval:
        """Mirror a child retry execution outcome onto an approved parent row.

        The parent approval status stays ``approved`` so grant semantics and
        existing retry tests remain unchanged, while export/events can surface
        ``result_status=executed`` on the parent record.
        """

        normalized_status = _normalize_status(result_status)
        if normalized_status not in {
            ApprovalStatus.EXECUTED.value,
            ApprovalStatus.BLOCKED.value,  # claim-check: allow terminal enum vocabulary in linked-execution guard
            ApprovalStatus.ERROR.value,
        }:
            raise ApprovalEvidenceTransitionError(
                "linked execution annotation requires a terminal result_status"
            )
        updates: dict[str, Any] = {"result_status": normalized_status}
        if result_hash is not None:
            updates["result_hash"] = result_hash
        self._validate_transition_fields(updates)
        with self._lock:
            self._begin()
            try:
                row = self._conn.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE request_id = ?",  # nosec B608
                    (parent_request_id,),
                ).fetchone()
                if row is None:
                    raise ApprovalEvidenceNotFoundError(
                        f"approval record not found: {parent_request_id}"
                    )
                record = _row_to_record(row)
                if record.status != ApprovalStatus.APPROVED.value:
                    return record
                assignments = ", ".join(f"{column} = ?" for column in updates)
                self._conn.execute(
                    f"UPDATE pending_approvals SET {assignments} WHERE request_id = ?",  # nosec B608
                    (*updates.values(), parent_request_id),
                )
                self._rebuild_chain_locked()
                self._conn.commit()
                self._secure_auxiliary_files()
            except Exception:
                self._conn.rollback()
                raise
        updated = self.get_pending(parent_request_id)
        if updated is None:
            raise ApprovalEvidenceNotFoundError(
                f"approval record not found: {parent_request_id}"
            )
        return updated

    def record_terminal_deny(
        self,
        *,
        request_id: str,
        session_id: str,
        client_id: str | None,
        downstream_server: str,
        tool_name: str,
        risk_class: str,
        resource_hash: str | None,
        payload_hash: str,
        policy_id: str,
        policy_rule_id: str | None,
        policy_context_hash: str,
        created_at: int,
        reason: str,
        action_gate_metadata_jcs: str | None = None,
    ) -> PendingApproval:
        """Persist a pre-approval local deny as a terminal evidence record.

        Used for proxy decisions that reject a ``tools/call`` before the approval
        flow runs (for example a ``secret_path_blocked`` hard-deny). The record is
        inserted and transitioned in one SQLite transaction with
        ``error_class=reason``. The call site does not register an approval
        prompt; the persisted fields are the hashes/metadata supplied by the
        caller, without raw arguments, file paths, or secrets.

        Evidence: test_record_terminal_deny_writes_single_blocked_record and
        test_record_terminal_deny_rolls_back_on_transition_error cover the
        terminal status and rollback behavior.
        """

        record = PendingApproval(
            request_id=request_id,
            session_id=session_id,
            client_id=client_id,
            downstream_server=downstream_server,
            tool_name=tool_name,
            action_class=risk_class,
            risk_class=risk_class,
            resource_hash=resource_hash,
            payload_hash=payload_hash,
            policy_id=policy_id,
            policy_rule_id=policy_rule_id,
            policy_context_hash=policy_context_hash,
            status=ApprovalStatus.PENDING.value,
            created_at=created_at,
            expires_at=None,
            action_gate_metadata_jcs=action_gate_metadata_jcs,
        )
        self._validate_pending_record(record)
        normalized = ApprovalStatus.BLOCKED.value  # claim-check: allow tested terminal status
        with self._lock:
            self._begin()
            try:
                count = self._conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
                if count >= self.max_records:
                    raise ApprovalEvidenceCapacityError(
                        "approval evidence store record cap reached; operator pruning required"
                    )
                existing = self._conn.execute(
                    "SELECT 1 FROM pending_approvals WHERE request_id = ?",
                    (record.request_id,),
                ).fetchone()
                if existing is not None:
                    raise ApprovalEvidenceDuplicateError(
                        f"pending approval already exists: {record.request_id}"
                    )
                prev_event_hash, append_only = self._compute_chain_link_for_insert_locked(record)
                record = replace(record, prev_event_hash=prev_event_hash)
                values = _record_values(record)
                placeholders = ", ".join("?" for _ in _COLUMNS)
                # Static column list; values are bound parameters.
                self._conn.execute(
                    f"INSERT INTO pending_approvals ({', '.join(_COLUMNS)}) VALUES ({placeholders})",  # nosec B608
                    values,
                )
                self._validate_transition(record.status, normalized)
                updates = {
                    "error_class": reason,
                    "result_status": normalized,
                    "status": normalized,
                }
                self._validate_transition_fields(updates)
                assignments = ", ".join(f"{column} = ?" for column in updates)
                # Assignment columns are restricted; values are bound parameters.
                self._conn.execute(
                    f"UPDATE pending_approvals SET {assignments} WHERE request_id = ?",  # nosec B608
                    (*updates.values(), request_id),
                )
                if not append_only:
                    self._rebuild_chain_locked()
                self._conn.commit()
                self._secure_auxiliary_files()
            except Exception:
                self._conn.rollback()
                raise
        updated = self.get_pending(request_id)
        if updated is None:
            raise ApprovalEvidenceNotFoundError(f"approval record not found: {request_id}")
        return updated

    def annotate_controlled_path_metadata(
        self,
        request_id: str,
        *,
        metadata_jcs: str,
    ) -> PendingApproval:
        """Attach bounded controlled-path metadata to an existing evidence row."""

        with self._lock:
            self._begin()
            try:
                row = self._conn.execute(
                    "SELECT 1 FROM pending_approvals WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if row is None:
                    raise ApprovalEvidenceNotFoundError(
                        f"approval record not found: {request_id}"
                    )
                self._conn.execute(
                    "UPDATE pending_approvals SET action_gate_metadata_jcs = ? "
                    "WHERE request_id = ?",
                    (metadata_jcs, request_id),
                )
                self._rebuild_chain_locked()
                self._conn.commit()
                self._secure_auxiliary_files()
            except Exception:
                self._conn.rollback()
                raise
        updated = self.get_pending(request_id)
        if updated is None:
            raise ApprovalEvidenceNotFoundError(f"approval record not found: {request_id}")
        return updated

    def record_allow_execution(
        self,
        *,
        request_id: str,
        session_id: str,
        client_id: str | None,
        downstream_server: str,
        tool_name: str,
        action_class: str,
        risk_class: str,
        resource_hash: str | None,
        payload_hash: str,
        policy_id: str,
        policy_rule_id: str | None,
        policy_context_hash: str,
        created_at: int,
        result_hash: str,
        action_gate_metadata_jcs: str | None = None,
    ) -> PendingApproval:
        """Persist a local ALLOW execution as a terminal executed evidence record."""

        record = PendingApproval(
            request_id=request_id,
            session_id=session_id,
            client_id=client_id,
            downstream_server=downstream_server,
            tool_name=tool_name,
            action_class=action_class,
            risk_class=risk_class,
            resource_hash=resource_hash,
            payload_hash=payload_hash,
            policy_id=policy_id,
            policy_rule_id=policy_rule_id,
            policy_context_hash=policy_context_hash,
            status=ApprovalStatus.PENDING.value,
            created_at=created_at,
            expires_at=None,
            action_gate_metadata_jcs=action_gate_metadata_jcs,
        )
        self._validate_pending_record(record)
        normalized = ApprovalStatus.EXECUTED.value
        with self._lock:
            self._begin()
            try:
                count = self._conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
                if count >= self.max_records:
                    raise ApprovalEvidenceCapacityError(
                        "approval evidence store record cap reached; operator pruning required"
                    )
                existing = self._conn.execute(
                    "SELECT 1 FROM pending_approvals WHERE request_id = ?",
                    (record.request_id,),
                ).fetchone()
                if existing is not None:
                    raise ApprovalEvidenceDuplicateError(
                        f"pending approval already exists: {record.request_id}"
                    )
                prev_event_hash, append_only = self._compute_chain_link_for_insert_locked(record)
                record = replace(record, prev_event_hash=prev_event_hash)
                values = _record_values(record)
                placeholders = ", ".join("?" for _ in _COLUMNS)
                self._conn.execute(
                    f"INSERT INTO pending_approvals ({', '.join(_COLUMNS)}) VALUES ({placeholders})",  # nosec B608
                    values,
                )
                self._validate_transition(record.status, normalized)
                updates = {
                    "result_status": normalized,
                    "result_hash": result_hash,
                    "status": normalized,
                }
                self._validate_transition_fields(updates)
                assignments = ", ".join(f"{column} = ?" for column in updates)
                self._conn.execute(
                    f"UPDATE pending_approvals SET {assignments} WHERE request_id = ?",  # nosec B608
                    (*updates.values(), request_id),
                )
                if not append_only:
                    self._rebuild_chain_locked()
                self._conn.commit()
                self._secure_auxiliary_files()
            except Exception:
                self._conn.rollback()
                raise
        updated = self.get_pending(request_id)
        if updated is None:
            raise ApprovalEvidenceNotFoundError(f"approval record not found: {request_id}")
        return updated

    def expire_overdue(self, *, now_timestamp: int | None = None) -> list[str]:
        """Mark pending records past expires_at as expired."""

        now = int(time.time()) if now_timestamp is None else int(now_timestamp)
        with self._lock:
            self._begin()
            try:
                rows = self._conn.execute(
                    "SELECT request_id FROM pending_approvals WHERE status = ? "
                    "AND expires_at IS NOT NULL AND expires_at <= ? ORDER BY created_at, request_id",
                    (ApprovalStatus.PENDING.value, now),
                ).fetchall()
                request_ids = [str(row["request_id"]) for row in rows]
                if request_ids:
                    self._conn.executemany(
                        "UPDATE pending_approvals SET status = ?, error_class = ? "
                        "WHERE request_id = ?",
                        [
                            (ApprovalStatus.EXPIRED.value, "approval_expired", request_id)
                            for request_id in request_ids
                        ],
                    )
                    self._rebuild_chain_locked()
                self._conn.commit()
                self._secure_auxiliary_files()
            except Exception:
                self._conn.rollback()
                raise
        return request_ids

    def expire_stale_approvals(
        self,
        *,
        now_timestamp: int | None = None,
        grace_seconds: int = 3600,
    ) -> list[str]:
        """Invalidate approved records that never reached an execution result."""

        if grace_seconds < 0:
            raise ValueError("grace_seconds must be non-negative")
        now = int(time.time()) if now_timestamp is None else int(now_timestamp)
        cutoff = now - int(grace_seconds)
        with self._lock:
            rows = self._conn.execute(
                "SELECT request_id FROM pending_approvals "
                "WHERE status = ? AND approval_decided_at IS NOT NULL "
                "AND approval_decided_at <= ? "
                "AND (result_status IS NULL OR result_status != ?) "
                "ORDER BY created_at, request_id",
                (
                    ApprovalStatus.APPROVED.value,
                    cutoff,
                    ApprovalStatus.EXECUTED.value,
                ),
            ).fetchall()
            request_ids = [str(row["request_id"]) for row in rows]
        for request_id in request_ids:
            self.transition(
                request_id,
                ApprovalStatus.INVALIDATED.value,
                error_class="approval_stale_no_execution",
            )
        return request_ids

    def recover_on_startup(
        self,
        *,
        stale_approval_grace_seconds: int = 3600,
        now_timestamp: int | None = None,
    ) -> RecoveryReport:
        """Recover local approval state without approving anything."""

        pending_before = self._count_status(ApprovalStatus.PENDING.value)
        now = int(time.time()) if now_timestamp is None else int(now_timestamp)
        expired = tuple(self.expire_overdue(now_timestamp=now))
        stale_approvals = tuple(self.expire_stale_approvals(
            now_timestamp=now,
            grace_seconds=stale_approval_grace_seconds,
        ))
        pending_after = self._count_status(ApprovalStatus.PENDING.value)
        return RecoveryReport(
            total_records=self._count_records(),
            pending_before=pending_before,
            pending_after=pending_after,
            expired_request_ids=expired,
            stale_approval_request_ids=stale_approvals,
        )

    def list_records(
        self,
        *,
        since_timestamp: int | None = None,
        until_timestamp: int | None = None,
        request_ids: Iterable[str] | None = None,
    ) -> list[PendingApproval]:
        """List evidence records in deterministic chain order."""

        clauses: list[str] = []
        params: list[Any] = []
        if since_timestamp is not None:
            clauses.append("created_at >= ?")
            params.append(int(since_timestamp))
        if until_timestamp is not None:
            clauses.append("created_at <= ?")
            params.append(int(until_timestamp))
        ids = tuple(request_ids or ())
        if ids:
            placeholders = ", ".join("?" for _ in ids)
            clauses.append(f"request_id IN ({placeholders})")
            params.extend(ids)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            # SQL is safe: _COLUMNS is static and where clauses are validated.
            rows = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals "  # nosec B608
                f"{where} ORDER BY created_at, request_id",
                params,
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def find_active_similar_grant(
        self,
        *,
        downstream_server: str,
        tool_name: str,
        policy_rule_id: str | None,
        risk_class: str,
        policy_context_hash: str,
        resource_hash: str | None,
        now_timestamp: int,
    ) -> PendingApproval | None:
        """Return a still-active similar-scope approval grant for an exact match.

        The match is bound to ``policy_context_hash`` (which folds in policy_id,
        decision_mode, risk_class, policy_rule_id, and the policy schema version)
        so a similar_5m grant cannot be reused across policy-context drift such as
        a hot-reload that changes policy_id or decision_mode.
        """

        reusable_statuses = (
            ApprovalStatus.APPROVED.value,
            ApprovalStatus.EXECUTED.value,
            ApprovalStatus.BLOCKED.value,
            ApprovalStatus.ERROR.value,
        )
        placeholders = ", ".join("?" for _ in reusable_statuses)
        with self._lock:
            # SQL is safe: _COLUMNS is static and filters are bound.
            row = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals "  # nosec B608
                f"WHERE status IN ({placeholders}) "
                "AND approval_scope = ? AND granted_scope_expires_at > ? "
                "AND downstream_server = ? AND tool_name = ? AND risk_class = ? "
                "AND policy_rule_id IS ? AND policy_context_hash = ? AND resource_hash IS ? "
                "ORDER BY granted_scope_expires_at DESC, created_at DESC, request_id DESC "
                "LIMIT 1",
                (
                    *reusable_statuses,
                    "similar_5m",
                    int(now_timestamp),
                    downstream_server,
                    tool_name,
                    risk_class,
                    policy_rule_id,
                    policy_context_hash,
                    resource_hash,
                ),
            ).fetchone()
        return None if row is None else _row_to_record(row)

    def find_active_exact_grant(
        self,
        *,
        downstream_server: str,
        tool_name: str,
        policy_rule_id: str | None,
        risk_class: str,
        policy_context_hash: str,
        resource_hash: str | None,
        payload_hash: str,
        now_timestamp: int,
    ) -> PendingApproval | None:
        """Return one unconsumed exact approval grant for an identical retry.

        The match is bound to ``policy_context_hash`` (which folds in policy_id,
        decision_mode, risk_class, policy_rule_id, and the policy schema version)
        so an exact grant cannot be reused across policy-context drift such as a
        hot-reload that changes policy_id or decision_mode.
        """

        with self._lock:
            # SQL is safe: _COLUMNS is static and filters are bound.
            row = self._conn.execute(
                f"SELECT {', '.join('parent.' + column for column in _COLUMNS)} "  # nosec B608
                "FROM pending_approvals parent "
                "WHERE parent.status = ? "
                "AND parent.approval_scope = ? "
                "AND parent.granted_by_request_id IS NULL "
                "AND (parent.expires_at IS NULL OR parent.expires_at > ?) "
                "AND parent.downstream_server = ? "
                "AND parent.tool_name = ? "
                "AND parent.risk_class = ? "
                "AND parent.policy_rule_id IS ? "
                "AND parent.policy_context_hash = ? "
                "AND parent.resource_hash IS ? "
                "AND parent.payload_hash = ? "
                "AND NOT EXISTS ("
                "SELECT 1 FROM pending_approvals child "
                "WHERE child.granted_by_request_id = parent.request_id"
                ") "
                "ORDER BY parent.created_at, parent.request_id "
                "LIMIT 1",
                (
                    ApprovalStatus.APPROVED.value,
                    "exact",
                    int(now_timestamp),
                    downstream_server,
                    tool_name,
                    risk_class,
                    policy_rule_id,
                    policy_context_hash,
                    resource_hash,
                    payload_hash,
                ),
            ).fetchone()
        return None if row is None else _row_to_record(row)

    def vacuum_terminal_records(self, *, before_timestamp: int) -> int:
        """Delete old terminal records and reconstruct the remaining chain."""

        terminal = tuple(sorted(TERMINAL_STATUSES))
        placeholders = ", ".join("?" for _ in terminal)
        with self._lock:
            self._begin()
            try:
                # SQL is safe: terminal status placeholders and cutoff are controlled.
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM pending_approvals "
                    f"WHERE status IN ({placeholders}) AND created_at < ?",  # nosec B608
                    (*terminal, int(before_timestamp)),
                ).fetchone()
                deleted = int(row[0])
                if deleted:
                    # SQL is safe: terminal status placeholders and cutoff are controlled.
                    self._conn.execute(
                        "DELETE FROM pending_approvals "
                        f"WHERE status IN ({placeholders}) AND created_at < ?",  # nosec B608
                        (*terminal, int(before_timestamp)),
                    )
                    self._rebuild_chain_locked()
                self._conn.commit()
                self._secure_auxiliary_files()
            except Exception:
                self._conn.rollback()
                raise
        return deleted

    def _ensure_db_file(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.db_path.parent, 0o700)
        except PermissionError:
            pass
        if self.db_path.exists():
            os.chmod(self.db_path, 0o600)
            return
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        fd = os.open(self.db_path, flags, 0o600)
        os.close(fd)

    def _secure_auxiliary_files(self) -> None:
        for suffix in ("-wal", "-shm"):
            aux_path = Path(f"{self.db_path}{suffix}")
            if aux_path.exists():
                os.chmod(aux_path, 0o600)

    def _configure_connection(self) -> None:
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")

    def _apply_schema(self) -> None:
        with self._lock:
            self._begin()
            try:
                self._conn.execute(
                    "CREATE TABLE IF NOT EXISTS evidence_schema_version (version INTEGER NOT NULL)"
                )
                self._conn.execute(_CREATE_PENDING_APPROVALS_SQL)
                self._ensure_optional_columns()
                rows = self._conn.execute(
                    "SELECT version FROM evidence_schema_version"
                ).fetchall()
                if not rows:
                    self._conn.execute(
                        "INSERT INTO evidence_schema_version (version) VALUES (?)",
                        (EVIDENCE_SCHEMA_VERSION,),
                    )
                    self._rebuild_chain_locked()
                else:
                    version = max(int(row["version"]) for row in rows)
                    if version > EVIDENCE_SCHEMA_VERSION:
                        raise ApprovalEvidenceSchemaError(
                            f"evidence schema version {version} is newer than supported version "
                            f"{EVIDENCE_SCHEMA_VERSION}"
                        )
                    if version < 1:
                        raise ApprovalEvidenceSchemaError(
                            f"evidence schema version {version} is unsupported"
                        )
                    if version < EVIDENCE_SCHEMA_VERSION:
                        self._migrate_schema_locked(version)
                self._validate_chain_locked()
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def _ensure_optional_columns(self) -> None:
        existing = {
            str(row["name"])
            for row in self._conn.execute("PRAGMA table_info(pending_approvals)").fetchall()
        }
        for column, column_type in {
            "approval_scope": "TEXT NULL",
            "granted_scope_expires_at": "INTEGER NULL",
            "matched_policy_rule": "TEXT NULL",
            "user_decision_timestamp": "INTEGER NULL",
            "prev_event_hash": "TEXT NULL",
            "granted_by_request_id": "TEXT NULL",
            "approval_grant_jcs": "TEXT NULL",
            "action_gate_metadata_jcs": "TEXT NULL",
        }.items():
            if column not in existing:
                self._conn.execute(f"ALTER TABLE pending_approvals ADD COLUMN {column} {column_type}")

    def _migrate_schema_locked(self, version: int) -> None:
        if version in {1, 2}:
            self._rebuild_chain_locked()
            self._set_schema_version_locked(3)
            self._migrate_v3_to_v4_locked()
            return
        if version == 3:
            self._migrate_v3_to_v4_locked()
            return
        raise ApprovalEvidenceSchemaError(f"evidence schema version {version} is unsupported")

    def _migrate_v3_to_v4_locked(self) -> None:
        # SQLite cannot relax a NOT NULL column constraint in place; rebuild the table.
        columns = ", ".join(_COLUMNS)
        self._conn.execute(_CREATE_PENDING_APPROVALS_MIGRATION_SQL)
        # SQL is safe: migration columns are restricted to static _COLUMNS.
        self._conn.execute(
            f"INSERT INTO pending_approvals_new ({columns}) "  # nosec B608
            f"SELECT {columns} FROM pending_approvals"
        )
        self._conn.execute("DROP TABLE pending_approvals")
        self._conn.execute("ALTER TABLE pending_approvals_new RENAME TO pending_approvals")
        self._set_schema_version_locked(EVIDENCE_SCHEMA_VERSION)
        self._validate_chain_locked()

    def _set_schema_version_locked(self, version: int) -> None:
        self._conn.execute("DELETE FROM evidence_schema_version")
        self._conn.execute(
            "INSERT INTO evidence_schema_version (version) VALUES (?)",
            (version,),
        )

    def _compute_chain_link_for_insert_locked(self, record: PendingApproval) -> tuple[str, bool]:
        # SQL is safe: _COLUMNS is static.
        row = self._conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals "  # nosec B608
            "ORDER BY created_at DESC, request_id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return GENESIS_PREV_EVENT_HASH, True
        last_record = _row_to_record(row)
        if (record.created_at, record.request_id) > (
            last_record.created_at,
            last_record.request_id,
        ):
            return record_hash(last_record), True
        return GENESIS_PREV_EVENT_HASH, False

    def _rebuild_chain_locked(self) -> None:
        # SQL is safe: _COLUMNS is static.
        rows = self._conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals ORDER BY created_at, request_id"  # nosec B608
        ).fetchall()
        prev_hash = GENESIS_PREV_EVENT_HASH
        for row in rows:
            record = _row_to_record(row)
            self._conn.execute(
                "UPDATE pending_approvals SET prev_event_hash = ? WHERE request_id = ?",
                (prev_hash, record.request_id),
            )
            data = _record_dict(record)
            data["prev_event_hash"] = prev_hash
            prev_hash = record_hash(data)

    def _validate_chain_locked(self) -> None:
        # SQL is safe: _COLUMNS is static.
        rows = self._conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals ORDER BY created_at, request_id"  # nosec B608
        ).fetchall()
        prev_hash = GENESIS_PREV_EVENT_HASH
        for row in rows:
            record = _row_to_record(row)
            if record.prev_event_hash is None:
                self._rebuild_chain_locked()
                return
            if record.prev_event_hash != prev_hash:
                raise ApprovalEvidenceSchemaError(
                    f"evidence hash chain mismatch at request_id {record.request_id}"
                )
            prev_hash = record_hash(record)

    def _begin(self) -> None:
        self._conn.execute("BEGIN IMMEDIATE")

    def _validate_pending_record(self, record: PendingApproval) -> None:
        if record.status != ApprovalStatus.PENDING.value:
            raise ApprovalEvidenceTransitionError("write_pending only accepts pending records")
        if record.expires_at is not None and record.expires_at <= record.created_at:
            raise ApprovalEvidenceTransitionError("expires_at must be after created_at")
        for column in _COLUMNS:
            value = getattr(record, column)
            if column in _OPTIONAL_COLUMNS:
                continue
            if isinstance(value, str):
                if not value:
                    raise ApprovalEvidenceTransitionError(f"{column} must not be empty")
            elif value is None:
                raise ApprovalEvidenceTransitionError(f"{column} is required")
        self._validate_transition_fields(_record_dict(record))

    def _validate_transition(self, current_status: str, new_status: str) -> None:
        if current_status in TERMINAL_STATUSES:
            raise ApprovalEvidenceTransitionError(
                f"cannot transition terminal approval status {current_status}"
            )
        allowed = _ALLOWED_TRANSITIONS.get(current_status, set())
        if new_status not in allowed:
            raise ApprovalEvidenceTransitionError(
                f"invalid approval transition: {current_status} -> {new_status}"
            )

    def _validate_transition_fields(self, values: dict[str, Any]) -> None:
        for column, value in values.items():
            if value is None:
                continue
            if column in _HASH_COLUMNS:
                _require_prefixed_hash(column, value)
            elif column in _HEX_HASH_COLUMNS:
                _require_hash_like(column, value)

    def _count_status(self, status: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM pending_approvals WHERE status = ?",
                (status,),
            ).fetchone()
        return int(row[0])

    def _count_records(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()
        return int(row[0])


def _record_values(record: PendingApproval) -> tuple[Any, ...]:
    return tuple(getattr(record, column) for column in _COLUMNS)


def _record_dict(record: PendingApproval) -> dict[str, Any]:
    return {column: getattr(record, column) for column in _COLUMNS}


def record_hash(record: PendingApproval | Mapping[str, Any]) -> str:
    """Return the canonical sha256 hash for one evidence record."""

    if isinstance(record, PendingApproval):
        data = _record_dict(record)
    else:
        data = dict(record)
    data.pop("prev_event_hash", None)
    data.pop("record_hash", None)
    # Export-only linkage from an approved parent to its executed child retry row.
    data.pop("execution_record_id", None)
    # Parsed export view; canonical chain hash uses action_gate_metadata_jcs.
    data.pop("action_gate_metadata", None)
    return "sha256:" + hashlib.sha256(jcs.canonicalize(data)).hexdigest()


def _row_to_record(row: sqlite3.Row) -> PendingApproval:
    return PendingApproval(**{column: row[column] for column in _COLUMNS})


def _normalize_status(value: str | ApprovalStatus) -> str:
    raw = value.value if isinstance(value, ApprovalStatus) else value
    if raw not in {status.value for status in ApprovalStatus}:
        raise ApprovalEvidenceTransitionError(f"unknown approval status: {raw}")
    return raw


def _require_prefixed_hash(column: str, value: Any) -> None:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ApprovalEvidenceTransitionError(f"{column} must be a sha256-prefixed hash")
    digest = value[len("sha256:"):]
    if len(digest) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in digest):
        raise ApprovalEvidenceTransitionError(
            f"{column} must be a sha256-prefixed hash with 64 hex chars"
        )


def _require_hash_like(column: str, value: Any) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdefABCDEF" for ch in value)
    ):
        raise ApprovalEvidenceTransitionError(f"{column} must be a 64-char hex hash")


_CREATE_PENDING_APPROVALS_SQL = """
CREATE TABLE IF NOT EXISTS pending_approvals (
    request_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    client_id TEXT NULL,
    downstream_server TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    action_class TEXT NOT NULL,
    risk_class TEXT NOT NULL,
    resource_hash TEXT NULL,
    payload_hash TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_rule_id TEXT NULL,
    policy_context_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    prev_event_hash TEXT NULL,
    decision_audit_id TEXT NULL,
    decision_receipt_sha256 TEXT NULL,
    approval_token_hash TEXT NULL,
    approval_decided_at INTEGER NULL,
    approval_decided_by TEXT NULL,
    result_status TEXT NULL,
    result_hash TEXT NULL,
    error_class TEXT NULL,
    approval_scope TEXT NULL,
    granted_scope_expires_at INTEGER NULL,
    matched_policy_rule TEXT NULL,
    user_decision_timestamp INTEGER NULL,
    granted_by_request_id TEXT NULL,
    approval_grant_jcs TEXT NULL,
    action_gate_metadata_jcs TEXT NULL
)
"""

_CREATE_PENDING_APPROVALS_MIGRATION_SQL = _CREATE_PENDING_APPROVALS_SQL.replace(
    "CREATE TABLE IF NOT EXISTS pending_approvals",
    "CREATE TABLE pending_approvals_new",
    1,
)


__all__ = [
    "ApprovalEvidenceCapacityError",
    "ApprovalEvidenceDuplicateError",
    "ApprovalEvidenceError",
    "ApprovalEvidenceNotFoundError",
    "ApprovalEvidenceSchemaError",
    "ApprovalEvidenceStore",
    "ApprovalEvidenceTransitionError",
    "ApprovalStatus",
    "GENESIS_PREV_EVENT_HASH",
    "PendingApproval",
    "RecoveryReport",
    "TERMINAL_STATUSES",
    "record_hash",
]
