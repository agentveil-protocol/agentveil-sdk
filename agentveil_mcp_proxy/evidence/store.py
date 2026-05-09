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

from dataclasses import dataclass, fields
from enum import Enum
import hashlib
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterable, Mapping

import jcs


EVIDENCE_SCHEMA_VERSION = 2
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
    },
    ApprovalStatus.APPROVED.value: {
        ApprovalStatus.EXECUTED.value,
        ApprovalStatus.BLOCKED.value,
        ApprovalStatus.ERROR.value,
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
    expires_at: int
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


@dataclass(frozen=True)
class RecoveryReport:
    """Summary returned after startup recovery."""

    total_records: int
    pending_before: int
    pending_after: int
    expired_request_ids: tuple[str, ...]


_COLUMNS = tuple(field.name for field in fields(PendingApproval))
_OPTIONAL_COLUMNS = {
    "client_id",
    "resource_hash",
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
        values = _record_values(record)
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
                placeholders = ", ".join("?" for _ in _COLUMNS)
                self._conn.execute(
                    f"INSERT INTO pending_approvals ({', '.join(_COLUMNS)}) VALUES ({placeholders})",
                    values,
                )
                self._rebuild_chain_locked()
                self._conn.commit()
                self._secure_auxiliary_files()
            except Exception:
                self._conn.rollback()
                raise

    def get_pending(self, request_id: str) -> PendingApproval | None:
        """Return the approval record for a request ID, if present."""

        with self._lock:
            row = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        return None if row is None else _row_to_record(row)

    def list_pending(self, *, since_timestamp: int | None = None) -> list[PendingApproval]:
        """List non-expired pending approvals, optionally filtered by creation time."""

        with self._lock:
            if since_timestamp is None:
                rows = self._conn.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE status = ? "
                    "ORDER BY created_at, request_id",
                    (ApprovalStatus.PENDING.value,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE status = ? "
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
                row = self._conn.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE request_id = ?",
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
                    ApprovalStatus.BLOCKED.value,
                    ApprovalStatus.ERROR.value,
                }:
                    updates.setdefault("result_status", normalized)
                if normalized == ApprovalStatus.EXPIRED.value:
                    updates.setdefault("error_class", "approval_expired")
                updates["status"] = normalized
                self._validate_transition_fields(updates)
                assignments = ", ".join(f"{column} = ?" for column in updates)
                self._conn.execute(
                    f"UPDATE pending_approvals SET {assignments} WHERE request_id = ?",
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

    def expire_overdue(self, *, now_timestamp: int | None = None) -> list[str]:
        """Mark pending records past expires_at as expired."""

        now = int(time.time()) if now_timestamp is None else int(now_timestamp)
        with self._lock:
            self._begin()
            try:
                rows = self._conn.execute(
                    "SELECT request_id FROM pending_approvals WHERE status = ? AND expires_at <= ? "
                    "ORDER BY created_at, request_id",
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

    def recover_on_startup(self) -> RecoveryReport:
        """Recover local approval state without approving anything."""

        pending_before = self._count_status(ApprovalStatus.PENDING.value)
        expired = tuple(self.expire_overdue())
        pending_after = self._count_status(ApprovalStatus.PENDING.value)
        return RecoveryReport(
            total_records=self._count_records(),
            pending_before=pending_before,
            pending_after=pending_after,
            expired_request_ids=expired,
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
            rows = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals "
                f"{where} ORDER BY created_at, request_id",
                params,
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def vacuum_terminal_records(self, *, before_timestamp: int) -> int:
        """Delete old terminal records and reconstruct the remaining chain."""

        terminal = tuple(sorted(TERMINAL_STATUSES))
        placeholders = ", ".join("?" for _ in terminal)
        with self._lock:
            self._begin()
            try:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM pending_approvals "
                    f"WHERE status IN ({placeholders}) AND created_at < ?",
                    (*terminal, int(before_timestamp)),
                ).fetchone()
                deleted = int(row[0])
                if deleted:
                    self._conn.execute(
                        "DELETE FROM pending_approvals "
                        f"WHERE status IN ({placeholders}) AND created_at < ?",
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
        }.items():
            if column not in existing:
                self._conn.execute(f"ALTER TABLE pending_approvals ADD COLUMN {column} {column_type}")

    def _migrate_schema_locked(self, version: int) -> None:
        if version == 1:
            self._rebuild_chain_locked()
            self._conn.execute("DELETE FROM evidence_schema_version")
            self._conn.execute(
                "INSERT INTO evidence_schema_version (version) VALUES (?)",
                (EVIDENCE_SCHEMA_VERSION,),
            )
            return
        raise ApprovalEvidenceSchemaError(f"evidence schema version {version} is unsupported")

    def _rebuild_chain_locked(self) -> None:
        rows = self._conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals ORDER BY created_at, request_id"
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
        rows = self._conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals ORDER BY created_at, request_id"
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
        if record.expires_at <= record.created_at:
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
    return "sha256:" + hashlib.sha256(jcs.canonicalize(data)).hexdigest()


def _row_to_record(row: sqlite3.Row) -> PendingApproval:
    return PendingApproval(**{column: row[column] for column in _COLUMNS})


def _normalize_status(value: str | ApprovalStatus) -> str:
    raw = value.value if isinstance(value, ApprovalStatus) else value
    if raw not in {status.value for status in ApprovalStatus}:
        raise ApprovalEvidenceTransitionError(f"unknown approval status: {raw}")
    return raw


def _require_prefixed_hash(column: str, value: Any) -> None:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) <= len("sha256:"):
        raise ApprovalEvidenceTransitionError(f"{column} must be a sha256-prefixed hash")


def _require_hash_like(column: str, value: Any) -> None:
    if not isinstance(value, str) or not value:
        raise ApprovalEvidenceTransitionError(f"{column} must be a non-empty hash")


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
    expires_at INTEGER NOT NULL,
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
    user_decision_timestamp INTEGER NULL
)
"""


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
