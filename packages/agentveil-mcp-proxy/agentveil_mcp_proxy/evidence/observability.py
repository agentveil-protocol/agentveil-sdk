"""Redacted execution observability helpers for approval evidence."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agentveil_mcp_proxy.evidence.store import ApprovalStatus, PendingApproval


def execution_record_id_by_parent(
    records: Sequence[PendingApproval],
) -> dict[str, str]:
    """Map approved parent request IDs to their executed child retry records."""

    mapping: dict[str, str] = {}
    for record in records:
        parent_id = record.granted_by_request_id
        if not parent_id:
            continue
        if record.status != ApprovalStatus.EXECUTED.value:
            continue
        mapping[parent_id] = record.request_id
    return mapping


def event_record_dict(
    record: PendingApproval,
    *,
    execution_record_id: str | None = None,
) -> dict[str, Any]:
    """Build a redacted event view for one evidence record."""  # claim-check: allow descriptive redaction boundary, not a security guarantee.

    payload: dict[str, Any] = {
        "timestamp": record.created_at,
        "server": record.downstream_server,
        "tool": record.tool_name,
        "risk_class": record.risk_class,
        "status": record.status,
        "result_status": record.result_status,
        "policy_rule": record.policy_rule_id,
        "record_id": record.request_id,
    }
    if record.granted_by_request_id is not None:
        payload["granted_by_request_id"] = record.granted_by_request_id
    if execution_record_id is not None:
        payload["execution_record_id"] = execution_record_id
    return payload


def format_event_record(
    record: PendingApproval,
    *,
    receipt_status: str,
    execution_record_id: str | None = None,
    timestamp_formatter: Any,
    token_formatter: Any,
) -> str:
    """Format one evidence record for human-readable events output."""

    parts = [
        f"{timestamp_formatter(record.created_at)}",
        f"server={token_formatter(record.downstream_server)}",
        f"tool={token_formatter(record.tool_name)}",
        f"risk={token_formatter(record.risk_class)}",
        f"status={token_formatter(record.status)}",
    ]
    if record.result_status is not None:
        parts.append(f"result={token_formatter(record.result_status)}")
    parts.extend([
        f"rule={token_formatter(record.policy_rule_id)}",
        f"receipt={receipt_status}",
        f"id={token_formatter(record.request_id)}",
    ])
    if record.granted_by_request_id is not None:
        parts.append(f"grant_parent={token_formatter(record.granted_by_request_id)}")
    if execution_record_id is not None:
        parts.append(f"execution_id={token_formatter(execution_record_id)}")
    return " ".join(parts)
