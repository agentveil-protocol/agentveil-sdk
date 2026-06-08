"""Redacted execution observability helpers for approval evidence."""

from __future__ import annotations

from collections.abc import Sequence
import json
from typing import Any

from agentveil_mcp_proxy.evidence.store import ApprovalStatus, PendingApproval


def pending_approval_dict(
    *,
    request_id: str,
    client_id: str,
    session_id: str,
    downstream_server: str,
    tool_name: str,
    action_display: str,
    resource_display: str | None,
    risk_class: str,
    reason: str,
    payload_hash: str,
    policy_rule_id: str,
    created_at: int,
    expires_at: int,
) -> dict[str, Any]:
    """Build a redacted JSON view for one loopback pending approval."""

    resource = resource_display if resource_display is not None else "none"
    return {
        "request_id": request_id,
        "client_id": client_id,
        "session_id_prefix": session_id[:8],
        "downstream_server": downstream_server,
        "tool_name": tool_name,
        "risk_class": risk_class,
        "reason": reason,
        "action": action_display,
        "resource": resource,
        "payload_hash": payload_hash,
        "policy_rule_id": policy_rule_id,
        "status": ApprovalStatus.PENDING.value,
        "created_at": created_at,
        "expires_at": expires_at,
    }


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


def parse_controlled_path_metadata(record: PendingApproval) -> dict[str, Any] | None:
    """Parse bounded controlled-path metadata stored on one evidence record."""

    return parse_action_gate_metadata(record)


def parse_action_gate_metadata(record: PendingApproval) -> dict[str, Any] | None:
    """Parse bounded action-gate metadata stored on one evidence record."""

    raw = record.action_gate_metadata_jcs
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


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
        "policy_rule": record.policy_rule_id,
        "record_id": record.request_id,
    }
    if record.result_status is not None:
        payload["result_status"] = record.result_status
    if record.granted_by_request_id is not None:
        payload["granted_by_request_id"] = record.granted_by_request_id
    if execution_record_id is not None:
        payload["execution_record_id"] = execution_record_id
    controlled_path = parse_controlled_path_metadata(record)
    if controlled_path is not None:
        payload["controlled_path"] = controlled_path
        if "target_reached" in controlled_path:
            payload["target_reached"] = controlled_path["target_reached"]
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
