"""Redacted execution observability helpers for approval evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from typing import Any

from agentveil_mcp_proxy.authority_boundary import parse_authority_from_metadata
from agentveil_mcp_proxy.evidence.store import ApprovalStatus, PendingApproval

_BOUNDED_RESOURCE_KEY_PREFIXES = frozenset({
    "path",
    "paths",
    "source",
    "destination",
    "file",
    "filename",
    "uri",
    "url",
    "resource",
})


def risk_class_plain_label(risk_class: str) -> str:
    """Return a plain-language risk label for Approval Center UI."""

    labels = {
        "read": "Read-only",
        "write": "Write action",
        "destructive": "Destructive action",
        # claim-check: allow "production" as an internal risk_class enum key, not a support claim.
        "production": "Release/deploy action",
        "financial": "Financial action",
        "unknown": "Unknown risk",
    }
    return labels.get(risk_class, risk_class.replace("_", " ").title())


def human_approval_summary(
    *,
    tool_name: str,
    resource_display: str | None,
) -> str:
    """Return a short user-facing summary of what the agent wants to do."""

    target = resource_display if resource_display not in (None, "", "none") else "this workspace"
    return f"The agent wants to run {tool_name} on {target}."


def bounded_approval_resource_display(resource_plain: str | None) -> str | None:
    """Return a bounded basename/path label for Approval Center default view."""

    if not resource_plain:
        return None
    prefix, _, remainder = resource_plain.partition(":")
    if prefix not in _BOUNDED_RESOURCE_KEY_PREFIXES or not remainder:
        return None
    normalized = remainder.replace("\\", "/").strip()
    if not normalized or normalized in {".", ".."}:
        return None
    basename = Path(normalized).name
    if basename:
        return basename[:120]
    return normalized[:120]


def approval_resource_display(
    *,
    resource_plain: str | None,
    resource_hashed: str | None,
) -> str | None:
    """Return the default Approval Center target label."""

    bounded = bounded_approval_resource_display(resource_plain)
    if bounded is not None:
        return bounded
    return resource_hashed


def approval_display_risk_class(
    *,
    risk_class: str,
    tool_name: str,
    action_plain: str,
    resource_plain: str | None,
) -> str:
    """Return the risk class label shown on Approval Center default pages."""

    if risk_class != "unknown":
        return risk_class
    from agentveil_mcp_proxy.classification import infer_risk_class

    return infer_risk_class(
        action_plain,
        tool=tool_name,
        resource=resource_plain,
        arguments={},
    ).value


def human_approval_reason_label(reason: str) -> str:
    """Return a plain-language reason label for one pending approval."""

    if reason == "local_approval_required":
        return "Needs your approval before it can run"
    if reason == "role_authority_denied":
        return "Not allowed for the current agent role"
    if reason.startswith("package_manager"):
        return "Package manager action needs approval"
    if "instruction" in reason:
        return "Instruction or repo surface risk detected"
    return "Needs review before it can run"


def policy_decision_plain_label(decision: str) -> str:
    """Return a plain-language policy decision label for approval proof."""

    # claim-check: allow bounded UI decision labels; behavior is covered by
    # approval proof/detail tests and does not claim host-wide protection.
    labels = {
        "approval": "Approval required",
        "allow": "Allowed",
        "block": "Stopped by policy",
        "deny": "Denied",
    }
    return labels.get(decision, decision.replace("_", " ").title())


def approval_access_plain_label(*, reason: str, policy_decision: str) -> str:
    """Return whether approval is possible or policy stopped the action."""

    if reason == "role_authority_denied" or policy_decision in {"block", "deny"}:
        return "Stopped by policy"
    if policy_decision == "approval":
        return "Approval required"
    return policy_decision_plain_label(policy_decision)


_FILESYSTEM_TOOL_NAMES = frozenset({
    "list_workspace",
    "instruction_surface_status",
    "write_file",
    "read_file",
    "get_file_info",
    "delete_file",
    "rmdir_tree",
    "move_file",
    "copy_file",
    "chmod_file",
    "create_symlink",
})


def _is_filesystem_operation(preview: Mapping[str, Any]) -> bool:
    """Return True when blast-radius preview describes a filesystem tool action."""

    tool = str(preview.get("tool", "")).lower()
    server = str(preview.get("server", "")).lower()
    if "filesystem" in server:
        return True
    if tool in _FILESYSTEM_TOOL_NAMES:
        return True
    return tool.startswith(("read_", "get_", "list_", "fetch_", "write_", "delete_", "remove_"))


def blast_radius_has_unassessed_dimensions(preview: Mapping[str, Any]) -> bool:
    """Return True when blast-radius preview includes unknown dimensions."""

    caps = preview.get("capabilities")
    if isinstance(caps, Mapping) and any(value == "unknown" for value in caps.values()):
        return True
    credential = preview.get("credential_posture")
    return credential == "unknown"


def assessed_blast_radius_lines(preview: Mapping[str, Any]) -> tuple[str, ...]:
    """Return blast-radius lines for dimensions that were actually assessed."""

    from agentveil_mcp_proxy.permission_doctor import blast_radius_lines

    return tuple(
        line
        for line in blast_radius_lines(preview)
        if not line.endswith(": unknown")
        and not line.startswith("Why approval required:")
    )


def blast_radius_unassessed_note(preview: Mapping[str, Any]) -> str | None:
    """Return a compact note when some blast-radius dimensions were not assessed."""

    if not blast_radius_has_unassessed_dimensions(preview):
        return None
    if _is_filesystem_operation(preview):
        return "Not applicable to this filesystem operation."
    return "Not evaluated by this policy mode."


def approval_proof_detail_rows(
    *,
    tool_name: str,
    resource_display: str | None,
    risk_class: str,
    reason: str,
    payload_hash: str,
    policy_rule_id: str,
    request_id: str,
    created_at: int,
    expires_at: int,
    action_gate_metadata: dict[str, Any] | None,
) -> tuple[tuple[str, str], ...]:
    """Return compact human proof rows for Approval Center detail pages."""

    metadata = action_gate_metadata if isinstance(action_gate_metadata, dict) else {}
    policy_decision = str(metadata.get("policy_decision", "approval"))
    rows: list[tuple[str, str]] = [
        ("Decision", approval_access_plain_label(reason=reason, policy_decision=policy_decision)),
        ("Why approval is required", human_approval_reason_label(reason)),
        ("Tool", tool_name),
        ("Target", resource_display or "none"),
        ("Risk", risk_class_plain_label(risk_class)),
        ("Policy rule", policy_rule_id),
    ]
    action_family = metadata.get("action_family")
    if isinstance(action_family, str) and action_family:
        rows.append(("Action family", action_family))
    for key, label in (
        ("approval_status", "Approval status"),
        ("execution_status", "Execution status"),
        ("target_reached", "Target reached"),
    ):
        value = metadata.get(key)
        if isinstance(value, bool):
            rows.append((label, "true" if value else "false"))
        elif isinstance(value, str) and value:
            rows.append((label, value))
    rows.extend([
        ("Request id", request_id),
        ("Payload hash", payload_hash),
        ("Created", str(created_at)),
        ("Expires", str(expires_at)),
    ])
    blast_radius = metadata.get("blast_radius")
    if isinstance(blast_radius, Mapping):
        for line in assessed_blast_radius_lines(blast_radius):
            if ":" not in line:
                continue
            label, value = line.split(":", 1)
            rows.append((label.strip(), value.strip()))
        note = blast_radius_unassessed_note(blast_radius)
        if note is not None:
            rows.append(("Scope note", note))
    return tuple(rows)


def approval_raw_evidence_rows(
    *,
    client_id: str,
    session_id_prefix: str,
    action_display: str,
    action_gate_metadata: dict[str, Any] | None,
) -> tuple[tuple[str, str], ...]:
    """Return bounded raw/debug rows for Approval Center advanced evidence."""

    metadata = action_gate_metadata if isinstance(action_gate_metadata, dict) else {}
    rows: list[tuple[str, str]] = [
        ("Client", client_id),
        ("Session prefix", session_id_prefix),
        ("Action", action_display),
    ]
    for key, label in (
        ("role", "Role"),
        ("authority", "Authority"),
        ("policy_decision", "Policy decision"),
        ("redirect_playbook_id", "Redirect"),
    ):
        value = metadata.get(key)
        if isinstance(value, str) and value:
            rows.append((label, value))
    blast_radius = metadata.get("blast_radius")
    if isinstance(blast_radius, Mapping):
        from agentveil_mcp_proxy.permission_doctor import blast_radius_lines

        for line in blast_radius_lines(blast_radius):
            if ":" not in line:
                continue
            label, value = line.split(":", 1)
            rows.append((f"Blast radius: {label.strip()}", value.strip()))
    return tuple(rows)


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
    action_gate_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a redacted JSON view for one loopback pending approval."""

    resource = resource_display if resource_display is not None else "none"
    payload = {
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
    if action_gate_metadata is not None:
        payload["action_gate_metadata"] = action_gate_metadata
        authority = parse_authority_from_metadata(action_gate_metadata)
        if authority is not None:
            payload["authority"] = authority
    return payload


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


def terminal_state_for_record_status(status: str) -> str | None:
    """Map durable evidence status to Approval Center terminal page state."""

    if status == ApprovalStatus.APPROVED.value:
        return "already_decided_approve"
    if status == ApprovalStatus.DENIED.value:
        return "already_decided_deny"
    if status == ApprovalStatus.EXPIRED.value:
        return "approval_expired"
    return None


def bounded_action_display(record: PendingApproval) -> str:
    """Return a bounded action label for one evidence record."""

    return f"{record.downstream_server}.{record.tool_name}"


def bounded_resource_display(record: PendingApproval) -> str:
    """Return a bounded resource label for one evidence record."""

    if not record.resource_hash:
        return "none"
    return f"hash:{record.resource_hash[:12]}"


def bounded_reason_for_record(record: PendingApproval) -> str:
    """Return a bounded reason label for one evidence record."""

    if record.error_class:
        return record.error_class
    if record.status == ApprovalStatus.APPROVED.value:
        return "user_approved"
    if record.status == ApprovalStatus.DENIED.value:
        return "user_denied"
    return "local_approval_required"


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


def parse_session_integrity_metadata(record: PendingApproval) -> dict[str, Any] | None:
    """Parse first-class session-integrity metadata from one evidence record."""

    metadata = parse_action_gate_metadata(record)
    if metadata is None:
        return None
    if metadata.get("event_type") == "session_integrity_mismatch":
        return metadata
    return None


def parse_redirect_automation_metadata(record: PendingApproval) -> dict[str, Any] | None:
    """Parse redirect-automation fields from one evidence record."""

    metadata = parse_action_gate_metadata(record)
    if metadata is None:
        return None
    if "redirect_role" not in metadata and "redirect_playbook_id" not in metadata:
        return None
    return metadata


def redirect_automation_link_valid(
    original: PendingApproval,
    follow_up: PendingApproval,
) -> bool:
    """Return True when bounded metadata links one follow-up to its original action."""

    original_meta = parse_redirect_automation_metadata(original)
    follow_meta = parse_redirect_automation_metadata(follow_up)
    if original_meta is None or follow_meta is None:
        return False
    if original_meta.get("redirect_role") != "original":
        return False
    if follow_meta.get("redirect_role") != "follow_up":
        return False
    original_request_id = str(original.request_id)
    if follow_meta.get("redirect_parent_request_id") != original_request_id:
        return False
    if follow_meta.get("original_request_id") != original_request_id:
        return False
    if original_meta.get("redirect_playbook_id") != follow_meta.get("redirect_playbook_id"):
        return False
    if original_meta.get("target_reached") is not False:
        return False
    return True


def redirect_original_record_valid(
    record: PendingApproval,
    *,
    redirect_playbook_id: str,
) -> bool:
    """Return True when one evidence record is an acceptable redirect original."""

    metadata = parse_redirect_automation_metadata(record)
    if metadata is None:
        return False
    if metadata.get("redirect_role") != "original":
        return False
    if metadata.get("redirect_playbook_id") != redirect_playbook_id:
        return False
    if metadata.get("target_reached") is not False:
        return False
    return True


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
        authority = parse_authority_from_metadata(controlled_path)
        if authority is not None:
            payload["authority"] = authority
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
