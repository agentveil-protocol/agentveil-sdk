"""Redacted execution observability helpers for approval evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from agentveil_mcp_proxy.authority_boundary import parse_authority_from_metadata
from agentveil_mcp_proxy.evidence.store import ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.policy import derive_target_reached

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


@dataclass(frozen=True)
class DownstreamExecutionClassification:
    """Bounded downstream outcome shared by MCP evidence surfaces."""

    execution_status: str
    target_reached: bool
    error_class: str | None
    store_status: str


def classify_downstream_response(
    response: Mapping[str, Any],
    *,
    downstream_tool_call_seen: bool,
) -> DownstreamExecutionClassification:
    """Classify one downstream tools/call response for evidence truth.

    claim-check: allow "Fail closed"/"BLOCKED" name store status enum values used by
    the classifier contract; negative tests cover non-executed outcomes.
    Refuse executed unless a confirmed forwarded tools/call returns an object
    ``result`` without JSON-RPC ``error`` / MCP ``isError``.
    """

    failure = DownstreamExecutionClassification(
        execution_status=ApprovalStatus.BLOCKED.value,  # claim-check: allow enum store status
        target_reached=False,
        error_class="downstream_error",
        store_status=ApprovalStatus.BLOCKED.value,  # claim-check: allow enum store status
    )
    if "error" in response:
        return failure
    if not downstream_tool_call_seen:
        return failure
    result = response.get("result")
    if not isinstance(result, Mapping):
        return failure
    if result.get("isError") is True:
        return failure
    execution_status = ApprovalStatus.EXECUTED.value
    return DownstreamExecutionClassification(
        execution_status=execution_status,
        target_reached=derive_target_reached(
            execution_status=execution_status,
            downstream_tool_call_seen=True,
        ),
        error_class=None,
        store_status=ApprovalStatus.EXECUTED.value,
    )


def target_reached_for_evidence_record(record: PendingApproval) -> bool:
    """Return explicit metadata target_reached; omit invented success.

    claim-check: allow "never" restates the historical-evidence contract covered
    by outcome-truth negatives.
    """

    metadata = parse_action_gate_metadata(record)
    if metadata is None:
        return False
    value = metadata.get("target_reached")
    return value is True


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


_PATH_OUTSIDE_SANDBOX_USER_MESSAGE = (
    "Path is outside the configured sandbox. "
    "Use a relative path under the project workspace."
)
_TOOL_NOT_AVAILABLE_USER_MESSAGE = (
    "Controlled MCP tool is not available. Configure or enable the MCP route "
    "that advertises this tool."
)
_SECRET_PATH_BLOCKED_USER_MESSAGE = (
    "Stopped by policy: this looks like a secret-bearing path. Approval will "
    "not help for this route."
)
_RUNTIME_GATE_UNAVAILABLE_USER_MESSAGE = (
    "Stopped by policy: Runtime Gate is unavailable for this action. Approval "
    "will not help for this route."
)
_RUNTIME_GATE_BLOCKED_USER_MESSAGE = (
    "Stopped by Runtime Gate: this action was denied before execution. "
    "Approval will not help for this decision."
)
_DEFAULT_POLICY_STOP_USER_MESSAGE = (
    "Stopped by policy: this action is not allowed by local policy and cannot "
    "be approved."
)
_USER_DENIED_USER_MESSAGE = (
    "Denied by user. This action was rejected in Approval Center and will not run."
)
_CLASSIFIER_ERROR_USER_MESSAGE = (
    "Proxy could not classify this tool call. Approval will not help. "
    "Retry; report if persistent."
)
_PROXY_RUNTIME_DECISION_ERROR_USER_MESSAGE = (
    "Proxy/runtime decision error: this action could not be evaluated safely. "
    "Approval will not help. Retry; report if persistent."
)
_DEDICATED_USER_MESSAGE_REASONS = frozenset({
    "classifier_error",
    "unknown_policy_decision",
    "untrusted_runtime_decision",
    "unsupported_runtime_decision",
    "unknown_tool",
    "unknown_tool_not_advertised",
    "tool_schema_unavailable",
    "runtime_gate_not_configured",
    "runtime_gate_unavailable",
    "runtime_gate_evidence_unavailable",
    "approval_evidence_unavailable",
    "runtime_gate_block",
    "role_authority_denied",
    "path_outside_workspace",
    "secret_path_blocked",
    "user_denied",
})
_DEFAULT_HARD_DENY_NEXT_STEP = (
    "This action cannot be approved. Adjust the tool call or local policy."
)
APPROVAL_REQUIRED_INSTRUCTIONS = (
    "Approval required. Open the approval page and wait while the user approves or denies. "
    "After approval, immediately retry this exact same AgentVeil MCP tool call yourself "
    "without changing tool, target, or payload. Do not ask the user for another message."
)
APPROVAL_REQUIRED_USER_MESSAGE = APPROVAL_REQUIRED_INSTRUCTIONS
APPROVAL_NOT_DELIVERED_USER_MESSAGE = (
    "Approval required. The pending approval card was created but did not open automatically. "
    "Ask the operator to run the recovery command, then wait for approval or denial. "
    "After approval, immediately retry this exact same AgentVeil MCP tool call yourself "
    "without changing tool, target, or payload. Do not ask the user for another message."
)
_APPROVAL_REQUIRED_NEXT_STEP = (
    "Wait for the user to approve or deny in the approval page. "
    "After approval, immediately retry this exact same AgentVeil MCP tool call yourself "
    "without changing tool, target, or payload. Do not ask the user for another message."
)


def approval_center_open_recovery_command(record_id: str) -> str:
    """Return an operator recovery command containing the pending record ID."""

    return f"agentveil-mcp-proxy approval-center open --record-id {record_id}"
APPROVAL_CONTINUE_AGENT_PROMPT = (
    "Immediately retry the exact same AgentVeil MCP tool call that required approval. "
    "Do not ask the user for another message. "
    "After retry, use the local_proof MCP tool to inspect outcome. Do not run shell commands."
)
_AGENT_CONTINUE_AFTER_APPROVAL = "retry_same_tool_call_immediately"
_RETRY_CONTRACT_SAME_TOOL_CALL = "same_tool_call"
_TOOL_NOT_AVAILABLE_NEXT_STEP = (
    "Configure or enable the MCP route that advertises this tool."
)
_DEFAULT_SANDBOX_PATH_HINT = (
    "Use a relative path under the configured sandbox, for example notes/example.txt."
)


def approval_retry_contract_fields() -> dict[str, Any]:
    """Return bounded machine-readable fields for approval-required retry."""

    return {
        "retry_contract": _RETRY_CONTRACT_SAME_TOOL_CALL,
        "retry_same_tool_call": True,
        "approved_retry_requires_same_tool": True,
        "approved_retry_requires_same_resource": True,
        "approved_retry_requires_same_payload": True,
        "agent_continue_after_approval": _AGENT_CONTINUE_AFTER_APPROVAL,
        "retry_requires_new_user_message": False,
    }


def approval_required_actionable_message(approval_url: str) -> str:
    """Return approval-required MCP error text that includes the approval URL."""

    return (
        f"Approval required. Open {approval_url}, wait for user approval, "
        "then immediately retry this exact same MCP tool call without changing "
        "tool, target, or payload. Do not ask the user for another message."
    )


def mcp_error_reason_code(reason: str) -> str:
    """Return a bounded public reason_code for MCP proxy errors."""

    mapping = {
        "local_approval_required": "approval_required",
        "path_outside_workspace": "path_outside_sandbox",
        "unknown_tool_not_advertised": "tool_not_available",
        "tool_schema_unavailable": "tool_not_available",
        "runtime_gate_not_configured": "runtime_gate_unavailable",
        "runtime_gate_evidence_unavailable": "runtime_gate_unavailable",
        "approval_evidence_unavailable": "approval_unavailable",
    }
    return mapping.get(reason, reason)


def _leaf_tool_name(tool_name: str | None) -> str | None:
    if not tool_name:
        return None
    leaf = tool_name.rsplit(".", 1)[-1].strip()
    return leaf or None


def enrich_mcp_error_contract(
    data: dict[str, Any],
    *,
    tool_name: str | None = None,
) -> dict[str, Any]:
    """Attach minimal structured MCP error contract fields to JSON-RPC error data."""

    status = str(data.get("status", ""))
    reason = str(data.get("reason", ""))
    reason_code = mcp_error_reason_code(reason)
    data["reason_code"] = reason_code
    # Terminal non-success MCP errors did not reach the downstream target.
    # claim-check: allow "never" restates the MCP error contract; negatives cover it.
    if "target_reached" not in data:
        data["target_reached"] = False

    if status == "approval_required":
        data["approval_possible"] = True
        data["retry_after_approval"] = True
        data.update(approval_retry_contract_fields())
        if "next_step" not in data:
            data["next_step"] = _APPROVAL_REQUIRED_NEXT_STEP
        leaf = _leaf_tool_name(tool_name)
        if leaf is not None:
            data.setdefault("suggested_tool", leaf)
        return data

    data["approval_possible"] = False
    data["retry_after_approval"] = False

    if reason == "path_outside_workspace":
        data["next_step"] = (
            "Choose a relative path under the configured sandbox or project workspace."
        )
        data["safe_path_hint"] = _DEFAULT_SANDBOX_PATH_HINT
        leaf = _leaf_tool_name(tool_name)
        if leaf is not None:
            data.setdefault("suggested_tool", leaf)
        return data

    if reason in {"unknown_tool_not_advertised", "tool_schema_unavailable"}:
        data["next_step"] = _TOOL_NOT_AVAILABLE_NEXT_STEP
        return data

    if "next_step" not in data:
        data["next_step"] = _DEFAULT_HARD_DENY_NEXT_STEP
    return data


def reason_has_dedicated_user_message(reason: str) -> bool:
    """Return True when ``mcp_error_user_message`` should replace internal text."""

    return reason in _DEDICATED_USER_MESSAGE_REASONS


def mcp_error_user_message(data: Mapping[str, Any]) -> str:
    """Return a differentiated user-facing MCP error message."""

    status = str(data.get("status", ""))
    reason = str(data.get("reason", ""))
    if status == "approval_required":
        return (
            "Approval required. Open the approval page and wait while the user approves or denies. "
            "After approval, immediately retry this exact same AgentVeil MCP tool call yourself "
            "without changing tool, target, or payload. Do not ask the user for another message."
        )
    if reason == "path_outside_workspace":
        return _PATH_OUTSIDE_SANDBOX_USER_MESSAGE
    if reason in {"unknown_tool_not_advertised", "tool_schema_unavailable", "unknown_tool"}:
        return _TOOL_NOT_AVAILABLE_USER_MESSAGE
    if reason == "secret_path_blocked":
        return _SECRET_PATH_BLOCKED_USER_MESSAGE
    if reason == "classifier_error":
        return _CLASSIFIER_ERROR_USER_MESSAGE
    if reason in {
        "unknown_policy_decision",
        "untrusted_runtime_decision",
        "unsupported_runtime_decision",
    }:
        return _PROXY_RUNTIME_DECISION_ERROR_USER_MESSAGE
    if reason in {
        "runtime_gate_not_configured",
        "runtime_gate_unavailable",
        "runtime_gate_evidence_unavailable",
        "approval_evidence_unavailable",
    }:
        return _RUNTIME_GATE_UNAVAILABLE_USER_MESSAGE
    if reason == "runtime_gate_block":
        return _RUNTIME_GATE_BLOCKED_USER_MESSAGE
    if reason == "user_denied":
        return _USER_DENIED_USER_MESSAGE
    if status == "blocked":  # claim-check: allow bounded JSON-RPC status vocabulary; negative tests assert no downstream execution.
        if reason == "role_authority_denied":
            return str(data.get("explanation") or _DEFAULT_HARD_DENY_NEXT_STEP)
        if reason in {
            "local_policy_block",
            "filesystem_delete",
            "undeclared_tool",
            "extra_undeclared_downstream_tool",
        }:
            return _DEFAULT_POLICY_STOP_USER_MESSAGE
    return _DEFAULT_POLICY_STOP_USER_MESSAGE


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
    if status == ApprovalStatus.CANCELLED.value:
        return "approval_cancelled"
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
