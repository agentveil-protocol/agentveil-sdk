"""Human-readable local evidence history for ``events show``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Final

from agentveil_mcp_proxy.control_surface import build_timeline_entry
from agentveil_mcp_proxy.evidence.observability import (
    bounded_reason_for_record,
    parse_action_gate_metadata,
    parse_redirect_automation_metadata,
)
from agentveil_mcp_proxy.evidence.store import (
    GENESIS_PREV_EVENT_HASH,
    ApprovalEvidenceStore,
    ApprovalStatus,
    PendingApproval,
    record_hash,
)


DEFAULT_SHOW_LAST = 10
LOCAL_PROOF_MCP_TOOL_NAME = "local_proof"
LOCAL_PROOF_INSPECTION_COMMAND = "agentveil-mcp-proxy events show --last --verify"
LOCAL_PROOF_USER_REQUEST = "Show AgentVeil local proof for the last action."
LOCAL_PROOF_LAUNCHER_HINT = f'Ask your agent: "{LOCAL_PROOF_USER_REQUEST}"'
LOCAL_PROOF_AGENT_PROMPT = (
    "Show AgentVeil local proof using the local_proof MCP tool. "
    "Do not run shell commands."
)
LOCAL_PROOF_AGENT_INSPECTION_HINT = (
    "Use the AgentVeil local_proof MCP tool to inspect local proof. "
    f"A human can also run `{LOCAL_PROOF_INSPECTION_COMMAND}` manually."
)
LOCAL_PROOF_BLOCK_TITLE = "Local proof"
LOCAL_PROOF_PENDING_QUIET_LINE = "This decision will be recorded locally."
LOCAL_PROOF_POST_APPROVE_BODY = (
    "After the agent retries the same MCP call, copy this prompt into the agent chat:"
)
LOCAL_PROOF_POST_DENY_BODY = (
    "This denial was recorded. Copy this prompt into the agent chat to inspect local proof:"
)
LOCAL_PROOF_INSPECTION_HINT = (
    "After retry, use the AgentVeil local_proof MCP tool to inspect local proof. "
    f"A human can also run `{LOCAL_PROOF_INSPECTION_COMMAND}` manually."
)
LOCAL_PROOF_INSPECTION_DISCOVER_HINT = LOCAL_PROOF_AGENT_INSPECTION_HINT
_LOCAL_PROOF_SUMMARY = (
    "Local proof shows what was requested, decided, executed, and whether the "
    "target was reached."
)
_EMPTY_NEXT_STEP = (
    "Run a routed MCP action, then use the AgentVeil local_proof MCP tool to "
    "inspect local proof. "
    f"A human can also run `{LOCAL_PROOF_INSPECTION_COMMAND}` manually."
)
_SETUP_NEXT_STEP = (
    "Run `agentveil-mcp-proxy setup status` or initialize the proxy with `init`."
)


def _format_timestamp(value: int) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_records(evidence_path: Path) -> list[PendingApproval]:
    if not evidence_path.is_file():
        return []
    with ApprovalEvidenceStore(evidence_path) as store:
        return store.list_records()


def _event_decision(record: PendingApproval, entry: Mapping[str, Any]) -> str:
    kind = str(entry.get("event_kind", "unknown"))
    target_reached = entry.get("target_reached")
    if kind == "approval_pending":
        return "approval_required"
    if kind == "approval_granted":
        return "approved"
    if kind in {"approval_denied", "policy_deny", "role_violation"}:
        return "hard_blocked"
    if kind in {"redirect_original", "redirect_follow_up"}:
        return "redirected"
    if record.error_class == "path_outside_workspace":
        return "hard_blocked"
    if kind == "executed":
        if target_reached is True:
            return "target_reached"
        if target_reached is False:
            return "execution_not_reached"
        if record.risk_class == "read" or record.action_class == "read":
            return "allowed"
        if record.granted_by_request_id:
            return "approved"
        return "allowed"
    if record.status == ApprovalStatus.BLOCKED.value:  # claim-check: allow enum status label; bounded renderer tests cover policy deny display.
        return "hard_blocked"
    if kind == "unknown" and entry.get("metadata_state") == "unparseable_metadata":
        return "invalid"
    return "allowed"


def _reason_summary(record: PendingApproval, *, decision: str) -> str:
    if decision == "target_reached":
        return "Action reached target."
    if decision == "approved":
        return (
            "Approved by user. Retry the same MCP tool call without changing "
            "tool, target, or payload."
        )
    if decision == "approval_required":
        return (
            "Approval required before execution. Retry the same MCP tool call "
            "after approval."
        )
    if decision == "execution_not_reached":
        return "Execution did not reach target."
    if record.error_class:
        if record.error_class == "path_outside_workspace":
            return "Path was outside the configured sandbox."
        return record.error_class.replace("_", " ")
    reason = bounded_reason_for_record(record)
    if reason == "user_denied":
        return "Denied by user."
    if reason == "user_approved":
        return (
            "Approved by user. Retry the same MCP tool call without changing "
            "tool, target, or payload."
        )
    return reason.replace("_", " ")


def _next_step_for_decision(decision: str) -> str | None:
    if decision == "approval_required":
        return (
            "Open the approval page, decide, then retry the same MCP tool call. "
            f"{LOCAL_PROOF_INSPECTION_DISCOVER_HINT}"
        )
    if decision == "approved":
        return (
            "Retry the same MCP tool call without changing tool, target, or payload. "
            f"{LOCAL_PROOF_INSPECTION_HINT}"
        )
    if decision == "target_reached":
        return LOCAL_PROOF_INSPECTION_DISCOVER_HINT
    if decision == "redirected":
        return "Follow the redirect hint and retry with the suggested controlled tool."
    if decision == "hard_blocked":
        return "Adjust the tool call or policy; approval will not help for this action."
    if decision == "execution_not_reached":
        return (
            "Inspect approval status and retry if the action should still run. "
            f"{LOCAL_PROOF_INSPECTION_DISCOVER_HINT}"
        )
    return None


def _target_display(record: PendingApproval) -> str:
    if not record.resource_hash:
        return "none"
    digest = record.resource_hash
    if digest.startswith("sha256:"):
        digest = digest[7:19]
    return f"resource:{digest}"


def _action_family(record: PendingApproval) -> str | None:
    gate = parse_action_gate_metadata(record)
    if gate is None:
        return record.action_class or None
    action_family = gate.get("action_family")
    if isinstance(action_family, str) and action_family:
        return action_family
    return record.action_class or None


def build_event_show_entry(
    record: PendingApproval,
    *,
    linked_follow_up_id: str | None = None,
    include_debug: bool = False,
) -> dict[str, Any]:
    """Build one bounded event row for ``events show``."""

    if not isinstance(record.request_id, str) or not record.request_id:
        return {"valid": False, "reason": "missing record id"}
    try:
        timeline = build_timeline_entry(
            record,
            linked_follow_up_id=linked_follow_up_id,
        )
    except Exception:
        return {
            "valid": False,
            "record_id": record.request_id,
            "reason": "could not render event",
        }
    decision = _event_decision(record, timeline)
    if decision == "invalid":
        return {
            "valid": False,
            "record_id": record.request_id,
            "reason": "unparseable metadata",
        }
    entry: dict[str, Any] = {
        "valid": True,
        "record_id": record.request_id,
        "timestamp": record.created_at,
        "timestamp_utc": _format_timestamp(record.created_at),
        "client": record.client_id or "unknown",
        "connector": record.client_id or "unknown",
        "action_family": _action_family(record),
        "tool": record.tool_name,
        "decision": decision,
        "target": _target_display(record),
        "policy_rule": record.policy_rule_id or record.policy_id,
        "reason_summary": _reason_summary(record, decision=decision),
        "status": record.status,
        "risk_class": record.risk_class,
        "payload_hash": record.payload_hash,
    }
    if "target_reached" in timeline:
        entry["target_reached"] = timeline["target_reached"]
    if record.result_status is not None:
        entry["execution_status"] = record.result_status
    next_step = _next_step_for_decision(decision)
    if next_step is not None:
        entry["next_step"] = next_step
    redirect_meta = parse_redirect_automation_metadata(record)
    if redirect_meta is not None:
        playbook_id = redirect_meta.get("redirect_playbook_id")
        if isinstance(playbook_id, str) and playbook_id:
            entry["redirect_playbook_id"] = playbook_id
        if redirect_meta.get("original_request_id") is not None:
            entry["original_request_id"] = redirect_meta.get("original_request_id")
    if record.granted_by_request_id is not None:
        entry["granted_by_request_id"] = record.granted_by_request_id
    if linked_follow_up_id is not None:
        entry["linked_follow_up_id"] = linked_follow_up_id
    if include_debug:
        gate = parse_action_gate_metadata(record)
        if gate is not None:
            entry["debug"] = {
                "event_kind": timeline.get("event_kind"),
                "metadata_state": timeline.get("metadata_state"),
                "action_gate": gate,
            }
        if record.prev_event_hash is not None:
            entry["debug"] = entry.get("debug", {})
            entry["debug"]["prev_event_hash"] = record.prev_event_hash
        entry["debug"] = entry.get("debug", {})
        entry["debug"]["record_hash"] = record_hash(record)
    return entry


def verify_local_evidence_chain(records: Sequence[PendingApproval]) -> dict[str, Any]:
    """Return honest local hash-chain verification status."""

    if not records:
        return {"status": "not_available", "reason": "no evidence records"}
    if all(record.prev_event_hash is None for record in records):  # claim-check: allow Python quantifier for local chain availability check.
        return {"status": "not_available", "reason": "hash chain not initialized"}
    expected_prev = GENESIS_PREV_EVENT_HASH
    for record in records:
        if record.prev_event_hash is None:
            return {
                "status": "not_available",
                "reason": f"missing chain link at {record.request_id}",
            }
        if record.prev_event_hash != expected_prev:
            return {
                "status": "failed",
                "reason": f"chain mismatch at {record.request_id}",
            }
        expected_prev = record_hash(record)
    return {"status": "intact", "chain_root_hash": expected_prev}


def _link_follow_up_ids(records: Sequence[PendingApproval]) -> dict[str, str]:
    from agentveil_mcp_proxy.evidence.observability import redirect_automation_link_valid

    links: dict[str, str] = {}
    originals = [
        record for record in records
        if (meta := parse_redirect_automation_metadata(record)) is not None
        and meta.get("redirect_role") == "original"
    ]
    follow_ups = [
        record for record in records
        if (meta := parse_redirect_automation_metadata(record)) is not None
        and meta.get("redirect_role") == "follow_up"
    ]
    for original in originals:
        for follow_up in follow_ups:
            if redirect_automation_link_valid(original, follow_up):
                links[original.request_id] = follow_up.request_id
                break
    return links


def build_events_show_payload(
    *,
    evidence_path: Path,
    config_path: Path | None,
    last: int | None = None,
    session_id: str | None = None,
    include_debug: bool = False,
    verify: bool = False,
) -> dict[str, Any]:
    """Build bounded payload for ``events show``."""

    if last is not None and last <= 0:
        raise ValueError("--last must be positive")
    records = _load_records(evidence_path)
    if session_id is not None:
        records = [record for record in records if record.session_id == session_id]
    warnings: list[str] = []
    if config_path is not None and not config_path.is_file():
        warnings.append("proxy config missing; run setup status or init")
    limit = last if last is not None else DEFAULT_SHOW_LAST
    selected = records[-limit:]
    links = _link_follow_up_ids(records)
    events = [
        build_event_show_entry(
            record,
            linked_follow_up_id=links.get(record.request_id),
            include_debug=include_debug,
        )
        for record in selected
    ]
    payload: dict[str, Any] = {
        "ok": True,
        "errors": [],
        "warnings": warnings,
        "evidence_count": len(records),
        "event_count": len(events),
        "events": events,
    }
    if not records:
        payload["empty"] = True
        payload["next_step"] = _EMPTY_NEXT_STEP
    elif config_path is not None and not config_path.is_file():
        payload["next_step"] = _SETUP_NEXT_STEP
    if verify:
        payload["verify"] = verify_local_evidence_chain(records)
    return payload


def _local_proof_event_row(entry: Mapping[str, Any]) -> dict[str, Any]:
    if entry.get("valid") is False:
        return {
            "valid": False,
            "record_id": entry.get("record_id"),
            "reason": entry.get("reason"),
        }
    row: dict[str, Any] = {
        "time": entry.get("timestamp_utc"),
        "decision": entry.get("decision"),
        "tool": entry.get("tool"),
    }
    if entry.get("action_family"):
        row["action"] = entry["action_family"]
    target = entry.get("target")
    if target not in (None, "none"):
        row["target"] = target
    if entry.get("policy_rule"):
        row["policy"] = entry["policy_rule"]
    if entry.get("reason_summary"):
        row["why"] = entry["reason_summary"]
    if entry.get("next_step"):
        row["next_step"] = entry["next_step"]
    if "target_reached" in entry:
        row["target_reached"] = entry["target_reached"]
    return row


def build_local_proof_mcp_payload(
    *,
    evidence_path: Path,
    config_path: Path | None,
    last: int | None = None,
    session_id: str | None = None,
    verify: bool = True,
    include_debug: bool = False,
) -> dict[str, Any]:
    """Build bounded MCP ``local_proof`` response payload."""

    show_payload = build_events_show_payload(
        evidence_path=evidence_path,
        config_path=config_path,
        last=last,
        session_id=session_id,
        include_debug=include_debug,
        verify=verify,
    )
    proof: dict[str, Any] = {
        "events": [
            _local_proof_event_row(event)
            for event in show_payload.get("events", [])
            if isinstance(event, Mapping)
        ],
    }
    if verify:
        verify_block = show_payload.get("verify")
        if isinstance(verify_block, Mapping):
            proof["verify"] = {"status": verify_block.get("status", "not_available")}
        else:
            proof["verify"] = {"status": "not_available"}
    payload: dict[str, Any] = {"status": "ok", "proof": proof}
    if show_payload.get("empty"):
        payload["empty"] = True
    warnings = show_payload.get("warnings")
    if warnings:
        payload["warnings"] = list(warnings)
    return payload


_WRITE_OUTCOME_ACTIONS: Final[frozenset[str]] = frozenset({"write", "destructive"})
_DECISION_PATH_LABELS: Final[Mapping[str, str]] = {
    "approval_required": "approval required",
    "approved": "approved",
    "target_reached": "target reached",
    "allowed": "allowed",
    "hard_blocked": "stopped",
    "execution_not_reached": "execution not reached",
    "redirected": "redirected",
}


def _format_time_hms(timestamp_utc: str) -> str:
    if "T" in timestamp_utc:
        return timestamp_utc.split("T", 1)[1].replace("Z", "")
    return timestamp_utc


def _valid_show_events(events: object) -> list[Mapping[str, Any]]:
    if not isinstance(events, list):
        return []
    return [
        event
        for event in events
        if isinstance(event, Mapping) and event.get("valid") is not False
    ]


def _is_read_only_event(entry: Mapping[str, Any]) -> bool:
    decision = entry.get("decision")
    if decision not in {"allowed", "target_reached"}:
        return False
    action = entry.get("action_family") or entry.get("action") or ""
    risk = entry.get("risk_class") or ""
    return action == "read" or risk == "read"


def _is_primary_write_outcome(entry: Mapping[str, Any]) -> bool:
    if entry.get("decision") != "target_reached":
        return False
    action = entry.get("action_family") or ""
    risk = entry.get("risk_class") or ""
    return action in _WRITE_OUTCOME_ACTIONS or risk in _WRITE_OUTCOME_ACTIONS


def _find_primary_outcome_event(events: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    for event in reversed(events):
        if _is_primary_write_outcome(event):
            return event
    for event in reversed(events):
        if event.get("decision") == "approval_required":
            return event
    for event in reversed(events):
        decision = event.get("decision")
        if decision not in {"allowed"}:
            return event
    return events[-1] if events else None


def _record_id(entry: Mapping[str, Any]) -> str | None:
    record_id = entry.get("record_id")
    if isinstance(record_id, str) and record_id:
        return record_id
    return None


def _action_identity(entry: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(entry.get("tool") or ""),
        str(entry.get("target") or "none"),
        str(entry.get("payload_hash") or ""),
    )


def _decision_chain_for_primary(
    events: Sequence[Mapping[str, Any]],
    *,
    primary: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    """Return events linked to one primary outcome for a concise summary."""

    by_id = {
        record_id: event
        for event in events
        if (record_id := _record_id(event)) is not None
    }
    chain_ids: set[str] = set()
    primary_id = _record_id(primary)
    if primary_id is not None:
        chain_ids.add(primary_id)

    changed = True
    while changed:
        changed = False
        for event in events:
            record_id = _record_id(event)
            if record_id is None:
                continue
            linked_ids: list[str] = []
            granted_by = event.get("granted_by_request_id")
            follow_up = event.get("linked_follow_up_id")
            if isinstance(granted_by, str) and granted_by:
                linked_ids.append(granted_by)
            if isinstance(follow_up, str) and follow_up:
                linked_ids.append(follow_up)
            if record_id in chain_ids:
                for linked_id in linked_ids:
                    if linked_id in by_id and linked_id not in chain_ids:
                        chain_ids.add(linked_id)
                        changed = True
            for linked_id in linked_ids:
                if linked_id in chain_ids and record_id not in chain_ids:
                    chain_ids.add(record_id)
                    changed = True

    chain = [event for event in events if _record_id(event) in chain_ids]
    if len(chain) <= 1:
        tool, target, payload_hash = _action_identity(primary)
        if tool and target not in {"", "none"} and payload_hash:
            same_identity = [
                event
                for event in events
                if _action_identity(event) == (tool, target, payload_hash)
            ]
            if len(same_identity) > 1:
                chain = same_identity
        elif primary_id is not None:
            chain = [primary]

    chain.sort(key=lambda event: int(event.get("timestamp", 0)))
    return chain


def _decision_path(chain: Sequence[Mapping[str, Any]]) -> str:
    labels: list[str] = []
    seen: set[str] = set()
    for event in chain:
        decision = str(event.get("decision", "unknown"))
        label = _DECISION_PATH_LABELS.get(decision, decision.replace("_", " "))
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return " -> ".join(labels) if labels else "recorded"


def _result_summary_line(
    primary: Mapping[str, Any],
    chain: Sequence[Mapping[str, Any]],
) -> str:
    decisions = {str(event.get("decision")) for event in chain}
    tool = str(primary.get("tool") or "unknown")
    if "target_reached" in decisions and "approved" in decisions:
        return "write approved and completed"
    if "target_reached" in decisions:
        action = primary.get("action_family") or primary.get("action") or ""
        risk = primary.get("risk_class") or ""
        if action == "read" or risk == "read":
            return "read action completed"
        return f"{tool} completed"
    if "approval_required" in decisions and "approved" not in decisions:
        return f"approval required for {tool}"
    if "approved" in decisions:
        return f"{tool} approved, awaiting retry"
    if primary.get("decision") == "hard_blocked":
        return f"{tool} stopped"
    decision = str(primary.get("decision", "recorded")).replace("_", " ")
    return f"{tool} {decision}"


def _verification_status_line(show_payload: Mapping[str, Any]) -> str:
    verify = show_payload.get("verify")
    if isinstance(verify, Mapping):
        return str(verify.get("status", "not_available"))
    return "not_available"


def format_local_proof_human_summary(show_payload: Mapping[str, Any]) -> str:
    """Render concise human-readable ``local_proof`` output."""

    lines = ["AgentVeil proof", ""]
    if show_payload.get("empty"):
        lines.extend([
            "No local evidence yet.",
            "",
            f"Verification: {_verification_status_line(show_payload)}",
            "",
            "Run a routed MCP action, then inspect proof again.",
        ])
        return "\n".join(lines)

    events = _valid_show_events(show_payload.get("events"))
    primary = _find_primary_outcome_event(events)
    if primary is None:
        lines.extend([
            "Result: no bounded events available",
            f"Verification: {_verification_status_line(show_payload)}",
            "",
            "Use debug/json for full bounded evidence.",
        ])
        return "\n".join(lines)

    tool = str(primary.get("tool") or "unknown")
    chain = _decision_chain_for_primary(events, primary=primary)
    lines.append(f"Result: {_result_summary_line(primary, chain)}")
    lines.append(f"Verification: {_verification_status_line(show_payload)}")
    lines.append(f"Tool: {tool}")
    lines.append(f"Decision path: {_decision_path(chain)}")
    target = primary.get("target")
    if target not in (None, "none"):
        lines.append(f"Target: {target}")
    timestamps = [
        str(event.get("timestamp_utc"))
        for event in chain
        if event.get("timestamp_utc")
    ]
    if len(timestamps) >= 2:
        lines.append(
            f"Time: {_format_time_hms(timestamps[0])} -> {_format_time_hms(timestamps[-1])}"
        )
    elif timestamps:
        lines.append(f"Time: {_format_time_hms(timestamps[0])}")

    chain_ids = {event.get("record_id") for event in chain}
    read_events = [
        event
        for event in events
        if event.get("record_id") not in chain_ids and _is_read_only_event(event)
    ]
    if read_events:
        lines.append("")
        lines.append("Observed read-only actions:")
        for event in read_events:
            read_tool = str(event.get("tool") or "unknown")
            decision = str(event.get("decision", "recorded"))
            label = "allowed" if decision in {"allowed", "target_reached"} else decision.replace("_", " ")
            lines.append(f"- {read_tool} {label}")

    lines.extend(["", "Use debug/json for full bounded evidence."])
    return "\n".join(lines)


def render_local_proof_mcp_content(
    *,
    evidence_path: Path,
    config_path: Path | None,
    last: int | None = None,
    session_id: str | None = None,
    verify: bool = True,
    output_format: str = "text",
    debug: bool = False,
) -> str:
    """Return MCP ``local_proof`` text content for the requested output mode."""

    if output_format == "json" or debug:
        payload = build_local_proof_mcp_payload(
            evidence_path=evidence_path,
            config_path=config_path,
            last=last,
            session_id=session_id,
            verify=verify,
            include_debug=debug,
        )
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)
    show_payload = build_events_show_payload(
        evidence_path=evidence_path,
        config_path=config_path,
        last=last,
        session_id=session_id,
        verify=verify,
    )
    return format_local_proof_human_summary(show_payload)


def format_events_show_human(payload: Mapping[str, Any]) -> str:
    """Render human-readable ``events show`` output."""

    if payload.get("empty"):
        lines = ["No local evidence yet.", f"Next step: {payload.get('next_step', _EMPTY_NEXT_STEP)}"]
        if payload.get("verify"):
            verify = payload["verify"]
            if isinstance(verify, Mapping):
                lines.append(f"Verify: {verify.get('status', 'not_available')}")
        return "\n".join(lines)
    lines = [f"Local evidence ({payload.get('event_count', 0)} shown)"]
    for warning in payload.get("warnings", ()):
        lines.append(f"Warning: {warning}")
    for event in payload.get("events", ()):
        if not isinstance(event, Mapping):
            continue
        if event.get("valid") is False:
            lines.append(
                f"- skipped invalid event record={event.get('record_id', '?')} "
                f"reason={event.get('reason', 'invalid')}"
            )
            continue
        parts = [
            event.get("timestamp_utc", "?"),
            f"decision={event.get('decision', '?')}",
            f"tool={event.get('tool', '?')}",
        ]
        if event.get("action_family"):
            parts.append(f"action={event['action_family']}")
        if event.get("target") not in (None, "none"):
            parts.append(f"target={event['target']}")
        if event.get("policy_rule"):
            parts.append(f"policy={event['policy_rule']}")
        if event.get("reason_summary"):
            parts.append(f"why={event['reason_summary']}")
        if "target_reached" in event:
            parts.append(f"target_reached={event['target_reached']}")
        if event.get("next_step"):
            parts.append(f"next={event['next_step']}")
        lines.append("- " + " | ".join(parts))
    verify = payload.get("verify")
    if isinstance(verify, Mapping):
        lines.append(f"Verify: {verify.get('status', 'not_available')}")
        reason = verify.get("reason")
        if isinstance(reason, str) and reason:
            lines.append(f"  {reason}")
    if payload.get("next_step") and not payload.get("empty"):
        lines.append(f"Next step: {payload['next_step']}")
    lines.append(_LOCAL_PROOF_SUMMARY)
    lines.append("Use --json or --debug for structured or deeper bounded fields.")
    return "\n".join(lines)


def events_show_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


__all__ = [
    "DEFAULT_SHOW_LAST",
    "LOCAL_PROOF_AGENT_INSPECTION_HINT",
    "LOCAL_PROOF_AGENT_PROMPT",
    "LOCAL_PROOF_INSPECTION_COMMAND",
    "LOCAL_PROOF_BLOCK_TITLE",
    "LOCAL_PROOF_MCP_TOOL_NAME",
    "LOCAL_PROOF_PENDING_QUIET_LINE",
    "LOCAL_PROOF_POST_APPROVE_BODY",
    "LOCAL_PROOF_POST_DENY_BODY",
    "LOCAL_PROOF_INSPECTION_DISCOVER_HINT",
    "LOCAL_PROOF_INSPECTION_HINT",
    "build_event_show_entry",
    "build_events_show_payload",
    "build_local_proof_mcp_payload",
    "events_show_json",
    "format_events_show_human",
    "format_local_proof_human_summary",
    "render_local_proof_mcp_content",
    "verify_local_evidence_chain",
]
