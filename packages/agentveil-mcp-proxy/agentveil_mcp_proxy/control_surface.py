"""Daily control surface: local-first status and timeline for routed MCP operators."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from pathlib import Path
from typing import Any, Literal, Mapping

from agentveil_mcp_proxy.config_wizard import (
    ConfigWizardError,
    derive_setup_status,
    setup_status_to_dict,
)
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.authority_boundary import parse_authority_from_metadata
from agentveil_mcp_proxy.redirect_playbooks import redirect_metadata_from_action_gate
from agentveil_mcp_proxy.evidence.observability import (
    parse_action_gate_metadata,
    parse_redirect_automation_metadata,
    redirect_automation_link_valid,
)
from agentveil_mcp_proxy.policy import ProxyConfig, ProxyConfigError

AutomationLevel = Literal[
    "metadata_only",
    "policy_checked_followup",
    "approval_required",
    "unsupported",
]
RedirectPackStatus = Literal["supported", "planned", "unsupported"]

_LOCAL_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/", "/tmp/")
_PRIVACY_FAIL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/tmp/\S+"), "/tmp"),
    (re.compile(r"/Users/\S+"), "/Users"),
    (re.compile(r"/private/\S+"), "/private"),
    (re.compile(r"/var/folders/\S+"), "/var/folders"),
    (re.compile(r"(?i)\bpassphrase\b"), "passphrase"),
    (re.compile(r"\bTOKEN\b"), "TOKEN"),
    (re.compile(r"\bSECRET\b"), "SECRET"),
    (re.compile(r"\bPASSWORD\b"), "PASSWORD"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (
        re.compile(r'(?i)"(?:secret|password|token|api[_-]?key)"\s*:\s*"[^"]{4,}"'),
        "raw secret-like json field",
    ),
    (
        re.compile(r"(?i)\b(?:secret|password|token|api[_-]?key)\s*[=:]\s*\S{4,}"),
        "secret assignment",
    ),
    (
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
        "GitHub PAT",
    ),
    (
        re.compile(r"gh[pours]_[A-Za-z0-9]{20,}"),
        "GitHub token",
    ),
    (
        re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
        "API key token",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
)
_PRIVACY_BOUNDARY_MESSAGE = "control output failed privacy boundary check"
_ROLE_AUTHORITY_REASON = "role_authority_denied"
_VIOLATION_TYPE_ROLE_AUTHORITY = "role_authority"

_REDIRECT_PLAYBOOK_COVERAGE: tuple[dict[str, Any], ...] = (
    {
        "pack": "filesystem",
        "redirect_playbook_id": "create_implementer_task",
        "automation_level": "policy_checked_followup",
    },
    {
        "pack": "filesystem",
        "redirect_playbook_id": "use_read_only_tool",
        "automation_level": "policy_checked_followup",
    },
    {
        "pack": "filesystem",
        "redirect_playbook_id": "switch_to_build_agent",
        "automation_level": "policy_checked_followup",
    },
    {
        "pack": "filesystem",
        "redirect_playbook_id": "request_approval",
        "automation_level": "approval_required",
    },
    {
        "pack": "unknown",
        "redirect_playbook_id": "stop_and_classify_unknown_action",
        "automation_level": "metadata_only",
    },
)

_REDIRECT_PACK_SUMMARY: tuple[dict[str, Any], ...] = (
    {
        "pack": "filesystem",
        "status": "supported",
        "summary": "filesystem redirects: supported",
    },
    {
        "pack": "git",
        "status": "supported",
        "summary": "git redirects: show_git_status_and_diff",
    },
    {
        "pack": "github",
        "status": "supported",
        "summary": "github redirects: repo_change_review / workflow_review",
    },
    {
        "pack": "package",
        "status": "supported",
        "summary": "package redirects: inspect_package_risk",
    },
    {
        "pack": "secrets",
        "status": "supported",
        "summary": "secret redirects: secret_posture_only",
    },
    {
        "pack": "deployment",
        "status": "supported",
        "summary": "deployment redirects: release_readiness_check",
    },
    {
        "pack": "remote",
        "status": "supported",
        "summary": "remote command redirects: remote_command_review",
    },
    {
        "pack": "unknown",
        "status": "supported",
        "summary": "unknown redirects: stop_and_classify / metadata_only",
    },
    {
        "pack": "shell",
        "status": "unsupported",
        "summary": (
            "shell redirects: unsupported unless routed through a controlled adapter"
        ),
    },
)


_KNOWN_POLICY_PACKS = frozenset({
    "filesystem",
    "git",
    "github",
    "shell",
    "package",
    "default",
})


class ControlSurfaceError(Exception):
    """Bounded control-surface error without raw filesystem paths."""

    def __init__(self, message: str, *, code: str = "control_surface_error") -> None:
        super().__init__(message)
        self.code = code

    def public_message(self) -> str:
        """Return a bounded user-facing message for human and JSON CLI output."""

        if self.code == "privacy_violation":
            return _PRIVACY_BOUNDARY_MESSAGE
        return str(self)


def redirect_playbook_coverage() -> tuple[dict[str, Any], ...]:
    """Return static redirect playbook coverage for the daily control surface."""

    return _REDIRECT_PLAYBOOK_COVERAGE


def redirect_pack_summaries() -> tuple[dict[str, Any], ...]:
    """Return user-facing redirect pack coverage summaries."""

    return _REDIRECT_PACK_SUMMARY


def supported_redirect_packs() -> tuple[str, ...]:
    return tuple(
        item["pack"]
        for item in _REDIRECT_PACK_SUMMARY
        if item["status"] == "supported"
    )


def planned_redirect_packs() -> tuple[str, ...]:
    return tuple(
        item["pack"]
        for item in _REDIRECT_PACK_SUMMARY
        if item["status"] == "planned"
    )


def unsupported_redirect_packs() -> tuple[str, ...]:
    return tuple(
        item["pack"]
        for item in _REDIRECT_PACK_SUMMARY
        if item["status"] == "unsupported"
    )


def privacy_markers_in_control_output(text: str) -> list[str]:
    """Return privacy marker labels found in serialized control output."""

    findings: list[str] = []
    for marker in _LOCAL_PATH_MARKERS:
        if marker.lower() in text.lower():
            findings.append(marker)
    for pattern, label in _PRIVACY_FAIL_PATTERNS:
        if pattern.search(text):
            findings.append(label)
    if '": "/' in text:
        findings.append("absolute json path")
    return findings


def assert_control_output_is_privacy_safe(payload: Mapping[str, Any]) -> None:
    """Reject control output that could leak secrets, raw payloads, or full paths."""

    serialized = json.dumps(payload, sort_keys=True)
    for label in privacy_markers_in_control_output(serialized):
        raise ControlSurfaceError(
            _PRIVACY_BOUNDARY_MESSAGE,
            code="privacy_violation",
        )


def _read_policy_pack_id(config_path: Path) -> str | None:
    if not config_path.is_file():
        return None
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, Mapping):
        return None
    policy = raw.get("policy")
    if not isinstance(policy, Mapping):
        return None
    policy_id = policy.get("id")
    return policy_id if isinstance(policy_id, str) and policy_id else None


def _protected_packs_from_config(config_path: Path) -> list[str]:
    if not config_path.is_file():
        return []
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(raw, Mapping):
        return []
    policy = raw.get("policy")
    if not isinstance(policy, Mapping):
        return []
    packs: set[str] = set()
    rules = policy.get("rules")
    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, Mapping):
                continue
            match = rule.get("match")
            if not isinstance(match, Mapping):
                continue
            servers = match.get("server")
            if isinstance(servers, str) and servers in _KNOWN_POLICY_PACKS:
                packs.add(servers)
            elif isinstance(servers, list):
                for item in servers:
                    if isinstance(item, str) and item in _KNOWN_POLICY_PACKS:
                        packs.add(item)
    return sorted(packs)


def _load_evidence_records(evidence_path: Path) -> list[Any]:
    if not evidence_path.is_file():
        return []
    with ApprovalEvidenceStore(evidence_path) as store:
        return store.list_records()


def _metadata_parse_state(record: Any) -> str:
    raw = getattr(record, "action_gate_metadata_jcs", None)
    if not isinstance(raw, str) or not raw:
        return "none"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return "unparseable_metadata"
    if not isinstance(parsed, dict):
        return "unparseable_metadata"
    return "ok"


def _target_reached_for_record(record: Any) -> bool | None:
    metadata = parse_action_gate_metadata(record)
    if metadata is None:
        return None
    value = metadata.get("target_reached")
    return value if isinstance(value, bool) else None


def parse_role_violation_projection(record: Any) -> dict[str, Any] | None:
    """Return bounded role-authority violation fields when evidence supports it."""

    reason = getattr(record, "error_class", None)
    if reason != _ROLE_AUTHORITY_REASON:
        return None
    gate = parse_action_gate_metadata(record)
    if gate is None:
        return None
    role = gate.get("role")
    authority = gate.get("authority")
    if not isinstance(role, str) or not role:
        return None
    if not isinstance(authority, str) or not authority:
        return None
    projection: dict[str, Any] = {
        "role": role,
        "authority": authority,
        "reason": _ROLE_AUTHORITY_REASON,
        "violation_type": _VIOLATION_TYPE_ROLE_AUTHORITY,
    }
    action_family = gate.get("action_family")
    if isinstance(action_family, str) and action_family:
        projection["action_family"] = action_family
    policy_rule_id = getattr(record, "policy_rule_id", None)
    if not isinstance(policy_rule_id, str) or not policy_rule_id:
        policy_rule = gate.get("policy_rule")
        policy_rule_id = policy_rule if isinstance(policy_rule, str) else None
    if isinstance(policy_rule_id, str) and policy_rule_id:
        projection["policy_rule_id"] = policy_rule_id
    redirect_meta = parse_redirect_automation_metadata(record)
    if redirect_meta is not None:
        playbook_id = redirect_meta.get("redirect_playbook_id")
        if isinstance(playbook_id, str) and playbook_id:
            projection["redirect_playbook_id"] = playbook_id
    target_reached = _target_reached_for_record(record)
    projection["target_reached"] = False if target_reached is None else target_reached
    return projection


def _is_redirect_original(record: Any) -> bool:
    redirect_meta = parse_redirect_automation_metadata(record)
    return redirect_meta is not None and redirect_meta.get("redirect_role") == "original"


def _is_redirect_follow_up(record: Any) -> bool:
    redirect_meta = parse_redirect_automation_metadata(record)
    return redirect_meta is not None and redirect_meta.get("redirect_role") == "follow_up"


def _timeline_kind(record: Any) -> str:
    if parse_role_violation_projection(record) is not None:
        return "role_violation"
    redirect_meta = parse_redirect_automation_metadata(record)
    if record.status == ApprovalStatus.PENDING.value:
        return "approval_pending"
    if record.status == ApprovalStatus.DENIED.value:
        return "approval_denied"
    if record.status == ApprovalStatus.APPROVED.value:
        return "approval_granted"
    if redirect_meta is not None:
        role = redirect_meta.get("redirect_role")
        if role == "original":
            return "redirect_original"
        if role == "follow_up":
            return "redirect_follow_up"
    if record.status == ApprovalStatus.BLOCKED.value:  # claim-check: allow status enum; tests cover role/generic deny split.
        return "policy_deny"
    if record.status == ApprovalStatus.EXECUTED.value:
        return "executed"
    return "unknown"


def build_timeline_entry(
    record: Any,
    *,
    linked_follow_up_id: str | None = None,
) -> dict[str, Any]:
    """Build one bounded timeline entry from a durable evidence record."""

    redirect_meta = parse_redirect_automation_metadata(record)
    metadata_state = _metadata_parse_state(record)
    entry: dict[str, Any] = {
        "record_id": record.request_id,
        "timestamp": record.created_at,
        "event_kind": _timeline_kind(record),
        "server": record.downstream_server,
        "tool": record.tool_name,
        "status": record.status,
        "metadata_state": metadata_state,
    }
    target_reached = _target_reached_for_record(record)
    if target_reached is not None:
        entry["target_reached"] = target_reached
    if redirect_meta is not None:
        entry["redirect_role"] = redirect_meta.get("redirect_role")
        entry["redirect_playbook_id"] = redirect_meta.get("redirect_playbook_id")
        if redirect_meta.get("original_request_id") is not None:
            entry["original_request_id"] = redirect_meta.get("original_request_id")
        if redirect_meta.get("redirect_parent_request_id") is not None:
            entry["redirect_parent_request_id"] = redirect_meta.get("redirect_parent_request_id")
    if linked_follow_up_id is not None:
        entry["linked_follow_up_id"] = linked_follow_up_id
    role_violation = parse_role_violation_projection(record)
    if role_violation is not None:
        entry.update(role_violation)
    gate = parse_action_gate_metadata(record)
    authority = parse_authority_from_metadata(gate)
    if authority is not None:
        entry["authority"] = authority
    redirect_fields = redirect_metadata_from_action_gate(gate)
    if redirect_fields:
        entry.update(redirect_fields)
    if metadata_state == "unparseable_metadata":
        entry["event_kind"] = "unknown"
    return entry


def _link_follow_up_ids(records: list[Any]) -> dict[str, str]:
    links: dict[str, str] = {}
    originals = [record for record in records if _is_redirect_original(record)]
    follow_ups = [record for record in records if _is_redirect_follow_up(record)]
    for original in originals:
        for follow_up in follow_ups:
            if redirect_automation_link_valid(original, follow_up):
                links[original.request_id] = follow_up.request_id
                break
    return links


def summarize_evidence(records: list[Any]) -> dict[str, Any]:
    """Aggregate evidence counts used by control status."""

    summary: dict[str, int] = {
        "pending_approval_count": 0,
        "approval_denied_count": 0,
        "policy_deny_count": 0,
        "role_violation_count": 0,
        "redirect_original_count": 0,
        "redirect_follow_up_count": 0,
        "target_reached_true_count": 0,
        "target_reached_false_count": 0,
        "unparseable_metadata_count": 0,
    }
    for record in records:
        kind = _timeline_kind(record)
        if parse_role_violation_projection(record) is not None:
            summary["role_violation_count"] += 1
        if kind == "approval_pending":
            summary["pending_approval_count"] += 1
        elif kind == "approval_denied":
            summary["approval_denied_count"] += 1
        elif kind == "policy_deny":
            summary["policy_deny_count"] += 1
        if _is_redirect_original(record):
            summary["redirect_original_count"] += 1
        elif _is_redirect_follow_up(record):
            summary["redirect_follow_up_count"] += 1
        if _metadata_parse_state(record) == "unparseable_metadata":
            summary["unparseable_metadata_count"] += 1
        target_reached = _target_reached_for_record(record)
        if target_reached is True:
            summary["target_reached_true_count"] += 1
        elif target_reached is False:
            summary["target_reached_false_count"] += 1
    return summary


def build_control_status(
    *,
    home: Path,
    client_id: str = "cursor",
    proxy_config_path: Path | None = None,
    proxy_command: str | None = None,
) -> dict[str, Any]:
    """Build daily control status from actual setup files and evidence."""

    from agentveil_mcp_proxy.cli import proxy_paths

    paths = proxy_paths(home, proxy_config_path)
    config_path = paths.config_path
    evidence_path = paths.proxy_dir / "evidence.sqlite"

    setup_payload: dict[str, Any]
    config_error: str | None = None
    try:
        setup_report = derive_setup_status(
            home=home,
            client_id=client_id,
            proxy_command=proxy_command,
            proxy_config_path=config_path,
        )
        setup_payload = setup_status_to_dict(setup_report)
    except ConfigWizardError as exc:
        setup_payload = {
            "setup_status": "incomplete",
            "mode": "unknown",
            "role_preset": "unknown",
            "proxy_config_valid": False,
            "client_config_routes_through_agentveil": False,
            "direct_downstream_entries_count": 0,
            "bypass_risks": ["setup_status_unavailable"],
        }
        config_error = str(exc)

    if config_path.is_file():
        try:
            raw_config = json.loads(config_path.read_text(encoding="utf-8"))
            ProxyConfig.from_dict(raw_config)
        except (ProxyConfigError, json.JSONDecodeError, OSError, TypeError, ValueError):
            setup_payload["setup_status"] = "incomplete"
            config_error = config_error or "proxy_config_invalid"

    policy_pack_id = _read_policy_pack_id(config_path)
    protected_packs = _protected_packs_from_config(config_path)
    records = _load_evidence_records(evidence_path)
    evidence_summary = summarize_evidence(records)

    payload: dict[str, Any] = {
        "ok": config_error is None,
        "errors": [] if config_error is None else [config_error],
        "setup_status": setup_payload.get("setup_status", "incomplete"),
        "mode": setup_payload.get("mode"),
        "role_preset": setup_payload.get("role_preset"),
        "protected_packs": protected_packs,
        "policy_pack": policy_pack_id,
        "client_routes_through_proxy": setup_payload.get(
            "client_config_routes_through_agentveil",
            False,
        ),
        "direct_downstream_entries_count": setup_payload.get(
            "direct_downstream_entries_count",
            0,
        ),
        "bypass_risks": list(setup_payload.get("bypass_risks", ())),
        "unsupported_surfaces": list(unsupported_redirect_packs()),
        "unknown_surfaces": [
            item["summary"]
            for item in _REDIRECT_PACK_SUMMARY
            if item["status"] == "planned"
        ],
        "supported_redirect_packs": list(supported_redirect_packs()),
        "planned_redirect_packs": list(planned_redirect_packs()),
        "unsupported_redirect_packs": list(unsupported_redirect_packs()),
        "redirect_playbook_coverage": list(redirect_playbook_coverage()),
        "redirect_coverage_lines": [item["summary"] for item in _REDIRECT_PACK_SUMMARY],
        "evidence_count": len(records),
        **evidence_summary,
    }
    assert_control_output_is_privacy_safe(payload)
    return payload


def build_control_timeline(
    *,
    home: Path,
    proxy_config_path: Path | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Build bounded timeline entries from durable evidence records."""

    from agentveil_mcp_proxy.cli import proxy_paths

    if limit <= 0:
        raise ControlSurfaceError("--limit must be positive", code="invalid_limit")

    paths = proxy_paths(home, proxy_config_path)
    evidence_path = paths.proxy_dir / "evidence.sqlite"
    records = _load_evidence_records(evidence_path)
    links = _link_follow_up_ids(records)
    selected = records[-limit:]
    events = [
        build_timeline_entry(
            record,
            linked_follow_up_id=links.get(record.request_id),
        )
        for record in selected
    ]
    payload = {
        "ok": True,
        "errors": [],
        "evidence_count": len(records),
        "event_count": len(events),
        "events": events,
    }
    assert_control_output_is_privacy_safe(payload)
    return payload


def _format_timestamp(value: int) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_control_status_human(payload: Mapping[str, Any]) -> str:
    """Render human-readable daily control status."""

    lines = [
        "Daily control status",
        f"Setup: {payload.get('setup_status', 'unknown')}",
        f"Mode: {payload.get('mode', 'unknown')}",
        f"Role preset: {payload.get('role_preset', 'unknown')}",
        f"Protected packs: {', '.join(payload.get('protected_packs', [])) or 'none'}",
        f"Pending approvals: {payload.get('pending_approval_count', 0)}",
        f"Policy denies: {payload.get('policy_deny_count', 0)}",
        f"Role violations: {payload.get('role_violation_count', 0)}",
        f"Redirect originals: {payload.get('redirect_original_count', 0)}",
        f"Redirect follow-ups: {payload.get('redirect_follow_up_count', 0)}",
        (
            "Target reached: "
            f"true={payload.get('target_reached_true_count', 0)} "
            f"false={payload.get('target_reached_false_count', 0)}"
        ),
        "Redirect coverage:",
    ]
    for line in payload.get("redirect_coverage_lines", ()):
        lines.append(f"  - {line}")
    for playbook in payload.get("redirect_playbook_coverage", ()):
        if not isinstance(playbook, Mapping):
            continue
        lines.append(
            "  - "
            f"{playbook.get('redirect_playbook_id')}: "
            f"{playbook.get('automation_level')}"
        )
    bypass_risks = payload.get("bypass_risks", [])
    if bypass_risks:
        lines.append("Bypass risks:")
        for risk in bypass_risks:
            lines.append(f"  - {risk}")
    unsupported = payload.get("unsupported_redirect_packs", [])
    if unsupported:
        lines.append(f"Unsupported redirect packs: {', '.join(unsupported)}")
    planned = payload.get("planned_redirect_packs", [])
    if planned:
        lines.append(f"Planned redirect packs: {', '.join(planned)}")
    for error in payload.get("errors", ()):
        lines.append(f"ERROR: {error}")
    return "\n".join(lines)


def format_control_timeline_human(payload: Mapping[str, Any]) -> str:
    """Render human-readable timeline output."""

    if payload.get("evidence_count", 0) == 0:
        return "Timeline: no evidence records (evidence_count=0)"
    lines = [f"Timeline ({payload.get('event_count', 0)} events)"]
    for event in payload.get("events", ()):
        if not isinstance(event, Mapping):
            continue
        if event.get("event_kind") == "role_violation":
            parts = [
                _format_timestamp(int(event.get("timestamp", 0))),
                "kind=role_violation",
                f"role={event.get('role', '-')}",
                f"authority={event.get('authority', '-')}",
            ]
            if event.get("action_family"):
                parts.append(f"action_family={event['action_family']}")
            parts.append(f"reason={event.get('reason', _ROLE_AUTHORITY_REASON)}")
            if "target_reached" in event:
                parts.append(f"target_reached={event['target_reached']}")
            if event.get("redirect_playbook_id"):
                parts.append(f"playbook={event['redirect_playbook_id']}")
            if event.get("record_id"):
                parts.append(f"evidence={event['record_id']}")
            if event.get("linked_follow_up_id"):
                parts.append(f"linked_follow_up={event['linked_follow_up_id']}")
            lines.append(" ".join(parts))
            continue
        parts = [
            _format_timestamp(int(event.get("timestamp", 0))),
            f"kind={event.get('event_kind', 'unknown')}",
            f"tool={event.get('tool', '-')}",
            f"status={event.get('status', '-')}",
        ]
        if "target_reached" in event:
            parts.append(f"target_reached={event['target_reached']}")
        if event.get("redirect_playbook_id"):
            parts.append(f"playbook={event['redirect_playbook_id']}")
        if event.get("linked_follow_up_id"):
            parts.append(f"linked_follow_up={event['linked_follow_up_id']}")
        if event.get("metadata_state") == "unparseable_metadata":
            parts.append("metadata=unparseable")
        lines.append(" ".join(parts))
    return "\n".join(lines)


__all__ = [
    "AutomationLevel",
    "ControlSurfaceError",
    "RedirectPackStatus",
    "assert_control_output_is_privacy_safe",
    "privacy_markers_in_control_output",
    "build_control_status",
    "build_control_timeline",
    "build_timeline_entry",
    "format_control_status_human",
    "format_control_timeline_human",
    "parse_role_violation_projection",
    "planned_redirect_packs",
    "redirect_pack_summaries",
    "redirect_playbook_coverage",
    "summarize_evidence",
    "supported_redirect_packs",
    "unsupported_redirect_packs",
]
