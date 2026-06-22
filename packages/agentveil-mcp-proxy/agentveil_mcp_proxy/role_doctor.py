"""Bounded explain/redirect guidance and role doctor output for MCP proxy presets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

from agentveil_mcp_proxy.classification import ClassifiedToolCall
from agentveil_mcp_proxy.policy import RiskClass
from agentveil_mcp_proxy.role_presets import ROLE_PRESET_NAMES, resolve_role_preset

_ROLE_AUTHORITY_REASON = "role_authority_denied"

# Keep aligned with policy.role_authority_builtin_rules mutation families.
MUTATION_ACTION_FAMILIES: tuple[str, ...] = (
    "write",
    "create",
    "update",
    "delete",
    "remove",
    "exec",
    "shell",
)
READ_ACTION_FAMILIES: tuple[str, ...] = (
    "read",
    "list",
    "get",
    "search",
    "fetch",
)
WRITE_CAPABLE_ACTION_FAMILIES: tuple[str, ...] = MUTATION_ACTION_FAMILIES
POLICY_APPROVAL_ACTION_FAMILIES: tuple[str, ...] = (
    "write",
    "create",
    "update",
    "delete",
    "remove",
    "destructive",
    # claim-check: allow "production" is a bounded policy action-family label.
    "production",
    "financial",
    "unknown",
)

_REDIRECT_CREATE_IMPLEMENTER_TASK = "create_implementer_task"
_REDIRECT_SWITCH_TO_BUILD_AGENT = "switch_to_build_agent"
_REDIRECT_USE_READ_ONLY_TOOL = "use_read_only_tool"
_REDIRECT_REQUEST_APPROVAL = "request_approval"
_REDIRECT_STOP_AND_CLASSIFY = "stop_and_classify_unknown_action"

REDIRECT_CONTEXT_ARG = "redirect_context"
REDIRECT_ROLE_ORIGINAL = "original"
REDIRECT_ROLE_FOLLOW_UP = "follow_up"
INVALID_REDIRECT_CONTEXT = "invalid_redirect_context"
UNSUPPORTED_REDIRECT_PLAYBOOK = "unsupported_redirect_playbook"


@dataclass(frozen=True)
class RedirectPlaybookSpec:
    """Bounded redirect playbook definition for follow-up workflows."""

    redirect_playbook_id: str
    supports_follow_up: bool
    allowed_follow_up_tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class RedirectContext:
    """Bounded redirect linkage carried on an explicit follow-up tools/call."""

    original_request_id: str
    redirect_playbook_id: str


REDIRECT_PLAYBOOKS: dict[str, RedirectPlaybookSpec] = {
    _REDIRECT_CREATE_IMPLEMENTER_TASK: RedirectPlaybookSpec(
        redirect_playbook_id=_REDIRECT_CREATE_IMPLEMENTER_TASK,
        supports_follow_up=True,
        allowed_follow_up_tools=("read_file",),
    ),
    _REDIRECT_USE_READ_ONLY_TOOL: RedirectPlaybookSpec(
        redirect_playbook_id=_REDIRECT_USE_READ_ONLY_TOOL,
        supports_follow_up=True,
        allowed_follow_up_tools=("read_file",),
    ),
    _REDIRECT_REQUEST_APPROVAL: RedirectPlaybookSpec(
        redirect_playbook_id=_REDIRECT_REQUEST_APPROVAL,
        supports_follow_up=True,
        allowed_follow_up_tools=("write_file",),
    ),
    _REDIRECT_STOP_AND_CLASSIFY: RedirectPlaybookSpec(
        redirect_playbook_id=_REDIRECT_STOP_AND_CLASSIFY,
        supports_follow_up=False,
    ),
    _REDIRECT_SWITCH_TO_BUILD_AGENT: RedirectPlaybookSpec(
        redirect_playbook_id=_REDIRECT_SWITCH_TO_BUILD_AGENT,
        supports_follow_up=True,
        allowed_follow_up_tools=("read_file",),
    ),
}


@dataclass(frozen=True)
class RedirectGuidance:
    """Bounded redirect metadata for deny or approval-required responses."""

    next_step: str
    suggested_next_step_id: str
    redirect_playbook_id: str


@dataclass(frozen=True)
class DenyGuidance:
    """Human-facing deny explanation plus redirect metadata."""

    message: str
    explanation: str
    redirect: RedirectGuidance


@dataclass(frozen=True)
class ApprovalGuidance:
    """Human-facing approval explanation plus redirect metadata."""

    message: str
    explanation: str
    redirect: RedirectGuidance


@dataclass(frozen=True)
class RolePresetGuide:
    """Bounded role doctor view for one preset."""

    preset: str
    role: str
    authority: str
    allowed_action_families: tuple[str, ...]
    approval_required_action_families: tuple[str, ...]
    blocked_action_families: tuple[str, ...]
    summary: str


def _is_mutation_action_family(action_family: str) -> bool:
    return action_family in MUTATION_ACTION_FAMILIES


def _preset_label(preset_name: str) -> str:
    labels = {
        "reviewer": "Review Agent",
        "readonly": "Read-only Agent",
        "implementer": "Implementer Agent",
        "build": "Build Agent",
    }
    return labels.get(preset_name, preset_name.replace("_", " ").title())


def build_deny_guidance(
    classification: ClassifiedToolCall,
    *,
    reason: str,
) -> DenyGuidance:
    """Return bounded deny message, explanation, and redirect metadata."""

    role = classification.role
    action_family = classification.action_family
    if reason == _ROLE_AUTHORITY_REASON and role == "reviewer" and _is_mutation_action_family(action_family):
        explanation = "Review Agent cannot write files."
        redirect = RedirectGuidance(
            next_step="Assign file changes to an Implementer or Build agent.",
            suggested_next_step_id=_REDIRECT_CREATE_IMPLEMENTER_TASK,
            redirect_playbook_id=_REDIRECT_CREATE_IMPLEMENTER_TASK,
        )
        return DenyGuidance(
            message=explanation,
            explanation=explanation,
            redirect=redirect,
        )
    if reason == _ROLE_AUTHORITY_REASON and role == "readonly" and _is_mutation_action_family(action_family):
        explanation = "Read-only Agent cannot modify files or run commands."
        redirect = RedirectGuidance(
            next_step="Use a read-only tool or switch to a Build agent for changes.",
            suggested_next_step_id=_REDIRECT_USE_READ_ONLY_TOOL,
            redirect_playbook_id=_REDIRECT_USE_READ_ONLY_TOOL,
        )
        return DenyGuidance(
            message=explanation,
            explanation=explanation,
            redirect=redirect,
        )
    if classification.risk_class is RiskClass.UNKNOWN:
        explanation = "Unknown action denied until it is classified."
        redirect = RedirectGuidance(
            next_step="Stop and classify this unknown action before retrying.",
            suggested_next_step_id=_REDIRECT_STOP_AND_CLASSIFY,
            redirect_playbook_id=_REDIRECT_STOP_AND_CLASSIFY,
        )
        return DenyGuidance(
            message=explanation,
            explanation=explanation,
            redirect=redirect,
        )
    explanation = "Action denied by MCP proxy policy."
    redirect = RedirectGuidance(
        next_step="Review local policy or switch to an allowed role preset.",
        suggested_next_step_id=_REDIRECT_SWITCH_TO_BUILD_AGENT,
        redirect_playbook_id=_REDIRECT_SWITCH_TO_BUILD_AGENT,
    )
    return DenyGuidance(
        message=explanation,
        explanation=explanation,
        redirect=redirect,
    )


def build_approval_guidance(classification: ClassifiedToolCall, *, reason: str) -> ApprovalGuidance:
    """Return bounded approval-required explanation and redirect metadata."""

    risk = classification.risk_class.value
    action_family = classification.action_family
    explanation = (
        f"Approval is required before this {risk} risk action "
        f"({action_family}) can run."
    )
    redirect = RedirectGuidance(
        next_step="Request human approval, then retry the tool call if approved.",
        suggested_next_step_id=_REDIRECT_REQUEST_APPROVAL,
        redirect_playbook_id=_REDIRECT_REQUEST_APPROVAL,
    )
    return ApprovalGuidance(
        message="approval required",
        explanation=explanation,
        redirect=redirect,
    )


def redirect_fields(redirect: RedirectGuidance) -> dict[str, str]:
    """Return bounded redirect keys for JSON-RPC error data."""

    return {
        "next_step": redirect.next_step,
        "suggested_next_step_id": redirect.suggested_next_step_id,
        "redirect_playbook_id": redirect.redirect_playbook_id,
    }


def playbook_spec(playbook_id: str) -> RedirectPlaybookSpec | None:
    """Return a redirect playbook spec when ``playbook_id`` is known."""

    return REDIRECT_PLAYBOOKS.get(playbook_id)


def playbook_supports_follow_up(playbook_id: str) -> bool:
    """Return True when a playbook allows explicit follow-up tool actions."""

    spec = playbook_spec(playbook_id)
    return spec is not None and spec.supports_follow_up


def redirect_context_stub(
    *,
    original_request_id: str,
    redirect_playbook_id: str,
) -> dict[str, str]:
    """Return bounded redirect_context for client follow-up tools/call args."""

    return {
        "original_request_id": original_request_id,
        "redirect_playbook_id": redirect_playbook_id,
    }


def redirect_automation_status_fields(
    *,
    original_executed: bool,
    follow_up_required: bool,
) -> dict[str, bool]:
    """Return bounded redirect automation status for user-visible responses."""

    return {
        "original_executed": original_executed,
        "follow_up_required": follow_up_required,
    }


def parse_redirect_context(arguments: Any) -> tuple[RedirectContext | None, str | None]:
    """Parse and validate bounded redirect_context from MCP tool arguments."""

    if not isinstance(arguments, Mapping):
        return None, None
    raw = arguments.get(REDIRECT_CONTEXT_ARG)
    if raw is None:
        return None, None
    if not isinstance(raw, Mapping):
        return None, INVALID_REDIRECT_CONTEXT
    original_request_id = raw.get("original_request_id")
    redirect_playbook_id = raw.get("redirect_playbook_id")
    if not isinstance(original_request_id, str) or not original_request_id.strip():
        return None, INVALID_REDIRECT_CONTEXT
    if not isinstance(redirect_playbook_id, str) or not redirect_playbook_id.strip():
        return None, INVALID_REDIRECT_CONTEXT
    if playbook_spec(redirect_playbook_id) is None:
        return None, INVALID_REDIRECT_CONTEXT
    return RedirectContext(
        original_request_id=original_request_id.strip(),
        redirect_playbook_id=redirect_playbook_id.strip(),
    ), None


def validate_follow_up_redirect(context: RedirectContext, tool_name: str) -> str | None:
    """Return a bounded error reason when follow-up redirect cannot proceed."""

    spec = playbook_spec(context.redirect_playbook_id)
    if spec is None:
        return INVALID_REDIRECT_CONTEXT
    if not spec.supports_follow_up:
        return UNSUPPORTED_REDIRECT_PLAYBOOK
    if spec.allowed_follow_up_tools and tool_name not in spec.allowed_follow_up_tools:
        return UNSUPPORTED_REDIRECT_PLAYBOOK
    return None


def strip_redirect_context(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Return tool arguments with redirect_context removed before downstream."""

    if REDIRECT_CONTEXT_ARG not in arguments:
        return dict(arguments)
    stripped = dict(arguments)
    stripped.pop(REDIRECT_CONTEXT_ARG, None)
    return stripped


def redirect_playbook_id_for_classification(
    classification: ClassifiedToolCall,
    *,
    reason: str,
    outcome: Literal["deny", "approval"],
) -> str:
    """Return the redirect playbook id for one classified tool call."""

    if outcome == "approval":
        return build_approval_guidance(classification, reason=reason).redirect.redirect_playbook_id
    return build_deny_guidance(classification, reason=reason).redirect.redirect_playbook_id


def enrich_error_data(
    data: dict[str, Any],
    classification: ClassifiedToolCall | None,
    *,
    outcome: Literal["deny", "approval"],
    original_request_id: str | None = None,
) -> dict[str, Any]:
    """Attach bounded explanation and redirect metadata to JSON-RPC error data."""

    if classification is None:
        return data
    reason = str(data.get("reason", ""))
    if outcome == "approval":
        guidance = build_approval_guidance(classification, reason=reason)
        data["explanation"] = guidance.explanation
        data.update(redirect_fields(guidance.redirect))
    else:
        guidance = build_deny_guidance(classification, reason=reason)
        data["explanation"] = guidance.explanation
        data.update(redirect_fields(guidance.redirect))
    if original_request_id is not None:
        data["original_request_id"] = original_request_id
        data["redirect_context"] = redirect_context_stub(
            original_request_id=original_request_id,
            redirect_playbook_id=guidance.redirect.redirect_playbook_id,
        )
        data["redirect_automation"] = redirect_automation_status_fields(
            original_executed=False,
            follow_up_required=playbook_supports_follow_up(guidance.redirect.redirect_playbook_id),
        )
    return data


def blocked_error_message(
    classification: ClassifiedToolCall | None,
    *,
    reason: str,
    default_message: str,
) -> str:
    """Return a human-facing deny message when guidance is available."""

    if classification is None:
        return default_message
    if reason == _ROLE_AUTHORITY_REASON or classification.risk_class is RiskClass.UNKNOWN:
        return build_deny_guidance(classification, reason=reason).message
    return default_message


def build_role_preset_guide(preset_name: str) -> RolePresetGuide:
    """Return bounded allowed/approval/deny families for one role preset."""

    preset = resolve_role_preset(preset_name)
    if preset.name in {"reviewer", "readonly"}:
        return RolePresetGuide(
            preset=preset.name,
            role=preset.role,
            authority=preset.authority,
            allowed_action_families=READ_ACTION_FAMILIES,
            approval_required_action_families=POLICY_APPROVAL_ACTION_FAMILIES,
            blocked_action_families=MUTATION_ACTION_FAMILIES,
            summary=(
                f"{_preset_label(preset.name)} may read and inspect tools; "
                # claim-check: allow "blocked" is bounded role-doctor status text.
                "mutation and command actions are blocked by role authority."
            ),
        )
    return RolePresetGuide(
        preset=preset.name,
        role=preset.role,
        authority=preset.authority,
        allowed_action_families=READ_ACTION_FAMILIES + WRITE_CAPABLE_ACTION_FAMILIES,
        approval_required_action_families=POLICY_APPROVAL_ACTION_FAMILIES,
        blocked_action_families=(),
        summary=(
            f"{_preset_label(preset.name)} may read and write when local policy allows; "
            "high-risk actions may still require approval."
        ),
    )


def build_role_doctor_report(
    *,
    preset_name: str | None = None,
    role_preset: str | None = None,
) -> dict[str, Any]:
    """Return JSON-serializable role doctor output for one preset or the preset set."""

    selected = preset_name or role_preset
    if selected:
        guide = build_role_preset_guide(selected)
        return {
            "preset": guide.preset,
            "role": guide.role,
            "authority": guide.authority,
            "allowed_action_families": list(guide.allowed_action_families),
            "approval_required_action_families": list(guide.approval_required_action_families),
            "blocked_action_families": list(guide.blocked_action_families),
            "summary": guide.summary,
        }
    return {
        "presets": [
            build_role_doctor_report(preset_name=name)
            for name in ROLE_PRESET_NAMES
        ],
    }


def format_role_doctor_report(report: Mapping[str, Any]) -> str:
    """Render human-readable role doctor output."""

    if "presets" in report:
        lines = ["Role doctor: preset capabilities", ""]
        for preset_report in report["presets"]:
            lines.append(format_role_doctor_report(preset_report))
            lines.append("")
        return "\n".join(lines).rstrip()

    lines = [
        f"Preset: {report['preset']}",
        f"Role: {report['role']}",
        f"Authority: {report['authority']}",
        f"Allowed action families: {', '.join(report['allowed_action_families'])}",
        (
            "Approval-required action families: "
            f"{', '.join(report['approval_required_action_families'])}"
        ),
        # claim-check: allow "Blocked" is the literal bounded role-doctor label.
        f"Blocked action families: {', '.join(report['blocked_action_families']) or 'none'}",
        f"Summary: {report['summary']}",
    ]
    return "\n".join(lines)


__all__ = [
    "ApprovalGuidance",
    "DenyGuidance",
    "INVALID_REDIRECT_CONTEXT",
    "MUTATION_ACTION_FAMILIES",
    "READ_ACTION_FAMILIES",
    "REDIRECT_CONTEXT_ARG",
    "REDIRECT_PLAYBOOKS",
    "REDIRECT_ROLE_FOLLOW_UP",
    "REDIRECT_ROLE_ORIGINAL",
    "RedirectContext",
    "RedirectGuidance",
    "RedirectPlaybookSpec",
    "RolePresetGuide",
    "UNSUPPORTED_REDIRECT_PLAYBOOK",
    "blocked_error_message",
    "build_approval_guidance",
    "build_deny_guidance",
    "build_role_doctor_report",
    "build_role_preset_guide",
    "enrich_error_data",
    "format_role_doctor_report",
    "parse_redirect_context",
    "playbook_spec",
    "playbook_supports_follow_up",
    "redirect_automation_status_fields",
    "redirect_context_stub",
    "redirect_fields",
    "redirect_playbook_id_for_classification",
    "strip_redirect_context",
    "validate_follow_up_redirect",
]
