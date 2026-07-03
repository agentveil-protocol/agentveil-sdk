"""Risk-family redirect playbooks for product-route MCP proxy behavior.

Maps ``tool -> risk_family -> redirect_playbook`` with bounded guidance for
approval, deny, and block responses. Tool resolution is deterministic and
catalog-driven; it does not match natural-language scenario text.

Negative test: packages/agentveil-mcp-proxy/tests/test_mcp_proxy_redirect_playbooks.py
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Mapping

from agentveil_mcp_proxy.classification import ClassifiedToolCall
from agentveil_mcp_proxy.policy import RiskClass
from agentveil_mcp_proxy.product_route import (
    PRODUCT_ROUTE_POLICY_ID,
    PRODUCT_ROUTE_TOOL_CATALOG,
    SANDBOX_READ_ONLY_MCP_TOOLS,
)


class RiskFamily(str, Enum):
    """Stable risk families for redirect routing."""

    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    GIT_MUTATION = "git_mutation"
    PACKAGE_MUTATION = "package_mutation"
    SECRET_ACCESS = "secret_access"
    DEPLOY_RELEASE = "deploy_release"
    REPO_ADMIN_OR_MERGE = "repo_admin_or_merge"
    UNTRUSTED_INSTRUCTION_SURFACE = "untrusted_instruction_surface"
    CI_WORKFLOW_MUTATION = "ci_workflow_mutation"
    REMOTE_COMMAND = "remote_command"
    UNKNOWN = "unknown"


class RedirectPlaybook(str, Enum):
    """Deterministic redirect playbook identifiers."""

    INSPECT_BEFORE_WRITE = "inspect_before_write"
    INSPECT_BEFORE_DELETE = "inspect_before_delete"
    SHOW_GIT_STATUS_AND_DIFF = "show_git_status_and_diff"
    INSPECT_PACKAGE_RISK = "inspect_package_risk"
    SECRET_POSTURE_ONLY = "secret_posture_only"
    RELEASE_READINESS_CHECK = "release_readiness_check"
    REPO_CHANGE_REVIEW = "repo_change_review"
    UNTRUSTED_TEXT_REVIEW = "untrusted_text_review"
    WORKFLOW_REVIEW = "workflow_review"
    REMOTE_COMMAND_REVIEW = "remote_command_review"
    STOP_AND_CLASSIFY_UNKNOWN = "stop_and_classify_unknown_action"


RISK_FAMILY_TO_PLAYBOOK: dict[RiskFamily, RedirectPlaybook] = {
    RiskFamily.FILE_WRITE: RedirectPlaybook.INSPECT_BEFORE_WRITE,
    RiskFamily.FILE_DELETE: RedirectPlaybook.INSPECT_BEFORE_DELETE,
    RiskFamily.GIT_MUTATION: RedirectPlaybook.SHOW_GIT_STATUS_AND_DIFF,
    RiskFamily.PACKAGE_MUTATION: RedirectPlaybook.INSPECT_PACKAGE_RISK,
    RiskFamily.SECRET_ACCESS: RedirectPlaybook.SECRET_POSTURE_ONLY,
    RiskFamily.DEPLOY_RELEASE: RedirectPlaybook.RELEASE_READINESS_CHECK,
    RiskFamily.REPO_ADMIN_OR_MERGE: RedirectPlaybook.REPO_CHANGE_REVIEW,
    RiskFamily.UNTRUSTED_INSTRUCTION_SURFACE: RedirectPlaybook.UNTRUSTED_TEXT_REVIEW,
    RiskFamily.CI_WORKFLOW_MUTATION: RedirectPlaybook.WORKFLOW_REVIEW,
    RiskFamily.REMOTE_COMMAND: RedirectPlaybook.REMOTE_COMMAND_REVIEW,
    RiskFamily.UNKNOWN: RedirectPlaybook.STOP_AND_CLASSIFY_UNKNOWN,
}

REQUIRED_RISK_FAMILIES: frozenset[RiskFamily] = frozenset({
    RiskFamily.FILE_WRITE,
    RiskFamily.FILE_DELETE,
    RiskFamily.GIT_MUTATION,
    RiskFamily.PACKAGE_MUTATION,
    RiskFamily.SECRET_ACCESS,
    RiskFamily.DEPLOY_RELEASE,
    RiskFamily.REPO_ADMIN_OR_MERGE,
    RiskFamily.CI_WORKFLOW_MUTATION,
    RiskFamily.REMOTE_COMMAND,
    RiskFamily.UNTRUSTED_INSTRUCTION_SURFACE,
})

_FILE_WRITE_TOOLS = frozenset({
    "write_file",
    "move_file",
    "copy_file",
    "chmod_file",
    "create_symlink",
    "create_issue",
    "update_issue",
    "create_comment",
    "add_labels",
    "remove_labels",
    "request_review",
})

_FILE_DELETE_TOOLS = frozenset({
    "delete_file",
    "rmdir_tree",
    "close_issue",
    "delete_branch",
    "cancel_workflow",
    "git_clean",
    "git_reset",
})

_GIT_MUTATION_TOOLS = frozenset({
    "git_add",
    "git_commit",
    "git_push",
    "git_checkout",
    "git_create_branch",
    "git_rebase",
})

_PACKAGE_MUTATION_TOOLS = frozenset({
    "pip_install",
    "pip_uninstall",
    "pip_update",
    "pip_run_script",
})

_SECRET_ACCESS_TOOLS = frozenset({
    "get_secret",
    "get_env_secret",
    "manage_secret",
    "list_secret_names",
})

_DEPLOY_RELEASE_TOOLS = frozenset({
    "deploy_release",
    "create_release",
    "rerun_workflow",
    "dispatch_workflow",
    "publish_package",
})

_REPO_ADMIN_TOOLS = frozenset({
    "merge_pull_request",
    "update_repository_settings",
})

_UNTRUSTED_SURFACE_TOOLS = frozenset({
    "instruction_surface_status",
    "untrusted_context_status",
    "package_risk_status",
    "github_target_snapshot",
    "ci_repo_target_snapshot",
})

_CI_WORKFLOW_TOOLS = frozenset({
    "rerun_workflow",
    "cancel_workflow",
    "dispatch_workflow",
})

_REMOTE_COMMAND_TOOLS = frozenset({
    "run_remote_command",
})

_TOOL_RISK_FAMILIES: dict[str, RiskFamily] = {}
for tool in _FILE_WRITE_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.FILE_WRITE
for tool in _FILE_DELETE_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.FILE_DELETE
for tool in _GIT_MUTATION_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.GIT_MUTATION
for tool in _PACKAGE_MUTATION_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.PACKAGE_MUTATION
for tool in _SECRET_ACCESS_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.SECRET_ACCESS
for tool in _DEPLOY_RELEASE_TOOLS - _CI_WORKFLOW_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.DEPLOY_RELEASE
for tool in _REPO_ADMIN_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.REPO_ADMIN_OR_MERGE
for tool in _UNTRUSTED_SURFACE_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.UNTRUSTED_INSTRUCTION_SURFACE
for tool in _CI_WORKFLOW_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.CI_WORKFLOW_MUTATION
for tool in _REMOTE_COMMAND_TOOLS:
    _TOOL_RISK_FAMILIES[tool] = RiskFamily.REMOTE_COMMAND

_READ_TOOL_FALLBACK: dict[str, RiskFamily] = {
    "list_workspace": RiskFamily.FILE_WRITE,
    "git_status": RiskFamily.GIT_MUTATION,
    "git_log": RiskFamily.GIT_MUTATION,
    "git_diff": RiskFamily.GIT_MUTATION,
    "git_diff_staged": RiskFamily.GIT_MUTATION,
    "git_diff_unstaged": RiskFamily.GIT_MUTATION,
    "git_show": RiskFamily.GIT_MUTATION,
    "git_branch": RiskFamily.GIT_MUTATION,
    "package_list_manifest": RiskFamily.PACKAGE_MUTATION,
    "package_inspect_state": RiskFamily.PACKAGE_MUTATION,
    "get_repository": RiskFamily.REPO_ADMIN_OR_MERGE,
    "list_issues": RiskFamily.REPO_ADMIN_OR_MERGE,
    "get_issue": RiskFamily.REPO_ADMIN_OR_MERGE,
    "list_pull_requests": RiskFamily.REPO_ADMIN_OR_MERGE,
    "get_pull_request": RiskFamily.REPO_ADMIN_OR_MERGE,
    "list_comments": RiskFamily.REPO_ADMIN_OR_MERGE,
    "list_branches": RiskFamily.REPO_ADMIN_OR_MERGE,
    "list_files": RiskFamily.FILE_WRITE,
    "get_repository_settings": RiskFamily.REPO_ADMIN_OR_MERGE,
    "list_workflow_runs": RiskFamily.CI_WORKFLOW_MUTATION,
    "list_workflows": RiskFamily.CI_WORKFLOW_MUTATION,
    "get_workflow": RiskFamily.CI_WORKFLOW_MUTATION,
    "list_ci_jobs": RiskFamily.CI_WORKFLOW_MUTATION,
    "get_ci_job": RiskFamily.CI_WORKFLOW_MUTATION,
    "get_package_metadata": RiskFamily.PACKAGE_MUTATION,
}
for tool, family in _READ_TOOL_FALLBACK.items():
    _TOOL_RISK_FAMILIES.setdefault(tool, family)

for tool in PRODUCT_ROUTE_TOOL_CATALOG:
    _TOOL_RISK_FAMILIES.setdefault(tool, RiskFamily.UNKNOWN)

_SENSITIVE_PATH_MARKERS: tuple[str, ...] = (
    ".git/",
    ".env",
    ".ssh/",
    ".avp/",
    ".agentveil/",
)

_DEFAULT_REDIRECT_TOOLS: frozenset[str] = frozenset({
    "list_workspace",
    "read_file",
    "get_file_info",
    "instruction_surface_status",
    "git_status",
    "git_diff",
    "git_diff_staged",
    "git_diff_unstaged",
    "git_log",
    "git_show",
    "git_branch",
    "package_inspect_state",
    "package_list_manifest",
    "package_risk_status",
}) | SANDBOX_READ_ONLY_MCP_TOOLS

_PLAYBOOK_PRIMARY_TOOLS: dict[str, str] = {
    RedirectPlaybook.INSPECT_BEFORE_WRITE.value: "read_file",
    RedirectPlaybook.INSPECT_BEFORE_DELETE.value: "read_file",
    RedirectPlaybook.SHOW_GIT_STATUS_AND_DIFF.value: "git_status",
    RedirectPlaybook.INSPECT_PACKAGE_RISK.value: "package_inspect_state",
    RedirectPlaybook.SECRET_POSTURE_ONLY.value: "instruction_surface_status",
    RedirectPlaybook.RELEASE_READINESS_CHECK.value: "list_workspace",
    RedirectPlaybook.REPO_CHANGE_REVIEW.value: "list_workspace",
    RedirectPlaybook.UNTRUSTED_TEXT_REVIEW.value: "instruction_surface_status",
    RedirectPlaybook.WORKFLOW_REVIEW.value: "list_workspace",
    RedirectPlaybook.REMOTE_COMMAND_REVIEW.value: "list_workspace",
    RedirectPlaybook.STOP_AND_CLASSIFY_UNKNOWN.value: "list_workspace",
}

RedirectOutcome = Literal["approval_required", "hard_blocked"]


@dataclass(frozen=True)
class PlaybookSpec:
    """Bounded redirect playbook content."""

    redirect_playbook: RedirectPlaybook
    risk_reason: str
    safe_first_step: str
    target_outcome: str


PLAYBOOK_SPECS: dict[RedirectPlaybook, PlaybookSpec] = {
    RedirectPlaybook.INSPECT_BEFORE_WRITE: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.INSPECT_BEFORE_WRITE,
        risk_reason="File writes can overwrite data or introduce untrusted content.",
        safe_first_step="List workspace files and read the target path before writing.",
        target_outcome="Target file unchanged until inspection completes and approval is granted.",
    ),
    RedirectPlaybook.INSPECT_BEFORE_DELETE: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.INSPECT_BEFORE_DELETE,
        risk_reason="Deletes remove data and may be irreversible.",
        safe_first_step="Read the target path and confirm it is safe to delete.",  # claim-check: allow bounded playbook UI string.
        target_outcome="Target path still present until delete is approved and executed.",
    ),
    RedirectPlaybook.SHOW_GIT_STATUS_AND_DIFF: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.SHOW_GIT_STATUS_AND_DIFF,
        risk_reason="Git mutations change repository history or remotes.",
        safe_first_step="Run git status and review the diff before staging or pushing.",
        target_outcome="Repository state unchanged until git mutation is approved.",
    ),
    RedirectPlaybook.INSPECT_PACKAGE_RISK: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.INSPECT_PACKAGE_RISK,
        risk_reason="Package installs and scripts can execute arbitrary code.",
        safe_first_step="Inspect package manifest and risk status before installing.",
        target_outcome="Package environment unchanged until install is approved.",
    ),
    RedirectPlaybook.SECRET_POSTURE_ONLY: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.SECRET_POSTURE_ONLY,
        risk_reason="Secret access can expose credentials; values are never returned.",  # claim-check: allow negative-test contract wording for secret posture.
        safe_first_step="Review secret posture metadata only; secret values are never returned.",  # claim-check: allow negative-test contract wording for secret posture.
        target_outcome="No secret value retrieved; target secret store unchanged.",
    ),
    RedirectPlaybook.RELEASE_READINESS_CHECK: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.RELEASE_READINESS_CHECK,
        risk_reason="Deploy and release actions affect production targets.",  # claim-check: allow production as RiskClass enum vocabulary.
        safe_first_step="Review release readiness, workflow status, and target snapshot.",
        target_outcome="Production target unchanged until release action is approved.",  # claim-check: allow production as RiskClass enum vocabulary.
    ),
    RedirectPlaybook.REPO_CHANGE_REVIEW: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.REPO_CHANGE_REVIEW,
        risk_reason="Repository admin actions can merge or reconfigure protected resources.",
        safe_first_step="Review pull request, branch protections, and repo settings diff.",
        target_outcome="Repository admin state unchanged until change is approved.",
    ),
    RedirectPlaybook.UNTRUSTED_TEXT_REVIEW: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.UNTRUSTED_TEXT_REVIEW,
        risk_reason="Untrusted instruction surfaces must not become authority.",
        safe_first_step="Review instruction-surface status and untrusted-text markers only.",
        target_outcome="No mutation from untrusted text; inspection metadata only.",
    ),
    RedirectPlaybook.WORKFLOW_REVIEW: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.WORKFLOW_REVIEW,
        risk_reason="CI workflow mutations can change automation and deployment paths.",
        safe_first_step="Review workflow definition, recent runs, and target snapshot.",
        target_outcome="Workflow target unchanged until workflow mutation is approved.",
    ),
    RedirectPlaybook.REMOTE_COMMAND_REVIEW: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.REMOTE_COMMAND_REVIEW,
        risk_reason="Remote commands execute code outside the local sandbox.",
        safe_first_step="Review remote command scope, target snapshot, and approval posture.",
        target_outcome="Remote target unchanged until command is approved.",
    ),
    RedirectPlaybook.STOP_AND_CLASSIFY_UNKNOWN: PlaybookSpec(
        redirect_playbook=RedirectPlaybook.STOP_AND_CLASSIFY_UNKNOWN,
        risk_reason="Unknown actions are denied until classified into a risk family.",
        safe_first_step="Stop and classify this action before retrying.",
        target_outcome="Target unchanged until the action is classified and approved.",
    ),
}


@dataclass(frozen=True)
class RiskFamilyRedirectGuidance:
    """Bounded redirect guidance derived from risk-family playbooks."""

    risk_family: str
    redirect_playbook: str
    requested_action: str
    risk_reason: str
    safe_first_step_id: str
    approval_required: bool
    target_outcome: str
    redirect_playbook_id: str


def resolve_risk_family(
    tool: str,
    *,
    action_family: str | None = None,
    risk_class: RiskClass | None = None,
) -> RiskFamily:
    """Return the stable risk family for one MCP tool name."""

    explicit = _TOOL_RISK_FAMILIES.get(tool)
    if explicit is not None:
        return explicit
    return _fallback_risk_family(
        tool,
        action_family=action_family or "unknown",
        risk_class=risk_class or RiskClass.UNKNOWN,
    )


def _fallback_risk_family(
    tool: str,
    *,
    action_family: str,
    risk_class: RiskClass,
) -> RiskFamily:
    """Deterministic metadata fallback when a tool is outside the catalog map."""

    if tool in _SECRET_ACCESS_TOOLS or action_family in {"secret"}:
        return RiskFamily.SECRET_ACCESS
    if action_family in {"delete", "remove"} or risk_class is RiskClass.DESTRUCTIVE:
        return RiskFamily.FILE_DELETE
    if action_family in {"exec", "shell"} or tool.startswith("run_"):
        return RiskFamily.REMOTE_COMMAND
    if risk_class is RiskClass.PRODUCTION:  # claim-check: allow production as RiskClass enum vocabulary.
        return RiskFamily.DEPLOY_RELEASE
    if action_family in {"write", "create", "update"} or risk_class is RiskClass.WRITE:
        return RiskFamily.FILE_WRITE
    if action_family.startswith("git") or tool.startswith("git_"):
        return RiskFamily.GIT_MUTATION
    if action_family in {"install", "update"} or tool.startswith("pip_"):
        return RiskFamily.PACKAGE_MUTATION
    return RiskFamily.UNKNOWN


def resolve_redirect_playbook(risk_family: RiskFamily) -> RedirectPlaybook:
    """Return the redirect playbook constant for one risk family."""

    return RISK_FAMILY_TO_PLAYBOOK[risk_family]


def uses_risk_family_redirects(classification: ClassifiedToolCall) -> bool:
    """Return True when redirect output should use risk-family playbooks."""

    return classification.policy_evaluation.policy_id == PRODUCT_ROUTE_POLICY_ID


def build_risk_family_guidance(
    classification: ClassifiedToolCall,
    *,
    outcome: Literal["deny", "approval", "block"],
    reason: str = "",
) -> RiskFamilyRedirectGuidance:
    """Build bounded redirect guidance for one classified tool call."""

    del reason  # deterministic routing ignores free-text reason strings
    risk_family = resolve_risk_family(
        classification.tool,
        action_family=classification.action_family,
        risk_class=classification.risk_class,
    )
    playbook = resolve_redirect_playbook(risk_family)
    spec = PLAYBOOK_SPECS[playbook]
    playbook_id = playbook.value
    return RiskFamilyRedirectGuidance(
        risk_family=risk_family.value,
        redirect_playbook=playbook_id,
        requested_action=classification.tool,
        risk_reason=spec.risk_reason,
        safe_first_step_id=playbook_id,
        approval_required=outcome == "approval",
        target_outcome=spec.target_outcome,
        redirect_playbook_id=playbook_id,
    )


def redirect_fields_from_guidance(
    guidance: RiskFamilyRedirectGuidance,
    *,
    classification: ClassifiedToolCall | None = None,
    request_id: str | None = None,
    available_tools: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Return bounded redirect keys for JSON-RPC error data."""

    redirect_outcome: RedirectOutcome = (
        "approval_required" if guidance.approval_required else "hard_blocked"
    )
    fields: dict[str, Any] = {
        "risk_family": guidance.risk_family,
        "redirect_playbook": guidance.redirect_playbook,
        "requested_action": guidance.requested_action,
        "risk_reason": guidance.risk_reason,
        "safe_first_step_id": guidance.safe_first_step_id,
        "approval_required": guidance.approval_required,
        "redirect_outcome": redirect_outcome,
        "target_outcome": guidance.target_outcome,
        "target_reached": False,
        "redirect_playbook_id": guidance.redirect_playbook_id,
    }
    if classification is not None:
        fields["redirect"] = build_structured_redirect_contract(
            classification,
            guidance,
            redirect_outcome=redirect_outcome,
            available_tools=available_tools,
        )
        if request_id is not None:
            fields["original_request_fingerprint"] = build_original_request_fingerprint(
                classification,
                request_id,
            )
    return fields


def _path_is_sensitive(resource_plain: str | None) -> bool:
    if resource_plain is None:
        return False
    normalized = resource_plain.replace("\\", "/").lower().strip()
    if not normalized:
        return False
    if normalized.startswith("/") or normalized.startswith("~"):
        return True
    if any(marker in normalized for marker in _SENSITIVE_PATH_MARKERS):
        return True
    return any(part.startswith(".") for part in Path(normalized).parts)


def _bounded_relative_path(resource_plain: str | None) -> str | None:
    if resource_plain is None:
        return None
    text = resource_plain.strip()
    if not text or text.startswith("/") or text.startswith("~"):
        return None
    if ".." in Path(text).parts:
        return None
    if _path_is_sensitive(text):
        return None
    return text


def _redirect_tool_available(tool: str, available_tools: frozenset[str]) -> bool:
    return tool in available_tools


def _next_action_for_tool(
    tool: str,
    classification: ClassifiedToolCall,
    *,
    available_tools: frozenset[str],
) -> dict[str, Any] | None:
    if not _redirect_tool_available(tool, available_tools):
        return None
    args: dict[str, Any] = {}
    if tool in {"read_file", "get_file_info"}:
        path = _bounded_relative_path(classification.resource_plain)
        if path is None:
            return None
        args = {"path": path}
    return {"tool": tool, "args": args}


_FALLBACK_TOOL_CANDIDATES: tuple[str, ...] = (
    "list_workspace",
    "instruction_surface_status",
    "git_status",
    "package_inspect_state",
)


def _first_available_tool(
    candidates: tuple[str, ...],
    available_tools: frozenset[str],
) -> str | None:
    for tool in candidates:
        if tool in available_tools:
            return tool
    return None


def build_structured_redirect_contract(
    classification: ClassifiedToolCall,
    guidance: RiskFamilyRedirectGuidance,
    *,
    redirect_outcome: RedirectOutcome,
    available_tools: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Return bounded machine-readable redirect next action for agents."""

    tools = _DEFAULT_REDIRECT_TOOLS if available_tools is None else available_tools
    then_retry_original = redirect_outcome == "approval_required"
    playbook_id = guidance.redirect_playbook_id
    primary_tool = _PLAYBOOK_PRIMARY_TOOLS.get(playbook_id, "list_workspace")
    fallback_tool = _first_available_tool(_FALLBACK_TOOL_CANDIDATES, tools)

    if guidance.risk_family == RiskFamily.SECRET_ACCESS.value:
        primary_tool = "instruction_surface_status"
    elif _path_is_sensitive(classification.resource_plain):
        primary_tool = fallback_tool or primary_tool
    if redirect_outcome == "hard_blocked" and guidance.risk_family in {
        RiskFamily.FILE_DELETE.value,
        RiskFamily.SECRET_ACCESS.value,
    }:
        primary_tool = fallback_tool or primary_tool

    next_action = _next_action_for_tool(
        primary_tool,
        classification,
        available_tools=tools,
    )
    fallback_next_action = None
    if fallback_tool is not None:
        fallback_next_action = _next_action_for_tool(
            fallback_tool,
            classification,
            available_tools=tools,
        )
        if fallback_next_action is None and _redirect_tool_available(fallback_tool, tools):
            fallback_next_action = {"tool": fallback_tool, "args": {}}
    if next_action is None and fallback_next_action is not None:
        next_action = fallback_next_action

    kind = playbook_id
    if redirect_outcome == "hard_blocked" and guidance.risk_family == RiskFamily.SECRET_ACCESS.value:
        kind = "sensitive_path_blocked"

    contract: dict[str, Any] = {
        "kind": kind,
        "target_changed": False,
        "then_retry_original": then_retry_original,
        "next_action": next_action,
        "fallback_next_action": fallback_next_action,
    }
    if next_action is None:
        contract["next_action_unavailable_reason"] = (
            "no advertised read-only tool is available for this redirect"
        )
    return contract


def build_original_request_fingerprint(
    classification: ClassifiedToolCall,
    request_id: str,
) -> dict[str, str]:
    """Return bounded original-request identity without raw payload content."""

    if classification.resource_hash:
        target_ref = f"resource:{classification.resource_hash}"
    elif classification.resource:
        target_ref = f"resource:{classification.resource}"
    else:
        target_ref = "target:unknown"
    return {
        "tool": classification.tool,
        "target_ref": target_ref,
        "payload_hash": classification.payload_hash,
        "request_id": request_id,
    }


def message_visible_approval_redirect(
    guidance: RiskFamilyRedirectGuidance,
    *,
    approval_url: str,
) -> str:
    """Return bounded redirect guidance for clients that only show error.message."""

    spec = PLAYBOOK_SPECS[RedirectPlaybook(guidance.redirect_playbook_id)]
    return (
        f"Approval required for {guidance.risk_family}.\n"
        f"Redirect playbook: {guidance.redirect_playbook}.\n"
        f"Safe first step: {spec.safe_first_step}\n"  # claim-check: allow bounded playbook UI string.
        f"Approval can allow the exact same MCP tool call after review.\n"
        f"Open {approval_url}, approve or deny, then retry the same request."
    )


def message_visible_blocked_redirect(
    guidance: RiskFamilyRedirectGuidance,
) -> str:
    """Return bounded block guidance for clients that only show error.message."""

    spec = PLAYBOOK_SPECS[RedirectPlaybook(guidance.redirect_playbook_id)]
    if guidance.risk_family == RiskFamily.SECRET_ACCESS.value:
        return (
            "Secret access blocked.\n"  # claim-check: allow blocked as JSON-RPC status vocabulary.
            f"Redirect playbook: {guidance.redirect_playbook}.\n"
            f"Safe first step: {spec.safe_first_step}\n"  # claim-check: allow bounded playbook UI string.
            "The original secret access will not be allowed; inspect posture only."
        )
    if guidance.risk_family == RiskFamily.FILE_DELETE.value:
        return (
            f"Action blocked for {guidance.risk_family}.\n"  # claim-check: allow blocked as JSON-RPC status vocabulary.
            f"Redirect playbook: {guidance.redirect_playbook}.\n"
            f"Safe first step: {spec.safe_first_step}\n"  # claim-check: allow bounded playbook UI string.
            "The original delete will not be allowed; confirm target identity with read-only inspection only."
        )
    return (
        f"Action blocked for {guidance.risk_family}.\n"  # claim-check: allow blocked as JSON-RPC status vocabulary.
        f"Redirect playbook: {guidance.redirect_playbook}.\n"
        f"Safe first step: {spec.safe_first_step}\n"  # claim-check: allow bounded playbook UI string.
        "The original action will not be allowed; use the safe inspection step only."
    )


def redirect_playbook_id_for_risk_family(
    classification: ClassifiedToolCall,
    *,
    outcome: Literal["deny", "approval", "block"],
    reason: str = "",
) -> str:
    """Return redirect playbook id from risk-family routing."""

    return build_risk_family_guidance(
        classification,
        outcome=outcome,
        reason=reason,
    ).redirect_playbook_id


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


def enrich_risk_family_error_data(
    data: dict[str, Any],
    classification: ClassifiedToolCall,
    *,
    outcome: Literal["deny", "approval", "block"],
    original_request_id: str | None = None,
) -> dict[str, Any]:
    """Attach risk-family redirect metadata to JSON-RPC error data."""

    guidance = build_risk_family_guidance(classification, outcome=outcome)
    data.update(
        redirect_fields_from_guidance(
            guidance,
            classification=classification,
            request_id=original_request_id,
        )
    )
    if original_request_id is not None:
        data["original_request_id"] = original_request_id
        data["redirect_context"] = redirect_context_stub(
            original_request_id=original_request_id,
            redirect_playbook_id=guidance.redirect_playbook_id,
        )
        data["redirect_automation"] = redirect_automation_status_fields(
            original_executed=False,
            follow_up_required=(
                guidance.redirect_playbook_id
                != RedirectPlaybook.STOP_AND_CLASSIFY_UNKNOWN.value
            ),
        )
    return data


def _outcome_from_metadata(metadata: Mapping[str, Any]) -> Literal["deny", "approval", "block"]:
    policy_decision = str(metadata.get("policy_decision", "")).lower()
    approval_status = str(metadata.get("approval_status", "")).lower()
    if policy_decision == "block" or approval_status == "blocked":  # claim-check: allow blocked as approval_status enum value.
        return "block"
    if policy_decision == "approval" or approval_status == "pending":
        return "approval"
    return "deny"


def should_attach_redirect_playbook_fields(metadata: Mapping[str, Any]) -> bool:
    """Return True only for gated outcomes that need redirect guidance."""

    policy_decision = str(metadata.get("policy_decision", "")).lower()
    if policy_decision in {"allow", "observe"}:
        return False
    if policy_decision in {"approval", "block", "quarantine", "deny"}:
        return True
    approval_status = str(metadata.get("approval_status", "")).lower()
    if approval_status in {"pending", "blocked", "denied", "expired"}:  # claim-check: allow blocked as approval_status enum value.
        return True
    if policy_decision == "approval" and approval_status in {"approved", "executed"}:
        return True
    return False


def attach_redirect_playbook_fields(
    metadata: dict[str, Any],
    classification: ClassifiedToolCall,
    *,
    reason: str = "",
    outcome: Literal["deny", "approval", "block"] | None = None,
) -> dict[str, Any]:
    """Attach bounded redirect playbook fields to action-gate metadata."""

    if not uses_risk_family_redirects(classification):
        return metadata
    if not should_attach_redirect_playbook_fields(metadata):
        return metadata
    resolved_outcome = outcome or _outcome_from_metadata(metadata)
    guidance = build_risk_family_guidance(
        classification,
        outcome=resolved_outcome,
        reason=reason,
    )
    metadata.setdefault("risk_family", guidance.risk_family)
    metadata.setdefault("redirect_playbook", guidance.redirect_playbook)
    metadata.setdefault("redirect_playbook_id", guidance.redirect_playbook_id)
    metadata.setdefault("safe_first_step_id", guidance.safe_first_step_id)
    return metadata


def attach_redirect_playbook_fields_for_evidence_record(
    metadata: dict[str, Any],
    *,
    policy_id: str | None,
    tool_name: str,
    outcome: Literal["deny", "approval", "block"] | None = None,
) -> dict[str, Any]:
    """Attach redirect fields when only durable evidence record context is available."""

    if policy_id != PRODUCT_ROUTE_POLICY_ID:
        return metadata
    if not should_attach_redirect_playbook_fields(metadata):
        return metadata
    family = resolve_risk_family(tool_name)
    playbook = resolve_redirect_playbook(family)
    playbook_id = playbook.value
    metadata.setdefault("risk_family", family.value)
    metadata.setdefault("redirect_playbook", playbook_id)
    metadata.setdefault("redirect_playbook_id", playbook_id)
    metadata.setdefault("safe_first_step_id", playbook_id)
    return metadata


def redirect_metadata_from_action_gate(
    metadata: Mapping[str, Any] | None,
) -> dict[str, str]:
    """Return bounded redirect fields stored on action-gate metadata."""

    if not isinstance(metadata, Mapping):
        return {}
    fields: dict[str, str] = {}
    for key in ("risk_family", "redirect_playbook_id", "safe_first_step_id"):
        value = metadata.get(key)
        if isinstance(value, str) and value:
            fields[key] = value
    return fields


def risk_family_redirect_coverage() -> tuple[dict[str, Any], ...]:
    """Return static risk-family redirect coverage for control surfaces."""

    rows: list[dict[str, Any]] = []
    for family in sorted(REQUIRED_RISK_FAMILIES, key=lambda item: item.value):
        playbook = RISK_FAMILY_TO_PLAYBOOK[family]
        rows.append({
            "risk_family": family.value,
            "redirect_playbook": playbook.value,
            "redirect_playbook_id": playbook.value,
            "safe_first_step_id": playbook.value,
            "automation_level": "approval_required",
        })
    rows.append({
        "risk_family": RiskFamily.UNKNOWN.value,
        "redirect_playbook": RedirectPlaybook.STOP_AND_CLASSIFY_UNKNOWN.value,
        "redirect_playbook_id": RedirectPlaybook.STOP_AND_CLASSIFY_UNKNOWN.value,
        "safe_first_step_id": RedirectPlaybook.STOP_AND_CLASSIFY_UNKNOWN.value,
        "automation_level": "metadata_only",
    })
    return tuple(rows)


def representative_tool_risk_families() -> Mapping[str, str]:
    """Return representative tool -> risk_family mappings for tests."""

    tools = (
        "write_file",
        "delete_file",
        "git_add",
        "git_commit",
        "pip_install",
        "pip_uninstall",
        "get_secret",
        "get_env_secret",
        "merge_pull_request",
        "deploy_release",
        "dispatch_workflow",
        "run_remote_command",
        "instruction_surface_status",
    )
    return {tool: resolve_risk_family(tool).value for tool in tools}


__all__ = [
    "PLAYBOOK_SPECS",
    "REQUIRED_RISK_FAMILIES",
    "RISK_FAMILY_TO_PLAYBOOK",
    "RedirectPlaybook",
    "RiskFamily",
    "RiskFamilyRedirectGuidance",
    "attach_redirect_playbook_fields",
    "attach_redirect_playbook_fields_for_evidence_record",
    "build_original_request_fingerprint",
    "build_risk_family_guidance",
    "build_structured_redirect_contract",
    "enrich_risk_family_error_data",
    "message_visible_approval_redirect",
    "message_visible_blocked_redirect",
    "redirect_automation_status_fields",
    "redirect_context_stub",
    "redirect_fields_from_guidance",
    "redirect_metadata_from_action_gate",
    "redirect_playbook_id_for_risk_family",
    "representative_tool_risk_families",
    "resolve_redirect_playbook",
    "resolve_risk_family",
    "risk_family_redirect_coverage",
    "should_attach_redirect_playbook_fields",
    "uses_risk_family_redirects",
]
