"""Deterministic adaptive setup planning for AgentVeil Safe Mode. claim-check: allow "Safe Mode" is the literal product surface name, not a safety claim.

Pure local functions only: no LLM, network, AVP token use, or hidden policy
generation. Planning output is metadata-only and prepares later setup UX slices.

claim-check: allow "Safe Mode" is the literal product surface name, not a
safety claim.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Literal, Mapping, Sequence

from agentveil_mcp_proxy.policy import (
    PolicyDecision,
    PolicyEngine,
    ProxyConfig,
    ProxyConfigError,
    builtin_policy_pack,
)
from agentveil_mcp_proxy.role_presets import apply_role_preset_to_config_payload

SETUP_MODES: tuple[str, ...] = ("readonly", "review", "build")
DEFAULT_SAFE_AUTOPILOT_SETUP_MODE = "review"
DEFAULT_SAFE_AUTOPILOT_ROLE_PRESET = "reviewer"
UNSUPPORTED_SETUP_MODES: tuple[str, ...] = ("operate", "break_glass")

PACK_NAMES: tuple[str, ...] = (
    "filesystem",
    "git",
    "github",
    "browser",
    "email",
    "package",
    "deploy",
    "secrets",
    "database",
)

OVERLAY_IDS: tuple[str, ...] = (
    "docs_write_only",
    "github_comments_no_merge",
    "tests_no_package_install",
    "external_send_approval",
    "deny_secrets_always",
)

ProtectionStatus = Literal["protected", "partial", "bypassable", "planning_only"]
Posture = Literal["allow", "approval", "block", "gated"]

_MODE_ROLE_PRESETS: Mapping[str, str] = {
    "readonly": "readonly",
    "review": "reviewer",
    "build": "build",
}

_MODE_FALLBACKS: Mapping[str, Mapping[str, str]] = {
    "readonly": {
        "read": "allow",
        "write": "block",
        "destructive": "block",
        "production": "block",  # claim-check: allow "production" is RiskClass vocabulary.
        "financial": "block",
        "unknown": "block",
    },
    "review": {
        "read": "allow",
        "write": "approval",
        "destructive": "block",
        "production": "block",  # claim-check: allow "production" is RiskClass vocabulary.
        "financial": "block",
        "unknown": "approval",
    },
    "build": {
        "read": "allow",
        "write": "allow",
        "destructive": "approval",
        "production": "approval",  # claim-check: allow "production" is RiskClass vocabulary.
        "financial": "block",
        "unknown": "approval",
    },
}

_FORBIDDEN_INVENTORY_TOKENS: tuple[str, ...] = (
    "prompt",
    "chat",
    "stdout",
    "stderr",
    "password",
    "secret",
    "token",
    "credential",
    "api_key",
    "private_key",
)

_PACK_SERVER_HINTS: Mapping[str, tuple[str, ...]] = {
    "filesystem": ("filesystem", "fs", "files", "file"),
    "git": ("git",),
    "github": ("github",),
    "browser": ("browser", "puppeteer", "playwright", "cursor-ide-browser"),
    "email": ("email", "smtp", "gmail", "mail"),
    "package": ("package", "npm", "pypi", "pip", "cargo"),
    "deploy": ("deploy", "kubernetes", "k8s", "helm"),
    "secrets": ("secrets", "vault", "credential", "ssh", "aws"),
    "database": ("database", "postgres", "mysql", "sql", "db", "sqlite"),
}

_PACK_TOOL_HINTS: Mapping[str, tuple[str, ...]] = {
    "filesystem": (
        "read_file",
        "read_text_file",
        "write_file",
        "edit_file",
        "delete_file",
        "list_directory",
        "move_file",
    ),
    "git": (
        "git_status",
        "git_log",
        "git_diff",
        "git_commit",
        "git_add",
        "git_push",
        "git_reset",
    ),
    "github": (
        "get_issue",
        "list_pull_requests",
        "create_pull_request",
        "merge_pull_request",
        "create_issue_comment",
    ),
    "browser": (
        "browser_navigate",
        "browser_click",
        "browser_snapshot",
        "browser_take_screenshot",
    ),
    "email": ("send_email", "send_message", "draft_email"),
    "package": ("npm_install", "pip_install", "install_package", "add_dependency"),
    "deploy": ("deploy_release", "deploy_service", "rollback_release"),
    "secrets": ("get_secret", "read_secret", "list_secrets", "export_credentials"),
    "database": ("query_database", "execute_sql", "run_migration"),
}

_BUILTIN_POLICY_PACKS: frozenset[str] = frozenset({"filesystem", "git", "github"})

_RISK_READ_PREFIXES = ("read", "get", "list", "stat", "show", "search", "fetch", "view")
_RISK_WRITE_PREFIXES = ("write", "edit", "create", "update", "commit", "push", "add", "send")
_RISK_DESTRUCTIVE_PREFIXES = ("delete", "remove", "destroy", "drop", "purge", "reset", "wipe")


class AdaptiveSetupError(ValueError):
    """Raised when adaptive setup input or mode vocabulary is invalid."""


@dataclass(frozen=True)
class ToolInventoryEntry:
    """Metadata-only tool inventory row."""

    tool_name: str
    server_label: str | None = None
    capabilities: tuple[str, ...] = ()
    path_hint: str | None = None
    category_hint: str | None = None


@dataclass(frozen=True)
class ToolClassification:
    """Deterministic pack classification for one inventory tool."""

    tool_name: str
    server_label: str | None
    pack: str | None
    risk_class: str
    requires_classification: bool


@dataclass(frozen=True)
class SetupOverlay:
    """User-confirmable overlay represented as structured data."""

    overlay_id: str
    label: str
    scope_hint: str | None = None
    config_mappable: bool = True


@dataclass(frozen=True)
class PolicyIntent:
    """Canonical policy posture shared by summary and config generation."""

    pack: str
    subject: str
    posture: Posture
    overlay_id: str | None = None


@dataclass(frozen=True)
class AdaptiveSetupPlan:
    """Single source of truth for summary and config generation."""

    mode: str
    role_preset: str
    packs: tuple[str, ...]
    overlays: tuple[SetupOverlay, ...]
    classifications: tuple[ToolClassification, ...]
    unknown_tools: tuple[str, ...]
    policy_intents: tuple[PolicyIntent, ...]
    protection_status: ProtectionStatus = "planning_only"
    routing_active: bool = False
    requires_classification: bool = False
    config_validatable: bool = True
    unsupported_reason: str | None = None


@dataclass(frozen=True)
class AdaptiveSetupSummary:
    """User-visible summary derived from one plan object."""

    mode: str
    role_preset: str
    packs: tuple[str, ...]
    overlay_labels: tuple[str, ...]
    unknown_tools: tuple[str, ...]
    lines: tuple[str, ...]
    protection_status: ProtectionStatus
    routing_active: bool
    requires_classification: bool


@dataclass(frozen=True)
class AdaptiveSetupResult:
    """Bounded adaptive setup output for one inventory."""

    plan: AdaptiveSetupPlan
    summary: AdaptiveSetupSummary
    config_data: Mapping[str, Any]
    config_validated: bool


def _normalize_token(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def _contains_forbidden_metadata(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in _FORBIDDEN_INVENTORY_TOKENS)


def _validate_inventory_entry(entry: ToolInventoryEntry) -> None:
    if not entry.tool_name.strip():
        raise AdaptiveSetupError("tool inventory entry requires non-empty tool_name")
    for value in (entry.path_hint or "", entry.category_hint or "", *entry.capabilities):
        if value and _contains_forbidden_metadata(value):
            raise AdaptiveSetupError(
                "tool inventory must be metadata-only; forbidden prompt/secret payload markers detected"
            )


def normalize_setup_mode(mode: str | None) -> str:
    """Return a supported setup mode or raise."""

    if mode is None:
        return "review"
    normalized = _normalize_token(mode)
    if normalized in UNSUPPORTED_SETUP_MODES:
        supported = ", ".join(SETUP_MODES)
        raise AdaptiveSetupError(
            f"unsupported setup mode {mode!r}; expected one of: {supported}"
        )
    if normalized not in SETUP_MODES:
        supported = ", ".join(SETUP_MODES)
        raise AdaptiveSetupError(f"unsupported setup mode {mode!r}; expected one of: {supported}")
    return normalized


def _infer_risk_class(tool_name: str, capabilities: Sequence[str]) -> str:
    normalized = _normalize_token(tool_name)
    capability_tokens = {_normalize_token(item) for item in capabilities}
    if any(token in capability_tokens for token in ("destructive", "delete")):
        return "destructive"
    if any(token in capability_tokens for token in ("write", "mutate", "send")):
        return "write"
    if any(normalized.startswith(prefix) or f"_{prefix}" in normalized for prefix in _RISK_DESTRUCTIVE_PREFIXES):
        return "destructive"
    if any(normalized.startswith(prefix) or f"_{prefix}" in normalized for prefix in _RISK_WRITE_PREFIXES):
        return "write"
    if any(normalized.startswith(prefix) for prefix in _RISK_READ_PREFIXES):
        return "read"
    return "unknown"


def _server_matches_pack(server_label: str | None, pack: str) -> bool:
    if not server_label:
        return False
    normalized = _normalize_token(server_label)
    if pack == "git" and "github" in normalized:
        return False
    return any(hint in normalized for hint in _PACK_SERVER_HINTS[pack])


def _tool_matches_pack(tool_name: str, pack: str) -> bool:
    normalized = _normalize_token(tool_name)
    if normalized in _PACK_TOOL_HINTS[pack]:
        return True
    if pack == "git" and normalized.startswith("git_"):
        return True
    if pack == "github":
        if "github" in normalized:
            return True
        return False
    if pack == "filesystem" and any(
        normalized.startswith(prefix) for prefix in ("read_", "write_", "edit_", "delete_", "list_", "move_")
    ):
        return True
    if pack == "browser" and normalized.startswith("browser_"):
        return True
    if pack == "email" and ("email" in normalized or normalized.startswith("send_")):
        return True
    if pack == "package" and any(token in normalized for token in ("install", "npm", "pip", "package")):
        return True
    if pack == "deploy" and any(token in normalized for token in ("deploy", "release", "rollback")):
        return True
    if pack == "secrets" and any(token in normalized for token in ("secret", "credential", "vault")):
        return True
    if pack == "database" and any(token in normalized for token in ("sql", "query", "database", "migration")):
        return True
    return False


def classify_tool(entry: ToolInventoryEntry) -> ToolClassification:
    """Classify one inventory tool into a pack candidate or unknown."""

    _validate_inventory_entry(entry)
    hints = (
        entry.category_hint,
        entry.server_label,
        entry.tool_name,
    )
    matched_packs: list[str] = []
    for pack in PACK_NAMES:
        if entry.category_hint and _normalize_token(entry.category_hint) == pack:
            matched_packs.append(pack)
            continue
        if _server_matches_pack(entry.server_label, pack) or _tool_matches_pack(entry.tool_name, pack):
            matched_packs.append(pack)
    if not matched_packs:
        return ToolClassification(
            tool_name=entry.tool_name,
            server_label=entry.server_label,
            pack=None,
            risk_class=_infer_risk_class(entry.tool_name, entry.capabilities),
            requires_classification=True,
        )
    if len(matched_packs) > 1:
        # Deterministic tie-break: lexicographically first pack, still flagged for review.
        pack = sorted(matched_packs)[0]
        return ToolClassification(
            tool_name=entry.tool_name,
            server_label=entry.server_label,
            pack=pack,
            risk_class=_infer_risk_class(entry.tool_name, entry.capabilities),
            requires_classification=True,
        )
    return ToolClassification(
        tool_name=entry.tool_name,
        server_label=entry.server_label,
        pack=matched_packs[0],
        risk_class=_infer_risk_class(entry.tool_name, entry.capabilities),
        requires_classification=False,
    )


def classify_inventory(
    inventory: Sequence[ToolInventoryEntry],
) -> tuple[tuple[ToolClassification, ...], tuple[str, ...], tuple[str, ...]]:
    """Classify inventory tools and return classifications, unknown tools, and packs."""

    classifications = tuple(classify_tool(entry) for entry in inventory)
    unknown_tools = tuple(
        sorted(
            {
                item.tool_name
                for item in classifications
                if item.requires_classification and item.pack is None
            }
        )
    )
    packs = tuple(sorted({item.pack for item in classifications if item.pack is not None}))
    return classifications, unknown_tools, packs


def recommend_mode(
    inventory: Sequence[ToolInventoryEntry],
    *,
    requested_mode: str | None = None,
) -> str:
    """Recommend one setup mode from inventory and optional requested mode."""

    mode = normalize_setup_mode(requested_mode)
    classifications, unknown_tools, _packs = classify_inventory(inventory)
    if unknown_tools:
        return mode
    risky = any(item.risk_class in {"write", "destructive", "unknown"} for item in classifications)
    if mode == "readonly" and risky:
        return "readonly"
    if mode == "build" and not risky:
        return "build"
    return mode


_OVERLAY_DEFINITIONS: Mapping[str, SetupOverlay] = {
    "docs_write_only": SetupOverlay(
        overlay_id="docs_write_only",
        label="Allow writes only under docs/",
        scope_hint="docs/",
        config_mappable=False,
    ),
    "github_comments_no_merge": SetupOverlay(
        overlay_id="github_comments_no_merge",
        label="Allow GitHub comments but not merge",
        config_mappable=True,
    ),
    "tests_no_package_install": SetupOverlay(
        overlay_id="tests_no_package_install",
        label="Allow tests but not package install",
        config_mappable=True,
    ),
    "external_send_approval": SetupOverlay(
        overlay_id="external_send_approval",
        label="Approval required for external send",
        config_mappable=True,
    ),
    "deny_secrets_always": SetupOverlay(
        overlay_id="deny_secrets_always",
        label="Deny secrets always",  # claim-check: allow "always" is the overlay label, not a universal product guarantee.
        config_mappable=True,
    ),
}


def _normalize_overlay_ids(overlays: Sequence[str]) -> tuple[SetupOverlay, ...]:
    normalized: list[SetupOverlay] = []
    for overlay_id in overlays:
        token = _normalize_token(overlay_id)
        if token not in _OVERLAY_DEFINITIONS:
            supported = ", ".join(OVERLAY_IDS)
            raise AdaptiveSetupError(f"unsupported overlay {overlay_id!r}; expected one of: {supported}")
        normalized.append(_OVERLAY_DEFINITIONS[token])
    return tuple(normalized)


def _posture_for_mode(*, mode: str, risk_class: str, pack: str, tool_name: str) -> Posture:
    if mode == "readonly":
        if risk_class in {"write", "destructive", "unknown"}:
            return "block"
        return "allow"
    if mode == "review":
        if risk_class == "destructive":
            return "block"
        if risk_class in {"write", "unknown"}:
            return "approval"
        if pack == "git" and _normalize_token(tool_name) == "git_push":
            return "approval"
        return "allow"
    # build
    if pack == "package" and any(token in _normalize_token(tool_name) for token in ("install", "npm", "pip")):
        return "block"
    if risk_class == "destructive":
        return "approval"
    if risk_class == "write":
        return "allow"
    if risk_class == "unknown":
        return "approval"
    return "allow"


def _build_policy_intents(
    *,
    mode: str,
    packs: Sequence[str],
    classifications: Sequence[ToolClassification],
    overlays: Sequence[SetupOverlay],
) -> tuple[PolicyIntent, ...]:
    overlay_ids = {item.overlay_id for item in overlays}
    intents: list[PolicyIntent] = []

    for pack in packs:
        pack_tools = [item for item in classifications if item.pack == pack]
        for tool in pack_tools:
            posture = _posture_for_mode(
                mode=mode,
                risk_class=tool.risk_class,
                pack=pack,
                tool_name=tool.tool_name,
            )
            intents.append(
                PolicyIntent(
                    pack=pack,
                    subject=f"{pack}.{tool.tool_name}",
                    posture=posture,
                )
            )
        if not pack_tools:
            intents.append(PolicyIntent(pack=pack, subject=f"{pack}.*", posture="gated"))

    if "github_comments_no_merge" in overlay_ids:
        intents.append(
            PolicyIntent(
                pack="github",
                subject="github.merge",
                posture="block",
                overlay_id="github_comments_no_merge",
            )
        )
        intents.append(
            PolicyIntent(
                pack="github",
                subject="github.comment",
                posture="allow" if mode != "readonly" else "block",
                overlay_id="github_comments_no_merge",
            )
        )
    if "tests_no_package_install" in overlay_ids:
        intents.append(
            PolicyIntent(
                pack="package",
                subject="package.install",
                posture="block",
                overlay_id="tests_no_package_install",
            )
        )
        intents.append(
            PolicyIntent(
                pack="package",
                subject="package.test",
                posture="allow" if mode == "build" else "approval",
                overlay_id="tests_no_package_install",
            )
        )
    if "external_send_approval" in overlay_ids:
        intents.append(
            PolicyIntent(
                pack="email",
                subject="email.external_send",
                posture="approval",
                overlay_id="external_send_approval",
            )
        )
    if "deny_secrets_always" in overlay_ids:
        intents.append(
            PolicyIntent(
                pack="secrets",
                subject="secrets.*",
                posture="block",
                overlay_id="deny_secrets_always",
            )
        )

    deduped: dict[tuple[str, str, str | None], PolicyIntent] = {}
    for intent in intents:
        key = (intent.pack, intent.subject, intent.overlay_id)
        existing = deduped.get(key)
        if existing is None or _posture_rank(intent.posture) > _posture_rank(existing.posture):
            deduped[key] = intent
    return tuple(sorted(deduped.values(), key=lambda item: (item.pack, item.subject, item.overlay_id or "")))


def _posture_rank(posture: Posture) -> int:
    return {"allow": 0, "gated": 1, "approval": 2, "block": 3}[posture]


def _classification_subject(classification: ToolClassification) -> str | None:
    if classification.pack is None:
        return None
    return f"{classification.pack}.{classification.tool_name}"


def _tool_context_for_classification(classification: ToolClassification) -> dict[str, str]:
    return {
        "server": classification.server_label or classification.pack or "unknown",
        "tool": classification.tool_name,
        "risk_class": classification.risk_class,
    }


def _posture_for_policy_decision(decision: PolicyDecision) -> Posture:
    if decision == PolicyDecision.ALLOW:
        return "allow"
    if decision == PolicyDecision.BLOCK:
        return "block"
    if decision == PolicyDecision.APPROVAL:
        return "approval"
    return "gated"


def _unsupported_reason_for_unmappable_plan(
    *,
    unmappable_overlays: Sequence[SetupOverlay],
    classifications: Sequence[ToolClassification],
    unknown_tools: Sequence[str],
) -> str | None:
    reasons: list[str] = []
    if unmappable_overlays:
        overlay_ids = ", ".join(item.overlay_id for item in unmappable_overlays)
        reasons.append(
            f"overlay(s) {overlay_ids} cannot be mapped deterministically to proxy config "
            "in this policy pack; PolicyMatch has no path/resource scope"
        )
    ambiguous_tools = tuple(
        item.tool_name
        for item in classifications
        if item.requires_classification and item.pack is not None
    )
    if unknown_tools:
        reasons.append(
            f"unknown tool(s) {', '.join(unknown_tools)} require classification before config generation"
        )
    if ambiguous_tools:
        reasons.append(
            f"ambiguous tool(s) {', '.join(sorted(ambiguous_tools))} require classification before config generation"
        )
    if not reasons:
        return None
    return "; ".join(reasons)


def _align_intents_to_effective_policy(plan: AdaptiveSetupPlan) -> tuple[PolicyIntent, ...]:
    config = ProxyConfig.from_dict(generate_config_data(plan))
    engine = PolicyEngine(config)
    effective_by_subject: dict[str, Posture] = {}
    for classification in plan.classifications:
        subject = _classification_subject(classification)
        if subject is None:
            continue
        evaluation = engine.evaluate(_tool_context_for_classification(classification))
        effective_by_subject[subject] = _posture_for_policy_decision(evaluation.decision)
    if not effective_by_subject:
        return plan.policy_intents
    aligned: list[PolicyIntent] = []
    for intent in plan.policy_intents:
        effective = effective_by_subject.get(intent.subject)
        if effective is None:
            aligned.append(intent)
        else:
            aligned.append(replace(intent, posture=effective))
    return tuple(aligned)


def build_adaptive_setup_plan(
    inventory: Sequence[ToolInventoryEntry],
    *,
    requested_mode: str | None = None,
    overlays: Sequence[str] = (),
) -> AdaptiveSetupPlan:
    """Build the canonical adaptive setup plan for one inventory."""

    mode = recommend_mode(inventory, requested_mode=requested_mode)
    overlay_objects = _normalize_overlay_ids(overlays)
    classifications, unknown_tools, packs = classify_inventory(inventory)
    requires_classification = bool(unknown_tools) or any(
        item.requires_classification for item in classifications
    )
    policy_intents = _build_policy_intents(
        mode=mode,
        packs=packs,
        classifications=classifications,
        overlays=overlay_objects,
    )
    unmappable = tuple(item for item in overlay_objects if not item.config_mappable)
    config_validatable = not (unmappable or requires_classification)
    unsupported_reason = _unsupported_reason_for_unmappable_plan(
        unmappable_overlays=unmappable,
        classifications=classifications,
        unknown_tools=unknown_tools,
    )
    plan = AdaptiveSetupPlan(
        mode=mode,
        role_preset=_MODE_ROLE_PRESETS[mode],
        packs=packs,
        overlays=overlay_objects,
        classifications=classifications,
        unknown_tools=unknown_tools,
        policy_intents=policy_intents,
        protection_status="planning_only",
        routing_active=False,
        requires_classification=requires_classification,
        config_validatable=config_validatable,
        unsupported_reason=unsupported_reason,
    )
    if config_validatable:
        plan = replace(plan, policy_intents=_align_intents_to_effective_policy(plan))
    return plan


def _intent_phrase(intent: PolicyIntent) -> str:
    if intent.posture == "allow":
        action = "allowed"
    elif intent.posture == "approval":
        action = "approval_required"
    elif intent.posture == "block":
        action = "denied"
    else:
        action = "gated"
    overlay = f" (overlay={intent.overlay_id})" if intent.overlay_id else ""
    return f"{intent.subject}: {action}{overlay}"


def generate_summary(plan: AdaptiveSetupPlan) -> AdaptiveSetupSummary:
    """Generate a user-visible summary from one plan object."""

    lines: list[str] = [
        f"mode={plan.mode}",
        f"role_preset={plan.role_preset}",
        f"packs={', '.join(plan.packs) if plan.packs else 'none'}",
        f"protection_status={plan.protection_status}",
        f"routing_active={str(plan.routing_active).lower()}",
    ]
    if plan.overlays:
        lines.append(f"overlays={', '.join(item.overlay_id for item in plan.overlays)}")
    for overlay in plan.overlays:
        if not overlay.config_mappable:
            lines.append(f"overlay:{overlay.overlay_id}=unsupported")
    if not plan.config_validatable:
        lines.append("config_validatable=false")
        if plan.unsupported_reason:
            lines.append(f"unsupported_reason={plan.unsupported_reason}")
    if plan.unknown_tools:
        lines.append(f"unknown_tools={', '.join(plan.unknown_tools)}")
        lines.append("requires_classification=true")
    elif plan.requires_classification:
        lines.append("requires_classification=true")
    else:
        lines.append("requires_classification=false")
    for intent in plan.policy_intents:
        lines.append(_intent_phrase(intent))
    return AdaptiveSetupSummary(
        mode=plan.mode,
        role_preset=plan.role_preset,
        packs=plan.packs,
        overlay_labels=tuple(item.label for item in plan.overlays),
        unknown_tools=plan.unknown_tools,
        lines=tuple(lines),
        protection_status=plan.protection_status,
        routing_active=plan.routing_active,
        requires_classification=plan.requires_classification,
    )


def _adaptive_pack_rules(pack: str) -> list[dict[str, Any]]:
    templates: Mapping[str, list[dict[str, Any]]] = {
        "browser": [
            {
                "id": "browser-read",
                "source": "builtin",
                "decision": "allow",
                "risk_class": "read",
                "match": {"server": ["browser", "browser-*", "*browser*"], "tool": ["browser_snapshot", "browser_*"]},
            },
            {
                "id": "browser-write",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "write",
                "match": {"server": ["browser", "browser-*", "*browser*"], "tool": ["browser_click", "browser_navigate", "browser_*"]},
            },
        ],
        "email": [
            {
                "id": "email-read",
                "source": "builtin",
                "decision": "allow",
                "risk_class": "read",
                "match": {"server": ["email", "mail", "*email*"], "tool": ["draft_*", "list_*"]},
            },
            {
                "id": "email-send",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "write",
                "match": {"server": ["email", "mail", "*email*"], "tool": ["send_*", "send_email"]},
            },
        ],
        "package": [
            {
                "id": "package-test",
                "source": "builtin",
                "decision": "allow",
                "risk_class": "read",
                "match": {"server": ["package", "npm", "pip", "*package*"], "tool": ["test_*", "run_test", "pytest"]},
            },
            {
                "id": "package-install",
                "source": "builtin",
                "decision": "block",
                "risk_class": "write",
                "match": {
                    "server": ["package", "npm", "pip", "*package*"],
                    "tool": ["install_*", "npm_install", "pip_install", "add_dependency"],
                },
            },
        ],
        "deploy": [
            {
                "id": "deploy-read",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "read",
                "match": {"server": ["deploy", "k8s", "kubernetes", "*deploy*"], "tool": ["get_*", "list_*", "status_*"]},
            },
            {
                "id": "deploy-write",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "production",  # claim-check: allow "production" is RiskClass vocabulary.
                "match": {"server": ["deploy", "k8s", "kubernetes", "*deploy*"], "tool": ["deploy_*", "rollback_*", "release_*"]},
            },
        ],
        "secrets": [
            {
                "id": "secrets-block",
                "source": "builtin",
                "decision": "block",
                "risk_class": "unknown",
                "match": {"server": ["secrets", "vault", "credential", "*secret*"], "tool": ["*"]},
            },
        ],
        "database": [
            {
                "id": "database-read",
                "source": "builtin",
                "decision": "allow",
                "risk_class": "read",
                "match": {"server": ["database", "postgres", "mysql", "db", "*db*"], "tool": ["query_*", "list_*", "describe_*"]},
            },
            {
                "id": "database-write",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "write",
                "match": {"server": ["database", "postgres", "mysql", "db", "*db*"], "tool": ["execute_*", "run_migration", "write_*"]},
            },
        ],
    }
    return list(templates.get(pack, []))


def _decision_for_posture(posture: Posture) -> str:
    if posture == "allow":
        return "allow"
    if posture == "approval":
        return "approval"
    if posture == "block":
        return "block"
    return "approval"


def _pack_server_patterns(pack: str) -> list[str]:
    hints = list(_PACK_SERVER_HINTS.get(pack, (pack,)))
    return hints + [f"*{hint}*" for hint in hints if hint]


def _overlay_rule(intent: PolicyIntent) -> dict[str, Any] | None:
    if intent.overlay_id is None:
        return None
    rule_id = f"overlay-{intent.overlay_id}-{intent.subject.replace('.', '-')}"
    decision = _decision_for_posture(intent.posture)
    if intent.subject == "filesystem.write":
        return {
            "id": rule_id,
            "source": "user",
            "decision": decision,
            "risk_class": "write",
            "reason": f"adaptive_setup:{intent.overlay_id}",
            "match": {"server": ["filesystem", "fs", "*filesystem*"], "tool": ["write_*", "edit_*", "move_*"]},
        }
    if intent.subject == "github.merge":
        return {
            "id": rule_id,
            "source": "user",
            "decision": decision,
            "risk_class": "write",
            "reason": f"adaptive_setup:{intent.overlay_id}",
            "match": {"server": ["github", "github-*", "*github*"], "tool": ["merge_*"]},
        }
    if intent.subject == "github.comment":
        return {
            "id": rule_id,
            "source": "user",
            "decision": decision,
            "risk_class": "write",
            "reason": f"adaptive_setup:{intent.overlay_id}",
            "match": {"server": ["github", "github-*", "*github*"], "tool": ["create_*comment*", "comment_*"]},
        }
    if intent.subject == "package.install":
        return {
            "id": rule_id,
            "source": "user",
            "decision": decision,
            "risk_class": "write",
            "reason": f"adaptive_setup:{intent.overlay_id}",
            "match": {"server": ["package", "npm", "pip", "*package*"], "tool": ["install_*", "npm_install", "pip_install"]},
        }
    if intent.subject == "package.test":
        return {
            "id": rule_id,
            "source": "user",
            "decision": decision,
            "risk_class": "read",
            "reason": f"adaptive_setup:{intent.overlay_id}",
            "match": {"server": ["package", "npm", "pip", "*package*"], "tool": ["test_*", "pytest", "run_test"]},
        }
    if intent.subject == "email.external_send":
        return {
            "id": rule_id,
            "source": "user",
            "decision": decision,
            "risk_class": "write",
            "reason": f"adaptive_setup:{intent.overlay_id}",
            "match": {"server": ["email", "mail", "*email*"], "tool": ["send_*", "send_email"]},
        }
    if intent.subject == "secrets.*":
        return {
            "id": rule_id,
            "source": "user",
            "decision": decision,
            "risk_class": "unknown",
            "reason": f"adaptive_setup:{intent.overlay_id}",
            "match": {"server": ["secrets", "vault", "credential", "*secret*"], "tool": ["*"]},
        }
    return None


def _tool_intent_rule(intent: PolicyIntent) -> dict[str, Any] | None:
    pack, _, remainder = intent.subject.partition(".")
    if not remainder or remainder.endswith("*"):
        return None
    aggregate_subjects = {
        "write": (["write_*", "edit_*", "move_*"], "write"),
        "merge": (["merge_*"], "write"),
        "comment": (["create_*comment*", "comment_*"], "write"),
        "install": (["install_*", "npm_install", "pip_install", "add_dependency"], "write"),
        "test": (["test_*", "pytest", "run_test"], "read"),
        "external_send": (["send_*", "send_email"], "write"),
    }
    if remainder in aggregate_subjects:
        tools, risk_class = aggregate_subjects[remainder]
        rule_id = f"intent-{pack}-{remainder}"
        if intent.overlay_id:
            rule_id = f"overlay-{intent.overlay_id}-{remainder}"
        return {
            "id": rule_id,
            "source": "user",
            "decision": _decision_for_posture(intent.posture),
            "risk_class": risk_class,
            "reason": f"adaptive_setup:{intent.subject}",
            "match": {"server": _pack_server_patterns(pack), "tool": tools},
        }
    return {
        "id": f"intent-{pack}-{remainder}",
        "source": "user",
        "decision": _decision_for_posture(intent.posture),
        "reason": f"adaptive_setup:{intent.subject}",
        "match": {"server": _pack_server_patterns(pack), "tool": [remainder]},
    }


def _policy_intent_rule(intent: PolicyIntent) -> dict[str, Any] | None:
    overlay_rule = _overlay_rule(intent)
    if overlay_rule is not None:
        return overlay_rule
    return _tool_intent_rule(intent)


def _pack_rules(pack: str) -> list[dict[str, Any]]:
    if pack in _BUILTIN_POLICY_PACKS:
        policy = builtin_policy_pack(pack)
        rules: list[dict[str, Any]] = []
        for rule in policy.rules:
            match: dict[str, Any] = {}
            if rule.match.server:
                match["server"] = list(rule.match.server)
            if rule.match.tool:
                match["tool"] = list(rule.match.tool)
            if rule.match.action:
                match["action"] = list(rule.match.action)
            if rule.match.risk_class:
                match["risk_class"] = [item.value for item in rule.match.risk_class]
            rules.append(
                {
                    "id": rule.id,
                    "source": rule.source,
                    "decision": rule.decision.value,
                    "risk_class": rule.risk_class.value if rule.risk_class else None,
                    "match": match,
                }
            )
        return rules
    return _adaptive_pack_rules(pack)


def _apply_mode_to_rules(rules: list[dict[str, Any]], *, mode: str) -> list[dict[str, Any]]:
    adjusted: list[dict[str, Any]] = []
    for rule in rules:
        risk = rule.get("risk_class")
        decision = rule.get("decision")
        # claim-check: allow "production" is RiskClass vocabulary.
        if mode == "readonly" and risk in {"write", "destructive", "unknown", "production"}:
            decision = "block"
        elif mode == "review" and risk in {"write", "unknown"} and decision == "allow":
            decision = "approval"
        elif mode == "review" and risk == "destructive":
            decision = "block"
        adjusted.append({**rule, "decision": decision})
    return adjusted


def generate_config_data(
    plan: AdaptiveSetupPlan,
    *,
    avp_agent_name: str = "adaptive-setup",
    avp_base_url: str = "https://agentveil.dev",
    trusted_signer_did: str = "did:key:z6MktrustedSigner",
) -> dict[str, Any]:
    """Generate proxy config draft data from one plan object."""

    if not plan.config_validatable:
        return {
            "config_validatable": False,
            "unsupported_reason": plan.unsupported_reason,
            "mode": plan.mode,
            "role_preset": plan.role_preset,
            "packs": list(plan.packs),
        }

    rules: list[dict[str, Any]] = []
    for pack in plan.packs:
        rules.extend(_apply_mode_to_rules(_pack_rules(pack), mode=plan.mode))
    for intent in plan.policy_intents:
        intent_rule = _policy_intent_rule(intent)
        if intent_rule is not None:
            rules.append(intent_rule)

    payload = apply_role_preset_to_config_payload(
        {
            "proxy_config_schema_version": 1,
            "avp": {
                "base_url": avp_base_url,
                "agent_name": avp_agent_name,
                "trusted_signer_dids": [trusted_signer_did],
            },
            "mode": "protect",
            "privacy": {
                "action": "redacted",
                "resource": "hash",
                "payload": "hash_only",
                "evidence_upload": False,
            },
            "fallback": dict(_MODE_FALLBACKS[plan.mode]),
            "approval": {
                "approval_timeout_seconds": 300,
                "on_timeout": "deny",
                "ui_open_mode": "browser",
            },
            "policy": {
                "id": f"adaptive-setup-{plan.mode}",
                "policy_schema_version": 1,
                "default_decision": "ask_backend",
                "default_risk_class": "unknown",
                "rules": rules,
            },
        },
        preset_name=plan.role_preset,
    )
    return payload


def verify_plan_consistency(plan: AdaptiveSetupPlan) -> None:
    """Raise when summary-facing and config-facing views would diverge."""

    if plan.classifications and not plan.policy_intents and plan.config_validatable:
        raise AdaptiveSetupError("classified inventory requires policy_intents in plan")
    summary = generate_summary(plan)
    for intent in plan.policy_intents:
        phrase = _intent_phrase(intent)
        if phrase not in summary.lines:
            raise AdaptiveSetupError(
                "plan policy_intents are not reflected in generated summary"
            )
    if plan.unknown_tools and "requires_classification=true" not in summary.lines:
        raise AdaptiveSetupError("unknown tools require classification in summary")
    if not plan.config_validatable:
        return
    config = generate_config_data(plan)
    parsed_config = ProxyConfig.from_dict(config)
    engine = PolicyEngine(parsed_config)
    rules_by_id = {rule["id"]: rule for rule in config["policy"]["rules"]}
    for intent in plan.policy_intents:
        intent_rule = _policy_intent_rule(intent)
        if intent_rule is None:
            continue
        actual = rules_by_id.get(intent_rule["id"])
        if actual is None or actual["decision"] != intent_rule["decision"]:
            raise AdaptiveSetupError(
                "plan policy_intents are not reflected in generated config"
            )
    intents_by_subject = {intent.subject: intent for intent in plan.policy_intents}
    for classification in plan.classifications:
        subject = _classification_subject(classification)
        if subject is None:
            continue
        intent = intents_by_subject.get(subject)
        if intent is None:
            raise AdaptiveSetupError("classified inventory requires policy_intents in plan")
        effective = _posture_for_policy_decision(
            engine.evaluate(_tool_context_for_classification(classification)).decision
        )
        if intent.posture != effective:
            raise AdaptiveSetupError(
                "plan summary posture does not match effective generated config decision"
            )


def plan_adaptive_setup(
    inventory: Sequence[ToolInventoryEntry],
    *,
    requested_mode: str | None = None,
    overlays: Sequence[str] = (),
    avp_agent_name: str = "adaptive-setup",
    avp_base_url: str = "https://agentveil.dev",
    trusted_signer_did: str = "did:key:z6MktrustedSigner",
) -> AdaptiveSetupResult:
    """Plan adaptive setup from inventory through summary and config generation."""

    plan = build_adaptive_setup_plan(
        inventory,
        requested_mode=requested_mode,
        overlays=overlays,
    )
    verify_plan_consistency(plan)
    summary = generate_summary(plan)
    config_data = generate_config_data(
        plan,
        avp_agent_name=avp_agent_name,
        avp_base_url=avp_base_url,
        trusted_signer_did=trusted_signer_did,
    )
    config_validated = False
    if plan.config_validatable:
        try:
            ProxyConfig.from_dict(config_data)
            config_validated = True
        except ProxyConfigError:
            config_validated = False
    return AdaptiveSetupResult(
        plan=plan,
        summary=summary,
        config_data=config_data,
        config_validated=config_validated,
    )


__all__ = [
    "AdaptiveSetupError",
    "AdaptiveSetupPlan",
    "AdaptiveSetupResult",
    "AdaptiveSetupSummary",
    "OVERLAY_IDS",
    "PACK_NAMES",
    "PolicyIntent",
    "ProtectionStatus",
    "SETUP_MODES",
    "SetupOverlay",
    "ToolClassification",
    "ToolInventoryEntry",
    "UNSUPPORTED_SETUP_MODES",
    "build_adaptive_setup_plan",
    "classify_inventory",
    "classify_tool",
    "generate_config_data",
    "generate_summary",
    "normalize_setup_mode",
    "plan_adaptive_setup",
    "recommend_mode",
    "verify_plan_consistency",
]
