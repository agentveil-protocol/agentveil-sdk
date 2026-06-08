"""Config schema and internal local policy engine for MCP Proxy v0.1.

P1 intentionally stops at local config and policy evaluation. The engine sees
only normalized metadata, never raw MCP arguments, prompts, outputs, tokens, or
source code.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import fnmatch
import hashlib
from types import MappingProxyType
from typing import Any, Deque, Iterable, Mapping, Sequence

import jcs

from agentveil_mcp_proxy.circuit_breaker import CircuitBreakerConfig


PROXY_CONFIG_SCHEMA_VERSION = 1
POLICY_SCHEMA_VERSION = 1
MAX_RUNTIME_EVENTS = 1000


class ProxyConfigError(ValueError):
    """Raised when MCP proxy config or policy data is invalid."""


class DecisionMode(str, Enum):
    """Proxy enforcement mode."""

    OBSERVE = "observe"
    PROTECT = "protect"
    STRICT = "strict"


class ToolSurfaceMode(str, Enum):
    """Declared tool surface enforcement mode (orthogonal to DecisionMode)."""

    OFF = "off"
    OBSERVE = "observe"
    ENFORCE = "enforce"


class RoleAuthorityMode(str, Enum):
    """Least Agency role/authority enforcement mode."""

    OFF = "off"
    ENFORCE = "enforce"


class ApprovalUiOpenMode(str, Enum):
    """How the local approval surface is presented to the operator."""

    BROWSER = "browser"
    TERMINAL = "terminal"
    NONE = "none"


class PolicyDecision(str, Enum):
    """Internal local-policy decision vocabulary."""

    ALLOW = "allow"
    APPROVAL = "approval"
    BLOCK = "block"
    OBSERVE = "observe"
    ASK_BACKEND = "ask_backend"


class RiskClass(str, Enum):
    """Risk vocabulary for local proxy policy."""

    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    PRODUCTION = "production"
    FINANCIAL = "financial"
    UNKNOWN = "unknown"


class TimeoutAction(str, Enum):
    """Approval timeout behavior."""

    DENY = "deny"
    HANG = "hang"


_DECISION_RANK = {
    PolicyDecision.ALLOW: 0,
    PolicyDecision.OBSERVE: 1,
    PolicyDecision.ASK_BACKEND: 2,
    PolicyDecision.APPROVAL: 3,
    PolicyDecision.BLOCK: 4,
}

_RISK_RANK = {
    RiskClass.READ: 0,
    RiskClass.WRITE: 1,
    RiskClass.PRODUCTION: 2,
    RiskClass.FINANCIAL: 3,
    RiskClass.DESTRUCTIVE: 4,
    RiskClass.UNKNOWN: 5,
}

_FALLBACK_ALLOWED = {
    PolicyDecision.ALLOW,
    PolicyDecision.APPROVAL,
    PolicyDecision.BLOCK,
}


def _require_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProxyConfigError(f"{where} must be an object")
    return value


def _reject_unknown(data: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        names = ", ".join(unknown)
        raise ProxyConfigError(f"{where} has unknown field(s): {names}")


def _non_empty_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProxyConfigError(f"{where} must be a non-empty string")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ProxyConfigError(f"{where} must be a boolean")
    return value


def _positive_int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ProxyConfigError(f"{where} must be a positive integer")
    return value


def _enum(enum_type: type[Enum], value: Any, where: str) -> Any:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise ProxyConfigError(f"{where} must be a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise ProxyConfigError(f"{where} must be one of: {allowed}") from exc


def _string_patterns(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (_non_empty_str(value, where),)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = tuple(_non_empty_str(item, f"{where}[]") for item in value)
        if not items:
            raise ProxyConfigError(f"{where} must not be empty")
        return items
    raise ProxyConfigError(f"{where} must be a string or list of strings")


def _risk_values(value: Any, where: str) -> tuple[RiskClass, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or isinstance(value, RiskClass):
        return (_enum(RiskClass, value, where),)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = tuple(_enum(RiskClass, item, f"{where}[]") for item in value)
        if not items:
            raise ProxyConfigError(f"{where} must not be empty")
        return items
    raise ProxyConfigError(f"{where} must be a string or list of strings")


def _decision(value: Any, where: str) -> PolicyDecision:
    return _enum(PolicyDecision, value, where)


def _fallback_decision(value: Any, where: str) -> PolicyDecision:
    decision = _decision(value, where)
    if decision not in _FALLBACK_ALLOWED:
        allowed = ", ".join(sorted(item.value for item in _FALLBACK_ALLOWED))
        raise ProxyConfigError(f"{where} must be one of: {allowed}")
    return decision


def _patterns_match(patterns: tuple[str, ...], value: str | None) -> bool:
    if not patterns:
        return True
    if value is None:
        return False
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _risk_match(risks: tuple[RiskClass, ...], value: RiskClass) -> bool:
    return not risks or value in risks


def policy_context_hash(
    *,
    policy_id: str,
    policy_rule_id: str,
    risk_class: RiskClass | str,
    decision_mode: DecisionMode | str,
    policy_schema_version: int = POLICY_SCHEMA_VERSION,
) -> str:
    """Return the P0-defined opaque policy context hash as lowercase hex."""

    risk = _enum(RiskClass, risk_class, "risk_class").value
    mode = _enum(DecisionMode, decision_mode, "decision_mode").value
    payload = {
        "policy_schema_version": policy_schema_version,
        "policy_id": policy_id,
        "policy_rule_id": policy_rule_id,
        "risk_class": risk,
        "decision_mode": mode,
    }
    return hashlib.sha256(jcs.canonicalize(payload)).hexdigest()


@dataclass(frozen=True)
class AvpConfig:
    """AVP backend config needed by later proxy slices."""

    base_url: str
    agent_name: str
    trusted_signer_dids: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AvpConfig":
        data = _require_mapping(data, "avp")
        _reject_unknown(data, {"base_url", "agent_name", "trusted_signer_dids"}, "avp")
        trusted = data.get("trusted_signer_dids")
        if not isinstance(trusted, Sequence) or isinstance(trusted, (str, bytes, bytearray)):
            raise ProxyConfigError("avp.trusted_signer_dids must be a non-empty list of strings")
        trusted_dids = tuple(_non_empty_str(item, "avp.trusted_signer_dids[]") for item in trusted)
        if not trusted_dids:
            raise ProxyConfigError("avp.trusted_signer_dids must be a non-empty list of strings")
        return cls(
            base_url=_non_empty_str(data.get("base_url"), "avp.base_url"),
            agent_name=_non_empty_str(data.get("agent_name"), "avp.agent_name"),
            trusted_signer_dids=trusted_dids,
        )


@dataclass(frozen=True)
class PrivacyConfig:
    """Privacy config for proxy metadata sent to AVP."""

    action: str = "redacted"
    resource: str = "hash"
    payload: str = "hash_only"
    evidence_upload: bool = False
    show_details_in_approval_ui: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None = None) -> "PrivacyConfig":
        data = _require_mapping(data or {}, "privacy")
        _reject_unknown(
            data,
            {
                "action",
                "resource",
                "payload",
                "evidence_upload",
                "show_details_in_approval_ui",
            },
            "privacy",
        )
        action = data.get("action", "redacted")
        resource = data.get("resource", "hash")
        payload = data.get("payload", "hash_only")
        if action not in {"plain", "redacted", "hash"}:
            raise ProxyConfigError("privacy.action must be one of: plain, redacted, hash")
        if resource not in {"plain", "redacted", "hash"}:
            raise ProxyConfigError("privacy.resource must be one of: plain, redacted, hash")
        if payload != "hash_only":
            raise ProxyConfigError("privacy.payload must be hash_only for v0.1")
        return cls(
            action=action,
            resource=resource,
            payload=payload,
            evidence_upload=_bool(data.get("evidence_upload", False), "privacy.evidence_upload"),
            show_details_in_approval_ui=_bool(
                data.get("show_details_in_approval_ui", False),
                "privacy.show_details_in_approval_ui",
            ),
        )


@dataclass(frozen=True)
class FallbackConfig:
    """Backend-down fallback decisions by risk class.

    These apply only when the Runtime Gate is unavailable / the circuit breaker
    is open. No default fails open: every default is APPROVAL or BLOCK, so a Gate
    claim-check: allow "every"/"never" describe this class's own default fields; tested in tests/test_mcp_proxy_policy.py
    outage never silently forwards a tool call. An operator may still set any
    field to ``allow`` explicitly; that is an opt-in fail-open accepting the risk
    of forwarding without a backend decision during an outage.
    """

    read: PolicyDecision = PolicyDecision.APPROVAL
    write: PolicyDecision = PolicyDecision.APPROVAL
    destructive: PolicyDecision = PolicyDecision.BLOCK
    production: PolicyDecision = PolicyDecision.BLOCK
    financial: PolicyDecision = PolicyDecision.BLOCK
    unknown: PolicyDecision = PolicyDecision.APPROVAL

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None = None) -> "FallbackConfig":
        data = _require_mapping(data or {}, "fallback")
        allowed = {"read", "write", "destructive", "production", "financial", "unknown"}
        _reject_unknown(data, allowed, "fallback")
        defaults = cls()
        return cls(
            read=_fallback_decision(data.get("read", defaults.read.value), "fallback.read"),
            write=_fallback_decision(data.get("write", defaults.write.value), "fallback.write"),
            destructive=_fallback_decision(
                data.get("destructive", defaults.destructive.value), "fallback.destructive",
            ),
            production=_fallback_decision(
                data.get("production", defaults.production.value), "fallback.production",
            ),
            financial=_fallback_decision(
                data.get("financial", defaults.financial.value), "fallback.financial",
            ),
            unknown=_fallback_decision(data.get("unknown", defaults.unknown.value), "fallback.unknown"),
        )

    def for_risk(self, risk_class: RiskClass | str) -> PolicyDecision:
        risk = _enum(RiskClass, risk_class, "risk_class")
        return getattr(self, risk.value)


@dataclass(frozen=True)
class ApprovalConfig:
    """Approval timeout and local approval UI defaults."""

    approval_timeout_seconds: int = 300
    on_timeout: TimeoutAction = TimeoutAction.DENY
    ui_open_mode: ApprovalUiOpenMode = ApprovalUiOpenMode.BROWSER

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None = None) -> "ApprovalConfig":
        data = _require_mapping(data or {}, "approval")
        _reject_unknown(
            data,
            {"approval_timeout_seconds", "on_timeout", "ui_open_mode"},
            "approval",
        )
        timeout_action = data.get("on_timeout", "deny")
        if timeout_action == "allow":
            raise ProxyConfigError(
                "approval.on_timeout=allow removed; use deny or hang. "
                "allow created approval-bypass-via-inaction risk and is no longer supported."
            )
        return cls(
            approval_timeout_seconds=_positive_int(
                data.get("approval_timeout_seconds", 300),
                "approval.approval_timeout_seconds",
            ),
            on_timeout=_enum(TimeoutAction, timeout_action, "approval.on_timeout"),
            ui_open_mode=_enum(
                ApprovalUiOpenMode,
                data.get("ui_open_mode", ApprovalUiOpenMode.BROWSER.value),
                "approval.ui_open_mode",
            ),
        )


@dataclass(frozen=True)
class ProxyCircuitBreakerConfig:
    """Backend circuit breaker config wrapper for proxy schema validation."""

    failures_before_open: int = 5
    window_seconds: int = 60
    cooldown_seconds: int = 30
    half_open_test_count: int = 1

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None = None) -> "ProxyCircuitBreakerConfig":
        try:
            parsed = CircuitBreakerConfig.from_dict(data)
        except ValueError as exc:
            raise ProxyConfigError(str(exc)) from exc
        return cls(
            failures_before_open=parsed.failures_before_open,
            window_seconds=parsed.window_seconds,
            cooldown_seconds=parsed.cooldown_seconds,
            half_open_test_count=parsed.half_open_test_count,
        )

    def to_runtime_config(self) -> CircuitBreakerConfig:
        """Return the gateway-agnostic runtime circuit breaker config."""

        return CircuitBreakerConfig(
            failures_before_open=self.failures_before_open,
            window_seconds=self.window_seconds,
            cooldown_seconds=self.cooldown_seconds,
            half_open_test_count=self.half_open_test_count,
        )


@dataclass(frozen=True)
class PolicyMatch:
    """Rule match criteria.

    Empty fields are wildcards. Pattern fields use shell-style globs.
    """

    server: tuple[str, ...] = ()
    tool: tuple[str, ...] = ()
    action: tuple[str, ...] = ()
    risk_class: tuple[RiskClass, ...] = ()
    role: tuple[str, ...] = ()
    authority: tuple[str, ...] = ()
    action_family: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None = None) -> "PolicyMatch":
        data = _require_mapping(data or {}, "policy.rules[].match")
        _reject_unknown(
            data,
            {"server", "tool", "action", "risk_class", "role", "authority", "action_family"},
            "policy.rules[].match",
        )
        return cls(
            server=_string_patterns(data.get("server"), "policy.rules[].match.server"),
            tool=_string_patterns(data.get("tool"), "policy.rules[].match.tool"),
            action=_string_patterns(data.get("action"), "policy.rules[].match.action"),
            risk_class=_risk_values(data.get("risk_class"), "policy.rules[].match.risk_class"),
            role=_string_patterns(data.get("role"), "policy.rules[].match.role"),
            authority=_string_patterns(data.get("authority"), "policy.rules[].match.authority"),
            action_family=_string_patterns(
                data.get("action_family"),
                "policy.rules[].match.action_family",
            ),
        )

    def matches(self, context: "ToolCallContext") -> bool:
        return (
            _patterns_match(self.server, context.server)
            and _patterns_match(self.tool, context.tool)
            and _patterns_match(self.action, context.action)
            and _risk_match(self.risk_class, context.risk_class)
            and _patterns_match(self.role, context.role)
            and _patterns_match(self.authority, context.authority)
            and _patterns_match(self.action_family, context.action_family)
        )


@dataclass(frozen=True)
class PolicyRule:
    """One local policy rule."""

    id: str
    decision: PolicyDecision
    match: PolicyMatch = field(default_factory=PolicyMatch)
    risk_class: RiskClass | None = None
    source: str = "user"
    intentional_override: bool = False
    reason: str | None = None
    approval_scope_expansion: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PolicyRule":
        data = _require_mapping(data, "policy.rules[]")
        _reject_unknown(
            data,
            {
                "id",
                "decision",
                "match",
                "risk_class",
                "source",
                "intentional_override",
                "reason",
                "approval",
            },
            "policy.rules[]",
        )
        source = data.get("source", "user")
        if source not in {"user", "builtin"}:
            raise ProxyConfigError("policy.rules[].source must be one of: user, builtin")
        reason = data.get("reason")
        if reason is not None:
            reason = _non_empty_str(reason, "policy.rules[].reason")
        approval_scope_expansion = None
        approval = data.get("approval")
        if approval is not None:
            approval = _require_mapping(approval, "policy.rules[].approval")
            _reject_unknown(approval, {"scope_expansion"}, "policy.rules[].approval")
            scope = approval.get("scope_expansion")
            if scope is not None:
                scope = _non_empty_str(scope, "policy.rules[].approval.scope_expansion")
                if scope != "similar_5m":
                    raise ProxyConfigError(
                        "policy.rules[].approval.scope_expansion must be similar_5m"
                    )
                approval_scope_expansion = scope
        return cls(
            id=_non_empty_str(data.get("id"), "policy.rules[].id"),
            decision=_decision(data.get("decision"), "policy.rules[].decision"),
            match=PolicyMatch.from_dict(data.get("match", {})),
            risk_class=(
                None if data.get("risk_class") is None
                else _enum(RiskClass, data.get("risk_class"), "policy.rules[].risk_class")
            ),
            source=source,
            intentional_override=_bool(
                data.get("intentional_override", False),
                "policy.rules[].intentional_override",
            ),
            reason=reason,
            approval_scope_expansion=approval_scope_expansion,
        )

    def matches(self, context: "ToolCallContext") -> bool:
        return self.match.matches(context)


@dataclass(frozen=True)
class PolicyConfig:
    """Versioned local policy config."""

    id: str = "default"
    policy_schema_version: int = POLICY_SCHEMA_VERSION
    rules: tuple[PolicyRule, ...] = ()
    default_decision: PolicyDecision = PolicyDecision.ASK_BACKEND
    default_risk_class: RiskClass = RiskClass.UNKNOWN

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None = None) -> "PolicyConfig":
        data = _require_mapping(data or {}, "policy")
        _reject_unknown(
            data,
            {"id", "policy_schema_version", "rules", "default_decision", "default_risk_class"},
            "policy",
        )
        schema_version = data.get("policy_schema_version", POLICY_SCHEMA_VERSION)
        if schema_version != POLICY_SCHEMA_VERSION:
            raise ProxyConfigError("policy.policy_schema_version must be 1")
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, Sequence) or isinstance(raw_rules, (str, bytes, bytearray)):
            raise ProxyConfigError("policy.rules must be a list")
        return cls(
            id=_non_empty_str(data.get("id", "default"), "policy.id"),
            policy_schema_version=schema_version,
            rules=tuple(PolicyRule.from_dict(rule) for rule in raw_rules),
            default_decision=_decision(data.get("default_decision", "ask_backend"), "policy.default_decision"),
            default_risk_class=_enum(
                RiskClass,
                data.get("default_risk_class", "unknown"),
                "policy.default_risk_class",
            ),
        )


@dataclass(frozen=True)
class ToolSurfaceConfig:
    """Operator-declared tool surface enforcement config.

    ``mode`` defaults to ``off`` for backward compatibility. ``allow`` holds
    shell-style (fnmatchcase) patterns; a tool is declared only when its
    JSON-RPC ``params.name`` matches at least one pattern. An empty allowlist
    declares nothing, so under ``enforce`` every tool call is blocked and under
    claim-check: allow "blocked/every" describes tested allowlist semantics.
    ``observe`` every tool call is recorded -- operators opt in by listing the
    tools they expect.
    """

    mode: ToolSurfaceMode = ToolSurfaceMode.OFF
    allow: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None = None) -> "ToolSurfaceConfig":
        # Default only for an omitted block (None). A present-but-non-object
        # value (e.g. [], "", 0) must fail loudly rather than silently disable
        # enforcement -- a typo'd tool_surface should never quietly become off.
        # claim-check: allow "never" describes validation fail-closed intent.
        if data is None:
            data = {}
        data = _require_mapping(data, "tool_surface")
        _reject_unknown(data, {"mode", "allow"}, "tool_surface")
        mode = _enum(ToolSurfaceMode, data.get("mode", "off"), "tool_surface.mode")
        allow_raw = data.get("allow")
        if allow_raw is None:
            allow: tuple[str, ...] = ()
        elif isinstance(allow_raw, str):
            allow = (_non_empty_str(allow_raw, "tool_surface.allow"),)
        elif isinstance(allow_raw, Sequence) and not isinstance(allow_raw, (str, bytes, bytearray)):
            allow = tuple(_non_empty_str(item, "tool_surface.allow[]") for item in allow_raw)
        else:
            raise ProxyConfigError("tool_surface.allow must be a string or list of strings")
        return cls(mode=mode, allow=allow)

    def is_declared(self, tool_name: str) -> bool:
        """Return True when ``tool_name`` matches at least one allow pattern."""

        return any(fnmatch.fnmatchcase(tool_name, pattern) for pattern in self.allow)

    def is_action_gate_active(self) -> bool:
        """Return True when declared-vs-observed downstream surface checks apply."""

        return self.mode is not ToolSurfaceMode.OFF and bool(self.allow)

    def matching_observed_tools(self, observed: Iterable[str]) -> tuple[str, ...]:
        """Return sorted observed tool names that match at least one allow pattern."""

        return tuple(sorted(tool for tool in observed if self.is_declared(tool)))

    def extra_observed_tools(self, observed: Iterable[str]) -> tuple[str, ...]:
        """Return sorted observed tool names absent from the declared surface."""

        return tuple(sorted(tool for tool in observed if not self.is_declared(tool)))


@dataclass(frozen=True)
class RoleAuthorityConfig:
    """Operator-declared Least Agency role and authority for brokered tool calls."""

    mode: RoleAuthorityMode = RoleAuthorityMode.OFF
    role: str | None = None
    authority: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None = None) -> "RoleAuthorityConfig":
        if data is None:
            data = {}
        data = _require_mapping(data, "role_authority")
        _reject_unknown(data, {"mode", "role", "authority"}, "role_authority")
        mode = _enum(RoleAuthorityMode, data.get("mode", "off"), "role_authority.mode")
        role = data.get("role")
        authority = data.get("authority")
        if role is not None:
            role = _non_empty_str(role, "role_authority.role")
        if authority is not None:
            authority = _non_empty_str(authority, "role_authority.authority")
        if mode is RoleAuthorityMode.ENFORCE and role is None:
            raise ProxyConfigError("role_authority.role is required when role_authority.mode is enforce")
        return cls(mode=mode, role=role, authority=authority)

    def is_enforced(self) -> bool:
        return self.mode is RoleAuthorityMode.ENFORCE and self.role is not None


_ROLE_AUTHORITY_REVIEWER_BLOCKED_FAMILIES = (
    "write",
    "create",
    "update",
    "delete",
    "remove",
    "exec",
    "shell",
)
_ROLE_AUTHORITY_RULE_ID = "role_authority_reviewer_blocks_implementation"
_ROLE_AUTHORITY_READONLY_RULE_ID = "role_authority_readonly_blocks_mutation"
_ROLE_AUTHORITY_REASON = "role_authority_denied"
_ROLE_AUTHORITY_AUTHORITY = "review_only"
_ROLE_AUTHORITY_MUTATION_FAMILIES = _ROLE_AUTHORITY_REVIEWER_BLOCKED_FAMILIES


def _role_authority_match_patterns(
    role_authority: RoleAuthorityConfig,
) -> tuple[str, ...]:
    if role_authority.authority is None:
        return ()
    return (role_authority.authority,)


def _mutation_deny_rule(
    *,
    rule_id: str,
    role: str,
    authority_patterns: tuple[str, ...],
) -> PolicyRule:
    return PolicyRule(
        id=rule_id,
        decision=PolicyDecision.BLOCK,
        match=PolicyMatch(
            role=(role,),
            authority=authority_patterns,
            action_family=_ROLE_AUTHORITY_MUTATION_FAMILIES,
        ),
        source="builtin",
        reason=_ROLE_AUTHORITY_REASON,
    )


def role_authority_builtin_rules(role_authority: RoleAuthorityConfig) -> tuple[PolicyRule, ...]:
    """Return built-in Least Agency role/authority deny rules for one config."""

    if not role_authority.is_enforced() or role_authority.role is None:
        return ()
    authority_patterns = _role_authority_match_patterns(role_authority)
    if role_authority.role == "reviewer":
        return (
            _mutation_deny_rule(
                rule_id=_ROLE_AUTHORITY_RULE_ID,
                role="reviewer",
                authority_patterns=authority_patterns,
            ),
        )
    if role_authority.role == "readonly":
        return (
            _mutation_deny_rule(
                rule_id=_ROLE_AUTHORITY_READONLY_RULE_ID,
                role="readonly",
                authority_patterns=authority_patterns,
            ),
        )
    return ()


_ACTION_GATE_POLICY_ID = "mcp_proxy_action_gate"
_ACTION_GATE_AUTHORITY = "operator_declared_surface"
_ACTION_GATE_ESCALATION_SURFACE_DRIFT = "downstream_surface_drift"
_ACTION_GATE_ESCALATION_EXTRA_TOOL = "extra_undeclared_downstream_tool"
_ACTION_GATE_MAX_SURFACE_TOOLS = 64


def surface_name_hash(tool_names: Iterable[str]) -> str:
    """Return a bounded sha256 digest over a sorted tool-name list."""

    bounded = tuple(sorted(tool_names))[:_ACTION_GATE_MAX_SURFACE_TOOLS]
    return "sha256:" + hashlib.sha256(jcs.canonicalize(bounded)).hexdigest()


def derive_target_reached(*, execution_status: str, downstream_tool_call_seen: bool) -> bool:
    """Return True only when a brokered tools/call reached the fake downstream."""

    return downstream_tool_call_seen and execution_status == "executed"


def build_controlled_path_metadata(
    *,
    fixture_id: str,
    tool_name: str,
    policy_decision: str,
    policy_rule_id: str | None,
    approval_status: str,
    execution_status: str,
    target_reached: bool,
    request_id: str,
    request_chain: Iterable[str] | None = None,
    payload_hash: str | None = None,
    role: str | None = None,
    authority: str | None = None,
    action_family: str | None = None,
) -> dict[str, Any]:
    """Build bounded fake-target controlled-path metadata for evidence export."""

    metadata: dict[str, Any] = {
        "fixture_id": fixture_id,
        "tool": tool_name,
        "policy_decision": policy_decision,
        "policy_rule": policy_rule_id,
        "approval_status": approval_status,
        "execution_status": execution_status,
        "target_reached": target_reached,
        "request_id": request_id,
        "request_chain": list(request_chain or (request_id,)),
    }
    if payload_hash is not None:
        metadata["payload_hash"] = payload_hash
    if role is not None:
        metadata["role"] = role
    if authority is not None:
        metadata["authority"] = authority
    if action_family is not None:
        metadata["action_family"] = action_family
    return metadata


def build_action_gate_metadata(
    *,
    declared_patterns: Iterable[str],
    observed_tools: Iterable[str],
    tool_name: str,
    action_family: str,
    policy_decision: str,
    policy_rule_id: str | None,
    approval_status: str,
    execution_status: str,
    request_id: str,
    request_chain: Iterable[str] | None = None,
    escalation_trigger: str | None = None,
    payload_hash: str | None = None,
    target_reached: bool = False,
) -> dict[str, Any]:
    """Build bounded Least Agency metadata for one MCP action-gate event."""

    declared = tuple(sorted(declared_patterns))[:_ACTION_GATE_MAX_SURFACE_TOOLS]
    observed = tuple(sorted(observed_tools))[:_ACTION_GATE_MAX_SURFACE_TOOLS]
    matching = tuple(
        sorted(tool for tool in observed if any(fnmatch.fnmatchcase(tool, pattern) for pattern in declared))
    )
    extra = tuple(sorted(tool for tool in observed if tool not in matching))
    metadata: dict[str, Any] = {
        "declared_tool_surface": list(declared),
        "observed_tool_surface": list(observed),
        "matching_tool_surface": list(matching),
        "extra_undeclared_tools": list(extra),
        "declared_surface_hash": surface_name_hash(declared),
        "observed_surface_hash": surface_name_hash(observed),
        "action_family": action_family,
        "authority": _ACTION_GATE_AUTHORITY,
        "policy_decision": policy_decision,
        "policy_rule": policy_rule_id,
        "approval_status": approval_status,
        "execution_status": execution_status,
        "request_id": request_id,
        "request_chain": list(request_chain or (request_id,)),
        "tool": tool_name,
        "target_reached": target_reached,
    }
    if escalation_trigger is not None:
        metadata["escalation_trigger"] = escalation_trigger
    if payload_hash is not None:
        metadata["payload_hash"] = payload_hash
    return metadata


@dataclass(frozen=True)
class ProxyConfig:
    """Top-level MCP proxy config schema."""

    avp: AvpConfig
    proxy_config_schema_version: int = PROXY_CONFIG_SCHEMA_VERSION
    mode: DecisionMode = DecisionMode.PROTECT
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    fallback: FallbackConfig = field(default_factory=FallbackConfig)
    approval: ApprovalConfig = field(default_factory=ApprovalConfig)
    circuit_breaker: ProxyCircuitBreakerConfig = field(default_factory=ProxyCircuitBreakerConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    tool_surface: ToolSurfaceConfig = field(default_factory=ToolSurfaceConfig)
    role_authority: RoleAuthorityConfig = field(default_factory=RoleAuthorityConfig)
    role_preset: str | None = None
    downstream: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProxyConfig":
        data = _require_mapping(data, "proxy config")
        _reject_unknown(
            data,
            {
                "proxy_config_schema_version",
                "avp",
                "mode",
                "privacy",
                "fallback",
                "approval",
                "circuit_breaker",
                "policy",
                "tool_surface",
                "role_authority",
                "role_preset",
                "downstream",
            },
            "proxy config",
        )
        schema_version = data.get("proxy_config_schema_version")
        if schema_version != PROXY_CONFIG_SCHEMA_VERSION:
            raise ProxyConfigError("proxy_config_schema_version must be 1")
        downstream = data.get("downstream", {})
        downstream = _require_mapping(downstream, "downstream")
        return cls(
            proxy_config_schema_version=schema_version,
            avp=AvpConfig.from_dict(data.get("avp")),
            mode=_enum(DecisionMode, data.get("mode", "protect"), "mode"),
            privacy=PrivacyConfig.from_dict(data.get("privacy", {})),
            fallback=FallbackConfig.from_dict(data.get("fallback", {})),
            approval=ApprovalConfig.from_dict(data.get("approval", {})),
            circuit_breaker=ProxyCircuitBreakerConfig.from_dict(data.get("circuit_breaker")),
            policy=PolicyConfig.from_dict(data.get("policy", {})),
            tool_surface=ToolSurfaceConfig.from_dict(data.get("tool_surface", {})),
            role_authority=RoleAuthorityConfig.from_dict(data.get("role_authority", {})),
            role_preset=(
                None
                if data.get("role_preset") is None
                else _non_empty_str(data.get("role_preset"), "role_preset")
            ),
            downstream=MappingProxyType(dict(downstream)),
        )


@dataclass(frozen=True)
class ToolCallContext:
    """Metadata-only policy evaluation input."""

    server: str
    tool: str
    action: str | None = None
    risk_class: RiskClass = RiskClass.UNKNOWN
    role: str | None = None
    authority: str | None = None
    action_family: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ToolCallContext":
        data = _require_mapping(data, "tool_call_context")
        _reject_unknown(
            data,
            {"server", "tool", "action", "risk_class", "role", "authority", "action_family"},
            "tool_call_context",
        )
        action = data.get("action")
        if action is not None:
            action = _non_empty_str(action, "tool_call_context.action")
        role = data.get("role")
        authority = data.get("authority")
        action_family = data.get("action_family")
        if role is not None:
            role = _non_empty_str(role, "tool_call_context.role")
        if authority is not None:
            authority = _non_empty_str(authority, "tool_call_context.authority")
        if action_family is not None:
            action_family = _non_empty_str(action_family, "tool_call_context.action_family")
        return cls(
            server=_non_empty_str(data.get("server"), "tool_call_context.server"),
            tool=_non_empty_str(data.get("tool"), "tool_call_context.tool"),
            action=action,
            risk_class=_enum(RiskClass, data.get("risk_class", "unknown"), "tool_call_context.risk_class"),
            role=role,
            authority=authority,
            action_family=action_family,
        )


@dataclass(frozen=True)
class PolicyEvaluation:
    """Result of local policy evaluation."""

    decision: PolicyDecision
    risk_class: RiskClass
    policy_id: str
    policy_rule_id: str
    policy_context_hash: str
    matched_rule_ids: tuple[str, ...]
    would_decision: PolicyDecision | None = None
    intentional_override_applied: bool = False
    reason: str | None = None


class PolicyEngine:
    """Evaluate metadata-only tool calls against local policy."""

    def __init__(self, config: ProxyConfig):
        self.config = config

    def evaluate(self, context: ToolCallContext | Mapping[str, Any]) -> PolicyEvaluation:
        if isinstance(context, Mapping):
            context = ToolCallContext.from_dict(context)
        rules = self.config.policy.rules + role_authority_builtin_rules(self.config.role_authority)
        matching = tuple(rule for rule in rules if rule.matches(context))
        selected, override_applied = self._select_rule(matching)
        risk = self._risk_for(selected, context)
        effective = selected.decision
        would_decision = None
        if self.config.mode == DecisionMode.OBSERVE:
            would_decision = effective
            effective = PolicyDecision.OBSERVE
        return PolicyEvaluation(
            decision=effective,
            would_decision=would_decision,
            risk_class=risk,
            policy_id=self.config.policy.id,
            policy_rule_id=selected.id,
            matched_rule_ids=tuple(rule.id for rule in matching),
            intentional_override_applied=override_applied,
            reason=selected.reason,
            policy_context_hash=policy_context_hash(
                policy_id=self.config.policy.id,
                policy_rule_id=selected.id,
                risk_class=risk,
                decision_mode=self.config.mode,
                policy_schema_version=self.config.policy.policy_schema_version,
            ),
        )

    def _select_rule(self, matching: tuple[PolicyRule, ...]) -> tuple[PolicyRule, bool]:
        if not matching:
            return (
                PolicyRule(
                    id="default",
                    decision=self.config.policy.default_decision,
                    risk_class=self.config.policy.default_risk_class,
                    source="builtin",
                    reason="default policy decision",
                ),
                False,
            )
        override_rules = tuple(
            rule for rule in matching
            if rule.source == "user" and rule.intentional_override
        )
        if override_rules:
            # Intentional overrides may weaken built-in rules, but they should
            # not silently bypass another stricter user-authored rule.
            user_rules = tuple(rule for rule in matching if rule.source == "user")
            selected = max(user_rules, key=_rule_rank)
            return selected, selected.intentional_override
        return max(matching, key=_rule_rank), False

    def _risk_for(self, selected: PolicyRule, context: ToolCallContext) -> RiskClass:
        return selected.risk_class or context.risk_class


def _rule_rank(rule: PolicyRule) -> tuple[int, int, str]:
    risk_rank = _RISK_RANK.get(rule.risk_class or RiskClass.UNKNOWN, _RISK_RANK[RiskClass.UNKNOWN])
    return (_DECISION_RANK[rule.decision], risk_rank, rule.id)


@dataclass(frozen=True)
class PolicyReloadResult:
    """Outcome of a hot-reload attempt."""

    applied: bool
    config: ProxyConfig
    error: str | None
    event: Mapping[str, Any]


class PolicyRuntime:
    """Hold last-good config and apply hot reloads fail-safe.

    The events buffer is bounded with FIFO drop-oldest semantics so a long-running
    proxy cannot leak memory through unbounded event accumulation. P7 will add a
    persistent evidence store; until then the in-process buffer is capped.
    """

    def __init__(self, config: ProxyConfig, *, max_events: int = MAX_RUNTIME_EVENTS):
        if max_events <= 0:
            raise ValueError("max_events must be positive")
        self.config = config
        self.events: Deque[Mapping[str, Any]] = deque(maxlen=max_events)

    def reload_from_dict(self, data: Mapping[str, Any]) -> PolicyReloadResult:
        try:
            new_config = ProxyConfig.from_dict(data)
        except ProxyConfigError as exc:
            event = {
                "type": "policy_reload_failed",
                "applied": False,
                "error": str(exc),
                "kept_policy_id": self.config.policy.id,
            }
            self.events.append(event)
            return PolicyReloadResult(False, self.config, str(exc), event)

        self.config = new_config
        event = {
            "type": "policy_reload_applied",
            "applied": True,
            "policy_id": new_config.policy.id,
        }
        self.events.append(event)
        return PolicyReloadResult(True, self.config, None, event)

    @property
    def engine(self) -> PolicyEngine:
        return PolicyEngine(self.config)


def builtin_policy_pack(name: str) -> PolicyConfig:
    """Return a small built-in policy pack by name."""

    if name == "default":
        return PolicyConfig(id="default", rules=(), default_decision=PolicyDecision.ASK_BACKEND)

    packs = {
        "github": [
            {
                "id": "github-read",
                "source": "builtin",
                "decision": "allow",
                "risk_class": "read",
                "match": {
                    "server": ["github", "github-*", "github_*", "*github*"],
                    "tool": ["get_*", "list_*", "search_*", "read_*"],
                },
            },
            {
                "id": "github-write",
                "source": "builtin",
                "decision": "ask_backend",
                "risk_class": "write",
                "match": {
                    "server": ["github", "github-*", "github_*", "*github*"],
                    "tool": ["create_*", "update_*", "merge_*", "request_*", "rerun_*", "mark_*"],
                },
            },
            {
                "id": "github-destructive",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "destructive",
                "match": {
                    "server": ["github", "github-*", "github_*", "*github*"],
                    "tool": [
                        "delete_*",
                        "remove_*",
                        "purge_*",
                        "drop_*",
                        "destroy_*",
                        "revoke_*",
                    ],
                },
            },
        ],
        "filesystem": [
            {
                "id": "filesystem-read",
                "source": "builtin",
                "decision": "allow",
                "risk_class": "read",
                "match": {
                    "server": ["filesystem", "fs", "*filesystem*"],
                    "tool": ["read_*", "list_*", "stat_*"],
                },
            },
            {
                "id": "filesystem-write",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "write",
                "match": {
                    "server": ["filesystem", "fs", "*filesystem*"],
                    "tool": ["write_*", "edit_*", "move_*"],
                },
            },
            {
                "id": "filesystem-delete",
                "source": "builtin",
                "decision": "block",
                "risk_class": "destructive",
                "match": {
                    "server": ["filesystem", "fs", "*filesystem*"],
                    "tool": [
                        "delete_*",
                        "remove_*",
                        "purge_*",
                        "truncate_*",
                        "wipe_*",
                        "format_*",
                        "rm",
                        "rm_*",
                        "rmdir_*",
                        "unlink_*",
                        "clean_*",
                    ],
                },
            },
        ],
        "shell": [
            {
                "id": "shell-run",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "unknown",
                "match": {
                    "server": ["shell", "terminal", "*shell*"],
                    "tool": ["run_*", "execute_*", "shell", "command"],
                },
            },
        ],
        # Official MCP Git server tool surface. Server-name globs are kept narrow
        # so this pack does not shadow the github pack (negative test covers
        # server "github" not matching "git" / "git-*" / "git_*").
        "git": [
            {
                "id": "git-read",
                "source": "builtin",
                "decision": "allow",
                "risk_class": "read",
                "match": {
                    "server": ["git", "git-*", "git_*"],
                    "tool": [
                        "git_status",
                        "git_log",
                        "git_diff",
                        "git_diff_staged",
                        "git_diff_unstaged",
                        "git_show",
                        "git_branch",
                    ],
                },
            },
            {
                "id": "git-write",
                "source": "builtin",
                "decision": "ask_backend",
                "risk_class": "write",
                "match": {
                    "server": ["git", "git-*", "git_*"],
                    "tool": [
                        "git_add",
                        "git_commit",
                        "git_checkout",
                        "git_create_branch",
                    ],
                },
            },
            {
                "id": "git-destructive",
                "source": "builtin",
                "decision": "approval",
                "risk_class": "destructive",
                "match": {
                    "server": ["git", "git-*", "git_*"],
                    "tool": ["git_reset"],
                },
            },
        ],
        # Official MCP Fetch server tool surface. The `fetch` tool performs
        # network egress, so the two rules below discriminate on the risk class
        # produced by classification._network_fetch_risk for the SAME tool:
        #   - a benign public fetch classifies READ -> ask_backend, which keeps
        #     the decision the proxy already returned for an unmatched fetch
        #     (this slice only corrects the classification, not the posture);
        #   - a fetch to cloud metadata / link-local (SSRF) classifies
        #     PRODUCTION -> block locally before approval.
        # claim-check: allow "PRODUCTION" and "production" are existing policy
        # risk vocabulary values covered by fetch policy tests.
        # Tool verified against
        # https://github.com/modelcontextprotocol/servers/tree/main/src/fetch (Bug 2).
        "fetch": [
            {
                "id": "fetch-read",
                "source": "builtin",
                "decision": "ask_backend",
                "risk_class": "read",
                "match": {
                    "server": ["fetch", "fetch-*", "fetch_*", "*fetch*"],
                    "tool": ["fetch", "fetch_*"],
                    "risk_class": ["read"],
                },
            },
            {
                "id": "fetch-network-block",
                "source": "builtin",
                "decision": "block",
                "risk_class": "production",  # claim-check: allow "production" is policy vocabulary.
                "match": {
                    "server": ["fetch", "fetch-*", "fetch_*", "*fetch*"],
                    "tool": ["fetch", "fetch_*"],
                    "risk_class": ["production"],  # claim-check: allow "production" is policy vocabulary.
                },
            },
        ],
    }

    if name not in packs:
        known = ", ".join(["default", *sorted(packs)])
        raise ProxyConfigError(f"unknown built-in policy pack {name!r}; expected one of: {known}")
    return PolicyConfig.from_dict({
        "id": name,
        "policy_schema_version": POLICY_SCHEMA_VERSION,
        "default_decision": "ask_backend",
        "default_risk_class": "unknown",
        "rules": packs[name],
    })


__all__ = [
    "ApprovalConfig",
    "ApprovalUiOpenMode",
    "AvpConfig",
    "DecisionMode",
    "FallbackConfig",
    "PolicyConfig",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyEvaluation",
    "PolicyMatch",
    "PolicyReloadResult",
    "PolicyRule",
    "PolicyRuntime",
    "PrivacyConfig",
    "MAX_RUNTIME_EVENTS",
    "PROXY_CONFIG_SCHEMA_VERSION",
    "POLICY_SCHEMA_VERSION",
    "ProxyCircuitBreakerConfig",
    "ProxyConfig",
    "ProxyConfigError",
    "RiskClass",
    "RoleAuthorityConfig",
    "RoleAuthorityMode",
    "TimeoutAction",
    "ToolCallContext",
    "ToolSurfaceConfig",
    "ToolSurfaceMode",
    "builtin_policy_pack",
    "role_authority_builtin_rules",
    "policy_context_hash",
]
