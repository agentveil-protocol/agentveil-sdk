"""Tool-call classification and privacy hashing for MCP Proxy v0.1.

P4 builds local metadata for later Runtime Gate and evidence slices. It does
not call AVP, block downstream calls, or upload raw MCP arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Any, Mapping

import jcs

from agentveil_mcp_proxy.policy import (
    PolicyEngine,
    PolicyEvaluation,
    ProxyConfig,
    RiskClass,
    ToolCallContext,
)


HASH_PREFIX = "sha256:"
REDACTED = "redacted"
_RESOURCE_KEYS = (
    "resource",
    "uri",
    "url",
    "path",
    "file",
    "filename",
    "repo",
    "repository",
    "branch",
    "issue_number",
    "pull_number",
    "pr_number",
)
_READ_PREFIXES = ("get", "list", "read", "search", "fetch", "describe", "view", "show", "stat")
_WRITE_PREFIXES = (
    "create",
    "update",
    "write",
    "edit",
    "merge",
    "request",
    "rerun",
    "mark",
    "push",
    "commit",
    "open",
    "close",
)
_DESTRUCTIVE_PREFIXES = (
    "delete",
    "remove",
    "destroy",
    "drop",
    "revoke",
    "terminate",
    "purge",
    "truncate",
    "wipe",
    "format",
    "rm",
    "rmdir",
    "unlink",
    "clean",
)
_PRODUCTION_WORDS = ("prod", "production", "deploy", "release", "rollback", "infra", "cluster")
_FINANCIAL_WORDS = ("payment", "transfer", "invoice", "billing", "payroll", "purchase", "refund")

# Official Model Context Protocol Git server tool catalog. Source-control verbs
# such as "status", "log", "diff", "show", and "reset" do not match the generic
# _READ/_WRITE/_DESTRUCTIVE prefix lists, so without this explicit table the
# evidence pipeline records them as UNKNOWN. Tool list verified against
# https://github.com/modelcontextprotocol/servers/tree/main/src/git (Bug 1).
_GIT_TOOL_RISK_CLASSES: Mapping[str, RiskClass] = {
    "git_status": RiskClass.READ,
    "git_log": RiskClass.READ,
    "git_diff": RiskClass.READ,
    "git_diff_staged": RiskClass.READ,
    "git_diff_unstaged": RiskClass.READ,
    "git_show": RiskClass.READ,
    "git_branch": RiskClass.READ,
    "git_add": RiskClass.WRITE,
    "git_commit": RiskClass.WRITE,
    "git_checkout": RiskClass.WRITE,
    "git_create_branch": RiskClass.WRITE,
    "git_reset": RiskClass.DESTRUCTIVE,
}


def sha256_jcs(value: Any) -> str:
    """Return a prefixed SHA-256 digest over JCS-canonicalized JSON data."""

    return HASH_PREFIX + hashlib.sha256(jcs.canonicalize(_json_compatible(value))).hexdigest()


def sha256_text(value: str) -> str:
    """Return a prefixed SHA-256 digest over UTF-8 text."""

    return HASH_PREFIX + hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ClassifiedToolCall:
    """Privacy-preserving local metadata for one MCP tools/call request."""

    server: str
    tool: str
    action_plain: str
    action: str
    action_hash: str
    resource_plain: str | None
    resource: str | None
    resource_hash: str | None
    payload_hash: str
    risk_class: RiskClass
    policy_evaluation: PolicyEvaluation

    def backend_metadata(self) -> dict[str, Any]:
        """Return privacy-filtered metadata intended for later backend calls."""

        return {
            "action": self.action,
            "action_hash": self.action_hash if self.action == self.action_hash else None,
            "resource": self.resource,
            "resource_hash": self.resource_hash if self.resource == self.resource_hash else None,
            "risk_class": self.risk_class.value,
            "payload_hash": self.payload_hash,
            "policy_context_hash": self.policy_evaluation.policy_context_hash,
            "local_decision": self.policy_evaluation.decision.value,
            "would_decision": (
                None if self.policy_evaluation.would_decision is None
                else self.policy_evaluation.would_decision.value
            ),
        }

    def local_evidence_metadata(self) -> dict[str, Any]:
        """Return local-only metadata for future evidence slices."""

        return {
            "downstream_server": self.server,
            "tool": self.tool,
            "action_plain": self.action_plain,
            "action": self.action,
            "action_hash": self.action_hash,
            "resource": self.resource,
            "resource_hash": self.resource_hash,
            "risk_class": self.risk_class.value,
            "payload_hash": self.payload_hash,
            "policy_id": self.policy_evaluation.policy_id,
            "policy_rule_id": self.policy_evaluation.policy_rule_id,
            "policy_context_hash": self.policy_evaluation.policy_context_hash,
            "local_decision": self.policy_evaluation.decision.value,
            "matched_rule_ids": list(self.policy_evaluation.matched_rule_ids),
        }


class ToolCallClassifier:
    """Classify MCP tools/call requests without exposing raw arguments."""

    def __init__(self, config: ProxyConfig, *, server_name: str):
        self.config = config
        self.server_name = server_name
        self.engine = PolicyEngine(config)

    def classify_jsonrpc(self, message: Mapping[str, Any]) -> ClassifiedToolCall | None:
        """Classify a JSON-RPC message when it is an MCP tools/call request."""

        if message.get("method") != "tools/call":
            return None
        params = message.get("params")
        if not isinstance(params, Mapping):
            return None
        tool = params.get("name")
        if not isinstance(tool, str) or not tool:
            return None
        return self.classify(tool=tool, arguments=params.get("arguments", {}))

    def classify(self, *, tool: str, arguments: Any = None) -> ClassifiedToolCall:
        """Build local classification and privacy-safe hashes for one tool call."""

        payload = {} if arguments is None else arguments
        args = dict(arguments) if isinstance(arguments, Mapping) else {}
        action_plain = f"{self.server_name}.{tool}"
        resource_plain = extract_resource(args)
        heuristic_risk = infer_risk_class(action_plain, tool=tool, resource=resource_plain, arguments=args)
        context = ToolCallContext(
            server=self.server_name,
            tool=tool,
            action=action_plain,
            risk_class=heuristic_risk,
        )
        evaluation = self.engine.evaluate(context)
        action_hash = sha256_text(action_plain)
        resource_hash = None if resource_plain is None else sha256_text(resource_plain)
        return ClassifiedToolCall(
            server=self.server_name,
            tool=tool,
            action_plain=action_plain,
            action=_privacy_value(action_plain, self.config.privacy.action, value_hash=action_hash),
            action_hash=action_hash,
            resource_plain=resource_plain,
            resource=_privacy_value(resource_plain, self.config.privacy.resource, value_hash=resource_hash),
            resource_hash=resource_hash,
            payload_hash=sha256_jcs(payload),
            risk_class=evaluation.risk_class,
            policy_evaluation=evaluation,
        )


def extract_resource(arguments: Mapping[str, Any]) -> str | None:
    """Return a compact best-effort resource label from MCP tool arguments."""

    if not arguments:
        return None
    owner = arguments.get("owner")
    repo = arguments.get("repo") or arguments.get("repository")
    if isinstance(owner, str) and isinstance(repo, str) and owner and repo:
        return f"github:{owner}/{repo}"
    for key in _RESOURCE_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return f"{key}:{value}"
        if isinstance(value, int) and not isinstance(value, bool):
            return f"{key}:{value}"
    return None


def infer_risk_class(
    action: str,
    *,
    tool: str,
    resource: str | None = None,
    arguments: Mapping[str, Any] | None = None,
) -> RiskClass:
    """Best-effort local risk inference before policy rules are applied."""

    git_risk = _GIT_TOOL_RISK_CLASSES.get(tool)
    if git_risk is not None:
        return git_risk

    text_parts = [action, tool, resource or ""]
    if arguments:
        environment = arguments.get("environment") or arguments.get("env")
        if isinstance(environment, str):
            text_parts.append(environment)
    text = " ".join(text_parts).lower()
    tokens = tuple(item for item in re.split(r"[^a-z0-9]+", text) if item)
    # Keep compound-keyword inference aligned with policy._RISK_RANK.
    if _has_prefix(tokens, _DESTRUCTIVE_PREFIXES):
        return RiskClass.DESTRUCTIVE
    if _has_prefix(tokens, _FINANCIAL_WORDS):
        return RiskClass.FINANCIAL
    if _has_prefix(tokens, _PRODUCTION_WORDS):
        return RiskClass.PRODUCTION
    if _has_prefix(tokens, _WRITE_PREFIXES):
        return RiskClass.WRITE
    if _has_prefix(tokens, _READ_PREFIXES):
        return RiskClass.READ
    return RiskClass.UNKNOWN


def _has_prefix(tokens: tuple[str, ...], prefixes: tuple[str, ...]) -> bool:
    return any(token == prefix or token.startswith(f"{prefix}_") for token in tokens for prefix in prefixes)


def _privacy_value(value: str | None, mode: str, *, value_hash: str | None) -> str | None:
    if value is None:
        return None
    if mode == "plain":
        return value
    if mode == "hash":
        return value_hash
    return REDACTED


def _json_compatible(value: Any) -> Any:
    """Normalize arbitrary MCP args into JSON-compatible data before JCS hashing."""

    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError):
        return _normalize_json(value)


def _normalize_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item) for item in value]
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    return repr(value)


__all__ = [
    "ClassifiedToolCall",
    "HASH_PREFIX",
    "REDACTED",
    "ToolCallClassifier",
    "extract_resource",
    "infer_risk_class",
    "sha256_jcs",
    "sha256_text",
]
