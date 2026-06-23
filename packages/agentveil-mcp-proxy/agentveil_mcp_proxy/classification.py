"""Tool-call classification and privacy hashing for MCP Proxy v0.1.

P4 builds local metadata for later Runtime Gate and evidence slices. It does
not call AVP, block downstream calls, or upload raw MCP arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

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
    "paths",
    "source",
    "destination",
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
    "move",
    "copy",
    "chmod",
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
    "git_clean": RiskClass.DESTRUCTIVE,
    "git_rebase": RiskClass.DESTRUCTIVE,
    # claim-check: allow internal risk enum label, verified by git pack policy/classification tests.
    "git_push": RiskClass.PRODUCTION,
    "instruction_surface_status": RiskClass.READ,
}

# Python package-manager MCP tool surface. Ecosystem scope: pip only.
# GitHub MCP-style tool catalog for routed GitHub pack behavior. Tool names
# follow common GitHub MCP server conventions; risk classes align with the
# github-read / github-write / github-destructive / github-secrets-block pack.
_GITHUB_TOOL_RISK_CLASSES: Mapping[str, RiskClass] = {
    "get_repository": RiskClass.READ,
    "list_issues": RiskClass.READ,
    "get_issue": RiskClass.READ,
    "list_pull_requests": RiskClass.READ,
    "get_pull_request": RiskClass.READ,
    "list_comments": RiskClass.READ,
    "list_branches": RiskClass.READ,
    "list_files": RiskClass.READ,
    "list_secret_names": RiskClass.READ,
    "get_repository_settings": RiskClass.READ,
    "list_workflow_runs": RiskClass.READ,
    "list_workflows": RiskClass.READ,
    "get_workflow": RiskClass.READ,
    "list_ci_jobs": RiskClass.READ,
    "get_ci_job": RiskClass.READ,
    "get_package_metadata": RiskClass.READ,
    "untrusted_context_status": RiskClass.READ,
    "github_target_snapshot": RiskClass.READ,
    "ci_repo_target_snapshot": RiskClass.READ,
    "create_comment": RiskClass.WRITE,
    "create_issue": RiskClass.WRITE,
    "update_issue": RiskClass.WRITE,
    "add_labels": RiskClass.WRITE,
    "remove_labels": RiskClass.WRITE,
    "request_review": RiskClass.WRITE,
    # claim-check: allow "PRODUCTION" is a risk-class enum for GitHub mutation policy, not a release-readiness claim.
    "merge_pull_request": RiskClass.PRODUCTION,
    "close_issue": RiskClass.DESTRUCTIVE,
    "delete_branch": RiskClass.DESTRUCTIVE,
    "create_release": RiskClass.PRODUCTION,  # claim-check: allow "PRODUCTION" is a risk-class enum for GitHub mutation policy, not a release-readiness claim.
    "update_repository_settings": RiskClass.PRODUCTION,  # claim-check: allow "PRODUCTION" is a risk-class enum for GitHub mutation policy, not a release-readiness claim.
    "manage_secret": RiskClass.DESTRUCTIVE,
    "rerun_workflow": RiskClass.PRODUCTION,  # claim-check: allow "PRODUCTION" is a risk-class enum for GitHub mutation policy, not a release-readiness claim.
    "cancel_workflow": RiskClass.DESTRUCTIVE,
    "dispatch_workflow": RiskClass.PRODUCTION,  # claim-check: allow "PRODUCTION" is a risk-class enum for GitHub mutation policy, not a release-readiness claim.
    "publish_package": RiskClass.PRODUCTION,  # claim-check: allow "PRODUCTION" is a risk-class enum for GitHub mutation policy, not a release-readiness claim.
    "deploy_release": RiskClass.PRODUCTION,  # claim-check: allow "PRODUCTION" is a risk-class enum for GitHub mutation policy, not a release-readiness claim.
    "run_remote_command": RiskClass.DESTRUCTIVE,
    "get_secret": RiskClass.DESTRUCTIVE,
    "get_env_secret": RiskClass.DESTRUCTIVE,
}

_PACKAGE_TOOL_RISK_CLASSES: Mapping[str, RiskClass] = {
    "package_list_manifest": RiskClass.READ,
    "package_inspect_state": RiskClass.READ,
    "package_risk_status": RiskClass.READ,
    "pip_install": RiskClass.WRITE,
    "pip_uninstall": RiskClass.WRITE,
    "pip_update": RiskClass.WRITE,
    "pip_run_script": RiskClass.DESTRUCTIVE,
}

# Fetch/network MCP tools (e.g. the official MCP "fetch" server's `fetch` tool)
# take a URL argument. The tool name `fetch` matches the generic _READ prefix,
# so a benign public fetch already infers READ. The risk that this prefix misses
# is the *destination*: a URL pointing at cloud instance metadata or the
# link-local range is a server-side request forgery (SSRF) / credential-
# exfiltration surface and must not classify like a benign public read. Tool
# family verified against
# https://github.com/modelcontextprotocol/servers/tree/main/src/fetch (Bug 2).
_FETCH_TOOL_PREFIXES = ("fetch",)
_URL_ARGUMENT_KEYS = ("url", "uri")
# Hostnames that resolve to a cloud instance metadata service. Link-local IPs
# (169.254.0.0/16, which includes the 169.254.169.254 metadata endpoint used by
# AWS / GCP / Azure / DigitalOcean) are detected by range in _is_ssrf_network_host.
_METADATA_HOSTNAMES = frozenset({"metadata.google.internal", "metadata"})


def _is_fetch_tool(tool: str) -> bool:
    name = tool.lower()
    return any(
        name == prefix or name.startswith(f"{prefix}_") or name.startswith(f"{prefix}-")
        for prefix in _FETCH_TOOL_PREFIXES
    )


def _url_host(arguments: Mapping[str, Any]) -> str | None:
    """Return the lowercase host of the first URL-like argument, or None."""

    for key in _URL_ARGUMENT_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            host = urlsplit(value.strip()).hostname
            if host:
                return host.lower()
    return None


def _is_ssrf_network_host(host: str) -> bool:
    """Return True for cloud-metadata hostnames or link-local IP literals."""

    if host in _METADATA_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Link-local covers 169.254.0.0/16 (incl. 169.254.169.254) and fe80::/10.
    return ip.is_link_local


def _network_fetch_risk(tool: str, arguments: Mapping[str, Any] | None) -> RiskClass | None:
    """Elevate fetch/network tools that target SSRF-sensitive hosts.

    A fetch whose URL points at cloud instance metadata or the link-local range
    is mapped to the existing PRODUCTION risk vocabulary so local policy can
    route it before approval, instead of letting it classify as a public read.
    Evidence: tests/test_mcp_proxy_classification.py covers this mapping.
    PRODUCTION is reused (not a new risk class); the `fetch` builtin policy
    pack maps this to a local block decision. Returns None for non-fetch tools
    and for fetches to ordinary public hosts (which keep their normal read
    classification).
    """

    if not arguments or not _is_fetch_tool(tool):
        return None
    host = _url_host(arguments)
    if host is not None and _is_ssrf_network_host(host):
        # claim-check: allow "PRODUCTION" is the existing RiskClass enum value
        # used by tests to carry the network-target signal into policy.
        return RiskClass.PRODUCTION  # claim-check: allow "PRODUCTION" is the existing RiskClass enum value.
    return None


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
    action_family: str
    role: str | None = None
    authority: str | None = None

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
            "action_family": self.action_family,
            "role": self.role,
            "authority": self.authority,
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
        action_family = infer_action_family(tool)
        role_authority = self.config.role_authority
        context = ToolCallContext(
            server=self.server_name,
            tool=tool,
            action=action_plain,
            risk_class=heuristic_risk,
            role=role_authority.role if role_authority.is_enforced() else None,
            authority=role_authority.authority if role_authority.is_enforced() else None,
            action_family=action_family,
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
            action_family=action_family,
            role=context.role,
            authority=context.authority,
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
        if key == "paths" and isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item:
                    return f"paths:{item}"
        if isinstance(value, int) and not isinstance(value, bool):
            return f"{key}:{value}"
    return None


def infer_action_family(tool: str) -> str:
    # claim-check: allow "privacy-safe" describes a coarse label helper, not full data safety.
    """Return a coarse, privacy-safe action family label for one MCP tool name."""

    if not tool:
        return "unknown"
    if "." in tool:
        return tool.rsplit(".", 1)[0]
    lowered = tool.lower()
    for prefix in (
        "get_",
        "list_",
        "read_",
        "search_",
        "fetch_",
        "create_",
        "update_",
        "write_",
        "delete_",
        "remove_",
        "shell",
        "exec",
    ):
        if lowered == prefix.rstrip("_") or lowered.startswith(prefix):
            return prefix.rstrip("_")
    return "unknown"


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

    github_risk = _GITHUB_TOOL_RISK_CLASSES.get(tool)
    if github_risk is not None:
        return github_risk

    package_risk = _PACKAGE_TOOL_RISK_CLASSES.get(tool)
    if package_risk is not None:
        return package_risk

    network_risk = _network_fetch_risk(tool, arguments)
    if network_risk is not None:
        return network_risk

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
    "infer_action_family",
    "infer_risk_class",
    "sha256_jcs",
    "sha256_text",
]
