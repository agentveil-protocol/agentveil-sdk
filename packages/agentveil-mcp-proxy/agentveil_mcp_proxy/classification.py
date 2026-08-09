# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

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
import posixpath
import re
import shlex
from typing import Any, Mapping
from urllib.parse import urlsplit

import jcs

from agentveil.exceptions import AVPValidationError
from agentveil.runtime_install_clone import (
    EVIDENCE_CHANNEL_FILE_METADATA,
    EVIDENCE_CHANNEL_MCP_SCHEMA,
    EVIDENCE_CHANNEL_README,
    EVIDENCE_CHANNEL_TOOL_OUTPUT,
    validate_metadata_evidence_slot,
)
from agentveil_mcp_proxy.metadata_evidence_collectors import (
    collect_install_metadata_evidence,
)
from agentveil_mcp_proxy.policy import (
    PolicyEngine,
    PolicyEvaluation,
    ProxyConfig,
    RiskClass,
    ToolCallContext,
)
from agentveil_mcp_proxy.content_risk_signals import derive_content_risk_signals


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
_FILESYSTEM_READ_TOOL_RISK_CLASSES: Mapping[str, RiskClass] = {
    "list_workspace": RiskClass.READ,
    "read_file": RiskClass.READ,
    "get_file_info": RiskClass.READ,
    "instruction_surface_status": RiskClass.READ,
    "local_proof": RiskClass.READ,
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

# Package install/clone-relevant tools that may attach bounded Runtime Gate
# advisory context. Read-only package status tools are intentionally excluded.
_PACKAGE_INSTALL_CLONE_CONTEXT_TOOLS = frozenset({
    "pip_install",
    "pip_uninstall",
    "pip_update",
    "pip_run_script",
})
INSTALL_CLONE_SOURCE_REF = "src_package_route_builtin"
INSTALL_CLONE_PACKAGE_REF = "pkg_package_route_builtin"
INSTALL_CLONE_MCP_SCHEMA_EVIDENCE_REF = "ev_mcp_schema_package_route"

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
    metadata_evidence: Mapping[str, Any] | None = None
    content_risk_signals: Mapping[str, bool] | None = None

    def backend_metadata(self) -> dict[str, Any]:
        """Return privacy-filtered metadata intended for later backend calls."""

        metadata = {
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
        install_clone_context = build_install_clone_context(
            self.tool,
            metadata_evidence=self.metadata_evidence,
        )
        if install_clone_context is not None:
            metadata["install_clone_context"] = install_clone_context
        if self.content_risk_signals is not None:
            metadata["content_risk_signals"] = dict(self.content_risk_signals)
        return metadata

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
        metadata_evidence = None
        if tool in _PACKAGE_INSTALL_CLONE_CONTEXT_TOOLS:
            collected = collect_install_metadata_evidence(tool=tool, arguments=args)
            metadata_evidence = collected or None
        content_risk_signals = derive_content_risk_signals(args)
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
            metadata_evidence=metadata_evidence,
            content_risk_signals=content_risk_signals,
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


def build_install_clone_context(
    tool: str,
    *,
    metadata_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return bounded install/clone advisory context for package mutation tools.

    Returns ``None`` for non-package tools. Includes only stable bounded refs
    and optional private-schema evidence slots (``readme``, ``tool_output``,
    ``mcp_schema``, ``file_metadata``), without raw package names, paths, URLs,
    prompts, source, or secrets.

    When ``metadata_evidence`` is omitted, collectors may still supply slots from
    tool arguments during classification. If no collector evidence is available,
    the package-route sensor emits a bounded ``mcp_schema`` slot
    (``tool_declares_install``). Unsafe channel payloads are dropped without
    echoing raw input.
    """

    if tool not in _PACKAGE_INSTALL_CLONE_CONTEXT_TOOLS:
        return None

    context: dict[str, Any] = {
        "operation": "install",
        "source_ref": INSTALL_CLONE_SOURCE_REF,
        "source_ref_kind": "workspace_registry",
        "user_pinned_source": False,
        "intent_source": "user_direct",
        "target_source": "workspace_registry",
        "tool_source": "approved_registry",
        "metadata_influence": "none",
        "requested_package": INSTALL_CLONE_PACKAGE_REF,
        "expected_package": INSTALL_CLONE_PACKAGE_REF,
    }

    slots: dict[str, Any] = {
        EVIDENCE_CHANNEL_MCP_SCHEMA: {
            "signal_code": "tool_declares_install",
            "evidence_ref": INSTALL_CLONE_MCP_SCHEMA_EVIDENCE_REF,
        },
    }
    if metadata_evidence is not None:
        if not isinstance(metadata_evidence, Mapping):
            metadata_evidence = {}
        for channel in (
            EVIDENCE_CHANNEL_README,
            EVIDENCE_CHANNEL_TOOL_OUTPUT,
            EVIDENCE_CHANNEL_MCP_SCHEMA,
            EVIDENCE_CHANNEL_FILE_METADATA,
        ):
            if channel in metadata_evidence and metadata_evidence[channel] is not None:
                slots[channel] = metadata_evidence[channel]

    for channel, payload in slots.items():
        try:
            bounded_slot = validate_metadata_evidence_slot(channel, payload)
        except AVPValidationError:
            continue
        if bounded_slot is not None:
            context[channel] = bounded_slot
    return context


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

    filesystem_read_risk = _FILESYSTEM_READ_TOOL_RISK_CLASSES.get(tool)
    if filesystem_read_risk is not None:
        return filesystem_read_risk

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


# Native shell classification for client hooks (Claude, Codex, Cursor, Gemini).
# Default-deny with bounded allowlists for project-local developer workflows.
_SHELL_DESTRUCTIVE_TOKENS: tuple[str, ...] = (
    "rm ",
    "rmdir ",
    "unlink ",
    "shred ",
    "wipe ",
    " -delete",  # `find ... -delete`
)

_SHELL_MUTATION_TOKENS: tuple[str, ...] = (
    " > ",
    " >> ",
    " >|",
    " tee ",
    "mv ",
    "cp ",
    "mkdir ",
    "touch ",
    "chmod ",
    "chown ",
    " ln ",
    "curl -o",
    "wget -O",
    " dd ",
    " -exec",   # `find -exec`, `xargs -I {} -exec`
    " -i ",     # `sed -i`, `perl -i`
    " -pi",     # `perl -pi`
)

_SHELL_READONLY_FIRST_TOKEN: frozenset[str] = frozenset({
    "pwd",
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "rg",
    "find",
    "wc",
    "which",
    "whoami",
    "date",
    "echo",
    "true",
    "false",
    "pytest",
    "ruff",
})

_GIT_READ_SUBCOMMANDS: frozenset[str] = frozenset({
    "status",
    "diff",
    "log",
    "show",
    "rev-parse",
    "branch",
})

_GIT_LOCAL_DEV_SUBCOMMANDS: frozenset[str] = frozenset({
    "add",
    "commit",
    "switch",
    "checkout",
})

_GIT_REMOTE_OR_RELEASE_SUBCOMMANDS: frozenset[str] = frozenset({
    "push",
    "pull",
    "fetch",
    "tag",
    "release",
    "publish",
    "deploy",
})

_SHELL_COMPOSITION_PATTERNS: tuple[str, ...] = (
    "$(",   # command substitution
    "`",    # backtick command substitution
    "|",    # pipe (also covers ||)
    ";",    # command separator
    "&",    # background and && chaining
    ">",    # any output redirect (>, >>, >|, >( )
    "<(",   # process substitution (executes the inner command)
    "\n",   # embedded newline => multiple commands
    "\r",
)

_SHELL_COMPOSITION_TOKENS: frozenset[str] = frozenset({
    "$",
    "|",
    "||",
    ";",
    "&",
    "&&",
    "<",
    "<(",
    "<<",
    "<>",
})

_SHELL_OUTPUT_REDIRECT_TOKENS: frozenset[str] = frozenset({
    ">",
    ">>",
    ">|",
})

_SECRET_PATH_FILENAMES: frozenset[str] = frozenset({
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credential",
})

_GENERIC_SECRET_PATH_FILENAMES: frozenset[str] = frozenset({
    "secret",
    "secrets",
    "token",
    "tokens",
})

_SECRET_PATH_SEGMENTS: frozenset[str] = frozenset({".ssh", ".aws", ".gnupg"})
_GENERIC_SECRET_PATH_SEGMENTS: frozenset[str] = frozenset({
    "secret",
    "secrets",
    "token",
    "tokens",
})
_SECRET_PATH_PREFIXES: tuple[str, ...] = (
    ".env.",
    "credentials.",
    "credential.",
    "secret.",
    "secrets.",
    "token.",
    "tokens.",
)
_SECRET_PATH_SUFFIXES: tuple[str, ...] = (".env", ".pem", ".key")

_PACKAGE_MANAGERS: frozenset[str] = frozenset({
    "bun",
    "cargo",
    "composer",
    "gem",
    "go",
    "npm",
    "pip",
    "pip3",
    "pnpm",
    "poetry",
    "uv",
    "yarn",
    "brew",
})

_PACKAGE_MUTATION_VERBS: frozenset[str] = frozenset({
    "add",
    "ci",
    "get",
    "install",
    "remove",
    "require",
    "sync",
    "uninstall",
    "update",
    "upgrade",
})

_SHELL_PROFILE_BASENAMES: frozenset[str] = frozenset({
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zprofile",
    ".zshrc",
})


def _has_shell_composition(command: str) -> bool:
    """Return True if the command contains shell composition metacharacters."""

    return any(pattern in command for pattern in _SHELL_COMPOSITION_PATTERNS)


def _split_shell_tokens(command: str) -> list[str] | None:
    """Split a simple shell command while preserving quoted message operands."""

    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return None


def _classify_shell_composition_tokens(tokens: list[str]) -> RiskClass | None:
    """Classify unquoted shell operators without inspecting quoted strings."""

    if any(token in _SHELL_OUTPUT_REDIRECT_TOKENS for token in tokens):
        return RiskClass.WRITE
    if any(
        token in _SHELL_COMPOSITION_TOKENS or "`" in token
        for token in tokens
    ):
        return RiskClass.UNKNOWN
    return None


def _path_token_is_secret(path_token: str) -> bool:
    """Return True when a shell path token targets a secret or credential file."""

    normalized = path_token.strip("'\"`").replace("\\", "/")
    if not normalized:
        return False
    path_like = (
        "/" in normalized
        or normalized.startswith(".")
        or normalized.startswith("~")
    )
    resolved = posixpath.normpath(normalized)
    segments = [
        segment.lower()
        for segment in resolved.split("/")
        if segment and segment != "."
    ]
    if not segments:
        return False
    if any(segment in _SECRET_PATH_SEGMENTS for segment in segments):
        return True
    if any(segment in _GENERIC_SECRET_PATH_SEGMENTS for segment in segments):
        if path_like and (len(segments) > 1 or normalized.startswith((".", "~", "/"))):
            return True
    basename = segments[-1]
    if basename in _SECRET_PATH_FILENAMES:
        return True
    if basename in _GENERIC_SECRET_PATH_FILENAMES:
        return path_like
    if basename in _SHELL_PROFILE_BASENAMES:
        return True
    if basename.startswith(_SECRET_PATH_PREFIXES) or basename.endswith(_SECRET_PATH_SUFFIXES):
        return True
    return False


def _shell_tokens_reference_secret_or_system_path(tokens: list[str]) -> bool:
    # claim-check: allow bounded hook classifier secret/system path deny boundary.
    """Return True when command path operands target blocked secret/system paths."""

    for token in tokens:
        lowered = token.lower()
        if lowered == "/etc" or lowered.startswith("/etc/"):
            return True
        if _path_token_is_secret(token):
            return True
    return False


def _shell_command_references_secret_or_system_path(command: str) -> bool:
    # claim-check: allow "blocked" describes tested classifier boundary, not universal safety.
    """Return True when a simple shell command references blocked paths."""

    tokens = _split_shell_tokens(command)
    if tokens is None:
        return False
    return _shell_tokens_reference_secret_or_system_path(tokens)


def _is_package_manager_mutation(tokens: list[str]) -> bool:
    if not tokens:
        return False
    first = tokens[0]
    if first not in _PACKAGE_MANAGERS:
        return False
    if len(tokens) == 1:
        return True
    return tokens[1] in _PACKAGE_MUTATION_VERBS


def _is_env_assignment(token: str) -> bool:
    """Return True for a simple ``KEY=VALUE`` shell env prefix token."""

    if "=" not in token:
        return False
    key, _value = token.split("=", 1)
    if not key or not key[0].isalpha():
        return False
    return all(ch.isalnum() or ch == "_" for ch in key)  # claim-check: allow bounded KEY token grammar, not coverage.


def _strip_leading_env_assignments(tokens: list[str]) -> list[str]:
    """Drop leading env assignments so ``PYTHONPATH=x pytest ...`` can classify."""

    idx = 0
    while idx < len(tokens) and _is_env_assignment(tokens[idx]):
        idx += 1
    return tokens[idx:]


_SECRET_ENV_KEY_EXACT: frozenset[str] = frozenset({
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
})


def _env_key_is_secret_like(key: str) -> bool:
    """Return True when an env assignment key carries credential semantics."""

    upper = key.upper()
    if upper in _SECRET_ENV_KEY_EXACT:
        return True
    if upper.endswith("_TOKEN") or upper.endswith("_SECRET") or upper.endswith("_PASSWORD"):
        return True
    if upper.endswith("_API_KEY") or upper.endswith("_APIKEY"):
        return True
    return False


def _leading_env_assignments_are_secret(tokens: list[str]) -> bool:
    """Return True when a leading env prefix sets a secret-like variable."""

    for token in tokens:
        if not _is_env_assignment(token):
            break
        key = token.split("=", 1)[0]
        if _env_key_is_secret_like(key):
            return True
    return False


def _classify_ruff_command(tokens: list[str]) -> RiskClass | None:
    """Classify ``ruff`` invocations; plain check is read, fix/format mutate."""

    if not tokens or tokens[0] != "ruff":
        return None
    if len(tokens) >= 2 and tokens[1] == "format":
        return RiskClass.WRITE
    if len(tokens) >= 2 and tokens[1] == "check":
        if any(flag in tokens for flag in ("--fix", "--fix-only", "--fixable")):
            return RiskClass.WRITE
        return RiskClass.READ
    return RiskClass.UNKNOWN


def _classify_python_module_invocation(tokens: list[str]) -> RiskClass | None:
    """Classify bounded ``python -m ...`` verification forms."""

    if len(tokens) < 3 or tokens[0] not in {"python", "python3"} or tokens[1] != "-m":
        return None
    module = tokens[2]
    if module == "pytest":
        return RiskClass.READ
    if module in {"pip", "pip3"}:
        return RiskClass.WRITE
    return RiskClass.UNKNOWN


def _classify_alembic_command(tokens: list[str]) -> RiskClass | None:
    """Classify ``alembic`` invocations; read-only heads only."""

    if not tokens or tokens[0] != "alembic":
        return None
    if len(tokens) >= 2 and tokens[1] == "heads":
        return RiskClass.READ
    if len(tokens) >= 2 and tokens[1] in {"upgrade", "downgrade", "stamp", "revision"}:
        return RiskClass.WRITE
    return RiskClass.UNKNOWN


def _classify_native_shell_mutation(tokens: list[str]) -> RiskClass | None:
    """Classify native command names/flags that mutate or delete local state."""

    if not tokens:
        return None
    command = tokens[0].lower()
    lower_tokens = [token.lower() for token in tokens]
    if command in {"rm", "rmdir", "unlink", "shred", "wipe"}:
        return RiskClass.DESTRUCTIVE
    if command in {"mv", "cp", "mkdir", "touch", "chmod", "chown", "ln", "dd"}:
        return RiskClass.WRITE
    if command == "find":
        if "-delete" in lower_tokens:
            return RiskClass.DESTRUCTIVE
        if "-exec" in lower_tokens:
            return RiskClass.WRITE
    if command in {"sed", "perl"}:
        if any(token == "-i" or token.startswith("-i") or token.startswith("-pi") for token in lower_tokens):
            return RiskClass.WRITE
    if command == "curl" and any(token in {"-o", "--output"} for token in lower_tokens):
        return RiskClass.WRITE
    if command == "wget" and any(token in {"-o", "-O".lower()} for token in lower_tokens):
        return RiskClass.WRITE
    return None


def _git_checkout_is_path_restore(raw_tokens: list[str]) -> bool:
    """Return True for ``git checkout [--tree-ish] -- <path>`` file restore forms."""

    if len(raw_tokens) < 2 or raw_tokens[1].lower() != "checkout":
        return False
    return "--" in raw_tokens[2:]


def _git_pathspec_is_explicit(pathspec: str) -> bool:
    """Return True when a git pathspec names explicit paths, not magic/broad forms."""

    if pathspec.startswith(":"):
        return False
    return pathspec not in {".", ".."} and bool(pathspec)


def _git_add_is_broad(raw_tokens: list[str]) -> bool:
    """Return True for broad git add pathspec or staging forms."""

    args = raw_tokens[2:]
    if not args:
        return False
    lower_args = [arg.lower() for arg in args]
    if "." in lower_args:
        return True
    broad_flags = {"-a", "-A", "--all", "-u", "--update", "--intent-to-add"}  # claim-check: allow literal git flag name.
    if any(arg in broad_flags for arg in lower_args):
        return True
    for arg in args:
        lower = arg.lower()
        if lower.startswith("--pathspec-from-file") or lower == "--pathspec-file-nul":
            return True
        if lower in {":/", "::"} or lower.startswith(":/"):
            return True
    return False


def _git_add_has_explicit_paths_only(raw_tokens: list[str]) -> bool:
    args = raw_tokens[2:]
    if not args:
        return False
    if "--" in args:
        path_args = args[args.index("--") + 1:]
        return bool(path_args) and all(  # claim-check: allow bounded pathspec predicate, not coverage.
            _git_pathspec_is_explicit(path) for path in path_args
        )
    path_args = [arg for arg in args if not arg.startswith("-")]
    return bool(path_args) and all(  # claim-check: allow bounded pathspec predicate, not coverage.
        _git_pathspec_is_explicit(path) for path in path_args
    )


def _git_commit_is_unsafe(raw_tokens: list[str]) -> bool:
    """Return True for broad staging, amend, interactive, or patch commit forms."""

    args = raw_tokens[2:]
    lower_args = [arg.lower() for arg in args]
    if any(
        flag in lower_args
        for flag in ("--all", "--amend", "--interactive", "--patch")  # claim-check: allow literal git flag names.
    ):
        return True
    for arg in args:
        lower = arg.lower()
        if lower in {"-a", "-p", "-i"}:
            return True
        if arg.startswith("-") and not arg.startswith("--"):
            flags = arg[1:]
            if any(ch in flags for ch in ("a", "p", "i")):
                return True
    return False


def _git_switch_is_unsafe(raw_tokens: list[str]) -> bool:
    """Return True for ``git switch`` forms that discard, merge, or reset branch refs."""

    if len(raw_tokens) < 2 or raw_tokens[1].lower() != "switch":
        return False
    lower_args = [arg.lower() for arg in raw_tokens[2:]]
    if any(flag in lower_args for flag in ("--discard-changes", "--merge")):
        return True
    for arg in raw_tokens[2:]:
        if arg == "-C":
            return True
        if arg.startswith("-") and not arg.startswith("--") and "C" in arg[1:]:
            return True
    return False


def _git_checkout_is_unsafe(raw_tokens: list[str]) -> bool:
    """Return True for ``git checkout -B`` or interactive patch checkout forms."""

    if len(raw_tokens) < 2 or raw_tokens[1].lower() != "checkout":
        return False
    lower_args = [arg.lower() for arg in raw_tokens[2:]]
    if any(flag in lower_args for flag in ("--patch",)):
        return True
    for arg in raw_tokens[2:]:
        if arg == "-B":
            return True
        if arg.startswith("-") and not arg.startswith("--") and "B" in arg[1:]:
            return True
        if arg.startswith("-") and not arg.startswith("--") and "p" in arg[1:]:
            return True
    return False


def _classify_git_command(raw_tokens: list[str]) -> RiskClass:
    """Classify a tokenized ``git ...`` command (case preserved for short flags)."""

    if len(raw_tokens) < 2:
        return RiskClass.UNKNOWN
    subcommand = raw_tokens[1].lower()
    lower_args = [arg.lower() for arg in raw_tokens[2:]]

    if subcommand in _GIT_REMOTE_OR_RELEASE_SUBCOMMANDS:
        return RiskClass.PRODUCTION  # claim-check: allow enum value asserted by classifier tests.

    if subcommand == "reset":
        if any(flag in lower_args for flag in ("--hard", "-f", "--force")):
            return RiskClass.DESTRUCTIVE
        return RiskClass.WRITE

    if subcommand == "clean":
        clean_args = "".join(lower_args)
        if any(
            flag in lower_args or flag in clean_args
            for flag in ("-f", "--force", "-d", "-x", "-fd", "-ff")
        ):
            return RiskClass.DESTRUCTIVE
        return RiskClass.WRITE

    if subcommand == "rebase":
        if any(flag in lower_args for flag in ("--hard", "--force", "-f", "--onto")):
            return RiskClass.DESTRUCTIVE
        return RiskClass.UNKNOWN

    if subcommand == "add":
        if _git_add_is_broad(raw_tokens):
            return RiskClass.WRITE
        if _git_add_has_explicit_paths_only(raw_tokens):
            return RiskClass.READ
        return RiskClass.UNKNOWN

    if subcommand == "commit":
        if _git_commit_is_unsafe(raw_tokens):
            return RiskClass.WRITE
        return RiskClass.READ

    if subcommand == "branch":
        if any(flag in lower_args for flag in ("-d", "-m", "--move", "--delete")):
            return RiskClass.WRITE
        return RiskClass.READ

    if subcommand in ("switch", "checkout"):
        if subcommand == "checkout" and _git_checkout_is_path_restore(raw_tokens):
            return RiskClass.WRITE
        if subcommand == "switch" and _git_switch_is_unsafe(raw_tokens):
            return RiskClass.WRITE
        if subcommand == "checkout" and _git_checkout_is_unsafe(raw_tokens):
            return RiskClass.WRITE
        if any(flag in lower_args for flag in ("--force", "-f")):
            return RiskClass.DESTRUCTIVE
        if subcommand == "checkout" and len(raw_tokens) >= 3 and lower_args[0] in {".", "-"}:
            return RiskClass.UNKNOWN
        return RiskClass.READ

    if subcommand in _GIT_READ_SUBCOMMANDS:
        return RiskClass.READ

    if subcommand in _GIT_LOCAL_DEV_SUBCOMMANDS:
        return RiskClass.UNKNOWN

    return RiskClass.UNKNOWN


def classify_native_shell_command(command: str) -> RiskClass:
    """Classify a native shell command for hook policy evaluation.

    Unknown commands resolve through hook policy (``ASK_BACKEND`` -> deny).
    Project-local developer workflows (bounded git add/commit, read-only
    inspection, local branch switches) classify as ``READ`` so host-agent
    approval remains the operator gate without a duplicate Approval Center
    round-trip for ordinary local git.
    """

    stripped = command.strip()
    if not stripped:
        return RiskClass.UNKNOWN
    if "\n" in stripped or "\r" in stripped:
        return RiskClass.UNKNOWN

    raw_tokens = _split_shell_tokens(stripped)
    if raw_tokens is None:
        return RiskClass.UNKNOWN

    if _leading_env_assignments_are_secret(raw_tokens):
        return RiskClass.DESTRUCTIVE

    tokens = _strip_leading_env_assignments(raw_tokens)
    lower_tokens = [token.lower() for token in tokens]
    if not tokens:
        return RiskClass.UNKNOWN

    composition_risk = _classify_shell_composition_tokens(tokens)
    if composition_risk is not None:
        return composition_risk

    if _shell_tokens_reference_secret_or_system_path(tokens):
        return RiskClass.DESTRUCTIVE

    if _is_package_manager_mutation(lower_tokens):
        return RiskClass.WRITE

    ruff_risk = _classify_ruff_command(lower_tokens)
    if ruff_risk is not None:
        return ruff_risk

    python_module_risk = _classify_python_module_invocation(lower_tokens)
    if python_module_risk is not None:
        return python_module_risk

    alembic_risk = _classify_alembic_command(lower_tokens)
    if alembic_risk is not None:
        return alembic_risk

    if lower_tokens[0] == "git":
        return _classify_git_command(tokens)

    native_mutation_risk = _classify_native_shell_mutation(tokens)
    if native_mutation_risk is not None:
        return native_mutation_risk

    if lower_tokens[0] in _SHELL_READONLY_FIRST_TOKEN:
        return RiskClass.READ

    return RiskClass.UNKNOWN


__all__ = [
    "ClassifiedToolCall",
    "HASH_PREFIX",
    "INSTALL_CLONE_MCP_SCHEMA_EVIDENCE_REF",
    "INSTALL_CLONE_PACKAGE_REF",
    "INSTALL_CLONE_SOURCE_REF",
    "REDACTED",
    "ToolCallClassifier",
    "build_install_clone_context",
    "classify_native_shell_command",
    "extract_resource",
    "infer_action_family",
    "infer_risk_class",
    "sha256_jcs",
    "sha256_text",
]
