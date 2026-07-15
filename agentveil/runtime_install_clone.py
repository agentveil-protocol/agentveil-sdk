"""Bounded install/clone advisory context for Runtime Gate requests.

Public clients must not forward raw paths, URLs, prompts, package-manager
commands, or secrets in ``install_clone_context``. This module validates a
caller-supplied dict against the private-compatible bounded vocabulary before
any HTTP body is built.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from agentveil.exceptions import AVPValidationError

_SOURCE_REF_PATTERN = re.compile(r"^src_[a-z0-9_-]{1,58}$")
_NAMESPACE_REF_PATTERN = re.compile(r"^ns_[a-z0-9_-]{1,58}$")
_PACKAGE_REF_PATTERN = re.compile(r"^pkg_[a-z0-9_-]{1,58}$")
_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_REF_PATTERN = re.compile(r"^ev_[a-z0-9_-]{1,58}$")

_SOURCE_REF_KINDS = frozenset({
    "user_pinned",
    "workspace_registry",
    "internal_registry",
    "approved_namespace",
    "model_suggested",
    "metadata_suggested",
    "tool_output_suggested",
    "unknown",
})
_INTENT_SOURCES = frozenset({
    "user_direct",
    "user_pinned",
    "workspace_policy",
    "agent_plan",
    "metadata",
    "tool_output",
    "remote_context",
    "unknown",
})
_TARGET_SOURCES = frozenset({
    "user_pinned",
    "workspace_registry",
    "internal_registry",
    "tool_output",
    "metadata",
    "model_suggested",
    "remote_context",
    "unknown",
})
_TOOL_SOURCES = frozenset({
    "approved_registry",
    "workspace_registry",
    "local_manifest",
    "mcp_server_schema",
    "model_suggested",
    "unknown",
})
_METADATA_INFLUENCES = frozenset({
    "none",
    "low",
    "medium",
    "high",
    "unknown",
})

# Private InstallCloneAdvisoryContext evidence channel names (wire contract).
EVIDENCE_CHANNEL_README = "readme"
EVIDENCE_CHANNEL_TOOL_OUTPUT = "tool_output"
EVIDENCE_CHANNEL_MCP_SCHEMA = "mcp_schema"
EVIDENCE_CHANNEL_FILE_METADATA = "file_metadata"

EVIDENCE_CHANNELS = frozenset({
    EVIDENCE_CHANNEL_README,
    EVIDENCE_CHANNEL_TOOL_OUTPUT,
    EVIDENCE_CHANNEL_MCP_SCHEMA,
    EVIDENCE_CHANNEL_FILE_METADATA,
})

_ALLOWED_EVIDENCE_SLOT_KEYS = frozenset({
    "signal_code",
    "evidence_ref",
    "content_hash",
})

README_SIGNAL_CODES = frozenset({
    "no_signal",
    "install_hint",
    "clone_hint",
    "package_name_hint",
    "dependency_hint",
})
TOOL_OUTPUT_SIGNAL_CODES = frozenset({
    "no_signal",
    "install_command",
    "clone_command",
    "package_reference",
    "repo_reference",
})
MCP_SCHEMA_SIGNAL_CODES = frozenset({
    "no_signal",
    "tool_declares_install",
    "tool_declares_fetch",
    "resource_binding",
})
FILE_METADATA_SIGNAL_CODES = frozenset({
    "no_signal",
    "manifest_install_target",
    "lockfile_dependency",
    "config_package_ref",
})

_CHANNEL_SIGNAL_CODES = {
    EVIDENCE_CHANNEL_README: README_SIGNAL_CODES,
    EVIDENCE_CHANNEL_TOOL_OUTPUT: TOOL_OUTPUT_SIGNAL_CODES,
    EVIDENCE_CHANNEL_MCP_SCHEMA: MCP_SCHEMA_SIGNAL_CODES,
    EVIDENCE_CHANNEL_FILE_METADATA: FILE_METADATA_SIGNAL_CODES,
}

_REQUIRED_KEYS = frozenset({
    "operation",
    "source_ref",
    "source_ref_kind",
    "user_pinned_source",
    "intent_source",
    "target_source",
    "tool_source",
    "metadata_influence",
})
_OPTIONAL_KEYS = frozenset({
    "package_namespace",
    "requested_package",
    "expected_package",
    "expected_hash",
    "resource_hash",
    "payload_hash",
}) | EVIDENCE_CHANNELS
_ALLOWED_KEYS = _REQUIRED_KEYS | _OPTIONAL_KEYS

_FORBIDDEN_SUBSTRINGS = (
    "://",
    "/Users/",
    "/private/",
    "/var/folders/",
    "/home/",
    "\\Users\\",
    "X-Amz-",
    "sk_live_",
    "sk_test_",
    "ghp_",
    "-----BEGIN",
)


def validate_metadata_evidence_slot(
    channel: str,
    payload: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Return a bounded evidence slot copy or ``None`` when the channel is absent.

    Rejects unknown keys, channel-mismatched ``signal_code``, malformed refs/hashes,
    and forbidden raw markers. Does not echo rejected raw input in the error text.
    """

    if payload is None:
        return None
    if channel not in EVIDENCE_CHANNELS:
        raise AVPValidationError("install_clone_context evidence channel invalid")
    if not isinstance(payload, Mapping):
        raise AVPValidationError("install_clone_context evidence slot invalid")

    keys = set(payload)
    if keys - _ALLOWED_EVIDENCE_SLOT_KEYS:
        raise AVPValidationError("install_clone_context evidence slot has forbidden keys")
    if not keys:
        return None

    signal_code = payload.get("signal_code")
    evidence_ref = payload.get("evidence_ref")
    content_hash = payload.get("content_hash")
    if signal_code is None and evidence_ref is None and content_hash is None:
        return None
    if not isinstance(signal_code, str) or signal_code not in _CHANNEL_SIGNAL_CODES[channel]:
        raise AVPValidationError("install_clone_context evidence signal_code invalid")

    bounded: dict[str, Any] = {"signal_code": signal_code}
    if evidence_ref is not None:
        if not isinstance(evidence_ref, str) or not _EVIDENCE_REF_PATTERN.fullmatch(evidence_ref):
            raise AVPValidationError("install_clone_context evidence_ref invalid")
        bounded["evidence_ref"] = evidence_ref
    if content_hash is not None:
        if not isinstance(content_hash, str) or not _HASH_PATTERN.fullmatch(content_hash):
            raise AVPValidationError("install_clone_context content_hash invalid")
        bounded["content_hash"] = content_hash

    serialized = json.dumps(bounded, sort_keys=True)
    lowered = serialized.lower()
    for marker in _FORBIDDEN_SUBSTRINGS:
        if marker.lower() in lowered:
            raise AVPValidationError(
                "install_clone_context evidence contains forbidden raw marker"
            )
    return bounded


def validate_install_clone_context(context: Mapping[str, Any]) -> dict[str, Any]:
    """Return a bounded copy of ``install_clone_context`` or raise.

    Rejects unknown keys, invalid vocabulary, and values that look like raw
    paths, URLs, or secret markers. Returns a fresh bounded copy.
    """

    if not isinstance(context, Mapping):
        raise AVPValidationError("install_clone_context must be an object")

    keys = set(context)
    extra = keys - _ALLOWED_KEYS
    if extra:
        raise AVPValidationError(
            f"install_clone_context contains forbidden keys: {sorted(extra)}"
        )
    missing = _REQUIRED_KEYS - keys
    if missing:
        raise AVPValidationError(
            f"install_clone_context missing required keys: {sorted(missing)}"
        )

    operation = context["operation"]
    if operation not in {"install", "clone"}:
        raise AVPValidationError("install_clone_context.operation invalid")

    source_ref = _require_str(context["source_ref"], "source_ref")
    if not _SOURCE_REF_PATTERN.fullmatch(source_ref):
        raise AVPValidationError("install_clone_context.source_ref invalid")

    source_ref_kind = _require_str(context["source_ref_kind"], "source_ref_kind")
    if source_ref_kind not in _SOURCE_REF_KINDS:
        raise AVPValidationError("install_clone_context.source_ref_kind invalid")

    if not isinstance(context["user_pinned_source"], bool):
        raise AVPValidationError("install_clone_context.user_pinned_source must be bool")

    intent_source = _require_str(context["intent_source"], "intent_source")
    if intent_source not in _INTENT_SOURCES:
        raise AVPValidationError("install_clone_context.intent_source invalid")

    target_source = _require_str(context["target_source"], "target_source")
    if target_source not in _TARGET_SOURCES:
        raise AVPValidationError("install_clone_context.target_source invalid")

    tool_source = _require_str(context["tool_source"], "tool_source")
    if tool_source not in _TOOL_SOURCES:
        raise AVPValidationError("install_clone_context.tool_source invalid")

    metadata_influence = _require_str(context["metadata_influence"], "metadata_influence")
    if metadata_influence not in _METADATA_INFLUENCES:
        raise AVPValidationError("install_clone_context.metadata_influence invalid")

    bounded: dict[str, Any] = {
        "operation": operation,
        "source_ref": source_ref,
        "source_ref_kind": source_ref_kind,
        "user_pinned_source": context["user_pinned_source"],
        "intent_source": intent_source,
        "target_source": target_source,
        "tool_source": tool_source,
        "metadata_influence": metadata_influence,
    }

    for key in ("package_namespace", "requested_package", "expected_package"):
        if key not in context or context[key] is None:
            continue
        value = _require_str(context[key], key)
        pattern = _NAMESPACE_REF_PATTERN if key == "package_namespace" else _PACKAGE_REF_PATTERN
        if not pattern.fullmatch(value):
            raise AVPValidationError(f"install_clone_context.{key} invalid")
        bounded[key] = value

    for key in ("expected_hash", "resource_hash", "payload_hash"):
        if key not in context or context[key] is None:
            continue
        value = _require_str(context[key], key)
        if not _HASH_PATTERN.fullmatch(value):
            raise AVPValidationError(f"install_clone_context.{key} invalid")
        bounded[key] = value

    for channel in (
        EVIDENCE_CHANNEL_README,
        EVIDENCE_CHANNEL_TOOL_OUTPUT,
        EVIDENCE_CHANNEL_MCP_SCHEMA,
        EVIDENCE_CHANNEL_FILE_METADATA,
    ):
        if channel not in context or context[channel] is None:
            continue
        slot = validate_metadata_evidence_slot(channel, context[channel])
        if slot is not None:
            bounded[channel] = slot

    serialized = json.dumps(bounded, sort_keys=True)
    lowered = serialized.lower()
    for marker in _FORBIDDEN_SUBSTRINGS:
        if marker.lower() in lowered:
            raise AVPValidationError(
                "install_clone_context contains forbidden raw path/url/secret marker"
            )
    return bounded


def _require_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AVPValidationError(f"install_clone_context.{field} must be a string")
    text = value.strip()
    if not text or len(text) > 71:
        raise AVPValidationError(f"install_clone_context.{field} invalid")
    return text
