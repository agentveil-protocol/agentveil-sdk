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
})
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
