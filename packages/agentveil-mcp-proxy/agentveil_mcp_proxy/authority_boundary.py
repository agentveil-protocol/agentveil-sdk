"""Metadata-only authority boundary contract for MCP Proxy autonomy control.

Defines bounded authority records and privacy guards for local MCP Proxy runtime
metadata and evidence export.

Hosted Runtime Gate metadata targets a 30-day retention window, but automatic
hosted deletion is not live; callers must not claim automatic deletion.

Boundary: authority_status values including "blocked" are metadata enum labels only.
Negative test: packages/agentveil-mcp-proxy/tests/test_mcp_proxy_authority_boundary.py
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Literal

AuthorityStatus = Literal["allowed", "missing", "approved", "blocked"]  # claim-check: allow "blocked" as authority_status enum value.
AuthoritySource = Literal[
    "read_only",
    "approval_record",
    "policy_grant",
    "policy_block",
    "explicit_action_metadata",
    "untrusted_context",
    "none",
]

HASH_PREFIX = "sha256:"

# Bounded enum/id constants for authority metadata.
AUTHORITY_REASON_READ_ONLY = "read_only_access"
AUTHORITY_REASON_RISKY_MISSING = "risky_authority_missing"
AUTHORITY_REASON_APPROVAL_GRANTED = "approval_granted"
AUTHORITY_REASON_SECRET_BLOCKED = "secret_access_blocked"
AUTHORITY_REASON_UNTRUSTED_CONTEXT = "untrusted_context"
AUTHORITY_REASON_POLICY_BLOCK = "policy_block"
AUTHORITY_REASON_POLICY_GRANT = "policy_grant"

RISK_FAMILY_READ = "read"
RISK_FAMILY_WRITE = "write"
RISK_FAMILY_SECRET = "secret"
RISK_FAMILY_UNKNOWN = "unknown"

SAFE_FIRST_STEP_REQUEST_APPROVAL = "request_approval"
SAFE_FIRST_STEP_READ_ONLY_REVIEW = "read_only_review"
SAFE_FIRST_STEP_NO_ACTION = "no_action"

_READ_ACTION_FAMILIES = frozenset({
    "read",
    "fetch",
    "list",
    "search",
    "describe",
    "view",
    "show",
    "stat",
    "surface_audit",
})
_SECRET_POLICY_RULE_MARKERS = frozenset({"github-secrets-block"})
_SECRET_TOOL_EXACT = frozenset({"get_secret", "get_env_secret"})
_SECRET_TOOL_PREFIXES = ("get_secret", "read_secret")

_HOSTED_TOP_LEVEL_FIELDS = frozenset({
    "authority_status",
    "authority_source",
    "authority_reason_id",
    "risk_family",
    "safe_first_step_id",
    "approval_ref",
    "context_ref",
    "target_reached",
})
_HOSTED_APPROVAL_REF_FIELDS = frozenset({"approval_id", "approval_hash"})
_HOSTED_CONTEXT_REF_FIELDS = frozenset({
    "source_type",
    "source_basename",
    "context_hash",
    "line_count",
    "byte_count",
    "char_count",
    "token_count",
})
_FORBIDDEN_RECORD_KEYS = frozenset({
    "safe_first_step",
    "prompt",
    "chat",
    "tool_args",
    "raw_context",
    "stdout",
    "stderr",
    "file_contents",
    "package_script",
    "pr_body",
    "issue_body",
    "comment_body",
    "approval_text",
    "secret",
    "token",
    "password",
    "private_key",
})
_PRIVACY_FAIL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/tmp/\S+"), "/tmp path"),
    (re.compile(r"/Users/\S+"), "/Users path"),
    (re.compile(r"/private/\S+"), "/private path"),
    (re.compile(r"/var/folders/\S+"), "/var/folders path"),
    (re.compile(r"(?i)\bpassphrase\b"), "passphrase"),
    (re.compile(r"(?i)\bsecret_token\b"), "secret_token"),
    (re.compile(r"(?i)\bapi_key\b"), "api_key"),
    (re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), "private key"),
    (re.compile(r'"tool_args"\s*:'), "raw tool_args key"),
    (re.compile(r'"prompt"\s*:'), "raw prompt key"),
    (re.compile(r'"stdout"\s*:'), "raw stdout key"),
    (re.compile(r'"stderr"\s*:'), "raw stderr key"),
)


class AuthorityBoundaryError(ValueError):
    """Raised when authority metadata violates the bounded contract."""


def build_context_ref(
    *,
    source_type: str,
    source_basename: str,
    raw_context: str | bytes,
    line_count: int | None = None,
    byte_count: int | None = None,
    char_count: int | None = None,
    token_count: int | None = None,
) -> dict[str, Any]:
    """Hash raw context input and return bounded untrusted context metadata."""

    if not source_type:
        raise AuthorityBoundaryError("source_type is required")
    basename = _basename_only(source_basename)
    if not basename:
        raise AuthorityBoundaryError("source_basename is required")

    ref: dict[str, Any] = {
        "source_type": source_type,
        "source_basename": basename,
        "context_hash": _hash_value(raw_context),
    }
    for key, value in (
        ("line_count", line_count),
        ("byte_count", byte_count),
        ("char_count", char_count),
        ("token_count", token_count),
    ):
        if value is not None:
            if value < 0:
                raise AuthorityBoundaryError(f"{key} must be non-negative")
            ref[key] = value
    return ref


def build_approval_ref(
    *,
    approval_id: str,
    approval_hash: str | None = None,
) -> dict[str, str]:
    """Return approval metadata as id/hash only."""

    if not approval_id:
        raise AuthorityBoundaryError("approval_id is required")
    ref: dict[str, str] = {"approval_id": approval_id}
    if approval_hash is not None:
        ref["approval_hash"] = _normalize_hash(approval_hash)
    return ref


def build_authority_record(
    *,
    authority_status: AuthorityStatus,
    authority_source: AuthoritySource,
    authority_reason_id: str,
    risk_family: str,
    safe_first_step_id: str,
    target_reached: bool,
    approval_ref: Mapping[str, str] | None = None,
    context_ref: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a local authority record using enum/id fields only."""

    _require_non_empty("authority_reason_id", authority_reason_id)
    _require_non_empty("risk_family", risk_family)
    _require_non_empty("safe_first_step_id", safe_first_step_id)

    record: dict[str, Any] = {
        "authority_status": authority_status,
        "authority_source": authority_source,
        "authority_reason_id": authority_reason_id,
        "risk_family": risk_family,
        "safe_first_step_id": safe_first_step_id,
        "target_reached": target_reached,
    }
    if approval_ref is not None:
        record["approval_ref"] = build_approval_ref(
            approval_id=str(approval_ref["approval_id"]),
            approval_hash=approval_ref.get("approval_hash"),
        )
    if context_ref is not None:
        record["context_ref"] = _copy_bounded_context_ref(context_ref)
    reject_forbidden_record_fields(record)
    return record


def authority_record_to_hosted_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a local authority record to a hosted allowlisted payload."""

    reject_forbidden_record_fields(record)
    unknown = set(record) - _HOSTED_TOP_LEVEL_FIELDS
    if unknown:
        raise AuthorityBoundaryError(
            f"hosted payload rejects unknown fields: {sorted(unknown)}"
        )

    payload: dict[str, Any] = {}
    for key in _HOSTED_TOP_LEVEL_FIELDS:
        if key not in record:
            continue
        value = record[key]
        if key == "approval_ref":
            payload[key] = _hosted_approval_ref(value)
        elif key == "context_ref":
            payload[key] = _hosted_context_ref(value)
        else:
            payload[key] = value

    if "safe_first_step" in payload:
        raise AuthorityBoundaryError("hosted payload must not include safe_first_step")
    assert_authority_record_privacy_bounded(payload)
    return payload


def reject_forbidden_record_fields(record: Mapping[str, Any]) -> None:
    """Reject records that include free-text or raw sensitive fields."""

    forbidden = sorted(set(record) & _FORBIDDEN_RECORD_KEYS)
    if forbidden:
        raise AuthorityBoundaryError(
            f"forbidden authority record fields: {forbidden}"
        )
    if "safe_first_step" in record:
        raise AuthorityBoundaryError("safe_first_step text field is forbidden")


def privacy_markers_in_text(text: str) -> list[str]:
    """Return privacy violation labels found in serialized text."""

    findings: list[str] = []
    for pattern, label in _PRIVACY_FAIL_PATTERNS:
        if pattern.search(text or ""):
            findings.append(label)
    return findings


def assert_authority_record_privacy_bounded(record: Mapping[str, Any]) -> None:
    """Assert a record and its JSON serialization stay within privacy bounds."""

    reject_forbidden_record_fields(record)
    serialized = json.dumps(record, sort_keys=True)
    findings = privacy_markers_in_text(serialized)
    if findings:
        raise AuthorityBoundaryError(
            f"authority record privacy violation: {findings}"
        )
    _assert_nested_privacy(record)


def _hosted_approval_ref(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise AuthorityBoundaryError("approval_ref must be a mapping")
    unknown = set(value) - _HOSTED_APPROVAL_REF_FIELDS
    if unknown:
        raise AuthorityBoundaryError(
            f"approval_ref rejects unknown fields: {sorted(unknown)}"
        )
    return {key: str(value[key]) for key in sorted(value) if key in value}


def _hosted_context_ref(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorityBoundaryError("context_ref must be a mapping")
    unknown = set(value) - _HOSTED_CONTEXT_REF_FIELDS
    if unknown:
        raise AuthorityBoundaryError(
            f"context_ref rejects unknown fields: {sorted(unknown)}"
        )
    return {key: value[key] for key in sorted(value) if key in value}


def _copy_bounded_context_ref(context_ref: Mapping[str, Any]) -> dict[str, Any]:
    required = ("source_type", "source_basename", "context_hash")
    missing = [key for key in required if key not in context_ref]
    if missing:
        raise AuthorityBoundaryError(
            f"context_ref missing required fields: {missing}"
        )
    return _hosted_context_ref(context_ref)


def _assert_nested_privacy(record: Mapping[str, Any]) -> None:
    for key, value in record.items():
        if isinstance(value, Mapping):
            reject_forbidden_record_fields(value)
            _assert_nested_privacy(value)
        elif isinstance(value, str):
            findings = privacy_markers_in_text(value)
            if findings:
                raise AuthorityBoundaryError(
                    f"authority field {key!r} privacy violation: {findings}"
                )


def _basename_only(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def _hash_value(raw: str | bytes) -> str:
    if isinstance(raw, str):
        payload = raw.encode("utf-8")
    else:
        payload = raw
    return HASH_PREFIX + hashlib.sha256(payload).hexdigest()


def _normalize_hash(value: str) -> str:
    digest = value.removeprefix(HASH_PREFIX)
    if len(digest) != 64 or not all(ch in "0123456789abcdef" for ch in digest.lower()):  # claim-check: allow "all" validates hash charset only.
        raise AuthorityBoundaryError("approval_hash must be a sha256 hex digest")
    return HASH_PREFIX + digest.lower()


def _require_non_empty(field: str, value: str) -> None:
    if not value:
        raise AuthorityBoundaryError(f"{field} is required")


def risk_family_for_runtime(
    *,
    action_family: str | None = None,
    risk_class: str | None = None,
    block_reason: str | None = None,
    policy_rule: str | None = None,
    tool: str | None = None,
) -> str:
    """Map runtime action/risk labels to bounded authority risk families."""

    if runtime_secret_block_context(
        metadata={},
        risk_class=risk_class,
        block_reason=block_reason,
        policy_rule=policy_rule,
        tool=tool,
    ):
        return RISK_FAMILY_SECRET
    if block_reason and "secret" in block_reason.lower():
        return RISK_FAMILY_SECRET
    if isinstance(risk_class, str):
        normalized = risk_class.lower()
        if normalized == "read":
            return RISK_FAMILY_READ
        if normalized in {"write", "destructive", "production", "financial"}:  # claim-check: allow "production" is existing RiskClass enum vocabulary.
            return RISK_FAMILY_WRITE
    if isinstance(action_family, str):
        normalized = action_family.lower()
        if normalized in _READ_ACTION_FAMILIES:
            return RISK_FAMILY_READ
        if normalized in {"write", "delete", "execute", "install"}:
            return RISK_FAMILY_WRITE
    return RISK_FAMILY_UNKNOWN


def context_ref_from_untrusted_metadata(
    metadata: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Build bounded context_ref from untrusted-surface metadata only."""

    if metadata.get("instruction_surface_present") is True:
        basenames = metadata.get("instruction_surface_basenames")
        basename = "instruction_surface"
        if isinstance(basenames, list) and basenames:
            first = basenames[0]
            if isinstance(first, str) and first:
                basename = first
        count = metadata.get("instruction_surface_count")
        if not isinstance(count, int):
            count = len(basenames) if isinstance(basenames, list) else 1
        fingerprint = json.dumps(
            {"kind": "instruction_surface", "basename": basename, "count": count},
            sort_keys=True,
        )
        return build_context_ref(
            source_type="instruction_surface",
            source_basename=basename,
            raw_context=fingerprint,
            line_count=count,
        )
    if metadata.get("untrusted_text_surface_present") is True:
        issue_number = metadata.get("issue_number")
        pull_number = metadata.get("pull_number")
        workflow_name = metadata.get("workflow_name")
        basename = "untrusted_text"
        if isinstance(workflow_name, str) and workflow_name.strip():
            basename = workflow_name.strip()
        elif isinstance(pull_number, int) and not isinstance(pull_number, bool):
            basename = f"pull_{pull_number}"
        elif isinstance(issue_number, int) and not isinstance(issue_number, bool):
            basename = f"issue_{issue_number}"
        count = metadata.get("instruction_surface_count")
        if not isinstance(count, int):
            count = 1
        fingerprint = json.dumps(
            {
                "kind": "untrusted_text",
                "basename": basename,
                "issue_number": issue_number,
                "pull_number": pull_number,
            },
            sort_keys=True,
        )
        return build_context_ref(
            source_type="untrusted_text",
            source_basename=basename,
            raw_context=fingerprint,
            token_count=count,
        )
    return None


def _policy_rule_from_metadata(metadata: Mapping[str, Any]) -> str | None:
    policy_rule = metadata.get("policy_rule")
    if isinstance(policy_rule, str) and policy_rule:
        return policy_rule
    policy_rule_id = metadata.get("policy_rule_id")
    if isinstance(policy_rule_id, str) and policy_rule_id:
        return policy_rule_id
    return None


def _tool_from_metadata(metadata: Mapping[str, Any]) -> str | None:
    tool = metadata.get("tool")
    return tool if isinstance(tool, str) and tool else None


def _tool_indicates_secret_access(tool: str | None) -> bool:
    if not tool:
        return False
    lowered = tool.lower()
    if lowered in _SECRET_TOOL_EXACT:
        return True
    if "secret_value" in lowered:
        return True
    return any(lowered.startswith(prefix) for prefix in _SECRET_TOOL_PREFIXES)


def runtime_secret_block_context(
    *,
    metadata: Mapping[str, Any],
    risk_class: str | None = None,
    block_reason: str | None = None,
    policy_rule: str | None = None,
    tool: str | None = None,
) -> bool:
    """Return True when runtime metadata describes a secret-access block."""

    reason = block_reason
    if reason is None:
        raw_reason = metadata.get("block_reason")
        reason = raw_reason if isinstance(raw_reason, str) else None
    if reason and "secret" in reason.lower():
        return True

    resolved_policy_rule = policy_rule or _policy_rule_from_metadata(metadata)
    if isinstance(resolved_policy_rule, str):
        normalized = resolved_policy_rule.lower()
        if normalized in _SECRET_POLICY_RULE_MARKERS or "secret" in normalized:
            return True

    resolved_tool = tool or _tool_from_metadata(metadata)
    if _tool_indicates_secret_access(resolved_tool):
        return True

    return isinstance(risk_class, str) and risk_class.lower() == "secret"


def build_runtime_authority_record(
    *,
    metadata: Mapping[str, Any],
    risk_class: str | None = None,
) -> dict[str, Any]:
    """Derive a bounded authority record from runtime action-gate metadata."""

    policy_decision = str(metadata.get("policy_decision") or "").lower()
    approval_status = str(metadata.get("approval_status") or "").lower()
    target_reached = metadata.get("target_reached") is True
    action_family = metadata.get("action_family")
    action_family_str = action_family if isinstance(action_family, str) else None
    block_reason_raw = metadata.get("block_reason")
    block_reason = block_reason_raw if isinstance(block_reason_raw, str) else None
    policy_rule = _policy_rule_from_metadata(metadata)
    tool = _tool_from_metadata(metadata)
    secret_block = runtime_secret_block_context(
        metadata=metadata,
        risk_class=risk_class,
        block_reason=block_reason,
        policy_rule=policy_rule,
        tool=tool,
    )
    risk_family = risk_family_for_runtime(
        action_family=action_family_str,
        risk_class=risk_class,
        block_reason=block_reason,
        policy_rule=policy_rule,
        tool=tool,
    )
    context_ref = context_ref_from_untrusted_metadata(metadata)
    untrusted = context_ref is not None
    request_id = metadata.get("request_id")
    payload_hash = metadata.get("payload_hash")

    if policy_decision in {"block", "quarantine"} or approval_status == "blocked":  # claim-check: allow "blocked" as approval_status enum value.
        reason_id = (
            AUTHORITY_REASON_SECRET_BLOCKED
            if secret_block
            else AUTHORITY_REASON_POLICY_BLOCK
        )
        return build_authority_record(
            authority_status="blocked",  # claim-check: allow "blocked" as authority_status enum value.
            authority_source="policy_block",
            authority_reason_id=reason_id,
            risk_family=risk_family,
            safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
            target_reached=False,
            context_ref=context_ref,
        )

    if approval_status == "pending":
        return build_authority_record(
            authority_status="missing",
            authority_source="untrusted_context" if untrusted else "none",
            authority_reason_id=(
                AUTHORITY_REASON_UNTRUSTED_CONTEXT
                if untrusted
                else AUTHORITY_REASON_RISKY_MISSING
            ),
            risk_family=risk_family,
            safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
            target_reached=False,
            context_ref=context_ref,
        )

    if (
        approval_status in {"approved", "executed"}
        and policy_decision == "approval"
    ):
        approval_ref = None
        if isinstance(request_id, str) and request_id:
            approval_ref = build_approval_ref(
                approval_id=request_id,
                approval_hash=payload_hash if isinstance(payload_hash, str) else None,
            )
        return build_authority_record(
            authority_status="approved",
            authority_source="approval_record",
            authority_reason_id=AUTHORITY_REASON_APPROVAL_GRANTED,
            risk_family=risk_family,
            safe_first_step_id=SAFE_FIRST_STEP_NO_ACTION,
            target_reached=target_reached,
            approval_ref=approval_ref,
            context_ref=context_ref,
        )

    if policy_decision in {"allow", "observe"} and approval_status == "executed":
        read_only = (
            risk_class == "read"
            or (
                action_family_str is not None
                and action_family_str.lower() in _READ_ACTION_FAMILIES
            )
        )
        if read_only:
            return build_authority_record(
                authority_status="allowed",
                authority_source="read_only",
                authority_reason_id=AUTHORITY_REASON_READ_ONLY,
                risk_family=risk_family,
                safe_first_step_id=SAFE_FIRST_STEP_READ_ONLY_REVIEW,
                target_reached=target_reached,
                context_ref=context_ref,
            )
        return build_authority_record(
            authority_status="allowed",
            authority_source="policy_grant",
            authority_reason_id=AUTHORITY_REASON_POLICY_GRANT,
            risk_family=risk_family,
            safe_first_step_id=SAFE_FIRST_STEP_NO_ACTION,
            target_reached=target_reached,
            context_ref=context_ref,
        )

    return build_authority_record(
        authority_status="missing",
        authority_source="untrusted_context" if untrusted else "none",
        authority_reason_id=AUTHORITY_REASON_RISKY_MISSING,
        risk_family=risk_family,
        safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
        target_reached=target_reached,
        context_ref=context_ref,
    )


def attach_runtime_authority(
    metadata: dict[str, Any],
    *,
    risk_class: str | None = None,
) -> dict[str, Any]:
    """Attach a bounded authority record to one runtime metadata payload."""

    metadata["authority_record"] = build_runtime_authority_record(
        metadata=metadata,
        risk_class=risk_class,
    )
    return metadata


def parse_authority_from_metadata(
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Return a bounded authority record stored on runtime metadata, if any."""

    if not isinstance(metadata, Mapping):
        return None
    record = metadata.get("authority_record")
    if isinstance(record, Mapping):
        return dict(record)
    legacy = metadata.get("authority")
    if isinstance(legacy, Mapping):
        return dict(legacy)
    return None


__all__ = [
    "AUTHORITY_REASON_APPROVAL_GRANTED",
    "AUTHORITY_REASON_POLICY_BLOCK",
    "AUTHORITY_REASON_POLICY_GRANT",
    "AUTHORITY_REASON_READ_ONLY",
    "AUTHORITY_REASON_RISKY_MISSING",
    "AUTHORITY_REASON_SECRET_BLOCKED",
    "AUTHORITY_REASON_UNTRUSTED_CONTEXT",
    "AuthorityBoundaryError",
    "AuthoritySource",
    "AuthorityStatus",
    "HASH_PREFIX",
    "RISK_FAMILY_READ",
    "RISK_FAMILY_SECRET",
    "RISK_FAMILY_UNKNOWN",
    "RISK_FAMILY_WRITE",
    "SAFE_FIRST_STEP_NO_ACTION",
    "SAFE_FIRST_STEP_READ_ONLY_REVIEW",
    "SAFE_FIRST_STEP_REQUEST_APPROVAL",
    "assert_authority_record_privacy_bounded",
    "attach_runtime_authority",
    "authority_record_to_hosted_payload",
    "build_approval_ref",
    "build_authority_record",
    "build_context_ref",
    "build_runtime_authority_record",
    "context_ref_from_untrusted_metadata",
    "parse_authority_from_metadata",
    "privacy_markers_in_text",
    "reject_forbidden_record_fields",
    "risk_family_for_runtime",
    "runtime_secret_block_context",
]
