"""Proxy-signed local approval grant primitive (schema ``proxy_approval_grant/1``).

This artifact binds one local MCP-proxy approval decision to the proxy identity
that issued it, using the shipped Data Integrity signing primitive.

This module is intentionally isolated (SG-2): it does NOT touch the approval
manager, evidence store schema, evidence export/verify bundle, or CLI. Trust is
external-pinning only: a signer list embedded in a grant is not honored.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from agentveil.data_integrity import (
    DataIntegrityError,
    sign_eddsa_jcs_2022,
    verify_eddsa_jcs_2022,
)


APPROVAL_GRANT_SCHEMA = "proxy_approval_grant/1"

APPROVAL_SCOPE_EXACT = "exact"
APPROVAL_SCOPE_SIMILAR_5M = "similar_5m"
_SUPPORTED_SCOPES = frozenset({APPROVAL_SCOPE_EXACT, APPROVAL_SCOPE_SIMILAR_5M})

# SG-2 mints/accepts only APPROVED grants.
_SUPPORTED_DECISIONS = frozenset({"APPROVED"})

# Hash-shape contract follows existing repo producers:
#   classification.sha256_jcs/sha256_text -> "sha256:<64 hex>" (payload/resource)
#   policy.policy_context_hash            -> raw "<64 hex>"
#   runtime_gate receipt digest           -> raw "<64 hex>" (decision_receipt_sha256)
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Fields that must be present. Nullability is enforced per-field below.
_NON_EMPTY_STR_FIELDS = (
    "schema_version",
    "agent_did",
    "request_id",
    "downstream_server",
    "tool_name",
    "action_class",
    "risk_class",
    "policy_id",
    "policy_context_hash",
    "decision",
    "approval_scope",
    "decided_by",
)
_NULLABLE_STR_FIELDS = (
    "policy_rule_id",
    "resource_hash",
    "payload_hash",
)
_INT_FIELDS = (
    "issued_at",
    "expires_at",
)
_OPTIONAL_NULLABLE_STR_FIELDS = (
    "decision_audit_id",
    "decision_receipt_sha256",
    "granted_by_request_id",
)


class ApprovalGrantError(ValueError):
    """Raised on any build/verify failure for a proxy approval grant."""


def _require_non_empty_str(body: Mapping[str, Any], field: str) -> None:
    if field not in body:
        raise ApprovalGrantError(f"approval grant missing required field: {field}")
    value = body[field]
    if not isinstance(value, str) or not value:
        raise ApprovalGrantError(f"approval grant field {field} must be a non-empty string")


def _require_nullable_str(body: Mapping[str, Any], field: str) -> None:
    if field not in body:
        raise ApprovalGrantError(f"approval grant missing required field: {field}")
    value = body[field]
    if value is not None and (not isinstance(value, str) or not value):
        raise ApprovalGrantError(f"approval grant field {field} must be a non-empty string or null")


def _require_int(body: Mapping[str, Any], field: str) -> None:
    if field not in body:
        raise ApprovalGrantError(f"approval grant missing required field: {field}")
    value = body[field]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ApprovalGrantError(f"approval grant field {field} must be an integer")


def _check_prefixed_sha256(value: Any, field: str) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not _PREFIXED_SHA256_RE.fullmatch(value):
        raise ApprovalGrantError(f"approval grant field {field} must be 'sha256:<64 lowercase hex>'")


def _check_raw_sha256(value: Any, field: str, *, required: bool) -> None:
    if value is None:
        if required:
            raise ApprovalGrantError(
                f"approval grant field {field} must be a 64-char lowercase hex digest"
            )
        return
    if not isinstance(value, str) or not _RAW_SHA256_RE.fullmatch(value):
        raise ApprovalGrantError(
            f"approval grant field {field} must be a 64-char lowercase hex digest"
        )


def _validate_grant_body(body: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the proxy_approval_grant/1 shape and binding rules.

    Unknown extra fields are tolerated and ignored -- in particular, a
    self-declared trust hint embedded in the grant is not consulted.
    """
    if not isinstance(body, Mapping):
        raise ApprovalGrantError("approval grant body must be a mapping")

    for field in _NON_EMPTY_STR_FIELDS:
        _require_non_empty_str(body, field)
    for field in _NULLABLE_STR_FIELDS:
        _require_nullable_str(body, field)
    for field in _INT_FIELDS:
        _require_int(body, field)
    for field in _OPTIONAL_NULLABLE_STR_FIELDS:
        if field in body and body[field] is not None:
            if not isinstance(body[field], str) or not body[field]:
                raise ApprovalGrantError(
                    f"approval grant field {field} must be a non-empty string or null"
                )

    if body["schema_version"] != APPROVAL_GRANT_SCHEMA:
        raise ApprovalGrantError(
            f"unsupported approval grant schema_version: {body['schema_version']!r}"
        )
    if body["decision"] not in _SUPPORTED_DECISIONS:
        raise ApprovalGrantError(
            f"unsupported approval grant decision: {body['decision']!r}"
        )
    scope = body["approval_scope"]
    if scope not in _SUPPORTED_SCOPES:
        raise ApprovalGrantError(f"unsupported approval_scope: {scope!r}")

    if scope == APPROVAL_SCOPE_EXACT and not body.get("payload_hash"):
        raise ApprovalGrantError("approval_scope=exact requires a non-null payload_hash")
    if scope == APPROVAL_SCOPE_SIMILAR_5M and not body.get("resource_hash"):
        raise ApprovalGrantError("approval_scope=similar_5m requires a non-null resource_hash")

    # Hash-shape contract (repo semantics): prefixed for payload/resource, raw
    # 64-hex for policy_context_hash and the optional decision_receipt_sha256.
    _check_prefixed_sha256(body.get("payload_hash"), "payload_hash")
    _check_prefixed_sha256(body.get("resource_hash"), "resource_hash")
    _check_raw_sha256(body.get("policy_context_hash"), "policy_context_hash", required=True)
    _check_raw_sha256(body.get("decision_receipt_sha256"), "decision_receipt_sha256", required=False)

    return dict(body)


def build_approval_grant(body: Mapping[str, Any], private_key_seed: bytes) -> str:
    """Sign one approval-grant body with the proxy identity Ed25519 seed.

    Returns the JCS-canonical secured grant text. The body is validated against
    the proxy_approval_grant/1 shape and binding rules before signing. Expiry is
    not evaluated against a clock here; that is a verify-time check.
    """
    validated = _validate_grant_body(body)
    if "proof" in validated:
        raise ApprovalGrantError("approval grant body must not include 'proof'")
    try:
        return sign_eddsa_jcs_2022(validated, private_key_seed)
    except DataIntegrityError as exc:
        raise ApprovalGrantError(f"approval grant signing failed: {exc}") from exc


def verify_approval_grant(
    grant_jcs: str,
    *,
    expected_signer_dids: Iterable[str],
    now: int | None = None,
) -> dict[str, Any]:
    """Verify a proxy approval grant against externally pinned signer DIDs.

    Fail-closed: any structural, signature, trust, schema, binding, or expiry
    failure raises ``ApprovalGrantError``. A signer list embedded in the grant is
    not consulted; only ``expected_signer_dids`` is honored.
    """
    pinned = tuple(d for d in (expected_signer_dids or ()) if isinstance(d, str) and d)
    if not pinned:
        raise ApprovalGrantError(
            "verification requires externally supplied expected_signer_dids"
        )
    if not isinstance(grant_jcs, str) or not grant_jcs:
        raise ApprovalGrantError("grant_jcs must be a non-empty string")

    try:
        result = verify_eddsa_jcs_2022(grant_jcs)
    except DataIntegrityError as exc:
        raise ApprovalGrantError(f"approval grant signature invalid: {exc}") from exc

    signer_did = result.get("signer_did")
    if not isinstance(signer_did, str) or signer_did not in pinned:
        raise ApprovalGrantError("approval grant signer is not in the pinned signer set")

    body = result.get("document")
    if not isinstance(body, Mapping):
        raise ApprovalGrantError("approval grant document is not an object")
    validated = _validate_grant_body(body)

    if validated["agent_did"] != signer_did:
        raise ApprovalGrantError("agent_did does not match the proof signer")

    if now is not None and int(validated["expires_at"]) <= int(now):
        raise ApprovalGrantError("approval grant has expired")

    return validated


__all__ = [
    "APPROVAL_GRANT_SCHEMA",
    "APPROVAL_SCOPE_EXACT",
    "APPROVAL_SCOPE_SIMILAR_5M",
    "ApprovalGrantError",
    "build_approval_grant",
    "verify_approval_grant",
]
