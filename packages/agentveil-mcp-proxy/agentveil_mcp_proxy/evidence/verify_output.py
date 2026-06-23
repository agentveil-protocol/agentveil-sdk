"""Bounded verify CLI output and result contract classification."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from agentveil_mcp_proxy.evidence.proof import EvidenceVerificationError

VERIFY_PASSED = "verify_passed"
VERIFY_REQUIRES_TRUST_ROOTS = "verify_requires_trust_roots"
VERIFY_FAILED_UNEXPECTED = "verify_failed_unexpected"

_TRUST_ROOTS_MARKERS = (
    "externally supplied trusted_signer_dids",
    "trusted signer did(s) are required",
    "not accepted trust anchors",
)

_PRIVACY_FAIL_PATTERNS = (
    re.compile(r"/tmp/\S+"),
    re.compile(r"/Users/\S+"),
    re.compile(r"/private/\S+"),
    re.compile(r"/var/folders/\S+"),
    re.compile(r"(?i)\bpassphrase\b"),
    re.compile(r"\bTOKEN\b"),
    re.compile(r"\bSECRET\b"),
    re.compile(r"\bPASSWORD\b"),
    re.compile(r"\bPYTHONPATH\b"),
)


def _did_ref(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def classify_verify_error(exc: EvidenceVerificationError | Exception) -> str:
    message = str(exc or "").lower()
    if any(marker in message for marker in _TRUST_ROOTS_MARKERS):
        return VERIFY_REQUIRES_TRUST_ROOTS
    return VERIFY_FAILED_UNEXPECTED


def classify_verify_payload(payload: dict[str, Any]) -> str:
    """Map verify JSON output to a bounded contract state."""

    contract = payload.get("contract")
    if contract in {VERIFY_PASSED, VERIFY_REQUIRES_TRUST_ROOTS, VERIFY_FAILED_UNEXPECTED}:
        return str(contract)
    status = payload.get("status")
    if status == "ok":
        return VERIFY_PASSED
    if status == "requires_trust_roots":
        return VERIFY_REQUIRES_TRUST_ROOTS
    return VERIFY_FAILED_UNEXPECTED


def bundle_parse_summary(bundle_path: Path) -> dict[str, Any]:
    try:
        with bundle_path.open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {
            "bundle_parsed": False,
            "record_count": 0,
            "approval_grant_count": 0,
            "signed_receipt_count": 0,
        }
    if not isinstance(bundle, dict):
        return {
            "bundle_parsed": False,
            "record_count": 0,
            "approval_grant_count": 0,
            "signed_receipt_count": 0,
        }
    records = bundle.get("records")
    record_items = records if isinstance(records, list) else []
    approval_grant_count = sum(
        1
        for record in record_items
        if isinstance(record, dict) and record.get("approval_grant_jcs")
    )
    signed_receipts = bundle.get("signed_receipts")
    signed_receipt_count = len(signed_receipts) if isinstance(signed_receipts, dict) else 0
    return {
        "bundle_parsed": True,
        "record_count": len(record_items),
        "approval_grant_count": approval_grant_count,
        "signed_receipt_count": signed_receipt_count,
    }


def bounded_trust_summary(trusted_signer_dids: tuple[str, ...]) -> dict[str, Any]:
    return {
        "trusted_signer_count": len(trusted_signer_dids),
        "trusted_signer_refs": [_did_ref(did) for did in trusted_signer_dids if did],
    }


def build_verify_success_payload(
    *,
    result: Any,
    parse_summary: dict[str, Any],
    trusted_signer_dids: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "status": "ok",
        "contract": VERIFY_PASSED,
        "ok": True,
        "privacy_bounded": True,
        "bundle_parsed": parse_summary["bundle_parsed"],
        "record_count": result.record_count,
        "signed_receipt_count": result.signed_receipt_count,
        "unverified_receipt_count": result.unverified_receipt_count,
        "verified_approval_grant_count": result.verified_approval_grant_count,
        "approval_grant_count": parse_summary["approval_grant_count"],
        "trust_verification_completed": True,
        "chain_root_ref": _hash_ref(result.chain_root_hash),
        "warnings": list(result.warnings),
        **bounded_trust_summary(trusted_signer_dids),
    }


def build_verify_failure_payload(
    *,
    contract: str,
    parse_summary: dict[str, Any],
    trusted_signer_dids: tuple[str, ...],
    reason_code: str,
) -> dict[str, Any]:
    trust_completed = False
    if contract == VERIFY_REQUIRES_TRUST_ROOTS:
        message = (
            "Strict verification requires trusted signer DIDs (trust roots). "
            "Export was parsed; cryptographic/trust verification was not completed."
        )
        status = "requires_trust_roots"
    else:
        message = (
            "Evidence bundle verification failed unexpectedly. "
            "Export parsing may be incomplete; trust verification was not completed."
        )
        status = "invalid"
    return {
        "status": status,
        "contract": contract,
        "ok": False,
        "privacy_bounded": True,
        "bundle_parsed": parse_summary["bundle_parsed"],
        "record_count": parse_summary["record_count"],
        "approval_grant_count": parse_summary["approval_grant_count"],
        "signed_receipt_count": parse_summary["signed_receipt_count"],
        "trust_verification_completed": trust_completed,
        "reason_code": reason_code,
        "message": message,
        **bounded_trust_summary(trusted_signer_dids),
    }


def render_verify_human(payload: dict[str, Any]) -> str:
    contract = payload.get("contract")
    if contract == VERIFY_PASSED:
        lines = [
            "VERIFY: passed",
            (
                f"Records: {payload.get('record_count', 0)}; "
                f"signed_receipt_count: {payload.get('signed_receipt_count', 0)}; "
                f"verified approval grants: {payload.get('verified_approval_grant_count', 0)}"
            ),
            f"Trusted signer refs: {len(payload.get('trusted_signer_refs') or [])}",
        ]
        for warning in payload.get("warnings") or []:
            lines.append(f"WARN: {warning}")
        return "\n".join(lines)
    if contract == VERIFY_REQUIRES_TRUST_ROOTS:
        return "\n".join([
            "VERIFY: requires_trust_roots",
            (
                f"Export parsed: {payload.get('record_count', 0)} records, "
                f"{payload.get('approval_grant_count', 0)} approval grants, "
                f"signed_receipt_count={payload.get('signed_receipt_count', 0)}"
            ),
            str(payload.get("message") or ""),
        ])
    return "\n".join([
        "VERIFY: failed_unexpected",
        str(payload.get("message") or "Evidence bundle verification failed."),
        f"Reason code: {payload.get('reason_code') or 'verification_failed'}",
    ])


def reason_code_for_error(exc: EvidenceVerificationError | Exception) -> str:
    message = str(exc or "").lower()
    if "approval grants requires externally supplied trusted_signer_dids" in message:
        return "approval_grants_require_trust_roots"
    if "strict verification requires externally supplied trusted_signer_dids" in message:
        return "signed_receipts_require_trust_roots"
    if "trusted signer did(s) are required" in message:
        return "trust_roots_required"
    if "referenced signed receipt(s) missing from bundle" in message:
        return "signed_receipts_missing"
    if "strict verification failed" in message:
        return "strict_verification_failed"
    if "schema version unsupported" in message:
        return "unsupported_schema"
    return "verification_failed"


def privacy_markers_in_text(text: str) -> list[str]:
    findings: list[str] = []
    for pattern in _PRIVACY_FAIL_PATTERNS:
        if pattern.search(text or ""):
            findings.append(pattern.pattern)
    if '"command"' in (text or ""):
        findings.append("raw command key")
    if '"args"' in (text or ""):
        findings.append("raw args key")
    if "approval_grant_jcs" in (text or ""):
        findings.append("raw approval grant payload")
    return findings


def _hash_ref(value: str | None) -> str | None:
    if not value:
        return None
    digest = str(value)
    if digest.startswith("sha256:"):
        digest = digest.removeprefix("sha256:")
    return digest[:16] if digest else None
