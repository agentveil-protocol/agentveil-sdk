"""Offline verification helpers for AVP proof artifacts."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import base58
import jcs
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from agentveil.data_integrity import DataIntegrityError, verify_eddsa_jcs_2022
from agentveil.delegation import DelegationInvalid, verify_delegation


class ProofVerificationError(ValueError):
    """Raised when a proof artifact fails signature or semantic verification."""


def _did_to_public_key(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ProofVerificationError("signer DID must be did:key")
    try:
        decoded = base58.b58decode(did[len("did:key:z"):])
    except Exception as exc:
        raise ProofVerificationError("signer DID is not valid base58") from exc
    if len(decoded) < 2 or decoded[:2] != b"\xed\x01":
        raise ProofVerificationError("signer DID is not Ed25519 did:key")
    public_key = decoded[2:]
    if len(public_key) != 32:
        raise ProofVerificationError("signer DID has invalid Ed25519 public key")
    return public_key


def _receipt_dict(packet: Any) -> dict[str, Any]:
    if hasattr(packet, "to_dict"):
        packet = packet.to_dict()
    if not isinstance(packet, dict):
        raise ProofVerificationError("proof packet must be a dict-like object")
    return packet


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_delegation_hash(receipt: dict[str, Any]) -> str:
    return hashlib.sha256(jcs.canonicalize(receipt)).hexdigest()


def _historical_delegation_verify(receipt: dict[str, Any]) -> None:
    """Verify DelegationReceipt signature without rejecting historical expiry."""
    valid_from = receipt.get("validFrom")
    if isinstance(valid_from, str):
        try:
            now = datetime.strptime(valid_from, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc,
            )
        except ValueError:
            now = None
    else:
        now = None
    try:
        verify_delegation(receipt, now=now)
    except DelegationInvalid as exc:
        raise ProofVerificationError(f"DelegationReceipt invalid: {exc.reason}") from exc


def verify_signed_jcs(
    receipt_jcs: str,
    expected_signer_did: Optional[str] = None,
) -> dict[str, Any]:
    """Verify one DataIntegrityProof / eddsa-jcs-2022 JSON artifact.

    This is a signature-level helper. It proves which DID signed the JCS text.
    AVP semantic checks, trust-anchor checks, and cross-receipt hash linkage are
    handled by ``verify_proof_packet``.
    """
    if not isinstance(receipt_jcs, str) or not receipt_jcs:
        raise ProofVerificationError("receipt_jcs must be a non-empty string")
    try:
        receipt = json.loads(receipt_jcs)
    except json.JSONDecodeError as exc:
        raise ProofVerificationError("receipt_jcs is not valid JSON") from exc
    if not isinstance(receipt, dict):
        raise ProofVerificationError("receipt_jcs must decode to a JSON object")

    proof = receipt.get("proof")
    if not isinstance(proof, dict):
        raise ProofVerificationError("receipt proof is missing")
    if proof.get("type") != "DataIntegrityProof":
        raise ProofVerificationError("proof.type must be DataIntegrityProof")
    if proof.get("cryptosuite") != "eddsa-jcs-2022":
        raise ProofVerificationError("proof.cryptosuite must be eddsa-jcs-2022")

    verification_method = proof.get("verificationMethod")
    if not isinstance(verification_method, str) or "#" not in verification_method:
        raise ProofVerificationError("proof.verificationMethod is invalid")
    signer_did = verification_method.split("#", 1)[0]
    if expected_signer_did is not None and signer_did != expected_signer_did:
        raise ProofVerificationError("receipt signer does not match expected signer")

    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise ProofVerificationError("proof.proofValue must be multibase-z")
    try:
        signature = base58.b58decode(proof_value[1:])
    except Exception as exc:
        raise ProofVerificationError("proof.proofValue is not valid base58") from exc

    body = {key: value for key, value in receipt.items() if key != "proof"}
    try:
        VerifyKey(_did_to_public_key(signer_did)).verify(
            jcs.canonicalize(body),
            signature,
        )
    except BadSignatureError as exc:
        raise ProofVerificationError("receipt signature verification failed") from exc

    return {
        "valid": True,
        "body": body,
        "signer_did": signer_did,
        "schema_version": body.get("schema_version"),
        "digest": _sha256_text(receipt_jcs),
    }


def _require_backend_trust(
    verified: dict[str, Any],
    trusted_backend_signer_dids: set[str],
    label: str,
) -> None:
    if verified["signer_did"] not in trusted_backend_signer_dids:
        raise ProofVerificationError(f"{label} signer is not trusted")


def _normalize_trust_map(
    trusted_backend_signer_dids: Optional[Iterable[str]],
    trusted_decision_signer_dids: Optional[Iterable[str]],
    trusted_execution_signer_dids: Optional[Iterable[str]],
    trusted_human_approval_signer_dids: Optional[Iterable[str]],
) -> dict[str, set[str]]:
    fallback = {
        did for did in (trusted_backend_signer_dids or [])
        if isinstance(did, str)
    }
    decision = {
        did for did in (trusted_decision_signer_dids or fallback)
        if isinstance(did, str)
    }
    execution = {
        did for did in (trusted_execution_signer_dids or fallback)
        if isinstance(did, str)
    }
    approval = {
        did for did in (trusted_human_approval_signer_dids or fallback)
        if isinstance(did, str)
    }
    if not decision or not execution or not approval:
        raise ProofVerificationError("trusted signer DID(s) are required")
    return {
        "decision": decision,
        "execution": execution,
        "approval": approval,
    }


# The /3 receipt family (decision_receipt/3, execution_receipt/3, and
# claim-check: allow "W3C"/eddsa-jcs-2022 are literal cryptosuite identifiers (no external-conformance claim); "all"-receipts routing is tested in tests/test_proof_verification.py
# human_approval_receipt/3) is verified with the data-integrity (eddsa-jcs-2022)
# hashData path; /1 and /2 stay on the legacy raw-JCS verifier. The Runtime Gate
# currently emits decision_receipt/3; execution_receipt/3 and
# human_approval_receipt/3 are verifier-ready here for future backend emission.
_W3C_DI_RECEIPT_SCHEMAS = frozenset({
    "decision_receipt/3",
    "execution_receipt/3",
    "human_approval_receipt/3",
})
# execution_receipt/3 and human_approval_receipt/3 inherit /2 strictness: the
# shared intent fields and decision_receipt_hash are mandatory (not optional as
# for legacy /1).
_STRICT_EXECUTION_SCHEMAS = frozenset({"execution_receipt/2", "execution_receipt/3"})
_STRICT_APPROVAL_SCHEMAS = frozenset({"human_approval_receipt/2", "human_approval_receipt/3"})
_STRICT_INTENT_SCHEMAS = _STRICT_EXECUTION_SCHEMAS | _STRICT_APPROVAL_SCHEMAS


def _verify_backend_receipt(
    receipt_jcs: Any,
    trusted_backend_signer_dids: set[str],
    label: str,
) -> dict[str, Any]:
    """Verify one backend receipt JCS, routing the /3 receipt family to the
    claim-check: allow "W3C"/eddsa-jcs-2022 are literal cryptosuite identifiers (no external-conformance claim); "all"-receipts routing tested in tests/test_proof_verification.py
    first-party data-integrity (eddsa-jcs-2022) verifier and /1,/2 to the legacy
    raw-JCS verifier.

    Routing reads the signature-protected ``schema_version``: a receipt that
    claims one schema but was signed for the other fails closed because the
    signature does not reproduce under the wrong path (schema_version is itself
    claim-check: allow "never raises" — the schema peek is guarded by isinstance + try/except json.JSONDecodeError; tested in tests/test_proof_verification.py
    inside the signed body). The peek never raises — malformed or non-/3 input
    falls through to ``verify_signed_jcs``, which performs its own structural
    validation. Returns the same shape as ``verify_signed_jcs`` so the downstream
    trust check and cross-receipt linkage are unchanged.
    """
    is_w3c = False
    if isinstance(receipt_jcs, str):
        try:
            parsed = json.loads(receipt_jcs)
        except json.JSONDecodeError:
            parsed = None
        is_w3c = (
            isinstance(parsed, dict)
            and parsed.get("schema_version") in _W3C_DI_RECEIPT_SCHEMAS
        )
    if not is_w3c:
        verified = verify_signed_jcs(receipt_jcs)
        _require_backend_trust(verified, trusted_backend_signer_dids, label)
        return verified
    if not trusted_backend_signer_dids:
        raise ProofVerificationError("trusted signer DID(s) are required")
    last_error: Exception | None = None
    for signer_did in trusted_backend_signer_dids:
        try:
            verified = verify_eddsa_jcs_2022(
                receipt_jcs,
                expected_signer_did=signer_did,
            )
        except DataIntegrityError as exc:
            last_error = exc
            continue
        return {
            "valid": True,
            "body": verified["document"],
            "signer_did": verified["signer_did"],
            "schema_version": verified["schema_version"],
            "digest": _sha256_text(receipt_jcs),
        }
    raise ProofVerificationError(f"{label} signature verification failed") from last_error


def _verify_optional_backend_receipt(
    packet: dict[str, Any],
    key: str,
    trusted_backend_signer_dids: set[str],
    label: str,
) -> Optional[dict[str, Any]]:
    receipt_jcs = packet.get(key)
    if receipt_jcs is None:
        return None
    verified = _verify_backend_receipt(receipt_jcs, trusted_backend_signer_dids, label)
    return verified


def _assert_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise ProofVerificationError(f"{label} mismatch")


def _check_shared_intent(
    *,
    decision: dict[str, Any],
    other: dict[str, Any],
    other_label: str,
) -> None:
    required = other.get("schema_version") in _STRICT_INTENT_SCHEMAS
    for field in ("agent_did", "action", "resource", "environment"):
        other_field = (
            "requester_agent_did"
            if field == "agent_did" and other_label == "approval"
            else field
        )
        if other_field not in other:
            if required:
                raise ProofVerificationError(f"{other_label}.{other_field} is required")
            continue
        _assert_equal(
            other[other_field],
            decision.get(field),
            f"{other_label}.{other_field}",
        )


def _check_schema_version(body: dict[str, Any], allowed: Iterable[str], label: str) -> None:
    schema = body.get("schema_version")
    if schema is not None and schema not in set(allowed):
        raise ProofVerificationError(f"{label} schema_version is unsupported")


def _requires_field(body: dict[str, Any], strict_schemas: Iterable[str], field: str) -> bool:
    return body.get("schema_version") in set(strict_schemas) or field in body


def verify_proof_packet(
    packet: Any,
    trusted_backend_signer_dids: Optional[Iterable[str]] = None,
    *,
    trusted_decision_signer_dids: Optional[Iterable[str]] = None,
    trusted_execution_signer_dids: Optional[Iterable[str]] = None,
    trusted_human_approval_signer_dids: Optional[Iterable[str]] = None,
) -> dict[str, Any]:
    """Verify an AVP proof packet's signatures, trusted signers, and linkage."""
    trust = _normalize_trust_map(
        trusted_backend_signer_dids,
        trusted_decision_signer_dids,
        trusted_execution_signer_dids,
        trusted_human_approval_signer_dids,
    )

    data = _receipt_dict(packet)
    delegation_receipt = data.get("delegation_receipt")
    if not isinstance(delegation_receipt, dict):
        raise ProofVerificationError("proof packet missing DelegationReceipt")
    _historical_delegation_verify(delegation_receipt)
    delegation_hash = _canonical_delegation_hash(delegation_receipt)

    decision = _verify_optional_backend_receipt(
        data, "decision_receipt_jcs", trust["decision"], "DecisionReceipt",
    )
    approval = _verify_optional_backend_receipt(
        data, "approval_receipt_jcs", trust["approval"], "HumanApprovalReceipt",
    )
    execution = _verify_optional_backend_receipt(
        data, "execution_receipt_jcs", trust["execution"], "ExecutionReceipt",
    )

    if decision is None:
        raise ProofVerificationError("proof packet missing DecisionReceipt")
    decision_body = decision["body"]
    _check_schema_version(
        decision_body,
        {"decision_receipt/1", "decision_receipt/2", "decision_receipt/3"},
        "DecisionReceipt",
    )
    outcome_status = data.get("outcome_status")
    decision_value = decision_body.get("decision")
    if outcome_status == "executed" and execution is None:
        raise ProofVerificationError("executed proof packet missing ExecutionReceipt")
    if outcome_status == "blocked":
        if decision_value != "BLOCK":
            raise ProofVerificationError("blocked proof packet requires BLOCK DecisionReceipt")
        if execution is not None:
            raise ProofVerificationError("blocked proof packet must not include ExecutionReceipt")
    if outcome_status == "approval_required" and decision_value != "WAITING_FOR_HUMAN_APPROVAL":
        raise ProofVerificationError(
            "approval_required proof packet requires WAITING_FOR_HUMAN_APPROVAL DecisionReceipt"
        )
    _assert_equal(data.get("agent_did"), decision_body.get("agent_did"), "packet.agent_did")
    if data.get("audit_id") is not None:
        _assert_equal(data["audit_id"], decision_body.get("audit_id"), "packet.audit_id")
    if decision_body.get("delegation_receipt_hash") is not None:
        _assert_equal(
            decision_body["delegation_receipt_hash"],
            delegation_hash,
            "DecisionReceipt.delegation_receipt_hash",
        )

    if execution is not None:
        execution_body = execution["body"]
        _check_schema_version(
            execution_body,
            {"execution_receipt/1", "execution_receipt/2", "execution_receipt/3"},
            "ExecutionReceipt",
        )
        if _requires_field(execution_body, _STRICT_EXECUTION_SCHEMAS, "decision_receipt_hash"):
            _assert_equal(
                execution_body.get("decision_receipt_hash"),
                decision["digest"],
                "ExecutionReceipt.decision_receipt_hash",
            )
        _assert_equal(
            execution_body.get("gate_audit_id"),
            decision_body.get("audit_id"),
            "ExecutionReceipt.gate_audit_id",
        )
        _check_shared_intent(
            decision=decision_body,
            other=execution_body,
            other_label="execution",
        )

    if approval is not None:
        approval_body = approval["body"]
        _check_schema_version(
            approval_body,
            {"human_approval_receipt/1", "human_approval_receipt/2", "human_approval_receipt/3"},
            "HumanApprovalReceipt",
        )
        if _requires_field(
            approval_body,
            _STRICT_APPROVAL_SCHEMAS,
            "decision_receipt_hash",
        ):
            _assert_equal(
                approval_body.get("decision_receipt_hash"),
                decision["digest"],
                "HumanApprovalReceipt.decision_receipt_hash",
            )
        _assert_equal(
            approval_body.get("gate_audit_id"),
            decision_body.get("audit_id"),
            "HumanApprovalReceipt.gate_audit_id",
        )
        if approval_body.get("delegation_receipt_hash") is not None:
            _assert_equal(
                approval_body["delegation_receipt_hash"],
                delegation_hash,
                "HumanApprovalReceipt.delegation_receipt_hash",
            )
        _check_shared_intent(
            decision=decision_body,
            other=approval_body,
            other_label="approval",
        )

    approval_required = (
        data.get("outcome_status") == "approval_required"
        or (execution is not None and "approval_receipt_hash" in execution["body"])
        or data.get("approval") is not None
    )
    if approval_required and approval is None:
        raise ProofVerificationError("approval receipt is required for approval path")

    if execution is not None and approval is not None:
        _assert_equal(
            execution["body"].get("approval_receipt_hash"),
            approval["digest"],
            "ExecutionReceipt.approval_receipt_hash",
        )
        if approval["body"].get("decision") != "APPROVED":
            raise ProofVerificationError("approval receipt is not APPROVED")

    return {
        "valid": True,
        "decision_receipt": decision,
        "approval_receipt": approval,
        "execution_receipt": execution,
        "delegation_receipt_hash": delegation_hash,
    }


__all__ = [
    "ProofVerificationError",
    "verify_signed_jcs",
    "verify_proof_packet",
]
