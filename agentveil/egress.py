"""Agent-signed ``egress_receipt/2`` signer, verifier, and controlled-egress helper.

An ``egress_receipt/2`` proves a network-egress attempt that the AVP-controlled
boundary (this SDK helper) actually performed. Receipts are signed with the
agent's own identity DID. They are **agent-signed**, not backend-signed.

Boundary:
  - The helper performs the HTTPS send itself via embedded ``httpx.Client``.
    Calls that route through other code paths (raw ``requests.post(...)``,
    raw sockets, subprocesses, other libraries) are NOT recorded.
  - Runtime Gate evaluates the egress; the helper does not open the
    connection on BLOCK or WAITING.
  - A future slice may add a backend ``/v1/egress/sign`` endpoint for
    backend-attested EgressReceipts. The current SDK egress signer is
    local-signing only.

Dual hash convention:
  - ``payload_digest_hex = sha256(body).hex()`` — plain 64 hex chars,
    used in ``egress_receipt/2.payload_hash``.
  - ``runtime_payload_hash = "sha256:" + payload_digest_hex`` — prefixed
    form required by Runtime Gate's request schema (matches the pattern
    ``^sha256:[0-9a-f]{64}$``).

This helper emits ``egress_receipt/2`` signed with the SDK's data-integrity
signing path; the legacy raw-JCS receipt form remains verify-compatible. A
sibling egress contract lives in the AVP backend repo
(``app/core/egress_control/proof.py``); future consolidation may extract a
shared ``agentveil-protocol`` package.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, Callable, Optional

import base58
import httpx
import jcs
from nacl.signing import SigningKey, VerifyKey

from agentveil.data_integrity import (
    DataIntegrityError,
    sign_eddsa_jcs_2022,
    verify_eddsa_jcs_2022,
)

SCHEMA_VERSION = "egress_receipt/2"
# Legacy verify-only egress schema (raw-JCS proof construction). New receipts
# are issued as SCHEMA_VERSION; egress_receipt/1 is accepted only for verify.
LEGACY_SCHEMA_VERSION = "egress_receipt/1"
_SUPPORTED_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION, LEGACY_SCHEMA_VERSION})
EVALUATOR_VERSION = "egress-control/0.1.0"
ACTION_NETWORK_EGRESS = "network.egress"
PROOF_TYPE = "DataIntegrityProof"
CRYPTOSUITE = "eddsa-jcs-2022"

ED25519_MULTICODEC = bytes([0xED, 0x01])

_REQUIRED_STRING_FIELDS = (
    "receipt_id",
    "agent_did",
    "action",
    "destination",
    "protocol",
    "method",
    "credential_or_principal_class",
    "payload_hash",
    "policy_id",
    "decision",
    "outcome",
    "evaluator_version",
)

_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_RUNTIME_DECISIONS = frozenset({"ALLOW", "BLOCK", "WAITING_FOR_HUMAN_APPROVAL"})


class EgressReceiptProofError(ValueError):
    """Raised when an unsigned EgressReceipt body is malformed."""


class EgressReceiptVerificationError(ValueError):
    """Raised when a signed EgressReceipt fails offline verification."""


class EgressPolicyViolationError(RuntimeError):
    """Raised when Runtime Gate returns an unparseable response."""


@dataclass(frozen=True)
class ControlledEgressOutcome:
    """Result of an ``AVPAgent.controlled_egress(...)`` call.

    ``status`` values:
      - ``sent`` — Runtime Gate returned ALLOW and the helper completed
        the HTTPS send. Receipt is agent-signed with ``outcome=SENT``.
      - ``blocked`` — Runtime Gate returned BLOCK. Helper did NOT open
        the connection. Receipt is agent-signed with ``outcome=BLOCKED``.
      - ``approval_required`` — Runtime Gate returned
        ``WAITING_FOR_HUMAN_APPROVAL``. Helper did NOT open the
        connection. No receipt is emitted in v0.1.
      - ``failed`` — Runtime Gate returned ALLOW but the helper's HTTP
        send raised. Receipt is agent-signed with ``outcome=FAILED``.
        The sanitized error class is captured; raw exception messages
        and tracebacks are not stored.
    """

    status: str
    decision: dict[str, Any]
    receipt_jcs: Optional[str]
    receipt: Optional[dict[str, Any]]
    audit_id: Optional[str]
    send_result: Optional[dict[str, Any]]
    error_class: Optional[str] = None


def _did_from_public_key(public_key: bytes) -> str:
    multicodec_key = ED25519_MULTICODEC + public_key
    return "did:key:z" + base58.b58encode(multicodec_key).decode("ascii")


def _public_key_from_did(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise EgressReceiptVerificationError("signer DID must be did:key")
    try:
        decoded = base58.b58decode(did[len("did:key:z"):])
    except Exception as exc:
        raise EgressReceiptVerificationError("signer DID is not valid base58") from exc
    if len(decoded) < 2 or decoded[:2] != ED25519_MULTICODEC:
        raise EgressReceiptVerificationError("signer DID is not Ed25519 did:key")
    public_key = decoded[2:]
    if len(public_key) != 32:
        raise EgressReceiptVerificationError(
            "signer DID has invalid Ed25519 public key"
        )
    return public_key


def _validate_body(body: dict[str, Any]) -> None:
    if not isinstance(body, dict):
        raise EgressReceiptProofError("body must be a dict")
    if "proof" in body:
        raise EgressReceiptProofError(
            "body must not include 'proof'; pass unsigned fields"
        )
    if body.get("schema_version") not in _SUPPORTED_SCHEMA_VERSIONS:
        raise EgressReceiptProofError(
            f"body schema_version must be one of {sorted(_SUPPORTED_SCHEMA_VERSIONS)}"
        )
    for field_name in _REQUIRED_STRING_FIELDS:
        if not isinstance(body.get(field_name), str) or not body[field_name]:
            raise EgressReceiptProofError(
                f"body must include non-empty string field {field_name!r}"
            )
    if body["action"] != ACTION_NETWORK_EGRESS:
        raise EgressReceiptProofError(
            f"body action must be {ACTION_NETWORK_EGRESS!r}"
        )
    if body["evaluator_version"] != EVALUATOR_VERSION:
        raise EgressReceiptProofError(
            f"body evaluator_version must be {EVALUATOR_VERSION!r}"
        )
    if not _SHA256_HEX_RE.match(body["payload_hash"]):
        raise EgressReceiptProofError(
            "payload_hash must be a 64-character SHA-256 hex digest"
        )
    if "approval_id" not in body:
        raise EgressReceiptProofError("body must include 'approval_id'")
    if body["approval_id"] is not None and (
        not isinstance(body["approval_id"], str) or not body["approval_id"]
    ):
        raise EgressReceiptProofError(
            "approval_id must be a non-empty string or null"
        )


def sign_egress_receipt(*, body: dict[str, Any], signing_seed: bytes) -> str:
    """Sign an EgressReceipt body and return canonical JCS text.

    The receipt is signed with the agent's identity (not the backend's).
    The body's ``agent_did`` MUST equal the DID derived from
    ``signing_seed`` — agent-signed receipts must self-attest, and any
    mismatch would break offline audit by allowing one identity to
    sign a receipt claiming another identity performed the egress.
    """

    _validate_body(body)
    if body["schema_version"] != SCHEMA_VERSION:
        raise EgressReceiptProofError(
            f"sign_egress_receipt issues {SCHEMA_VERSION!r}; "
            f"{LEGACY_SCHEMA_VERSION!r} is verify-only"
        )
    if not isinstance(signing_seed, (bytes, bytearray)) or len(signing_seed) != 32:
        raise EgressReceiptProofError("signing_seed must be 32 bytes")
    issuer_did = _did_from_public_key(bytes(SigningKey(bytes(signing_seed)).verify_key))
    if body["agent_did"] != issuer_did:
        raise EgressReceiptProofError(
            "body.agent_did must equal the DID derived from signing_seed"
        )
    try:
        return sign_eddsa_jcs_2022(body, bytes(signing_seed))
    except DataIntegrityError as exc:
        raise EgressReceiptProofError(str(exc)) from exc


def verify_egress_receipt(
    receipt_jcs: str,
    *,
    trusted_signer_dids: Optional[Collection[str]] = None,
) -> dict[str, Any]:
    """Verify an agent-signed EgressReceipt offline.

    The receipt is signed by the agent's identity (not the AVP backend). This
    is a proof/security API and fails closed: the caller MUST pin the agent
    DID(s) they trust via ``trusted_signer_dids`` and the receipt signer DID
    must be in that set. With no trust configuration the verifier raises
    ``EgressReceiptVerificationError("trusted_signer_dids is required")`` rather
    than accepting any valid did:key signer. An empty trust set also fails
    closed.
    """

    if not isinstance(receipt_jcs, str) or not receipt_jcs:
        raise EgressReceiptVerificationError("receipt_jcs must be a non-empty string")
    try:
        receipt = json.loads(receipt_jcs)
    except json.JSONDecodeError as exc:
        raise EgressReceiptVerificationError("receipt is not valid JSON") from exc
    if not isinstance(receipt, dict):
        raise EgressReceiptVerificationError("receipt must be a JSON object")

    if receipt.get("schema_version") == SCHEMA_VERSION:
        return _verify_egress_receipt_w3c(receipt_jcs, receipt, trusted_signer_dids)

    # Legacy egress_receipt/1: raw-JCS proof envelope.
    proof = receipt.pop("proof", None)
    if not isinstance(proof, dict):
        raise EgressReceiptVerificationError("receipt proof missing")
    if proof.get("type") != PROOF_TYPE:
        raise EgressReceiptVerificationError("receipt proof type unsupported")
    if proof.get("cryptosuite") != CRYPTOSUITE:
        raise EgressReceiptVerificationError("receipt cryptosuite unsupported")

    verification_method = proof.get("verificationMethod")
    proof_value = proof.get("proofValue")
    if not isinstance(verification_method, str) or "#" not in verification_method:
        raise EgressReceiptVerificationError(
            "receipt verification method invalid"
        )
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise EgressReceiptVerificationError("receipt proof value invalid")

    signer_did = verification_method.split("#", 1)[0]
    if trusted_signer_dids is None:
        # Boundary: proof verification requires an explicit trust set. Covered
        # by test_no_trusted_signer_dids_fails_closed.
        raise EgressReceiptVerificationError("trusted_signer_dids is required")
    if signer_did not in set(trusted_signer_dids):
        raise EgressReceiptVerificationError("receipt signer is not trusted")

    public_key = _public_key_from_did(signer_did)
    try:
        signature = base58.b58decode(proof_value[1:])
        VerifyKey(public_key).verify(jcs.canonicalize(receipt), signature)
    except Exception as exc:
        raise EgressReceiptVerificationError("receipt signature invalid") from exc

    try:
        _validate_body(receipt)
    except EgressReceiptProofError as exc:
        raise EgressReceiptVerificationError(str(exc)) from exc
    # Bind body.agent_did to the proof signer DID. Without this check a
    # receipt signed by one agent but claiming another agent_did would
    # verify and misattribute egress in offline audit.
    if receipt.get("agent_did") != signer_did:
        raise EgressReceiptVerificationError(
            "receipt agent_did does not match proof signer DID"
        )
    return receipt


def _verify_egress_receipt_w3c(
    receipt_jcs: str,
    receipt: dict[str, Any],
    trusted_signer_dids: Optional[Collection[str]],
) -> dict[str, Any]:
    """Verify an ``egress_receipt/2`` via the data-integrity hashData
    construction. Trust pinning and agent_did binding match the legacy path; a
    verification failure surfaces as ``EgressReceiptVerificationError`` rather
    than a raw lower-level error.
    """

    proof = receipt.get("proof")
    if not isinstance(proof, dict):
        raise EgressReceiptVerificationError("receipt proof missing")
    verification_method = proof.get("verificationMethod")
    if not isinstance(verification_method, str) or "#" not in verification_method:
        raise EgressReceiptVerificationError("receipt verification method invalid")
    signer_did = verification_method.split("#", 1)[0]
    if trusted_signer_dids is None:
        raise EgressReceiptVerificationError("trusted_signer_dids is required")
    if signer_did not in set(trusted_signer_dids):
        raise EgressReceiptVerificationError("receipt signer is not trusted")
    try:
        verified = verify_eddsa_jcs_2022(receipt_jcs, expected_signer_did=signer_did)
    except DataIntegrityError as exc:
        raise EgressReceiptVerificationError("receipt signature invalid") from exc
    body = verified["document"]
    try:
        _validate_body(body)
    except EgressReceiptProofError as exc:
        raise EgressReceiptVerificationError(str(exc)) from exc
    if body.get("agent_did") != verified["signer_did"]:
        raise EgressReceiptVerificationError(
            "receipt agent_did does not match proof signer DID"
        )
    return body


def _sanitize_error_class(exc: BaseException) -> str:
    """Return only the exception class name; never the message or traceback."""
    return type(exc).__name__


def _coerce_decision(response: Any) -> dict[str, Any]:
    if not isinstance(response, Mapping):
        raise EgressPolicyViolationError("runtime gate response is not a mapping")
    decision = response.get("decision")
    if not isinstance(decision, str) or decision not in _RUNTIME_DECISIONS:
        raise EgressPolicyViolationError(
            "runtime gate decision missing or unsupported"
        )
    return dict(response)


def _sign_outcome_receipt(
    *,
    agent_did: str,
    destination: str,
    method: str,
    credential_or_principal_class: str,
    payload_digest_hex: str,
    policy_id: str,
    decision_value: str,
    outcome: str,
    signing_seed: bytes,
) -> str:
    """Build and sign the agent-signed ``egress_receipt/2`` body."""

    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": f"urn:uuid:{uuid.uuid4()}",
        "agent_did": agent_did,
        "action": ACTION_NETWORK_EGRESS,
        "destination": destination,
        "protocol": "https",
        "method": method,
        "credential_or_principal_class": credential_or_principal_class,
        "payload_hash": payload_digest_hex,
        "policy_id": policy_id,
        "decision": decision_value,
        "approval_id": None,
        "outcome": outcome,
        "evaluator_version": EVALUATOR_VERSION,
    }
    return sign_egress_receipt(body=body, signing_seed=signing_seed)


def controlled_egress(
    *,
    agent: Any,
    host: str,
    port: int,
    method: str,
    path: str,
    headers: Optional[Mapping[str, str]],
    body: bytes,
    credential_or_principal_class: str,
    policy_id: str,
    delegation_receipt: Mapping[str, Any],
    timeout_seconds: float = 30.0,
    _http_client_factory: Optional[Callable[..., Any]] = None,
) -> ControlledEgressOutcome:
    """Perform an HTTPS egress through the AVP-controlled boundary.

    The helper computes the payload digest in two forms:

    - ``payload_digest_hex`` (plain 64 hex chars) is recorded in the
      ``egress_receipt/2`` body's ``payload_hash`` field.
    - ``runtime_payload_hash`` (``"sha256:" + payload_digest_hex``) is
      sent to ``/v1/runtime/evaluate`` per the Runtime Gate request
      schema.

    On ALLOW the helper performs the HTTPS request itself via an
    embedded ``httpx.Client`` and signs an **agent-signed**
    ``egress_receipt/2`` with ``outcome=SENT`` (or ``FAILED`` on
    connection-class error). On BLOCK the helper signs ``outcome=BLOCKED``
    and does NOT open the connection. On ``WAITING_FOR_HUMAN_APPROVAL``
    the helper returns ``status="approval_required"`` with no receipt;
    the connection is not opened.

    The receipt is **agent-signed**, not backend-signed. Callers verify
    against the agent's DID via ``verify_egress_receipt(...,
    trusted_signer_dids=[agent.did])``.

    ``_http_client_factory`` is a private hook for tests; production
    callers should leave it unset so the helper uses ``httpx.Client``.
    """

    if not isinstance(body, (bytes, bytearray)):
        raise EgressReceiptProofError("body must be bytes")
    if not isinstance(host, str) or not host:
        raise EgressReceiptProofError("host must be a non-empty string")
    if not isinstance(port, int) or port <= 0 or port > 65535:
        raise EgressReceiptProofError("port must be a TCP port in 1..65535")
    if not isinstance(method, str) or not method:
        raise EgressReceiptProofError("method must be a non-empty string")
    if not isinstance(path, str) or not path.startswith("/"):
        raise EgressReceiptProofError("path must be a string starting with '/'")
    if (
        not isinstance(credential_or_principal_class, str)
        or not credential_or_principal_class
    ):
        raise EgressReceiptProofError(
            "credential_or_principal_class must be a non-empty string"
        )
    if not isinstance(policy_id, str) or not policy_id:
        raise EgressReceiptProofError("policy_id must be a non-empty string")
    if not isinstance(delegation_receipt, Mapping):
        raise EgressReceiptProofError("delegation_receipt must be a mapping")

    body_bytes = bytes(body)
    payload_digest_hex = hashlib.sha256(body_bytes).hexdigest()
    runtime_payload_hash = f"sha256:{payload_digest_hex}"
    destination = f"{host}:{port}"
    normalized_method = method.upper()

    try:
        gate_response = agent.runtime_evaluate(
            action=ACTION_NETWORK_EGRESS,
            resource=destination,
            environment="production",
            delegation_receipt=dict(delegation_receipt),
            payload_hash=runtime_payload_hash,
            risk_class="write",
        )
    except Exception as exc:
        raise EgressPolicyViolationError(
            f"runtime gate call failed: {_sanitize_error_class(exc)}"
        ) from exc

    decision = _coerce_decision(gate_response)
    decision_value = decision["decision"]
    audit_id_raw = decision.get("audit_id")
    audit_id = audit_id_raw if isinstance(audit_id_raw, str) else None

    if decision_value == "WAITING_FOR_HUMAN_APPROVAL":
        return ControlledEgressOutcome(
            status="approval_required",
            decision=decision,
            receipt_jcs=None,
            receipt=None,
            audit_id=audit_id,
            send_result=None,
        )

    if decision_value == "BLOCK":
        receipt_jcs = _sign_outcome_receipt(
            agent_did=agent.did,
            destination=destination,
            method=normalized_method,
            credential_or_principal_class=credential_or_principal_class,
            payload_digest_hex=payload_digest_hex,
            policy_id=policy_id,
            decision_value="BLOCK",
            outcome="BLOCKED",
            signing_seed=agent._private_key,
        )
        return ControlledEgressOutcome(
            status="blocked",
            decision=decision,
            receipt_jcs=receipt_jcs,
            receipt=json.loads(receipt_jcs),
            audit_id=audit_id,
            send_result=None,
        )

    # ALLOW path. Helper owns the HTTPS send.
    client_factory = _http_client_factory or httpx.Client
    started_at = time.monotonic()
    try:
        with client_factory(timeout=timeout_seconds) as client:
            response = client.request(
                method=normalized_method,
                url=f"https://{destination}{path}",
                headers=dict(headers) if headers is not None else None,
                content=body_bytes,
            )
    except Exception as exc:
        elapsed = time.monotonic() - started_at
        error_class = _sanitize_error_class(exc)
        receipt_jcs = _sign_outcome_receipt(
            agent_did=agent.did,
            destination=destination,
            method=normalized_method,
            credential_or_principal_class=credential_or_principal_class,
            payload_digest_hex=payload_digest_hex,
            policy_id=policy_id,
            decision_value="ALLOW",
            outcome="FAILED",
            signing_seed=agent._private_key,
        )
        return ControlledEgressOutcome(
            status="failed",
            decision=decision,
            receipt_jcs=receipt_jcs,
            receipt=json.loads(receipt_jcs),
            audit_id=audit_id,
            send_result={"elapsed_seconds": round(elapsed, 6)},
            error_class=error_class,
        )

    elapsed = time.monotonic() - started_at
    receipt_jcs = _sign_outcome_receipt(
        agent_did=agent.did,
        destination=destination,
        method=normalized_method,
        credential_or_principal_class=credential_or_principal_class,
        payload_digest_hex=payload_digest_hex,
        policy_id=policy_id,
        decision_value="ALLOW",
        outcome="SENT",
        signing_seed=agent._private_key,
    )
    return ControlledEgressOutcome(
        status="sent",
        decision=decision,
        receipt_jcs=receipt_jcs,
        receipt=json.loads(receipt_jcs),
        audit_id=audit_id,
        send_result={
            "status_code": int(getattr(response, "status_code", 0)),
            "elapsed_seconds": round(elapsed, 6),
        },
    )


__all__ = [
    "ACTION_NETWORK_EGRESS",
    "CRYPTOSUITE",
    "EVALUATOR_VERSION",
    "LEGACY_SCHEMA_VERSION",
    "PROOF_TYPE",
    "SCHEMA_VERSION",
    "ControlledEgressOutcome",
    "EgressPolicyViolationError",
    "EgressReceiptProofError",
    "EgressReceiptVerificationError",
    "controlled_egress",
    "sign_egress_receipt",
    "verify_egress_receipt",
]
