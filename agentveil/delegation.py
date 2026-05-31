"""
Agent delegation receipts — verifiable W3C VC v2.0 mandates.

A `DelegationReceipt` is a signed credential that records:
  - WHO delegated authority (issuer / principal)
  - TO WHOM (credentialSubject.id / agent)
  - WITHIN WHAT SCOPE (credentialSubject.scope predicates)
  - FOR WHAT PURPOSE (credentialSubject.purpose, free-text)
  - WHEN VALID (validFrom / validUntil)
  - SIGNED HOW (DataIntegrityProof / eddsa-jcs-2022)

The signing key is the principal's existing AVP Ed25519 keypair (did:key).
Verification is offline — see `examples/delegation/verify.py` for a
standalone reference verifier with no `agentveil` dependency.

Schema is STABLE: changing it after publication breaks signed receipts.
Any extension must add new optional predicates, never alter existing ones.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import base58
import jcs
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from agentveil._did import _public_key_to_did

# ---------------------------------------------------------------------------
# Constants — stable wire format. Do NOT change after publication.
# ---------------------------------------------------------------------------

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
DELEGATION_CONTEXT_V1 = "https://agentveil.dev/contexts/delegation/v1.jsonld"

VC_TYPE = "VerifiableCredential"
DELEGATION_TYPE = "AgentDelegation"

CRYPTOSUITE = "eddsa-jcs-2022"
PROOF_TYPE = "DataIntegrityProof"

SUPPORTED_PREDICATES = ("max_spend", "allowed_category")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class DelegationError(Exception):
    """Raised when a delegation receipt cannot be issued or parsed."""


class DelegationInvalid(Exception):
    """Raised by verifiers when a receipt fails validation. Carries reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# did:key helpers. ``_public_key_to_did`` lives in ``agentveil._did`` (imported
# above and re-exported here for backward-compatible imports); the decode-side
# helper below stays module-local because it raises ``DelegationInvalid``.
# ---------------------------------------------------------------------------

def _did_to_public_key(did: str) -> bytes:
    """Decode a did:key string to its 32-byte Ed25519 public key.

    Raises DelegationInvalid if the DID is malformed or non-Ed25519.
    """
    if not did.startswith("did:key:z"):
        raise DelegationInvalid("issuer DID is not a did:key")
    decoded = base58.b58decode(did[len("did:key:z"):])
    if len(decoded) < 2 or decoded[0] != 0xED or decoded[1] != 0x01:
        raise DelegationInvalid("did:key is not Ed25519 multicodec")
    public_key = decoded[2:]
    if len(public_key) != 32:
        raise DelegationInvalid("Ed25519 public key has wrong length")
    return public_key


# ---------------------------------------------------------------------------
# Scope predicate validation
# ---------------------------------------------------------------------------

def _validate_scope(scope: list[dict]) -> None:
    """Reject scope entries with unknown predicates or malformed shape.

    Schema v1 supports:
      - {"predicate": "max_spend", "currency": <ISO4217>, "amount": <number>}
      - {"predicate": "allowed_category", "value": <string>}
    """
    if not isinstance(scope, list):
        raise DelegationError("scope must be a list of predicate objects")

    for entry in scope:
        if not isinstance(entry, dict):
            raise DelegationError("scope entries must be objects")
        predicate = entry.get("predicate")
        if predicate not in SUPPORTED_PREDICATES:
            raise DelegationError(
                f"unsupported predicate: {predicate!r}. "
                f"v1 supports {SUPPORTED_PREDICATES}"
            )
        if predicate == "max_spend":
            currency = entry.get("currency")
            amount = entry.get("amount")
            if not isinstance(currency, str) or len(currency) != 3:
                raise DelegationError(
                    "max_spend.currency must be a 3-letter ISO 4217 code"
                )
            if not isinstance(amount, (int, float)) or amount <= 0:
                raise DelegationError("max_spend.amount must be a positive number")
        elif predicate == "allowed_category":
            value = entry.get("value")
            if not isinstance(value, str) or not value:
                raise DelegationError("allowed_category.value must be a non-empty string")


# ---------------------------------------------------------------------------
# Issue
# ---------------------------------------------------------------------------

def issue_delegation(
    principal_private_key: bytes,
    agent_did: str,
    scope: list[dict],
    purpose: str,
    valid_for: timedelta,
    *,
    valid_from: Optional[datetime] = None,
    receipt_id: Optional[str] = None,
) -> dict:
    """Sign a delegation receipt with the principal's Ed25519 private key.

    Args:
        principal_private_key: 32-byte Ed25519 secret seed.
        agent_did: did:key of the agent being authorized.
        scope: list of predicate objects (see SUPPORTED_PREDICATES).
        purpose: free-text human-readable description (audit aid; not enforced).
        valid_for: how long the delegation lasts after `valid_from`.
        valid_from: optional override (defaults to "now" UTC).
        receipt_id: optional override (defaults to `urn:uuid:<v4>`).

    Returns:
        A signed W3C VC v2.0 dict with a DataIntegrityProof / eddsa-jcs-2022.
    """
    if not isinstance(principal_private_key, (bytes, bytearray)) or len(principal_private_key) != 32:
        raise DelegationError("principal_private_key must be 32 bytes")
    if not isinstance(agent_did, str) or not agent_did.startswith("did:key:z"):
        raise DelegationError("agent_did must be a did:key string")
    if not isinstance(purpose, str):
        raise DelegationError("purpose must be a string")
    if not isinstance(valid_for, timedelta) or valid_for.total_seconds() <= 0:
        raise DelegationError("valid_for must be a positive timedelta")
    _validate_scope(scope)

    signing_key = SigningKey(bytes(principal_private_key))
    principal_public_key = bytes(signing_key.verify_key)
    principal_did = _public_key_to_did(principal_public_key)

    now = (valid_from or datetime.now(timezone.utc)).replace(microsecond=0)
    expires = now + valid_for
    rid = receipt_id or f"urn:uuid:{uuid.uuid4()}"

    payload: dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, DELEGATION_CONTEXT_V1],
        "type": [VC_TYPE, DELEGATION_TYPE],
        "id": rid,
        "issuer": principal_did,
        "validFrom": _format_iso8601(now),
        "validUntil": _format_iso8601(expires),
        "credentialSubject": {
            "id": agent_did,
            "scope": scope,
            "purpose": purpose,
        },
    }

    canonical = jcs.canonicalize(payload)
    signature = signing_key.sign(canonical).signature
    proof_value = "z" + base58.b58encode(signature).decode()
    verification_method = f"{principal_did}#{principal_did[len('did:key:'):]}"

    payload["proof"] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "verificationMethod": verification_method,
        "proofValue": proof_value,
    }
    return payload


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify_delegation(receipt: dict, *, now: Optional[datetime] = None) -> dict:
    """Verify a delegation receipt offline. No network calls.

    Returns a dict with parsed fields on success:
      {
        "valid": True,
        "issuer": "did:key:...",
        "subject": "did:key:...",
        "scope": [...],
        "purpose": "...",
        "valid_from": datetime,
        "valid_until": datetime,
        "id": "urn:uuid:...",
      }

    Raises DelegationInvalid(reason) on any failure (structure, expiration,
    signature, malformed DID, unsupported scope).
    """
    if not isinstance(receipt, dict):
        raise DelegationInvalid("receipt is not a JSON object")

    contexts = receipt.get("@context")
    if not isinstance(contexts, list) or VC_CONTEXT_V2 not in contexts:
        raise DelegationInvalid("@context missing W3C VC v2 base")
    if DELEGATION_CONTEXT_V1 not in contexts:
        raise DelegationInvalid("@context missing AgentVeil delegation v1 context")

    types = receipt.get("type")
    if not isinstance(types, list):
        raise DelegationInvalid("type must be a list")
    if VC_TYPE not in types or DELEGATION_TYPE not in types:
        raise DelegationInvalid(f"type must include both {VC_TYPE!r} and {DELEGATION_TYPE!r}")

    issuer = receipt.get("issuer")
    if not isinstance(issuer, str):
        raise DelegationInvalid("issuer is required")
    issuer_public_key = _did_to_public_key(issuer)

    subject = receipt.get("credentialSubject", {})
    if not isinstance(subject, dict):
        raise DelegationInvalid("credentialSubject must be an object")
    agent_did = subject.get("id")
    if not isinstance(agent_did, str) or not agent_did.startswith("did:key:z"):
        raise DelegationInvalid("credentialSubject.id must be a did:key")
    scope = subject.get("scope")
    try:
        _validate_scope(scope)
    except DelegationError as exc:
        raise DelegationInvalid(f"invalid scope: {exc}") from exc
    purpose = subject.get("purpose")
    if not isinstance(purpose, str):
        raise DelegationInvalid("credentialSubject.purpose must be a string")

    valid_from = _parse_iso8601(receipt.get("validFrom"), "validFrom")
    valid_until = _parse_iso8601(receipt.get("validUntil"), "validUntil")
    if valid_until <= valid_from:
        raise DelegationInvalid("validUntil must be after validFrom")

    current = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    if current < valid_from - timedelta(seconds=60):
        raise DelegationInvalid("delegation not yet valid (validFrom in the future)")
    if current > valid_until:
        raise DelegationInvalid("delegation expired")

    proof = receipt.get("proof")
    if not isinstance(proof, dict):
        raise DelegationInvalid("proof is required")
    if proof.get("type") != PROOF_TYPE:
        raise DelegationInvalid(f"proof.type must be {PROOF_TYPE!r}")
    if proof.get("cryptosuite") != CRYPTOSUITE:
        raise DelegationInvalid(f"proof.cryptosuite must be {CRYPTOSUITE!r}")
    proof_value = proof.get("proofValue", "")
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise DelegationInvalid("proof.proofValue must be multibase-z (base58)")
    try:
        signature = base58.b58decode(proof_value[1:])
    except Exception as exc:
        raise DelegationInvalid(f"proofValue not valid base58: {exc}") from exc

    verification_method = proof.get("verificationMethod", "")
    signer_did = verification_method.split("#")[0]
    if signer_did != issuer:
        raise DelegationInvalid("verificationMethod does not match issuer")

    payload = {k: v for k, v in receipt.items() if k != "proof"}
    canonical = jcs.canonicalize(payload)
    try:
        VerifyKey(issuer_public_key).verify(canonical, signature)
    except BadSignatureError as exc:
        raise DelegationInvalid("signature verification failed") from exc

    return {
        "valid": True,
        "issuer": issuer,
        "subject": agent_did,
        "scope": scope,
        "purpose": purpose,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "id": receipt.get("id"),
    }


# ---------------------------------------------------------------------------
# ISO 8601 helpers (UTC, second resolution — matches the rest of AVP)
# ---------------------------------------------------------------------------

def _format_iso8601(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso8601(raw: Optional[str], field: str) -> datetime:
    if not isinstance(raw, str):
        raise DelegationInvalid(f"{field} must be a string")
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise DelegationInvalid(f"{field} is not ISO 8601 (YYYY-MM-DDTHH:MM:SSZ)") from exc


__all__ = [
    "issue_delegation",
    "verify_delegation",
    "DelegationError",
    "DelegationInvalid",
    "VC_CONTEXT_V2",
    "DELEGATION_CONTEXT_V1",
    "DELEGATION_TYPE",
    "CRYPTOSUITE",
    "SUPPORTED_PREDICATES",
]
