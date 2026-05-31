"""W3C Data Integrity ``eddsa-jcs-2022`` construction (decision_receipt/3).

This is the standards-shaped signing/verification path. Unlike the legacy
``decision_receipt/2`` path (which signs the raw JCS of the body), the signature
here covers the W3C Data Integrity ``hashData``::

    hashData = SHA256(JCS(proofConfig)) || SHA256(JCS(unsecuredDocument))

where ``proofConfig`` is the emitted proof options without ``proofValue``. When
the document has a top-level ``@context`` it is copied into the emitted ``proof``
before signing, so ``proofConfig`` is reconstructible directly from the secured
document (``proof`` minus ``proofValue``) by any verifier — there is no
document-side ``@context`` injection.

First-party only for now. A passing **third-party** verifier (Digital Bazaar
``@digitalbazaar/eddsa-jcs-2022-cryptosuite`` is the Step 2B candidate) is
required before any external "W3C conformant" claim is made. The self-written
verifier below is sufficient for first-party round-trip and tamper tests, not
for an external-conformance claim.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

import base58
import jcs
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from agentveil.delegation import _public_key_to_did

PROOF_TYPE = "DataIntegrityProof"
CRYPTOSUITE = "eddsa-jcs-2022"
DEFAULT_PROOF_PURPOSE = "assertionMethod"
# Context for a non-VC Data Integrity secured document. The exact value must be
# reconciled with the chosen third-party verifier's document loader in Step 2B.
DATA_INTEGRITY_CONTEXT = "https://w3id.org/security/data-integrity/v2"


class DataIntegrityError(ValueError):
    """Raised on malformed input or signature failure for eddsa-jcs-2022."""


def _did_to_public_key(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise DataIntegrityError("signer DID must be did:key")
    try:
        decoded = base58.b58decode(did[len("did:key:z"):])
    except Exception as exc:  # noqa: BLE001
        raise DataIntegrityError("signer DID is not valid base58") from exc
    if len(decoded) < 2 or decoded[:2] != b"\xed\x01":
        raise DataIntegrityError("signer DID is not Ed25519 did:key")
    public_key = decoded[2:]
    if len(public_key) != 32:
        raise DataIntegrityError("signer DID has invalid Ed25519 public key")
    return public_key


def proof_configuration(proof: dict[str, Any]) -> dict[str, Any]:
    """The hashed proof configuration: the emitted proof options without
    ``proofValue``.

    The proof already carries ``@context`` (copied from the document at signing
    time per W3C eddsa-jcs-2022), so the configuration is reproducible by any
    third-party verifier directly from the emitted secured document. There is no
    document-side ``@context`` injection — what is hashed is exactly what is
    emitted.
    """
    return {key: value for key, value in proof.items() if key != "proofValue"}


def hash_data(proof_config: dict[str, Any], unsecured_document: dict[str, Any]) -> bytes:
    """W3C eddsa-jcs-2022 hashData: SHA256(JCS(proofConfig)) || SHA256(JCS(doc))."""
    proof_config_hash = hashlib.sha256(jcs.canonicalize(proof_config)).digest()
    document_hash = hashlib.sha256(jcs.canonicalize(unsecured_document)).digest()
    return proof_config_hash + document_hash


def sign_eddsa_jcs_2022(
    unsecured_document: dict[str, Any],
    signing_seed: bytes,
    *,
    proof_purpose: str = DEFAULT_PROOF_PURPOSE,
    created: Optional[str] = None,
) -> str:
    """Secure ``unsecured_document`` with an eddsa-jcs-2022 DataIntegrityProof.

    Returns the JCS-canonical text of the secured document. ``unsecured_document``
    MUST NOT already contain a ``proof`` member.
    """
    if not isinstance(unsecured_document, dict):
        raise DataIntegrityError("unsecured_document must be a dict")
    if "proof" in unsecured_document:
        raise DataIntegrityError("unsecured_document must not include 'proof'")
    if not isinstance(signing_seed, (bytes, bytearray)) or len(signing_seed) != 32:
        raise DataIntegrityError("signing_seed must be 32 bytes")

    signing_key = SigningKey(bytes(signing_seed))
    issuer_did = _public_key_to_did(bytes(signing_key.verify_key))
    verification_method = f"{issuer_did}#{issuer_did[len('did:key:'):]}"

    proof_options: dict[str, Any] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }
    if created is not None:
        proof_options["created"] = created
    # The emitted proof carries the document's @context so the proof
    # configuration (proof minus proofValue) is reproducible by a third-party
    # verifier directly from the secured document — no hidden injection.
    if "@context" in unsecured_document:
        proof_options["@context"] = unsecured_document["@context"]

    proof_config = proof_configuration(proof_options)
    signature = signing_key.sign(hash_data(proof_config, unsecured_document)).signature
    proof_options["proofValue"] = "z" + base58.b58encode(signature).decode("ascii")

    secured = {**unsecured_document, "proof": proof_options}
    return jcs.canonicalize(secured).decode("utf-8")


def verify_eddsa_jcs_2022(
    secured_jcs: str,
    *,
    expected_signer_did: Optional[str] = None,
) -> dict[str, Any]:
    """Verify one eddsa-jcs-2022 DataIntegrityProof via the W3C hashData rule.

    Returns the unsecured document and signer DID on success. Raises
    ``DataIntegrityError`` on any structural or signature failure (fail closed).
    """
    if not isinstance(secured_jcs, str) or not secured_jcs:
        raise DataIntegrityError("secured_jcs must be a non-empty string")
    try:
        secured = json.loads(secured_jcs)
    except json.JSONDecodeError as exc:
        raise DataIntegrityError("secured_jcs is not valid JSON") from exc
    if not isinstance(secured, dict):
        raise DataIntegrityError("secured_jcs must decode to a JSON object")

    proof = secured.get("proof")
    if not isinstance(proof, dict):
        raise DataIntegrityError("proof is missing")
    if proof.get("type") != PROOF_TYPE:
        raise DataIntegrityError("proof.type must be DataIntegrityProof")
    if proof.get("cryptosuite") != CRYPTOSUITE:
        raise DataIntegrityError("proof.cryptosuite must be eddsa-jcs-2022")
    if proof.get("proofPurpose") != DEFAULT_PROOF_PURPOSE:
        raise DataIntegrityError("proof.proofPurpose must be assertionMethod")

    verification_method = proof.get("verificationMethod")
    if not isinstance(verification_method, str) or "#" not in verification_method:
        raise DataIntegrityError("proof.verificationMethod is invalid")
    signer_did = verification_method.split("#", 1)[0]
    if expected_signer_did is not None and signer_did != expected_signer_did:
        raise DataIntegrityError("receipt signer does not match expected signer")

    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise DataIntegrityError("proof.proofValue must be multibase-z")
    try:
        signature = base58.b58decode(proof_value[1:])
    except Exception as exc:  # noqa: BLE001
        raise DataIntegrityError("proof.proofValue is not valid base58") from exc

    unsecured_document = {key: value for key, value in secured.items() if key != "proof"}
    # W3C verify: the proof must carry the same @context as the document, so the
    # proof configuration is exactly "proof minus proofValue" with no injection.
    if "@context" in unsecured_document and proof.get("@context") != unsecured_document["@context"]:
        raise DataIntegrityError("proof @context does not match document @context")
    proof_config = proof_configuration(proof)
    verify_key = VerifyKey(_did_to_public_key(signer_did))
    message = hash_data(proof_config, unsecured_document)
    try:
        verify_key.verify(message, signature)
    except BadSignatureError as exc:
        raise DataIntegrityError("eddsa-jcs-2022 signature verification failed") from exc
    except ValueError as exc:
        # A malformed/truncated proofValue (signature not exactly 64 bytes) makes
        # PyNaCl raise a raw ValueError; re-raise it through the DataIntegrityError
        # contract instead of leaking the lower-level nacl exception.
        raise DataIntegrityError("signature is malformed") from exc

    return {
        "valid": True,
        "document": unsecured_document,
        "signer_did": signer_did,
        "schema_version": unsecured_document.get("schema_version"),
        "cryptosuite": CRYPTOSUITE,
    }


__all__ = [
    "PROOF_TYPE",
    "CRYPTOSUITE",
    "DEFAULT_PROOF_PURPOSE",
    "DATA_INTEGRITY_CONTEXT",
    "DataIntegrityError",
    "proof_configuration",
    "hash_data",
    "sign_eddsa_jcs_2022",
    "verify_eddsa_jcs_2022",
]
