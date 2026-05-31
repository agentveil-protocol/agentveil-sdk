#!/usr/bin/env python3
"""
Standalone delegation receipt verifier.

Reads a JSON delegation receipt from a file or stdin, verifies it offline,
and prints a structured result. Supports both legacy raw-JCS delegation proofs
and newer hashData proofs. No `agentveil` SDK dependency.

Dependencies (third-party):
  - pynacl       Ed25519 signature verification
  - base58       did:key + multibase decoding
  - jcs          RFC 8785 JSON Canonicalization Scheme

Install:
  pip install pynacl base58 jcs

Usage:
  python verify.py samples/valid.json
  cat samples/valid.json | python verify.py -
  python verify.py samples/expired.json   # exit 1, prints reason

Exit codes:
  0  receipt is valid
  1  receipt is invalid (signature, expiration, structure, or scope)
  2  usage / IO error

This file deliberately avoids importing `agentveil` so that an auditor
can verify a receipt without trusting the AVP SDK or backend.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import base58
import jcs
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
DELEGATION_CONTEXT_V1 = "https://agentveil.dev/contexts/delegation/v1.jsonld"
VC_TYPE = "VerifiableCredential"
DELEGATION_TYPE = "AgentDelegation"
CRYPTOSUITE = "eddsa-jcs-2022"
PROOF_TYPE = "DataIntegrityProof"
DEFAULT_PROOF_PURPOSE = "assertionMethod"
SUPPORTED_PREDICATES = ("max_spend", "allowed_category")


def _did_to_public_key(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError("issuer DID is not a did:key")
    decoded = base58.b58decode(did[len("did:key:z"):])
    if len(decoded) < 2 or decoded[0] != 0xED or decoded[1] != 0x01:
        raise ValueError("did:key is not Ed25519 multicodec")
    public_key = decoded[2:]
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key has wrong length")
    return public_key


def _parse_iso8601(raw: Any, field: str) -> datetime:
    if not isinstance(raw, str):
        raise ValueError(f"{field} must be a string")
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError(f"{field} is not ISO 8601 (YYYY-MM-DDTHH:MM:SSZ)")


def _validate_scope(scope: Any) -> None:
    if not isinstance(scope, list):
        raise ValueError("scope must be a list of predicate objects")
    for entry in scope:
        if not isinstance(entry, dict):
            raise ValueError("scope entries must be objects")
        predicate = entry.get("predicate")
        if predicate not in SUPPORTED_PREDICATES:
            raise ValueError(f"unsupported predicate: {predicate!r}")
        if predicate == "max_spend":
            currency = entry.get("currency")
            amount = entry.get("amount")
            if not isinstance(currency, str) or len(currency) != 3:
                raise ValueError("max_spend.currency must be a 3-letter ISO 4217 code")
            if not isinstance(amount, (int, float)) or amount <= 0:
                raise ValueError("max_spend.amount must be a positive number")
        elif predicate == "allowed_category":
            value = entry.get("value")
            if not isinstance(value, str) or not value:
                raise ValueError("allowed_category.value must be a non-empty string")


def _proof_configuration(proof: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in proof.items() if key != "proofValue"}


def _hash_data(proof_config: dict[str, Any], unsecured_document: dict[str, Any]) -> bytes:
    proof_config_hash = hashlib.sha256(jcs.canonicalize(proof_config)).digest()
    document_hash = hashlib.sha256(jcs.canonicalize(unsecured_document)).digest()
    return proof_config_hash + document_hash


def _verify_ed25519(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    reason: str,
) -> None:
    try:
        VerifyKey(public_key).verify(message, signature)
    except BadSignatureError:
        raise ValueError(reason)
    except ValueError:
        raise ValueError("signature is malformed")


def _verify_legacy_raw_jcs(
    receipt: dict[str, Any],
    issuer_public_key: bytes,
    signature: bytes,
) -> None:
    payload = {k: v for k, v in receipt.items() if k != "proof"}
    canonical = jcs.canonicalize(payload)
    _verify_ed25519(issuer_public_key, canonical, signature, "signature verification failed")


def _verify_hashdata_proof(
    receipt: dict[str, Any],
    proof: dict[str, Any],
    issuer_public_key: bytes,
    signature: bytes,
) -> None:
    if proof.get("proofPurpose") != DEFAULT_PROOF_PURPOSE:
        raise ValueError(f"proof.proofPurpose must be {DEFAULT_PROOF_PURPOSE!r}")

    unsecured_document = {key: value for key, value in receipt.items() if key != "proof"}
    if (
        "@context" in unsecured_document
        and proof.get("@context") != unsecured_document["@context"]
    ):
        raise ValueError("proof @context does not match document @context")

    proof_config = _proof_configuration(proof)
    message = _hash_data(proof_config, unsecured_document)
    _verify_ed25519(
        issuer_public_key,
        message,
        signature,
        "data integrity signature verification failed",
    )


def verify_delegation(receipt: dict, now: datetime | None = None) -> dict:
    """Return parsed fields on success. Raise ValueError(reason) on failure."""
    if not isinstance(receipt, dict):
        raise ValueError("receipt is not a JSON object")

    contexts = receipt.get("@context")
    if not isinstance(contexts, list) or VC_CONTEXT_V2 not in contexts:
        raise ValueError("@context missing W3C VC v2 base")
    if DELEGATION_CONTEXT_V1 not in contexts:
        raise ValueError("@context missing AgentVeil delegation v1 context")

    types = receipt.get("type")
    if not isinstance(types, list) or VC_TYPE not in types or DELEGATION_TYPE not in types:
        raise ValueError(f"type must include both {VC_TYPE!r} and {DELEGATION_TYPE!r}")

    issuer = receipt.get("issuer")
    if not isinstance(issuer, str):
        raise ValueError("issuer is required")
    issuer_public_key = _did_to_public_key(issuer)

    subject = receipt.get("credentialSubject", {})
    if not isinstance(subject, dict):
        raise ValueError("credentialSubject must be an object")
    agent_did = subject.get("id")
    if not isinstance(agent_did, str) or not agent_did.startswith("did:key:z"):
        raise ValueError("credentialSubject.id must be a did:key")
    _validate_scope(subject.get("scope"))
    if not isinstance(subject.get("purpose"), str):
        raise ValueError("credentialSubject.purpose must be a string")

    valid_from = _parse_iso8601(receipt.get("validFrom"), "validFrom")
    valid_until = _parse_iso8601(receipt.get("validUntil"), "validUntil")
    if valid_until <= valid_from:
        raise ValueError("validUntil must be after validFrom")

    current = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    if current < valid_from - timedelta(seconds=60):
        raise ValueError("delegation not yet valid (validFrom in the future)")
    if current > valid_until:
        raise ValueError("delegation expired")

    proof = receipt.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("proof is required")
    if proof.get("type") != PROOF_TYPE:
        raise ValueError(f"proof.type must be {PROOF_TYPE!r}")
    if proof.get("cryptosuite") != CRYPTOSUITE:
        raise ValueError(f"proof.cryptosuite must be {CRYPTOSUITE!r}")
    proof_value = proof.get("proofValue", "")
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise ValueError("proof.proofValue must be multibase-z (base58)")
    try:
        signature = base58.b58decode(proof_value[1:])
    except Exception:
        raise ValueError("proofValue is not valid base58")

    verification_method = proof.get("verificationMethod", "")
    if not isinstance(verification_method, str):
        raise ValueError("proof.verificationMethod must be a string")
    if verification_method.split("#", 1)[0] != issuer:
        raise ValueError("verificationMethod does not match issuer")

    if "proofPurpose" in proof:
        if "#" not in verification_method:
            raise ValueError("proof.verificationMethod is invalid")
        _verify_hashdata_proof(receipt, proof, issuer_public_key, signature)
    else:
        _verify_legacy_raw_jcs(receipt, issuer_public_key, signature)

    return {
        "valid": True,
        "issuer": issuer,
        "subject": agent_did,
        "scope": subject.get("scope"),
        "purpose": subject.get("purpose"),
        "valid_from": valid_from.isoformat(),
        "valid_until": valid_until.isoformat(),
        "id": receipt.get("id"),
    }


def _read_input(arg: str) -> dict:
    if arg == "-":
        return json.loads(sys.stdin.read())
    with open(arg, "r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python verify.py <receipt.json | ->\n")
        return 2
    try:
        receipt = _read_input(sys.argv[1])
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"could not read receipt: {exc}\n")
        return 2

    try:
        result = verify_delegation(receipt)
    except ValueError as exc:
        out = {"valid": False, "reason": str(exc)}
        print(json.dumps(out, indent=2))
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
