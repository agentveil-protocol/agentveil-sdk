"""decision_receipt/3 — W3C Data Integrity eddsa-jcs-2022 path (Step 2A).

First-party round-trip, tamper, and cross-rejection tests, plus an independent
"construction-A" recomputation that does not use the module's own helpers.

These are NOT a W3C-conformance claim: a passing third-party verifier (Step 2B)
is still required before claiming external conformance.
"""

from __future__ import annotations

import hashlib
import json

import base58
import jcs
import pytest
from nacl.signing import SigningKey, VerifyKey

from agentveil.delegation import _public_key_to_did
from agentveil.data_integrity import (
    CRYPTOSUITE,
    DATA_INTEGRITY_CONTEXT,
    DataIntegrityError,
    sign_eddsa_jcs_2022,
    verify_eddsa_jcs_2022,
)
from agentveil.proof import ProofVerificationError, verify_signed_jcs

SEED_A = bytes.fromhex("11" * 32)
SEED_B = bytes.fromhex("22" * 32)
DID_A = _public_key_to_did(bytes(SigningKey(SEED_A).verify_key))
DID_B = _public_key_to_did(bytes(SigningKey(SEED_B).verify_key))
VM_A = f"{DID_A}#{DID_A[len('did:key:'):]}"
AUDIT_ID = "urn:uuid:00000000-0000-4000-8000-000000000001"
CREATED = "2026-05-29T00:00:00Z"
PAYLOAD_HASH = "sha256:" + "a" * 64


def _v3_doc(*, payload_hash: str = PAYLOAD_HASH) -> dict:
    return {
        "@context": [DATA_INTEGRITY_CONTEXT],
        "schema_version": "decision_receipt/3",
        "audit_id": AUDIT_ID,
        "agent_did": "did:key:z6Mkagent",
        "action": "infra.volume.delete",
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "intent_hash": "9d25b5d6a8d9cee973cd95cc505b7bbdd6f7341015132ee6107c711cea372806",
        "payload_hash": payload_hash,
    }


def _sign_v2_raw(body: dict, seed: bytes = SEED_A) -> str:
    """Legacy decision_receipt/2 signing: Ed25519 over raw JCS(body)."""
    key = SigningKey(seed)
    did = _public_key_to_did(bytes(key.verify_key))
    signature = key.sign(jcs.canonicalize(body)).signature
    signed = {
        **body,
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": f"{did}#{did[len('did:key:'):]}",
            "proofValue": "z" + base58.b58encode(signature).decode("ascii"),
        },
    }
    return jcs.canonicalize(signed).decode("utf-8")


# 1. /3 round-trips under the new W3C verifier.
def test_v3_roundtrip_verifies():
    secured = sign_eddsa_jcs_2022(_v3_doc(), SEED_A, created=CREATED)
    result = verify_eddsa_jcs_2022(secured, expected_signer_did=DID_A)
    assert result["valid"] is True
    assert result["signer_did"] == DID_A
    assert result["schema_version"] == "decision_receipt/3"
    assert result["document"]["audit_id"] == AUDIT_ID
    secured_obj = json.loads(secured)
    proof = secured_obj["proof"]
    assert proof["type"] == "DataIntegrityProof"
    assert proof["cryptosuite"] == CRYPTOSUITE
    assert proof["proofPurpose"] == "assertionMethod"
    assert proof["created"] == CREATED
    assert proof["proofValue"].startswith("z")
    # The emitted proof must carry the document's @context (so proofConfig is
    # reproducible by a third party as proof-minus-proofValue, no injection).
    assert proof["@context"] == secured_obj["@context"]


# 2. A legacy /2 raw receipt must FAIL under the /3 W3C verifier.
def test_v2_raw_receipt_fails_under_v3_verifier():
    v2 = _sign_v2_raw({
        "schema_version": "decision_receipt/2",
        "audit_id": AUDIT_ID,
        "agent_did": "did:key:z6Mkagent",
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "payload_hash": PAYLOAD_HASH,
    })
    with pytest.raises(DataIntegrityError):
        verify_eddsa_jcs_2022(v2)


# 3. A /3 receipt must FAIL under the legacy raw /2 verifier.
def test_v3_fails_under_legacy_raw_verifier():
    secured = sign_eddsa_jcs_2022(_v3_doc(), SEED_A, created=CREATED)
    with pytest.raises(ProofVerificationError):
        verify_signed_jcs(secured)


# 4. Body tamper fails.
def test_body_tamper_fails():
    secured = json.loads(sign_eddsa_jcs_2022(_v3_doc(), SEED_A, created=CREATED))
    secured["decision"] = "ALLOW"
    with pytest.raises(DataIntegrityError):
        verify_eddsa_jcs_2022(jcs.canonicalize(secured).decode("utf-8"))


# 5. proofConfig tamper (verificationMethod is part of the hashed config) fails.
def test_proof_config_tamper_fails():
    secured = json.loads(sign_eddsa_jcs_2022(_v3_doc(), SEED_A, created=CREATED))
    secured["proof"]["verificationMethod"] = f"{DID_B}#{DID_B[len('did:key:'):]}"
    with pytest.raises(DataIntegrityError):
        verify_eddsa_jcs_2022(jcs.canonicalize(secured).decode("utf-8"))


# 6. Wrong key fails: (a) expected-signer mismatch and (b) vm claims A but B signed.
def test_wrong_key_fails():
    secured = sign_eddsa_jcs_2022(_v3_doc(), SEED_A, created=CREATED)
    with pytest.raises(DataIntegrityError):
        verify_eddsa_jcs_2022(secured, expected_signer_did=DID_B)

    doc = _v3_doc()
    proof_options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": VM_A,
        "proofPurpose": "assertionMethod",
        "created": CREATED,
        "@context": doc["@context"],
    }
    # proofConfig is the emitted proof options minus proofValue (no injection).
    hd = (
        hashlib.sha256(jcs.canonicalize(proof_options)).digest()
        + hashlib.sha256(jcs.canonicalize(doc)).digest()
    )
    proof_options["proofValue"] = "z" + base58.b58encode(
        SigningKey(SEED_B).sign(hd).signature
    ).decode("ascii")
    forged = jcs.canonicalize({**doc, "proof": proof_options}).decode("utf-8")
    with pytest.raises(DataIntegrityError):
        verify_eddsa_jcs_2022(forged)  # vm says A, signature by B


# 7. proofValue tamper fails.
def test_proof_value_tamper_fails():
    secured = json.loads(sign_eddsa_jcs_2022(_v3_doc(), SEED_A, created=CREATED))
    pv = secured["proof"]["proofValue"]
    secured["proof"]["proofValue"] = pv[:-1] + ("A" if pv[-1] != "A" else "B")
    with pytest.raises(DataIntegrityError):
        verify_eddsa_jcs_2022(jcs.canonicalize(secured).decode("utf-8"))


# 8. created is part of proofConfig: tampering it fails.
def test_created_tamper_fails():
    secured = json.loads(sign_eddsa_jcs_2022(_v3_doc(), SEED_A, created=CREATED))
    assert secured["proof"]["created"] == CREATED
    secured["proof"]["created"] = "2026-01-01T00:00:00Z"
    with pytest.raises(DataIntegrityError):
        verify_eddsa_jcs_2022(jcs.canonicalize(secured).decode("utf-8"))


# 9. Independent construction-A: recompute hashData and verify with raw nacl,
#    NOT using the module's verify/helpers.
def test_construction_a_independent():
    doc = _v3_doc()
    secured = json.loads(sign_eddsa_jcs_2022(doc, SEED_A, created=CREATED))
    proof = secured["proof"]

    unsecured = {k: v for k, v in secured.items() if k != "proof"}
    # proofConfig is exactly proof-minus-proofValue from the EMITTED receipt:
    # no manual @context injection (the emitted proof already carries it). This
    # mirrors what a third-party W3C verifier reconstructs.
    proof_config = {k: v for k, v in proof.items() if k != "proofValue"}
    assert proof_config["@context"] == unsecured["@context"]

    proof_config_canon = jcs.canonicalize(proof_config)
    transformed_document = jcs.canonicalize(unsecured)
    expected_hash_data = (
        hashlib.sha256(proof_config_canon).digest()
        + hashlib.sha256(transformed_document).digest()
    )
    signature = base58.b58decode(proof["proofValue"][1:])

    decoded = base58.b58decode(DID_A[len("did:key:z"):])
    assert decoded[:2] == b"\xed\x01"
    VerifyKey(decoded[2:]).verify(expected_hash_data, signature)  # raises if invalid
    assert len(expected_hash_data) == 64


# 10. A truncated proofValue signature (valid base58 but not 64 bytes) must fail
#     closed via DataIntegrityError instead of leaking a raw nacl ValueError.
def test_truncated_signature_fails_closed():
    secured = json.loads(sign_eddsa_jcs_2022(_v3_doc(), SEED_A, created=CREATED))
    full = base58.b58decode(secured["proof"]["proofValue"][1:])
    assert len(full) == 64
    secured["proof"]["proofValue"] = "z" + base58.b58encode(full[:32]).decode("ascii")
    with pytest.raises(DataIntegrityError):
        verify_eddsa_jcs_2022(jcs.canonicalize(secured).decode("utf-8"))


# 11. A short (10-byte) proofValue signature must raise the project's
#     DataIntegrityError type, not a raw nacl ValueError leaking from the verifier.
def test_short_signature_raises_data_integrity_error_not_raw_valueerror():
    secured = json.loads(sign_eddsa_jcs_2022(_v3_doc(), SEED_A, created=CREATED))
    secured["proof"]["proofValue"] = "z" + base58.b58encode(b"\x00" * 10).decode("ascii")
    with pytest.raises(DataIntegrityError) as excinfo:
        verify_eddsa_jcs_2022(jcs.canonicalize(secured).decode("utf-8"))
    # A raw leak would be type nacl.exceptions.ValueError; assert it is exactly the
    # project's DataIntegrityError type instead.
    assert type(excinfo.value) is DataIntegrityError
