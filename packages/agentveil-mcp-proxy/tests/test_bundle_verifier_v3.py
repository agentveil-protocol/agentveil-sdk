"""decision_receipt/3 in the evidence bundle verifier (Step 2C).

Hostile bundle tests proving the bundle verifier routes /3 receipts to the W3C
Data Integrity verifier, enforces the strict/proof-grade trust boundary, and
that /2 and /3 cannot cross the wrong verifier path.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import base58
import jcs
import pytest
from nacl.signing import SigningKey

from agentveil.delegation import _public_key_to_did
from agentveil.data_integrity import DATA_INTEGRITY_CONTEXT, sign_eddsa_jcs_2022
from agentveil.proof import ProofVerificationError, verify_signed_jcs
from agentveil_mcp_proxy.evidence import (
    GENESIS_PREV_EVENT_HASH,
    ApprovalEvidenceStore,
    ApprovalStatus,
    EvidenceVerificationError,
    PendingApproval,
    build_evidence_bundle,
    record_hash,
    verify_evidence_bundle,
)

PAYLOAD_HASH = "sha256:" + "a" * 64
POLICY_CONTEXT_HASH = "c" * 64
BACKEND_SEED = bytes.fromhex("11" * 32)
ATTACKER_SEED = bytes.fromhex("ff" * 32)
BACKEND_DID = _public_key_to_did(bytes(SigningKey(BACKEND_SEED).verify_key))
ATTACKER_DID = _public_key_to_did(bytes(SigningKey(ATTACKER_SEED).verify_key))
AUDIT_ID = "urn:uuid:00000000-0000-4000-8000-000000000001"
CREATED = "2026-05-29T00:00:00Z"


def _v3_receipt(*, seed: bytes = BACKEND_SEED, payload_hash: str = PAYLOAD_HASH) -> str:
    body = {
        "@context": [DATA_INTEGRITY_CONTEXT],
        "schema_version": "decision_receipt/3",
        "audit_id": AUDIT_ID,
        "agent_did": "did:key:z6Mkagent",
        "action": "infra.volume.delete",
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "intent_hash": "h" * 64,
        "payload_hash": payload_hash,
        "client_risk_class": "write",
        "client_policy_context_hash": POLICY_CONTEXT_HASH,
    }
    return sign_eddsa_jcs_2022(body, seed, created=CREATED)


def _v2_receipt(*, seed: bytes = BACKEND_SEED) -> str:
    """Legacy decision_receipt/2 (Ed25519 over raw JCS(body))."""
    body = {
        "schema_version": "decision_receipt/2",
        "audit_id": AUDIT_ID,
        "agent_did": "did:key:z6Mkagent",
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "payload_hash": PAYLOAD_HASH,
        "client_risk_class": "write",
        "client_policy_context_hash": POLICY_CONTEXT_HASH,
    }
    key = SigningKey(seed)
    did = _public_key_to_did(bytes(key.verify_key))
    sig = key.sign(jcs.canonicalize(body)).signature
    signed = {
        **body,
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": f"{did}#{did[len('did:key:'):]}",
            "proofValue": "z" + base58.b58encode(sig).decode("ascii"),
        },
    }
    return jcs.canonicalize(signed).decode("utf-8")


def _bundle(tmp_path: Path, *, receipt_jcs: str, trusted: tuple[str, ...] = (BACKEND_DID,)) -> dict:
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with ApprovalEvidenceStore(tmp_path / "evidence.sqlite") as store:
        store.write_pending(PendingApproval(
            request_id="req-1",
            session_id="session-1",
            client_id="client-1",
            downstream_server="infra",
            tool_name="volume.delete",
            action_class="write",
            risk_class="write",
            resource_hash=None,
            payload_hash=PAYLOAD_HASH,
            policy_id="policy-1",
            policy_rule_id="rule-1",
            policy_context_hash=POLICY_CONTEXT_HASH,
            status=ApprovalStatus.PENDING.value,
            created_at=1_700_000_000,
            expires_at=1_700_000_300,
            decision_audit_id=AUDIT_ID,
            decision_receipt_sha256=digest,
        ))
        return build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=list(trusted),
            receipt_fetcher=lambda audit_id: receipt_jcs,
        )


def _rechain(bundle: dict) -> dict:
    prev = GENESIS_PREV_EVENT_HASH
    for rec in bundle["records"]:
        rec["prev_event_hash"] = prev
        rec["record_hash"] = record_hash(rec)
        prev = rec["record_hash"]
    bundle["chain_root_hash"] = prev
    return bundle


def _replace_receipt(bundle: dict, new_receipt_jcs: str) -> dict:
    new_digest = hashlib.sha256(new_receipt_jcs.encode("utf-8")).hexdigest()
    bundle["signed_receipts"] = {new_digest: new_receipt_jcs}
    bundle["records"][0]["decision_receipt_sha256"] = new_digest
    return _rechain(bundle)


# 1. /3 valid bundle + external pinned signer -> PASS
def test_v3_bundle_valid_with_pinned_signer(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_v3_receipt())
    result = verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])
    assert result.valid is True
    assert result.signed_receipt_count == 1
    assert result.unverified_receipt_count == 0
    assert result.warnings == ()


# 2. /3 bundle without external signer (proof-grade default) -> FAIL
def test_v3_bundle_without_external_signer_fails(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_v3_receipt())
    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(bundle)  # strict default
    assert "externally supplied trusted_signer_dids" in str(exc.value)


# 3. /3 forged self-trusted bundle (attacker DID inside bundle) -> FAIL
def test_v3_forged_self_trusted_fails(tmp_path):
    forged = _bundle(
        tmp_path,
        receipt_jcs=_v3_receipt(seed=ATTACKER_SEED),
        trusted=(ATTACKER_DID,),
    )
    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(forged)  # in-bundle anchor must be ignored
    assert "externally supplied trusted_signer_dids" in str(exc.value)


# 4. /3 forged bundle + external legitimate signer -> FAIL
def test_v3_forged_with_external_legit_signer_fails(tmp_path):
    forged = _bundle(
        tmp_path,
        receipt_jcs=_v3_receipt(seed=ATTACKER_SEED),
        trusted=(ATTACKER_DID,),
    )
    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(forged, trusted_signer_dids=[BACKEND_DID])
    assert "not trusted" in str(exc.value)


# 5. /3 missing referenced receipt -> FAIL
def test_v3_missing_referenced_receipt_fails(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_v3_receipt())
    bundle["signed_receipts"] = {}
    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])
    assert "missing from bundle" in str(exc.value)


# 6. /3 body tamper -> FAIL
def test_v3_body_tamper_fails(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_v3_receipt())
    receipt = json.loads(next(iter(bundle["signed_receipts"].values())))
    receipt["decision"] = "ALLOW"
    _replace_receipt(bundle, jcs.canonicalize(receipt).decode("utf-8"))
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


# 7. /3 proofConfig tamper (created is part of the hashed proof config) -> FAIL
def test_v3_proof_config_tamper_fails(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_v3_receipt())
    receipt = json.loads(next(iter(bundle["signed_receipts"].values())))
    receipt["proof"]["created"] = "2020-01-01T00:00:00Z"
    _replace_receipt(bundle, jcs.canonicalize(receipt).decode("utf-8"))
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


# 8. /3 proofValue tamper -> FAIL
def test_v3_proof_value_tamper_fails(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_v3_receipt())
    receipt = json.loads(next(iter(bundle["signed_receipts"].values())))
    pv = receipt["proof"]["proofValue"]
    receipt["proof"]["proofValue"] = pv[:-1] + ("A" if pv[-1] != "A" else "B")
    _replace_receipt(bundle, jcs.canonicalize(receipt).decode("utf-8"))
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


# 9. /3 wrong key -> FAIL (receipt signed by attacker, verified against backend)
def test_v3_wrong_key_fails(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_v3_receipt(seed=ATTACKER_SEED))
    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])
    assert "not trusted" in str(exc.value)


# 10. /2 still works on its own (raw) path
def test_v2_bundle_still_verifies_on_v2_path(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_v2_receipt())
    result = verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])
    assert result.valid is True
    assert result.signed_receipt_count == 1


# 11. /3 never verifies via the old raw verifier path.
def test_v3_never_verifies_via_raw_path(tmp_path):
    # (a) the raw /2 verifier rejects a /3 receipt directly.
    v3 = _v3_receipt()
    with pytest.raises(ProofVerificationError):
        verify_signed_jcs(v3, expected_signer_did=BACKEND_DID)

    # (b) mislabeling a /3 receipt as /2 routes it to the raw path in the
    #     bundle verifier, where its hashData signature does not reproduce.
    bundle = _bundle(tmp_path, receipt_jcs=v3)
    receipt = json.loads(next(iter(bundle["signed_receipts"].values())))
    receipt["schema_version"] = "decision_receipt/2"  # claim /2, still /3-signed
    _replace_receipt(bundle, jcs.canonicalize(receipt).decode("utf-8"))
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])
