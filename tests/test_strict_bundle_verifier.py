"""Strict offline bundle verifier semantics (Proof Layer Hardening Step 1).

Covers Conformance Pass findings F2 (self-trusted bundle) and F3 (missing
referenced receipt downgraded to a warning). These tests assert hard failure
status in strict mode, not warnings. They intentionally stay on the existing
``decision_receipt/2`` raw-JCS receipt format; W3C ``/3`` is a separate step.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import base58
import jcs
import pytest
from nacl.signing import SigningKey

from agentveil.delegation import _public_key_to_did
from agentveil_mcp_proxy.evidence import (
    GENESIS_PREV_EVENT_HASH,
    ApprovalEvidenceStore,
    ApprovalStatus,
    EvidenceVerificationError,
    PendingApproval,
    build_evidence_bundle,
    record_hash,
    verify_evidence_bundle,
    verify_evidence_bundle_file,
)

PAYLOAD_HASH = "sha256:" + "a" * 64
POLICY_CONTEXT_HASH = "c" * 64
BACKEND_SEED = bytes.fromhex("11" * 32)
ATTACKER_SEED = bytes.fromhex("ff" * 32)
BACKEND_DID = _public_key_to_did(bytes(SigningKey(BACKEND_SEED).verify_key))
ATTACKER_DID = _public_key_to_did(bytes(SigningKey(ATTACKER_SEED).verify_key))
AUDIT_ID = "urn:uuid:00000000-0000-4000-8000-000000000001"


def _signed_receipt(*, seed: bytes = BACKEND_SEED, payload_hash: str = PAYLOAD_HASH) -> str:
    """Build a decision_receipt/2 signed with the current raw-JCS scheme."""
    body = {
        "schema_version": "decision_receipt/2",
        "audit_id": AUDIT_ID,
        "agent_did": "did:key:z6Mkagent",
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "payload_hash": payload_hash,
        "client_risk_class": "write",
        "client_policy_context_hash": POLICY_CONTEXT_HASH,
    }
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


def _bundle(tmp_path: Path, *, receipt_jcs: str, trusted: tuple[str, ...] = (BACKEND_DID,)) -> dict:
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with ApprovalEvidenceStore(tmp_path / "evidence.sqlite") as store:
        store.write_pending(PendingApproval(
            request_id="req-1",
            session_id="session-1",
            client_id="client-1",
            downstream_server="github",
            tool_name="create_issue",
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
    """Recompute the record_hash chain so only the targeted tamper is tested."""
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


# 1. valid bundle + pinned signer -> PASS
def test_valid_bundle_with_pinned_signer_passes(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_signed_receipt())
    result = verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID], strict=True)
    assert result.valid is True
    assert result.signed_receipt_count == 1
    assert result.unverified_receipt_count == 0
    assert result.warnings == ()


# 2. valid bundle without external signer in strict mode -> FAIL
def test_valid_bundle_without_external_signer_fails_strict(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_signed_receipt())
    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(bundle, strict=True)
    assert "externally supplied trusted_signer_dids" in str(exc.value)


# 3. forged bundle + attacker DID inside bundle -> FAIL (in-bundle trust ignored)
def test_forged_self_trusted_bundle_fails_strict(tmp_path):
    forged = _bundle(
        tmp_path,
        receipt_jcs=_signed_receipt(seed=ATTACKER_SEED),
        trusted=(ATTACKER_DID,),  # attacker vouches for itself inside the bundle
    )
    # No external signer: strict must not fall back to the in-bundle anchor.
    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(forged, strict=True)
    assert "externally supplied trusted_signer_dids" in str(exc.value)


# 4. forged bundle + external legitimate signer -> FAIL (attacker signature rejected)
def test_forged_bundle_with_external_legit_signer_fails_strict(tmp_path):
    forged = _bundle(
        tmp_path,
        receipt_jcs=_signed_receipt(seed=ATTACKER_SEED),
        trusted=(ATTACKER_DID,),
    )
    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(forged, trusted_signer_dids=[BACKEND_DID], strict=True)
    assert "not trusted" in str(exc.value)


# 5. missing referenced signed receipt -> FAIL (F3)
def test_missing_referenced_receipt_fails_strict(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_signed_receipt())
    bundle["signed_receipts"] = {}  # record still references the now-absent receipt
    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID], strict=True)
    assert "missing from bundle" in str(exc.value)


# 6. receipt body tamper -> FAIL
def test_receipt_body_tamper_fails_strict(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_signed_receipt())
    receipt = json.loads(next(iter(bundle["signed_receipts"].values())))
    receipt["decision"] = "ALLOW"  # flip decision without re-signing
    tampered = jcs.canonicalize(receipt).decode("utf-8")
    _replace_receipt(bundle, tampered)
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID], strict=True)


# 7. proofValue tamper -> FAIL
def test_proof_value_tamper_fails_strict(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_signed_receipt())
    receipt = json.loads(next(iter(bundle["signed_receipts"].values())))
    pv = receipt["proof"]["proofValue"]
    receipt["proof"]["proofValue"] = pv[:-1] + ("A" if pv[-1] != "A" else "B")
    tampered = jcs.canonicalize(receipt).decode("utf-8")
    _replace_receipt(bundle, tampered)
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID], strict=True)


# 8. verificationMethod tamper -> FAIL (key substitution rejected against pinned signer)
def test_verification_method_tamper_fails_strict(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_signed_receipt())
    receipt = json.loads(next(iter(bundle["signed_receipts"].values())))
    receipt["proof"]["verificationMethod"] = (
        f"{ATTACKER_DID}#{ATTACKER_DID[len('did:key:'):]}"
    )
    tampered = jcs.canonicalize(receipt).decode("utf-8")
    _replace_receipt(bundle, tampered)
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID], strict=True)


# Legacy (strict=False) behavior is explicitly preserved and is NOT proof-grade.
def test_legacy_mode_still_self_trusts_and_warns_on_missing_receipt(tmp_path):
    # Self-trust fallback (the F2 behavior) survives ONLY under strict=False.
    bundle = _bundle(tmp_path, receipt_jcs=_signed_receipt())
    assert verify_evidence_bundle(bundle, strict=False).valid is True

    # Missing referenced receipt is a warning, not a failure, under legacy mode.
    missing = copy.deepcopy(bundle)
    missing["signed_receipts"] = {}
    legacy = verify_evidence_bundle(missing, strict=False)
    assert legacy.valid is True
    assert legacy.unverified_receipt_count == 1


# verify_evidence_bundle_file threads strict through to the same semantics.
def test_verify_file_strict_requires_external_signer(tmp_path):
    bundle = _bundle(tmp_path, receipt_jcs=_signed_receipt())
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert verify_evidence_bundle_file(
        path, trusted_signer_dids=[BACKEND_DID], strict=True
    ).valid is True
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle_file(path, strict=True)
