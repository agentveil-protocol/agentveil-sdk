"""Offline proof verifier tests."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import base58
import jcs
import pytest
from nacl.signing import SigningKey

from agentveil.data_integrity import DATA_INTEGRITY_CONTEXT, sign_eddsa_jcs_2022
from agentveil.delegation import _public_key_to_did, issue_delegation
from agentveil.proof import (
    ProofVerificationError,
    verify_proof_packet,
    verify_signed_jcs,
)


BACKEND_SEED = bytes.fromhex("11" * 32)
OTHER_BACKEND_SEED = bytes.fromhex("22" * 32)
APPROVAL_BACKEND_SEED = bytes.fromhex("55" * 32)
PRINCIPAL_SEED = bytes.fromhex("33" * 32)
AGENT_SEED = bytes.fromhex("44" * 32)

BACKEND_DID = _public_key_to_did(bytes(SigningKey(BACKEND_SEED).verify_key))
OTHER_BACKEND_DID = _public_key_to_did(bytes(SigningKey(OTHER_BACKEND_SEED).verify_key))
APPROVAL_BACKEND_DID = _public_key_to_did(
    bytes(SigningKey(APPROVAL_BACKEND_SEED).verify_key)
)
AGENT_DID = _public_key_to_did(bytes(SigningKey(AGENT_SEED).verify_key))


def _sign_jcs(body: dict, seed: bytes = BACKEND_SEED) -> str:
    key = SigningKey(seed)
    signer_did = _public_key_to_did(bytes(key.verify_key))
    canonical = jcs.canonicalize(body)
    signature = key.sign(canonical).signature
    signed = {
        **body,
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": f"{signer_did}#{signer_did[len('did:key:'):]}",
            "proofValue": "z" + base58.b58encode(signature).decode("ascii"),
        },
    }
    return jcs.canonicalize(signed).decode("utf-8")


def _delegation_receipt() -> dict:
    return issue_delegation(
        principal_private_key=PRINCIPAL_SEED,
        agent_did=AGENT_DID,
        scope=[{"predicate": "allowed_category", "value": "infrastructure"}],
        purpose="proof verifier test",
        valid_for=timedelta(hours=1),
    )


def _base_decision_body(delegation: dict) -> dict:
    delegation_hash = hashlib.sha256(jcs.canonicalize(delegation)).hexdigest()
    return {
        "schema_version": "decision_receipt/2",
        "audit_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "agent_did": AGENT_DID,
        "action": "infra.resource.inspect",
        "resource": "resource:vol-1",
        "environment": "development",
        "decision": "ALLOW",
        "reason": "read_action",
        "intent_hash": "aa" * 32,
        "delegation_receipt_id": delegation["id"],
        "delegation_receipt_hash": delegation_hash,
    }


def _execution_body(decision_jcs: str) -> dict:
    return {
        "schema_version": "execution_receipt/2",
        "receipt_id": "urn:uuid:22222222-2222-4222-8222-222222222222",
        "gate_audit_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "agent_did": AGENT_DID,
        "action": "infra.resource.inspect",
        "resource": "resource:vol-1",
        "environment": "development",
        "status": "SUCCESS",
        "adapter": "mock",
        "operation": "inspect",
        "idempotency_key": "idem",
        "params_hash": "bb" * 32,
        "request_shape_hash": "cc" * 32,
        "decision_receipt_hash": hashlib.sha256(decision_jcs.encode("utf-8")).hexdigest(),
        "started_at": "2026-04-30T00:00:00Z",
        "completed_at": "2026-04-30T00:00:01Z",
        "evaluator_version": "execution-runtime/0.1.0",
    }


def _approval_body(decision_jcs: str, delegation: dict) -> dict:
    delegation_hash = hashlib.sha256(jcs.canonicalize(delegation)).hexdigest()
    return {
        "schema_version": "human_approval_receipt/2",
        "approval_id": "urn:uuid:33333333-3333-4333-8333-333333333333",
        "gate_audit_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "requester_agent_did": AGENT_DID,
        "principal_did": delegation["issuer"],
        "action": "infra.resource.inspect",
        "resource": "resource:vol-1",
        "environment": "development",
        "risk_class": "read",
        "gate_reason": "read_action",
        "decision": "APPROVED",
        "reason": "",
        "requested_at": "2026-04-30T00:00:00Z",
        "decided_at": "2026-04-30T00:00:01Z",
        "expires_at": "2026-04-30T01:00:00Z",
        "evaluator_version": "human-control/0.1.0",
        "delegation_receipt_id": delegation["id"],
        "delegation_receipt_hash": delegation_hash,
        "decision_receipt_hash": hashlib.sha256(decision_jcs.encode("utf-8")).hexdigest(),
    }


def _packet(*, with_approval: bool = False) -> dict:
    delegation = _delegation_receipt()
    decision_jcs = _sign_jcs(_base_decision_body(delegation))
    execution = _execution_body(decision_jcs)
    approval_jcs = None
    if with_approval:
        approval_jcs = _sign_jcs(_approval_body(decision_jcs, delegation))
        execution["approval_receipt_hash"] = hashlib.sha256(
            approval_jcs.encode("utf-8")
        ).hexdigest()
    execution_jcs = _sign_jcs(execution)
    return {
        "agent_did": AGENT_DID,
        "base_url": "https://agentveil.dev",
        "sdk_version": "0.7.4",
        "generated_at": "2026-04-30T00:00:00Z",
        "delegation_receipt": delegation,
        "outcome_status": "executed",
        "audit_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "decision_receipt_jcs": decision_jcs,
        "execution_receipt_jcs": execution_jcs,
        "approval_receipt_jcs": approval_jcs,
    }


def test_verify_signed_jcs_valid_signature_passes():
    receipt_jcs = _sign_jcs({"schema_version": "decision_receipt/2", "x": 1})

    verified = verify_signed_jcs(receipt_jcs, expected_signer_did=BACKEND_DID)

    assert verified["valid"] is True
    assert verified["signer_did"] == BACKEND_DID
    assert verified["schema_version"] == "decision_receipt/2"
    assert verified["digest"] == hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()


def test_verify_signed_jcs_tamper_fails():
    receipt = json.loads(_sign_jcs({"schema_version": "decision_receipt/2", "x": 1}))
    receipt["x"] = 2
    tampered = jcs.canonicalize(receipt).decode("utf-8")

    with pytest.raises(ProofVerificationError):
        verify_signed_jcs(tampered)


def test_verify_signed_jcs_wrong_expected_signer_fails():
    receipt_jcs = _sign_jcs({"schema_version": "decision_receipt/2", "x": 1})

    with pytest.raises(ProofVerificationError):
        verify_signed_jcs(receipt_jcs, expected_signer_did=OTHER_BACKEND_DID)


def test_verify_proof_packet_no_approval_flow_passes():
    result = verify_proof_packet(_packet(), trusted_backend_signer_dids=[BACKEND_DID])

    assert result["valid"] is True
    assert result["approval_receipt"] is None
    assert result["execution_receipt"]["body"]["status"] == "SUCCESS"


def test_verify_proof_packet_role_specific_trust_passes():
    packet = _packet(with_approval=True)
    approval_body = {
        key: value
        for key, value in json.loads(packet["approval_receipt_jcs"]).items()
        if key != "proof"
    }
    approval_jcs = _sign_jcs(approval_body, seed=APPROVAL_BACKEND_SEED)
    packet["approval_receipt_jcs"] = approval_jcs
    execution_body = {
        key: value
        for key, value in json.loads(packet["execution_receipt_jcs"]).items()
        if key != "proof"
    }
    execution_body["approval_receipt_hash"] = hashlib.sha256(
        approval_jcs.encode("utf-8")
    ).hexdigest()
    packet["execution_receipt_jcs"] = _sign_jcs(execution_body)

    result = verify_proof_packet(
        packet,
        trusted_decision_signer_dids=[BACKEND_DID],
        trusted_execution_signer_dids=[BACKEND_DID],
        trusted_human_approval_signer_dids=[APPROVAL_BACKEND_DID],
    )

    assert result["approval_receipt"]["signer_did"] == APPROVAL_BACKEND_DID


def test_verify_proof_packet_untrusted_backend_signer_fails():
    with pytest.raises(ProofVerificationError):
        verify_proof_packet(_packet(), trusted_backend_signer_dids=[OTHER_BACKEND_DID])


def test_executed_packet_without_execution_receipt_fails():
    packet = _packet()
    packet.pop("execution_receipt_jcs")

    with pytest.raises(ProofVerificationError, match="missing ExecutionReceipt"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


def test_blocked_packet_with_allow_decision_fails():
    packet = _packet()
    packet["outcome_status"] = "blocked"
    packet.pop("execution_receipt_jcs")

    with pytest.raises(ProofVerificationError, match="requires BLOCK"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


def test_blocked_packet_with_execution_receipt_fails():
    delegation = _delegation_receipt()
    decision_body = {
        **_base_decision_body(delegation),
        "decision": "BLOCK",
        "reason": "capability_not_approvable",
    }
    decision_jcs = _sign_jcs(decision_body)
    packet = {
        "agent_did": AGENT_DID,
        "delegation_receipt": delegation,
        "outcome_status": "blocked",
        "audit_id": decision_body["audit_id"],
        "decision_receipt_jcs": decision_jcs,
        "execution_receipt_jcs": _sign_jcs(_execution_body(decision_jcs)),
    }

    with pytest.raises(ProofVerificationError, match="must not include ExecutionReceipt"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


def test_approval_required_packet_with_allow_decision_fails():
    packet = _packet()
    packet["outcome_status"] = "approval_required"
    packet.pop("execution_receipt_jcs")

    with pytest.raises(ProofVerificationError, match="WAITING_FOR_HUMAN_APPROVAL"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


def test_verify_proof_packet_mismatched_decision_execution_hash_fails():
    packet = _packet()
    execution = json.loads(packet["execution_receipt_jcs"])
    execution["decision_receipt_hash"] = "00" * 32
    packet["execution_receipt_jcs"] = _sign_jcs({
        key: value for key, value in execution.items() if key != "proof"
    })

    with pytest.raises(ProofVerificationError, match="decision_receipt_hash"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


@pytest.mark.parametrize("field", ["agent_did", "action", "resource", "environment"])
def test_verify_proof_packet_mismatched_intent_fields_fail(field):
    packet = _packet()
    execution = json.loads(packet["execution_receipt_jcs"])
    execution[field] = "changed" if field != "environment" else "production"
    packet["execution_receipt_jcs"] = _sign_jcs({
        key: value for key, value in execution.items() if key != "proof"
    })

    with pytest.raises(ProofVerificationError, match=field):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


@pytest.mark.parametrize("field", ["action", "resource", "environment"])
def test_execution_v2_missing_shared_intent_field_fails(field):
    packet = _packet()
    execution = json.loads(packet["execution_receipt_jcs"])
    execution.pop(field)
    packet["execution_receipt_jcs"] = _sign_jcs({
        key: value for key, value in execution.items() if key != "proof"
    })

    with pytest.raises(ProofVerificationError, match=f"execution.{field} is required"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


@pytest.mark.parametrize("field", ["action", "requester_agent_did"])
def test_approval_v2_missing_shared_intent_field_fails(field):
    packet = _packet(with_approval=True)
    approval = json.loads(packet["approval_receipt_jcs"])
    approval.pop(field)
    approval_jcs = _sign_jcs({
        key: value for key, value in approval.items() if key != "proof"
    })
    packet["approval_receipt_jcs"] = approval_jcs
    execution = json.loads(packet["execution_receipt_jcs"])
    execution["approval_receipt_hash"] = hashlib.sha256(
        approval_jcs.encode("utf-8")
    ).hexdigest()
    packet["execution_receipt_jcs"] = _sign_jcs({
        key: value for key, value in execution.items() if key != "proof"
    })

    with pytest.raises(ProofVerificationError, match=f"approval.{field} is required"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


def test_approval_path_requires_approval_receipt():
    packet = _packet(with_approval=True)
    packet["approval_receipt_jcs"] = None

    with pytest.raises(ProofVerificationError, match="approval receipt is required"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


def test_approval_required_packet_requires_approval_receipt():
    packet = _packet()
    packet["outcome_status"] = "approval_required"
    packet.pop("execution_receipt_jcs")
    decision_body = {
        key: value
        for key, value in json.loads(packet["decision_receipt_jcs"]).items()
        if key != "proof"
    }
    decision_body["decision"] = "WAITING_FOR_HUMAN_APPROVAL"
    decision_body["reason"] = "destructive_production_action"
    packet["decision_receipt_jcs"] = _sign_jcs(decision_body)

    with pytest.raises(ProofVerificationError, match="approval receipt is required"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])


def test_approval_path_passes_with_approval_receipt():
    packet = _packet(with_approval=True)

    result = verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])

    assert result["approval_receipt"]["body"]["decision"] == "APPROVED"


def test_execution_signed_by_approval_signer_role_fails():
    packet = _packet()
    execution_body = {
        key: value
        for key, value in json.loads(packet["execution_receipt_jcs"]).items()
        if key != "proof"
    }
    packet["execution_receipt_jcs"] = _sign_jcs(execution_body, seed=APPROVAL_BACKEND_SEED)

    with pytest.raises(ProofVerificationError, match="ExecutionReceipt signer"):
        verify_proof_packet(
            packet,
            trusted_decision_signer_dids=[BACKEND_DID],
            trusted_execution_signer_dids=[BACKEND_DID],
            trusted_human_approval_signer_dids=[APPROVAL_BACKEND_DID],
        )


def test_approval_signed_by_execution_signer_role_fails():
    packet = _packet(with_approval=True)

    with pytest.raises(ProofVerificationError, match="HumanApprovalReceipt signer"):
        verify_proof_packet(
            packet,
            trusted_decision_signer_dids=[BACKEND_DID],
            trusted_execution_signer_dids=[BACKEND_DID],
            trusted_human_approval_signer_dids=[APPROVAL_BACKEND_DID],
        )


def test_legacy_receipt_versions_verify_signature_without_v2_field_requirements():
    delegation = _delegation_receipt()
    decision_jcs = _sign_jcs({
        **_base_decision_body(delegation),
        "schema_version": "decision_receipt/1",
    })
    execution_body = _execution_body(decision_jcs)
    execution_body.pop("decision_receipt_hash")
    execution_body.pop("action")
    execution_body.pop("resource")
    execution_jcs = _sign_jcs({
        **execution_body,
        "schema_version": "execution_receipt/1",
    })
    packet = {
        "agent_did": AGENT_DID,
        "delegation_receipt": delegation,
        "outcome_status": "executed",
        "audit_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "decision_receipt_jcs": decision_jcs,
        "execution_receipt_jcs": execution_jcs,
    }

    result = verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])

    assert result["decision_receipt"]["schema_version"] == "decision_receipt/1"
    assert result["execution_receipt"]["schema_version"] == "execution_receipt/1"


# --- decision_receipt/3 (W3C Data Integrity eddsa-jcs-2022) packet routing ---
# claim-check: allow "W3C"/eddsa-jcs-2022 are literal cryptosuite identifiers in a test comment (no external-conformance claim)
# The Runtime Gate emits /3 and build_proof_packet embeds it verbatim, so the
# packet verifier must route /3 through the first-party verify_eddsa_jcs_2022
# while /1,/2 stay on the legacy raw-JCS path. The cross-receipt digest is the
# SHA256 of the full receipt text for both paths (see verify_signed_jcs and
# runtime_gate._verify_decision_receipt).


def _decision_body_v3(delegation: dict) -> dict:
    return {
        "@context": [DATA_INTEGRITY_CONTEXT],
        **_base_decision_body(delegation),
        "schema_version": "decision_receipt/3",
    }


def _v3_packet(*, decision_seed: bytes = BACKEND_SEED) -> dict:
    delegation = _delegation_receipt()
    decision_jcs = sign_eddsa_jcs_2022(
        _decision_body_v3(delegation), decision_seed, created="2026-04-30T00:00:00Z"
    )
    execution_jcs = _sign_jcs(_execution_body(decision_jcs))
    return {
        "agent_did": AGENT_DID,
        "base_url": "https://agentveil.dev",
        "sdk_version": "0.7.4",
        "generated_at": "2026-04-30T00:00:00Z",
        "delegation_receipt": delegation,
        "outcome_status": "executed",
        "audit_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "decision_receipt_jcs": decision_jcs,
        "execution_receipt_jcs": execution_jcs,
        "approval_receipt_jcs": None,
    }


def test_verify_proof_packet_decision_receipt_v3_passes():
    result = verify_proof_packet(_v3_packet(), trusted_backend_signer_dids=[BACKEND_DID])

    assert result["valid"] is True
    assert result["decision_receipt"]["schema_version"] == "decision_receipt/3"
    assert result["decision_receipt"]["signer_did"] == BACKEND_DID
    assert result["execution_receipt"]["body"]["status"] == "SUCCESS"


def test_verify_proof_packet_decision_receipt_v3_untrusted_signer_fails():
    with pytest.raises(ProofVerificationError, match="DecisionReceipt signer"):
        verify_proof_packet(_v3_packet(), trusted_backend_signer_dids=[OTHER_BACKEND_DID])


def test_verify_proof_packet_decision_receipt_v3_tamper_fails():
    packet = _v3_packet()
    secured = json.loads(packet["decision_receipt_jcs"])
    secured["reason"] = "tampered_reason"
    packet["decision_receipt_jcs"] = jcs.canonicalize(secured).decode("utf-8")

    with pytest.raises(ProofVerificationError, match="signature"):
        verify_proof_packet(packet, trusted_backend_signer_dids=[BACKEND_DID])
