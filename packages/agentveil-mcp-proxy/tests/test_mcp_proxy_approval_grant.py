"""SG-2 unit tests for the proxy-signed approval grant primitive.

These exercise the isolated build/verify primitive only -- no approval manager,
evidence store, bundle, or CLI integration.
"""

from __future__ import annotations

import json

import pytest
from nacl.signing import SigningKey

from agentveil.data_integrity import sign_eddsa_jcs_2022
from agentveil.delegation import _public_key_to_did
from agentveil_mcp_proxy.evidence.approval_grant import (
    APPROVAL_GRANT_SCHEMA,
    APPROVAL_SCOPE_EXACT,
    APPROVAL_SCOPE_SIMILAR_5M,
    ApprovalGrantError,
    build_approval_grant,
    verify_approval_grant,
)


SEED = bytes.fromhex("11" * 32)
OTHER_SEED = bytes.fromhex("22" * 32)
PROXY_DID = _public_key_to_did(bytes(SigningKey(SEED).verify_key))
OTHER_DID = _public_key_to_did(bytes(SigningKey(OTHER_SEED).verify_key))

_ISSUED_AT = 1_700_000_000
_EXPIRES_AT = 1_700_000_300


def _valid_body(*, scope: str = APPROVAL_SCOPE_EXACT, agent_did: str = PROXY_DID, **overrides):
    body = {
        "schema_version": APPROVAL_GRANT_SCHEMA,
        "agent_did": agent_did,
        "request_id": "req-1",
        "downstream_server": "github",
        "tool_name": "create_issue",
        "action_class": "write",
        "risk_class": "write",
        "resource_hash": "sha256:" + "a" * 64,
        "payload_hash": "sha256:" + "b" * 64,
        "policy_id": "policy-1",
        "policy_rule_id": "rule-1",
        "policy_context_hash": "c" * 64,
        "decision": "APPROVED",
        "approval_scope": scope,
        "decided_by": "local-user",
        "issued_at": _ISSUED_AT,
        "expires_at": _EXPIRES_AT,
    }
    body.update(overrides)
    return body


def test_round_trip_sign_and_verify():
    grant = build_approval_grant(_valid_body(), SEED)
    body = verify_approval_grant(grant, expected_signer_dids=[PROXY_DID], now=_ISSUED_AT + 1)
    assert body["request_id"] == "req-1"
    assert body["decision"] == "APPROVED"
    assert body["agent_did"] == PROXY_DID
    assert body["approval_scope"] == APPROVAL_SCOPE_EXACT
    # verify returns the unsecured document (proof stripped).
    assert "proof" not in body


def test_wrong_expected_signer_rejected():
    grant = build_approval_grant(_valid_body(), SEED)
    with pytest.raises(ApprovalGrantError, match="signer is not in the pinned"):
        verify_approval_grant(grant, expected_signer_dids=[OTHER_DID])


def test_empty_expected_signer_set_rejected():
    grant = build_approval_grant(_valid_body(), SEED)
    with pytest.raises(ApprovalGrantError, match="externally supplied expected_signer_dids"):
        verify_approval_grant(grant, expected_signer_dids=[])


def test_tampered_body_rejected():
    grant = build_approval_grant(_valid_body(), SEED)
    doc = json.loads(grant)
    doc["tool_name"] = "EVIL_TOOL"
    with pytest.raises(ApprovalGrantError, match="signature invalid"):
        verify_approval_grant(json.dumps(doc), expected_signer_dids=[PROXY_DID])


def test_tampered_proof_rejected():
    grant = build_approval_grant(_valid_body(), SEED)
    doc = json.loads(grant)
    proof_value = doc["proof"]["proofValue"]
    doc["proof"]["proofValue"] = proof_value[:-1] + ("A" if proof_value[-1] != "A" else "B")
    with pytest.raises(ApprovalGrantError, match="signature invalid"):
        verify_approval_grant(json.dumps(doc), expected_signer_dids=[PROXY_DID])


def test_unsupported_schema_rejected():
    bad = _valid_body()
    bad["schema_version"] = "proxy_approval_grant/2"
    grant = sign_eddsa_jcs_2022(bad, SEED)  # valid signature, bad schema
    with pytest.raises(ApprovalGrantError, match="unsupported approval grant schema_version"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])


def test_missing_required_field_rejected():
    bad = _valid_body()
    del bad["request_id"]
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="missing required field: request_id"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])


def test_expired_grant_rejected():
    grant = build_approval_grant(_valid_body(expires_at=_EXPIRES_AT), SEED)
    with pytest.raises(ApprovalGrantError, match="expired"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID], now=_EXPIRES_AT + 1)


def test_agent_did_signer_mismatch_rejected():
    # Body claims OTHER_DID but is signed by the PROXY key.
    bad = _valid_body(agent_did=OTHER_DID)
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="agent_did does not match"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])


def test_exact_without_payload_hash_rejected():
    bad = _valid_body(scope=APPROVAL_SCOPE_EXACT, payload_hash=None)
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="exact requires a non-null payload_hash"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])
    # build rejects the same malformed body up front.
    with pytest.raises(ApprovalGrantError, match="exact requires a non-null payload_hash"):
        build_approval_grant(bad, SEED)


def test_similar_5m_without_resource_hash_rejected():
    bad = _valid_body(scope=APPROVAL_SCOPE_SIMILAR_5M, resource_hash=None)
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="similar_5m requires a non-null resource_hash"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])


def test_similar_5m_with_resource_hash_round_trips():
    grant = build_approval_grant(_valid_body(scope=APPROVAL_SCOPE_SIMILAR_5M), SEED)
    body = verify_approval_grant(grant, expected_signer_dids=[PROXY_DID], now=_ISSUED_AT + 1)
    assert body["approval_scope"] == APPROVAL_SCOPE_SIMILAR_5M


def test_embedded_self_declared_trust_is_ignored():
    body = _valid_body()
    # A self-declared trust hint embedded in the grant is not honored.
    body["trusted_signer_dids"] = [OTHER_DID, "did:key:zAttacker"]
    grant = build_approval_grant(body, SEED)
    # External pin to the real signer verifies; embedded hint not consulted.
    ok = verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])
    assert ok["agent_did"] == PROXY_DID
    # Pinning only to the embedded "trusted" DID (not the actual signer) rejects.
    with pytest.raises(ApprovalGrantError, match="signer is not in the pinned"):
        verify_approval_grant(grant, expected_signer_dids=[OTHER_DID])


def test_unsupported_decision_denied_rejected():
    bad = _valid_body()
    bad["decision"] = "DENIED"
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="unsupported approval grant decision"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])
    with pytest.raises(ApprovalGrantError, match="unsupported approval grant decision"):
        build_approval_grant(bad, SEED)


def test_missing_action_class_rejected():
    bad = _valid_body()
    del bad["action_class"]
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="missing required field: action_class"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])
    with pytest.raises(ApprovalGrantError, match="missing required field: action_class"):
        build_approval_grant(bad, SEED)


def test_payload_hash_must_be_prefixed_sha256():
    # Raw 64-hex (missing the "sha256:" prefix) is rejected for payload_hash.
    bad = _valid_body(payload_hash="a" * 64)
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="payload_hash must be"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])
    with pytest.raises(ApprovalGrantError, match="payload_hash must be"):
        build_approval_grant(bad, SEED)


def test_resource_hash_must_be_prefixed_sha256():
    bad = _valid_body(resource_hash="not-a-valid-hash")
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="resource_hash must be"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])


def test_policy_context_hash_must_be_raw_hex():
    # A "sha256:"-prefixed value is rejected; policy_context_hash is raw 64-hex.
    bad = _valid_body(policy_context_hash="sha256:" + "c" * 64)
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="policy_context_hash must be a 64-char"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])
    # Correct-length but non-hex is rejected too.
    bad2 = _valid_body(policy_context_hash="z" * 64)
    grant2 = sign_eddsa_jcs_2022(bad2, SEED)
    with pytest.raises(ApprovalGrantError, match="policy_context_hash must be a 64-char"):
        verify_approval_grant(grant2, expected_signer_dids=[PROXY_DID])


def test_decision_receipt_sha256_shape_enforced_when_present():
    # Repo produces a raw digest; a "sha256:"-prefixed value is rejected.
    bad = _valid_body(decision_receipt_sha256="sha256:" + "d" * 64)
    grant = sign_eddsa_jcs_2022(bad, SEED)
    with pytest.raises(ApprovalGrantError, match="decision_receipt_sha256 must be a 64-char"):
        verify_approval_grant(grant, expected_signer_dids=[PROXY_DID])
    # A valid raw 64-hex digest round-trips.
    ok = build_approval_grant(_valid_body(decision_receipt_sha256="d" * 64), SEED)
    body = verify_approval_grant(ok, expected_signer_dids=[PROXY_DID])
    assert body["decision_receipt_sha256"] == "d" * 64
