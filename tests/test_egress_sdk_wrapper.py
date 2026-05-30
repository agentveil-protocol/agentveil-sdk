"""Unit coverage for ``AVPAgent.controlled_egress`` and agent-signed
``egress_receipt/1`` round-trip.

Tests are stub-driven: ``AVPAgent.runtime_evaluate`` is patched per test
to control the backend's response, and an in-process HTTP client factory
is injected via ``_http_client_factory``. No real network IO.

These tests exercise the SDK helper's own state machine. They do NOT
claim product-real backend ALLOW/BLOCK behavior — that is PR-A's
concern.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional
from unittest.mock import patch

import httpx
import jcs
import pytest
from nacl.signing import SigningKey

import base58

from agentveil import (
    AVPAgent,
    ControlledEgressOutcome,
    EgressReceiptProofError,
    EgressReceiptVerificationError,
    sign_egress_receipt,
    verify_egress_receipt,
)
from agentveil.egress import (
    ACTION_NETWORK_EGRESS,
    CRYPTOSUITE,
    ED25519_MULTICODEC,
    EVALUATOR_VERSION,
    PROOF_TYPE,
    SCHEMA_VERSION,
)


_DELEGATION_RECEIPT = {"id": "urn:uuid:delegation"}
_POLICY_ID = "policy-egress-payments-v0"
_CREDENTIAL_CLASS = "payment_processor_api_key"
_HOST = "api.stripe.com"
_PORT = 443
_METHOD = "POST"
_PATH = "/v1/charges"
_BODY = b'{"amount": 1000, "currency": "usd"}'


def _make_agent() -> AVPAgent:
    sk = SigningKey.generate()
    return AVPAgent(
        "http://localhost:8000",
        bytes(sk),
        name="egress-test",
        timeout=1.0,
    )


class _StubHttpResponse:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code


class _StubHttpClient:
    """Records the single ``request(...)`` call shape and returns a stub."""

    def __init__(
        self,
        *,
        response: Optional[_StubHttpResponse] = None,
        raises: Optional[BaseException] = None,
    ):
        self.response = response or _StubHttpResponse()
        self.raises = raises
        self.last_call: Optional[dict[str, Any]] = None
        self.call_count = 0

    def __enter__(self) -> "_StubHttpClient":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Any = None,
        content: Any = None,
    ) -> _StubHttpResponse:
        self.call_count += 1
        self.last_call = {
            "method": method,
            "url": url,
            "headers": headers,
            "content": content,
        }
        if self.raises is not None:
            raise self.raises
        return self.response


def _stub_factory(stub: _StubHttpClient):
    def _factory(**_kwargs: Any) -> _StubHttpClient:
        return stub

    return _factory


def _allow_decision(audit_id: str = "urn:uuid:audit-allow") -> dict[str, Any]:
    return {
        "audit_id": audit_id,
        "decision": "ALLOW",
        "reason": "write_action_within_scope",
    }


def _block_decision(audit_id: str = "urn:uuid:audit-block") -> dict[str, Any]:
    return {
        "audit_id": audit_id,
        "decision": "BLOCK",
        "reason": "category_not_allowed",
    }


def _waiting_decision(audit_id: str = "urn:uuid:audit-waiting") -> dict[str, Any]:
    return {
        "audit_id": audit_id,
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "reason": "destructive_production_action",
    }


def _call_controlled_egress(
    agent: AVPAgent,
    *,
    http_factory,
    body: bytes = _BODY,
) -> ControlledEgressOutcome:
    from agentveil.egress import controlled_egress as _controlled_egress

    return _controlled_egress(
        agent=agent,
        host=_HOST,
        port=_PORT,
        method=_METHOD,
        path=_PATH,
        headers={"Authorization": "Bearer test", "Content-Type": "application/json"},
        body=body,
        credential_or_principal_class=_CREDENTIAL_CLASS,
        policy_id=_POLICY_ID,
        delegation_receipt=_DELEGATION_RECEIPT,
        _http_client_factory=http_factory,
    )


def test_allow_path_signs_receipt_and_sends_via_helper():
    agent = _make_agent()
    stub = _StubHttpClient(response=_StubHttpResponse(status_code=200))

    with patch.object(agent, "runtime_evaluate", return_value=_allow_decision()):
        outcome = _call_controlled_egress(agent, http_factory=_stub_factory(stub))

    assert outcome.status == "sent"
    assert outcome.receipt is not None
    assert outcome.receipt["decision"] == "ALLOW"
    assert outcome.receipt["outcome"] == "SENT"
    assert outcome.receipt["agent_did"] == agent.did
    assert outcome.receipt["destination"] == f"{_HOST}:{_PORT}"
    assert outcome.receipt["action"] == ACTION_NETWORK_EGRESS
    assert outcome.receipt["protocol"] == "https"
    assert outcome.receipt["method"] == "POST"
    assert outcome.audit_id == "urn:uuid:audit-allow"
    assert outcome.send_result == {
        "status_code": 200,
        "elapsed_seconds": outcome.send_result["elapsed_seconds"],
    }

    # Receipt verifies offline against the agent's DID. The receipt is
    # agent-signed, not backend-signed.
    verified = verify_egress_receipt(
        outcome.receipt_jcs, trusted_signer_dids=[agent.did]
    )
    assert verified["agent_did"] == agent.did
    assert verified["decision"] == "ALLOW"
    assert verified["outcome"] == "SENT"

    # Helper actually opened the connection.
    assert stub.call_count == 1
    assert stub.last_call is not None
    assert stub.last_call["method"] == "POST"
    assert stub.last_call["url"] == f"https://{_HOST}:{_PORT}{_PATH}"
    assert stub.last_call["content"] == _BODY


def test_block_path_does_not_send_and_signs_blocked_receipt():
    agent = _make_agent()
    stub = _StubHttpClient()

    with patch.object(agent, "runtime_evaluate", return_value=_block_decision()):
        outcome = _call_controlled_egress(agent, http_factory=_stub_factory(stub))

    assert outcome.status == "blocked"
    assert stub.call_count == 0
    assert outcome.receipt is not None
    assert outcome.receipt["decision"] == "BLOCK"
    assert outcome.receipt["outcome"] == "BLOCKED"
    assert outcome.send_result is None

    verified = verify_egress_receipt(
        outcome.receipt_jcs, trusted_signer_dids=[agent.did]
    )
    assert verified["decision"] == "BLOCK"
    assert verified["outcome"] == "BLOCKED"


def test_waiting_path_does_not_send_and_emits_no_receipt():
    agent = _make_agent()
    stub = _StubHttpClient()

    with patch.object(agent, "runtime_evaluate", return_value=_waiting_decision()):
        outcome = _call_controlled_egress(agent, http_factory=_stub_factory(stub))

    assert outcome.status == "approval_required"
    assert outcome.receipt is None
    assert outcome.receipt_jcs is None
    assert stub.call_count == 0


def test_allow_path_with_connect_error_emits_failed_receipt_without_raw_message():
    agent = _make_agent()
    raw_secret_text = "private socket detail with token sk_live_DO_NOT_LEAK"
    stub = _StubHttpClient(raises=httpx.ConnectError(raw_secret_text))

    with patch.object(agent, "runtime_evaluate", return_value=_allow_decision()):
        outcome = _call_controlled_egress(agent, http_factory=_stub_factory(stub))

    assert outcome.status == "failed"
    assert outcome.receipt is not None
    assert outcome.receipt["decision"] == "ALLOW"
    assert outcome.receipt["outcome"] == "FAILED"
    assert outcome.error_class == "ConnectError"
    # Sanitization: no raw exception message anywhere in the receipt JCS or
    # in the outcome's serialized fields.
    assert raw_secret_text not in outcome.receipt_jcs
    assert raw_secret_text not in repr(outcome)
    assert stub.call_count == 1


def test_dual_hash_runtime_gate_prefixed_receipt_plain():
    agent = _make_agent()
    body = b"hello dual-hash"
    expected_digest = hashlib.sha256(body).hexdigest()
    expected_runtime_payload_hash = f"sha256:{expected_digest}"
    stub = _StubHttpClient()

    with patch.object(
        agent, "runtime_evaluate", return_value=_allow_decision()
    ) as eval_mock:
        outcome = _call_controlled_egress(
            agent, http_factory=_stub_factory(stub), body=body
        )

    eval_mock.assert_called_once()
    call_kwargs = eval_mock.call_args.kwargs
    assert call_kwargs["action"] == ACTION_NETWORK_EGRESS
    assert call_kwargs["payload_hash"] == expected_runtime_payload_hash

    assert outcome.receipt is not None
    assert outcome.receipt["payload_hash"] == expected_digest
    # Plain form, no "sha256:" prefix in the receipt body.
    assert ":" not in outcome.receipt["payload_hash"]
    assert len(outcome.receipt["payload_hash"]) == 64


def test_tampered_receipt_fails_signature_verification():
    agent = _make_agent()
    stub = _StubHttpClient()

    with patch.object(agent, "runtime_evaluate", return_value=_allow_decision()):
        outcome = _call_controlled_egress(agent, http_factory=_stub_factory(stub))

    parsed = json.loads(outcome.receipt_jcs)
    parsed["destination"] = "evil.example.com:443"
    tampered = jcs.canonicalize(parsed).decode("utf-8")

    with pytest.raises(EgressReceiptVerificationError, match="signature invalid"):
        verify_egress_receipt(tampered, trusted_signer_dids=[agent.did])


def test_wrong_trusted_signer_did_fails_verification():
    agent = _make_agent()
    other_did = AVPAgent(
        "http://localhost:8000", bytes(SigningKey.generate()), name="other"
    ).did
    stub = _StubHttpClient()

    with patch.object(agent, "runtime_evaluate", return_value=_allow_decision()):
        outcome = _call_controlled_egress(agent, http_factory=_stub_factory(stub))

    with pytest.raises(EgressReceiptVerificationError, match="not trusted"):
        verify_egress_receipt(outcome.receipt_jcs, trusted_signer_dids=[other_did])


def _allow_receipt_jcs() -> str:
    agent = _make_agent()
    stub = _StubHttpClient(response=_StubHttpResponse(status_code=200))
    with patch.object(agent, "runtime_evaluate", return_value=_allow_decision()):
        outcome = _call_controlled_egress(agent, http_factory=_stub_factory(stub))
    return outcome.receipt_jcs


def test_no_trusted_signer_dids_fails_closed():
    """Default (no trust config) must NOT accept any valid signer."""
    receipt_jcs = _allow_receipt_jcs()
    with pytest.raises(EgressReceiptVerificationError, match="trusted_signer_dids is required"):
        verify_egress_receipt(receipt_jcs)


def test_empty_trusted_signer_set_fails_closed():
    receipt_jcs = _allow_receipt_jcs()
    with pytest.raises(EgressReceiptVerificationError, match="not trusted"):
        verify_egress_receipt(receipt_jcs, trusted_signer_dids=[])


def test_runtime_gate_call_uses_network_egress_action_and_correct_kwargs():
    agent = _make_agent()
    stub = _StubHttpClient()

    with patch.object(
        agent, "runtime_evaluate", return_value=_allow_decision()
    ) as eval_mock:
        _call_controlled_egress(agent, http_factory=_stub_factory(stub))

    eval_mock.assert_called_once()
    call_kwargs = eval_mock.call_args.kwargs
    assert call_kwargs["action"] == "network.egress"
    assert call_kwargs["resource"] == f"{_HOST}:{_PORT}"
    assert call_kwargs["environment"] == "production"
    assert call_kwargs["risk_class"] == "write"
    assert call_kwargs["payload_hash"].startswith("sha256:")
    assert call_kwargs["delegation_receipt"] == _DELEGATION_RECEIPT


# ===========================================================================
# Agent-DID binding (signer + verifier must self-attest)
# ===========================================================================


def _valid_egress_body(*, agent_did: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": "urn:uuid:00000000-0000-4000-8000-000000000abc",
        "agent_did": agent_did,
        "action": ACTION_NETWORK_EGRESS,
        "destination": f"{_HOST}:{_PORT}",
        "protocol": "https",
        "method": "POST",
        "credential_or_principal_class": _CREDENTIAL_CLASS,
        "payload_hash": "a" * 64,
        "policy_id": _POLICY_ID,
        "decision": "ALLOW",
        "approval_id": None,
        "outcome": "SENT",
        "evaluator_version": EVALUATOR_VERSION,
    }


def _did_from_seed(seed: bytes) -> str:
    pubkey = bytes(SigningKey(seed).verify_key)
    return "did:key:z" + base58.b58encode(ED25519_MULTICODEC + pubkey).decode("ascii")


def _sign_egress_body_bypassing_agent_binding(
    body: dict, signing_seed: bytes
) -> str:
    """Local-only signer mirroring ``sign_egress_receipt`` minus the
    ``agent_did``-binding check. Used only by the verifier-binding
    regression test to construct a forged-attribution receipt that the
    public signer would refuse to produce.
    """
    signing_key = SigningKey(signing_seed)
    issuer_pubkey = bytes(signing_key.verify_key)
    issuer_did = "did:key:z" + base58.b58encode(
        ED25519_MULTICODEC + issuer_pubkey
    ).decode("ascii")
    canonical_body = jcs.canonicalize(body)
    signature = signing_key.sign(canonical_body).signature
    proof_value = "z" + base58.b58encode(signature).decode("ascii")
    verification_method = f"{issuer_did}#{issuer_did[len('did:key:'):]}"
    signed = {
        **body,
        "proof": {
            "type": PROOF_TYPE,
            "cryptosuite": CRYPTOSUITE,
            "verificationMethod": verification_method,
            "proofValue": proof_value,
        },
    }
    return jcs.canonicalize(signed).decode("utf-8")


def test_signer_rejects_body_agent_did_mismatching_signing_seed():
    """``sign_egress_receipt`` must self-attest: body.agent_did MUST equal
    the DID derived from signing_seed. Otherwise one agent could mint a
    receipt claiming another agent's identity.
    """
    signer_seed = bytes(SigningKey.generate())
    foreign_seed = bytes(SigningKey.generate())
    foreign_did = _did_from_seed(foreign_seed)
    body = _valid_egress_body(agent_did=foreign_did)

    with pytest.raises(EgressReceiptProofError, match="agent_did"):
        sign_egress_receipt(body=body, signing_seed=signer_seed)


def test_verifier_rejects_receipt_with_agent_did_mismatching_signer_did():
    """``verify_egress_receipt`` must reject a receipt whose signed
    body's ``agent_did`` does not equal the proof signer DID. Without
    this check a receipt with a valid signature but a forged
    ``agent_did`` field would verify and misattribute the egress.
    """
    actual_seed = bytes(SigningKey.generate())
    actual_did = _did_from_seed(actual_seed)
    other_seed = bytes(SigningKey.generate())
    other_did = _did_from_seed(other_seed)
    assert actual_did != other_did

    # Body declares ``other_did`` but is signed with ``actual_seed``.
    body = _valid_egress_body(agent_did=other_did)
    forged_jcs = _sign_egress_body_bypassing_agent_binding(body, actual_seed)

    with pytest.raises(EgressReceiptVerificationError, match="agent_did"):
        verify_egress_receipt(forged_jcs, trusted_signer_dids=[actual_did])
