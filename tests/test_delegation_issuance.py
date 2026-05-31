"""Tests for ergonomic SDK DelegationReceipt issuance."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from nacl.signing import SigningKey

from agentveil.agent import AVPAgent
from agentveil.delegation import issue_delegation, verify_delegation

FIXED_FROM = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _make_agent(name: str) -> AVPAgent:
    sk = SigningKey.generate()
    return AVPAgent("http://localhost:8000", bytes(sk), name=name, timeout=1.0)


def test_issue_delegation_emits_hashdata_proof_and_verifies():
    principal_seed = bytes.fromhex("11" * 32)
    agent = _make_agent("agent")

    receipt = issue_delegation(
        principal_private_key=principal_seed,
        agent_did=agent.did,
        scope=[{"predicate": "allowed_category", "value": "infrastructure"}],
        purpose="direct issuance",
        valid_for=timedelta(hours=1),
        valid_from=FIXED_FROM,
        receipt_id="urn:uuid:00000000-0000-4000-8000-000000000001",
    )
    proof = receipt["proof"]
    verified = verify_delegation(receipt, now=FIXED_FROM)

    assert isinstance(receipt, dict)
    assert proof["proofPurpose"] == "assertionMethod"
    assert proof["@context"] == receipt["@context"]
    assert proof["verificationMethod"] == (
        f"{receipt['issuer']}#{receipt['issuer'][len('did:key:'):]}"
    )
    assert proof["proofValue"].startswith("z")
    assert verified["valid"] is True
    assert verified["issuer"] == receipt["issuer"]
    assert verified["subject"] == agent.did


def test_issue_delegation_receipt_verifies_with_correct_issuer_and_subject():
    principal = _make_agent("principal")
    agent = _make_agent("agent")

    receipt = principal.issue_delegation_receipt(
        agent_did=agent.did,
        allowed_categories=["infrastructure"],
        valid_for=timedelta(hours=1),
    )
    proof = receipt["proof"]
    verified = verify_delegation(receipt)

    assert proof["proofPurpose"] == "assertionMethod"
    assert proof["@context"] == receipt["@context"]
    assert verified["issuer"] == principal.did
    assert verified["subject"] == agent.did
    assert verified["scope"] == [
        {"predicate": "allowed_category", "value": "infrastructure"}
    ]


def test_verify_delegation_receipt_helper_uses_existing_offline_verifier():
    principal = _make_agent("principal")
    agent = _make_agent("agent")
    receipt = principal.issue_delegation_receipt(
        agent_did=agent.did,
        allowed_categories=["data"],
        valid_for=timedelta(minutes=30),
    )

    verified = principal.verify_delegation_receipt(receipt)

    assert receipt["proof"]["proofPurpose"] == "assertionMethod"
    assert verified["valid"] is True
    assert verified["issuer"] == principal.did
    assert verified["subject"] == agent.did


def test_issue_delegation_receipt_encodes_multiple_categories_and_max_spend():
    principal = _make_agent("principal")
    agent = _make_agent("agent")

    receipt = principal.issue_delegation_receipt(
        agent_did=agent.did,
        allowed_categories=["infrastructure", "payments"],
        max_spend={"currency": "USD", "amount": 100},
        valid_for=timedelta(hours=2),
    )
    scope = verify_delegation(receipt)["scope"]

    assert scope == [
        {"predicate": "allowed_category", "value": "infrastructure"},
        {"predicate": "allowed_category", "value": "payments"},
        {"predicate": "max_spend", "currency": "USD", "amount": 100},
    ]


@pytest.mark.parametrize("valid_for", [timedelta(0), timedelta(seconds=-1)])
def test_issue_delegation_receipt_rejects_non_positive_valid_for(valid_for):
    principal = _make_agent("principal")
    agent = _make_agent("agent")

    with patch("agentveil.delegation.issue_delegation") as issue_mock:
        with pytest.raises(ValueError, match="valid_for must be a positive timedelta"):
            principal.issue_delegation_receipt(
                agent_did=agent.did,
                allowed_categories=["infrastructure"],
                valid_for=valid_for,
            )

    issue_mock.assert_not_called()


@pytest.mark.parametrize(
    "kwarg",
    ["allowed_actions", "allowed_resources", "allowed_environments"],
)
def test_issue_delegation_receipt_rejects_exact_scope_kwargs_before_signing(kwarg):
    principal = _make_agent("principal")
    agent = _make_agent("agent")

    with patch("agentveil.delegation.issue_delegation") as issue_mock:
        with pytest.raises(ValueError, match="unsupported exact-scope"):
            principal.issue_delegation_receipt(
                agent_did=agent.did,
                allowed_categories=["infrastructure"],
                valid_for=timedelta(hours=1),
                **{kwarg: ["infra.resource.inspect"]},
            )

    issue_mock.assert_not_called()


def test_generated_v1_receipt_works_in_mocked_controlled_action_flow():
    principal = _make_agent("principal")
    agent = _make_agent("agent")
    receipt = principal.issue_delegation_receipt(
        agent_did=agent.did,
        allowed_categories=["infrastructure"],
        valid_for=timedelta(hours=1),
    )
    raw_receipt = '{"receipt_id":"urn:uuid:receipt","status":"SUCCESS"}'

    def runtime_evaluate(**kwargs):
        scope = kwargs["delegation_receipt"]["credentialSubject"]["scope"]
        predicates = {entry["predicate"] for entry in scope}
        assert predicates == {"allowed_category"}
        return {
            "audit_id": "urn:uuid:audit",
            "decision": "ALLOW",
            "reason": "read_action",
        }

    with patch.object(agent, "runtime_evaluate", side_effect=runtime_evaluate), \
         patch.object(agent, "execute", return_value=raw_receipt) as execute_mock:
        result = agent.controlled_action(
            action="infra.resource.inspect",
            resource="resource:vol-123",
            environment="development",
            delegation_receipt=receipt,
            params={"resource_id": "vol-123"},
        )

    execute_mock.assert_called_once()
    assert result.status == "executed"
    assert result.receipt_jcs == raw_receipt
