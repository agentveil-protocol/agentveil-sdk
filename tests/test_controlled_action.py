"""Tests for high-level controlled action orchestration."""

import json
from unittest.mock import patch

from nacl.signing import SigningKey

from agentveil.agent import AVPAgent
from agentveil.results import ControlledActionOutcome, ProofPacket


def _make_agent() -> AVPAgent:
    sk = SigningKey.generate()
    return AVPAgent("http://localhost:8000", bytes(sk), name="controlled-test", timeout=1.0)


def test_controlled_action_allow_executes_and_preserves_receipt_jcs():
    agent = _make_agent()
    decision = {
        "audit_id": "urn:uuid:11111111-1111-1111-1111-111111111111",
        "decision": "ALLOW",
        "reason": "read_action",
    }
    receipt_jcs = '{"receipt_id":"urn:uuid:22222222-2222-2222-2222-222222222222","status":"SUCCESS"}'

    with patch.object(agent, "runtime_evaluate", return_value=decision) as eval_mock, \
         patch.object(agent, "execute", return_value=receipt_jcs) as execute_mock:
        result = agent.controlled_action(
            action="infra.resource.inspect",
            resource="resource:1",
            environment="development",
            delegation_receipt={"id": "urn:uuid:receipt"},
            params={"resource_id": "resource:1"},
        )

    eval_mock.assert_called_once()
    execute_mock.assert_called_once_with(
        audit_id=decision["audit_id"],
        action="infra.resource.inspect",
        resource="resource:1",
        environment="development",
        params={"resource_id": "resource:1"},
    )
    assert isinstance(result, ControlledActionOutcome)
    assert result.status == "executed"
    assert result.receipt_jcs == receipt_jcs
    assert result.receipt["status"] == "SUCCESS"
    assert result["status"] == "executed"


def test_controlled_action_waiting_creates_approval_without_executing():
    agent = _make_agent()
    decision = {
        "audit_id": "urn:uuid:11111111-1111-1111-1111-111111111111",
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "reason": "destructive_production_action",
    }
    approval = {"approval_id": "urn:uuid:approval", "status": "PENDING"}
    delegation_receipt = {"id": "urn:uuid:receipt"}

    with patch.object(agent, "runtime_evaluate", return_value=decision), \
         patch.object(agent, "create_approval", return_value=approval) as approval_mock, \
         patch.object(agent, "execute") as execute_mock:
        result = agent.controlled_action(
            action="infra.volume.delete",
            resource="volume:vol-1",
            environment="production",
            delegation_receipt=delegation_receipt,
            params={"resource_id": "vol-1"},
            approval_expires_in_seconds=900,
        )

    approval_mock.assert_called_once_with(
        audit_id=decision["audit_id"],
        delegation_receipt=delegation_receipt,
        expires_in_seconds=900,
    )
    execute_mock.assert_not_called()
    assert isinstance(result, ControlledActionOutcome)
    assert result.status == "approval_required"
    assert result.approval == approval


def test_controlled_action_blocked_does_not_create_approval_or_execute():
    agent = _make_agent()
    decision = {
        "audit_id": "urn:uuid:11111111-1111-1111-1111-111111111111",
        "decision": "BLOCK",
        "reason": "governance_recent_disputes",
    }

    with patch.object(agent, "runtime_evaluate", return_value=decision), \
         patch.object(agent, "create_approval") as approval_mock, \
         patch.object(agent, "execute") as execute_mock:
        result = agent.controlled_action(
            action="infra.volume.delete",
            resource="volume:vol-1",
            environment="production",
            delegation_receipt={"id": "urn:uuid:receipt"},
            params={"resource_id": "vol-1"},
        )

    approval_mock.assert_not_called()
    execute_mock.assert_not_called()
    assert isinstance(result, ControlledActionOutcome)
    assert result.status == "blocked"
    assert result.decision == decision
    assert result.reason == "governance_recent_disputes"


def test_controlled_action_unknown_decision_fails_closed():
    agent = _make_agent()
    decision = {
        "audit_id": "urn:uuid:11111111-1111-1111-1111-111111111111",
        "decision": "MFA_REQUIRED",
        "reason": "future_gate_state",
    }

    with patch.object(agent, "runtime_evaluate", return_value=decision), \
         patch.object(agent, "create_approval") as approval_mock, \
         patch.object(agent, "execute") as execute_mock:
        result = agent.controlled_action(
            action="infra.volume.delete",
            resource="volume:vol-1",
            environment="production",
            delegation_receipt={"id": "urn:uuid:receipt"},
            params={"resource_id": "vol-1"},
        )

    approval_mock.assert_not_called()
    execute_mock.assert_not_called()
    assert result.status == "blocked"
    assert result.reason == "future_gate_state"


def test_execute_after_approval_executes_with_approval_id():
    agent = _make_agent()
    receipt_jcs = '{"receipt_id":"urn:uuid:22222222-2222-2222-2222-222222222222","status":"SUCCESS"}'

    with patch.object(agent, "execute", return_value=receipt_jcs) as execute_mock:
        result = agent.execute_after_approval(
            audit_id="urn:uuid:11111111-1111-1111-1111-111111111111",
            approval_id="urn:uuid:approval",
            action="infra.volume.delete",
            resource="volume:vol-1",
            environment="production",
            params={"resource_id": "vol-1"},
        )

    execute_mock.assert_called_once_with(
        audit_id="urn:uuid:11111111-1111-1111-1111-111111111111",
        action="infra.volume.delete",
        resource="volume:vol-1",
        environment="production",
        params={"resource_id": "vol-1"},
        approval_id="urn:uuid:approval",
    )
    assert isinstance(result, ControlledActionOutcome)
    assert result.status == "executed"
    assert result.approval_id == "urn:uuid:approval"
    assert result.receipt["status"] == "SUCCESS"


def test_build_proof_packet_preserves_raw_receipt_and_uses_no_remote_fetch():
    agent = _make_agent()
    delegation_receipt = {
        "id": "urn:uuid:delegation",
        "scope": {"action": "infra.resource.inspect"},
    }
    receipt_jcs = (
        '{"receipt_id":"urn:uuid:22222222-2222-2222-2222-222222222222",'
        '"status":"SUCCESS","nested":{"keep":"exact"}}'
    )
    outcome = ControlledActionOutcome(
        status="executed",
        decision={"audit_id": "urn:uuid:audit", "decision": "ALLOW"},
        receipt_jcs=receipt_jcs,
        receipt=json.loads(receipt_jcs),
    )

    with patch("agentveil.agent.httpx.Client") as client_mock:
        packet = agent.build_proof_packet(
            delegation_receipt=delegation_receipt,
            outcome=outcome,
            decision_receipt_jcs='{"schema_version":"decision_receipt/2"}',
        )

    client_mock.assert_not_called()
    assert isinstance(packet, ProofPacket)
    assert packet.agent_did == agent.did
    assert packet.base_url == "http://localhost:8000"
    assert packet.sdk_version
    assert packet.audit_id == "urn:uuid:audit"
    assert packet.decision_receipt_jcs == '{"schema_version":"decision_receipt/2"}'
    assert packet.decision_receipt["schema_version"] == "decision_receipt/2"
    assert packet.execution_receipt_jcs == receipt_jcs
    assert packet.execution_receipt["status"] == "SUCCESS"

    delegation_receipt["scope"]["action"] = "changed"
    assert packet.delegation_receipt["scope"]["action"] == "infra.resource.inspect"

    packet_dict = packet.to_dict()
    assert packet_dict["decision_receipt_jcs"] == '{"schema_version":"decision_receipt/2"}'
    assert packet_dict["execution_receipt_jcs"] == receipt_jcs
    assert "approval_receipt_jcs" not in packet_dict
    assert "remediation_case" not in packet_dict


def test_build_proof_packet_includes_optional_approval_and_remediation_artifacts():
    agent = _make_agent()
    approval_receipt_jcs = '{"approval_id":"urn:uuid:approval","status":"APPROVED"}'
    remediation_case = {
        "id": "urn:uuid:case",
        "evidence": [{"reference_type": "execution_receipt"}],
    }
    remediation_refs = [{"case_id": "urn:uuid:case", "evidence_hash": "sha256:abc"}]
    outcome = ControlledActionOutcome(
        status="approval_required",
        decision={"audit_id": "urn:uuid:audit", "decision": "WAITING_FOR_HUMAN_APPROVAL"},
        approval={"approval_id": "urn:uuid:approval", "status": "PENDING"},
    )

    packet = agent.build_proof_packet(
        delegation_receipt={"id": "urn:uuid:delegation"},
        outcome=outcome,
        approval_receipt_jcs=approval_receipt_jcs,
        remediation_case=remediation_case,
        remediation_refs=remediation_refs,
    )

    assert packet.outcome_status == "approval_required"
    assert packet.approval == {"approval_id": "urn:uuid:approval", "status": "PENDING"}
    assert packet.approval_receipt_jcs == approval_receipt_jcs
    assert packet.approval_receipt["status"] == "APPROVED"
    assert packet.remediation_case["id"] == "urn:uuid:case"
    assert packet.remediation_refs == remediation_refs
    assert "execution_receipt_jcs" not in packet.to_dict()
