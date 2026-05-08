"""Approval routing pattern for a controlled action.

This no-backend demo uses mock agents and an in-memory approval service because
mock `controlled_action()` does not call the live Runtime Gate. The object
shapes and method sequence mirror the live SDK path:

controlled_action -> approval_required -> approve -> execute_after_approval

In production, replace DemoApprovalService calls with `agent.approve(...)`,
`agent.get_approval(...)`, and `agent.execute_after_approval(...)`.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from agentveil import AVPAgent, AVPError, ControlledActionOutcome


def _jcs_like(data: dict[str, Any]) -> str:
    """Return stable JSON text for demo receipts."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


class DemoApprovalService:
    """No-backend stand-in that preserves the SDK approval method sequence."""

    def __init__(self, agent_did: str) -> None:
        self.agent_did = agent_did
        self._approvals: dict[str, dict[str, Any]] = {}
        self._approval_receipts: dict[str, str] = {}

    def controlled_action_requires_approval(
        self,
        *,
        action: str,
        resource: str,
        environment: str,
        delegation_receipt: dict[str, Any],
        params: dict[str, Any],
    ) -> ControlledActionOutcome:
        audit_id = f"urn:uuid:{uuid.uuid4()}"
        approval_id = f"urn:uuid:{uuid.uuid4()}"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        approval = {
            "id": approval_id,
            "status": "pending",
            "audit_id": audit_id,
            "action": action,
            "resource": resource,
            "environment": environment,
            "expires_at": expires_at.isoformat(),
            "delegation_receipt_hash": f"demo:{delegation_receipt['id']}",
        }
        self._approvals[approval_id] = approval
        decision = {
            "audit_id": audit_id,
            "decision": "WAITING_FOR_HUMAN_APPROVAL",
            "agent_did": self.agent_did,
            "action": action,
            "resource": resource,
            "environment": environment,
            "params": params,
        }
        return ControlledActionOutcome(
            status="approval_required",
            decision=decision,
            approval=approval,
        )

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        return dict(self._approvals[approval_id])

    def approve(self, approval_id: str) -> str:
        approval = self._approvals[approval_id]
        approval["status"] = "approved"
        receipt_jcs = _jcs_like(
            {
                "schema_version": "human_approval_receipt/2",
                "approval_id": approval_id,
                "audit_id": approval["audit_id"],
                "decision": "APPROVED",
                "action": approval["action"],
                "resource": approval["resource"],
                "environment": approval["environment"],
                "proof": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": "did:key:demo#approval",
                    "proofValue": "demo-only",
                },
            }
        )
        self._approval_receipts[approval_id] = receipt_jcs
        return receipt_jcs

    def execute_after_approval(
        self,
        *,
        audit_id: str,
        approval_id: str,
        action: str,
        resource: str,
        environment: str,
        params: dict[str, Any],
    ) -> ControlledActionOutcome:
        approval = self._approvals[approval_id]
        if approval["status"] != "approved":
            raise RuntimeError(f"approval is not approved: {approval['status']}")
        receipt_jcs = _jcs_like(
            {
                "schema_version": "execution_receipt/2",
                "receipt_id": f"urn:uuid:{uuid.uuid4()}",
                "audit_id": audit_id,
                "approval_id": approval_id,
                "agent_did": self.agent_did,
                "action": action,
                "resource": resource,
                "environment": environment,
                "params": params,
                "status": "SUCCESS",
                "approval_receipt_jcs": self._approval_receipts[approval_id],
            }
        )
        return ControlledActionOutcome(
            status="executed",
            audit_id=audit_id,
            approval_id=approval_id,
            receipt_jcs=receipt_jcs,
            receipt=json.loads(receipt_jcs),
        )


def main() -> int:
    owner = AVPAgent.create(mock=True, name="approval-owner", save=False)
    agent = AVPAgent.create(mock=True, name="approval-agent", save=False)

    delegation = owner.issue_delegation_receipt(
        agent_did=agent.did,
        allowed_categories=["infrastructure"],
        valid_for=timedelta(minutes=15),
        purpose="Allow one reviewed infrastructure change",
    )
    owner.verify_delegation_receipt(delegation)

    action = "infra.volume.delete"
    resource = "volume:vol-123"
    environment = "production"
    params = {"resource_id": "vol-123"}

    demo = DemoApprovalService(agent.did)
    outcome = demo.controlled_action_requires_approval(
        action=action,
        resource=resource,
        environment=environment,
        params=params,
        delegation_receipt=delegation,
    )

    approval_id = outcome.approval["id"]
    approval = demo.get_approval(approval_id)
    print(f"status={outcome.status}")
    print(f"approval_id={approval_id}")
    print(f"approval_status={approval['status']}")
    print(f"action={approval['action']}")

    approval_receipt_jcs = demo.approve(approval_id)
    approval_receipt = json.loads(approval_receipt_jcs)
    print(f"approval_decision={approval_receipt['decision']}")

    final = demo.execute_after_approval(
        audit_id=outcome.decision["audit_id"],
        approval_id=approval_id,
        action=action,
        resource=resource,
        environment=environment,
        params=params,
    )
    print(f"final_status={final.status}")
    print(f"receipt_status={final.receipt['status']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AVPError, RuntimeError, KeyError, ValueError) as exc:
        print(f"approval_flow_error={type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
