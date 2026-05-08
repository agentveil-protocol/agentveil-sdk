"""Approval routing pattern for a controlled action.

By default this no-backend demo uses mock agents and an in-memory approval
service because mock `controlled_action()` does not call the live Runtime Gate.
The object shapes and method sequence mirror the live SDK path:

controlled_action -> approval_required -> approve -> execute_after_approval

For a real backend exercise, set:

    AVP_APPROVAL_LIVE=1
    AVP_BASE_URL=https://agentveil.dev
    AVP_AGENT_NAME=<saved requester agent name>
    AVP_AGENT_PASSPHRASE=<requester passphrase if encrypted>
    AVP_APPROVER_NAME=<saved principal/approver name>
    AVP_APPROVER_PASSPHRASE=<approver passphrase if encrypted>

The live path calls real SDK methods: `controlled_action(...)` (which calls
`create_approval(...)` when the Runtime Gate waits), `get_approval(...)`,
`approve(...)`, and `execute_after_approval(...)`.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from agentveil import AVPAgent, AVPError, ControlledActionOutcome


CONFIG_ERROR = 3
RETRYABLE_ERROR = 1
NON_RETRYABLE_ERROR = 2


class ConfigError(RuntimeError):
    """Raised when live-mode environment configuration is incomplete."""


def _jcs_like(data: dict[str, Any]) -> str:
    """Return stable JSON text for demo receipts, not backend canonical JCS."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _json_env(name: str, default: dict[str, Any]) -> dict[str, Any]:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{name} must be valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a JSON object")
    return value


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ConfigError(f"{name} is required when AVP_APPROVAL_LIVE=1")
    return value


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
                "schema_version": "demo/human_approval_receipt",
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
                "schema_version": "demo/execution_receipt",
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


def run_mock_flow() -> int:
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


def run_live_flow() -> int:
    base_url = _required_env("AVP_BASE_URL")
    agent_name = _required_env("AVP_AGENT_NAME")
    approver_name = _required_env("AVP_APPROVER_NAME")
    agent_passphrase = os.getenv("AVP_AGENT_PASSPHRASE")
    approver_passphrase = os.getenv("AVP_APPROVER_PASSPHRASE")

    action = os.getenv("AVP_APPROVAL_ACTION", "infra.volume.delete")
    resource = os.getenv("AVP_APPROVAL_RESOURCE", "volume:vol-123")
    environment = os.getenv("AVP_APPROVAL_ENVIRONMENT", "production")
    category = os.getenv("AVP_APPROVAL_CATEGORY", "infrastructure")
    params = _json_env("AVP_APPROVAL_PARAMS_JSON", {"resource_id": "vol-123"})

    agent = AVPAgent.load(base_url, name=agent_name, passphrase=agent_passphrase)
    approver = AVPAgent.load(
        base_url,
        name=approver_name,
        passphrase=approver_passphrase,
    )

    delegation = approver.issue_delegation_receipt(
        agent_did=agent.did,
        allowed_categories=[category],
        valid_for=timedelta(minutes=15),
        purpose="Allow one reviewed live approval-flow action",
    )

    outcome = agent.controlled_action(
        action=action,
        resource=resource,
        environment=environment,
        params=params,
        delegation_receipt=delegation,
    )

    print(f"live_status={outcome.status}")
    if outcome.status != "approval_required":
        print("expected_status=approval_required")
        print("live_note=configure backend policy so this action requires approval")
        return NON_RETRYABLE_ERROR

    if not outcome.approval or "id" not in outcome.approval:
        raise RuntimeError("approval_required outcome did not include approval['id']")

    approval_id = outcome.approval["id"]
    print(f"approval_id={approval_id}")
    print(f"outcome_approval_id={outcome.approval_id or '<empty>'}")

    approval = approver.get_approval(approval_id)
    print(f"approval_status={approval.get('status')}")
    print(f"approval_action={approval.get('action', action)}")

    approval_receipt_jcs = approver.approve(approval_id)
    approval_receipt = json.loads(approval_receipt_jcs)
    print(f"approval_receipt_schema={approval_receipt.get('schema_version')}")

    final = agent.execute_after_approval(
        audit_id=outcome.decision["audit_id"],
        approval_id=approval_id,
        action=action,
        resource=resource,
        environment=environment,
        params=params,
    )
    print(f"final_status={final.status}")
    print(f"final_approval_id={final.approval_id}")
    if final.receipt:
        print(f"receipt_schema={final.receipt.get('schema_version')}")
    return 0


def main() -> int:
    if os.getenv("AVP_APPROVAL_LIVE") == "1":
        return run_live_flow()
    return run_mock_flow()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConfigError, FileNotFoundError) as exc:
        print(f"approval_flow_config_error={exc}", file=sys.stderr)
        raise SystemExit(CONFIG_ERROR)
    except httpx.RequestError as exc:
        print(f"approval_flow_network_error={exc}", file=sys.stderr)
        raise SystemExit(RETRYABLE_ERROR)
    except (AVPError, RuntimeError, KeyError, ValueError) as exc:
        print(f"approval_flow_error={type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(NON_RETRYABLE_ERROR)
