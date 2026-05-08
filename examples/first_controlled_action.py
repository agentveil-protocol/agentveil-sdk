"""
First controlled-action integration template.

Default behavior is safe for production API use: it loads the local identity,
runs integration preflight, prints the readiness result, and exits before
Runtime Gate or execution calls.

To run the controlled-action path, set:

    AVP_RUN_CONTROLLED_ACTION=1
    AVP_DELEGATION_RECEIPT_FILE=/path/to/delegation_receipt.json

or:

    AVP_DELEGATION_RECEIPT_JSON='{"@context": ...}'

Do not put private keys, cloud tokens, or raw private logs in the delegation
receipt or action params.

Set AVP_PROOF_PACKET_OUT=/path/to/proof_packet.json to retain the explicit
pilot proof packet after controlled_action().
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from agentveil import (
    AVPAgent,
    AVPError,
    AVPRateLimitError,
    AVPServerError,
    AVPValidationError,
    ControlledActionOutcome,
)


BASE_URL = os.getenv("AVP_BASE_URL", "https://agentveil.dev")
AGENT_NAME = os.getenv("AVP_AGENT_NAME", "customer-agent")
AGENT_PASSPHRASE = os.getenv("AVP_AGENT_PASSPHRASE")

ACTION = os.getenv("AVP_ACTION", "infra.resource.inspect")
RESOURCE = os.getenv("AVP_RESOURCE", "resource:vol-123")
ENVIRONMENT = os.getenv("AVP_ENVIRONMENT", "development")
PARAMS_JSON = os.getenv("AVP_ACTION_PARAMS_JSON", '{"resource_id": "vol-123"}')


def load_delegation_receipt() -> dict[str, Any] | None:
    """Load the customer-issued DelegationReceipt from env or a local file."""
    inline = os.getenv("AVP_DELEGATION_RECEIPT_JSON")
    if inline:
        return json.loads(inline)

    receipt_file = os.getenv("AVP_DELEGATION_RECEIPT_FILE")
    if receipt_file:
        return json.loads(Path(receipt_file).read_text())

    return None


def print_preflight_failure(report: Any) -> None:
    print(f"preflight.status={report.status}")
    print(f"preflight.next_action={report.next_action}")
    if report.retry_after is not None:
        print(f"preflight.retry_after={report.retry_after}")


def handle_outcome(result: ControlledActionOutcome) -> None:
    if result.status == "executed":
        print("status=executed")
        print(f"audit_id={result.decision.get('audit_id') if result.decision else ''}")

        receipt_path = os.getenv("AVP_RECEIPT_OUT")
        if receipt_path and result.receipt_jcs:
            Path(receipt_path).write_text(result.receipt_jcs)
            print(f"receipt_jcs_written={receipt_path}")
        else:
            print("receipt_jcs_available=true")
        return

    if result.status == "approval_required":
        print("status=approval_required")
        print(f"audit_id={result.decision.get('audit_id') if result.decision else ''}")
        print(f"approval_id={result.approval.get('approval_id') if result.approval else ''}")
        print("next_action=principal must approve, then call execute_after_approval(...)")
        return

    print("status=blocked")
    print(f"reason={result.reason}")


def write_proof_packet(
    agent: AVPAgent,
    result: ControlledActionOutcome,
    delegation_receipt: dict[str, Any],
) -> None:
    proof_packet_path = os.getenv("AVP_PROOF_PACKET_OUT")
    if not proof_packet_path:
        return

    packet = agent.build_proof_packet(
        delegation_receipt=delegation_receipt,
        outcome=result,
    )
    Path(proof_packet_path).write_text(json.dumps(packet.to_dict(), indent=2, sort_keys=True))
    print(f"proof_packet_written={proof_packet_path}")


def print_sdk_error(exc: AVPError) -> None:
    if isinstance(exc, AVPRateLimitError):
        print("error=rate_limited")
        print(f"retry_after={exc.retry_after}")
        return

    if isinstance(exc, AVPValidationError):
        print("error=validation_failed")
        print(f"detail={exc.message}")
        return

    if isinstance(exc, AVPServerError):
        print("error=backend_unavailable")
        print("next_action=retry later with backoff")
        return

    print("error=avp_request_failed")
    print(f"detail={exc.message}")


def main() -> int:
    agent = AVPAgent.load(BASE_URL, name=AGENT_NAME, passphrase=AGENT_PASSPHRASE)

    report = agent.integration_preflight()
    if not report.ready:
        print_preflight_failure(report)
        return 1

    print("preflight.status=ready")
    print(f"agent.did={agent.did}")

    if os.getenv("AVP_RUN_CONTROLLED_ACTION") != "1":
        print("next_action=set AVP_RUN_CONTROLLED_ACTION=1 after reviewing the action scope")
        return 0

    delegation_receipt = load_delegation_receipt()
    if delegation_receipt is None:
        print("missing_delegation_receipt=true")
        print("next_action=set AVP_DELEGATION_RECEIPT_FILE or AVP_DELEGATION_RECEIPT_JSON")
        return 1

    params = json.loads(PARAMS_JSON)
    try:
        result = agent.controlled_action(
            action=ACTION,
            resource=RESOURCE,
            environment=ENVIRONMENT,
            params=params,
            delegation_receipt=delegation_receipt,
        )
    except AVPError as exc:
        print_sdk_error(exc)
        return 1

    handle_outcome(result)
    write_proof_packet(agent, result, delegation_receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
