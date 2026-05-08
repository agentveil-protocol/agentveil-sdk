#!/usr/bin/env python3
"""Production live developer adoption smoke for the 0.7.12 release train.

This script is intentionally not a mock. It validates the production
registration, Runtime Gate, approval, signed receipt, Proof Packet, offline
verification, and typed-error paths using pre-provisioned smoke identities.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import traceback
from datetime import timedelta
from pathlib import Path
from typing import Callable

import httpx
import jcs


BASE_URL = os.environ.get("AVP_BASE_URL", "https://agentveil.dev").rstrip("/")
REQUESTER_NAME = "0_7_12_smoke_requester"
APPROVER_NAME = "0_7_12_smoke_approver"
REQUESTER_DID = "did:key:z6Mks5BKfUngtUHUge7qJywv8b38jXJDzgeui1StCRi1zSYS"
APPROVER_DID = "did:key:z6MkfHok1PNjpgXYyJiZcw8pZGmqHbPBFrQLZmzjQD8vVJMu"

PINNED_DECISION_SIGNERS = {"did:key:z6MkkvQQ9SxaNX9eEVHd5NtEamVY3YiZSpHZE567Vxs5jQQ3"}
PINNED_EXECUTION_SIGNERS = {"did:key:z6MkkvQQ9SxaNX9eEVHd5NtEamVY3YiZSpHZE567Vxs5jQQ3"}
PINNED_HUMAN_APPROVAL_SIGNERS = {"did:key:z6Mkjw22249tpNN4LJGLyq1oGSq1Skh3ks94fiMrgi4oqveo"}

ALLOW = {
    "action": "infra.resource.inspect",
    "resource": "infra_sandbox:resource:synthetic-vol-1",
    "environment": "production",
    "params": {"resource_id": "synthetic-vol-1"},
}
BLOCK = {
    "action": "github.read_file",
    "resource": "repo:agentveil/smoke",
    "environment": "production",
    "params": {"repo": "agentveil/smoke", "path": "README.md"},
}
WAITING = {
    "action": "infra.volume.delete",
    "resource": "infra_sandbox:resource:smoke-9b-0-7-12",
    "environment": "production",
    "params": {"resource_id": "smoke-9b-0-7-12"},
}


class SmokeFailure(RuntimeError):
    """Release-gate failure."""


def log(message: str, **fields: object) -> None:
    suffix = ""
    if fields:
        suffix = " " + " ".join(f"{key}={value}" for key, value in fields.items())
    print(f"SMOKE: {message}{suffix}", flush=True)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_canonical(value: object) -> str:
    return hashlib.sha256(jcs.canonicalize(value)).hexdigest()


def extract_signer(receipt_jcs: str, verify_signed_jcs: Callable[..., dict]) -> str:
    signer = verify_signed_jcs(receipt_jcs)["signer_did"]
    require(
        isinstance(signer, str) and signer.startswith("did:key:z6Mk"),
        f"invalid signer DID: {signer}",
    )
    return signer


def expect_exception(
    label: str,
    call: Callable[[], object],
    expected: tuple[type[BaseException], ...],
) -> str:
    try:
        call()
    except expected as exc:
        name = exc.__class__.__name__
        log("typed_error_confirmed", scenario=label, exception=name)
        return name
    except Exception as exc:  # noqa: BLE001 - exact unexpected failure is evidence.
        raise SmokeFailure(f"{label} raised unexpected {exc.__class__.__name__}: {exc}") from exc
    raise SmokeFailure(f"{label} did not raise")


def require_agent_file(name: str) -> None:
    path = Path.home() / ".avp" / "agents" / f"{name}.json"
    require(path.exists(), f"missing smoke credential file: {path}")


def probe_agent_status(did: str) -> dict:
    response = httpx.get(f"{BASE_URL}/v1/agents/{did}", timeout=15.0)
    response.raise_for_status()
    data = response.json()
    require(data.get("status") == "active", f"{did} status is {data.get('status')}")
    require(data.get("is_verified") is True, f"{did} is not verified")
    return data


def runtime_probe(agent, label: str, expected: str, fixture: dict, delegation_receipt: dict) -> dict:
    decision = agent.runtime_evaluate(
        action=fixture["action"],
        resource=fixture["resource"],
        environment=fixture["environment"],
        delegation_receipt=delegation_receipt,
    )
    actual = decision.get("decision")
    require(
        actual == expected,
        f"{label} fixture drift: expected={expected} actual={actual} reason={decision.get('reason')}",
    )
    log(
        "fixture_probe",
        label=label,
        decision=actual,
        audit_id=decision["audit_id"],
        reason=decision.get("reason"),
    )
    return decision


def main() -> int:
    try:
        from agentveil import AVPAgent, verify_proof_packet, verify_signed_jcs
        from agentveil.exceptions import AVPAuthError, AVPNotFoundError, AVPValidationError

        log("python_version", value=sys.version.split()[0])
        require(BASE_URL == "https://agentveil.dev", f"unexpected base URL: {BASE_URL}")
        health = httpx.get(f"{BASE_URL}/v1/health", timeout=15.0)
        health.raise_for_status()
        log("health_probe", base_url=BASE_URL, response=json.dumps(health.json(), sort_keys=True))

        require_agent_file(REQUESTER_NAME)
        require_agent_file(APPROVER_NAME)
        requester = AVPAgent.load(BASE_URL, name=REQUESTER_NAME)
        approver = AVPAgent.load(BASE_URL, name=APPROVER_NAME)
        require(requester.did == REQUESTER_DID, f"requester DID drift: {requester.did}")
        require(approver.did == APPROVER_DID, f"approver DID drift: {approver.did}")
        require(requester.is_verified and approver.is_verified, "saved smoke identities not verified")

        requester_status = probe_agent_status(requester.did)
        approver_status = probe_agent_status(approver.did)
        log(
            "identity_probe",
            requester_did=requester.did,
            requester_status=requester_status.get("status"),
            requester_verified=requester_status.get("is_verified"),
            approver_did=approver.did,
            approver_status=approver_status.get("status"),
            approver_verified=approver_status.get("is_verified"),
        )

        delegation_receipt = approver.issue_delegation_receipt(
            agent_did=requester.did,
            allowed_categories=["infrastructure"],
            valid_for=timedelta(minutes=30),
            purpose="AVP SDK 0.7.12 live developer adoption smoke",
        )
        verification = requester.verify_delegation_receipt(delegation_receipt)
        scopes = [
            entry.get("value")
            for entry in verification.get("scope", [])
            if entry.get("predicate") == "allowed_category"
        ]
        require(verification.get("valid") is True, "DelegationReceipt invalid")
        require("infrastructure" in scopes, "DelegationReceipt missing infrastructure scope")

        log(
            "CRITERION 1 PASS: production path mirrored",
            base_url=BASE_URL,
            requester_did=requester.did,
            approver_did=approver.did,
        )
        log(
            "CRITERION 2 PASS: delegation_receipt_hash="
            + sha256_canonical(delegation_receipt),
            valid=verification.get("valid"),
            scope=",".join(scopes),
        )

        runtime_probe(requester, "ALLOW", "ALLOW", ALLOW, delegation_receipt)
        runtime_probe(requester, "BLOCK", "BLOCK", BLOCK, delegation_receipt)
        runtime_probe(requester, "WAITING", "WAITING_FOR_HUMAN_APPROVAL", WAITING, delegation_receipt)

        allow_outcome = requester.controlled_action(
            action=ALLOW["action"],
            resource=ALLOW["resource"],
            environment=ALLOW["environment"],
            params=ALLOW["params"],
            delegation_receipt=delegation_receipt,
        )
        require(allow_outcome.status == "executed", f"ALLOW outcome drift: {allow_outcome.status}")

        approval_outcome = requester.controlled_action(
            action=WAITING["action"],
            resource=WAITING["resource"],
            environment=WAITING["environment"],
            params=WAITING["params"],
            delegation_receipt=delegation_receipt,
            approval_expires_in_seconds=900,
        )
        require(
            approval_outcome.status == "approval_required",
            f"WAITING outcome drift: {approval_outcome.status}",
        )
        require(
            approval_outcome.approval and "approval_id" in approval_outcome.approval,
            f"approval_required outcome missing approval_id: {approval_outcome.approval}",
        )

        block_outcome = requester.controlled_action(
            action=BLOCK["action"],
            resource=BLOCK["resource"],
            environment=BLOCK["environment"],
            params=BLOCK["params"],
            delegation_receipt=delegation_receipt,
        )
        require(block_outcome.status == "blocked", f"BLOCK outcome drift: {block_outcome.status}")
        log(
            "CRITERION 3 PASS: executed=true, approval_required=true, blocked=true",
            executed_audit_id=allow_outcome.decision["audit_id"],
            approval_audit_id=approval_outcome.decision["audit_id"],
            blocked_audit_id=block_outcome.decision["audit_id"],
        )

        approval_id = approval_outcome.approval["approval_id"]
        approval_lookup = approver.get_approval(approval_id)
        require(
            approval_lookup.get("approval_id") == approval_id,
            f"approval lookup mismatch: {approval_lookup}",
        )
        approval_receipt_jcs = approver.approve(approval_id)
        final_outcome = requester.execute_after_approval(
            audit_id=approval_outcome.decision["audit_id"],
            approval_id=approval_id,
            action=WAITING["action"],
            resource=WAITING["resource"],
            environment=WAITING["environment"],
            params=WAITING["params"],
        )
        require(final_outcome.status == "executed", f"final outcome drift: {final_outcome.status}")
        require(final_outcome.receipt_jcs, "final execution receipt missing")
        log(
            "CRITERION 4 PASS: approval_id="
            + approval_id,
            approval_receipt_jcs_sha256=sha256_text(approval_receipt_jcs),
            final_receipt_jcs_sha256=sha256_text(final_outcome.receipt_jcs),
            final_outcome_status=final_outcome.status,
            final_receipt_status=final_outcome.receipt.get("status"),
        )

        decision_receipt_jcs = requester.get_decision_receipt(approval_outcome.decision["audit_id"])
        proof_packet = requester.build_proof_packet(
            delegation_receipt=delegation_receipt,
            outcome=final_outcome,
            decision_receipt_jcs=decision_receipt_jcs,
            approval_receipt_jcs=approval_receipt_jcs,
        )
        packet = proof_packet.to_dict()
        packet_fields = {"decision_receipt_jcs", "execution_receipt_jcs", "approval_receipt_jcs"}
        missing = sorted(field for field in packet_fields if field not in packet)
        require(not missing, f"ProofPacket missing JCS fields: {missing}")
        log(
            "CRITERION 5 PASS: packet has decision/execution/approval receipt jcs",
            fields=",".join(sorted(packet_fields)),
            audit_id=packet.get("audit_id"),
        )

        actual_decision_signer = extract_signer(decision_receipt_jcs, verify_signed_jcs)
        actual_execution_signer = extract_signer(final_outcome.receipt_jcs, verify_signed_jcs)
        actual_approval_signer = extract_signer(approval_receipt_jcs, verify_signed_jcs)
        require(actual_decision_signer in PINNED_DECISION_SIGNERS, f"decision signer drift: {actual_decision_signer}")
        require(actual_execution_signer in PINNED_EXECUTION_SIGNERS, f"execution signer drift: {actual_execution_signer}")
        require(actual_approval_signer in PINNED_HUMAN_APPROVAL_SIGNERS, f"approval signer drift: {actual_approval_signer}")

        verified_packet = verify_proof_packet(
            packet,
            trusted_decision_signer_dids=PINNED_DECISION_SIGNERS,
            trusted_execution_signer_dids=PINNED_EXECUTION_SIGNERS,
            trusted_human_approval_signer_dids=PINNED_HUMAN_APPROVAL_SIGNERS,
        )
        require(verified_packet.get("valid") is True, "verify_proof_packet returned invalid")
        captured = {
            "decision": actual_decision_signer,
            "execution": actual_execution_signer,
            "human_approval": actual_approval_signer,
        }
        log(
            "CRITERION 6 PASS: signature_valid=True, linkage_valid=True, trust_set_strict=True",
            captured_signer_dids=json.dumps(captured, sort_keys=True),
            pinned_decision_signers=json.dumps(sorted(PINNED_DECISION_SIGNERS)),
            pinned_execution_signers=json.dumps(sorted(PINNED_EXECUTION_SIGNERS)),
            pinned_human_approval_signers=json.dumps(sorted(PINNED_HUMAN_APPROVAL_SIGNERS)),
        )

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            unregistered = AVPAgent.create(BASE_URL, name="0_7_12_smoke_unregistered_temp", save=False)
        typed = [
            expect_exception(
                "local_empty_attest_batch",
                lambda: requester.attest_batch([]),
                (AVPValidationError,),
            ),
            expect_exception(
                "unknown_approval_id",
                lambda: requester.get_approval("urn:uuid:00000000-0000-0000-0000-000000000000"),
                (AVPNotFoundError, AVPAuthError),
            ),
            expect_exception(
                "unregistered_requester_action",
                lambda: unregistered.runtime_evaluate(
                    action=ALLOW["action"],
                    resource=ALLOW["resource"],
                    environment=ALLOW["environment"],
                    delegation_receipt=delegation_receipt,
                ),
                (AVPAuthError,),
            ),
        ]
        require(len(typed) == 3, f"typed error coverage incomplete: {typed}")
        log("CRITERION 7 PASS: triggered_exceptions=" + json.dumps(typed), count=len(typed))

        leftovers = sorted(Path("/tmp").glob("avp-slice9b-home-*"))
        require(not leftovers, f"unexpected /tmp leftovers: {[str(p) for p in leftovers]}")
        log("cleanup_confirmation", tmp_leftovers=0)
        log("LIVE_DEVELOPER_ADOPTION_SMOKE PASS")
        return 0
    except Exception as exc:  # noqa: BLE001 - release smoke must report exact failure.
        log("LIVE_DEVELOPER_ADOPTION_SMOKE FAIL", exception=exc.__class__.__name__, error_message=str(exc))
        if not isinstance(exc, SmokeFailure):
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
