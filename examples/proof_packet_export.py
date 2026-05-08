#!/usr/bin/env python3
"""Build, save, reload, and verify a Proof Packet offline.

This no-backend demo uses mock SDK agents plus disposable local signer keys to
simulate the signed DecisionReceipt and ExecutionReceipt a backend would emit.
In production, keep the exact receipt_jcs strings returned by AgentVeil.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path

import base58
import jcs
from nacl.signing import SigningKey

from agentveil import AVPAgent, ControlledActionOutcome, verify_proof_packet
from agentveil.proof import ProofVerificationError


def did_for_key(signing_key: SigningKey) -> str:
    multicodec = b"\xed\x01" + bytes(signing_key.verify_key)
    return "did:key:z" + base58.b58encode(multicodec).decode("ascii")


def sign_receipt(body: dict, signing_key: SigningKey) -> str:
    signer_did = did_for_key(signing_key)
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": f"{signer_did}#{signer_did[len('did:key:'):]}",
        "proofValue": "z" + base58.b58encode(
            signing_key.sign(jcs.canonicalize(body)).signature
        ).decode("ascii"),
    }
    signed = dict(body)
    signed["proof"] = proof
    return jcs.canonicalize(signed).decode("utf-8")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_jcs(value: dict) -> str:
    return hashlib.sha256(jcs.canonicalize(value)).hexdigest()


def main() -> int:
    owner = AVPAgent.create(mock=True, name="proof-owner")
    agent = AVPAgent.create(mock=True, name="proof-agent")

    delegation = owner.issue_delegation_receipt(
        agent_did=agent.did,
        allowed_categories=["deploy"],
        valid_for=timedelta(minutes=15),
        purpose="Export one proof packet for a deploy action",
    )

    signer = SigningKey.generate()
    signer_did = did_for_key(signer)
    audit_id = f"urn:uuid:{uuid.uuid4()}"
    action = "deploy.release"
    resource = "service:billing-api"
    environment = "production"

    decision_body = {
        "schema_version": "decision_receipt/2",
        "audit_id": audit_id,
        "agent_did": agent.did,
        "action": action,
        "resource": resource,
        "environment": environment,
        "decision": "ALLOW",
        "delegation_receipt_hash": sha256_jcs(delegation),
    }
    decision_jcs = sign_receipt(decision_body, signer)

    execution_body = {
        "schema_version": "execution_receipt/2",
        "receipt_id": f"urn:uuid:{uuid.uuid4()}",
        "gate_audit_id": audit_id,
        "agent_did": agent.did,
        "action": action,
        "resource": resource,
        "environment": environment,
        "status": "SUCCESS",
        "decision_receipt_hash": sha256_text(decision_jcs),
    }
    execution_jcs = sign_receipt(execution_body, signer)

    outcome = ControlledActionOutcome(
        status="executed",
        decision=decision_body,
        receipt_jcs=execution_jcs,
        receipt=json.loads(execution_jcs),
    )

    packet = agent.build_proof_packet(
        delegation_receipt=delegation,
        outcome=outcome,
        decision_receipt_jcs=decision_jcs,
    )

    path = Path(tempfile.gettempdir()) / "agentveil-proof-packet.json"
    path.write_text(json.dumps(packet.to_dict(), indent=2), encoding="utf-8")
    loaded = json.loads(path.read_text(encoding="utf-8"))

    try:
        verified = verify_proof_packet(
            loaded,
            trusted_backend_signer_dids={signer_did},
        )
    except ProofVerificationError as exc:
        print("verified: False")
        print("reason:", str(exc))
        return 1

    print("saved:", path)
    print("verified:", verified["valid"])
    print("signer:", signer_did)
    print("delegation_hash:", verified["delegation_receipt_hash"][:16])
    print("decision_digest:", verified["decision_receipt"]["digest"][:16])
    print("execution_digest:", verified["execution_receipt"]["digest"][:16])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
