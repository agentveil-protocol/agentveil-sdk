#!/usr/bin/env python3
"""Live P5 Runtime Gate validation for the MCP proxy.

This script runs against a real AVP API, creates a local MCP proxy identity via
``agentveil-mcp-proxy init``, registers that identity, uses the generated local
control grant, and verifies ALLOW, WAITING_FOR_HUMAN_APPROVAL, and BLOCK
DecisionReceipt branches with pinned signer verification.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import agentveil.agent as agent_module
from agentveil.agent import AVPAgent
from agentveil.proof import ProofVerificationError, verify_signed_jcs
from agentveil_mcp_proxy.classification import ClassifiedToolCall, sha256_jcs, sha256_text
from agentveil_mcp_proxy.cli import init_proxy
from agentveil_mcp_proxy.policy import (
    PolicyDecision,
    PolicyEvaluation,
    ProxyConfig,
    RiskClass,
    policy_context_hash,
)
from agentveil_mcp_proxy.runtime_gate import RuntimeGateClient


BASE_URL = os.environ.get("AVP_BASE_URL", "https://agentveil.dev").rstrip("/")
AGENT_NAME = os.environ.get("AVP_MCP_PROXY_LIVE_AGENT_NAME", f"mcp_proxy_p5_{int(time.time())}")
HOME = Path(os.environ.get("AVP_HOME", tempfile.mkdtemp(prefix="avp-mcp-proxy-live-")))
TRUSTED_SIGNERS = (
    "did:key:z6MkkvQQ9SxaNX9eEVHd5NtEamVY3YiZSpHZE567Vxs5jQQ3",
    "did:key:z6Mkjw22249tpNN4LJGLyq1oGSq1Skh3ks94fiMrgi4oqveo",
)


@dataclass(frozen=True)
class Fixture:
    label: str
    expected_decision: str
    action: str
    resource: str
    environment: str
    params: dict
    risk_class: RiskClass


FIXTURES = (
    Fixture(
        label="ALLOW",
        expected_decision="ALLOW",
        action="infra.resource.inspect",
        resource="infra_sandbox:resource:synthetic-vol-1",
        environment="production",
        params={"resource_id": "synthetic-vol-1"},
        risk_class=RiskClass.READ,
    ),
    Fixture(
        label="WAITING",
        expected_decision="WAITING_FOR_HUMAN_APPROVAL",
        action="infra.volume.delete",
        resource="infra_sandbox:resource:smoke-p5-runtime-gate",
        environment="production",
        params={"resource_id": "smoke-p5-runtime-gate"},
        risk_class=RiskClass.DESTRUCTIVE,
    ),
    Fixture(
        label="BLOCK",
        expected_decision="BLOCK",
        action="github.read_file",
        resource="repo:agentveil/smoke",
        environment="production",
        params={"repo": "agentveil/smoke", "path": "README.md"},
        risk_class=RiskClass.READ,
    ),
)


class LiveSmokeFailure(RuntimeError):
    """Raised when a live Runtime Gate criterion fails."""


def log(message: str, **fields: object) -> None:
    suffix = ""
    if fields:
        suffix = " " + " ".join(f"{key}={value}" for key, value in fields.items())
    print(f"P5_LIVE: {message}{suffix}", flush=True)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LiveSmokeFailure(message)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def register_proxy_identity(identity_path: Path) -> AVPAgent:
    agent_module.AGENTS_DIR = str(HOME / "agents")
    identity = load_json(identity_path)
    agent = AVPAgent(
        BASE_URL,
        bytes.fromhex(identity["private_key_hex"]),
        name=AGENT_NAME,
        timeout=15.0,
    )
    if not agent.is_registered:
        result = agent.register(
            display_name=f"MCP Proxy P5 Live {int(time.time())}",
            capabilities=["mcp_proxy", "runtime_gate"],
        )
        log("registered_proxy_identity", did=agent.did, response_did=result.get("did"))
    return agent


def plain_privacy_config(config_path: Path) -> ProxyConfig:
    data = load_json(config_path)
    data["privacy"] = {
        "action": "plain",
        "resource": "plain",
        "payload": "hash_only",
        "evidence_upload": False,
    }
    return ProxyConfig.from_dict(data)


def classification_for(fixture: Fixture, config: ProxyConfig) -> ClassifiedToolCall:
    policy_rule_id = f"live-{fixture.label.lower()}"
    evaluation = PolicyEvaluation(
        decision=PolicyDecision.ASK_BACKEND,
        risk_class=fixture.risk_class,
        policy_id="p5-live-smoke",
        policy_rule_id=policy_rule_id,
        matched_rule_ids=(policy_rule_id,),
        policy_context_hash=policy_context_hash(
            policy_id="p5-live-smoke",
            policy_rule_id=policy_rule_id,
            risk_class=fixture.risk_class,
            decision_mode=config.mode,
        ),
    )
    return ClassifiedToolCall(
        server="live-runtime-gate",
        tool=fixture.action,
        action_plain=fixture.action,
        action=fixture.action,
        action_hash=sha256_text(fixture.action),
        resource_plain=fixture.resource,
        resource=fixture.resource,
        resource_hash=sha256_text(fixture.resource),
        payload_hash=sha256_jcs(fixture.params),
        risk_class=fixture.risk_class,
        policy_evaluation=evaluation,
    )


def verify_digest_round_trip(client: RuntimeGateClient, audit_id: str, expected_digest: str) -> str:
    receipt_jcs = client.agent.get_decision_receipt(audit_id)
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    require(digest == expected_digest, "DecisionReceipt sha256 round-trip mismatch")
    verified = None
    last_error: Exception | None = None
    for signer in client.trusted_signer_dids:
        try:
            verified = verify_signed_jcs(receipt_jcs, expected_signer_did=signer)
            break
        except ProofVerificationError as exc:
            last_error = exc
    if verified is None:
        raise LiveSmokeFailure("DecisionReceipt signer not trusted") from last_error
    require(verified["digest"] == expected_digest, "verified digest mismatch")
    return verified["signer_did"]


def main() -> int:
    try:
        require(BASE_URL == "https://agentveil.dev", f"unexpected base URL: {BASE_URL}")
        result = init_proxy(
            home=HOME,
            base_url=BASE_URL,
            agent_name=AGENT_NAME,
            trusted_signer_dids=TRUSTED_SIGNERS,
            allowed_categories=["infrastructure"],
            force=True,
        )
        registered_agent = register_proxy_identity(result.identity_path)
        config = plain_privacy_config(result.config_path)
        require(config.avp.trusted_signer_dids == TRUSTED_SIGNERS, "trusted signer config drift")
        require(registered_agent.did == result.agent_did, "registered DID mismatch")
        log(
            "setup_complete",
            base_url=BASE_URL,
            home=str(HOME),
            agent_did=result.agent_did,
            control_grant=str(result.control_grant_path),
        )

        branch_results = {}
        for fixture in FIXTURES:
            client = RuntimeGateClient.from_files(
                identity_path=result.identity_path,
                control_grant_path=result.control_grant_path,
                config=config,
                timeout=2.0,
                environment=fixture.environment,
            )
            decision = client.evaluate(classification_for(fixture, config))
            require(
                decision.decision == fixture.expected_decision,
                f"{fixture.label} decision drift: expected={fixture.expected_decision} actual={decision.decision}",
            )
            require(decision.audit_id is not None, f"{fixture.label} missing audit_id")
            signer = verify_digest_round_trip(client, decision.audit_id, decision.receipt_digest)
            branch_results[fixture.label] = decision.decision
            log(
                "branch_verified",
                label=fixture.label,
                decision=decision.decision,
                audit_id=decision.audit_id,
                decision_receipt_sha256=decision.receipt_digest,
                signer_did=signer,
            )

        require(branch_results == {
            "ALLOW": "ALLOW",
            "WAITING": "WAITING_FOR_HUMAN_APPROVAL",
            "BLOCK": "BLOCK",
        }, f"branch coverage incomplete: {branch_results}")
        log("MCP_PROXY_RUNTIME_GATE_LIVE_SMOKE PASS", branches=json.dumps(branch_results, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001 - live validation should print exact failure class.
        log("MCP_PROXY_RUNTIME_GATE_LIVE_SMOKE FAIL", exception=exc.__class__.__name__, error_message=str(exc))
        if not isinstance(exc, LiveSmokeFailure):
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
