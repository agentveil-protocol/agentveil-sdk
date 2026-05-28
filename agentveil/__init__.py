"""
AVP SDK — Python client for Agent Veil Protocol.

Usage:
    from agentveil import AVPAgent

    agent = AVPAgent.create("https://avp.example.com", name="MyAgent")
    agent.register()
    agent.publish_card(capabilities=["code_review", "testing"], provider="anthropic")

    rep = agent.get_reputation(other_agent_did)
    agent.attest(other_agent_did, outcome="positive", weight=0.9)
"""

from agentveil.agent import AVPAgent
from agentveil.egress import (
    ControlledEgressOutcome,
    EgressPolicyViolationError,
    EgressReceiptProofError,
    EgressReceiptVerificationError,
    controlled_egress,
    sign_egress_receipt,
    verify_egress_receipt,
)
from agentveil.mock import AVPMockAgent
from agentveil.proof import ProofVerificationError, verify_proof_packet, verify_signed_jcs
from agentveil.results import ControlledActionOutcome, IntegrationPreflightReport, ProofPacket
from agentveil.tracked import avp_tracked, clear_agent_cache
from agentveil.exceptions import (
    AVPError,
    AVPAuthError,
    AVPNotFoundError,
    AVPRateLimitError,
    AVPValidationError,
    AVPServerError,
)

__version__ = "0.7.17"

__all__ = [
    "AVPAgent",
    "AVPMockAgent",
    "ControlledActionOutcome",
    "ControlledEgressOutcome",
    "EgressPolicyViolationError",
    "EgressReceiptProofError",
    "EgressReceiptVerificationError",
    "IntegrationPreflightReport",
    "ProofPacket",
    "ProofVerificationError",
    "controlled_egress",
    "sign_egress_receipt",
    "verify_egress_receipt",
    "verify_proof_packet",
    "verify_signed_jcs",
    "avp_tracked",
    "clear_agent_cache",
    "AVPError",
    "AVPAuthError",
    "AVPNotFoundError",
    "AVPRateLimitError",
    "AVPValidationError",
    "AVPServerError",
]
