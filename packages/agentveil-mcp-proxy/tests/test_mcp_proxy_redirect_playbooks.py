"""Public tests for bounded redirect metadata.

Detailed risk-family/playbook coverage is kept out of this public smoke surface.
These tests keep the public contract focused on behavior: routed risky actions
receive bounded redirect identifiers, not raw safe-step text or payloads.
"""

from __future__ import annotations

from agentveil_mcp_proxy.approval.manager import ApprovalOutcome
from agentveil_mcp_proxy.classification import ClassifiedToolCall, infer_action_family, sha256_text
from agentveil_mcp_proxy.passthrough import _approval_required_error, _blocked_error, _enrich_redirect_error_data
from agentveil_mcp_proxy.policy import PolicyDecision, RiskClass
from agentveil_mcp_proxy.product_route import evaluate_product_route_tool
from agentveil_mcp_proxy.redirect_playbooks import (
    build_risk_family_guidance,
    redirect_fields_from_guidance,
    uses_risk_family_redirects,
)

PAYLOAD_HASH = "sha256:" + "a" * 64


def _product_route_classification(tool: str) -> ClassifiedToolCall:
    evaluation = evaluate_product_route_tool(tool)
    return ClassifiedToolCall(
        server="product",
        tool=tool,
        action_plain=tool,
        action=tool,
        action_hash=sha256_text(tool),
        resource_plain=None,
        resource=None,
        resource_hash=None,
        payload_hash=PAYLOAD_HASH,
        risk_class=evaluation.risk_class,
        policy_evaluation=evaluation,
        action_family=infer_action_family(tool),
    )


def _non_product_classification(tool: str = "write_file") -> ClassifiedToolCall:
    from agentveil_mcp_proxy.policy import PolicyEvaluation

    evaluation = PolicyEvaluation(
        decision=PolicyDecision.APPROVAL,
        risk_class=RiskClass.WRITE,
        policy_id="filesystem-pack",
        policy_rule_id="filesystem-write",
        matched_rule_ids=("filesystem-write",),
        policy_context_hash="c" * 64,
    )
    return ClassifiedToolCall(
        server="filesystem",
        tool=tool,
        action_plain=tool,
        action=tool,
        action_hash=sha256_text(tool),
        resource_plain=None,
        resource=None,
        resource_hash=None,
        payload_hash=PAYLOAD_HASH,
        risk_class=RiskClass.WRITE,
        policy_evaluation=evaluation,
        action_family=infer_action_family(tool),
    )


def _assert_bounded_redirect_fields(data: dict) -> None:
    for key in ("risk_family", "redirect_playbook_id", "safe_first_step_id"):
        assert isinstance(data.get(key), str) and data[key]
    assert data["redirect_playbook_id"] == data["safe_first_step_id"]
    assert "safe_first_step" not in data
    assert data.get("target_reached") is False


def test_risky_product_route_action_gets_bounded_redirect_fields() -> None:
    guidance = build_risk_family_guidance(_product_route_classification("write_file"), outcome="approval")
    fields = redirect_fields_from_guidance(guidance)

    _assert_bounded_redirect_fields(fields)


def test_non_product_redirect_metadata_remains_bounded() -> None:
    data = _enrich_redirect_error_data(
        {"status": "approval_required", "reason": "local_approval_required"},
        _non_product_classification(),
        outcome="approval",
        original_request_id="req-read-1",
    )

    assert isinstance(data.get("redirect_playbook_id"), str) and data["redirect_playbook_id"]
    assert isinstance(data.get("suggested_next_step_id"), str) and data["suggested_next_step_id"]
    assert "safe_first_step" not in data
    assert uses_risk_family_redirects(_product_route_classification("write_file")) is True
    assert uses_risk_family_redirects(_non_product_classification()) is False


def test_approval_required_error_includes_bounded_redirect_metadata() -> None:
    response = _approval_required_error(
        "req-write",
        reason="local_approval_required",
        approval_outcome=ApprovalOutcome(
            "approval-1",
            "pending",
            "local_approval_required",
            approval_url="http://127.0.0.1/approval/test",
        ),
        classification=_product_route_classification("write_file"),
        enrich_guidance=True,
    )
    data = response["error"]["data"]

    _assert_bounded_redirect_fields(data)
    assert data["status"] == "approval_required"
    assert data["record_id"] == "approval-1"
    assert data["approval_url"].startswith("http://127.0.0.1/")


def test_blocked_error_includes_bounded_redirect_metadata() -> None:
    response = _blocked_error(
        "req-block-secret",
        "blocked by local MCP policy",  # claim-check: allow blocked as JSON-RPC status vocabulary.
        reason="github-secrets-block",
        classification=_product_route_classification("get_secret"),
        enrich_guidance=True,
    )
    data = response["error"]["data"]

    _assert_bounded_redirect_fields(data)
    assert data["status"] == "blocked"


def test_block_guidance_uses_bounded_fallback_fields() -> None:
    guidance = build_risk_family_guidance(_product_route_classification("get_secret"), outcome="block")
    fields = redirect_fields_from_guidance(guidance)

    _assert_bounded_redirect_fields(fields)
