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
    build_original_request_fingerprint,
    build_risk_family_guidance,
    build_structured_redirect_contract,
    redirect_fields_from_guidance,
    uses_risk_family_redirects,
)

PAYLOAD_HASH = "sha256:" + "a" * 64
RESOURCE_HASH = "sha256:" + "b" * 64


def _product_route_classification(
    tool: str,
    *,
    resource_plain: str | None = "notes.txt",
) -> ClassifiedToolCall:
    evaluation = evaluate_product_route_tool(tool)
    resource_hash = None if resource_plain is None else sha256_text(resource_plain)
    return ClassifiedToolCall(
        server="product",
        tool=tool,
        action_plain=tool,
        action=tool,
        action_hash=sha256_text(tool),
        resource_plain=resource_plain,
        resource=resource_hash,
        resource_hash=resource_hash,
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
        resource_plain="notes.txt",
        resource=RESOURCE_HASH,
        resource_hash=RESOURCE_HASH,
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
    fields = redirect_fields_from_guidance(
        guidance,
        classification=_product_route_classification("write_file"),
        request_id="req-write-1",
    )

    _assert_bounded_redirect_fields(fields)
    assert fields["redirect_outcome"] == "approval_required"
    assert fields["redirect"]["then_retry_original"] is True
    assert fields["redirect"]["target_changed"] is False
    assert fields["redirect"]["next_action"]["tool"] == "read_file"
    assert fields["redirect"]["next_action"]["args"] == {"path": "notes.txt"}
    assert fields["original_request_fingerprint"]["request_id"] == "req-write-1"
    assert fields["original_request_fingerprint"]["payload_hash"] == PAYLOAD_HASH
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in str(fields)


def test_hard_blocked_redirect_uses_distinct_contract() -> None:
    classification = _product_route_classification("delete_file")
    guidance = build_risk_family_guidance(classification, outcome="block")
    fields = redirect_fields_from_guidance(
        guidance,
        classification=classification,
        request_id="req-delete-1",
    )

    assert fields["redirect_outcome"] == "hard_blocked"
    assert fields["redirect"]["then_retry_original"] is False
    assert fields["redirect"]["next_action"]["tool"] in {"read_file", "list_workspace"}


def test_secret_block_does_not_suggest_read_file() -> None:
    classification = _product_route_classification("get_secret", resource_plain=".env")
    guidance = build_risk_family_guidance(classification, outcome="block")
    redirect = build_structured_redirect_contract(
        classification,
        guidance,
        redirect_outcome="hard_blocked",
    )

    assert redirect["kind"] == "sensitive_path_blocked"
    assert redirect["then_retry_original"] is False
    assert redirect["next_action"]["tool"] != "read_file"


def test_redirect_contract_respects_advertised_tool_surface() -> None:
    classification = _product_route_classification("write_file")
    guidance = build_risk_family_guidance(classification, outcome="approval")
    redirect = build_structured_redirect_contract(
        classification,
        guidance,
        redirect_outcome="approval_required",
        available_tools=frozenset({"git_status"}),
    )

    assert redirect["next_action"] is not None
    assert redirect["next_action"]["tool"] == "git_status"
    assert redirect["next_action"]["tool"] != "list_workspace"


def test_redirect_contract_null_when_no_safe_tool_advertised() -> None:
    classification = _product_route_classification("write_file")
    guidance = build_risk_family_guidance(classification, outcome="approval")
    redirect = build_structured_redirect_contract(
        classification,
        guidance,
        redirect_outcome="approval_required",
        available_tools=frozenset(),
    )

    assert redirect["next_action"] is None
    assert redirect["next_action_unavailable_reason"]
    assert "list_workspace" not in str(redirect)


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
    assert data["redirect_outcome"] == "approval_required"
    assert data["record_id"] == "approval-1"
    assert data["approval_url"].startswith("http://127.0.0.1/")
    assert data["redirect"]["then_retry_original"] is True
    assert data["original_request_fingerprint"]["tool"] == "write_file"


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
    assert data["redirect_outcome"] == "hard_blocked"
    assert data["redirect"]["then_retry_original"] is False


def test_block_guidance_uses_bounded_fallback_fields() -> None:
    guidance = build_risk_family_guidance(_product_route_classification("get_secret"), outcome="block")
    fields = redirect_fields_from_guidance(
        guidance,
        classification=_product_route_classification("get_secret"),
        request_id="req-secret",
    )

    _assert_bounded_redirect_fields(fields)
    assert fields["redirect_outcome"] == "hard_blocked"


def test_original_request_fingerprint_is_bounded() -> None:
    classification = _product_route_classification("write_file")
    fingerprint = build_original_request_fingerprint(classification, "req-1")

    assert fingerprint["tool"] == "write_file"
    assert fingerprint["target_ref"] == f"resource:{classification.resource_hash}"
    assert fingerprint["payload_hash"] == PAYLOAD_HASH
    assert fingerprint["request_id"] == "req-1"
