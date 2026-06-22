"""Tests for risk-family redirect playbooks."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from agentveil_mcp_proxy.authority_boundary import (
    AUTHORITY_REASON_READ_ONLY,
    build_runtime_authority_record,
)
from agentveil_mcp_proxy.classification import (
    ClassifiedToolCall,
    infer_action_family,
    sha256_text,
)
from agentveil_mcp_proxy.cli import init_proxy, proxy_paths, run_proxy
from agentveil_mcp_proxy.control_surface import build_timeline_entry
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata
from agentveil_mcp_proxy.evidence.summary import evidence_summary_record
from agentveil_mcp_proxy.passthrough import (
    _approval_required_error,
    _blocked_error,
    _enrich_redirect_error_data,
    _redirect_playbook_id_for_classification,
)
from agentveil_mcp_proxy.policy import PolicyDecision, RiskClass
from agentveil_mcp_proxy.product_route import (
    PRODUCT_ROUTE_POLICY_ID,
    PRODUCT_ROUTE_SETUP_PROFILE,
    build_product_route_downstream_config,
    evaluate_product_route_tool,
    initialize_product_route_profile,
)
from agentveil_mcp_proxy.redirect_playbooks import (
    RISK_FAMILY_TO_PLAYBOOK,
    RedirectPlaybook,
    RiskFamily,
    attach_redirect_playbook_fields,
    build_risk_family_guidance,
    enrich_risk_family_error_data,
    redirect_fields_from_guidance,
    representative_tool_risk_families,
    resolve_risk_family,
    resolve_redirect_playbook,
    should_attach_redirect_playbook_fields,
    uses_risk_family_redirects,
)

PAYLOAD_HASH = "sha256:" + "a" * 64
RESOURCE_HASH = "sha256:" + "b" * 64


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


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _init_product_route_home(tmp_path: Path) -> Path:
    profile_root = tmp_path / "profile"
    home = tmp_path / "home"
    initialize_product_route_profile(profile_root)
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="product_route",
        setup_profile=PRODUCT_ROUTE_SETUP_PROFILE,
        downstream_config=build_product_route_downstream_config(profile_root),
    )
    pythonpath = os.environ.get("PYTHONPATH")
    if pythonpath:
        config_path = proxy_paths(home).config_path
        config = json.loads(config_path.read_text(encoding="utf-8"))
        downstream = config.setdefault("downstream", {})
        passthrough = list(downstream.get("env_passthrough") or [])
        if "PYTHONPATH" not in passthrough:
            passthrough.append("PYTHONPATH")
        downstream["env_passthrough"] = passthrough
        config_path.write_text(json.dumps(config), encoding="utf-8")
    return home


def _run_tool(home: Path, tool: str, *, call_id: str = "call-1") -> dict:
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": {}},
        })),
        out=out,
        approval_ui_mode="none",
    ) == 0
    return _responses(out.getvalue())[0]


def _assert_no_redirect_metadata(metadata: dict) -> None:
    assert "risk_family" not in metadata
    assert "redirect_playbook_id" not in metadata
    assert "safe_first_step_id" not in metadata


@pytest.mark.parametrize(
    ("tool", "risk_family", "playbook"),
    [
        ("write_file", RiskFamily.FILE_WRITE, RedirectPlaybook.INSPECT_BEFORE_WRITE),
        ("delete_file", RiskFamily.FILE_DELETE, RedirectPlaybook.INSPECT_BEFORE_DELETE),
        ("git_add", RiskFamily.GIT_MUTATION, RedirectPlaybook.SHOW_GIT_STATUS_AND_DIFF),
        ("git_commit", RiskFamily.GIT_MUTATION, RedirectPlaybook.SHOW_GIT_STATUS_AND_DIFF),
        ("pip_install", RiskFamily.PACKAGE_MUTATION, RedirectPlaybook.INSPECT_PACKAGE_RISK),
        ("pip_uninstall", RiskFamily.PACKAGE_MUTATION, RedirectPlaybook.INSPECT_PACKAGE_RISK),
        ("get_secret", RiskFamily.SECRET_ACCESS, RedirectPlaybook.SECRET_POSTURE_ONLY),
        ("get_env_secret", RiskFamily.SECRET_ACCESS, RedirectPlaybook.SECRET_POSTURE_ONLY),
        ("merge_pull_request", RiskFamily.REPO_ADMIN_OR_MERGE, RedirectPlaybook.REPO_CHANGE_REVIEW),
        ("deploy_release", RiskFamily.DEPLOY_RELEASE, RedirectPlaybook.RELEASE_READINESS_CHECK),
        ("dispatch_workflow", RiskFamily.CI_WORKFLOW_MUTATION, RedirectPlaybook.WORKFLOW_REVIEW),
        ("run_remote_command", RiskFamily.REMOTE_COMMAND, RedirectPlaybook.REMOTE_COMMAND_REVIEW),
        (
            "instruction_surface_status",
            RiskFamily.UNTRUSTED_INSTRUCTION_SURFACE,
            RedirectPlaybook.UNTRUSTED_TEXT_REVIEW,
        ),
    ],
)
def test_representative_tools_map_to_expected_risk_family_and_playbook(
    tool: str,
    risk_family: RiskFamily,
    playbook: RedirectPlaybook,
) -> None:
    assert resolve_risk_family(tool) is risk_family
    assert resolve_redirect_playbook(risk_family) is playbook
    assert representative_tool_risk_families()[tool] == risk_family.value


def test_ci_workflow_and_remote_command_use_distinct_playbooks() -> None:
    assert (
        RISK_FAMILY_TO_PLAYBOOK[RiskFamily.CI_WORKFLOW_MUTATION]
        is RedirectPlaybook.WORKFLOW_REVIEW
    )
    assert (
        RISK_FAMILY_TO_PLAYBOOK[RiskFamily.REMOTE_COMMAND]
        is RedirectPlaybook.REMOTE_COMMAND_REVIEW
    )


def test_redirect_fields_use_safe_first_step_id_not_free_text() -> None:
    classification = _product_route_classification("write_file")
    guidance = build_risk_family_guidance(classification, outcome="approval")
    fields = redirect_fields_from_guidance(guidance)

    assert fields["safe_first_step_id"] == RedirectPlaybook.INSPECT_BEFORE_WRITE.value
    assert "safe_first_step" not in fields
    assert fields["redirect_playbook_id"] == RedirectPlaybook.INSPECT_BEFORE_WRITE.value
    assert fields["target_reached"] is False


def test_enrich_risk_family_error_data_stores_ids_only() -> None:
    classification = _product_route_classification("get_secret")
    data = enrich_risk_family_error_data(
        {"status": "blocked", "reason": "github-secrets-block"},  # claim-check: allow blocked as JSON-RPC status vocabulary.
        classification,
        outcome="block",
        original_request_id="req-secret-1",
    )

    assert data["risk_family"] == RiskFamily.SECRET_ACCESS.value
    assert data["redirect_playbook_id"] == RedirectPlaybook.SECRET_POSTURE_ONLY.value
    assert data["safe_first_step_id"] == RedirectPlaybook.SECRET_POSTURE_ONLY.value
    assert "safe_first_step" not in data
    assert data["redirect_context"]["redirect_playbook_id"] == RedirectPlaybook.SECRET_POSTURE_ONLY.value


def test_uses_risk_family_redirects_only_for_product_route() -> None:
    assert uses_risk_family_redirects(_product_route_classification("write_file")) is True
    assert uses_risk_family_redirects(_non_product_classification()) is False


def test_safe_read_tools_do_not_require_redirect_enrichment_on_non_product_policy() -> None:
    classification = _non_product_classification("list_workspace")
    data = _enrich_redirect_error_data(
        {"status": "approval_required", "reason": "local_approval_required"},
        classification,
        outcome="approval",
        original_request_id="req-read-1",
    )
    assert "risk_family" not in data or data.get("risk_family") != RiskFamily.FILE_WRITE.value


def test_blocked_error_includes_redirect_metadata_for_product_route() -> None:
    classification = _product_route_classification("get_secret")
    response = _blocked_error(
        "req-block-secret",
        "blocked by local MCP policy",  # claim-check: allow blocked as JSON-RPC status vocabulary.
        reason="github-secrets-block",
        classification=classification,
        enrich_guidance=True,
    )
    data = response["error"]["data"]

    assert data["risk_family"] == RiskFamily.SECRET_ACCESS.value
    assert data["redirect_playbook_id"] == RedirectPlaybook.SECRET_POSTURE_ONLY.value
    assert data["safe_first_step_id"] == RedirectPlaybook.SECRET_POSTURE_ONLY.value
    assert "safe_first_step" not in data
    assert "Secret access blocked" in response["error"]["message"]  # claim-check: allow blocked as JSON-RPC status vocabulary.


def test_approval_required_error_includes_redirect_metadata_and_url_message() -> None:
    classification = _product_route_classification("write_file")
    response = _approval_required_error(
        "req-approval-write",
        reason="local_approval_required",
        classification=classification,
        enrich_guidance=True,
        approval_outcome=type(
            "Outcome",
            (),
            {
                "request_id": "req-approval-write",
                "status": "pending",
                "approval_url": "http://127.0.0.1:8765/approve/req-approval-write",
                "reason": "local_approval_required",
                "approved": False,
            },
        )(),
    )
    data = response["error"]["data"]

    assert data["risk_family"] == RiskFamily.FILE_WRITE.value
    assert data["redirect_playbook_id"] == RedirectPlaybook.INSPECT_BEFORE_WRITE.value
    assert data["safe_first_step_id"] == RedirectPlaybook.INSPECT_BEFORE_WRITE.value
    assert "safe_first_step" not in data
    assert "http://127.0.0.1:8765/approve/req-approval-write" in response["error"]["message"]


def test_attach_redirect_playbook_fields_coexists_with_authority_record() -> None:
    classification = _product_route_classification("git_add")
    metadata = {
        "policy_decision": "approval",
        "approval_status": "pending",
        "target_reached": False,
        "action_family": classification.action_family,
        "request_id": "req-git-add",
    }
    attach_redirect_playbook_fields(metadata, classification, reason="local_approval_required")
    metadata["authority_record"] = build_runtime_authority_record(
        metadata=metadata,
        risk_class=classification.risk_class.value,
    )

    assert metadata["risk_family"] == RiskFamily.GIT_MUTATION.value
    assert metadata["redirect_playbook_id"] == RedirectPlaybook.SHOW_GIT_STATUS_AND_DIFF.value
    assert metadata["safe_first_step_id"] == RedirectPlaybook.SHOW_GIT_STATUS_AND_DIFF.value
    assert metadata["authority_record"]["authority_status"] == "missing"
    assert "safe_first_step" not in metadata
    assert "safe_first_step" not in metadata["authority_record"]


def test_redirect_playbook_id_for_classification_product_route() -> None:
    classification = _product_route_classification("dispatch_workflow")
    playbook_id = _redirect_playbook_id_for_classification(
        classification,
        reason="local_approval_required",
        outcome="approval",
    )
    assert playbook_id == RedirectPlaybook.WORKFLOW_REVIEW.value


def test_evidence_summary_exports_redirect_metadata_with_authority() -> None:
    metadata = {
        "policy_decision": "block",
        "approval_status": "blocked",  # claim-check: allow blocked as approval_status enum value.
        "target_reached": False,
        "action_family": "write",
        "request_id": "req-summary-redirect",
        "risk_family": RiskFamily.SECRET_ACCESS.value,
        "redirect_playbook_id": RedirectPlaybook.SECRET_POSTURE_ONLY.value,
        "safe_first_step_id": RedirectPlaybook.SECRET_POSTURE_ONLY.value,
        "authority_record": {
            "authority_status": "blocked",  # claim-check: allow blocked as authority_status enum value.
            "authority_source": "policy_block",
            "authority_reason_id": "secret_access_blocked",
            "risk_family": "secret",
            "safe_first_step_id": "request_approval",
            "target_reached": False,
        },
    }
    record = PendingApproval(
        request_id="req-summary-redirect",
        session_id="session-1",
        client_id="cursor:session-1",
        downstream_server="product",
        tool_name="get_secret",
        action_class="secret",
        risk_class="secret",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id=PRODUCT_ROUTE_POLICY_ID,
        policy_rule_id="product_route::github::get_secret",
        policy_context_hash="c" * 64,
        status=ApprovalStatus.BLOCKED.value,  # claim-check: allow blocked as approval_status enum value.
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        action_gate_metadata_jcs=json.dumps(metadata, sort_keys=True),
    )

    summary = evidence_summary_record(record)
    assert summary["authority"]["authority_status"] == "blocked"  # claim-check: allow blocked as authority_status enum value.
    assert summary["risk_family"] == RiskFamily.SECRET_ACCESS.value
    assert summary["redirect_playbook_id"] == RedirectPlaybook.SECRET_POSTURE_ONLY.value
    assert summary["safe_first_step_id"] == RedirectPlaybook.SECRET_POSTURE_ONLY.value
    assert "safe_first_step" not in summary


def test_timeline_entry_exports_redirect_metadata_with_authority() -> None:
    metadata = {
        "policy_decision": "approval",
        "approval_status": "pending",
        "target_reached": False,
        "action_family": "write",
        "request_id": "req-timeline-redirect",
        "risk_family": RiskFamily.FILE_WRITE.value,
        "redirect_playbook_id": RedirectPlaybook.INSPECT_BEFORE_WRITE.value,
        "safe_first_step_id": RedirectPlaybook.INSPECT_BEFORE_WRITE.value,
        "authority_record": {
            "authority_status": "missing",
            "authority_source": "none",
            "authority_reason_id": "risky_authority_missing",
            "risk_family": "write",
            "safe_first_step_id": "request_approval",
            "target_reached": False,
        },
    }
    record = PendingApproval(
        request_id="req-timeline-redirect",
        session_id="session-1",
        client_id="cursor:session-1",
        downstream_server="product",
        tool_name="write_file",
        action_class="write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id=PRODUCT_ROUTE_POLICY_ID,
        policy_rule_id="product_route::filesystem::write_file",
        policy_context_hash="c" * 64,
        status=ApprovalStatus.PENDING.value,
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        action_gate_metadata_jcs=json.dumps(metadata, sort_keys=True),
    )

    entry = build_timeline_entry(record)
    assert entry["authority"]["authority_status"] == "missing"
    assert entry["risk_family"] == RiskFamily.FILE_WRITE.value
    assert entry["redirect_playbook_id"] == RedirectPlaybook.INSPECT_BEFORE_WRITE.value
    assert entry["safe_first_step_id"] == RedirectPlaybook.INSPECT_BEFORE_WRITE.value
    assert "safe_first_step" not in entry


def test_read_only_allow_authority_semantics_remain_for_product_route_reads() -> None:
    metadata = {
        "policy_decision": "allow",
        "approval_status": "executed",
        "target_reached": True,
        "action_family": "read",
        "request_id": "req-read-only",
    }
    authority = build_runtime_authority_record(metadata=metadata, risk_class="read")
    assert authority["authority_status"] == "allowed"
    assert authority["authority_source"] == "read_only"
    assert authority["authority_reason_id"] == AUTHORITY_REASON_READ_ONLY


@pytest.mark.parametrize(
    "tool",
    ("list_workspace", "git_status", "package_inspect_state", "get_repository"),
)
def test_attach_redirect_playbook_fields_skips_allow_reads(tool: str) -> None:
    classification = _product_route_classification(tool)
    metadata = {
        "policy_decision": "allow",
        "approval_status": "executed",
        "target_reached": True,
        "action_family": "read",
        "request_id": f"req-{tool}",
        "tool": tool,
    }
    attach_redirect_playbook_fields(metadata, classification)
    assert "redirect_playbook_id" not in metadata
    assert "risk_family" not in metadata
    assert "safe_first_step_id" not in metadata
    assert should_attach_redirect_playbook_fields(metadata) is False


def test_should_attach_redirect_playbook_fields_for_gated_outcomes() -> None:
    assert should_attach_redirect_playbook_fields({
        "policy_decision": "approval",
        "approval_status": "pending",
    }) is True
    assert should_attach_redirect_playbook_fields({
        "policy_decision": "block",
        "approval_status": "blocked",  # claim-check: allow blocked as approval_status enum value.
    }) is True
    assert should_attach_redirect_playbook_fields({
        "policy_decision": "approval",
        "approval_status": "executed",
    }) is True
    assert should_attach_redirect_playbook_fields({
        "policy_decision": "allow",
        "approval_status": "executed",
    }) is False


@pytest.mark.parametrize(
    "tool",
    ("list_workspace", "git_status", "package_inspect_state", "get_repository"),
)
def test_product_route_safe_reads_have_no_redirect_metadata_in_evidence(
    tmp_path: Path,
    tool: str,
) -> None:
    home = _init_product_route_home(tmp_path)
    response = _run_tool(home, tool, call_id=f"read-{tool}")
    assert "result" in response, response
    assert "error" not in response

    with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
        records = store.list_records()
        metadata_matches = [
            parse_controlled_path_metadata(record)
            for record in records
            if parse_controlled_path_metadata(record) is not None
            and parse_controlled_path_metadata(record).get("tool") == tool
        ]
    assert metadata_matches
    metadata = metadata_matches[-1]
    _assert_no_redirect_metadata(metadata)
    assert metadata["authority_record"]["authority_status"] == "allowed"

    tool_record = next(record for record in records if record.tool_name == tool)
    summary = evidence_summary_record(tool_record)
    assert "redirect_playbook_id" not in summary
    assert "risk_family" not in summary
    assert "safe_first_step_id" not in summary
    assert summary["authority"]["authority_status"] == "allowed"

    timeline = build_timeline_entry(tool_record)
    assert "redirect_playbook_id" not in timeline
    assert "risk_family" not in timeline
    assert "safe_first_step_id" not in timeline
    assert timeline["authority"]["authority_status"] == "allowed"
