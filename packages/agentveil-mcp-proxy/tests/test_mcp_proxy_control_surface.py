"""Control surface timeline privacy and GitHub credential-management regressions."""

from __future__ import annotations

import json

import pytest

from agentveil_mcp_proxy.control_surface import (
    ControlSurfaceError,
    assert_control_output_is_privacy_safe,
    build_timeline_entry,
    format_control_status_human,
    planned_redirect_packs,
    privacy_markers_in_control_output,
    redirect_pack_summaries,
    redirect_playbook_coverage,
    supported_redirect_packs,
)
from agentveil_mcp_proxy.evidence import ApprovalStatus, PendingApproval

PAYLOAD_HASH = "sha256:" + "a" * 64
RESOURCE_HASH = "sha256:" + "b" * 64


def _record(*, tool_name: str, status: str, error_class: str | None = None) -> PendingApproval:
    return PendingApproval(
        request_id="req-manage-secret",
        session_id="session-1",
        client_id="cursor:session-7",
        downstream_server="github-mcp",
        tool_name=tool_name,
        action_class="write",
        risk_class="destructive",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id="github-default",
        policy_rule_id="github-manage-secret-block",
        policy_context_hash="c" * 64,
        status=status,
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        error_class=error_class,
    )


def _timeline_payload(*records: PendingApproval) -> dict:
    events = [build_timeline_entry(record) for record in records]
    return {
        "ok": True,
        "errors": [],
        "evidence_count": len(events),
        "event_count": len(events),
        "events": events,
    }


def test_manage_secret_denied_timeline_passes_privacy_guard() -> None:
    record = _record(
        tool_name="manage_secret",
        status=ApprovalStatus.BLOCKED.value,  # claim-check: allow tested evidence status enum.
        error_class="secret_path_blocked",
    )
    payload = _timeline_payload(record)

    assert payload["events"][0]["tool"] == "manage_secret"
    assert payload["events"][0]["event_kind"] == "policy_deny"
    assert privacy_markers_in_control_output(json.dumps(payload, sort_keys=True)) == []
    assert_control_output_is_privacy_safe(payload)


def test_get_secret_tool_label_passes_privacy_guard() -> None:
    record = _record(
        tool_name="get_secret",
        status=ApprovalStatus.BLOCKED.value,  # claim-check: allow tested evidence status enum.
    )
    payload = _timeline_payload(record)
    assert_control_output_is_privacy_safe(payload)


def test_raw_secret_json_field_fails_privacy_guard() -> None:
    payload = {
        "ok": True,
        "errors": [],
        "events": [
            {
                "record_id": "req-leak",
                "tool": "manage_secret",
                "secret": "super-secret-token-value",
            }
        ],
    }
    with pytest.raises(ControlSurfaceError) as exc:
        assert_control_output_is_privacy_safe(payload)
    assert exc.value.code == "privacy_violation"
    assert "raw secret-like json field" in privacy_markers_in_control_output(
        json.dumps(payload, sort_keys=True)
    )


def test_raw_token_value_fails_privacy_guard() -> None:
    payload = {
        "ok": True,
        "errors": [],
        "events": [{"record_id": "req-leak", "token": "ghp_abcdefghijklmnopqrstuvwxyz123456"}],
    }
    with pytest.raises(ControlSurfaceError) as exc:
        assert_control_output_is_privacy_safe(payload)
    assert exc.value.code == "privacy_violation"
    assert "GitHub token" in privacy_markers_in_control_output(json.dumps(payload, sort_keys=True))


def test_ghp_token_in_generic_message_field_fails_privacy_guard() -> None:
    payload = {
        "ok": True,
        "errors": [],
        "events": [{"record_id": "req-leak", "message": "leaked ghp_abcdefghijklmnopqrstuvwxyz123456"}],
    }
    with pytest.raises(ControlSurfaceError) as exc:
        assert_control_output_is_privacy_safe(payload)
    assert exc.value.code == "privacy_violation"
    assert "GitHub token" in privacy_markers_in_control_output(json.dumps(payload, sort_keys=True))


def test_github_pat_in_generic_message_field_fails_privacy_guard() -> None:
    token = "github_pat_" + ("A" * 40)
    payload = {
        "ok": True,
        "errors": [],
        "events": [{"record_id": "req-leak", "message": f"leaked {token}"}],
    }
    with pytest.raises(ControlSurfaceError) as exc:
        assert_control_output_is_privacy_safe(payload)
    assert exc.value.code == "privacy_violation"
    assert "GitHub PAT" in privacy_markers_in_control_output(json.dumps(payload, sort_keys=True))


def test_secret_path_blocked_reason_label_still_passes_privacy_guard() -> None:
    payload = {
        "ok": True,
        "errors": [],
        "events": [
            {
                "record_id": "req-label",
                "tool": "read_file",
                "reason": "secret_path_blocked",
            }
        ],
    }
    assert privacy_markers_in_control_output(json.dumps(payload, sort_keys=True)) == []
    assert_control_output_is_privacy_safe(payload)


def test_absolute_path_in_timeline_fails_privacy_guard() -> None:
    payload = {
        "ok": True,
        "errors": [],
        "events": [{"record_id": "req-leak", "path": "/Users/agent/project/.env"}],
    }
    with pytest.raises(ControlSurfaceError):
        assert_control_output_is_privacy_safe(payload)


def test_timeline_entry_includes_bounded_authority_record() -> None:
    metadata = json.dumps({
        "policy_decision": "block",
        "approval_status": "blocked",  # claim-check: allow "blocked" as approval_status enum value.
        "target_reached": False,
        "action_family": "write",
        "request_id": "req-block-1",
        "authority_record": {
            "authority_status": "blocked",  # claim-check: allow "blocked" as authority_status enum value.
            "authority_source": "policy_block",
            "authority_reason_id": "secret_access_blocked",
            "risk_family": "secret",
            "safe_first_step_id": "request_approval",
            "target_reached": False,
        },
    }, sort_keys=True)
    record = PendingApproval(
        request_id="req-block-1",
        session_id="session-1",
        client_id="cursor:session-1",
        downstream_server="fake-downstream",
        tool_name="write_file",
        action_class="write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id="block-test",
        policy_rule_id="block-tool",
        policy_context_hash="c" * 64,
        status=ApprovalStatus.BLOCKED.value,  # claim-check: allow BLOCKED as stored approval-status enum value.
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        action_gate_metadata_jcs=metadata,
    )

    entry = build_timeline_entry(record)
    assert entry["authority"]["authority_status"] == "blocked"  # claim-check: allow "blocked" as authority_status enum value.
    assert entry["authority"]["authority_source"] == "policy_block"
    assert entry["authority"]["authority_reason_id"] == "secret_access_blocked"
    assert entry["authority"]["risk_family"] == "secret"
    assert "safe_first_step" not in entry
    assert "safe_first_step" not in entry["authority"]


def test_redirect_pack_summary_matches_runtime_risk_family_redirects() -> None:
    summaries = list(redirect_pack_summaries())

    assert supported_redirect_packs()
    assert planned_redirect_packs() == ()
    assert all(isinstance(item.get("summary"), str) and item["summary"] for item in summaries)


def test_redirect_coverage_uses_public_runtime_language() -> None:
    coverage = list(redirect_playbook_coverage())

    assert coverage
    assert {item["automation_level"] for item in coverage} <= {
        "approval_required",
        "metadata_only",
        "policy_checked_followup",
    }


def test_control_status_human_does_not_report_supported_redirects_as_planned() -> None:
    rendered = format_control_status_human({
        "setup_status": "configured",
        "mode": "local",
        "role_preset": None,
        "protected_packs": ["git", "github", "package"],
        "pending_approval_count": 0,
        "policy_deny_count": 0,
        "role_violation_count": 0,
        "redirect_original_count": 0,
        "redirect_follow_up_count": 0,
        "target_reached_true_count": 0,
        "target_reached_false_count": 0,
        "redirect_coverage_lines": [item["summary"] for item in redirect_pack_summaries()],
        "redirect_playbook_coverage": list(redirect_playbook_coverage()),
        "unsupported_redirect_packs": ["shell"],
        "planned_redirect_packs": list(planned_redirect_packs()),
        "errors": [],
    })

    assert "redirects:" in rendered
    assert "git redirects: planned" not in rendered
    assert "github redirects: planned" not in rendered
