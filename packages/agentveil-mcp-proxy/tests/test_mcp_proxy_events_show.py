"""Tests for ``events show`` evidence visibility."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from agentveil_mcp_proxy.cli import ProxyCliError, init_proxy, main, proxy_paths, show_events
from agentveil_mcp_proxy.evidence.events_show import (
    build_event_show_entry,
    build_events_show_payload,
    verify_local_evidence_chain,
)
from agentveil_mcp_proxy.evidence.store import (
    GENESIS_PREV_EVENT_HASH,
    ApprovalEvidenceStore,
    PendingApproval,
    record_hash,
)

TEST_PASSPHRASE = "test-passphrase-123"


def _record(
    request_id: str,
    *,
    session_id: str = "session-a",
    status: str = "pending",
    tool_name: str = "write_file",
    risk_class: str = "write",
    action_class: str = "write",
    error_class: str | None = None,
    metadata_jcs: str | None = None,
    prev_event_hash: str | None = None,
    granted_by: str | None = None,
    created_at: int = 1_700_000_000,
) -> PendingApproval:
    return PendingApproval(
        request_id=request_id,
        session_id=session_id,
        client_id="claude_code",
        downstream_server="filesystem",
        tool_name=tool_name,
        action_class=action_class,
        risk_class=risk_class,
        resource_hash="sha256:" + "a" * 64,
        payload_hash="sha256:" + "b" * 64,
        policy_id="filesystem",
        policy_rule_id="write-approval",
        policy_context_hash="c" * 64,
        status=status,
        created_at=created_at,
        expires_at=created_at + 300,
        error_class=error_class,
        action_gate_metadata_jcs=metadata_jcs,
        prev_event_hash=prev_event_hash,
        granted_by_request_id=granted_by,
    )


def test_events_show_empty_state_is_friendly(tmp_path: Path) -> None:
    home = tmp_path / "home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    out = io.StringIO()
    count = show_events(home=home, last=1, out=out)
    text = out.getvalue()

    assert count == 0
    assert "No local evidence yet" in text
    assert "events show --last --verify" in text
    assert "unknown" not in text.lower()


def test_events_show_human_output_is_readable_and_bounded(tmp_path: Path) -> None:
    home = tmp_path / "home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    paths = proxy_paths(home)
    metadata = json.dumps({
        "action_family": "write",
        "policy_decision": "approval",
        "approval_status": "pending",
        "execution_status": "not_reached",
        "target_reached": False,
    }, separators=(",", ":"))
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_record("req-write", metadata_jcs=metadata))

    out = io.StringIO()
    show_events(home=home, last=1, out=out)
    text = out.getvalue()

    assert "decision=approval_required" in text
    assert "tool=write_file" in text
    assert "policy=write-approval" in text
    assert "sha256:" not in text
    assert "b" * 64 not in text
    assert "unknown" not in text.lower()


def test_events_show_json_returns_bounded_fields(tmp_path: Path) -> None:
    home = tmp_path / "home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    paths = proxy_paths(home)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_record("req-json"))

    out = io.StringIO()
    show_events(home=home, last=1, output_json=True, out=out)
    payload = json.loads(out.getvalue())

    assert payload["ok"] is True
    assert payload["event_count"] == 1
    event = payload["events"][0]
    assert event["record_id"] == "req-json"
    assert event["decision"] == "approval_required"
    assert event["payload_hash"].startswith("sha256:")
    assert "debug" not in event


def test_events_show_debug_includes_bounded_debug_fields(tmp_path: Path) -> None:
    home = tmp_path / "home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    paths = proxy_paths(home)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_record("req-debug"))

    out = io.StringIO()
    show_events(home=home, last=1, debug=True, output_json=True, out=out)
    event = json.loads(out.getvalue())["events"][0]

    assert "debug" in event
    assert "record_hash" in event["debug"]


def test_events_show_session_filter(tmp_path: Path) -> None:
    home = tmp_path / "home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    paths = proxy_paths(home)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_record("req-a", session_id="keep-me"))
        store.write_pending(_record("req-b", session_id="other"))

    payload = build_events_show_payload(
        evidence_path=paths.proxy_dir / "evidence.sqlite",
        config_path=paths.config_path,
        session_id="keep-me",
        last=10,
    )

    assert payload["event_count"] == 1
    assert payload["events"][0]["record_id"] == "req-a"


def test_events_show_hard_block_and_sandbox_reason() -> None:
    # claim-check: allow blocked/hard_blocked fixture literals; this test verifies bounded event display, not a coverage claim.
    record = _record(
        "req-blocked",  # claim-check: allow blocked fixture id for bounded renderer test.
        status="blocked",  # claim-check: allow blocked status enum fixture.
        error_class="path_outside_workspace",
    )
    entry = build_event_show_entry(record)

    assert entry["valid"] is True
    assert entry["decision"] == "hard_blocked"
    assert "sandbox" in entry["reason_summary"].lower()


def test_events_show_verify_not_available_without_chain() -> None:
    record = _record("req-no-chain")
    result = verify_local_evidence_chain([record])
    assert result["status"] == "not_available"


def test_events_show_verify_intact_for_chained_records() -> None:
    first = _record("req-1", prev_event_hash=GENESIS_PREV_EVENT_HASH)
    first_hash = record_hash(first)
    second = _record("req-2", prev_event_hash=first_hash)
    result = verify_local_evidence_chain([first, second])
    assert result["status"] == "intact"
    assert result["chain_root_hash"] == record_hash(second)


def test_events_show_verify_failed_on_mismatch() -> None:
    first = _record("req-1", prev_event_hash=GENESIS_PREV_EVENT_HASH)
    second = _record("req-2", prev_event_hash="sha256:" + "f" * 64)
    result = verify_local_evidence_chain([first, second])
    assert result["status"] == "failed"


def test_events_show_skips_unparseable_metadata_without_crashing() -> None:
    record = _record("req-bad", metadata_jcs="{not-json")
    entry = build_event_show_entry(record)
    assert entry["valid"] is False


def test_events_show_last_must_be_positive(tmp_path: Path) -> None:
    home = tmp_path / "home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    with pytest.raises(ProxyCliError, match="positive"):
        show_events(home=home, last=0)


def test_cli_events_show_last_integration(tmp_path: Path, capsys) -> None:
    home = tmp_path / "home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    paths = proxy_paths(home)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_record("req-cli"))

    rc = main(["events", "show", "--last", "--home", str(home)])
    assert rc == 0
    text = capsys.readouterr().out
    assert "decision=approval_required" in text
    assert "write_file" in text


def test_cli_events_show_bare_last_includes_pending_write_same_second(
    tmp_path: Path,
    capsys,
) -> None:
    home = tmp_path / "home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    paths = proxy_paths(home)
    same_second = 1_700_000_000
    read_metadata = json.dumps({"target_reached": True}, separators=(",", ":"))
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_record(
            "aaa-write-pending",
            status="pending",
            created_at=same_second,
        ))
        for request_id, tool_name, action_class in (
            ("read-list", "list_workspace", "read"),
            ("read-file", "read_file", "read"),
            ("zzz-tail-read", "instruction_surface_status", "read"),
        ):
            store.write_pending(_record(
                request_id,
                status="pending",
                tool_name=tool_name,
                risk_class="read",
                action_class=action_class,
                metadata_jcs=read_metadata,
                created_at=same_second,
            ))
            store.transition(
                request_id,
                "executed",
                result_hash="sha256:" + "f" * 64,
            )

    rc = main(["events", "show", "--last", "--home", str(home)])
    assert rc == 0
    text = capsys.readouterr().out
    assert "decision=approval_required" in text
    assert "tool=write_file" in text
    assert "tool=instruction_surface_status" in text


def test_events_show_read_only_allowed() -> None:
    metadata = json.dumps({
        "action_family": "read",
        "target_reached": True,
    }, separators=(",", ":"))
    record = _record(
        "req-read",
        status="executed",
        tool_name="read_file",
        risk_class="read",
        action_class="read",
        metadata_jcs=metadata,
    )
    entry = build_event_show_entry(record)
    assert entry["decision"] == "target_reached"


def test_events_show_read_only_allowed_without_target_flag() -> None:
    record = _record(
        "req-read-plain",
        status="executed",
        tool_name="read_file",
        risk_class="read",
        action_class="read",
    )
    entry = build_event_show_entry(record)
    assert entry["decision"] == "allowed"


def test_events_show_approved_event() -> None:
    record = _record("req-approved", status="approved")
    entry = build_event_show_entry(record)
    assert entry["decision"] == "approved"
    assert "Approved by user" in entry["reason_summary"]


def test_events_show_target_reached_after_execution() -> None:
    metadata = json.dumps({
        "action_family": "write",
        "target_reached": True,
        "execution_status": "executed",
    }, separators=(",", ":"))
    record = _record(
        "req-reached",
        status="executed",
        metadata_jcs=metadata,
        granted_by="req-parent",
    )
    entry = build_event_show_entry(record)
    assert entry["decision"] == "target_reached"
    assert entry["target_reached"] is True
    assert entry["reason_summary"] == "Action reached target."
    assert "Approval required before execution" not in entry["reason_summary"]
    assert "events show --last --verify" in entry["next_step"]


def test_events_show_why_copy_matches_decision_semantics() -> None:
    pending = build_event_show_entry(_record("req-pending", status="pending"))
    approved = build_event_show_entry(_record("req-approved", status="approved"))
    reached_metadata = json.dumps({"target_reached": True}, separators=(",", ":"))
    reached = build_event_show_entry(_record(
        "req-reached",
        status="executed",
        metadata_jcs=reached_metadata,
        granted_by="req-parent",
    ))
    denied = build_event_show_entry(_record("req-denied", status="denied"))

    assert pending["decision"] == "approval_required"
    assert "Approval required before execution" in pending["reason_summary"]
    assert "Retry the same MCP tool call after approval" in pending["reason_summary"]

    assert approved["decision"] == "approved"
    assert "Approved by user" in approved["reason_summary"]
    assert "Retry the same MCP tool call" in approved["reason_summary"]
    assert approved["reason_summary"] != pending["reason_summary"]

    assert reached["decision"] == "target_reached"
    assert reached["reason_summary"] == "Action reached target."
    assert "Approval required before execution" not in reached["reason_summary"]
    assert reached["reason_summary"] != pending["reason_summary"]
    assert reached["reason_summary"] != approved["reason_summary"]

    assert denied["decision"] == "hard_blocked"
    assert denied["reason_summary"] == "Denied by user."
    assert denied["reason_summary"] != pending["reason_summary"]


def test_events_show_execution_not_reached() -> None:
    metadata = json.dumps({
        "action_family": "write",
        "target_reached": False,
        "execution_status": "not_reached",
    }, separators=(",", ":"))
    record = _record("req-not-reached", status="executed", metadata_jcs=metadata)
    entry = build_event_show_entry(record)
    assert entry["decision"] == "execution_not_reached"
    assert entry["target_reached"] is False
    assert entry.get("next_step")


def test_events_show_human_output_includes_local_proof_discoverability(tmp_path: Path) -> None:
    home = tmp_path / "home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    paths = proxy_paths(home)
    metadata = json.dumps({"target_reached": True}, separators=(",", ":"))
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_record(
            "req-proof",
            status="pending",
            metadata_jcs=metadata,
        ))
        store.transition("req-proof", "executed", result_hash="sha256:" + "f" * 64)

    out = io.StringIO()
    show_events(home=home, last=1, out=out)
    text = out.getvalue()

    assert "Local proof shows what was requested, decided, executed" in text
    assert "events show --last --verify" in text
    assert "/proof" not in text


def test_events_show_redirect_original_includes_next_step() -> None:
    # claim-check: allow blocked fixture literal; redirect renderer behavior is asserted below.
    metadata = json.dumps({
        "redirect_role": "original",
        "redirect_playbook_id": "use_read_only_tool",
        "original_request_id": "req-redirect",
        "target_reached": False,
    }, separators=(",", ":"))
    record = _record(
        "req-redirect",
        status="blocked",  # claim-check: allow blocked status enum fixture.
        metadata_jcs=metadata,
    )
    entry = build_event_show_entry(record)
    assert entry["decision"] == "redirected"
    assert entry.get("redirect_playbook_id") == "use_read_only_tool"
    assert "redirect" in entry["next_step"].lower()


def test_events_show_user_denied_vs_policy_hard_block() -> None:
    # claim-check: allow blocked/hard_blocked fixture literals; this is an enum/status rendering test.
    denied = build_event_show_entry(_record("req-denied", status="denied"))
    blocked = build_event_show_entry(_record(  # claim-check: allow blocked variable in enum rendering test.
        "req-blocked",  # claim-check: allow blocked fixture id.
        status="blocked",  # claim-check: allow blocked status enum fixture.
        error_class="local_policy_block",
    ))
    assert denied["decision"] == "hard_blocked"
    assert blocked["decision"] == "hard_blocked"  # claim-check: allow hard_blocked decision enum assertion.
    assert denied["reason_summary"] == "Denied by user."
    assert blocked["reason_summary"] == "local policy block"  # claim-check: allow policy block fixture text.
