"""Tests for bounded Approval Center redirect context projection."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from agentveil_mcp_proxy.approval.server import (
    ApprovalPrompt,
    ApprovalServer,
    ApprovalServerDecision,
    TERMINAL_ALREADY_DECIDED_APPROVE,
    build_owner_client_id,
    publish_owner_claim,
)
from agentveil_mcp_proxy.client_guidance import NATIVE_REDIRECT_ORIGIN_REASON
from agentveil_mcp_proxy.evidence import ApprovalEvidenceError, ApprovalEvidenceStore, ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.evidence.observability import verified_redirect_projection_rows

from test_mcp_proxy_approval import (
    _get_csrf,
    _post_decision,
    _prompt_not_expired,
)


PAYLOAD_HASH = "sha256:" + "a" * 64
RESOURCE_HASH = "sha256:" + "b" * 64
POLICY_CONTEXT_HASH = "c" * 64
APPROVAL_TOKEN_HASH = "sha256:" + "e" * 64
SCOPE_FP = "sha256:" + "d" * 64
PLAYBOOK = "request_approval"
SESSION = "session-proj-1234567890"
INSTANCE_TOKEN = "redirect-projection-inst"
CLIENT = build_owner_client_id("cursor", pid=os.getpid(), instance_token=INSTANCE_TOKEN)
DOWNSTREAM = "filesystem"
ORIGINAL_ID = "orig-redirect"
FOLLOW_ID = "follow-redirect"

FORBIDDEN_REDIRECT_FRAGMENTS = (
    ORIGINAL_ID,
    FOLLOW_ID,
    SCOPE_FP,
    PAYLOAD_HASH,
    "csrf-token-value",
    "manifest.json",
    "internal_register_token",
    "session-proj-1234567890",
    '"arguments"',
    "/Users/",
    "project_scope_fingerprint",
)


def _original_meta(*, scope_fp: str = SCOPE_FP, playbook: str = PLAYBOOK) -> dict[str, object]:
    return {
        "redirect_role": "original",
        "redirect_playbook_id": playbook,
        "target_reached": False,
        "original_request_id": ORIGINAL_ID,
        "project_scope_fingerprint": scope_fp,
        "action_family": "write",
        "execution_status": "not_reached",
        "native_hook_denied": True,
    }


def seed_verified_native_redirect_bundle(
    store: ApprovalEvidenceStore,
    *,
    client_id: str,
    session_id: str,
    original_id: str = ORIGINAL_ID,
    follow_id: str = FOLLOW_ID,
) -> None:
    """Insert durable native-hook original, verified follow-up, and matching claim."""

    original_meta = {
        "redirect_role": "original",
        "redirect_playbook_id": PLAYBOOK,
        "target_reached": False,
        "original_request_id": original_id,
        "project_scope_fingerprint": SCOPE_FP,
        "action_family": "write",
        "execution_status": "not_reached",
        "native_hook_denied": True,
    }
    store.record_terminal_deny(
        request_id=original_id,
        session_id=session_id,
        client_id=client_id,
        downstream_server=DOWNSTREAM,
        tool_name="Write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id="redirect-lineage",
        policy_rule_id=None,
        policy_context_hash=POLICY_CONTEXT_HASH,
        created_at=int(time.time()),
        reason=NATIVE_REDIRECT_ORIGIN_REASON,
        action_gate_metadata_jcs=json.dumps(original_meta, separators=(",", ":")),
    )
    now = int(time.time())
    follow_meta = _follow_meta()
    follow_meta["original_request_id"] = original_id
    follow_meta["redirect_parent_request_id"] = original_id
    store.write_pending(
        PendingApproval(
            request_id=follow_id,
            session_id=session_id,
            client_id=client_id,
            downstream_server=DOWNSTREAM,
            tool_name="write_file",
            action_class="write",
            risk_class="write",
            resource_hash=RESOURCE_HASH,
            payload_hash=PAYLOAD_HASH,
            policy_id="redirect-lineage",
            policy_rule_id="write-approval",
            policy_context_hash=POLICY_CONTEXT_HASH,
            status=ApprovalStatus.PENDING.value,
            created_at=now,
            expires_at=now + 300,
            action_gate_metadata_jcs=json.dumps(follow_meta, separators=(",", ":")),
        )
    )
    store.claim_redirect_lineage(
        original_id,
        follow_up_request_id=follow_id,
        claimed_at=int(time.time()),
        redirect_playbook_id=PLAYBOOK,
        project_scope_fingerprint=SCOPE_FP,
        expected_session_id=session_id,
        expected_client_id=client_id,
        expected_downstream_server=DOWNSTREAM,
        expected_resource_hash=RESOURCE_HASH,
    )


def _follow_meta(
    *,
    scope_fp: str = SCOPE_FP,
    playbook: str = PLAYBOOK,
    lineage_status: str = "verified",
) -> dict[str, object]:
    return {
        "redirect_role": "follow_up",
        "redirect_playbook_id": playbook,
        "target_reached": False,
        "original_request_id": ORIGINAL_ID,
        "redirect_parent_request_id": ORIGINAL_ID,
        "lineage_status": lineage_status,
        "project_scope_fingerprint": scope_fp,
        "intent_relationship": "resource_identity_preserved",
        "original_action_family": "write",
        "follow_up_action_family": "write",
    }


def _seed_original(
    store: ApprovalEvidenceStore,
    *,
    meta: dict[str, object] | None = None,
    reason: str = NATIVE_REDIRECT_ORIGIN_REASON,
) -> None:
    store.record_terminal_deny(
        request_id=ORIGINAL_ID,
        session_id=SESSION,
        client_id=CLIENT,
        downstream_server=DOWNSTREAM,
        tool_name="Write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id="redirect-lineage",
        policy_rule_id=None,
        policy_context_hash=POLICY_CONTEXT_HASH,
        created_at=int(time.time()),
        reason=reason,
        action_gate_metadata_jcs=json.dumps(meta or _original_meta(), separators=(",", ":")),
    )


def _seed_follow_up(
    store: ApprovalEvidenceStore,
    *,
    meta: dict[str, object] | None = None,
    status: str = ApprovalStatus.PENDING.value,
) -> PendingApproval:
    now = int(time.time())
    record = PendingApproval(
        request_id=FOLLOW_ID,
        session_id=SESSION,
        client_id=CLIENT,
        downstream_server=DOWNSTREAM,
        tool_name="write_file",
        action_class="write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id="redirect-lineage",
        policy_rule_id="write-approval",
        policy_context_hash=POLICY_CONTEXT_HASH,
        status=status,
        created_at=now,
        expires_at=now + 300,
        action_gate_metadata_jcs=json.dumps(meta or _follow_meta(), separators=(",", ":")),
    )
    store.write_pending(record)
    return record


def _claim_lineage(store: ApprovalEvidenceStore, *, follow_up_id: str = FOLLOW_ID) -> None:
    store.claim_redirect_lineage(
        ORIGINAL_ID,
        follow_up_request_id=follow_up_id,
        claimed_at=int(time.time()),
        redirect_playbook_id=PLAYBOOK,
        project_scope_fingerprint=SCOPE_FP,
        expected_session_id=SESSION,
        expected_client_id=CLIENT,
        expected_downstream_server=DOWNSTREAM,
        expected_resource_hash=RESOURCE_HASH,
    )


def _register_prompt(server: ApprovalServer, *, request_id: str = FOLLOW_ID) -> ApprovalPrompt:
    prompt = replace(
        _prompt_not_expired(request_id),
        client_id=CLIENT,
        session_id=SESSION,
        downstream_server=DOWNSTREAM,
        tool_name="write_file",
        action_display=f"{DOWNSTREAM}.write_file",
        resource_display="note.txt",
        reason="local_approval_required",
        csrf_token="csrf-token-value",
        action_gate_metadata=_follow_meta(),
    )
    server.register(prompt)
    return prompt


def _detail_html(server: ApprovalServer, request_id: str = FOLLOW_ID) -> str:
    with httpx.Client() as client:
        response = client.get(server.approval_url(request_id))
    assert response.status_code == 200
    return response.text


def _assert_redirect_section_privacy_safe(text: str) -> None:
    section_match = re.search(
        r'<section class="approval-redirect-context">.*?</section>',
        text,
        flags=re.DOTALL,
    )
    assert section_match is not None
    section = section_match.group(0)
    for fragment in FORBIDDEN_REDIRECT_FRAGMENTS:
        assert fragment not in section


@pytest.fixture
def redirect_fixture(tmp_path: Path):
    proxy_dir = tmp_path / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    lease = publish_owner_claim(
        proxy_dir / "owner_claims",
        pid=os.getpid(),
        instance_token=INSTANCE_TOKEN,
        session_id=SESSION,
    )
    server = ApprovalServer(evidence_store=store)
    server.start()
    try:
        yield store, server
    finally:
        lease.close()
        server.stop()
        store.close()


def test_verified_evidence_and_claim_renders_bounded_redirect_section(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)

    html = _detail_html(server)
    assert '<section class="approval-redirect-context">' in html
    assert "Original action" in html
    assert "Native Write" in html
    assert "Hook decision" in html
    assert "Stopped before mutation" in html
    assert "Controlled route" in html
    assert "AgentVeil MCP / write_file" in html
    assert "Intent binding" in html
    assert "Same target and requested change" in html
    assert "Target reached" in html
    assert "No" in html
    _assert_redirect_section_privacy_safe(html)


def test_role_deny_original_without_native_hook_marker_omits_redirect_section(redirect_fixture):
    store, server = redirect_fixture
    meta = _original_meta()
    meta.pop("native_hook_denied", None)
    _seed_original(store, meta=meta, reason="role_authority_denied")
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)

    html = _detail_html(server)
    assert '<section class="approval-redirect-context">' not in html
    assert 'name="decision" value="approve"' in html


def test_unknown_native_tool_omits_redirect_section(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    with sqlite3.connect(str(store.db_path)) as conn:
        conn.execute(
            "UPDATE pending_approvals SET tool_name = ? WHERE request_id = ?",
            ("run_terminal_cmd", ORIGINAL_ID),
        )
        conn.commit()
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)

    html = _detail_html(server)
    assert '<section class="approval-redirect-context">' not in html


def test_projection_evidence_error_keeps_ordinary_card_actionable(redirect_fixture, monkeypatch):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)

    def explode(*_args, **_kwargs):
        raise ApprovalEvidenceError("claim read failed")

    monkeypatch.setattr(store, "get_redirect_lineage_claim", explode)
    html = _detail_html(server)
    assert '<section class="approval-redirect-context">' not in html
    assert 'name="decision" value="approve"' in html
    assert 'name="decision" value="deny"' in html


def test_direct_mcp_pending_card_has_no_redirect_section(redirect_fixture):
    store, server = redirect_fixture
    now = int(time.time())
    store.write_pending(
        PendingApproval(
            request_id="direct-only",
            session_id=SESSION,
            client_id=CLIENT,
            downstream_server=DOWNSTREAM,
            tool_name="write_file",
            action_class="write",
            risk_class="write",
            resource_hash=RESOURCE_HASH,
            payload_hash=PAYLOAD_HASH,
            policy_id="policy",
            policy_rule_id="write-approval",
            policy_context_hash=POLICY_CONTEXT_HASH,
            status=ApprovalStatus.PENDING.value,
            created_at=now,
            expires_at=now + 300,
        )
    )
    server.register(
        replace(
            _prompt_not_expired("direct-only"),
            client_id=CLIENT,
            session_id=SESSION,
            downstream_server=DOWNSTREAM,
            tool_name="write_file",
            resource_display="note.txt",
            csrf_token="csrf-token-value",
        )
    )

    html = _detail_html(server, "direct-only")
    assert '<section class="approval-redirect-context">' not in html
    assert "The agent wants to run write_file" in html
    assert "Proof details" in html


def test_verified_metadata_without_claim_omits_redirect_section(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _register_prompt(server)

    assert verified_redirect_projection_rows(store.get_pending(FOLLOW_ID), store=store) is None
    html = _detail_html(server)
    assert '<section class="approval-redirect-context">' not in html


def test_wrong_follow_up_request_id_omits_redirect_section(redirect_fixture):
    store, _server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store, follow_up_id="other-follow")
    follow_up = store.get_pending(FOLLOW_ID)
    assert verified_redirect_projection_rows(follow_up, store=store) is None


def test_wrong_playbook_in_follow_metadata_omits_redirect_section(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store, meta=_follow_meta(playbook="create_implementer_task"))
    _claim_lineage(store)
    _register_prompt(server)
    html = _detail_html(server)
    assert '<section class="approval-redirect-context">' not in html


def test_wrong_scope_in_follow_metadata_omits_redirect_section(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    tampered = _follow_meta(scope_fp="sha256:" + "f" * 64)
    with sqlite3.connect(str(store.db_path)) as conn:
        conn.execute(
            "UPDATE pending_approvals SET action_gate_metadata_jcs = ? WHERE request_id = ?",
            (json.dumps(tampered, separators=(",", ":")), FOLLOW_ID),
        )
        conn.commit()
    _register_prompt(server)
    html = _detail_html(server)
    assert '<section class="approval-redirect-context">' not in html


def test_terminal_card_does_not_render_verified_redirect_context(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)
    server.unregister(FOLLOW_ID, terminal_state=TERMINAL_ALREADY_DECIDED_APPROVE)

    with httpx.Client() as client:
        response = client.get(server.approval_url(FOLLOW_ID))
    assert response.status_code == 410
    assert '<section class="approval-redirect-context">' not in response.text


def test_in_process_get_remains_actionable_with_redirect_section(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    prompt = _register_prompt(server)

    html = _detail_html(server)
    assert 'name="csrf_token"' in html
    assert 'name="decision" value="approve"' in html
    assert 'name="decision" value="deny"' in html
    with httpx.Client() as client:
        csrf = _get_csrf(client, server.approval_url(prompt.request_id))
        response = _post_decision(
            client,
            server.approval_url(prompt.request_id),
            decision="approve",
            csrf=csrf,
        )
    assert response.status_code == 200


def test_post_approve_updates_durable_status_after_redirect_card(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    prompt = _register_prompt(server)

    def persist_approve(decision: ApprovalServerDecision) -> bool:
        store.transition(
            decision.request_id,
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
        )
        return True

    server.set_decision_handler(persist_approve)
    assert '<section class="approval-redirect-context">' in _detail_html(server)
    with httpx.Client() as client:
        csrf = _get_csrf(client, server.approval_url(prompt.request_id))
        assert _post_decision(
            client,
            server.approval_url(prompt.request_id),
            decision="approve",
            csrf=csrf,
        ).status_code == 200
    assert store.get_pending(FOLLOW_ID).status == ApprovalStatus.APPROVED.value


def test_post_deny_records_user_denied_after_redirect_card(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    prompt = _register_prompt(server)

    def persist_deny(decision: ApprovalServerDecision) -> bool:
        store.transition(
            decision.request_id,
            ApprovalStatus.DENIED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
            error_class="user_denied",
        )
        return True

    server.set_decision_handler(persist_deny)
    with httpx.Client() as client:
        csrf = _get_csrf(client, server.approval_url(prompt.request_id))
        assert _post_decision(
            client,
            server.approval_url(prompt.request_id),
            decision="deny",
            csrf=csrf,
        ).status_code == 200
    denied = store.get_pending(FOLLOW_ID)
    assert denied.status == ApprovalStatus.DENIED.value
    assert denied.error_class == "user_denied"


def test_ordinary_approval_card_snapshot_unchanged_without_redirect(redirect_fixture):
    store, server = redirect_fixture
    now = int(time.time())
    store.write_pending(
        PendingApproval(
            request_id="ordinary",
            session_id=SESSION,
            client_id=CLIENT,
            downstream_server="github",
            tool_name="create_issue",
            action_class="write",
            risk_class="write",
            resource_hash=RESOURCE_HASH,
            payload_hash=PAYLOAD_HASH,
            policy_id="github-default",
            policy_rule_id="write-approval",
            policy_context_hash=POLICY_CONTEXT_HASH,
            status=ApprovalStatus.PENDING.value,
            created_at=now,
            expires_at=now + 300,
            action_gate_metadata_jcs=json.dumps(
                {
                    "role": "implementer",
                    "authority": "implement",
                    "policy_decision": "approval",
                    "execution_status": "not_reached",
                    "target_reached": False,
                },
                separators=(",", ":"),
            ),
        )
    )
    server.register(
        replace(
            _prompt_not_expired("ordinary"),
            client_id=CLIENT,
            session_id=SESSION,
            downstream_server="github",
            tool_name="create_issue",
            action_display="github.create_issue",
            resource_display="issue-1",
            reason="local_approval_required",
            csrf_token="csrf-token-value",
            action_gate_metadata={
                "role": "implementer",
                "authority": "implement",
                "policy_decision": "approval",
                "execution_status": "not_reached",
                "target_reached": False,
            },
        )
    )

    html = _detail_html(server, "ordinary")
    assert '<section class="approval-redirect-context">' not in html
    assert "The agent wants to run create_issue" in html
    assert "Needs your approval before it can run" in html
    assert "Proof details" in html
    assert "Raw evidence" in html
    assert "Payload hash" in html


def test_cancelled_follow_up_does_not_project_verified_context(redirect_fixture):
    store, _server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    store.transition(
        FOLLOW_ID,
        ApprovalStatus.CANCELLED.value,
        error_class="client_cancelled",
    )
    follow_up = store.get_pending(FOLLOW_ID)
    assert follow_up is not None
    assert verified_redirect_projection_rows(follow_up, store=store) is None
