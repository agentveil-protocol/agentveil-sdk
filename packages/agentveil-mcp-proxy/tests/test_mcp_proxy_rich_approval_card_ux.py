"""Tests for rich Approval Center action-review layout."""

from __future__ import annotations

import os
import re
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from agentveil_mcp_proxy.approval.server import (
    ApprovalServer,
    ApprovalServerDecision,
    build_owner_client_id,
    publish_owner_claim,
)
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.evidence.observability import (
    approval_remaining_seconds,
    format_approval_remaining_time,
    rich_approval_action_semantics_label,
    rich_approval_requested_change_label,
    rich_redirect_card_title,
)

from test_mcp_proxy_approval import (
    _get_csrf,
    _post_decision,
    _prompt_not_expired,
)
from test_mcp_proxy_approval_redirect_projection import (
    CLIENT,
    DOWNSTREAM,
    FOLLOW_ID,
    INSTANCE_TOKEN,
    PAYLOAD_HASH,
    POLICY_CONTEXT_HASH,
    RESOURCE_HASH,
    SESSION,
    _claim_lineage,
    _register_prompt,
    _seed_follow_up,
    _seed_original,
    redirect_fixture,
    seed_verified_native_redirect_bundle,
)


FORBIDDEN_PREVIEW_FRAGMENTS = (
    "/Users/",
    "sha256:",
    "csrf-token-value",
    "manifest.json",
    '"arguments"',
)


def _detail_html(server: ApprovalServer, request_id: str = FOLLOW_ID) -> str:
    with httpx.Client() as client:
        response = client.get(server.approval_url(request_id))
    assert response.status_code == 200
    return response.text


def _register_ordinary_prompt(
    server: ApprovalServer,
    store: ApprovalEvidenceStore,
    *,
    request_id: str,
    tool_name: str,
    resource_display: str = "note.txt",
    action_details: str | None = None,
    risk_class: str = "write",
) -> None:
    now = int(time.time())
    store.write_pending(
        PendingApproval(
            request_id=request_id,
            session_id=SESSION,
            client_id=CLIENT,
            downstream_server=DOWNSTREAM,
            tool_name=tool_name,
            action_class="write",
            risk_class=risk_class,
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
            _prompt_not_expired(request_id),
            client_id=CLIENT,
            session_id=SESSION,
            downstream_server=DOWNSTREAM,
            tool_name=tool_name,
            resource_display=resource_display,
            action_details=action_details,
            reason="local_approval_required",
            risk_class=risk_class,
            csrf_token="csrf-token-value",
        )
    )


def test_verified_redirect_desktop_structure(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)

    html = _detail_html(server)
    assert "Review redirected action" in html
    assert "Review: write_file" not in html
    assert "HUMAN DECISION" not in html
    assert "Same intent. Controlled route. Exact action." not in html
    assert '<section class="approval-action-summary">' in html
    assert '<section class="approval-redirect-context">' in html
    assert "Action summary" in html
    assert "Redirect context" in html
    assert "Controlled tool" in html
    assert "Approve exact action" in html
    assert 'class="approval-rich-detail approval-rich-detail--redirected"' in html


def test_ordinary_card_has_no_redirect_specific_ui(redirect_fixture):
    store, server = redirect_fixture
    _register_ordinary_prompt(server, store, request_id="ordinary-write", tool_name="write_file")

    html = _detail_html(server, "ordinary-write")
    assert "Review redirected action" not in html
    assert "Review: write_file" in html
    assert '<section class="approval-redirect-context">' not in html
    assert "HUMAN DECISION" not in html
    assert "Same intent. Controlled route. Exact action." not in html
    assert "Approve exact action" not in html
    assert 'name="decision" value="approve">Approve</button>' in html


def test_green_panel_exists_only_for_verified_lineage(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)
    redirected = _detail_html(server)
    assert "approval-redirect-context" in redirected
    assert "rgba(46, 160, 67" in redirected

    _register_ordinary_prompt(server, store, request_id="plain-card", tool_name="write_file")
    ordinary = _detail_html(server, "plain-card")
    assert '<section class="approval-redirect-context">' not in ordinary


def test_native_hook_write_labels_are_correct(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)

    html = _detail_html(server)
    assert "Native Write" in html
    assert "Native Bash" not in html
    assert "Stopped before mutation" in html
    assert "AgentVeil MCP / write_file" in html


@pytest.mark.parametrize(
    ("tool_name", "expected_label"),
    [
        ("delete_file", "Delete file"),
        ("move_file", "Move file"),
        ("copy_file", "Copy file"),
        ("create_symlink", "Create symlink"),
        ("rmdir_tree", "Remove directory"),
    ],
)
def test_action_labels_for_semantic_tools(tool_name, expected_label):
    assert rich_approval_action_semantics_label(tool_name) == expected_label


def test_unknown_tool_does_not_fabricate_action_label():
    assert rich_approval_action_semantics_label("custom_vendor_action") == "Tool action"


def test_requested_change_preview_is_bounded_and_privacy_safe(redirect_fixture):
    store, server = redirect_fixture
    _register_ordinary_prompt(
        server,
        store,
        request_id="bounded-preview",
        tool_name="write_file",
        action_details="restart_workers",
    )
    html = _detail_html(server, "bounded-preview")
    section_match = re.search(
        r'<section class="approval-action-summary">.*?</section>',
        html,
        flags=re.DOTALL,
    )
    assert section_match is not None
    section = section_match.group(0)
    assert "restart_workers" in section
    for fragment in FORBIDDEN_PREVIEW_FRAGMENTS:
        assert fragment not in section

    unsafe = rich_approval_requested_change_label(
        tool_name="write_file",
        action_details="/Users/secret/path.txt",
    )
    assert unsafe == "File change"


def test_long_values_wrap_safely(redirect_fixture):
    store, server = redirect_fixture
    long_target = "a" * 180 + ".txt"
    _register_ordinary_prompt(
        server,
        store,
        request_id="long-target",
        tool_name="write_file",
        resource_display=long_target,
    )
    html = _detail_html(server, "long-target")
    assert "overflow-wrap: anywhere" in html
    assert long_target in html


def test_countdown_renders_from_expires_at(redirect_fixture):
    store, server = redirect_fixture
    _register_ordinary_prompt(server, store, request_id="countdown-card", tool_name="write_file")
    prompt = server.prompt_for("countdown-card")
    assert prompt is not None
    remaining = approval_remaining_seconds(prompt.expires_at)
    html = _detail_html(server, "countdown-card")
    assert f'data-expires-at="{prompt.expires_at}"' in html
    assert format_approval_remaining_time(remaining) in html
    assert "approval-countdown" in html


def test_expired_page_disables_decision_controls(redirect_fixture):
    store, server = redirect_fixture
    now = int(time.time())
    store.write_pending(
        PendingApproval(
            request_id="expired-card",
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
            created_at=now - 400,
            expires_at=now - 1,
        )
    )
    server.register(
        replace(
            _prompt_not_expired("expired-card"),
            client_id=CLIENT,
            session_id=SESSION,
            downstream_server=DOWNSTREAM,
            tool_name="write_file",
            created_at=now - 400,
            expires_at=now - 1,
            csrf_token="csrf-token-value",
        )
    )

    with httpx.Client() as client:
        response = client.get(server.approval_url("expired-card"))
    assert response.status_code == 410
    assert "Timed out" in response.text
    assert 'name="decision" value="approve"' not in response.text


def test_post_after_expiry_remains_rejected(redirect_fixture):
    store, server = redirect_fixture
    now = int(time.time())
    store.write_pending(
        PendingApproval(
            request_id="expired-post",
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
            created_at=now - 400,
            expires_at=now - 1,
        )
    )
    server.register(
        replace(
            _prompt_not_expired("expired-post"),
            client_id=CLIENT,
            session_id=SESSION,
            downstream_server=DOWNSTREAM,
            tool_name="write_file",
            created_at=now - 400,
            expires_at=now - 1,
            csrf_token="csrf-token-value",
        )
    )

    with httpx.Client() as client:
        response = _post_decision(
            client,
            server.approval_url("expired-post"),
            decision="approve",
            csrf="csrf-token-value",
        )
    assert response.status_code == 410


def test_approve_and_deny_update_durable_status(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)

    def persist_approve(decision: ApprovalServerDecision) -> bool:
        store.transition(
            decision.request_id,
            ApprovalStatus.APPROVED.value,
            approval_token_hash="sha256:" + "e" * 64,
        )
        return True

    def persist_deny(decision: ApprovalServerDecision) -> bool:
        store.transition(
            decision.request_id,
            ApprovalStatus.DENIED.value,
            approval_token_hash="sha256:" + "e" * 64,
            error_class="user_denied",
        )
        return True

    with httpx.Client() as client:
        url = server.approval_url(FOLLOW_ID)
        csrf = _get_csrf(client, url)
        server.set_decision_handler(persist_approve)
        approve = _post_decision(client, url, decision="approve", csrf=csrf)
        assert approve.status_code == 200

    approved = store.get_pending(FOLLOW_ID)
    assert approved is not None
    assert approved.status == ApprovalStatus.APPROVED.value

    _register_ordinary_prompt(server, store, request_id="deny-card", tool_name="write_file")
    server.set_decision_handler(persist_deny)
    with httpx.Client() as client:
        url = server.approval_url("deny-card")
        csrf = _get_csrf(client, url)
        deny = _post_decision(client, url, decision="deny", csrf=csrf)
        assert deny.status_code == 200

    denied = store.get_pending("deny-card")
    assert denied is not None
    assert denied.status == ApprovalStatus.DENIED.value


def test_terminal_pages_do_not_show_actionable_controls(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    prompt = _register_prompt(server)

    with httpx.Client() as client:
        url = server.approval_url(FOLLOW_ID)
        csrf = _get_csrf(client, url)
        _post_decision(client, url, decision="approve", csrf=csrf)
        stale = client.get(url)
    assert stale.status_code == 410
    assert 'name="decision" value="approve"' not in stale.text


def test_narrow_viewport_has_no_horizontal_overflow_styles(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)

    html = _detail_html(server)
    assert "@media (max-width: 720px)" in html
    assert "grid-template-columns: minmax(0, 1fr)" in html
    assert "overflow-wrap: anywhere" in html


def test_redirect_card_title_helper_matches_rendered_page(redirect_fixture):
    store, server = redirect_fixture
    _seed_original(store)
    _seed_follow_up(store)
    _claim_lineage(store)
    _register_prompt(server)

    html = _detail_html(server)
    assert rich_redirect_card_title() in html
