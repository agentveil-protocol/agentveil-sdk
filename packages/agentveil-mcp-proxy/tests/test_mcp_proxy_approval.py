"""P6 tests for MCP proxy approval UX."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import re
import signal
import socket
import sys
import threading
import time
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

import httpx
import pytest
import webbrowser
from nacl.signing import SigningKey

from agentveil.delegation import _public_key_to_did
import agentveil_mcp_proxy.approval.server as approval_server_module
import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.approval import (
    ApprovalFlowError,
    ApprovalManager,
    ApprovalNotifier,
    ApprovalPrompt,
    ApprovalServer,
    ApprovalServerDecision,
    HeadlessPolicy,
    HeadlessPolicyError,
)
from agentveil_mcp_proxy.approval.server import (
    TERMINAL_ALREADY_DECIDED_APPROVE,
    TERMINAL_ALREADY_DECIDED_DENY,
    TERMINAL_APPROVAL_EXPIRED,
)
from agentveil_mcp_proxy.approval.notification import NotificationResult
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceCapacityError,
    ApprovalEvidenceStore,
    ApprovalStatus,
    build_evidence_bundle,
)
from agentveil_mcp_proxy.evidence.observability import (
    event_record_dict,
    execution_record_id_by_parent,
    format_event_record,
)
from agentveil_mcp_proxy.evidence.approval_grant import (
    ApprovalGrantError,
    verify_approval_grant,
)
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough
from agentveil_mcp_proxy.policy import ProxyConfig, ProxyConfigError

from mcp_fake_downstream import tool_entry, write_downstream


SECRET = "SECRET_APPROVAL_PAYLOAD"
PACKAGE_MANAGER_SECRET = "marker-pkg"
PACKAGE_MANAGER_COMMAND_FRAGMENT = "npm install"
TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
APPROVAL_GRANT_SEED = bytes.fromhex("33" * 32)
APPROVAL_GRANT_DID = _public_key_to_did(bytes(SigningKey(APPROVAL_GRANT_SEED).verify_key))


class NoopNotifier:
    def __init__(self):
        self.prompts: list[ApprovalPrompt] = []

    def notify(self, prompt: ApprovalPrompt) -> NotificationResult:
        self.prompts.append(prompt)
        return NotificationResult("test", attempted=True, delivered=True)


def _config(
    *,
    privacy: dict[str, Any] | None = None,
    policy_rule: dict[str, Any] | None = None,
    approval_timeout_seconds: int = 300,
    on_timeout: str = "deny",
    ui_open_mode: str = "browser",
    policy_id: str = "approval-test",
    role_authority: dict[str, Any] | None = None,
) -> ProxyConfig:
    payload = {
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
        },
        "mode": "protect",
        "privacy": privacy or {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "fallback": {
            "read": "allow",
            "write": "approval",
            "destructive": "block",
            "production": "block",
            "financial": "block",
            "unknown": "approval",
        },
        "approval": {
            "approval_timeout_seconds": approval_timeout_seconds,
            "on_timeout": on_timeout,
            "ui_open_mode": ui_open_mode,
        },
        "policy": {
            "id": policy_id,
            "policy_schema_version": 1,
            "default_decision": "approval",
            "default_risk_class": "write",
            "rules": [policy_rule] if policy_rule is not None else [],
        },
        "downstream": {},
    }
    if role_authority is not None:
        payload["role_authority"] = role_authority
    return ProxyConfig.from_dict(payload)


def _allow_run_terminal_cmd_rule() -> dict[str, Any]:
    return {
        "id": "allow-run-terminal",
        "source": "user",
        "decision": "allow",
        "risk_class": "unknown",
        "match": {"server": "fake-downstream", "tool": "run_terminal_cmd"},
    }


def _allow_write_file_rule() -> dict[str, Any]:
    return {
        "id": "allow-write-file",
        "source": "user",
        "decision": "allow",
        "risk_class": "write",
        "match": {"server": "fake-downstream", "tool": "write_file"},
    }


def _fake_downstream_write_approval_rule() -> dict[str, Any]:
    return {
        "id": "fake-write-approval",
        "source": "user",
        "decision": "approval",
        "risk_class": "write",
        "match": {"server": "fake-downstream", "tool": "write_file"},
    }


def _fake_downstream_write_ask_backend_rule() -> dict[str, Any]:
    return {
        "id": "fake-write-ask-backend",
        "source": "user",
        "decision": "ask_backend",
        "risk_class": "write",
        "match": {"server": "fake-downstream", "tool": "write_file"},
    }


RUNTIME_GATE_WAITING_AUDIT_ID = "urn:uuid:11111111-1111-4111-8111-111111111111"


class _RuntimeGateWaitingStub:
    """Returns WAITING_FOR_HUMAN_APPROVAL for TrapDoor/runtime-gate regression tests."""

    def evaluate(self, _classification):
        from agentveil_mcp_proxy.runtime_gate import RuntimeGateDecision

        return RuntimeGateDecision(
            decision="WAITING_FOR_HUMAN_APPROVAL",
            audit_id=RUNTIME_GATE_WAITING_AUDIT_ID,
            approval_id="urn:uuid:approval",
            receipt_digest="aa" * 32,
            receipt_body={},
        )


def _write_rule(*, scope_expansion: bool = False, risk_class: str = "write") -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": "write-approval",
        "source": "user",
        "decision": "approval",
        "risk_class": risk_class,
        "match": {"server": "github", "tool": "create_issue"},
    }
    if scope_expansion:
        rule["approval"] = {"scope_expansion": "similar_5m"}
    return rule


def _classification(config: ProxyConfig | None = None, *, tool: str = "create_issue"):
    config = config or _config(policy_rule=_write_rule())
    return ToolCallClassifier(config, server_name="github").classify(
        tool=tool,
        arguments={
            "owner": "acme",
            "repo": "private-repo",
            "title": SECRET,
            "token": "ghp_private",
            "source_code": "print('private')",
        },
    )


def _prompt(request_id: str = "req-1") -> ApprovalPrompt:
    return ApprovalPrompt(
        request_id=request_id,
        client_id="cursor:session-1",
        session_id="session-abcdef",
        downstream_server="github",
        tool_name="create_issue",
        action_display="redacted",
        action_details=None,
        resource_display="sha256:" + "a" * 64,
        resource_details=None,
        risk_class="write",
        payload_hash="sha256:" + "b" * 64,
        policy_rule_id="write-approval",
        reason="local_approval_required",
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        csrf_token="csrf-token",
    )


def _prompt_not_expired(request_id: str = "req-1") -> ApprovalPrompt:
    now = int(time.time())
    return replace(_prompt(request_id), created_at=now, expires_at=now + 300)


def _manager(
    tmp_path: Path,
    *,
    config: ProxyConfig | None = None,
    server: ApprovalServer | None = None,
    headless: bool = False,
    auto_deny: bool = False,
    headless_policy: HeadlessPolicy | None = None,
    cli_out: io.StringIO | None = None,
    browser_open: Callable[[str], bool] | None = None,
    wait_for_decision: bool = True,
    approval_grant_private_key_seed: bytes | None = None,
    approval_grant_agent_did: str | None = None,
) -> tuple[ApprovalManager, ApprovalEvidenceStore, ApprovalServer, io.StringIO]:
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = server or ApprovalServer()
    if not server.is_running:
        server.start()
    cli = cli_out or io.StringIO()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=config or _config(policy_rule=_write_rule()),
        client_id="cursor:pid:123",
        session_id="session-1234567890",
        headless=headless,
        auto_deny=auto_deny,
        headless_policy=headless_policy,
        cli_out=cli,
        browser_open=browser_open or (lambda _url: False),
        notifier=NoopNotifier(),
        wait_for_decision=wait_for_decision,
        approval_grant_private_key_seed=approval_grant_private_key_seed,
        approval_grant_agent_did=approval_grant_agent_did,
    )
    return manager, store, server, cli


def _get_csrf(client: httpx.Client, url: str) -> str:
    response = client.get(url)
    assert response.status_code == 200
    match = TOKEN_RE.search(response.text)
    assert match
    return match.group(1)


def _get_csrf_and_cookie(client: httpx.Client, url: str) -> tuple[str, str]:
    response = client.get(url)
    assert response.status_code == 200
    match = TOKEN_RE.search(response.text)
    assert match
    return match.group(1), response.headers["Set-Cookie"].split(";", 1)[0]


def _post_decision(client: httpx.Client, url: str, *, decision: str, csrf: str, scope: str = "exact"):
    return client.post(url, data={
        "decision": decision,
        "csrf_token": csrf,
        "approval_scope": scope,
    })


def _dashboard_list_html(server: ApprovalServer) -> str:
    response = httpx.get(server.approval_center_url(), follow_redirects=False)
    assert response.status_code == 200
    return response.text


def _request_and_post(
    manager: ApprovalManager,
    server: ApprovalServer,
    classification,
    *,
    decision: str = "approve",
    scope: str = "exact",
):
    result_box: dict[str, Any] = {}
    worker = threading.Thread(
        target=lambda: result_box.setdefault(
            "outcome",
            manager.request_approval(classification, reason="local_approval_required"),
        ),
        daemon=True,
    )
    worker.start()
    deadline = time.monotonic() + 2
    while not server.pending_prompts() and time.monotonic() < deadline:
        time.sleep(0.01)
    prompt = server.pending_prompts()[0]
    with httpx.Client() as client:
        csrf = _get_csrf(client, server.approval_url(prompt.request_id))
        response = _post_decision(
            client,
            server.approval_url(prompt.request_id),
            decision=decision,
            csrf=csrf,
            scope=scope,
        )
    worker.join(timeout=3)
    assert "outcome" in result_box
    return result_box["outcome"], prompt, response


def _raw_http_request(host: str, port: int, request: str, *, timeout: float = 2.0) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request.encode("utf-8"))
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def _raw_post(
    server: ApprovalServer,
    url: str,
    *,
    content_length: str,
    body: str = "",
    cookie: str | None = None,
) -> bytes:
    path = urlsplit(url).path
    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {server.host}:{server.port}",
        "Content-Type: application/x-www-form-urlencoded",
        f"Content-Length: {content_length}",
        "Connection: close",
    ]
    if cookie is not None:
        headers.append(f"Cookie: {cookie}")
    request = "\r\n".join(headers) + "\r\n\r\n" + body
    return _raw_http_request(server.host, server.port, request)


def _assert_status(raw_response: bytes, status_code: int) -> None:
    status_line = raw_response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    assert status_line.startswith(f"HTTP/1.0 {status_code} ") or status_line.startswith(
        f"HTTP/1.1 {status_code} "
    ), raw_response.decode("utf-8", errors="replace")


def test_approval_server_binds_only_to_127_0_0_1():
    server = ApprovalServer()
    server.start()
    try:
        assert server.host == "127.0.0.1"
        assert server.base_url.startswith("http://127.0.0.1:")
    finally:
        server.stop()

    with pytest.raises(Exception):
        ApprovalServer(host="0.0.0.0")


def test_approval_server_request_threads_are_daemon(monkeypatch):
    seen: dict[str, bool] = {}
    original_do_get = approval_server_module._ApprovalRequestHandler.do_GET

    def recording_do_get(self):
        seen["daemon"] = threading.current_thread().daemon
        return original_do_get(self)

    monkeypatch.setattr(approval_server_module._ApprovalRequestHandler, "do_GET", recording_do_get)
    server = ApprovalServer()
    server.start()
    try:
        assert server._httpd is not None
        assert server._httpd.daemon_threads is True
        url = server.register(_prompt_not_expired())
        response = httpx.get(url)
        assert response.status_code == 200
        assert seen["daemon"] is True
    finally:
        server.stop()


def _assert_invalid_content_length_rejected(content_length: str) -> None:
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        with httpx.Client() as client:
            _csrf, cookie = _get_csrf_and_cookie(client, url)
        response = _raw_post(server, url, content_length=content_length, cookie=cookie)
        _assert_status(response, 400)
        assert b"invalid content length" in response
    finally:
        server.stop()


def test_post_with_non_numeric_content_length_returns_400():
    _assert_invalid_content_length_rejected("abc")


def test_post_with_negative_content_length_returns_400():
    _assert_invalid_content_length_rejected("-100")


def test_post_with_oversized_content_length_returns_400():
    _assert_invalid_content_length_rejected("99999")


def test_post_with_valid_content_length_succeeds():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        with httpx.Client() as client:
            csrf, cookie = _get_csrf_and_cookie(client, url)
        body = urlencode({
            "decision": "approve",
            "csrf_token": csrf,
            "approval_scope": "exact",
        })
        response = _raw_post(
            server,
            url,
            content_length=str(len(body.encode("utf-8"))),
            body=body,
            cookie=cookie,
        )
        _assert_status(response, 200)
        decision = server.wait_for_decision("req-1", timeout=0.1)
        assert decision is not None
        assert decision.decision == "approve"
    finally:
        server.stop()


def test_slow_client_request_socket_timeout(monkeypatch):
    monkeypatch.setattr(approval_server_module, "REQUEST_SOCKET_TIMEOUT_SECONDS", 0.25)
    server = ApprovalServer()
    server.start()
    try:
        with socket.create_connection((server.host, server.port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(b"GET /approval/")
            time.sleep(0.6)
            try:
                data = sock.recv(1)
            except (ConnectionResetError, TimeoutError, socket.timeout):
                data = b""
        assert data == b""
    finally:
        server.stop()


def test_post_without_token_returns_403():
    server = ApprovalServer()
    server.start()
    try:
        server.register(_prompt_not_expired())
        response = httpx.post(f"{server.base_url}/approval/wrong/pending/req-1", data={})
        assert response.status_code == 403
    finally:
        server.stop()


def test_post_with_wrong_csrf_returns_403():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        with httpx.Client() as client:
            _get_csrf(client, url)
            response = _post_decision(client, url, decision="approve", csrf="wrong")
        assert response.status_code == 403
    finally:
        server.stop()


def test_post_with_correct_token_and_cookie_and_csrf_records_decision():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            response = _post_decision(client, url, decision="approve", csrf=csrf)
        assert response.status_code == 200
        decision = server.wait_for_decision("req-1", timeout=0.1)
        assert decision is not None
        assert decision.decision == "approve"
        assert decision.approval_scope == "exact"
    finally:
        server.stop()


def test_post_after_approve_returns_410_gone():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        with httpx.Client() as client:
            csrf, cookie = _get_csrf_and_cookie(client, url)
            assert _post_decision(client, url, decision="approve", csrf=csrf).status_code == 200
        with httpx.Client(headers={"Cookie": cookie}) as client:
            stale_post = _post_decision(client, url, decision="deny", csrf=csrf)
        assert stale_post.status_code == 410
        assert "text/html" in stale_post.headers.get("content-type", "")
        _assert_stale_html_privacy_safe(stale_post.text, session_token=server.session_token)
    finally:
        server.stop()


def test_post_after_deny_returns_410_gone():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        with httpx.Client() as client:
            csrf, cookie = _get_csrf_and_cookie(client, url)
            assert _post_decision(client, url, decision="deny", csrf=csrf).status_code == 200
        with httpx.Client(headers={"Cookie": cookie}) as client:
            stale_post = _post_decision(client, url, decision="approve", csrf=csrf)
        assert stale_post.status_code == 410
        assert "text/html" in stale_post.headers.get("content-type", "")
        _assert_stale_html_privacy_safe(stale_post.text, session_token=server.session_token)
    finally:
        server.stop()


def test_response_headers_include_referrer_policy_no_referrer():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        response = httpx.get(url)
        assert response.headers["Referrer-Policy"] == "no-referrer"
    finally:
        server.stop()


def test_response_headers_include_cache_control_no_store():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        response = httpx.get(url)
        assert "no-store" in response.headers["Cache-Control"]
        assert "max-age=0" in response.headers["Cache-Control"]
    finally:
        server.stop()


def test_response_headers_include_x_frame_options_deny_and_csp_frame_ancestors_none():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        response = httpx.get(url)
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "Strict-Transport-Security" not in response.headers
    finally:
        server.stop()


def test_token_rotates_on_proxy_restart():
    server_one = ApprovalServer()
    server_one.start()
    old_token = server_one.session_token
    server_one.stop()

    server_two = ApprovalServer()
    server_two.start()
    try:
        assert server_two.session_token != old_token
        response = httpx.get(f"{server_two.base_url}/approval/{old_token}")
        assert response.status_code == 403
    finally:
        server_two.stop()


def test_pending_approval_persisted_before_ui_render(tmp_path):
    class FailingStore:
        def find_active_exact_grant(self, **_kwargs):
            return None

        def find_active_similar_grant(self, **_kwargs):
            return None

        def write_pending(self, _record):
            raise ApprovalEvidenceCapacityError("full")

    class FailingServer(ApprovalServer):
        def register(self, _prompt):
            raise AssertionError("UI rendered before durable write")

    server = FailingServer()
    manager = ApprovalManager(
        evidence_store=FailingStore(),
        approval_server=server,
        config=_config(policy_rule=_write_rule()),
        client_id="cursor",
        session_id="session",
        cli_out=io.StringIO(),
        browser_open=lambda _url: False,
        notifier=NoopNotifier(),
    )

    with pytest.raises(ApprovalFlowError):
        manager.request_approval(_classification(), reason="local_approval_required")


def test_headless_auto_deny_records_denial_evidence_and_does_not_render_ui(tmp_path):
    class FailingServer(ApprovalServer):
        def register(self, _prompt):
            raise AssertionError("headless auto-deny must not render UI")

    manager, store, server, _cli = _manager(
        tmp_path,
        server=FailingServer(),
        headless=True,
        auto_deny=True,
    )
    try:
        outcome = manager.request_approval(_classification(), reason="local_approval_required")
        record = store.get_pending(outcome.request_id)
        assert outcome.status == ApprovalStatus.DENIED.value
        assert record.status == ApprovalStatus.DENIED.value
        assert record.error_class == "headless_auto_deny"
    finally:
        server.stop()
        store.close()


def test_headless_policy_pre_approval_matches_exact_payload_for_destructive(tmp_path):
    config = _config(policy_rule=_write_rule(risk_class="destructive"))
    classification = _classification(config)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    policy = HeadlessPolicy.from_dict({
        "headless_policy_schema_version": 1,
        "pre_approvals": [{
            "server": "github",
            "tool": "create_issue",
            "risk_class": "destructive",
            "environment": "mcp_proxy",
            "resource_hash": classification.resource_hash,
            "max_payload_hash": classification.payload_hash,
            "expires_at": expires,
        }],
    })
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        headless=True,
        headless_policy=policy,
    )
    try:
        outcome = manager.request_approval(classification, reason="local_approval_required")
        record = store.get_pending(outcome.request_id)
        assert outcome.approved
        assert record.status == ApprovalStatus.APPROVED.value
        assert record.approval_scope == "exact"
    finally:
        server.stop()
        store.close()


def test_local_approval_mints_signed_approval_grant(tmp_path):
    manager, store, server, _cli = _manager(
        tmp_path,
        approval_grant_private_key_seed=APPROVAL_GRANT_SEED,
        approval_grant_agent_did=APPROVAL_GRANT_DID,
    )
    try:
        classification = _classification()
        outcome, _prompt, response = _request_and_post(manager, server, classification)
        record = store.get_pending(outcome.request_id)

        assert response.status_code == 200
        assert record.approval_grant_jcs is not None
        grant = verify_approval_grant(
            record.approval_grant_jcs,
            expected_signer_dids=[APPROVAL_GRANT_DID],
            now=record.user_decision_timestamp,
        )

        assert grant["agent_did"] == APPROVAL_GRANT_DID
        assert grant["request_id"] == record.request_id
        assert grant["downstream_server"] == record.downstream_server
        assert grant["tool_name"] == record.tool_name
        assert grant["action_class"] == record.action_class
        assert grant["risk_class"] == record.risk_class
        assert grant["resource_hash"] == record.resource_hash
        assert grant["payload_hash"] == record.payload_hash
        assert grant["policy_id"] == record.policy_id
        assert grant["policy_rule_id"] == record.policy_rule_id
        assert grant["policy_context_hash"] == record.policy_context_hash
        assert grant["decision"] == "APPROVED"
        assert grant["approval_scope"] == "exact"
        assert grant["decided_by"] == "local-user"
        assert grant["issued_at"] == record.user_decision_timestamp
        assert grant["expires_at"] == record.expires_at
        assert grant["decision_audit_id"] is None
        assert grant["decision_receipt_sha256"] is None
    finally:
        server.stop()
        store.close()


def test_approval_without_signer_records_no_grant(tmp_path):
    manager, store, server, _cli = _manager(tmp_path)
    try:
        outcome, _prompt, response = _request_and_post(manager, server, _classification())
        record = store.get_pending(outcome.request_id)

        assert response.status_code == 200
        assert record.status == ApprovalStatus.APPROVED.value
        assert record.approval_grant_jcs is None
    finally:
        server.stop()
        store.close()


def test_grant_mint_failure_is_signaled_but_fails_closed(tmp_path, monkeypatch):
    cli = io.StringIO()
    manager, store, server, _cli = _manager(
        tmp_path,
        cli_out=cli,
        approval_grant_private_key_seed=APPROVAL_GRANT_SEED,
        approval_grant_agent_did=APPROVAL_GRANT_DID,
    )

    def _boom(_body, _seed):
        raise ApprovalGrantError("forced mint failure for test")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.manager.build_approval_grant", _boom
    )
    try:
        outcome, _prompt, response = _request_and_post(manager, server, _classification())
        record = store.get_pending(outcome.request_id)

        assert response.status_code == 200
        # Boundary: signer + expiry were present but minting failed; the
        # approval still records and the grant remains unset.
        assert record.status == ApprovalStatus.APPROVED.value
        assert record.approval_grant_jcs is None
        # Sanitized observability signal fired (counter + cli_out line).
        assert manager.approval_grant_mint_failures == 1
        cli_output = cli.getvalue()
        assert record.request_id in cli_output
        assert "ApprovalGrantError" in cli_output
        # Sanitized: no key/seed material and no raw error message body leaked.
        assert APPROVAL_GRANT_SEED.hex() not in cli_output
        assert "forced mint failure for test" not in cli_output
    finally:
        server.stop()
        store.close()


def test_headless_policy_grant_records_headless_decider(tmp_path):
    config = _config(policy_rule=_write_rule(risk_class="destructive"))
    classification = _classification(config)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    policy = HeadlessPolicy.from_dict({
        "headless_policy_schema_version": 1,
        "pre_approvals": [{
            "server": "github",
            "tool": "create_issue",
            "risk_class": "destructive",
            "environment": "mcp_proxy",
            "resource_hash": classification.resource_hash,
            "max_payload_hash": classification.payload_hash,
            "expires_at": expires,
        }],
    })
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        headless=True,
        headless_policy=policy,
        approval_grant_private_key_seed=APPROVAL_GRANT_SEED,
        approval_grant_agent_did=APPROVAL_GRANT_DID,
    )
    try:
        outcome = manager.request_approval(classification, reason="local_approval_required")
        record = store.get_pending(outcome.request_id)

        assert record.approval_decided_by == "headless-policy"
        assert record.approval_grant_jcs is not None
        grant = verify_approval_grant(
            record.approval_grant_jcs,
            expected_signer_dids=[APPROVAL_GRANT_DID],
            now=record.user_decision_timestamp,
        )
        assert grant["decided_by"] == "headless-policy"
    finally:
        server.stop()
        store.close()


def test_headless_policy_missing_match_denies_by_default(tmp_path):
    policy = HeadlessPolicy.from_dict({
        "headless_policy_schema_version": 1,
        "pre_approvals": [],
    })
    manager, store, server, _cli = _manager(tmp_path, headless=True, headless_policy=policy)
    try:
        outcome = manager.request_approval(_classification(), reason="local_approval_required")
        record = store.get_pending(outcome.request_id)
        assert outcome.status == ApprovalStatus.DENIED.value
        assert record.error_class == "headless_policy_no_match"
    finally:
        server.stop()
        store.close()


def test_nonblocking_approval_returns_pending_url_and_records_later_decision(tmp_path):
    manager, store, server, _cli = _manager(
        tmp_path,
        config=_config(policy_rule=_write_rule(), approval_timeout_seconds=60),
        wait_for_decision=False,
    )
    try:
        outcome = manager.request_approval(_classification(), reason="local_approval_required")

        assert outcome.status == ApprovalStatus.PENDING.value
        assert outcome.reason == "local_approval_required"
        assert outcome.approval_url == server.approval_url(outcome.request_id)
        assert store.get_pending(outcome.request_id).status == ApprovalStatus.PENDING.value

        with httpx.Client() as client:
            csrf = _get_csrf(client, outcome.approval_url)
            response = _post_decision(
                client,
                outcome.approval_url,
                decision="approve",
                csrf=csrf,
            )
        assert response.status_code == 200

        deadline = time.monotonic() + 2
        record = store.get_pending(outcome.request_id)
        while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
            time.sleep(0.01)
            record = store.get_pending(outcome.request_id)

        assert record.status == ApprovalStatus.APPROVED.value
        assert record.approval_scope == "exact"
        assert server.pending_prompts() == []

        retry = manager.request_approval(_classification(), reason="local_approval_required")
        retry_record = store.get_pending(retry.request_id)
        assert retry.approved
        assert retry.reason == "scope_cache_hit"
        assert retry_record.status == ApprovalStatus.APPROVED.value
        assert retry_record.granted_by_request_id == outcome.request_id
        assert server.pending_prompts() == []

        third = manager.request_approval(_classification(), reason="local_approval_required")
        assert third.status == ApprovalStatus.PENDING.value
        assert third.approval_url == server.approval_url(third.request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, third.approval_url)
            _post_decision(client, third.approval_url, decision="deny", csrf=csrf)
        deadline = time.monotonic() + 2
        third_record = store.get_pending(third.request_id)
        while third_record.status != ApprovalStatus.DENIED.value and time.monotonic() < deadline:
            time.sleep(0.01)
            third_record = store.get_pending(third.request_id)
        assert third_record.status == ApprovalStatus.DENIED.value
    finally:
        server.stop()
        store.close()


def test_headless_policy_yaml_or_json_schema_validation_rejects_unknown_fields():
    with pytest.raises(HeadlessPolicyError, match="unknown field"):
        HeadlessPolicy.from_dict({
            "headless_policy_schema_version": 1,
            "pre_approvals": [],
            "allow_everything": True,
        })


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode checks are not stable on Windows")
def test_headless_policy_file_rejects_group_readable_permissions(tmp_path):
    policy_path = tmp_path / "headless-policy.json"
    policy_path.write_text(
        json.dumps({"headless_policy_schema_version": 1, "pre_approvals": []}),
        encoding="utf-8",
    )
    policy_path.chmod(0o644)

    with pytest.raises(HeadlessPolicyError, match="owner-only"):
        HeadlessPolicy.from_file(policy_path)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode checks are not stable on Windows")
@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_headless_policy_file_accepts_owner_only_permissions(tmp_path, mode):
    policy_path = tmp_path / "headless-policy.json"
    policy_path.write_text(
        json.dumps({"headless_policy_schema_version": 1, "pre_approvals": []}),
        encoding="utf-8",
    )
    policy_path.chmod(mode)

    assert HeadlessPolicy.from_file(policy_path).pre_approvals == ()


def test_headless_policy_destructive_requires_payload_hash_and_resource_selector_unless_explicitly_narrow():
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(HeadlessPolicyError, match="resource or resource_hash"):
        HeadlessPolicy.from_dict({
            "headless_policy_schema_version": 1,
            "pre_approvals": [{
                "server": "github",
                "tool": "delete_repo",
                "risk_class": "destructive",
                "expires_at": expires,
            }],
        })
    with pytest.raises(HeadlessPolicyError, match="max_payload_hash"):
        HeadlessPolicy.from_dict({
            "headless_policy_schema_version": 1,
            "pre_approvals": [{
                "server": "github",
                "tool": "delete_repo",
                "risk_class": "destructive",
                "resource": "github:acme/private-repo",
                "expires_at": expires,
            }],
        })
    policy = HeadlessPolicy.from_dict({
        "headless_policy_schema_version": 1,
        "pre_approvals": [{
            "server": "github",
            "tool": "delete_repo",
            "risk_class": "destructive",
            "resource": "github:acme/private-repo",
            "allow_narrow_match": True,
            "expires_at": expires,
        }],
    })
    assert policy.pre_approvals[0].allow_narrow_match is True
    config = _config(policy_rule={
        "id": "delete-approval",
        "source": "user",
        "decision": "approval",
        "risk_class": "destructive",
        "match": {"server": "github", "tool": "delete_repo"},
    })
    classification = ToolCallClassifier(config, server_name="github").classify(
        tool="delete_repo",
        arguments={"owner": "acme", "repo": "private-repo"},
    )
    assert policy.match(classification) is not None


def test_headless_policy_validates_resource_hash_format():
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(HeadlessPolicyError, match="resource_hash"):
        HeadlessPolicy.from_dict({
            "headless_policy_schema_version": 1,
            "pre_approvals": [{
                "server": "github",
                "tool": "delete_repo",
                "risk_class": "destructive",
                "resource_hash": "sha256:not-hex",
                "max_payload_hash": "sha256:" + "a" * 64,
                "expires_at": expires,
            }],
        })


def test_headless_policy_accepts_uppercase_hash_digest_for_matching():
    config = _config(policy_rule=_write_rule(risk_class="destructive"))
    classification = _classification(config)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    policy = HeadlessPolicy.from_dict({
        "headless_policy_schema_version": 1,
        "pre_approvals": [{
            "server": "github",
            "tool": "create_issue",
            "risk_class": "destructive",
            "environment": "mcp_proxy",
            "resource_hash": "sha256:" + classification.resource_hash.removeprefix("sha256:").upper(),
            "max_payload_hash": "sha256:" + classification.payload_hash.removeprefix("sha256:").upper(),
            "expires_at": expires,
        }],
    })

    assert policy.pre_approvals[0].resource_hash == classification.resource_hash
    assert policy.pre_approvals[0].max_payload_hash == classification.payload_hash
    assert policy.match(classification) is not None


def test_token_hash_in_evidence_not_raw_token(tmp_path):
    manager, store, server, _cli = _manager(tmp_path, headless=True, auto_deny=True)
    try:
        outcome = manager.request_approval(_classification(), reason="local_approval_required")
        rendered = json.dumps(store.get_pending(outcome.request_id).__dict__, sort_keys=True)
        assert server.token_hash in rendered
        assert server.session_token not in rendered
    finally:
        server.stop()
        store.close()


def test_token_url_not_printed_when_stdout_not_tty(tmp_path):
    manager, store, server, cli = _manager(tmp_path, config=_config(
        policy_rule=_write_rule(),
        approval_timeout_seconds=1,
    ))
    worker = threading.Thread(
        target=lambda: manager.request_approval(_classification(), reason="local_approval_required"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.session_token not in cli.getvalue()
        assert "record_id=" in cli.getvalue()
        assert "session token omitted on non-TTY output" in cli.getvalue()
    finally:
        prompt = server.pending_prompts()[0]
        url = server.approval_url(prompt.request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            _post_decision(client, url, decision="deny", csrf=csrf)
        worker.join(timeout=2)
        server.stop()
        store.close()


def test_notification_chain_falls_through_to_cli_when_browser_unavailable(tmp_path):
    manager, store, server, cli = _manager(tmp_path)
    worker = threading.Thread(
        target=lambda: manager.request_approval(_classification(), reason="local_approval_required"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert "approval pending:" in cli.getvalue()
        assert "blast radius:" in cli.getvalue()
        prompt = server.pending_prompts()[0]
        metadata = prompt.action_gate_metadata or {}
        assert isinstance(metadata.get("blast_radius"), dict)
    finally:
        prompt = server.pending_prompts()[0]
        url = server.approval_url(prompt.request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            _post_decision(client, url, decision="deny", csrf=csrf)
        worker.join(timeout=2)
        server.stop()
        store.close()


def test_os_notification_does_not_include_token_or_payload(monkeypatch):
    captured = {}

    def runner(args, **_kwargs):
        captured["args"] = args

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/osascript")
    notifier = ApprovalNotifier(runner=runner)
    prompt = _prompt()
    notifier.notify(prompt)

    rendered = json.dumps(captured["args"])
    assert SECRET not in rendered
    assert "csrf-token" not in rendered
    assert "github.create_issue" in rendered


def test_notification_includes_client_id_and_session_id(monkeypatch):
    captured = {}

    def runner(args, **_kwargs):
        captured["args"] = args

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/osascript")
    notifier = ApprovalNotifier(runner=runner)
    notifier.notify(_prompt())

    rendered = json.dumps(captured["args"])
    assert "cursor:session-1" in rendered
    assert "session-" in rendered


def test_approval_ui_redacts_action_resource_per_privacy_config(tmp_path):
    manager, store, server, _cli = _manager(tmp_path)
    worker = threading.Thread(
        target=lambda: manager.request_approval(_classification(), reason="local_approval_required"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = server.pending_prompts()[0]
        text = httpx.get(server.approval_url(prompt.request_id)).text
        assert SECRET not in text
        assert "private-repo" not in text
        assert "redacted" in text
    finally:
        url = server.approval_url(server.pending_prompts()[0].request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            _post_decision(client, url, decision="deny", csrf=csrf)
        worker.join(timeout=2)
        server.stop()
        store.close()


def test_show_details_button_only_renders_when_config_allows():
    server = ApprovalServer()
    server.start()
    try:
        no_details = server.register(_prompt_not_expired("no-details"))
        assert "Show local details" not in httpx.get(no_details).text

        details_prompt = replace(
            _prompt_not_expired("details"),
            action_details="github.create_issue",
            resource_details="github:acme/private-repo",
        )
        details_url = server.register(details_prompt)
        assert "Show local details" in httpx.get(details_url).text
    finally:
        server.stop()


def test_terminal_requests_are_pruned_after_retention(monkeypatch):
    now = 1_700_000_000.0
    monkeypatch.setattr(approval_server_module.time, "time", lambda: now)
    server = ApprovalServer()
    terminal_prompt = replace(_prompt("terminal"), created_at=100, expires_at=110)
    active_prompt = _prompt("active")
    server.start()
    try:
        server.register(terminal_prompt)
        server.unregister("terminal")
        assert server.is_terminal("terminal")

        now = 1_700_000_019.0
        assert server.is_terminal("terminal")

        server.register(active_prompt)
        now = 1_700_000_021.0
        assert not server.is_terminal("terminal")
        assert server.prompt_for("active") == active_prompt
        assert server.pending_prompts() == [active_prompt]
        assert "terminal" not in server._terminal_requests
    finally:
        server.stop()


def test_ui_never_shows_more_detail_than_backend_metadata_privacy_mode(tmp_path):
    config = _config(
        privacy={
            "action": "hash",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
            "show_details_in_approval_ui": True,
        },
        policy_rule=_write_rule(),
    )
    manager, store, server, _cli = _manager(tmp_path, config=config)
    worker = threading.Thread(
        target=lambda: manager.request_approval(_classification(config), reason="local_approval_required"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = server.pending_prompts()[0]
        text = httpx.get(server.approval_url(prompt.request_id)).text
        assert "github.create_issue" not in text
        assert "private-repo" not in text
        assert "sha256:" in text
    finally:
        url = server.approval_url(server.pending_prompts()[0].request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            _post_decision(client, url, decision="deny", csrf=csrf)
        worker.join(timeout=2)
        server.stop()
        store.close()


def test_destructive_approval_defaults_to_exact_request_scope(tmp_path):
    config = _config(policy_rule=_write_rule(risk_class="destructive"))
    classification = _classification(config)
    manager, store, server, _cli = _manager(tmp_path, config=config)
    try:
        prompt = manager._prompt_for(
            classification,
            request_id="req",
            created_at=1,
            expires_at=2,
            scope_expansion_allowed=manager._scope_expansion_allowed(classification),
            reason="local_approval_required",
        )
        assert prompt.scope_expansion_allowed is False
    finally:
        server.stop()
        store.close()


def test_write_approval_optional_5min_similar_only_when_policy_allows(tmp_path):
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    manager, store, server, _cli = _manager(tmp_path, config=config)
    try:
        classification = _classification(config)
        prompt = manager._prompt_for(
            classification,
            request_id="req",
            created_at=1,
            expires_at=2,
            scope_expansion_allowed=manager._scope_expansion_allowed(classification),
            reason="local_approval_required",
        )
        assert prompt.scope_expansion_allowed is True
    finally:
        server.stop()
        store.close()


def test_scope_expansion_choice_recorded_in_evidence_fields(tmp_path):
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        approval_grant_private_key_seed=APPROVAL_GRANT_SEED,
        approval_grant_agent_did=APPROVAL_GRANT_DID,
    )
    result_box = {}
    worker = threading.Thread(
        target=lambda: result_box.setdefault(
            "outcome",
            manager.request_approval(_classification(config), reason="local_approval_required"),
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = server.pending_prompts()[0]
        url = server.approval_url(prompt.request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            response = _post_decision(client, url, decision="approve", csrf=csrf, scope="similar_5m")
        assert response.status_code == 200
        worker.join(timeout=2)
        record = store.get_pending(result_box["outcome"].request_id)
        assert record.approval_scope == "similar_5m"
        assert record.granted_scope_expires_at is not None
        assert record.matched_policy_rule == "write-approval"
        assert record.user_decision_timestamp is not None
        assert record.approval_grant_jcs is not None
        grant = verify_approval_grant(
            record.approval_grant_jcs,
            expected_signer_dids=[APPROVAL_GRANT_DID],
            now=record.user_decision_timestamp,
        )
        assert grant["approval_scope"] == "similar_5m"
        assert grant["resource_hash"] == record.resource_hash
        assert grant["payload_hash"] is None
        assert grant["expires_at"] == record.granted_scope_expires_at
    finally:
        server.stop()
        store.close()


def test_similar_scope_retry_within_five_minutes_skips_ui_and_links_evidence(tmp_path):
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        approval_grant_private_key_seed=APPROVAL_GRANT_SEED,
        approval_grant_agent_did=APPROVAL_GRANT_DID,
    )
    try:
        first_outcome, _prompt_seen, response = _request_and_post(
            manager,
            server,
            _classification(config),
            scope="similar_5m",
        )
        assert response.status_code == 200
        first_record = store.get_pending(first_outcome.request_id)
        assert first_record.approval_scope == "similar_5m"
        store.transition(
            first_outcome.request_id,
            ApprovalStatus.EXECUTED.value,
            result_hash="sha256:" + "f" * 64,
        )

        second_outcome = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        second_record = store.get_pending(second_outcome.request_id)

        assert second_outcome.approved
        assert second_outcome.reason == "scope_cache_hit"
        assert second_record.status == ApprovalStatus.APPROVED.value
        assert second_record.approval_scope == "exact"
        assert second_record.granted_by_request_id == first_outcome.request_id
        assert second_record.decision_audit_id is None
        assert second_record.approval_decided_by == "scope-cache-hit"
        assert second_record.approval_grant_jcs is not None
        second_grant = verify_approval_grant(
            second_record.approval_grant_jcs,
            expected_signer_dids=[APPROVAL_GRANT_DID],
            now=second_record.user_decision_timestamp,
        )
        assert second_grant["approval_scope"] == "exact"
        assert second_grant["payload_hash"] == second_record.payload_hash
        assert second_grant["granted_by_request_id"] == first_outcome.request_id
        assert second_grant["decided_by"] == "scope-cache-hit"
        assert store.get_pending(first_outcome.request_id).status == ApprovalStatus.EXECUTED.value
        assert store.get_pending(first_outcome.request_id).approval_scope == "similar_5m"
        assert server.pending_prompts() == []
    finally:
        server.stop()
        store.close()


def test_similar_scope_expired_or_mismatched_calls_trigger_ui(tmp_path, monkeypatch):
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    manager, store, server, _cli = _manager(tmp_path, config=config)
    try:
        monkeypatch.setattr("agentveil_mcp_proxy.approval.manager.time.time", lambda: 1_700_000_000)
        first_outcome, _prompt_seen, _response = _request_and_post(
            manager,
            server,
            _classification(config),
            scope="similar_5m",
        )
        assert store.get_pending(first_outcome.request_id).granted_scope_expires_at == 1_700_000_300

        monkeypatch.setattr("agentveil_mcp_proxy.approval.manager.time.time", lambda: 1_700_000_301)
        worker = threading.Thread(
            target=lambda: manager.request_approval(
                _classification(config),
                reason="local_approval_required",
            ),
            daemon=True,
        )
        worker.start()
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.pending_prompts(), "expired similar grant must not auto-approve"
        prompt = server.pending_prompts()[0]
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(prompt.request_id))
            _post_decision(client, server.approval_url(prompt.request_id), decision="deny", csrf=csrf)
        worker.join(timeout=3)

        monkeypatch.setattr("agentveil_mcp_proxy.approval.manager.time.time", lambda: 1_700_000_100)
        different_tool_call = replace(_classification(config), tool="update_issue")
        different_tool = threading.Thread(
            target=lambda: manager.request_approval(
                different_tool_call,
                reason="local_approval_required",
            ),
            daemon=True,
        )
        different_tool.start()
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.pending_prompts(), "different tool must not match similar grant"
        prompt = server.pending_prompts()[0]
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(prompt.request_id))
            _post_decision(client, server.approval_url(prompt.request_id), decision="deny", csrf=csrf)
        different_tool.join(timeout=3)
    finally:
        server.stop()
        store.close()


def test_similar_scope_different_resource_hash_triggers_ui(tmp_path):
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    manager, store, server, _cli = _manager(tmp_path, config=config)
    try:
        _request_and_post(manager, server, _classification(config), scope="similar_5m")
        different_resource = ToolCallClassifier(config, server_name="github").classify(
            tool="create_issue",
            arguments={"owner": "acme", "repo": "other-repo", "title": SECRET},
        )
        worker = threading.Thread(
            target=lambda: manager.request_approval(
                different_resource,
                reason="local_approval_required",
            ),
            daemon=True,
        )
        worker.start()
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.pending_prompts(), "different resource_hash must not match similar grant"
        prompt = server.pending_prompts()[0]
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(prompt.request_id))
            _post_decision(client, server.approval_url(prompt.request_id), decision="deny", csrf=csrf)
        worker.join(timeout=3)
    finally:
        server.stop()
        store.close()


def test_similar_scope_policy_context_drift_triggers_ui(tmp_path):
    # A hot-reload that changes policy_id (or decision_mode) recomputes
    # policy_context_hash. A live similar_5m grant minted under the previous
    # policy context must not be reused once the context drifts, yet it stays
    # reusable while the context is unchanged.
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    drifted_config = _config(
        policy_rule=_write_rule(scope_expansion=True),
        policy_id="approval-test-reloaded",
    )
    manager, store, server, _cli = _manager(tmp_path, config=config)
    try:
        _request_and_post(manager, server, _classification(config), scope="similar_5m")
        drifted = _classification(drifted_config)
        # Same server/tool/rule/risk/resource; only policy_id (and therefore
        # policy_context_hash) changed.
        assert drifted.policy_evaluation.policy_rule_id == "write-approval"
        assert (
            drifted.policy_evaluation.policy_context_hash
            != _classification(config).policy_evaluation.policy_context_hash
        )
        worker = threading.Thread(
            target=lambda: manager.request_approval(
                drifted,
                reason="local_approval_required",
            ),
            daemon=True,
        )
        worker.start()
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.pending_prompts(), "policy-context drift must not match similar grant"
        prompt = server.pending_prompts()[0]
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(prompt.request_id))
            _post_decision(client, server.approval_url(prompt.request_id), decision="deny", csrf=csrf)
        worker.join(timeout=3)

        # Positive control: under the unchanged policy context the same grant is
        # still live and is reused without a prompt.
        reused = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert reused.approved
        assert reused.reason == "scope_cache_hit"
    finally:
        server.stop()
        store.close()


def test_exact_scope_policy_context_drift_triggers_ui(tmp_path):
    # An exact approval grant (identical-payload retry) is reusable only within
    # the same policy context. A hot-reload changing policy_id or decision_mode
    # recomputes policy_context_hash, after which the live exact grant must not
    # be reused, yet it stays reusable while the context is unchanged.
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    drifted_config = _config(
        policy_rule=_write_rule(scope_expansion=True),
        policy_id="approval-test-reloaded",
    )
    manager, store, server, _cli = _manager(tmp_path, config=config)
    try:
        _request_and_post(manager, server, _classification(config), scope="exact")
        drifted = _classification(drifted_config)
        # Identical payload; only policy_id (and therefore policy_context_hash)
        # changed.
        assert (
            drifted.policy_evaluation.policy_context_hash
            != _classification(config).policy_evaluation.policy_context_hash
        )
        worker = threading.Thread(
            target=lambda: manager.request_approval(
                drifted,
                reason="local_approval_required",
            ),
            daemon=True,
        )
        worker.start()
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.pending_prompts(), "policy-context drift must not reuse exact grant"
        prompt = server.pending_prompts()[0]
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(prompt.request_id))
            _post_decision(client, server.approval_url(prompt.request_id), decision="deny", csrf=csrf)
        worker.join(timeout=3)

        # Positive control: under the unchanged policy context the same exact
        # grant is still live and is reused without a prompt.
        reused = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert reused.approved
        assert reused.reason == "scope_cache_hit"
    finally:
        server.stop()
        store.close()


def test_pending_list_shows_correlation_fields_for_multiple_clients():
    server = ApprovalServer()
    server.start()
    try:
        first = _prompt_not_expired("req-a")
        second = replace(
            _prompt_not_expired("req-b"),
            client_id="claude:session-2",
            session_id="session-b",
        )
        server.register(first)
        server.register(second)
        text = httpx.get(server.approval_center_url()).text
        assert "approval-card" in text
        assert "create_issue" in text
        assert "Write action" in text or "write" in text
        assert "cursor:session-1" in text
        assert "claude:session-2" in text
    finally:
        server.stop()


def test_browser_tab_title_includes_client_id_and_session_short_id():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        text = httpx.get(url).text
        assert "<title>Review: create_issue</title>" in text
    finally:
        server.stop()


def test_headless_disables_browser_launch_and_os_notification(tmp_path):
    class FailingNotifier:
        def notify(self, _prompt):
            raise AssertionError("headless must not notify")

    manager, store, server, _cli = _manager(tmp_path, headless=True, auto_deny=True)
    manager.notifier = FailingNotifier()
    manager.browser_open = lambda _url: (_ for _ in ()).throw(AssertionError("headless browser"))
    try:
        outcome = manager.request_approval(_classification(), reason="local_approval_required")
        assert outcome.status == ApprovalStatus.DENIED.value
    finally:
        server.stop()
        store.close()


def test_approval_flow_does_not_send_raw_args_to_evidence_store_or_ui_or_notification(tmp_path):
    manager, store, server, _cli = _manager(tmp_path)
    worker = threading.Thread(
        target=lambda: manager.request_approval(_classification(), reason="local_approval_required"),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = server.pending_prompts()[0]
        text = httpx.get(server.approval_url(prompt.request_id)).text
        rendered_record = json.dumps(store.get_pending(prompt.request_id).__dict__, sort_keys=True)
        assert SECRET not in text
        assert SECRET not in rendered_record
        assert "ghp_private" not in text
        assert "ghp_private" not in rendered_record
    finally:
        url = server.approval_url(server.pending_prompts()[0].request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            _post_decision(client, url, decision="deny", csrf=csrf)
        worker.join(timeout=2)
        server.stop()
        store.close()


def _approval_downstream(tmp_path: Path, log_path: Path) -> Path:
    return write_downstream(
        tmp_path,
        filename="approval_downstream.py",
        tools=[tool_entry("create_issue")],
        call_result_text="approved",
    )


def _command_tool_downstream(tmp_path: Path, log_path: Path) -> Path:
    schema = {
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
        "additionalProperties": False,
    }
    return write_downstream(
        tmp_path,
        filename="command_tool_downstream.py",
        tools=[tool_entry("run_terminal_cmd", schema)],
        call_result_text="pkg-ok",
    )


def _npm_install_call() -> str:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "run_terminal_cmd",
            "arguments": {"command": "npm install marker-pkg"},
        },
    }, separators=(",", ":")) + "\n"


def _filesystem_write_downstream(tmp_path: Path, log_path: Path) -> Path:
    schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
        },
        "required": ["path", "content"],
        "additionalProperties": False,
    }
    return write_downstream(
        tmp_path,
        filename="filesystem_write_downstream.py",
        tools=[tool_entry("write_file", schema)],
        call_result_text="downstream-ok",
    )


def _persistence_bashrc_call(*, call_id: str = "call-1") -> str:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": ".bashrc", "content": "persistence trapdoor body"},
        },
    }, separators=(",", ":")) + "\n"


def _tool_call() -> str:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "create_issue",
            "arguments": {"owner": "acme", "repo": "private-repo", "title": SECRET},
        },
    }, separators=(",", ":")) + "\n"


def test_approve_resumes_downstream_call_and_records_evidence(tmp_path):
    config = _config(policy_rule=_write_rule())
    manager, store, server, _cli = _manager(tmp_path, config=config)
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_approval_downstream(tmp_path, log_path))),
            name="github",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="github"),
        approval_manager=manager,
    )
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: passthrough.run_stdio(io.StringIO(_tool_call()), client_out),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = server.pending_prompts()[0]
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(prompt.request_id))
            _post_decision(client, server.approval_url(prompt.request_id), decision="approve", csrf=csrf)
        worker.join(timeout=3)
        responses = [json.loads(line) for line in client_out.getvalue().splitlines()]
        assert responses[0]["result"]["content"][0]["text"] == "approved"
        record = store.get_pending(prompt.request_id)
        assert record.status == ApprovalStatus.EXECUTED.value
        assert record.result_status == "executed"
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_deny_blocks_downstream_call_and_records_evidence(tmp_path):
    config = _config(policy_rule=_write_rule())
    manager, store, server, _cli = _manager(tmp_path, config=config)
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_approval_downstream(tmp_path, log_path))),
            name="github",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="github"),
        approval_manager=manager,
    )
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: passthrough.run_stdio(io.StringIO(_tool_call()), client_out),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = server.pending_prompts()[0]
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(prompt.request_id))
            _post_decision(client, server.approval_url(prompt.request_id), decision="deny", csrf=csrf)
        worker.join(timeout=3)
        responses = [json.loads(line) for line in client_out.getvalue().splitlines()]
        assert responses[0]["error"]["data"]["reason"] == "user_denied"
        record = store.get_pending(prompt.request_id)
        assert record.status == ApprovalStatus.DENIED.value
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_timeout_marks_pending_as_expired_and_returns_sanitized_error(tmp_path):
    config = _config(policy_rule=_write_rule(), approval_timeout_seconds=1)
    manager, store, server, _cli = _manager(tmp_path, config=config)
    outcome = manager.request_approval(_classification(config), reason="local_approval_required")
    record = store.get_pending(outcome.request_id)
    try:
        assert outcome.status == ApprovalStatus.EXPIRED.value
        assert record.status == ApprovalStatus.EXPIRED.value
        assert record.expires_at is not None
        assert record.error_class == "approval_timeout"
        assert SECRET not in outcome.reason
    finally:
        server.stop()
        store.close()


def test_deny_mode_writes_pending_record_with_concrete_expires_at(tmp_path):
    config = _config(policy_rule=_write_rule(), approval_timeout_seconds=60)
    manager, store, server, _cli = _manager(tmp_path, config=config)

    def wait_for_decision(request_id, *, timeout):
        return ApprovalServerDecision(request_id=request_id, decision="approve", approval_scope="exact")

    server.wait_for_decision = wait_for_decision  # type: ignore[method-assign]
    try:
        outcome = manager.request_approval(_classification(config), reason="local_approval_required")
        record = store.get_pending(outcome.request_id)

        assert record.expires_at is not None
        assert record.expires_at > record.created_at
    finally:
        server.stop()
        store.close()


def test_post_after_timeout_returns_410_gone(tmp_path):
    config = _config(policy_rule=_write_rule(), approval_timeout_seconds=1)
    manager, store, server, _cli = _manager(tmp_path, config=config)
    result_box: dict[str, Any] = {}
    worker = threading.Thread(
        target=lambda: result_box.setdefault(
            "outcome",
            manager.request_approval(_classification(config), reason="local_approval_required"),
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = server.pending_prompts()[0]
        url = server.approval_url(prompt.request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            worker.join(timeout=3)
            assert result_box["outcome"].status == ApprovalStatus.EXPIRED.value
            assert _post_decision(client, url, decision="approve", csrf=csrf).status_code == 410
    finally:
        server.stop()
        store.close()


def test_approval_timeout_hang_waits_for_eventual_decision(tmp_path):
    config = _config(policy_rule=_write_rule(), approval_timeout_seconds=1, on_timeout="hang")
    manager, store, server, _cli = _manager(tmp_path, config=config)
    calls = []

    def wait_for_decision(request_id, *, timeout):
        calls.append(timeout)
        if len(calls) == 1:
            return None
        return ApprovalServerDecision(request_id=request_id, decision="approve", approval_scope="exact")

    server.wait_for_decision = wait_for_decision  # type: ignore[method-assign]
    try:
        outcome = manager.request_approval(_classification(config), reason="local_approval_required")
        record = store.get_pending(outcome.request_id)
        assert len(calls) == 2
        assert outcome.approved
        assert record.status == ApprovalStatus.APPROVED.value
        assert record.expires_at is None
    finally:
        server.stop()
        store.close()


def test_hang_mode_writes_pending_record_with_null_expires_at(tmp_path):
    config = _config(policy_rule=_write_rule(), approval_timeout_seconds=60, on_timeout="hang")
    manager, store, server, _cli = _manager(tmp_path, config=config)

    def wait_for_decision(request_id, *, timeout):
        return ApprovalServerDecision(request_id=request_id, decision="approve", approval_scope="exact")

    server.wait_for_decision = wait_for_decision  # type: ignore[method-assign]
    try:
        outcome = manager.request_approval(_classification(config), reason="local_approval_required")
        record = store.get_pending(outcome.request_id)

        assert record.expires_at is None
    finally:
        server.stop()
        store.close()


def test_approval_timeout_allow_is_rejected_with_migration_message():
    with pytest.raises(ProxyConfigError, match="approval.on_timeout=allow removed"):
        _config(policy_rule=_write_rule(), on_timeout="allow")


def test_signal_handlers_extend_to_approval_server_graceful_shutdown(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = proxy_cli.init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads(result.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "fake",
        "command": sys.executable,
        "args": ["-c", "print('ready')"],
    }
    result.config_path.write_text(json.dumps(config), encoding="utf-8")

    stopped = {"server": False, "store": False}

    class RecordingServer(ApprovalServer):
        def stop(self, *args, **kwargs):
            stopped["server"] = True
            return super().stop(*args, **kwargs)

    class RecordingStore(ApprovalEvidenceStore):
        def close(self):
            stopped["store"] = True
            return super().close()

    def fake_run_stdio(self, _client_in, _out):
        raise proxy_cli._RunProxySignalExit(signal.SIGTERM)

    monkeypatch.setattr(proxy_cli, "ApprovalServer", RecordingServer)
    monkeypatch.setattr(proxy_cli, "ApprovalEvidenceStore", RecordingStore)
    monkeypatch.setattr(McpPassthrough, "run_stdio", fake_run_stdio)

    assert proxy_cli.run_proxy(home=home, client_in=io.StringIO(), out=io.StringIO()) == 0
    assert stopped == {"server": True, "store": True}


def test_run_proxy_wires_identity_signer_into_approval_manager(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = proxy_cli.init_proxy(home=home, agent_name="proxy", plaintext=True)
    identity = json.loads(result.identity_path.read_text(encoding="utf-8"))
    config = json.loads(result.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "fake",
        "command": sys.executable,
        "args": ["-c", "print('ready')"],
    }
    result.config_path.write_text(json.dumps(config), encoding="utf-8")

    captured: dict[str, Any] = {}

    def fake_run_stdio(self, _client_in, _out):
        captured["seed"] = self.approval_manager.approval_grant_private_key_seed
        captured["did"] = self.approval_manager.approval_grant_agent_did
        return 0

    monkeypatch.setattr(McpPassthrough, "run_stdio", fake_run_stdio)

    assert proxy_cli.run_proxy(home=home, client_in=io.StringIO(), out=io.StringIO()) == 0
    assert captured == {
        "seed": bytes.fromhex(identity["private_key_hex"]),
        "did": identity["did"],
    }


# --- similar_5m resource-binding guard (Step 10) ---

def _classification_no_resource(config: ProxyConfig):
    # WRITE tool that matches the similar_5m rule but exposes no
    # resource-extractable argument, so classification.resource_hash is None.
    return ToolCallClassifier(config, server_name="github").classify(
        tool="create_issue",
        arguments={"title": "no-resource-target"},
    )


def test_scope_expansion_allowed_when_resource_hash_present(tmp_path):
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    manager, store, server, _cli = _manager(tmp_path, config=config)
    try:
        classification = _classification(config)
        assert classification.resource_hash is not None
        assert classification.risk_class.value == "write"
        assert manager._scope_expansion_allowed(classification) is True
    finally:
        server.stop()
        store.close()


def test_scope_expansion_blocked_when_resource_hash_missing(tmp_path):
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    manager, store, server, _cli = _manager(tmp_path, config=config)
    try:
        classification = _classification_no_resource(config)
        # Still a WRITE call under the similar_5m rule -- only the missing
        # resource binding should block expansion.
        assert classification.resource_hash is None
        assert classification.risk_class.value == "write"
        assert manager._scope_expansion_allowed(classification) is False
    finally:
        server.stop()
        store.close()


def test_missing_resource_hash_skips_similar_reuse_and_requires_fresh_approval(tmp_path, monkeypatch):
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    manager, store, server, _cli = _manager(tmp_path, config=config, wait_for_decision=False)
    try:
        similar_lookups = {"count": 0}
        original = store.find_active_similar_grant

        def _spy(**kwargs):
            similar_lookups["count"] += 1
            return original(**kwargs)

        monkeypatch.setattr(store, "find_active_similar_grant", _spy)

        outcome = manager.request_approval(
            _classification_no_resource(config),
            reason="local_approval_required",
        )

        # No resource binding -> the similar-grant reuse lookup is never
        # claim-check: allow "never" describes this negative reuse test.
        # attempted, so no prior grant can be reused...
        assert similar_lookups["count"] == 0
        # ...and the call is not auto-approved via scope cache; a fresh approval
        # prompt is created instead.
        assert outcome.reason != "scope_cache_hit"
        assert outcome.status == ApprovalStatus.PENDING.value
        assert server.pending_prompts(), "missing resource_hash must require a fresh approval"
    finally:
        server.stop()
        store.close()


def test_present_resource_hash_still_attempts_similar_reuse(tmp_path, monkeypatch):
    config = _config(policy_rule=_write_rule(scope_expansion=True))
    manager, store, server, _cli = _manager(tmp_path, config=config, wait_for_decision=False)
    try:
        similar_lookups = {"count": 0}
        original = store.find_active_similar_grant

        def _spy(**kwargs):
            similar_lookups["count"] += 1
            return original(**kwargs)

        monkeypatch.setattr(store, "find_active_similar_grant", _spy)

        manager.request_approval(
            _classification(config),  # resource_hash present
            reason="local_approval_required",
        )

        # Resource-bound similar_5m still consults the reuse cache (preserved).
        assert similar_lookups["count"] == 1
    finally:
        server.stop()
        store.close()


def test_nonblocking_watcher_honors_full_timeout_before_expiring(tmp_path, monkeypatch):
    """Regression: the background decision watcher must honor the full configured
    approval_timeout_seconds.

    A human approval that lands after the first bounded (<=60s) poll slice
    previously expired the pending parent immediately (on_timeout=deny), so the
    later approval failed to make the record reusable and the retry opened a
    fresh pending approval -- the live-console retry loop.
    """

    config = _config(
        policy_rule=_write_rule(),
        approval_timeout_seconds=300,
        on_timeout="deny",
    )
    manager, store, server, _cli = _manager(
        tmp_path, config=config, wait_for_decision=False
    )
    try:
        calls = {"n": 0}

        def slow_wait(request_id, *, timeout):
            # First bounded slice returns no decision (operator still deciding);
            # the next slice carries the approval.
            calls["n"] += 1
            if calls["n"] == 1:
                return None
            return ApprovalServerDecision(
                request_id=request_id, decision="approve", approval_scope="exact"
            )

        monkeypatch.setattr(server, "wait_for_decision", slow_wait)

        outcome = manager.request_approval(
            _classification(config), reason="local_approval_required"
        )
        assert outcome.status == ApprovalStatus.PENDING.value

        deadline = time.monotonic() + 2
        record = store.get_pending(outcome.request_id)
        while record.status == ApprovalStatus.PENDING.value and time.monotonic() < deadline:
            time.sleep(0.01)
            record = store.get_pending(outcome.request_id)

        assert record.status == ApprovalStatus.APPROVED.value
        assert record.approval_scope == "exact"
        assert calls["n"] >= 2
    finally:
        server.stop()
        store.close()


def test_await_decision_returns_approved_when_post_handler_persisted_first(
    tmp_path, monkeypatch
):
    """POST sync handler may finalize evidence before the waiter reads _decisions."""

    config = _config(policy_rule=_write_rule(), approval_timeout_seconds=1, on_timeout="deny")
    manager, store, server, _cli = _manager(tmp_path, config=config, wait_for_decision=False)
    try:
        outcome = manager.request_approval(
            _classification(config), reason="local_approval_required"
        )
        assert outcome.status == ApprovalStatus.PENDING.value
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(outcome.request_id))
            assert _post_decision(
                client,
                server.approval_url(outcome.request_id),
                decision="approve",
                csrf=csrf,
            ).status_code == 200
        assert store.get_pending(outcome.request_id).status == ApprovalStatus.APPROVED.value

        monkeypatch.setattr(server, "wait_for_decision", lambda request_id, *, timeout: None)

        result = manager._await_decision(outcome.request_id, timeout=1)
        assert result.status == ApprovalStatus.APPROVED.value
        assert result.reason == "user_approved"
        assert result.status != ApprovalStatus.EXPIRED.value
    finally:
        server.stop()
        store.close()


def _wait_for_status(store, request_id, status, *, timeout=2.0):
    deadline = time.monotonic() + timeout
    record = store.get_pending(request_id)
    while (record is None or record.status != status) and time.monotonic() < deadline:
        time.sleep(0.01)
        record = store.get_pending(request_id)
    return record


def test_immediate_retry_after_approve_post_matches_live_console(tmp_path):
    """Regression for approval-center race: POST approve then retry immediately.

    Do not wait for the parent evidence row to reach APPROVED before retrying.
    Prior tests that called ``_wait_for_status`` masked this race.
    """

    config = _config(policy_rule=_write_rule())
    manager, store, server, _cli = _manager(
        tmp_path, config=config, wait_for_decision=False
    )
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_approval_downstream(tmp_path, log_path))),
            name="github",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="github"),
        approval_manager=manager,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_tool_call())
        assert len(first) == 1
        assert "error" in first[0], first[0]
        assert first[0]["error"]["data"]["status"] == "approval_required"

        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompts = server.pending_prompts()
        assert prompts, "expected a pending approval prompt for the first call"
        parent_id = prompts[0].request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(parent_id))
            response = _post_decision(
                client, server.approval_url(parent_id), decision="approve", csrf=csrf
            )
        assert response.status_code == 200

        retry = passthrough.handle_client_line(_tool_call())
        assert len(retry) == 1
        assert "result" in retry[0], retry[0]
        assert retry[0]["result"]["content"][0]["text"] == "approved"
        assert server.pending_prompts() == []

        children = [
            record
            for record in store.list_records()
            if record.granted_by_request_id == parent_id
        ]
        assert len(children) == 1, "retry must reuse the grant, not open a new prompt"
        assert children[0].status == ApprovalStatus.EXECUTED.value
        assert children[0].result_status == "executed"
        parent = store.get_pending(parent_id)
        assert parent is not None
        assert parent.status == ApprovalStatus.APPROVED.value
        assert parent.result_status == "executed"
        records = store.list_records()
        execution_by_parent = execution_record_id_by_parent(records)
        assert execution_by_parent[parent_id] == children[0].request_id
        parent_event = event_record_dict(
            parent,
            execution_record_id=execution_by_parent[parent_id],
        )
        assert parent_event["result_status"] == "executed"
        assert parent_event["execution_record_id"] == children[0].request_id
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did=APPROVAL_GRANT_DID,
            trusted_signer_dids=[APPROVAL_GRANT_DID],
        )
        exported_parent = next(
            item for item in bundle["records"] if item["request_id"] == parent_id
        )
        assert exported_parent["status"] == ApprovalStatus.APPROVED.value
        assert exported_parent["result_status"] == "executed"
        assert exported_parent["execution_record_id"] == children[0].request_id
        for record in records:
            blob = f"{record.tool_name}:{record.payload_hash}:{record.status}"
            assert SECRET not in blob
        assert SECRET not in json.dumps(bundle)
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_persistence_retry_after_approve_does_not_reopen_pending(tmp_path):
    """Regression for approval-center user path: trapdoor then policy on retry.

    After POST approve, a persistent ``run`` retry hits persistence TrapDoor
    (``request_approval`` + grant child) and then local policy still returns
    APPROVAL. The policy layer must coalesce the in-flight TrapDoor approval,
    not register a second pending prompt.
    """

    config = _config(policy_rule=_fake_downstream_write_approval_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_filesystem_write_downstream(tmp_path, log_path))),
            name="fake-downstream",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="fake-downstream"),
        approval_manager=manager,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_persistence_bashrc_call())
        assert first[0]["error"]["data"]["status"] == "approval_required"

        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        parent_id = server.pending_prompts()[0].request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(parent_id))
            assert _post_decision(
                client,
                server.approval_url(parent_id),
                decision="approve",
                csrf=csrf,
            ).status_code == 200

        retry = passthrough.handle_client_line(_persistence_bashrc_call())
        assert len(retry) == 1
        assert "result" in retry[0], retry[0]
        assert server.pending_prompts() == []
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]

        children = [
            record
            for record in store.list_records()
            if record.granted_by_request_id == parent_id
        ]
        assert len(children) == 1
        assert children[0].status == ApprovalStatus.EXECUTED.value
        parent = store.get_pending(parent_id)
        assert parent is not None
        assert parent.status == ApprovalStatus.APPROVED.value
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_trapdoor_approved_retry_still_requires_runtime_gate_waiting(tmp_path):
    """TrapDoor grant must not satisfy a separate Runtime Gate WAITING approval."""

    config = _config(policy_rule=_fake_downstream_write_ask_backend_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_filesystem_write_downstream(tmp_path, log_path))),
            name="fake-downstream",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="fake-downstream"),
        approval_manager=manager,
        runtime_gate_factory=_RuntimeGateWaitingStub,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_persistence_bashrc_call(call_id="call-1"))
        assert first[0]["error"]["data"]["reason"] == "persistence_path_write_requires_approval"

        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        trapdoor_parent_id = server.pending_prompts()[0].request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(trapdoor_parent_id))
            assert _post_decision(
                client,
                server.approval_url(trapdoor_parent_id),
                decision="approve",
                csrf=csrf,
            ).status_code == 200

        retry = passthrough.handle_client_line(_persistence_bashrc_call(call_id="call-2"))
        assert len(retry) == 1
        assert "error" in retry[0]
        assert retry[0]["error"]["data"]["status"] == "approval_required"
        assert (
            retry[0]["error"]["data"]["reason"]
            == "runtime_gate_waiting_for_human_approval"
        )
        assert retry[0]["error"]["data"]["decision"] == "WAITING_FOR_HUMAN_APPROVAL"
        assert retry[0]["error"]["data"]["audit_id"] == RUNTIME_GATE_WAITING_AUDIT_ID
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]
        assert len(server.pending_prompts()) >= 1
        runtime_prompt_ids = {
            prompt.request_id
            for prompt in server.pending_prompts()
        }
        assert runtime_prompt_ids.isdisjoint({trapdoor_parent_id})
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_independent_identical_request_does_not_reuse_inflight_approval(tmp_path):
    """Approved retry children must not auto-reuse across separate MCP requests."""

    config = _config(policy_rule=_fake_downstream_write_approval_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_filesystem_write_downstream(tmp_path, log_path))),
            name="fake-downstream",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="fake-downstream"),
        approval_manager=manager,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_persistence_bashrc_call(call_id="call-1"))
        assert first[0]["error"]["data"]["status"] == "approval_required"
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        parent_id = server.pending_prompts()[0].request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(parent_id))
            assert _post_decision(
                client,
                server.approval_url(parent_id),
                decision="approve",
                csrf=csrf,
            ).status_code == 200

        retry = passthrough.handle_client_line(_persistence_bashrc_call(call_id="call-2"))
        assert "result" in retry[0]
        assert server.pending_prompts() == []

        second_request = passthrough.handle_client_line(
            _persistence_bashrc_call(call_id="call-3")
        )
        assert second_request[0]["error"]["data"]["status"] == "approval_required"
        assert len(server.pending_prompts()) == 1
        assert server.pending_prompts()[0].request_id != parent_id
        assert log_path.read_text(encoding="utf-8").splitlines() == [
            "tools/list",
            "tools/call",
        ]
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_passthrough_retry_after_trapdoor_approval_records_executed_evidence(tmp_path):
    """Regression for persistent run: trapdoor approval must keep retry outcome.

    Mirrors ``run_proxy`` (``wait_for_decision=False``) plus TrapDoor persistence
    path approval before local policy allow would otherwise drop the outcome.
    """

    config = _config(policy_rule=_allow_write_file_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
        approval_grant_private_key_seed=APPROVAL_GRANT_SEED,
        approval_grant_agent_did=APPROVAL_GRANT_DID,
    )
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_filesystem_write_downstream(tmp_path, log_path))),
            name="fake-downstream",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="fake-downstream"),
        approval_manager=manager,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_persistence_bashrc_call())
        assert len(first) == 1
        assert first[0]["error"]["data"]["reason"] == "persistence_path_write_requires_approval"

        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        parent_id = server.pending_prompts()[0].request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(parent_id))
            response = _post_decision(
                client,
                server.approval_url(parent_id),
                decision="approve",
                csrf=csrf,
            )
        assert response.status_code == 200

        retry = passthrough.handle_client_line(_persistence_bashrc_call())
        assert len(retry) == 1
        assert retry[0]["result"]["content"][0]["text"] == "downstream-ok"
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]

        children = [
            record
            for record in store.list_records()
            if record.granted_by_request_id == parent_id
        ]
        assert len(children) == 1
        assert children[0].status == ApprovalStatus.EXECUTED.value
        assert children[0].result_status == "executed"
        parent = store.get_pending(parent_id)
        assert parent.status == ApprovalStatus.APPROVED.value
        assert parent.result_status == "executed"
        execution_by_parent = execution_record_id_by_parent(store.list_records())
        assert execution_by_parent[parent_id] == children[0].request_id
        assert "persistence trapdoor body" not in json.dumps(
            event_record_dict(
                parent,
                execution_record_id=execution_by_parent[parent_id],
            )
        )
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def _assert_package_manager_evidence_privacy_safe(
    *,
    store: ApprovalEvidenceStore,
    parent_id: str,
    parent: Any,
    children: list[Any],
    secret: str = PACKAGE_MANAGER_SECRET,
    command_fragment: str = PACKAGE_MANAGER_COMMAND_FRAGMENT,
) -> None:
    """Assert T6 evidence surfaces omit raw package-manager command content."""

    records = store.list_records()
    execution_by_parent = execution_record_id_by_parent(records)
    assert execution_by_parent[parent_id] == children[0].request_id
    parent_event = event_record_dict(
        parent,
        execution_record_id=execution_by_parent[parent_id],
    )
    assert parent_event["result_status"] == "executed"
    assert parent_event["execution_record_id"] == children[0].request_id
    for forbidden in (secret, command_fragment):
        assert forbidden not in json.dumps(parent_event)

    bundle = build_evidence_bundle(
        store,
        proxy_identity_did=APPROVAL_GRANT_DID,
        trusted_signer_dids=[APPROVAL_GRANT_DID],
    )
    exported_parent = next(
        item for item in bundle["records"] if item["request_id"] == parent_id
    )
    exported_child = next(
        item for item in bundle["records"] if item["request_id"] == children[0].request_id
    )
    assert exported_parent["execution_record_id"] == children[0].request_id
    assert "execution_record_id" not in exported_child
    bundle_blob = json.dumps(bundle)
    for forbidden in (secret, command_fragment):
        assert forbidden not in json.dumps(exported_parent)
        assert forbidden not in json.dumps(exported_child)
        assert forbidden not in bundle_blob
    assert '"arguments"' not in bundle_blob

    for record in records:
        blob = json.dumps(asdict(record))
        for forbidden in (secret, command_fragment):
            assert forbidden not in blob
        assert '"arguments"' not in blob

    rendered_event = format_event_record(
        parent,
        receipt_status="present",
        execution_record_id=execution_by_parent[parent_id],
        timestamp_formatter=str,
        token_formatter=str,
    )
    for forbidden in (secret, command_fragment):
        assert forbidden not in rendered_event


def test_package_manager_retry_executes_once_after_approval(tmp_path):
    """Approved package-manager retry runs downstream once with executed evidence."""

    config = _config(policy_rule=_allow_run_terminal_cmd_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
        approval_grant_private_key_seed=APPROVAL_GRANT_SEED,
        approval_grant_agent_did=APPROVAL_GRANT_DID,
    )
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_command_tool_downstream(tmp_path, log_path))),
            name="fake-downstream",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="fake-downstream"),
        approval_manager=manager,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_npm_install_call())
        assert first[0]["error"]["data"]["reason"] == "package_manager_action_requires_approval"
        for forbidden in (PACKAGE_MANAGER_SECRET, PACKAGE_MANAGER_COMMAND_FRAGMENT):
            assert forbidden not in json.dumps(first[0])

        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        parent_id = server.pending_prompts()[0].request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(parent_id))
            response = _post_decision(
                client,
                server.approval_url(parent_id),
                decision="approve",
                csrf=csrf,
            )
        assert response.status_code == 200

        retry = passthrough.handle_client_line(_npm_install_call())
        assert retry[0]["result"]["content"][0]["text"] == "pkg-ok"
        assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]
        assert server.pending_prompts() == []

        children = [
            record
            for record in store.list_records()
            if record.granted_by_request_id == parent_id
        ]
        assert len(children) == 1
        assert children[0].status == ApprovalStatus.EXECUTED.value
        assert children[0].result_status == "executed"
        parent = store.get_pending(parent_id)
        assert parent is not None
        assert parent.status == ApprovalStatus.APPROVED.value
        assert parent.result_status == "executed"
        _assert_package_manager_evidence_privacy_safe(
            store=store,
            parent_id=parent_id,
            parent=parent,
            children=children,
        )
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def _tty_cli() -> io.StringIO:
    cli = io.StringIO()
    cli.isatty = lambda: True  # type: ignore[method-assign]
    return cli


def _run_terminal_cmd_approval_rule() -> dict[str, Any]:
    return {
        "id": "cmd-approval",
        "source": "user",
        "decision": "approval",
        "risk_class": "write",
        "match": {"server": "fake-downstream", "tool": "run_terminal_cmd"},
    }


def _command_classification(config: ProxyConfig, *, command: str) -> Any:
    return ToolCallClassifier(config, server_name="fake-downstream").classify(
        tool="run_terminal_cmd",
        arguments={"command": command},
    )


T1_FORBIDDEN_HTML_FRAGMENTS = (
    SECRET,
    "ghp_private",
    PACKAGE_MANAGER_SECRET,
    "npm install",
    "private-repo",
    "print('private')",
    '"arguments"',
    '"command":',
)


def _assert_t1_privacy_safe_text(text: str) -> None:
    for fragment in T1_FORBIDDEN_HTML_FRAGMENTS:
        assert fragment not in text


@pytest.mark.parametrize(
    ("ui_open_mode", "headless", "auto_deny", "expected_browser_open_calls"),
    [
        ("browser", False, False, 1),
        ("terminal", False, False, 0),
        ("none", False, False, 0),
        ("browser", True, True, 0),
    ],
)
def test_t1_browser_open_budget_uses_injected_mock_only(
    tmp_path,
    ui_open_mode,
    headless,
    auto_deny,
    expected_browser_open_calls,
):
    """Browser spam fix through injected browser_open."""

    opened_urls: list[str] = []
    config = _config(ui_open_mode=ui_open_mode)
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        cli_out=_tty_cli(),
        headless=headless,
        auto_deny=auto_deny,
        wait_for_decision=False,
        browser_open=lambda url: opened_urls.append(url) or True,
    )
    assert manager.browser_open is not webbrowser.open
    try:
        repeat = 1 if headless else 10
        for _index in range(repeat):
            manager.request_approval(_classification(config), reason="local_approval_required")
        assert len(opened_urls) == expected_browser_open_calls
        if expected_browser_open_calls == 1:
            assert opened_urls[0] == server.approval_center_url()
            for fragment in T1_FORBIDDEN_HTML_FRAGMENTS:
                assert fragment not in opened_urls[0]
    finally:
        server.stop()
        store.close()


def test_t1_default_approval_list_and_detail_html_exclude_raw_secrets(tmp_path):
    """Default HTML surfaces stay redacted; no raw arg preview."""

    cmd_config = _config(policy_rule=_run_terminal_cmd_approval_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=cmd_config,
        wait_for_decision=False,
    )
    try:
        manager.request_approval(
            _command_classification(cmd_config, command="pip list"),
            reason="local_approval_required",
        )
        manager.request_approval(
            _command_classification(
                cmd_config,
                command=f"npm install {PACKAGE_MANAGER_SECRET}",
            ),
            reason="package_manager_action_requires_approval",
        )
        list_html = httpx.get(server.approval_center_url(), follow_redirects=True).text
        _assert_t1_privacy_safe_text(list_html)
        assert "Show local details" not in list_html

        for prompt in server.pending_prompts():
            detail_html = httpx.get(server.approval_url(prompt.request_id)).text
            _assert_t1_privacy_safe_text(detail_html)
            assert "Show local details" not in detail_html
            assert cmd_config.privacy.show_details_in_approval_ui is False
    finally:
        server.stop()
        store.close()


def test_t1_center_output_lines_exclude_raw_payload(tmp_path):
    """CLI fallback/center output omits raw MCP payload."""

    cli = _tty_cli()
    config = _config(
        ui_open_mode="browser",
        policy_rule=_run_terminal_cmd_approval_rule(),
    )
    opened_urls: list[str] = []
    manager, store, server, _ = _manager(
        tmp_path,
        config=config,
        cli_out=cli,
        wait_for_decision=False,
        browser_open=lambda url: opened_urls.append(url) or True,
    )
    try:
        for _index in range(3):
            manager.request_approval(
                _command_classification(
                    config,
                    command=f"npm install {PACKAGE_MANAGER_SECRET}",
                ),
                reason="local_approval_required",
            )
        output = cli.getvalue()
        _assert_t1_privacy_safe_text(output)
        assert len(opened_urls) == 1
        assert opened_urls[0] == server.approval_center_url()
    finally:
        server.stop()
        store.close()


def test_browser_mode_opens_approval_center_once_for_repeated_pending(tmp_path):
    opened_urls: list[str] = []
    config = _config()
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        cli_out=_tty_cli(),
        wait_for_decision=False,
        browser_open=lambda url: opened_urls.append(url) or True,
    )
    try:
        for _index in range(10):
            outcome = manager.request_approval(
                _classification(config),
                reason="local_approval_required",
            )
            assert outcome.status == ApprovalStatus.PENDING.value
        assert len(opened_urls) == 1
        assert opened_urls[0] == server.approval_center_url()
        assert len(server.pending_prompts()) == 10
    finally:
        server.stop()
        store.close()


def test_terminal_mode_prints_url_without_browser_open(tmp_path):
    opened_urls: list[str] = []
    cli = _tty_cli()
    config = _config(ui_open_mode="terminal")
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        cli_out=cli,
        wait_for_decision=False,
        browser_open=lambda url: opened_urls.append(url) or True,
    )
    try:
        outcome = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert outcome.status == ApprovalStatus.PENDING.value
        assert opened_urls == []
        rendered = cli.getvalue()
        assert "/pending/" in rendered
        assert "record_id=" in rendered
        assert SECRET not in rendered
    finally:
        server.stop()
        store.close()


@pytest.mark.parametrize("ui_mode", ["none"])
def test_ui_none_mode_never_opens_browser(tmp_path, ui_mode):
    opened_urls: list[str] = []
    config = _config(ui_open_mode=ui_mode)
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        cli_out=_tty_cli(),
        wait_for_decision=False,
        browser_open=lambda url: opened_urls.append(url) or True,
    )
    try:
        manager.request_approval(_classification(config), reason="local_approval_required")
        assert opened_urls == []
    finally:
        server.stop()
        store.close()


def test_headless_never_opens_browser_even_when_config_requests_browser(tmp_path):
    opened_urls: list[str] = []
    config = _config(ui_open_mode="browser")
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        headless=True,
        auto_deny=True,
        wait_for_decision=False,
        browser_open=lambda url: opened_urls.append(url) or True,
    )
    try:
        outcome = manager.request_approval(_classification(config), reason="local_approval_required")
        assert outcome.status == ApprovalStatus.DENIED.value
        assert opened_urls == []
    finally:
        server.stop()
        store.close()


def test_api_approvals_returns_pending_json(tmp_path):
    config = _config(policy_rule=_run_terminal_cmd_approval_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    try:
        manager.request_approval(
            _command_classification(config, command="pip list"),
            reason="local_approval_required",
        )
        manager.request_approval(
            _command_classification(
                config,
                command=f"npm install {PACKAGE_MANAGER_SECRET}",
            ),
            reason="package_manager_action_requires_approval",
        )
        response = httpx.get(
            f"{server.base_url}/approval/{server.session_token}/api/approvals",
            timeout=2,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["ok"] is True
        assert len(payload["approvals"]) == 2
        for item in payload["approvals"]:
            assert item["status"] == ApprovalStatus.PENDING.value
            assert "request_id" in item
            assert "session_id_prefix" in item
            assert len(item["session_id_prefix"]) == 8
            assert "session_id" not in item
            assert "csrf_token" not in item
        reasons = {item["reason"] for item in payload["approvals"]}
        assert "local_approval_required" in reasons
        assert "package_manager_action_requires_approval" in reasons
        _assert_t1_privacy_safe_text(json.dumps(payload))
    finally:
        server.stop()
        store.close()


def test_api_approvals_includes_bounded_level2_metadata(tmp_path):
    config = _config(
        policy_rule=_write_rule(),
        role_authority={"mode": "enforce", "role": "implementer", "authority": "implement"},
    )
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    try:
        outcome = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        response = httpx.get(
            f"{server.base_url}/approval/{server.session_token}/api/approvals",
            timeout=2,
        )
        assert response.status_code == 200
        payload = response.json()
        approval = next(item for item in payload["approvals"] if item["request_id"] == outcome.request_id)
        metadata = approval["action_gate_metadata"]
        assert metadata["action_family"] == "create"
        assert metadata["policy_decision"] == "approval"
        assert metadata["approval_status"] == ApprovalStatus.PENDING.value
        assert metadata["execution_status"] == "not_reached"
        assert metadata["target_reached"] is False
        assert metadata["redirect_playbook_id"] == "request_approval"
        assert metadata["role"] == "implementer"
        assert metadata["authority"] == "implement"
        blast_radius = metadata.get("blast_radius")
        assert isinstance(blast_radius, dict)
        assert isinstance(blast_radius.get("capabilities"), dict)
        assert blast_radius.get("credential_posture") in {
            "visible_static_key",
            "short_lived_token",
            "brokered",
            "hardware_bound",
            "unknown",
        }
        rendered = json.dumps(payload)
        _assert_t1_privacy_safe_text(rendered)
        assert SECRET not in rendered
        assert "ghp_private" not in rendered
        assert "source_code" not in rendered
        assert "session-1234567890" not in rendered
    finally:
        server.stop()
        store.close()


def test_api_approvals_forbidden_without_valid_token():
    server = ApprovalServer()
    server.start()
    try:
        server.register(_prompt("req-api"))
        response = httpx.get(f"{server.base_url}/approval/not-a-valid-token/api/approvals")
        assert response.status_code == 403
    finally:
        server.stop()


def test_dashboard_empty_state_renders():
    server = ApprovalServer()
    server.start()
    try:
        text = httpx.get(server.approval_center_url()).text
        assert "No pending approvals" in text
        assert "approval-empty" in text
        assert "approval-card" not in text
    finally:
        server.stop()


def test_dashboard_pending_cards_render_sanitized_fields(tmp_path):
    config = _config(policy_rule=_run_terminal_cmd_approval_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    try:
        outcome = manager.request_approval(
            _command_classification(config, command="pip list"),
            reason="local_approval_required",
        )
        manager.request_approval(
            _command_classification(config, command="pip show setuptools"),
            reason="local_approval_required",
        )
        assert outcome.status == ApprovalStatus.PENDING.value
        text = _dashboard_list_html(server)
        assert "approval-card" in text
        assert "The agent wants to run" in text
        assert "run_terminal_cmd" in text
        assert "Needs your approval" in text
        assert "Write action" in text or "approval-risk-write" in text
        assert "Review &amp; decide" in text
        assert "payload_hash" not in text
    finally:
        server.stop()
        store.close()


def test_dashboard_and_detail_render_level2_metadata_without_raw_payload(tmp_path):
    config = _config(
        policy_rule=_write_rule(),
        role_authority={"mode": "enforce", "role": "implementer", "authority": "implement"},
    )
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    try:
        manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        prompt = server.pending_prompts()[0]
        dashboard = _dashboard_list_html(server)
        detail = httpx.get(server.approval_url(prompt.request_id)).text
        assert "Technical details" in detail
        assert "Payload hash" in detail
        for text in (dashboard, detail):
            assert "The agent wants to run" in text
            assert "Needs your approval" in text or "Needs review" in text
            _assert_t1_privacy_safe_text(text)
            assert SECRET not in text
            assert "ghp_private" not in text
            assert "source_code" not in text
            assert "session-1234567890" not in text
        for text in (detail,):
            assert "Role" in text
            assert "implementer" in text
            assert "Authority" in text
            assert "implement" in text
            assert "Action family" in text
            assert "create" in text
            assert "Policy decision" in text
            assert "approval" in text
            assert "Approval status" in text
            assert "pending" in text
            assert "Execution status" in text
            assert "not_reached" in text
            assert "Target reached" in text
            assert "false" in text
            assert "Redirect" in text
            assert "request_approval" in text
    finally:
        server.stop()
        store.close()


def test_dashboard_excludes_raw_secrets_and_long_plaintext(tmp_path):
    config = _config(policy_rule=_run_terminal_cmd_approval_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    try:
        manager.request_approval(
            _command_classification(
                config,
                command=f"npm install {PACKAGE_MANAGER_SECRET}",
            ),
            reason="package_manager_action_requires_approval",
        )
        manager.request_approval(
            _command_classification(config, command="pip list"),
            reason="local_approval_required",
        )
        text = _dashboard_list_html(server)
        _assert_t1_privacy_safe_text(text)
        prompt = server.pending_prompts()[0]
        detail = httpx.get(server.approval_url(prompt.request_id)).text
        assert "sha256:" in detail
    finally:
        server.stop()
        store.close()


def test_dashboard_hides_terminal_prompts():
    server = ApprovalServer()
    server.start()
    try:
        server.register(_prompt("req-terminal"))
        server.unregister("req-terminal")
        text = httpx.get(server.approval_center_url()).text
        assert "No pending approvals" in text
        assert "req-terminal" not in text
    finally:
        server.stop()


def test_approval_center_redirects_to_actionable_detail_when_single_pending(tmp_path):
    config = _config(policy_rule=_write_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    try:
        outcome = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert outcome.approval_url is not None
        with httpx.Client(follow_redirects=False) as client:
            response = client.get(server.approval_center_url())
            assert response.status_code == 302
            assert response.headers["location"].endswith(f"/pending/{outcome.request_id}")
            detail = client.get(server.approval_center_url(), follow_redirects=True)
        assert "Approve" in detail.text
        assert "Deny" in detail.text
        assert 'name="csrf_token"' in detail.text
    finally:
        server.stop()
        store.close()


def test_approval_center_list_includes_inline_approve_deny_for_multiple_pending(tmp_path):
    config = _config(policy_rule=_write_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    try:
        manager.request_approval(_classification(config), reason="local_approval_required")
        manager.request_approval(_classification(config), reason="local_approval_required")
        with httpx.Client() as client:
            response = client.get(server.approval_center_url())
        assert response.status_code == 200
        assert response.text.count('name="decision" value="approve"') >= 2
        assert response.text.count('name="decision" value="deny"') >= 2
        assert "Review &amp; decide" in response.text
    finally:
        server.stop()
        store.close()


def test_post_decision_page_instructs_retry():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired("req-retry-hint"))
        with httpx.Client() as client:
            csrf = _get_csrf(client, url)
            response = _post_decision(client, url, decision="approve", csrf=csrf)
        assert response.status_code == 200
        assert "Decision recorded" in response.text
        assert "Retry the same request" in response.text
    finally:
        server.stop()


def test_dashboard_detail_approve_deny_flow_still_works(tmp_path):
    """Dashboard links to detail page; approve POST + immediate retry still execute."""

    config = _config(policy_rule=_write_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_approval_downstream(tmp_path, log_path))),
            name="github",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="github"),
        approval_manager=manager,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_tool_call())
        assert len(first) == 1
        assert first[0]["error"]["data"]["status"] == "approval_required"

        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = server.pending_prompts()[0]
        detail_url = server.approval_url(prompt.request_id)
        center_detail = httpx.get(server.approval_center_url(), follow_redirects=True).text
        assert "Approve" in center_detail
        assert "Deny" in center_detail
        detail = httpx.get(detail_url).text
        assert "Approve" in detail
        assert "Deny" in detail
        assert "Back to pending list" in detail
        assert "&larr;" in detail
        with httpx.Client() as client:
            csrf = _get_csrf(client, detail_url)
            response = _post_decision(
                client,
                detail_url,
                decision="approve",
                csrf=csrf,
            )
        assert response.status_code == 200

        retry = passthrough.handle_client_line(_tool_call())
        assert len(retry) == 1
        assert "result" in retry[0], retry[0]
        assert log_path.read_text(encoding="utf-8").splitlines() == [
            "tools/list",
            "tools/call",
        ]
    finally:
        passthrough.stop()
        server.stop()
        store.close()


def test_dashboard_and_detail_include_light_theme_css():
    server = ApprovalServer()
    server.start()
    try:
        dashboard = httpx.get(server.approval_center_url()).text
        detail_url = server.register(_prompt_not_expired("req-t31-theme"))
        detail = httpx.get(detail_url).text
        for html in (dashboard, detail):
            assert "prefers-color-scheme: light" in html
            assert ":root" in html
            assert "--bg:" in html
            assert "var(--text)" in html
            assert "var(--bg)" in html
    finally:
        server.stop()


def test_detail_shows_session_prefix_not_full_session_id():
    server = ApprovalServer()
    server.start()
    try:
        prompt = _prompt_not_expired("req-t31-session")
        assert prompt.session_id == "session-abcdef"
        assert prompt.session_id[:8] == "session-"
        detail = httpx.get(server.register(prompt)).text
        assert "session-abcdef" not in detail
        assert "abcdef" not in detail
        assert "Session prefix" in detail
        assert "session-" in detail
        assert "req-t31-session" in detail
    finally:
        server.stop()


def test_dashboard_and_detail_include_local_url_warning():
    warning = approval_server_module.APPROVAL_LOCAL_URL_WARNING
    server = ApprovalServer()
    server.start()
    try:
        dashboard = httpx.get(server.approval_center_url()).text
        detail = httpx.get(server.register(_prompt_not_expired("req-t31-warning"))).text
        for html in (dashboard, detail):
            assert warning in html
            assert "approval-security-notice" in html
    finally:
        server.stop()


def test_api_approvals_json_excludes_raw_secrets_and_html_still_works(tmp_path):
    config = _config(policy_rule=_run_terminal_cmd_approval_rule())
    manager, store, server, _cli = _manager(
        tmp_path,
        config=config,
        wait_for_decision=False,
    )
    try:
        manager.request_approval(
            _command_classification(
                config,
                command=f"npm install {PACKAGE_MANAGER_SECRET}",
            ),
            reason="package_manager_action_requires_approval",
        )
        manager.request_approval(
            _command_classification(config, command="pip list"),
            reason="local_approval_required",
        )
        api_url = f"{server.base_url}/approval/{server.session_token}/api/approvals"
        payload = httpx.get(api_url).json()
        _assert_t1_privacy_safe_text(json.dumps(payload))

        list_html = _dashboard_list_html(server)
        assert "Pending approvals" in list_html
        assert "approval-card" in list_html
        _assert_t1_privacy_safe_text(list_html)

        prompt = server.pending_prompts()[0]
        detail_html = httpx.get(server.approval_url(prompt.request_id)).text
        assert "Review:" in detail_html
        _assert_t1_privacy_safe_text(detail_html)
    finally:
        server.stop()
        store.close()


def test_immediate_retry_materializes_when_post_handler_disabled(tmp_path):
    """Grant flush on retry even without the POST sync handler."""

    config = _config(policy_rule=_write_rule())
    manager, store, server, _cli = _manager(
        tmp_path, config=config, wait_for_decision=False
    )
    server.set_decision_handler(None)
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_approval_downstream(tmp_path, log_path))),
            name="github",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="github"),
        approval_manager=manager,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_tool_call())
        assert first[0]["error"]["data"]["status"] == "approval_required"
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        parent_id = server.pending_prompts()[0].request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(parent_id))
            assert _post_decision(
                client, server.approval_url(parent_id), decision="approve", csrf=csrf
            ).status_code == 200
        retry = passthrough.handle_client_line(_tool_call())
        assert "result" in retry[0]
        assert server.pending_prompts() == []
    finally:
        passthrough.stop()
        server.stop()
        store.close()


STALE_HTML_FORBIDDEN_FRAGMENTS = (
    SECRET,
    PACKAGE_MANAGER_SECRET,
    '"arguments"',
    '"command":',
    "csrf-token",
    "session-abcdef",
)


def _assert_stale_html_privacy_safe(text: str, *, session_token: str | None = None) -> None:
    lowered = text.lower()
    assert "<form" not in lowered
    assert 'name="csrf_token"' not in lowered
    if session_token:
        assert session_token not in text
    for fragment in STALE_HTML_FORBIDDEN_FRAGMENTS:
        assert fragment not in text


def _assert_stale_html_response(
    response: httpx.Response,
    *,
    headline: str,
    session_token: str | None = None,
) -> None:
    assert "text/html" in response.headers.get("content-type", "")
    assert headline in response.text
    _assert_stale_html_privacy_safe(response.text, session_token=session_token)


def test_get_after_approve_returns_stale_html_terminal_no_forms():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired())
        with httpx.Client() as client:
            csrf, cookie = _get_csrf_and_cookie(client, url)
            assert _post_decision(client, url, decision="approve", csrf=csrf).status_code == 200
            stale = client.get(url, headers={"Cookie": cookie})
        assert stale.status_code == 410
        _assert_stale_html_response(
            stale,
            headline="Already decided",
            session_token=server.session_token,
        )
        assert "Approved" in stale.text
        snapshot = server.stale_terminal_snapshot_for("req-1")
        assert snapshot is not None
        assert snapshot.state == TERMINAL_ALREADY_DECIDED_APPROVE
    finally:
        server.stop()


def test_get_after_deny_returns_stale_html_terminal_no_forms():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired("req-deny"))
        with httpx.Client() as client:
            csrf, cookie = _get_csrf_and_cookie(client, url)
            assert _post_decision(client, url, decision="deny", csrf=csrf).status_code == 200
            stale = client.get(url, headers={"Cookie": cookie})
        assert stale.status_code == 410
        _assert_stale_html_response(
            stale,
            headline="Already decided",
            session_token=server.session_token,
        )
        assert "Denied" in stale.text
        snapshot = server.stale_terminal_snapshot_for("req-deny")
        assert snapshot is not None
        assert snapshot.state == TERMINAL_ALREADY_DECIDED_DENY
    finally:
        server.stop()


def test_get_after_timeout_unregister_returns_expired_html_page(tmp_path):
    config = _config(policy_rule=_write_rule(), approval_timeout_seconds=1)
    manager, store, server, _cli = _manager(tmp_path, config=config)
    worker = threading.Thread(
        target=lambda: manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while not server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = server.pending_prompts()[0]
        url = server.approval_url(prompt.request_id)
        worker.join(timeout=3)
        snapshot = server.terminal_snapshot_for(prompt.request_id)
        assert snapshot is not None
        assert snapshot.state == TERMINAL_APPROVAL_EXPIRED
        stale = httpx.get(url)
        assert stale.status_code == 410
        _assert_stale_html_response(
            stale,
            headline="Approval expired",
            session_token=server.session_token,
        )
    finally:
        server.stop()
        store.close()


def test_get_unknown_request_id_returns_html_no_longer_pending():
    server = ApprovalServer()
    server.start()
    try:
        response = httpx.get(
            f"{server.base_url}/approval/{server.session_token}/pending/does-not-exist",
        )
        assert response.status_code == 404
        _assert_stale_html_response(
            response,
            headline="Request no longer pending",
            session_token=server.session_token,
        )
    finally:
        server.stop()


def test_expired_pending_removed_from_default_dashboard_list(monkeypatch):
    server = ApprovalServer()
    server.start()
    try:
        prompt = replace(
            _prompt("req-expired-dashboard"),
            created_at=100,
            expires_at=150,
        )
        server.register(prompt)
        monkeypatch.setattr(approval_server_module.time, "time", lambda: 200.0)
        assert not server.pending_prompts()
        text = httpx.get(server.approval_center_url()).text
        assert "No pending approvals" in text
        assert server.terminal_snapshot_for(prompt.request_id) is not None
    finally:
        server.stop()


def test_get_expired_prompt_before_unregister_shows_expired_html(monkeypatch):
    server = ApprovalServer()
    server.start()
    try:
        prompt = replace(
            _prompt("req-expired"),
            created_at=100,
            expires_at=150,
        )
        url = server.register(prompt)
        monkeypatch.setattr(approval_server_module.time, "time", lambda: 200.0)
        response = httpx.get(url)
        assert response.status_code == 410
        _assert_stale_html_response(
            response,
            headline="Approval expired",
            session_token=server.session_token,
        )
        assert not server.pending_prompts()
        assert server.terminal_snapshot_for(prompt.request_id) is not None
    finally:
        server.stop()


def test_invalid_approval_token_returns_403_html_without_leaking_pending():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired("req-secret"))
        wrong = url.replace(server.session_token, "not-the-real-session-token-value")
        response = httpx.get(wrong)
        assert response.status_code == 403
        assert "text/html" in response.headers.get("content-type", "")
        assert "Forbidden" in response.text
        assert "req-secret" not in response.text
        assert "github.create_issue" not in response.text
        _assert_stale_html_privacy_safe(response.text, session_token=server.session_token)
    finally:
        server.stop()


# ----- P0.1 installed-path approval UX: human-readable write_file detail -----


def test_write_file_approval_detail_shows_bounded_target_and_write_risk(tmp_path):
    from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream

    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )
    config = ProxyConfig.from_dict(
        json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8")),
    )
    manager, store, server, _cli = _manager(
        home,
        config=config,
        wait_for_decision=False,
    )
    try:
        classification = ToolCallClassifier(config, server_name="filesystem").classify(
            tool="write_file",
            arguments={"path": "approval-ui-smoke.txt", "content": "probe"},
        )
        outcome = manager.request_approval(classification, reason="local_approval_required")
        assert outcome.status == ApprovalStatus.PENDING.value
        prompt = server.pending_prompts()[0]
        detail = httpx.get(server.approval_url(prompt.request_id)).text
        assert "write_file" in detail
        assert "approval-ui-smoke.txt" in detail
        assert "Write action" in detail
        assert "Unknown risk" not in detail
        assert "Approve</button>" in detail
        assert "Deny</button>" in detail
        main_view, _, _ = detail.partition("<details class=\"approval-technical-details\">")
        assert "sha256:" not in main_view
    finally:
        server.stop()
        store.close()


# ----- P10D.14 S3 follow-up: G4 approve->retry payload-drift diagnosis -------
#
# Root cause of the live G4 failure: a controlled write_file retry through a
# *separate* Claude session produced the same path but different content bytes
# (e.g. a trailing newline), so payload_hash drifted while resource_hash stayed
# identical. exact-scope approval is payload-bound, so it correctly did NOT  # claim-check: allow approval binding property asserted by tests below.
# cover the changed-content retry. similar_5m is resource-bound and
# payload-AGNOSTIC (store.find_active_similar_grant has no payload_hash filter),
# so enabling it for filesystem writes would approve *changed content* to the
# same path for 5 minutes — which the slice explicitly forbids. These tests pin
# that security property so the "broad similar" fix cannot be introduced by
# accident.


def test_g4_changed_content_changes_payload_but_not_resource() -> None:
    from agentveil_mcp_proxy.classification import (
        extract_resource,
        sha256_jcs,
        sha256_text,
    )

    args_a = {"path": "config.py", "content": "FEATURE_X=true"}
    args_b = {"path": "config.py", "content": "FEATURE_X=true\n"}  # trailing-newline drift

    # Same path -> identical resource label and resource_hash.
    assert extract_resource(args_a) == extract_resource(args_b)
    assert sha256_text(extract_resource(args_a)) == sha256_text(extract_resource(args_b))

    # Different content -> different payload_hash. This is why an exact-scope
    # approval of args_a does NOT cover an args_b retry (security-correct).
    assert sha256_jcs(args_a) != sha256_jcs(args_b)


def test_g4_identical_retry_keeps_same_payload_hash() -> None:
    """Exact retry stability: a byte-identical retry hashes the same, so an
    exact grant would be reused (the in-session interactive retry path)."""
    from agentveil_mcp_proxy.classification import sha256_jcs

    args = {"path": "config.py", "content": "FEATURE_X=true"}
    assert sha256_jcs(args) == sha256_jcs(dict(args))


def test_g4_similar_grant_matching_is_payload_agnostic_by_design() -> None:
    """Guard: find_active_similar_grant does not constrain payload_hash, so
    enabling similar_5m for filesystem writes would cover changed content.
    This documents WHY similar_5m is rejected for the controlled write route."""
    import inspect

    from agentveil_mcp_proxy.evidence.store import ApprovalEvidenceStore

    src = inspect.getsource(ApprovalEvidenceStore.find_active_similar_grant)
    # The SQL match binds resource_hash but must not bind payload_hash.
    assert "resource_hash" in src
    assert "payload_hash" not in src, (
        "similar grant matching now references payload_hash; re-verify the G4 "
        "scope analysis before enabling similar_5m for filesystem writes"
    )
