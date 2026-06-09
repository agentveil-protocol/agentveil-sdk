"""P10A.9 tests for the stable local Approval Center product path."""

from __future__ import annotations

import io
import json
import re
import sys
import threading
import time
from pathlib import Path

import httpx

from agentveil_mcp_proxy.approval import persistent as persistent_module
from agentveil_mcp_proxy.approval import ApprovalManager, ApprovalNotifier, ApprovalPrompt
from agentveil_mcp_proxy.approval.client import RemoteApprovalServer, resolve_approval_server
from agentveil_mcp_proxy.approval.persistent import (
    build_manifest_for_server,
    create_persistent_server,
    load_manifest,
    manifest_is_reachable,
    save_manifest,
)
from agentveil_mcp_proxy.approval.server import (
    INTERNAL_REGISTER_TOKEN_HEADER,
    ApprovalServer,
    approval_prompt_to_dict,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough
from agentveil_mcp_proxy.policy import ProxyConfig

from test_mcp_proxy_approval import (
    SECRET,
    NoopNotifier,
    _approval_downstream,
    _classification,
    _config,
    _get_csrf,
    _post_decision,
    _prompt_not_expired,
    _tool_call,
    _wait_for_status,
    _write_rule,
)


TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
STALE_HTML_FORBIDDEN_FRAGMENTS = (
    SECRET,
    "ghp_private",
    "private-repo",
    "session-abcdef",
    '"command":',
)


def _assert_stale_html_privacy_safe(text: str, *, session_token: str | None = None) -> None:
    lowered = text.lower()
    assert "<form" not in lowered
    assert 'name="csrf_token"' not in lowered
    if session_token:
        assert session_token not in text
    for fragment in STALE_HTML_FORBIDDEN_FRAGMENTS:
        assert fragment not in text


def _start_persistent_center(
    tmp_path: Path,
    *,
    config: ProxyConfig | None = None,
) -> tuple[ApprovalEvidenceStore, ApprovalServer, ApprovalManager, Path]:
    config = config or _config(policy_rule=_write_rule())
    proxy_dir = tmp_path / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = create_persistent_server(proxy_dir=proxy_dir, evidence_store=store)
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=config,
        client_id="github:approval-center",
        headless=True,
        wait_for_decision=False,
        notifier=NoopNotifier(),
    )
    save_manifest(proxy_dir, build_manifest_for_server(server))
    return store, server, manager, proxy_dir


def _run_manager(
    tmp_path: Path,
    *,
    proxy_dir: Path,
    config: ProxyConfig,
) -> tuple[ApprovalManager, ApprovalEvidenceStore, ApprovalServer | RemoteApprovalServer]:
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = resolve_approval_server(
        proxy_dir,
        evidence_store=store,
        fallback_factory=lambda: (_ for _ in ()).throw(AssertionError("expected persistent center")),
    )
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=config,
        client_id="github:pid:123",
        session_id="session-1234567890",
        headless=False,
        wait_for_decision=False,
        notifier=NoopNotifier(),
        browser_open=lambda _url: False,
    )
    return manager, store, server


def test_persistent_manifest_is_reachable(tmp_path):
    store, server, _manager, proxy_dir = _start_persistent_center(tmp_path)
    try:
        manifest = load_manifest(proxy_dir)
        assert manifest is not None
        assert manifest_is_reachable(manifest)
        assert manifest.port == server.port
        assert manifest.session_token == server.session_token
        assert manifest.internal_register_token == server.internal_register_token
    finally:
        server.stop()
        store.close()


def test_windows_process_alive_check_does_not_send_signal(monkeypatch):
    def fail_kill(_pid, _signal):
        raise AssertionError("Windows process check must not call os.kill(pid, 0)")

    monkeypatch.setattr(persistent_module.os, "name", "nt")
    monkeypatch.setattr(persistent_module.os, "kill", fail_kill)
    monkeypatch.setattr(
        persistent_module,
        "_windows_process_alive",
        lambda pid: pid == 12345,
    )

    assert persistent_module.is_process_alive(12345)
    assert not persistent_module.is_process_alive(54321)


def test_manifest_health_check_uses_direct_loopback_socket(tmp_path, monkeypatch):
    store, server, _manager, proxy_dir = _start_persistent_center(tmp_path)

    original_create_connection = persistent_module.socket.create_connection
    seen_addresses: list[tuple[str, int]] = []

    def direct_loopback_connection(address, *args, **kwargs):
        seen_addresses.append(address)
        return original_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(
        persistent_module.socket,
        "create_connection",
        direct_loopback_connection,
    )
    try:
        manifest = load_manifest(proxy_dir)
        assert manifest is not None
        assert manifest_is_reachable(manifest)
        assert seen_addresses == [("127.0.0.1", server.port)]
    finally:
        server.stop()
        store.close()


def test_public_session_token_cannot_register_prompts(tmp_path):
    store, server, _manager, proxy_dir = _start_persistent_center(tmp_path)
    manifest = load_manifest(proxy_dir)
    assert manifest is not None
    fake_prompt = approval_prompt_to_dict(_prompt_not_expired("fake-inject"))
    try:
        legacy_url = (
            f"{server.base_url}/approval/{server.session_token}/internal/register"
        )
        assert httpx.post(legacy_url, json=fake_prompt).status_code == 403
        assert httpx.post(f"{server.base_url}/internal/register", json=fake_prompt).status_code == 403
        assert httpx.post(
            f"{server.base_url}/internal/register",
            json=fake_prompt,
            headers={INTERNAL_REGISTER_TOKEN_HEADER: server.session_token},
        ).status_code == 403
        assert server.pending_prompts() == []
        assert manifest.internal_register_token not in legacy_url
    finally:
        server.stop()
        store.close()


def test_run_reuses_persistent_approval_center_url(tmp_path):
    config = _config(policy_rule=_write_rule(), ui_open_mode="terminal")
    persistent_store, persistent_server, _persistent_manager, proxy_dir = _start_persistent_center(
        tmp_path,
        config=config,
    )
    run_manager, run_store, run_server = _run_manager(tmp_path, proxy_dir=proxy_dir, config=config)
    try:
        outcome = run_manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert outcome.approval_url is not None
        assert outcome.approval_url.startswith(persistent_server.base_url)
        assert persistent_server.session_token in outcome.approval_url
        manifest = load_manifest(proxy_dir)
        assert manifest is not None
        assert manifest.internal_register_token not in outcome.approval_url
        assert isinstance(run_server, RemoteApprovalServer)
        assert persistent_server.pending_prompts()
    finally:
        run_store.close()
        persistent_server.stop()
        persistent_store.close()


def test_persistent_approve_retry_reaches_downstream(tmp_path):
    config = _config(policy_rule=_write_rule())
    persistent_store, persistent_server, _persistent_manager, proxy_dir = _start_persistent_center(
        tmp_path,
        config=config,
    )
    run_manager, run_store, run_server = _run_manager(tmp_path, proxy_dir=proxy_dir, config=config)
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_approval_downstream(tmp_path, log_path))),
            name="github",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="github"),
        approval_manager=run_manager,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_tool_call())
        assert first[0]["error"]["data"]["status"] == "approval_required"
        deadline = time.monotonic() + 2
        while not persistent_server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = persistent_server.pending_prompts()[0]
        approval_url = persistent_server.approval_url(prompt.request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, approval_url)
            assert _post_decision(client, approval_url, decision="approve", csrf=csrf).status_code == 200
        retry = passthrough.handle_client_line(_tool_call())
        assert "result" in retry[0]
        assert retry[0]["result"]["content"][0]["text"] == "approved"
        assert persistent_server.pending_prompts() == []
        parent = run_store.get_pending(prompt.request_id)
        assert parent is not None
        assert parent.status == ApprovalStatus.APPROVED.value
    finally:
        passthrough.stop()
        run_store.close()
        persistent_server.stop()
        persistent_store.close()


def test_persistent_deny_blocks_downstream(tmp_path):
    config = _config(policy_rule=_write_rule())
    persistent_store, persistent_server, _persistent_manager, proxy_dir = _start_persistent_center(
        tmp_path,
        config=config,
    )
    run_manager, run_store, _run_server = _run_manager(tmp_path, proxy_dir=proxy_dir, config=config)
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_approval_downstream(tmp_path, log_path))),
            name="github",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="github"),
        approval_manager=run_manager,
    )
    passthrough.start()
    try:
        first = passthrough.handle_client_line(_tool_call())
        assert first[0]["error"]["data"]["status"] == "approval_required"
        deadline = time.monotonic() + 2
        while not persistent_server.pending_prompts() and time.monotonic() < deadline:
            time.sleep(0.01)
        prompt = persistent_server.pending_prompts()[0]
        approval_url = persistent_server.approval_url(prompt.request_id)
        with httpx.Client() as client:
            csrf = _get_csrf(client, approval_url)
            assert _post_decision(client, approval_url, decision="deny", csrf=csrf).status_code == 200
        retry = passthrough.handle_client_line(_tool_call())
        assert "error" in retry[0]
        assert "tools/call" not in log_path.read_text(encoding="utf-8")
        parent = run_store.get_pending(prompt.request_id)
        assert parent is not None
        assert parent.status == ApprovalStatus.DENIED.value
    finally:
        passthrough.stop()
        run_store.close()
        persistent_server.stop()
        persistent_store.close()


def test_old_approved_url_after_run_exit_uses_evidence_terminal_page(tmp_path):
    config = _config(policy_rule=_write_rule())
    persistent_store, persistent_server, _persistent_manager, proxy_dir = _start_persistent_center(
        tmp_path,
        config=config,
    )
    run_manager, run_store, _run_server = _run_manager(tmp_path, proxy_dir=proxy_dir, config=config)
    try:
        outcome = run_manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert outcome.approval_url is not None
        approval_url = outcome.approval_url
        request_id = outcome.request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, approval_url)
            assert _post_decision(client, approval_url, decision="approve", csrf=csrf).status_code == 200
        _wait_for_status(run_store, request_id, ApprovalStatus.APPROVED.value)
    finally:
        run_store.close()

    try:
        with httpx.Client() as client:
            stale = client.get(approval_url)
        assert stale.status_code == 410
        assert "Already decided" in stale.text
        assert "Approved" in stale.text
        _assert_stale_html_privacy_safe(
            stale.text,
            session_token=persistent_server.session_token,
        )
    finally:
        persistent_server.stop()
        persistent_store.close()


def test_old_denied_url_after_run_exit_uses_evidence_terminal_page(tmp_path):
    config = _config(policy_rule=_write_rule())
    persistent_store, persistent_server, _persistent_manager, proxy_dir = _start_persistent_center(
        tmp_path,
        config=config,
    )
    run_manager, run_store, _run_server = _run_manager(tmp_path, proxy_dir=proxy_dir, config=config)
    try:
        outcome = run_manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        assert outcome.approval_url is not None
        approval_url = outcome.approval_url
        request_id = outcome.request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, approval_url)
            assert _post_decision(client, approval_url, decision="deny", csrf=csrf).status_code == 200
        _wait_for_status(run_store, request_id, ApprovalStatus.DENIED.value)
    finally:
        run_store.close()

    try:
        with httpx.Client() as client:
            stale = client.get(approval_url)
        assert stale.status_code == 410
        assert "Already decided" in stale.text
        assert "Denied" in stale.text
        _assert_stale_html_privacy_safe(
            stale.text,
            session_token=persistent_server.session_token,
        )
    finally:
        persistent_server.stop()
        persistent_store.close()


def test_evidence_backed_terminal_snapshot_without_in_memory_prompt(tmp_path):
    config = _config(policy_rule=_write_rule())
    proxy_dir = tmp_path / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = ApprovalServer(evidence_store=store)
    server.start()
    try:
        manager = ApprovalManager(
            evidence_store=store,
            approval_server=server,
            config=config,
            client_id="github:pid:1",
            headless=False,
            wait_for_decision=False,
            notifier=NoopNotifier(),
            browser_open=lambda _url: False,
        )
        outcome = manager.request_approval(
            _classification(config),
            reason="local_approval_required",
        )
        request_id = outcome.request_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(request_id))
            assert _post_decision(
                client,
                server.approval_url(request_id),
                decision="approve",
                csrf=csrf,
            ).status_code == 200
        _wait_for_status(store, request_id, ApprovalStatus.APPROVED.value)
        server.stop()
        server = ApprovalServer(
            port=0,
            session_token="stable-session-token",
            evidence_store=store,
        )
        server.start()
        snapshot = server.stale_terminal_snapshot_for(request_id)
        assert snapshot is not None
        assert snapshot.state == "already_decided_approve"
        response = httpx.get(server.approval_url(request_id))
        assert response.status_code == 410
        assert "Approved" in response.text
        _assert_stale_html_privacy_safe(response.text, session_token=server.session_token)
    finally:
        server.stop()
        store.close()
