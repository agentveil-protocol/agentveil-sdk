"""P9b multi-instance isolation coverage for MCP proxy approval stacks."""

from __future__ import annotations

from dataclasses import dataclass
import io
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any

import httpx

from agentveil_mcp_proxy.approval import ApprovalManager, ApprovalPrompt, ApprovalServer
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceStore,
    ApprovalStatus,
    EVIDENCE_SCHEMA_VERSION,
    PendingApproval,
)
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough
from agentveil_mcp_proxy.policy import ProxyConfig


def _config() -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
        },
        "mode": "protect",
        "privacy": {
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
        "approval": {"approval_timeout_seconds": 30, "on_timeout": "deny"},
        "policy": {
            "id": "multi-instance-test",
            "policy_schema_version": 1,
            "default_decision": "approval",
            "default_risk_class": "write",
            "rules": [],
        },
        "downstream": {},
    })


def _classification(config: ProxyConfig | None = None, *, nonce: str = "one"):
    config = config or _config()
    return ToolCallClassifier(config, server_name="github").classify(
        tool="create_issue",
        arguments={"owner": "acme", "repo": "private-repo", "title": nonce},
    )


def _prompt(request_id: str) -> ApprovalPrompt:
    return ApprovalPrompt(
        request_id=request_id,
        client_id="cursor:pid:1",
        session_id="session-1",
        downstream_server="github",
        tool_name="create_issue",
        action_display="redacted",
        action_details=None,
        resource_display="sha256:" + "a" * 64,
        resource_details=None,
        risk_class="write",
        payload_hash="sha256:" + "b" * 64,
        policy_rule_id="default",
        reason="local_approval_required",
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        csrf_token=f"csrf-{request_id}",
    )


def _pending_record(request_id: str) -> PendingApproval:
    return PendingApproval(
        request_id=request_id,
        session_id="session",
        client_id="client",
        downstream_server="github",
        tool_name="create_issue",
        action_class="redacted",
        risk_class="write",
        resource_hash="sha256:" + "a" * 64,
        payload_hash="sha256:" + "b" * 64,
        policy_id="multi-instance-test",
        policy_rule_id="default",
        policy_context_hash="c" * 64,
        status=ApprovalStatus.PENDING.value,
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
    )


def _post_decision(server: ApprovalServer, prompt: ApprovalPrompt, *, decision: str) -> httpx.Response:
    url = server.approval_url(prompt.request_id)
    with httpx.Client() as client:
        get_response = client.get(url)
        assert get_response.status_code == 200
        return client.post(url, data={
            "decision": decision,
            "csrf_token": prompt.csrf_token,
            "approval_scope": "exact",
        })


@dataclass
class _Stack:
    manager: ApprovalManager
    store: ApprovalEvidenceStore
    server: ApprovalServer
    passthrough: McpPassthrough

    def close(self) -> None:
        self.server.stop()
        self.store.close()


def _stack(tmp_path: Path, name: str) -> _Stack:
    store = ApprovalEvidenceStore(tmp_path / f"{name}.sqlite")
    server = ApprovalServer()
    server.start()
    config = _config()
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=config,
        client_id=f"{name}:pid:123",
        session_id=f"{name}:session",
        cli_out=io.StringIO(),
        browser_open=lambda _url: True,
    )
    passthrough = McpPassthrough(
        DownstreamConfig(command="unused", args=(), name=name),
        classifier=ToolCallClassifier(config, server_name="github"),
        approval_manager=manager,
    )
    return _Stack(manager=manager, store=store, server=server, passthrough=passthrough)


def test_two_passthrough_instances_have_distinct_approval_server_ports(tmp_path):
    stack_a = _stack(tmp_path, "claude")
    stack_b = _stack(tmp_path, "cursor")
    try:
        assert stack_a.passthrough.approval_manager is stack_a.manager
        assert stack_b.passthrough.approval_manager is stack_b.manager
        assert stack_a.server.host == "127.0.0.1"
        assert stack_b.server.host == "127.0.0.1"
        assert stack_a.server.port != stack_b.server.port
    finally:
        stack_a.close()
        stack_b.close()


def test_two_evidence_stores_at_distinct_paths_are_independent(tmp_path):
    store_a = ApprovalEvidenceStore(tmp_path / "claude.sqlite")
    store_b = ApprovalEvidenceStore(tmp_path / "cursor.sqlite")
    try:
        store_a.write_pending(_pending_record("request-a"))

        assert store_a.get_pending("request-a") is not None
        assert store_b.get_pending("request-a") is None
        assert store_a.db_path != store_b.db_path
        for path in (store_a.db_path, store_b.db_path):
            conn = sqlite3.connect(str(path))
            try:
                version = conn.execute("SELECT version FROM evidence_schema_version").fetchone()[0]
            finally:
                conn.close()
            assert version == EVIDENCE_SCHEMA_VERSION
    finally:
        store_a.close()
        store_b.close()


def test_two_managers_approval_decision_does_not_cross_contaminate(tmp_path):
    stack_a = _stack(tmp_path, "claude")
    stack_b = _stack(tmp_path, "cursor")
    outcomes: dict[str, Any] = {}

    def request(stack: _Stack, key: str, nonce: str) -> None:
        outcomes[key] = stack.manager.request_approval(
            _classification(nonce=nonce),
            reason="local_approval_required",
        )

    thread_a = threading.Thread(target=request, args=(stack_a, "a", "from-a"), daemon=True)
    thread_b = threading.Thread(target=request, args=(stack_b, "b", "from-b"), daemon=True)
    thread_a.start()
    thread_b.start()
    try:
        deadline = time.monotonic() + 2
        while (
            (not stack_a.server.pending_prompts() or not stack_b.server.pending_prompts())
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        prompt_a = stack_a.server.pending_prompts()[0]
        prompt_b = stack_b.server.pending_prompts()[0]

        response_a = _post_decision(stack_a.server, prompt_a, decision="approve")
        assert response_a.status_code == 200
        thread_a.join(timeout=2)

        assert "a" in outcomes
        assert "b" not in outcomes
        assert stack_a.store.get_pending(outcomes["a"].request_id).status == ApprovalStatus.APPROVED.value
        assert stack_b.store.get_pending(prompt_b.request_id).status == ApprovalStatus.PENDING.value
        assert stack_b.server.pending_prompts()[0].request_id == prompt_b.request_id

        response_b = _post_decision(stack_b.server, prompt_b, decision="deny")
        assert response_b.status_code == 200
        thread_b.join(timeout=2)
        assert outcomes["b"].status == ApprovalStatus.DENIED.value
    finally:
        stack_a.close()
        stack_b.close()
