"""Declared tool surface and P10A.1 action-gate tests for the MCP passthrough.

These exercise handle_client_line directly with a stubbed downstream so the
tool-surface and declared-vs-observed downstream surface checks (which run
before schema/classification/policy/Runtime Gate/downstream) can be observed
in isolation.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Mapping

from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.evidence.observability import parse_action_gate_metadata
from agentveil_mcp_proxy.passthrough import (
    DownstreamConfig,
    JSONRPC_POLICY_BLOCKED,
    McpPassthrough,
)
from agentveil_mcp_proxy.policy import ProxyConfig

from mcp_fake_downstream import seed_tool_schemas, tool_entry


SECRET_ARG = "SUPER_SECRET_ARGUMENT_VALUE"


def _config(*, mode: str, allow: Any = None) -> ProxyConfig:
    tool_surface: dict[str, Any] = {"mode": mode}
    if allow is not None:
        tool_surface["allow"] = allow
    payload = {
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "tool-surface-proxy",
            "trusted_signer_dids": ["did:key:zToolSurfaceTest"],
        },
        "mode": "protect",
        "privacy": {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "approval": {},
        # Local policy ALLOW isolates the tool-surface check from policy/approval.
        "policy": {
            "id": "tool-surface-test",
            "policy_schema_version": 1,
            "default_decision": "allow",
            "default_risk_class": "read",
            "rules": [],
        },
        "tool_surface": tool_surface,
        "downstream": {},
    }
    return ProxyConfig.from_dict(payload)


class _RecordingApprovalManager:
    def __init__(self, store: ApprovalEvidenceStore) -> None:
        self.evidence_store = store
        self.session_id = "session-action-gate"
        self.client_id = "cursor:session-action-gate"


class _RecordingPassthrough(McpPassthrough):
    """Passthrough that records downstream forwards without a real subprocess."""

    def __init__(
        self,
        config: ProxyConfig,
        *,
        evidence_store: ApprovalEvidenceStore | None = None,
    ) -> None:
        classifier = ToolCallClassifier(config, server_name="srv")
        super().__init__(
            DownstreamConfig(command=sys.executable, args=(), name="srv"),
            classifier=classifier,
        )
        self.forwarded: list[Mapping[str, Any]] = []
        self.policy_calls = 0
        if evidence_store is not None:
            self.approval_manager = _RecordingApprovalManager(evidence_store)
        seed_tool_schemas(
            self,
            [
                tool_entry("get_issue"),
                tool_entry("delete_repo"),
                tool_entry("exfiltrate"),
            ],
        )

    def _send_downstream(self, message: Mapping[str, Any]) -> None:
        self.forwarded.append(message)

    def _wait_downstream_response(self, expected_id: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": expected_id, "result": {"ok": True}}

    def _policy_error_response(self, classification, request_id, *, in_flight_approval=None):
        self.policy_calls += 1
        return super()._policy_error_response(
            classification,
            request_id,
            in_flight_approval=in_flight_approval,
        )


def _tool_call(tool: str) -> str:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"secret": SECRET_ARG}},
    })


def test_off_mode_forwards_undeclared_without_event():
    proxy = _RecordingPassthrough(_config(mode="off"))

    responses = proxy.handle_client_line(_tool_call("get_issue"))

    assert [m["params"]["name"] for m in proxy.forwarded] == ["get_issue"]
    assert responses[0].get("result") == {"ok": True}
    assert proxy.security_events == ()


def test_observe_mode_blocks_extra_downstream_tool_before_policy(tmp_path):
    """P10A.1 fail-closes advertised-but-undeclared tools even in observe mode."""

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    try:
        proxy = _RecordingPassthrough(
            _config(mode="observe", allow=["list_*"]),
            evidence_store=store,
        )

        responses = proxy.handle_client_line(_tool_call("delete_repo"))

        assert proxy.forwarded == []
        assert proxy.policy_calls == 0
        error = responses[0]["error"]
        assert error["code"] == JSONRPC_POLICY_BLOCKED
        assert error["data"] == {
            # claim-check: allow "blocked" as JSON-RPC status vocabulary.
            "status": "blocked",
            "reason": "extra_undeclared_downstream_tool",
        }
        extra_events = [
            event for event in proxy.security_events
            if event.get("type") == "action_gate_extra_downstream_tool"
        ]
        assert len(extra_events) == 1
        records = store.list_records()
        assert len(records) == 1
        # claim-check: allow BLOCKED as stored approval-status enum value.
        assert records[0].status == ApprovalStatus.BLOCKED.value
        assert records[0].error_class == "extra_undeclared_downstream_tool"
        metadata = parse_action_gate_metadata(records[0])
        assert metadata is not None
        assert metadata["declared_tool_surface"] == ["list_*"]
        assert "delete_repo" in metadata["extra_undeclared_tools"]
        assert metadata["action_family"] == "delete"
        assert metadata["authority"] == "operator_declared_surface"
        assert metadata["escalation_trigger"] == "extra_undeclared_downstream_tool"
        assert metadata["execution_status"] == "not_reached"
        assert SECRET_ARG not in json.dumps(metadata)
        assert SECRET_ARG not in json.dumps(responses[0])
        assert SECRET_ARG not in json.dumps(list(proxy.security_events))
    finally:
        store.close()


def test_declared_downstream_tool_passes_action_gate():
    proxy = _RecordingPassthrough(_config(mode="enforce", allow=["get_*"]))

    responses = proxy.handle_client_line(_tool_call("get_issue"))

    assert [m["params"]["name"] for m in proxy.forwarded] == ["get_issue"]
    assert responses[0].get("result") == {"ok": True}
    assert not any(
        event.get("type") == "action_gate_extra_downstream_tool"
        for event in proxy.security_events
    )


def test_surface_drift_quarantines_extra_downstream_tools():
    proxy = _RecordingPassthrough(_config(mode="enforce", allow=["get_*"]))

    quarantined = proxy._sync_downstream_surface_quarantine()

    assert "delete_repo" in quarantined
    assert "exfiltrate" in quarantined
    assert "get_issue" not in quarantined
    assert any(
        event.get("type") == "action_gate_surface_drift"
        for event in proxy.security_events
    )


def test_enforce_mode_blocks_undeclared_without_forwarding():
    proxy = _RecordingPassthrough(_config(mode="enforce", allow=["list_*"]))

    responses = proxy.handle_client_line(_tool_call("delete_repo"))

    # Not forwarded downstream.
    assert proxy.forwarded == []
    error = responses[0]["error"]
    assert error["code"] == JSONRPC_POLICY_BLOCKED
    assert error["data"] == {
        # claim-check: allow "blocked" as JSON-RPC status vocabulary.
        "status": "blocked",
        "reason": "extra_undeclared_downstream_tool",
    }
    assert proxy.security_events[0] == {
        "type": "action_gate_extra_downstream_tool",
        "action": "blocked_pre_approval",
        "reason": "extra_undeclared_downstream_tool",
        "tool": "delete_repo",
        "declared_surface_hash": proxy.security_events[0]["declared_surface_hash"],
        "observed_surface_hash": proxy.security_events[0]["observed_surface_hash"],
    }


def test_enforce_allows_declared_exact_tool():
    proxy = _RecordingPassthrough(_config(mode="enforce", allow=["get_issue"]))

    responses = proxy.handle_client_line(_tool_call("get_issue"))

    assert [m["params"]["name"] for m in proxy.forwarded] == ["get_issue"]
    assert responses[0].get("result") == {"ok": True}
    assert proxy.security_events == ()


def test_enforce_allows_declared_glob_tool():
    proxy = _RecordingPassthrough(_config(mode="enforce", allow=["get_*"]))

    responses = proxy.handle_client_line(_tool_call("get_issue"))

    assert [m["params"]["name"] for m in proxy.forwarded] == ["get_issue"]
    assert responses[0].get("result") == {"ok": True}
    assert proxy.security_events == ()


def test_non_tools_call_passes_through_under_enforce():
    proxy = _RecordingPassthrough(_config(mode="enforce", allow=[]))

    responses = proxy.handle_client_line(
        json.dumps({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list"})
    )

    # Non-tools/call protocol messages are never surface-checked.  # claim-check: allow "never" describes protocol boundary.
    assert [m.get("method") for m in proxy.forwarded] == ["tools/list"]
    assert responses[0].get("result") == {"ok": True}
    assert proxy.security_events == ()


def test_enforce_block_does_not_leak_raw_arguments():
    proxy = _RecordingPassthrough(_config(mode="enforce", allow=[]))

    responses = proxy.handle_client_line(_tool_call("exfiltrate"))

    assert proxy.forwarded == []
    # Neither the blocked response nor the security event carries raw arguments.  # claim-check: allow "blocked" is expected error vocabulary.
    assert SECRET_ARG not in json.dumps(responses[0])
    assert SECRET_ARG not in json.dumps(list(proxy.security_events))
    # Only the tool name is recorded.
    assert proxy.security_events[0]["tool"] == "exfiltrate"


# ---------------------------------------------------------------------------
# Bug 6 regression: deny tools/call for tool names absent from downstream
# tools/list. Evidence: these tests assert the pre-approval error and event.
# These run with operator-surface mode OFF so the operator-declared B9 gate
# above does not fire and isolate the downstream-advertised gate.
# ---------------------------------------------------------------------------


def test_unknown_tool_call_denied_before_approval():
    """A tool name absent from downstream tools/list is denied before approval."""

    proxy = _RecordingPassthrough(_config(mode="off"))

    responses = proxy.handle_client_line(_tool_call("totally_unknown_tool"))

    # Evidence: no downstream forwarding occurs for this denied request.
    assert proxy.forwarded == []
    error = responses[0]["error"]
    assert error["code"] == JSONRPC_POLICY_BLOCKED
    assert error["data"] == {"status": "blocked", "reason": "unknown_tool"}  # claim-check: allow "blocked" is expected JSON-RPC error data vocabulary.

    # Security evidence carries the tool-identity classification and records
    # only the tool name, not raw arguments.
    assert proxy.security_events == ({
        "type": "unknown_tool_call",
        "action": "blocked_pre_approval",  # claim-check: allow "blocked_pre_approval" is the existing event action vocabulary for pre-approval denies.
        "reason": "unknown_tool",
        "risk_class": "tool_identity_violation",
        "tool": "totally_unknown_tool",
    },)
    assert SECRET_ARG not in json.dumps(responses[0])
    assert SECRET_ARG not in json.dumps(list(proxy.security_events))


def test_spoofed_tool_name_denied_before_approval():
    """A plausible-looking tool name that was NOT advertised by this
    downstream is denied, even if a different downstream might
    legitimately advertise the same name."""

    proxy = _RecordingPassthrough(_config(mode="off"))

    fs_responses = proxy.handle_client_line(_tool_call("filesystem.write_file"))
    shell_responses = proxy.handle_client_line(_tool_call("shell"))

    assert proxy.forwarded == []

    fs_error = fs_responses[0]["error"]
    assert fs_error["code"] == JSONRPC_POLICY_BLOCKED
    assert fs_error["data"] == {"status": "blocked", "reason": "unknown_tool"}  # claim-check: allow "blocked" is JSON-RPC error data vocabulary.

    shell_error = shell_responses[0]["error"]
    assert shell_error["code"] == JSONRPC_POLICY_BLOCKED
    assert shell_error["data"] == {"status": "blocked", "reason": "unknown_tool"}  # claim-check: allow "blocked" is JSON-RPC error data vocabulary.

    recorded = [
        (e.get("type"), e.get("reason"), e.get("risk_class"), e.get("tool"))
        for e in proxy.security_events
    ]
    assert recorded == [
        ("unknown_tool_call", "unknown_tool", "tool_identity_violation", "filesystem.write_file"),
        ("unknown_tool_call", "unknown_tool", "tool_identity_violation", "shell"),
    ]
    assert SECRET_ARG not in json.dumps(list(proxy.security_events))


def test_advertised_tool_passes_unknown_gate_and_reaches_downstream():
    """A tool the downstream advertised via tools/list must pass the
    unknown-tool gate and reach the existing downstream-forward path."""

    proxy = _RecordingPassthrough(_config(mode="off"))

    responses = proxy.handle_client_line(_tool_call("get_issue"))

    # Forwarded downstream and the existing stubbed result reaches the client.
    assert [m["params"]["name"] for m in proxy.forwarded] == ["get_issue"]
    assert responses[0].get("result") == {"ok": True}
    # No unknown-tool event for an advertised tool name.
    assert not any(
        e.get("type") == "unknown_tool_call" for e in proxy.security_events
    )
