"""B9 declared tool surface enforcement tests for the MCP passthrough.

These exercise handle_client_line directly with a stubbed downstream so the
tool-surface check (which runs before schema/classification/policy/Runtime
Gate/downstream) can be observed in isolation.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Mapping

from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.passthrough import (
    DownstreamConfig,
    JSONRPC_POLICY_BLOCKED,
    McpPassthrough,
)
from agentveil_mcp_proxy.policy import ProxyConfig


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


class _RecordingPassthrough(McpPassthrough):
    """Passthrough that records downstream forwards without a real subprocess."""

    def __init__(self, config: ProxyConfig) -> None:
        classifier = ToolCallClassifier(config, server_name="srv")
        super().__init__(
            DownstreamConfig(command=sys.executable, args=(), name="srv"),
            classifier=classifier,
        )
        self.forwarded: list[Mapping[str, Any]] = []

    def _send_downstream(self, message: Mapping[str, Any]) -> None:
        self.forwarded.append(message)

    def _wait_downstream_response(self, expected_id: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": expected_id, "result": {"ok": True}}


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


def test_observe_mode_forwards_undeclared_and_records_event():
    proxy = _RecordingPassthrough(_config(mode="observe", allow=["list_*"]))

    responses = proxy.handle_client_line(_tool_call("get_issue"))

    # observe forwards downstream...
    assert [m["params"]["name"] for m in proxy.forwarded] == ["get_issue"]
    assert responses[0].get("result") == {"ok": True}
    # ...and records a sanitized security event.
    assert proxy.security_events == ({
        "type": "undeclared_tool_call",
        "action": "observed",
        "reason": "undeclared_tool",
        "tool": "get_issue",
    },)


def test_enforce_mode_blocks_undeclared_without_forwarding():
    proxy = _RecordingPassthrough(_config(mode="enforce", allow=["list_*"]))

    responses = proxy.handle_client_line(_tool_call("delete_repo"))

    # Not forwarded downstream.
    assert proxy.forwarded == []
    error = responses[0]["error"]
    assert error["code"] == JSONRPC_POLICY_BLOCKED
    assert error["data"] == {"status": "blocked", "reason": "undeclared_tool"}  # claim-check: allow "blocked" is expected error data.
    assert proxy.security_events == ({
        "type": "undeclared_tool_call",
        "action": "blocked",  # claim-check: allow "blocked" is expected event vocabulary.
        "reason": "undeclared_tool",
        "tool": "delete_repo",
    },)


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
