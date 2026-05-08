"""
MCP Slice 4 — hosted-mode tests.

Covers three new behaviors added for the hosted HTTP deployment:
- AVP_MCP_READONLY=1 gates local/full tools at REGISTRATION, not call-time.
  Identity/write and action-control tools must not appear in the FastMCP
  tool registry.
- The HTTP ASGI app enforces Authorization: Bearer <AVP_MCP_TOKEN> on every
  path except /healthz, which returns 200 unauthenticated.
- main() with --http and an empty AVP_MCP_TOKEN refuses to start
  (fail-closed), raising SystemExit(2).

All tests skip when the optional `mcp` runtime isn't installed.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import os
import sys
from typing import Iterable

import pytest


def _mcp_runtime_available() -> bool:
    try:
        import mcp.server.fastmcp  # noqa: F401
        return True
    except ImportError:
        return False


requires_mcp = pytest.mark.skipif(
    not _mcp_runtime_available(),
    reason="MCP runtime not installed; install with pip install 'agentveil[mcp]'",
)


WRITE_TOOLS = {"register_agent", "submit_attestation", "publish_agent_card", "get_my_agent_info"}
ACTION_CONTROL_TOOLS = {
    "runtime_evaluate_action",
    "controlled_action",
    "get_approval_request",
    "approve_action",
    "deny_action",
    "execute_after_approval",
    "get_decision_receipt",
    "get_execution_receipt",
}
READ_TOOLS = {
    "check_reputation", "check_trust", "get_agent_info", "search_agents",
    "get_attestations_received", "get_protocol_stats", "verify_audit_chain",
    "get_audit_trail",
}
LOCAL_ONLY_TOOLS = WRITE_TOOLS | ACTION_CONTROL_TOOLS
ALL_TOOLS = READ_TOOLS | LOCAL_ONLY_TOOLS


def _reload_server_with_env(env_overrides: dict) -> object:
    """Reload agentveil_mcp.server with the given env overrides applied.

    Restores the prior env after returning. Returns the reloaded module.
    """
    prior = {k: os.environ.get(k) for k in env_overrides}
    try:
        for k, v in env_overrides.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        # Drop cached module so module-level flags are re-evaluated.
        for mod_name in ("agentveil_mcp.server", "agentveil_mcp"):
            sys.modules.pop(mod_name, None)
        import agentveil_mcp.server as s
        return s
    finally:
        for k, old in prior.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def _tool_names(server_mod) -> set[str]:
    """Ask the FastMCP instance for its registered tool names."""
    tools = asyncio.run(server_mod.mcp.list_tools())
    return {t.name for t in tools}


# ------------------------------------------------------------------
# Readonly tool-registration gate
# ------------------------------------------------------------------

@requires_mcp
def test_full_mode_registers_all_20_tools():
    s = _reload_server_with_env({"AVP_MCP_READONLY": None})
    try:
        names = _tool_names(s)
        assert names == ALL_TOOLS, f"expected all 20 tools, got {names}"
    finally:
        # Leave module state fresh-ish for next test by clearing it.
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_readonly_mode_registers_only_read_tools():
    s = _reload_server_with_env({"AVP_MCP_READONLY": "1"})
    try:
        names = _tool_names(s)
        assert names == READ_TOOLS, f"expected 8 read tools, got {names}"
        # Bright-line check: none of the local/full names must be present.
        for name in LOCAL_ONLY_TOOLS:
            assert name not in names, f"local/full tool {name!r} leaked into readonly mode"
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_readonly_write_callables_still_exist_as_plain_python():
    """Write tool functions remain module attributes, just not registered with FastMCP.

    This is intentional: it keeps the module importable and lets unit tests
    exercise the functions directly if needed. The registration gate is the
    protocol-surface contract, not Python reachability.
    """
    s = _reload_server_with_env({"AVP_MCP_READONLY": "1"})
    try:
        for name in WRITE_TOOLS:
            assert callable(getattr(s, name, None)), f"{name} missing as module attr"
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_runtime_evaluate_action_parses_delegation_receipt(monkeypatch):
    s = _reload_server_with_env({"AVP_MCP_READONLY": None})

    class FakeAgent:
        def __init__(self):
            self.call = None

        def runtime_evaluate(self, **kwargs):
            self.call = kwargs
            return {
                "audit_id": "audit-1",
                "decision": "WAITING_FOR_HUMAN_APPROVAL",
                "reason": "requires_principal_review",
            }

    fake = FakeAgent()
    monkeypatch.setattr(s, "_get_agent", lambda: fake)
    try:
        body = json.loads(s.runtime_evaluate_action(
            action="deploy.release",
            resource="service:api",
            environment="production",
            delegation_receipt='{"id":"delegation-1","scope":[{"type":"allowed_category","value":"deploy"}]}',
            amount=42.5,
            currency="USD",
        ))
        assert body["decision"] == "WAITING_FOR_HUMAN_APPROVAL"
        assert fake.call["delegation_receipt"]["id"] == "delegation-1"
        assert fake.call["amount"] == 42.5
        assert fake.call["currency"] == "USD"

        error = json.loads(s.runtime_evaluate_action(
            action="deploy.release",
            resource="service:api",
            environment="production",
            delegation_receipt='["not", "an", "object"]',
        ))
        assert error["type"] == "ValueError"
        assert "delegation_receipt" in error["error"]
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_execute_after_approval_uses_approval_id_and_parses_params(monkeypatch):
    s = _reload_server_with_env({"AVP_MCP_READONLY": None})

    class FakeOutcome:
        def __init__(self, data):
            self._data = data

        def to_dict(self):
            return dict(self._data)

    class FakeAgent:
        def __init__(self):
            self.call = None

        def execute_after_approval(self, **kwargs):
            self.call = kwargs
            return FakeOutcome({
                "status": "executed",
                "audit_id": kwargs["audit_id"],
                "approval_id": kwargs["approval_id"],
                "receipt_jcs": '{"receipt_id":"receipt-1"}',
            })

    fake = FakeAgent()
    monkeypatch.setattr(s, "_get_agent", lambda: fake)
    try:
        body = json.loads(s.execute_after_approval(
            audit_id="audit-1",
            approval_id="approval-1",
            action="deploy.release",
            resource="service:api",
            environment="production",
            params='{"ticket":"CHG-1"}',
        ))
        assert body["status"] == "executed"
        assert body["approval_id"] == "approval-1"
        assert fake.call["approval_id"] == "approval-1"
        assert "id" not in fake.call
        assert fake.call["params"] == {"ticket": "CHG-1"}
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_decision_receipt_preserves_raw_jcs_and_adds_sha256(monkeypatch):
    s = _reload_server_with_env({"AVP_MCP_READONLY": None})
    raw_jcs = '{"schema_version":"decision_receipt/2","decision":"ALLOW","nested":{"keep":"exact"}}'

    class FakeAgent:
        def get_decision_receipt(self, audit_id):
            assert audit_id == "audit-1"
            return raw_jcs

    monkeypatch.setattr(s, "_get_agent", lambda: FakeAgent())
    try:
        body = json.loads(s.get_decision_receipt("audit-1"))
        assert body["decision_receipt_jcs"] == raw_jcs
        assert body["sha256"] == hashlib.sha256(raw_jcs.encode("utf-8")).hexdigest()
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_approve_action_preserves_raw_jcs_and_adds_sha256(monkeypatch):
    s = _reload_server_with_env({"AVP_MCP_READONLY": None})
    raw_jcs = '{"schema_version":"human_approval_receipt/2","status":"APPROVED"}'

    class FakeAgent:
        def __init__(self):
            self.approval_id = None

        def approve(self, approval_id):
            self.approval_id = approval_id
            return raw_jcs

    fake = FakeAgent()
    monkeypatch.setattr(s, "_get_agent", lambda: fake)
    try:
        body = json.loads(s.approve_action("approval-1"))
        assert fake.approval_id == "approval-1"
        assert body["approval_receipt_jcs"] == raw_jcs
        assert body["sha256"] == hashlib.sha256(raw_jcs.encode("utf-8")).hexdigest()
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_deny_action_preserves_raw_jcs_and_default_reason_is_none(monkeypatch):
    s = _reload_server_with_env({"AVP_MCP_READONLY": None})
    raw_jcs = '{"schema_version":"human_approval_receipt/2","status":"DENIED"}'

    class FakeAgent:
        def __init__(self):
            self.call = None

        def deny(self, approval_id, reason=None):
            self.call = {"approval_id": approval_id, "reason": reason}
            return raw_jcs

    fake = FakeAgent()
    monkeypatch.setattr(s, "_get_agent", lambda: fake)
    try:
        body = json.loads(s.deny_action("approval-1"))
        assert fake.call == {"approval_id": "approval-1", "reason": None}
        assert body["denial_receipt_jcs"] == raw_jcs
        assert body["sha256"] == hashlib.sha256(raw_jcs.encode("utf-8")).hexdigest()
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_execution_receipt_preserves_raw_jcs_and_adds_sha256(monkeypatch):
    s = _reload_server_with_env({"AVP_MCP_READONLY": None})
    raw_jcs = '{"schema_version":"execution_receipt/2","receipt_id":"receipt-1"}'

    class FakeAgent:
        def __init__(self):
            self.receipt_id = None

        def get_execution_receipt(self, receipt_id):
            self.receipt_id = receipt_id
            return raw_jcs

    fake = FakeAgent()
    monkeypatch.setattr(s, "_get_agent", lambda: fake)
    try:
        body = json.loads(s.get_execution_receipt("receipt-1"))
        assert fake.receipt_id == "receipt-1"
        assert body["execution_receipt_jcs"] == raw_jcs
        assert body["sha256"] == hashlib.sha256(raw_jcs.encode("utf-8")).hexdigest()
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


# ------------------------------------------------------------------
# HTTP ASGI app: bearer-token middleware + health
# ------------------------------------------------------------------

@pytest.fixture
def http_app():
    s = _reload_server_with_env({"AVP_MCP_READONLY": "1"})
    app = s._build_http_app(token="test-token-123")
    try:
        yield app
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_healthz_is_unauthenticated_and_returns_200(http_app):
    from starlette.testclient import TestClient

    with TestClient(http_app) as client:
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


@requires_mcp
def test_mcp_path_without_token_returns_401(http_app):
    from starlette.testclient import TestClient

    with TestClient(http_app) as client:
        r = client.get("/mcp/")
        assert r.status_code == 401
        body = r.json()
        assert "unauthorized" in body.get("error", "").lower()
        # Standard challenge header so clients can prompt for credentials.
        assert "Bearer" in r.headers.get("WWW-Authenticate", "")


@requires_mcp
def test_mcp_path_with_wrong_token_returns_401(http_app):
    from starlette.testclient import TestClient

    with TestClient(http_app) as client:
        r = client.get("/mcp/", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401


@requires_mcp
def test_mcp_path_with_correct_token_passes_middleware(http_app):
    """With a valid token, middleware forwards to the MCP ASGI app.

    We don't care what MCP returns (could be 404/405/500-from-missing-lifespan,
    depending on the transport's internal state); we only care that the middleware
    did NOT short-circuit to 401 — i.e., the gate let the request through.

    The real MCP app needs a full ASGI lifespan to initialize its session
    manager; TestClient without `raise_server_exceptions=False` surfaces that
    lifecycle gap as a raised exception. We set it False so we observe the
    HTTP status the middleware produced, which is what this test is about.
    """
    from starlette.testclient import TestClient

    with TestClient(http_app, raise_server_exceptions=False) as client:
        r = client.get("/mcp/", headers={"Authorization": "Bearer test-token-123"})
        assert r.status_code != 401, f"valid token rejected; body: {r.text}"


# ------------------------------------------------------------------
# Fail-closed on empty token
# ------------------------------------------------------------------

@requires_mcp
def test_http_mode_with_empty_token_exits_nonzero(monkeypatch):
    """main() must refuse to start an HTTP server if AVP_MCP_TOKEN is empty."""
    monkeypatch.setenv("AVP_MCP_READONLY", "1")
    monkeypatch.setenv("AVP_MCP_TOKEN", "")
    monkeypatch.setattr(sys, "argv", ["agentveil-mcp", "--http", "--port", "0"])

    s = _reload_server_with_env({"AVP_MCP_READONLY": "1", "AVP_MCP_TOKEN": ""})
    try:
        with pytest.raises(SystemExit) as excinfo:
            s.main()
        assert excinfo.value.code == 2
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


# ------------------------------------------------------------------
# Transport security / allowed hosts (DNS-rebind protection)
# ------------------------------------------------------------------

@requires_mcp
def test_transport_security_defaults_to_localhost_only():
    """Unset AVP_MCP_ALLOWED_HOSTS → FastMCP's localhost-only default stays."""
    s = _reload_server_with_env({"AVP_MCP_ALLOWED_HOSTS": None, "AVP_MCP_ALLOWED_ORIGINS": None})
    try:
        ts = s.mcp.settings.transport_security
        assert ts.enable_dns_rebinding_protection is True
        # When we pass nothing, FastMCP fills its own localhost default.
        # The allowed_hosts list should NOT contain our public-domain marker.
        assert not any("agentveil.dev" in h for h in (ts.allowed_hosts or []))
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)


@requires_mcp
def test_transport_security_adds_public_host_when_env_set():
    """AVP_MCP_ALLOWED_HOSTS adds the listed hostnames without removing localhost."""
    s = _reload_server_with_env({
        "AVP_MCP_ALLOWED_HOSTS": "agentveil.dev,mcp.example.test",
        "AVP_MCP_ALLOWED_ORIGINS": "https://agentveil.dev",
    })
    try:
        ts = s.mcp.settings.transport_security
        assert ts.enable_dns_rebinding_protection is True
        hosts = ts.allowed_hosts or []
        origins = ts.allowed_origins or []
        # Configured hosts present
        assert "agentveil.dev" in hosts
        assert "mcp.example.test" in hosts
        # Localhost entries kept alongside (healthcheck + local dev must still work)
        assert any("127.0.0.1" in h for h in hosts)
        assert any("localhost" in h for h in hosts)
        # Origins
        assert "https://agentveil.dev" in origins
        assert any("localhost" in o for o in origins)
    finally:
        sys.modules.pop("agentveil_mcp.server", None)
        sys.modules.pop("agentveil_mcp", None)
