"""P5 tests for MCP proxy Runtime Gate integration."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import time
from unittest.mock import MagicMock, patch

import base58
import httpx
import jcs
from nacl.signing import SigningKey

from agentveil.agent import AVPAgent
from agentveil.delegation import _public_key_to_did
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.passthrough import (
    DownstreamConfig,
    JSONRPC_APPROVAL_REQUIRED,
    JSONRPC_POLICY_BLOCKED,
    JSONRPC_RUNTIME_GATE_UNAVAILABLE,
    JSONRPC_RUNTIME_GATE_UNTRUSTED,
    McpPassthrough,
)
from agentveil_mcp_proxy.policy import ProxyConfig, builtin_policy_pack
from agentveil_mcp_proxy.runtime_gate import (
    RuntimeGateClient,
    RuntimeGateDecision,
    RuntimeGateUnavailableError,
)


BACKEND_SEED = bytes.fromhex("11" * 32)
OTHER_BACKEND_SEED = bytes.fromhex("22" * 32)
AGENT_SEED = bytes.fromhex("44" * 32)
BACKEND_DID = _public_key_to_did(bytes(SigningKey(BACKEND_SEED).verify_key))
AGENT_DID = _public_key_to_did(bytes(SigningKey(AGENT_SEED).verify_key))
SECRET = "SECRET_PROJECT_ALPHA"
AUDIT_ID = "urn:uuid:11111111-1111-4111-8111-111111111111"


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _policy_to_dict(name: str) -> dict:
    policy = builtin_policy_pack(name)
    rules = []
    for rule in policy.rules:
        match = {}
        if rule.match.server:
            match["server"] = list(rule.match.server)
        if rule.match.tool:
            match["tool"] = list(rule.match.tool)
        item = {
            "id": rule.id,
            "source": rule.source,
            "decision": rule.decision.value,
            "match": match,
        }
        if rule.risk_class is not None:
            item["risk_class"] = rule.risk_class.value
        rules.append(item)
    return {
        "id": policy.id,
        "policy_schema_version": policy.policy_schema_version,
        "default_decision": policy.default_decision.value,
        "default_risk_class": policy.default_risk_class.value,
        "rules": rules,
    }


def _config(*, privacy: dict | None = None, fallback: dict | None = None) -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": [BACKEND_DID],
        },
        "mode": "protect",
        "privacy": privacy or {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "fallback": fallback or {
            "read": "allow",
            "write": "approval",
            "destructive": "block",
            "production": "block",
            "financial": "block",
            "unknown": "approval",
        },
        "approval": {},
        "policy": _policy_to_dict("github"),
        "downstream": {},
    })


def _classification(config: ProxyConfig):
    return ToolCallClassifier(config, server_name="github").classify(
        tool="create_issue",
        arguments={
            "owner": "acme",
            "repo": "private-repo",
            "title": SECRET,
            "prompt": "summarize confidential plan",
            "output": "private model output",
            "token": "ghp_secret_token",
            "source_code": "print('do not upload')",
        },
    )


def _sign_jcs(body: dict, seed: bytes = BACKEND_SEED) -> str:
    key = SigningKey(seed)
    signer_did = _public_key_to_did(bytes(key.verify_key))
    signature = key.sign(jcs.canonicalize(body)).signature
    signed = {
        **body,
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": f"{signer_did}#{signer_did[len('did:key:'):]}",
            "proofValue": "z" + base58.b58encode(signature).decode("ascii"),
        },
    }
    return jcs.canonicalize(signed).decode("utf-8")


def _decision_receipt(
    request: dict,
    *,
    decision: str = "ALLOW",
    approval_id: str | None = None,
    seed: bytes = BACKEND_SEED,
    backend_risk_class: str = "unknown",
    backend_policy_context_hash: str = "b" * 64,
) -> str:
    body = {
        "schema_version": "decision_receipt/2",
        "audit_id": AUDIT_ID,
        "agent_did": AGENT_DID,
        "action": request["action"],
        "resource": request["resource"],
        "environment": request["environment"],
        "decision": decision,
        "payload_hash": request["payload_hash"],
        "risk_class": backend_risk_class,
        "policy_context_hash": backend_policy_context_hash,
        "client_risk_class": request["risk_class"],
        "client_policy_context_hash": request["policy_context_hash"],
    }
    if approval_id is not None:
        body["approval_id"] = approval_id
    return _sign_jcs(body, seed=seed)


class RecordingAgent:
    did = AGENT_DID

    def __init__(self, *, decision: str = "ALLOW", seed: bytes = BACKEND_SEED):
        self.decision = decision
        self.seed = seed
        self.calls: list[dict] = []

    def runtime_evaluate(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "audit_id": AUDIT_ID,
            "decision": self.decision,
            "decision_receipt_jcs": _decision_receipt(
                kwargs,
                decision=self.decision,
                approval_id=(
                    "urn:uuid:approval"
                    if self.decision == "WAITING_FOR_HUMAN_APPROVAL"
                    else None
                ),
                seed=self.seed,
            ),
        }

    def get_decision_receipt(self, audit_id: str) -> str:
        raise AssertionError("inline decision_receipt_jcs should avoid a receipt fetch")


class StaticGate:
    def __init__(self, decision: RuntimeGateDecision | Exception):
        self.decision = decision
        self.calls = []

    def evaluate(self, classification):
        self.calls.append(classification)
        if isinstance(self.decision, Exception):
            raise self.decision
        return self.decision


def _echo_downstream(tmp_path: Path, log_path: Path) -> Path:
    script = tmp_path / "runtime_gate_echo.py"
    script.write_text(
        """
import json
import os
import sys

log_path = os.environ["DOWNSTREAM_LOG"]
for line in sys.stdin:
    msg = json.loads(line)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(msg.get("method", "") + "\\n")
    if "id" not in msg:
        continue
    print(json.dumps({
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {"content": [{"type": "text", "text": "forwarded"}]},
    }), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _passthrough(tmp_path: Path, gate: object, config: ProxyConfig) -> tuple[McpPassthrough, Path]:
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_echo_downstream(tmp_path, log_path))),
            name="github",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name="github"),
        runtime_gate_factory=lambda: gate,
    )
    return passthrough, log_path


def _tool_call() -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "create_issue",
            "arguments": {"owner": "acme", "repo": "private-repo", "title": SECRET},
        },
    })


def test_ask_backend_runtime_request_is_privacy_safe_metadata_only():
    config = _config()
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    result = client.evaluate(_classification(config))

    assert result.decision == "ALLOW"
    call = agent.calls[0]
    assert set(call) == {
        "action",
        "resource",
        "environment",
        "delegation_receipt",
        "payload_hash",
        "risk_class",
        "policy_context_hash",
    }
    assert call["action"] == "redacted"
    assert call["resource"].startswith("sha256:")
    assert call["environment"] == "mcp_proxy"
    assert call["payload_hash"].startswith("sha256:")
    assert call["risk_class"] == "write"
    body_text = json.dumps(call, sort_keys=True)
    for forbidden in (
        SECRET,
        "private-repo",
        "summarize confidential plan",
        "private model output",
        "ghp_secret_token",
        "source_code",
        "create_issue",
        "github.create_issue",
    ):
        assert forbidden not in body_text


def test_runtime_evaluate_wire_body_excludes_raw_mcp_args_and_secrets():
    config = _config()
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="wire-test", timeout=2.0)
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    captured: dict[str, object] = {}

    def mock_post(url, **kwargs):
        body = json.loads(kwargs["content"])
        captured["url"] = url
        captured["body"] = body
        receipt_jcs = _decision_receipt(body, decision="ALLOW")
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {
            "audit_id": AUDIT_ID,
            "decision": "ALLOW",
            "decision_receipt_jcs": receipt_jcs,
        }
        return response

    with patch.object(httpx.Client, "post", side_effect=mock_post):
        result = client.evaluate(_classification(config))

    assert result.decision == "ALLOW"
    assert captured["url"] == "/v1/runtime/evaluate"
    body = captured["body"]
    assert set(body) == {
        "agent_did",
        "action",
        "resource",
        "environment",
        "receipt",
        "payload_hash",
        "risk_class",
        "policy_context_hash",
    }
    assert body["agent_did"] == AGENT_DID
    assert body["action"] == "redacted"
    assert body["resource"].startswith("sha256:")
    assert body["receipt"] == {"id": "grant"}
    body_text = json.dumps(body, sort_keys=True)
    for forbidden in (
        SECRET,
        "private-repo",
        "summarize confidential plan",
        "private model output",
        "ghp_secret_token",
        "print('do not upload')",
        "create_issue",
    ):
        assert forbidden not in body_text


def test_verified_allow_forwards_downstream(tmp_path):
    config = _config()
    gate = StaticGate(RuntimeGateDecision(
        decision="ALLOW",
        audit_id=AUDIT_ID,
        approval_id=None,
        receipt_digest="aa" * 32,
        receipt_body={},
    ))
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    assert _responses(client_out.getvalue()) == [{
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {"content": [{"type": "text", "text": "forwarded"}]},
    }]
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/call"]
    assert len(gate.calls) == 1


def test_block_does_not_forward_and_returns_sanitized_error(tmp_path):
    config = _config()
    gate = StaticGate(RuntimeGateDecision(
        decision="BLOCK",
        audit_id=AUDIT_ID,
        approval_id=None,
        receipt_digest="aa" * 32,
        receipt_body={},
    ))
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    assert response["error"]["message"] == "blocked by AVP Runtime Gate"
    assert response["error"]["data"]["status"] == "blocked"
    assert response["error"]["data"]["audit_id"] == AUDIT_ID
    assert SECRET not in client_out.getvalue()
    assert not log_path.exists()


def test_waiting_does_not_forward_and_returns_approval_required_shape(tmp_path):
    config = _config()
    gate = StaticGate(RuntimeGateDecision(
        decision="WAITING_FOR_HUMAN_APPROVAL",
        audit_id=AUDIT_ID,
        approval_id="urn:uuid:approval",
        receipt_digest="aa" * 32,
        receipt_body={},
    ))
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["message"] == "approval required"
    assert response["error"]["data"] == {
        "status": "approval_required",
        "reason": "runtime_gate_waiting_for_human_approval",
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "audit_id": AUDIT_ID,
        "approval_id": "urn:uuid:approval",
    }
    assert SECRET not in client_out.getvalue()
    assert not log_path.exists()


def test_unverified_receipt_is_rejected_without_downstream_execution(tmp_path):
    config = _config()
    agent = RecordingAgent(seed=OTHER_BACKEND_SEED)
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    passthrough, log_path = _passthrough(tmp_path, client, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_UNTRUSTED
    assert response["error"]["data"] == {
        "status": "blocked",
        "reason": "untrusted_runtime_decision",
    }
    assert passthrough.security_events[-1] == {
        "type": "runtime_decision_untrusted",
        "action": "blocked",
        "reason": "untrusted_runtime_decision",
    }
    assert SECRET not in client_out.getvalue()
    assert not log_path.exists()


def test_backend_timeout_error_is_sanitized_and_bounded(tmp_path):
    config = _config(fallback={"write": "block"})
    gate = StaticGate(RuntimeGateUnavailableError(f"timed out while handling {SECRET}"))
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    started = time.monotonic()
    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0
    elapsed = time.monotonic() - started

    response = _responses(client_out.getvalue())[0]
    assert elapsed < 1.0
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_UNAVAILABLE
    assert response["error"]["message"] == "AVP Runtime Gate unavailable"
    assert response["error"]["data"] == {
        "status": "blocked",
        "reason": "runtime_gate_unavailable",
    }
    assert SECRET not in client_out.getvalue()
    assert not log_path.exists()
