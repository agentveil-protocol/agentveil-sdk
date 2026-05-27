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
import pytest
from nacl.signing import SigningKey

from agentveil.agent import AVPAgent
from agentveil.delegation import _public_key_to_did
from agentveil_mcp_proxy.approval import ApprovalManager, ApprovalServer
from agentveil_mcp_proxy.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceStore,
    ApprovalStatus,
    export_evidence_bundle,
    verify_evidence_bundle,
)
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
    RuntimeGateUntrustedError,
)
import agentveil_mcp_proxy.runtime_gate as runtime_gate_module


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
    audit_id: str = AUDIT_ID,
    seed: bytes = BACKEND_SEED,
    backend_risk_class: str = "unknown",
    backend_policy_context_hash: str = "b" * 64,
    omit_fields: tuple[str, ...] = (),
) -> str:
    body = {
        "schema_version": "decision_receipt/2",
        "audit_id": audit_id,
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
    for field in omit_fields:
        body.pop(field, None)
    return _sign_jcs(body, seed=seed)


class RecordingAgent:
    did = AGENT_DID

    def __init__(
        self,
        *,
        decision: str = "ALLOW",
        seed: bytes = BACKEND_SEED,
        omit_receipt_fields: tuple[str, ...] = (),
    ):
        self.decision = decision
        self.seed = seed
        self.omit_receipt_fields = omit_receipt_fields
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
                omit_fields=self.omit_receipt_fields,
            ),
        }

    def get_decision_receipt(self, audit_id: str) -> str:
        raise AssertionError("inline decision_receipt_jcs should avoid a receipt fetch")


class FetchableRecordingAgent(RecordingAgent):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.receipts: dict[str, str] = {}

    def runtime_evaluate(self, **kwargs):
        response = super().runtime_evaluate(**kwargs)
        self.receipts[response["audit_id"]] = response["decision_receipt_jcs"]
        return response

    def get_decision_receipt(self, audit_id: str) -> str:
        return self.receipts[audit_id]


class SequencedReceiptAgent:
    did = AGENT_DID

    def __init__(self, audit_ids: list[str]):
        self.audit_ids = list(audit_ids)
        self.calls: list[dict] = []

    def runtime_evaluate(self, **kwargs):
        self.calls.append(kwargs)
        audit_id = self.audit_ids.pop(0)
        receipt_jcs = _decision_receipt(kwargs, audit_id=audit_id)
        return {
            "audit_id": audit_id,
            "decision": "ALLOW",
            "decision_receipt_jcs": receipt_jcs,
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


def _passthrough(
    tmp_path: Path,
    gate: object,
    config: ProxyConfig,
    *,
    approval_manager: ApprovalManager | None = None,
) -> tuple[McpPassthrough, Path]:
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
        approval_manager=approval_manager,
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


def test_runtime_gate_rejects_zero_cache_ttl():
    with pytest.raises(ValueError, match="cache_ttl_seconds must be positive"):
        RuntimeGateClient(
            agent=MagicMock(),
            config=_config(),
            control_grant={"id": "grant"},
            cache_ttl_seconds=0,
        )


def test_runtime_gate_rejects_negative_cache_ttl():
    with pytest.raises(ValueError, match="cache_ttl_seconds must be positive"):
        RuntimeGateClient(
            agent=MagicMock(),
            config=_config(),
            control_grant={"id": "grant"},
            cache_ttl_seconds=-1.0,
        )


def test_runtime_gate_rejects_zero_cache_max_entries():
    with pytest.raises(ValueError, match="cache_max_entries must be positive"):
        RuntimeGateClient(
            agent=MagicMock(),
            config=_config(),
            control_grant={"id": "grant"},
            cache_max_entries=0,
        )


def test_runtime_gate_rejects_negative_cache_max_entries():
    with pytest.raises(ValueError, match="cache_max_entries must be positive"):
        RuntimeGateClient(
            agent=MagicMock(),
            config=_config(),
            control_grant={"id": "grant"},
            cache_max_entries=-1,
        )


def test_runtime_gate_accepts_positive_cache_settings():
    client = RuntimeGateClient(agent=MagicMock(), config=_config(), control_grant={"id": "grant"})

    assert client.cache_ttl_seconds > 0
    assert client.cache_max_entries > 0


def test_runtime_gate_accepts_minimal_positive_cache_settings():
    client = RuntimeGateClient(
        agent=MagicMock(),
        config=_config(),
        control_grant={"id": "grant"},
        cache_ttl_seconds=0.001,
        cache_max_entries=1,
    )

    assert client.cache_ttl_seconds == 0.001
    assert client.cache_max_entries == 1


def test_replay_of_previously_verified_receipt_is_rejected_as_untrusted():
    config = _config()
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    assert client.evaluate(_classification(config)).decision == "ALLOW"

    with pytest.raises(RuntimeGateUntrustedError, match="decision receipt replay detected"):
        client.evaluate(_classification(config))


def test_distinct_receipts_for_same_intent_both_pass():
    config = _config()
    agent = SequencedReceiptAgent(["audit-1", "audit-2"])
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    first = client.evaluate(_classification(config))
    second = client.evaluate(_classification(config))

    assert first.decision == "ALLOW"
    assert second.decision == "ALLOW"
    assert first.receipt_digest != second.receipt_digest
    assert client.seen_receipt_cache_size == 2


def test_seen_receipt_cache_prunes_after_ttl(monkeypatch):
    clock = {"now": 100.0}
    monkeypatch.setattr(runtime_gate_module.time, "monotonic", lambda: clock["now"])
    config = _config()
    agent = RecordingAgent()
    client = RuntimeGateClient(
        agent=agent,
        config=config,
        control_grant={"id": "grant"},
        cache_ttl_seconds=5.0,
    )

    assert client.evaluate(_classification(config)).decision == "ALLOW"
    clock["now"] = 106.0

    assert client.evaluate(_classification(config)).decision == "ALLOW"
    assert client.seen_receipt_cache_size == 1


def test_seen_receipt_cache_evicts_oldest_when_max_entries_exceeded():
    config = _config()
    agent = SequencedReceiptAgent(["audit-1", "audit-2", "audit-3"])
    client = RuntimeGateClient(
        agent=agent,
        config=config,
        control_grant={"id": "grant"},
        cache_max_entries=2,
    )

    digests = [
        client.evaluate(_classification(config)).receipt_digest,
        client.evaluate(_classification(config)).receipt_digest,
        client.evaluate(_classification(config)).receipt_digest,
    ]

    assert client.seen_receipt_cache_size == 2
    assert digests[0] not in client._seen_receipt_digests
    assert digests[1] in client._seen_receipt_digests
    assert digests[2] in client._seen_receipt_digests


def test_replay_detection_does_not_record_circuit_failure():
    config = _config()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    agent = RecordingAgent()
    client = RuntimeGateClient(
        agent=agent,
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )

    assert client.evaluate(_classification(config)).decision == "ALLOW"
    with pytest.raises(RuntimeGateUntrustedError, match="decision receipt replay detected"):
        client.evaluate(_classification(config))

    assert breaker.state_change_count == 0


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


def test_verified_allow_records_runtime_receipt_and_downstream_result(tmp_path):
    config = _config()
    digest = "aa" * 32
    gate = StaticGate(RuntimeGateDecision(
        decision="ALLOW",
        audit_id=AUDIT_ID,
        approval_id=None,
        receipt_digest=digest,
        receipt_body={},
    ))
    with ApprovalEvidenceStore(tmp_path / "evidence.sqlite") as store:
        manager = ApprovalManager(
            evidence_store=store,
            approval_server=ApprovalServer(),
            config=config,
            client_id="pytest",
            session_id="session-runtime-allow",
        )
        passthrough, log_path = _passthrough(
            tmp_path,
            gate,
            config,
            approval_manager=manager,
        )
        client_out = io.StringIO()

        assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

        records = store.list_records()

    assert _responses(client_out.getvalue()) == [{
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {"content": [{"type": "text", "text": "forwarded"}]},
    }]
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/call"]
    assert len(records) == 1
    record = records[0]
    assert record.status == ApprovalStatus.EXECUTED.value
    assert record.decision_audit_id == AUDIT_ID
    assert record.decision_receipt_sha256 == digest
    assert record.result_status == "executed"
    assert record.result_hash is not None
    assert record.approval_token_hash is None
    assert record.approval_decided_by is None


def test_verified_allow_export_bundle_attaches_signed_decision_receipt(tmp_path):
    config = _config()
    agent = FetchableRecordingAgent(decision="ALLOW")
    gate = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    bundle_path = tmp_path / "evidence-bundle.json"
    with ApprovalEvidenceStore(tmp_path / "evidence.sqlite") as store:
        manager = ApprovalManager(
            evidence_store=store,
            approval_server=ApprovalServer(),
            config=config,
            client_id="pytest",
            session_id="session-runtime-bundle",
        )
        passthrough, _log_path = _passthrough(
            tmp_path,
            gate,
            config,
            approval_manager=manager,
        )
        client_out = io.StringIO()

        assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

        bundle = export_evidence_bundle(
            store,
            bundle_path,
            proxy_identity_did=AGENT_DID,
            trusted_signer_dids=[BACKEND_DID],
            receipt_fetcher=agent.get_decision_receipt,
        )

    result = verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])
    assert result.valid is True
    assert result.record_count == 1
    assert result.signed_receipt_count == 1
    assert result.unverified_receipt_count == 0
    assert result.warnings == ()


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


def test_verified_block_records_runtime_receipt_without_forwarding(tmp_path):
    config = _config()
    digest = "aa" * 32
    gate = StaticGate(RuntimeGateDecision(
        decision="BLOCK",
        audit_id=AUDIT_ID,
        approval_id=None,
        receipt_digest=digest,
        receipt_body={},
    ))
    with ApprovalEvidenceStore(tmp_path / "evidence.sqlite") as store:
        manager = ApprovalManager(
            evidence_store=store,
            approval_server=ApprovalServer(),
            config=config,
            client_id="pytest",
            session_id="session-runtime-block",
        )
        passthrough, log_path = _passthrough(
            tmp_path,
            gate,
            config,
            approval_manager=manager,
        )
        client_out = io.StringIO()

        assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

        records = store.list_records()

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    assert response["error"]["data"]["reason"] == "runtime_gate_block"
    assert SECRET not in client_out.getvalue()
    assert not log_path.exists()
    assert len(records) == 1
    record = records[0]
    assert record.status == ApprovalStatus.BLOCKED.value
    assert record.decision_audit_id == AUDIT_ID
    assert record.decision_receipt_sha256 == digest
    assert record.result_status == "blocked"
    assert record.error_class == "runtime_gate_block"
    assert record.approval_token_hash is None
    assert record.approval_decided_by is None


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


@pytest.mark.parametrize(
    "missing_field",
    [
        "action",
        "resource",
        "environment",
        "payload_hash",
        "client_risk_class",
        "client_policy_context_hash",
        "audit_id",
    ],
)
def test_decision_receipt_missing_required_field_is_rejected(missing_field):
    config = _config()
    agent = RecordingAgent(omit_receipt_fields=(missing_field,))
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    with pytest.raises(RuntimeGateUntrustedError, match="missing"):
        client.evaluate(_classification(config))


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
