"""P5 tests for MCP proxy Runtime Gate integration."""

from __future__ import annotations

import io
import json
import os
import re
from copy import deepcopy
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
from agentveil.data_integrity import DATA_INTEGRITY_CONTEXT, sign_eddsa_jcs_2022
from agentveil.delegation import _public_key_to_did
from agentveil.exceptions import (
    AVPAuthError,
    AVPError,
    AVPNotFoundError,
    AVPRateLimitError,
    AVPServerError,
    AVPValidationError,
)
from agentveil_mcp_proxy.approval import ApprovalManager, ApprovalServer
from agentveil_mcp_proxy.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from agentveil_mcp_proxy.classification import ToolCallClassifier
import agentveil_mcp_proxy.classification as classification_module
from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceStore,
    ApprovalStatus,
    EvidenceVerificationError,
    export_evidence_bundle,
    verify_evidence_bundle,
)
from agentveil_mcp_proxy.passthrough import (
    APPROVAL_REQUIRED_USER_MESSAGE,
    DownstreamConfig,
    JSONRPC_APPROVAL_REQUIRED,
    JSONRPC_POLICY_BLOCKED,
    JSONRPC_RUNTIME_GATE_REJECTED,
    JSONRPC_RUNTIME_GATE_UNAVAILABLE,
    JSONRPC_RUNTIME_GATE_UNTRUSTED,
    McpPassthrough,
)
from agentveil_mcp_proxy.policy import ProxyConfig
from agentveil_mcp_proxy.runtime_gate import (
    CANONICAL_RUNTIME_ENVIRONMENTS,
    DEFAULT_RUNTIME_ENVIRONMENT,
    RuntimeGateClient,
    RuntimeGateDecision,
    RuntimeGateRejectedError,
    RuntimeGateUnavailableError,
    RuntimeGateUntrustedError,
    RuntimeGateWireContractError,
)
import agentveil_mcp_proxy.runtime_gate as runtime_gate_module

from mcp_fake_downstream import tool_entry, write_downstream


BACKEND_SEED = bytes.fromhex("11" * 32)
OTHER_BACKEND_SEED = bytes.fromhex("22" * 32)
AGENT_SEED = bytes.fromhex("44" * 32)
BACKEND_DID = _public_key_to_did(bytes(SigningKey(BACKEND_SEED).verify_key))
AGENT_DID = _public_key_to_did(bytes(SigningKey(AGENT_SEED).verify_key))
SECRET = "SECRET_PROJECT_ALPHA"
AUDIT_ID = "urn:uuid:11111111-1111-4111-8111-111111111111"
_PUBLIC_WIRE_CONTRACT_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "fixtures"
    / "runtime_gate_public_wire_contract.json"
)
_FORBIDDEN_PRIVATE_MARKERS = (
    "source_truth",
    "entitlement",
    "billing",
    "hosted_accounting",
    "kms",
    "s3",
    "team_context",
    "enterprise",
    "customer",
    "license_id",
    "workspace_id",
    "database",
    "db_",
    "resolver",
    "threshold",
)


def _public_wire_contract() -> dict:
    return json.loads(_PUBLIC_WIRE_CONTRACT_PATH.read_text(encoding="utf-8"))


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _runtime_gate_policy_to_dict() -> dict:
    return {
        "id": "runtime-gate-test",
        "policy_schema_version": 1,
        "default_decision": "ask_backend",
        "default_risk_class": "write",
        "rules": [
            {
                "id": "ask-runtime-gate-create-issue",
                "source": "user",
                "decision": "ask_backend",
                "match": {"server": ["github"], "tool": ["create_issue"]},
                "risk_class": "write",
            }
        ],
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
            # claim-check: allow "production" is a fallback risk-class key in test config.
            "production": "block",
            "financial": "block",
            "unknown": "approval",
        },
        "approval": {},
        "policy": _runtime_gate_policy_to_dict(),
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
    paid_approval_center_projection: dict | None = None,
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
    if paid_approval_center_projection is not None:
        body["paid_approval_center_projection"] = paid_approval_center_projection
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


def _decision_receipt_v3(
    request: dict,
    *,
    decision: str = "ALLOW",
    approval_id: str | None = None,
    audit_id: str = AUDIT_ID,
    seed: bytes = BACKEND_SEED,
    backend_risk_class: str = "unknown",
    backend_policy_context_hash: str = "b" * 64,
) -> str:
    """A W3C Data Integrity (eddsa-jcs-2022) decision_receipt/3, same fields as /2."""
    body = {
        "@context": [DATA_INTEGRITY_CONTEXT],
        "schema_version": "decision_receipt/3",
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
    return sign_eddsa_jcs_2022(body, seed, created="2026-05-29T00:00:00Z")


class FetchableRecordingAgentV3:
    """Stub backend that emits decision_receipt/3 and supports receipt fetch."""

    did = AGENT_DID

    def __init__(self, *, decision: str = "ALLOW", seed: bytes = BACKEND_SEED):
        self.decision = decision
        self.seed = seed
        self.calls: list[dict] = []
        self.receipts: dict[str, str] = {}

    def runtime_evaluate(self, **kwargs):
        self.calls.append(kwargs)
        receipt = _decision_receipt_v3(
            kwargs,
            decision=self.decision,
            seed=self.seed,
            approval_id=(
                "urn:uuid:approval"
                if self.decision == "WAITING_FOR_HUMAN_APPROVAL"
                else None
            ),
        )
        self.receipts[AUDIT_ID] = receipt
        return {"audit_id": AUDIT_ID, "decision": self.decision, "decision_receipt_jcs": receipt}

    def get_decision_receipt(self, audit_id: str) -> str:
        return self.receipts[audit_id]


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
    return write_downstream(
        tmp_path,
        filename="runtime_gate_echo.py",
        tools=[tool_entry("create_issue")],
        call_result_text="forwarded",
    )


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
    assert call["action"] == "privacy.redacted"
    assert call["resource"].startswith("sha256:")
    assert call["environment"] == "unknown"
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


def test_runtime_gate_forwards_only_bounded_paid_content_risk_signals(monkeypatch):
    signals = {
        "contains_secret_like_value": True,
        "destructive_shell_pattern": False,
        "write_then_execute_risk": False,
        "credential_exfil_pattern": False,
    }
    monkeypatch.setattr(
        classification_module,
        "derive_content_risk_signals",
        lambda arguments: signals,
    )
    config = _config()
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    assert client.evaluate(_classification(config)).decision == "ALLOW"
    call = agent.calls[0]
    assert call["content_risk_signals"] == signals
    assert call["paid_policy_route_kind"] == "mcp_tools_call"
    body_text = json.dumps(call, sort_keys=True)
    assert SECRET not in body_text
    assert "summarize confidential plan" not in body_text
    assert "ghp_secret_token" not in body_text


def test_default_runtime_environment_is_unknown():
    assert DEFAULT_RUNTIME_ENVIRONMENT == "unknown"


@pytest.mark.parametrize("environment", sorted(CANONICAL_RUNTIME_ENVIRONMENTS))
def test_runtime_gate_accepts_canonical_environments(environment):
    config = _config()
    agent = RecordingAgent()
    client = RuntimeGateClient(
        agent=agent,
        config=config,
        control_grant={"id": "grant"},
        environment=environment,
    )

    result = client.evaluate(_classification(config))

    assert result.decision == "ALLOW"
    assert agent.calls[0]["environment"] == environment
    assert client.environment == environment


@pytest.mark.parametrize(
    "invalid_environment",
    # claim-check: allow uppercase negative fixture, not a production claim.
    ["mcp_proxy", "prod", "", "PRODUCTION", "staging\n", "x" * 256],
)
def test_runtime_gate_rejects_invalid_environment_before_runtime_evaluate(
    invalid_environment,
):
    config = _config()
    agent = RecordingAgent()

    with pytest.raises(ValueError, match="environment invalid") as exc_info:
        RuntimeGateClient(
            agent=agent,
            config=config,
            control_grant={"id": "grant"},
            environment=invalid_environment,
        )

    if invalid_environment:
        assert invalid_environment not in str(exc_info.value)
    assert agent.calls == []


def test_receipt_verification_succeeds_with_default_unknown_environment():
    config = _config()
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    result = client.evaluate(_classification(config))

    assert result.decision == "ALLOW"
    assert result.receipt_body["environment"] == "unknown"
    assert agent.calls[0]["environment"] == "unknown"


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
    assert body["action"] == "privacy.redacted"
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


def _privacy_config(*, action: str, resource: str = "hash") -> ProxyConfig:
    return _config(privacy={
        "action": action,
        "resource": resource,
        "payload": "hash_only",
        "evidence_upload": False,
    })


def _metadata_classification(metadata: dict):
    class _MetadataClassification:
        def backend_metadata(self):
            return metadata

    return _MetadataClassification()


def _contract_action_spec() -> dict:
    return _public_wire_contract()["request"]["action"]


@pytest.mark.parametrize(
    "legacy_action",
    [
        "redacted",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ],
)
def test_legacy_local_action_tokens_fail_dotted_wire_pattern(legacy_action):
    dotted = runtime_gate_module._DOTTED_WIRE_ACTION_RE
    assert dotted.fullmatch(legacy_action) is None


def test_plain_wire_action_is_byte_identical_dotted_action():
    config = _privacy_config(action="plain", resource="plain")
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    classification = _classification(config)

    result = client.evaluate(classification)

    assert result.decision == "ALLOW"
    assert classification.action == "github.create_issue"
    assert agent.calls[0]["action"] == "github.create_issue"


def test_redacted_wire_action_is_exact_privacy_redacted():
    config = _privacy_config(action="redacted")
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    result = client.evaluate(_classification(config))

    assert result.decision == "ALLOW"
    assert agent.calls[0]["action"] == _contract_action_spec()["redacted_exact"]


def test_hash_wire_action_is_privacy_h_plus_action_hash_hex():
    config = _privacy_config(action="hash", resource="redacted")
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    classification = _classification(config)
    expected_hex = classification.action_hash.removeprefix("sha256:")

    result = client.evaluate(classification)

    assert result.decision == "ALLOW"
    assert agent.calls[0]["action"] == f"privacy.h{expected_hex}"


def test_same_action_produces_same_hash_surrogate():
    config = _privacy_config(action="hash", resource="redacted")
    classification = _classification(config)
    first_agent = RecordingAgent()
    second_agent = RecordingAgent()
    RuntimeGateClient(
        agent=first_agent,
        config=config,
        control_grant={"id": "grant"},
    ).evaluate(classification)
    RuntimeGateClient(
        agent=second_agent,
        config=config,
        control_grant={"id": "grant"},
    ).evaluate(classification)

    assert first_agent.calls[0]["action"] == second_agent.calls[0]["action"]


def test_different_actions_produce_different_hash_surrogates():
    config = _privacy_config(action="hash", resource="redacted")
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    first = ToolCallClassifier(config, server_name="github").classify(
        tool="create_issue",
        arguments={"owner": "acme", "repo": "alpha"},
    )
    second = ToolCallClassifier(config, server_name="github").classify(
        tool="read_file",
        arguments={"owner": "acme", "repo": "alpha", "path": "README.md"},
    )

    client.evaluate(first)
    client.evaluate(second)

    assert agent.calls[0]["action"] != agent.calls[1]["action"]
    assert agent.calls[0]["action"].startswith("privacy.h")
    assert agent.calls[1]["action"].startswith("privacy.h")


def test_redacted_and_hash_wire_body_exclude_raw_action_material():
    redacted_config = _privacy_config(action="redacted")
    hash_config = _privacy_config(action="hash", resource="redacted")
    redacted_agent = RecordingAgent()
    hash_agent = RecordingAgent()
    redacted_client = RuntimeGateClient(
        agent=redacted_agent,
        config=redacted_config,
        control_grant={"id": "grant"},
    )
    hash_client = RuntimeGateClient(
        agent=hash_agent,
        config=hash_config,
        control_grant={"id": "grant"},
    )

    redacted_client.evaluate(_classification(redacted_config))
    hash_client.evaluate(_classification(hash_config))

    for call in (redacted_agent.calls[0], hash_agent.calls[0]):
        body_text = json.dumps(call, sort_keys=True)
        for forbidden in (
            "create_issue",
            "github.create_issue",
            "github",
            "private-repo",
            SECRET,
        ):
            assert forbidden not in body_text


@pytest.mark.parametrize(
    "action_hash",
    [
        "sha256:" + ("a" * 63),
        "sha256:" + ("a" * 65),
        "sha256:" + ("A" * 64),
        "deadbeef",
        "",
    ],
)
def test_invalid_hash_action_material_rejects_before_http(action_hash):
    config = _privacy_config(action="hash", resource="redacted")
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    metadata = _classification(config).backend_metadata()
    metadata = {**metadata, "action_hash": action_hash}
    if action_hash and action_hash != metadata.get("action"):
        metadata = {**metadata, "action": action_hash}

    with pytest.raises(RuntimeGateWireContractError):
        client.evaluate(_metadata_classification(metadata))

    assert agent.calls == []


@pytest.mark.parametrize(
    "invalid_action",
    ["redacted", "GitHub.Create_Issue", "github", ""],
)
def test_invalid_plain_wire_action_rejects_before_http(invalid_action):
    config = _privacy_config(action="plain", resource="plain")
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    metadata = _classification(config).backend_metadata()
    metadata = {**metadata, "action": invalid_action}

    with pytest.raises(RuntimeGateWireContractError):
        client.evaluate(_metadata_classification(metadata))

    assert agent.calls == []


@pytest.mark.parametrize(
    ("privacy_action", "metadata_patch"),
    [
        ("plain", {"action": "redacted", "action_hash": None}),
        ("plain", {"action": "github.create_issue", "action_hash": "sha256:" + ("a" * 64)}),
        ("redacted", {"action": "github.create_issue", "action_hash": None}),
        ("redacted", {"action": "redacted", "action_hash": "sha256:" + ("a" * 64)}),
        ("hash", {"action": "redacted", "action_hash": None}),
        (
            "hash",
            {
                "action": "sha256:" + ("a" * 64),
                "action_hash": "sha256:" + ("b" * 64),
            },
        ),
    ],
)
def test_privacy_mode_material_mismatch_is_terminal_before_http(
    privacy_action,
    metadata_patch,
):
    config = _privacy_config(
        action=privacy_action,
        resource="plain" if privacy_action == "plain" else "redacted",
    )
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    metadata = _classification(config).backend_metadata()
    metadata = {**metadata, **metadata_patch}

    with pytest.raises(RuntimeGateWireContractError):
        client.evaluate(_metadata_classification(metadata))

    assert agent.calls == []


def test_invalid_plain_wire_action_passthrough_denies_without_fallback_or_downstream(
    tmp_path,
):
    config = _config(
        privacy={
            "action": "plain",
            "resource": "plain",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        fallback=_all_allow_fallback(),
    )
    agent = RecordingAgent()
    gate = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    passthrough.classifier = ToolCallClassifier(config, server_name="my-github")
    client_out = io.StringIO()
    tool_call = _json_line({
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "create_issue",
            "arguments": {"owner": "acme", "repo": "private-repo", "title": SECRET},
        },
    })

    assert passthrough.run_stdio(io.StringIO(tool_call), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response.get("error", response).get("code") == JSONRPC_RUNTIME_GATE_UNTRUSTED, response
    # claim-check: allow blocked is the asserted negative response contract
    assert response["error"]["data"]["status"] == "blocked"
    assert response["error"]["data"]["reason"] == "untrusted_runtime_decision"
    assert response["error"]["data"]["target_reached"] is False
    assert SECRET not in client_out.getvalue()
    assert len(agent.calls) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_wire_action_normalization_preserves_local_classification_metadata():
    for action_mode in ("plain", "redacted", "hash"):
        config = _privacy_config(
            action=action_mode,
            resource="plain" if action_mode == "plain" else "redacted",
        )
        agent = RecordingAgent()
        client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
        classification = _classification(config)
        before_metadata = classification.backend_metadata()
        before_evidence = classification.local_evidence_metadata()

        client.evaluate(classification)

        after_metadata = classification.backend_metadata()
        after_evidence = classification.local_evidence_metadata()
        assert after_metadata == before_metadata
        assert after_evidence == before_evidence


def test_public_wire_contract_action_inventory_matches_sender():
    spec = _contract_action_spec()
    dotted = runtime_gate_module._DOTTED_WIRE_ACTION_RE
    hash_pattern = re.compile(spec["hash_pattern"])
    plain_agent = RecordingAgent()
    redacted_agent = RecordingAgent()
    hash_agent = RecordingAgent()
    plain_config = _privacy_config(action="plain", resource="plain")
    redacted_config = _privacy_config(action="redacted")
    hash_config = _privacy_config(action="hash", resource="redacted")

    RuntimeGateClient(
        agent=plain_agent,
        config=plain_config,
        control_grant={"id": "grant"},
    ).evaluate(_classification(plain_config))
    RuntimeGateClient(
        agent=redacted_agent,
        config=redacted_config,
        control_grant={"id": "grant"},
    ).evaluate(_classification(redacted_config))
    RuntimeGateClient(
        agent=hash_agent,
        config=hash_config,
        control_grant={"id": "grant"},
    ).evaluate(_classification(hash_config))

    assert dotted.fullmatch(plain_agent.calls[0]["action"])
    assert redacted_agent.calls[0]["action"] == spec["redacted_exact"]
    assert hash_pattern.fullmatch(hash_agent.calls[0]["action"])


def _package_classification(config: ProxyConfig):
    return ToolCallClassifier(config, server_name="package").classify(
        tool="pip_install",
        arguments={
            "package_name": "raw-secret-package-name",
            "project_path": "/Users/secret/proj",
            "url": "https://evil.example/pkg.whl",
            "token": "sk_live_do_not_leak",
        },
    )


def _package_ask_backend_config() -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": [BACKEND_DID],
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
            # claim-check: allow "production" is a fallback risk-class key in test config.
            "production": "block",
            "financial": "block",
            "unknown": "approval",
        },
        "approval": {},
        "policy": {
            "id": "runtime-gate-package-test",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "write",
            "rules": [
                {
                    "id": "ask-runtime-gate-pip-install",
                    "source": "user",
                    "decision": "ask_backend",
                    "match": {"server": ["package"], "tool": ["pip_install"]},
                    "risk_class": "write",
                }
            ],
        },
        "downstream": {},
    })


def test_package_install_runtime_request_includes_bounded_install_clone_context():
    config = _package_ask_backend_config()
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    result = client.evaluate(_package_classification(config))

    assert result.decision == "ALLOW"
    call = agent.calls[0]
    assert "install_clone_context" in call
    context = call["install_clone_context"]
    assert context["operation"] == "install"
    assert context["source_ref"] == "src_package_route_builtin"
    assert context["source_ref_kind"] == "workspace_registry"
    assert context["tool_source"] == "approved_registry"
    assert context["requested_package"] == "pkg_package_route_builtin"
    assert context["mcp_schema"] == {
        "signal_code": "tool_declares_install",
        "evidence_ref": "ev_mcp_schema_package_route",
    }
    assert "readme" not in context
    body_text = json.dumps(call, sort_keys=True)
    for forbidden in (
        "raw-secret-package-name",
        "/Users/secret",
        "evil.example",
        "sk_live_do_not_leak",
        "readme_signal",
        "tool_output_signal",
    ):
        assert forbidden not in body_text


def test_package_install_runtime_request_includes_collected_metadata_evidence():
    config = _package_ask_backend_config()
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    classified = ToolCallClassifier(config, server_name="package").classify(
        tool="pip_install",
        arguments={
            "package_name": "raw-secret-package-name",
            "project_path": "/Users/secret/proj",
            "readme": "Clone the repository then pip install the package",
            "command_output": "git clone helper && pip install helper",
            "file_kind": "config",
        },
    )

    result = client.evaluate(classified)

    assert result.decision == "ALLOW"
    context = agent.calls[0]["install_clone_context"]
    assert context["readme"]["signal_code"] == "install_hint"
    assert context["tool_output"]["signal_code"] == "install_command"
    assert context["file_metadata"]["signal_code"] == "config_package_ref"
    assert context["mcp_schema"]["signal_code"] == "tool_declares_install"
    body_text = json.dumps(agent.calls[0], sort_keys=True)
    for forbidden in (
        "raw-secret-package-name",
        "/Users/secret",
        "Clone the repository",
        "git clone helper",
        "pip install the package",
    ):
        assert forbidden not in body_text


def test_package_install_runtime_request_rejects_unknown_evidence_fields_before_post():
    config = _package_ask_backend_config()
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    classification = _package_classification(config)
    metadata = classification.backend_metadata()
    context = dict(metadata["install_clone_context"])
    context["readme"] = {
        "signal_code": "install_hint",
        "raw_readme": "pip install evil from https://evil.example",
    }

    class _MutableClassification:
        def backend_metadata(self):
            return {
                **metadata,
                "install_clone_context": context,
            }

    with pytest.raises(RuntimeGateUnavailableError, match="install_clone_context invalid"):
        client.evaluate(_MutableClassification())  # type: ignore[arg-type]
    assert agent.calls == []


def test_non_package_runtime_request_omits_install_clone_context():
    config = _config()
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    client.evaluate(_classification(config))
    assert "install_clone_context" not in agent.calls[0]


def test_package_install_wire_body_includes_install_clone_context_without_raw_args():
    config = _package_ask_backend_config()
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="wire-package", timeout=2.0)
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    captured: dict[str, object] = {}

    def mock_post(url, **kwargs):
        body = json.loads(kwargs["content"])
        captured["url"] = url
        captured["body"] = body
        # Receipt verifies core fields only; advisory may be present in response.
        receipt_request = {
            key: body[key]
            for key in (
                "action",
                "resource",
                "environment",
                "payload_hash",
                "risk_class",
                "policy_context_hash",
            )
        }
        receipt_jcs = _decision_receipt(receipt_request, decision="ALLOW")
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {
            "audit_id": AUDIT_ID,
            "decision": "ALLOW",
            "decision_receipt_jcs": receipt_jcs,
            "install_clone_advisory": {
                "ok": True,
                "decision": "allow",
                "reason_code": "workspace_registry_trusted",
                "advisory_state": "verified",
                "live_enforcement": "HOLD",
                "source_truth": {"decision": "allow"},
            },
        }
        return response

    with patch.object(httpx.Client, "post", side_effect=mock_post):
        result = client.evaluate(_package_classification(config))

    assert result.decision == "ALLOW"
    body = captured["body"]
    assert body["install_clone_context"]["source_ref"] == "src_package_route_builtin"
    assert set(body) >= {
        "agent_did",
        "action",
        "resource",
        "environment",
        "receipt",
        "payload_hash",
        "risk_class",
        "policy_context_hash",
        "install_clone_context",
    }
    body_text = json.dumps(body, sort_keys=True)
    for forbidden in ("raw-secret-package-name", "/Users/secret", "sk_live_do_not_leak"):
        assert forbidden not in body_text


def test_receipt_with_install_clone_advisory_still_verifies():
    config = _package_ask_backend_config()

    class AdvisoryReceiptAgent(RecordingAgent):
        def runtime_evaluate(self, **kwargs):
            self.calls.append(kwargs)
            receipt_request = {
                key: kwargs[key]
                for key in (
                    "action",
                    "resource",
                    "environment",
                    "payload_hash",
                    "risk_class",
                    "policy_context_hash",
                )
            }
            receipt_jcs = _decision_receipt(receipt_request, decision="ALLOW")
            # Inject advisory into signed body after signing would break verification;
            # advisory is response-level, receipt core fields unchanged.
            return {
                "audit_id": AUDIT_ID,
                "decision": "ALLOW",
                "decision_receipt_jcs": receipt_jcs,
                "install_clone_advisory": {
                    "ok": False,
                    "decision": "redirect",
                    "reason_code": "model_suggested_source",
                    "advisory_state": "review_recommended",
                    "live_enforcement": "HOLD",
                    "source_truth": {"decision": "redirect"},
                },
            }

    agent = AdvisoryReceiptAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    result = client.evaluate(_package_classification(config))
    assert result.decision == "ALLOW"
    assert "install_clone_context" in agent.calls[0]


def test_signed_receipt_body_with_install_clone_advisory_still_verifies():
    """P2: advisory may also appear inside signed DecisionReceipt body."""

    config = _package_ask_backend_config()

    class SignedAdvisoryReceiptAgent(RecordingAgent):
        def runtime_evaluate(self, **kwargs):
            self.calls.append(kwargs)
            receipt_request = {
                key: kwargs[key]
                for key in (
                    "action",
                    "resource",
                    "environment",
                    "payload_hash",
                    "risk_class",
                    "policy_context_hash",
                )
            }
            body = {
                "schema_version": "decision_receipt/2",
                "audit_id": AUDIT_ID,
                "agent_did": AGENT_DID,
                "action": receipt_request["action"],
                "resource": receipt_request["resource"],
                "environment": receipt_request["environment"],
                "decision": "ALLOW",
                "payload_hash": receipt_request["payload_hash"],
                "risk_class": "unknown",
                "policy_context_hash": "b" * 64,
                "client_risk_class": receipt_request["risk_class"],
                "client_policy_context_hash": receipt_request["policy_context_hash"],
                "install_clone_advisory": {
                    "ok": False,
                    "decision": "redirect",
                    "reason_code": "model_suggested_source",
                    "advisory_state": "review_recommended",
                    "live_enforcement": "HOLD",
                    "source_truth": {"decision": "redirect"},
                },
            }
            return {
                "audit_id": AUDIT_ID,
                "decision": "ALLOW",
                "decision_receipt_jcs": _sign_jcs(body),
            }

    agent = SignedAdvisoryReceiptAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    result = client.evaluate(_package_classification(config))
    assert result.decision == "ALLOW"
    assert result.receipt_body["install_clone_advisory"]["advisory_state"] == "review_recommended"


def test_avp_agent_rejects_raw_install_clone_context_before_post():
    config = _package_ask_backend_config()
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="raw-context", timeout=2.0)
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    from agentveil.exceptions import AVPValidationError

    posted = {"called": False}

    def mock_post(*_args, **_kwargs):
        posted["called"] = True
        raise AssertionError("must not post raw install_clone_context")

    # Bypass RuntimeGateClient validation by calling agent directly.
    with patch.object(httpx.Client, "post", side_effect=mock_post):
        with pytest.raises(AVPValidationError):
            agent.runtime_evaluate(
                action="redacted",
                resource="sha256:" + ("a" * 64),
                environment="unknown",
                delegation_receipt={"id": "grant"},
                payload_hash="sha256:" + ("c" * 64),
                risk_class="write",
                policy_context_hash="sha256:" + ("d" * 64),
                install_clone_context={
                    "operation": "install",
                    "source_ref": "https://evil.example/pkg.whl",
                    "source_ref_kind": "workspace_registry",
                    "user_pinned_source": False,
                    "intent_source": "user_direct",
                    "target_source": "workspace_registry",
                    "tool_source": "approved_registry",
                    "metadata_influence": "none",
                    "requested_package": "/Users/secret/proj",
                },
            )
    assert posted["called"] is False
    # Keep client path green for valid package classification.
    assert client is not None


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
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]
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
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]
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
    assert response["error"]["message"].startswith("Stopped by Runtime Gate:")
    assert "Approval will not help" in response["error"]["message"]
    assert response["error"]["data"]["status"] == "blocked"
    assert response["error"]["data"]["audit_id"] == AUDIT_ID
    assert SECRET not in client_out.getvalue()
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


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
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]
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
    assert response["error"]["message"] == APPROVAL_REQUIRED_USER_MESSAGE
    data = response["error"]["data"]
    assert data["status"] == "approval_required"
    assert data["reason"] == "runtime_gate_waiting_for_human_approval"
    assert data["decision"] == "WAITING_FOR_HUMAN_APPROVAL"
    assert data["audit_id"] == AUDIT_ID
    assert data["approval_id"] == "urn:uuid:approval"
    assert data["approval_possible"] is True
    assert data["retry_after_approval"] is True
    assert data["retry_contract"] == "same_tool_call"
    assert data["retry_same_tool_call"] is True
    assert data["approved_retry_requires_same_tool"] is True
    assert data["approved_retry_requires_same_resource"] is True
    assert data["approved_retry_requires_same_payload"] is True
    assert data["reason_code"] == "runtime_gate_waiting_for_human_approval"
    assert "without changing tool, target, or payload" in data["next_step"]
    assert SECRET not in client_out.getvalue()
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_unverified_receipt_is_rejected_without_downstream_execution(tmp_path):
    config = _config()
    agent = RecordingAgent(seed=OTHER_BACKEND_SEED)
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    passthrough, log_path = _passthrough(tmp_path, client, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_UNTRUSTED
    data = response["error"]["data"]
    assert data["status"] == "blocked"  # claim-check: allow bounded JSON-RPC status vocabulary in this runtime-gate test.
    assert data["reason"] == "untrusted_runtime_decision"
    assert data["reason_code"] == "untrusted_runtime_decision"
    assert data["approval_possible"] is False
    assert data["retry_after_approval"] is False
    assert "Proxy/runtime decision error" in response["error"]["message"]
    assert "Stopped by policy" not in response["error"]["message"]
    assert passthrough.security_events[-1] == {
        "type": "runtime_decision_untrusted",
        "action": "blocked",
        "reason": "untrusted_runtime_decision",
    }
    assert SECRET not in client_out.getvalue()
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


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
        # claim-check: allow bounded JSON-RPC status asserted by a downstream-negative outage regression.
        "status": "blocked",
        "reason": "runtime_gate_unavailable",
    }
    assert SECRET not in client_out.getvalue()
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_evaluate_accepts_decision_receipt_v3():
    config = _config()
    agent = FetchableRecordingAgentV3()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    result = client.evaluate(_classification(config))

    assert result.decision == "ALLOW"
    assert result.receipt_body["schema_version"] == "decision_receipt/3"
    assert result.receipt_body["@context"] == [DATA_INTEGRITY_CONTEXT]


def test_decision_receipt_v3_signed_by_untrusted_key_is_rejected():
    config = _config()
    agent = FetchableRecordingAgentV3(seed=OTHER_BACKEND_SEED)
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    with pytest.raises(RuntimeGateUntrustedError, match="not trusted"):
        client.evaluate(_classification(config))


def test_v3_export_bundle_embeds_and_strict_verifies(tmp_path):
    config = _config()
    agent = FetchableRecordingAgentV3(decision="ALLOW")
    gate = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    bundle_path = tmp_path / "evidence-bundle.json"
    with ApprovalEvidenceStore(tmp_path / "evidence.sqlite") as store:
        manager = ApprovalManager(
            evidence_store=store,
            approval_server=ApprovalServer(),
            config=config,
            client_id="pytest",
            session_id="session-v3-bundle",
        )
        passthrough, _log_path = _passthrough(tmp_path, gate, config, approval_manager=manager)
        client_out = io.StringIO()

        assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

        bundle = export_evidence_bundle(
            store,
            bundle_path,
            proxy_identity_did=AGENT_DID,
            trusted_signer_dids=[BACKEND_DID],
            receipt_fetcher=agent.get_decision_receipt,
        )

    # The bundle embeds the exact /3 receipt.
    embedded = next(iter(bundle["signed_receipts"].values()))
    assert json.loads(embedded)["schema_version"] == "decision_receipt/3"

    # Strict + externally pinned signer verifies the embedded /3 receipt.
    result = verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])
    assert result.valid is True
    assert result.signed_receipt_count == 1
    assert result.unverified_receipt_count == 0
    assert result.warnings == ()

    # Strict default with no external signer fails closed.
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle(bundle)


def test_waiting_immediate_retry_after_approve_post(tmp_path):
    """WAITING path + live-console race: POST approve then immediate retry."""

    import re

    config = _config()
    gate = StaticGate(RuntimeGateDecision(
        decision="WAITING_FOR_HUMAN_APPROVAL",
        audit_id=AUDIT_ID,
        approval_id="urn:uuid:approval",
        receipt_digest="aa" * 32,
        receipt_body={},
    ))
    with ApprovalEvidenceStore(tmp_path / "evidence.sqlite") as store:
        server = ApprovalServer()
        server.start()
        manager = ApprovalManager(
            evidence_store=store,
            approval_server=server,
            config=config,
            client_id=f"pytest:pid:{os.getpid()}",
            session_id="session-waiting-retry",
            cli_out=io.StringIO(),
            browser_open=lambda _url: False,
            wait_for_decision=False,
        )
        passthrough, _log_path = _passthrough(
            tmp_path, gate, config, approval_manager=manager
        )
        passthrough.start()
        try:
            first = passthrough.handle_client_line(_tool_call())
            assert first[0]["error"]["data"]["status"] == "approval_required"

            deadline = time.monotonic() + 2
            while not server.pending_prompts() and time.monotonic() < deadline:
                time.sleep(0.01)
            prompts = server.pending_prompts()
            assert prompts, "expected a pending approval prompt for the first call"
            parent_id = prompts[0].request_id
            with httpx.Client() as client:
                page = client.get(server.approval_url(parent_id))
                csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
                response = client.post(
                    server.approval_url(parent_id),
                    data={
                        "decision": "approve",
                        "csrf_token": csrf,
                        "approval_scope": "exact",
                    },
                )
            assert response.status_code == 200

            retry = passthrough.handle_client_line(_tool_call())
            assert "result" in retry[0], retry[0]
            assert retry[0]["result"]["content"][0]["text"] == "forwarded"
            assert server.pending_prompts() == []

            children = [
                record
                for record in store.list_records()
                if record.granted_by_request_id == parent_id
            ]
            assert len(children) == 1, "retry must reuse the grant, not open a new prompt"
            assert children[0].status == ApprovalStatus.EXECUTED.value
        finally:
            passthrough.stop()
            server.stop()


def test_public_wire_contract_fixture_is_public_safe_and_matches_runtime_gate_client():
    data = _public_wire_contract()
    env = data["request"]["environment"]

    assert data["schema_version"] == "avp.runtime_gate.public_wire_contract.v1"
    # claim-check: allow production is a finite public wire enum value.
    assert env["allowed_values"] == [
        "production",  # claim-check: allow canonical transport enum, not a readiness claim.
        "staging",
        "development",
        "unknown",
    ]
    assert env["default_client_value"] == "unknown"
    assert DEFAULT_RUNTIME_ENVIRONMENT == env["default_client_value"]
    assert CANONICAL_RUNTIME_ENVIRONMENTS == frozenset(env["allowed_values"])
    serialized = json.dumps(data, sort_keys=True)
    for marker in _FORBIDDEN_PRIVATE_MARKERS:
        assert marker not in serialized


def test_package_install_outbound_body_matches_public_wire_contract():
    config = _package_ask_backend_config()
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="wire-contract", timeout=2.0)
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    contract = _public_wire_contract()
    top_level = contract["request"]["top_level_fields"]
    allowed_top_level = set(top_level["required"]) | set(top_level["optional"])
    context_spec = contract["request"]["install_clone_context"]
    allowed_context = set(context_spec["required"]) | set(context_spec["optional"])
    slots = context_spec["metadata_evidence_slots"]
    allowed_slots = set(slots["allowed_slot_names"])
    allowed_slot_keys = set(slots["allowed_payload_keys"])
    captured: dict[str, object] = {}

    def mock_post(url, **kwargs):
        body = json.loads(kwargs["content"])
        captured["body"] = body
        receipt_request = {
            key: body[key]
            for key in (
                "action",
                "resource",
                "environment",
                "payload_hash",
                "risk_class",
                "policy_context_hash",
            )
        }
        receipt_jcs = _decision_receipt(receipt_request, decision="ALLOW")
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {
            "audit_id": AUDIT_ID,
            "decision": "ALLOW",
            "decision_receipt_jcs": receipt_jcs,
        }
        return response

    with patch.object(httpx.Client, "post", side_effect=mock_post):
        result = client.evaluate(_package_classification(config))

    assert result.decision == "ALLOW"
    body = captured["body"]
    assert body["environment"] == "unknown"
    assert set(body) <= allowed_top_level
    assert set(top_level["required"]).issubset(set(body))
    context = body["install_clone_context"]
    assert set(context) <= allowed_context
    for slot_name in allowed_slots:
        if slot_name not in context:
            continue
        assert set(context[slot_name]) <= allowed_slot_keys
    body_text = json.dumps(body, sort_keys=True)
    for forbidden in (
        "raw-secret-package-name",
        "/Users/secret",
        "https://",
        "sk_live",
        "mcp_proxy",
    ):
        assert forbidden not in body_text


@pytest.mark.parametrize(
    "environment",
    _public_wire_contract()["request"]["environment"]["allowed_values"],
)
def test_runtime_gate_accepts_contract_environment_values(environment):
    config = _config()
    agent = RecordingAgent()
    client = RuntimeGateClient(
        agent=agent,
        config=config,
        control_grant={"id": "grant"},
        environment=environment,
    )

    result = client.evaluate(_classification(config))

    assert result.decision == "ALLOW"
    assert agent.calls[0]["environment"] == environment


def test_runtime_gate_rejects_contract_invalid_mcp_proxy_environment_before_http():
    config = _config()
    agent = RecordingAgent()
    fixtures = _public_wire_contract()["invalid_request_fixtures"]
    invalid_fixture = next(item for item in fixtures if item["name"] == "legacy_mcp_proxy_environment")
    invalid = deepcopy(invalid_fixture["body_patch"])

    with pytest.raises(ValueError, match="environment invalid") as exc_info:
        RuntimeGateClient(
            agent=agent,
            config=config,
            control_grant={"id": "grant"},
            environment=invalid["environment"],
        )

    assert invalid["environment"] == "mcp_proxy"
    assert "mcp_proxy" not in str(exc_info.value)
    assert agent.calls == []


def test_package_install_rejects_unknown_metadata_slot_name_before_post():
    config = _package_ask_backend_config()
    agent = RecordingAgent()
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    classification = _package_classification(config)
    metadata = classification.backend_metadata()
    context = dict(metadata["install_clone_context"])
    context["raw_readme"] = {"signal_code": "install_hint"}

    class _MutableClassification:
        def backend_metadata(self):
            return {
                **metadata,
                "install_clone_context": context,
            }

    with pytest.raises(RuntimeGateUnavailableError, match="install_clone_context invalid"):
        client.evaluate(_MutableClassification())  # type: ignore[arg-type]
    assert agent.calls == []


def _paid_approval_projection(**overrides) -> dict:
    payload = {
        "schema_version": "paid_approval_center_projection/1",
        "projection_kind": "paid_active",
        "provider_status": "active",
        "plan_family": "builder",
        "private_provider_enabled": True,
        "core_fallback_active": False,
        "decision": "allow",
        "reason_code": "paid_provider_active",
        "selection_reason": "deterministic_precedence",
        "summary": "Paid policy reviewed this tool call.",
        "capability_labels": ["Tools call routing"],
        "activation_source": "public_activation_install",
        "paid_policy_tightened": False,
    }
    payload.update(overrides)
    return payload


class _PaidProjectionRecordingAgent(RecordingAgent):
    def __init__(
        self,
        *,
        projection: dict | None,
        inject_top_level: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.projection = projection
        self.inject_top_level = inject_top_level

    def runtime_evaluate(self, **kwargs):
        self.calls.append(kwargs)
        signed_projection = None if self.inject_top_level else self.projection
        response = {
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
                paid_approval_center_projection=signed_projection,
            ),
        }
        if self.inject_top_level and self.projection is not None:
            response["paid_approval_center_projection"] = self.projection
        return response


def test_runtime_gate_decision_carries_paid_approval_center_projection():
    config = _config()
    agent = _PaidProjectionRecordingAgent(
        decision="WAITING_FOR_HUMAN_APPROVAL",
        projection=_paid_approval_projection(),
    )
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    result = client.evaluate(_classification(config))

    assert result.decision == "WAITING_FOR_HUMAN_APPROVAL"
    assert result.paid_approval_center_projection is not None
    assert result.paid_approval_center_projection["projection_kind"] == "paid_active"
    assert result.paid_approval_center_projection["private_provider_enabled"] is True


def test_runtime_gate_ignores_unsigned_top_level_paid_approval_projection():
    config = _config()
    agent = _PaidProjectionRecordingAgent(
        decision="WAITING_FOR_HUMAN_APPROVAL",
        projection=_paid_approval_projection(),
        inject_top_level=True,
    )
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    result = client.evaluate(_classification(config))

    assert result.decision == "WAITING_FOR_HUMAN_APPROVAL"
    assert result.paid_approval_center_projection is None


def test_runtime_gate_omits_unsupported_paid_approval_projection_before_metadata():
    config = _config()
    agent = _PaidProjectionRecordingAgent(
        decision="WAITING_FOR_HUMAN_APPROVAL",
        projection=_paid_approval_projection(
            schema_version="paid_approval_center_projection/99",
        ),
    )
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    result = client.evaluate(_classification(config))

    assert result.decision == "WAITING_FOR_HUMAN_APPROVAL"
    assert result.paid_approval_center_projection is None


def test_runtime_gate_omits_malformed_paid_approval_projection_before_metadata():
    config = _config()
    agent = _PaidProjectionRecordingAgent(
        decision="WAITING_FOR_HUMAN_APPROVAL",
        projection=_paid_approval_projection(**{"customer_id": "cust_123"}),
    )
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    result = client.evaluate(_classification(config))

    assert result.decision == "WAITING_FOR_HUMAN_APPROVAL"
    assert result.paid_approval_center_projection is None


# ---------------------------------------------------------------------------
# Runtime Gate reached-4xx corrective:
# a reached HTTP 4xx is a bounded terminal rejection, not an availability
# outage. It does not invoke local fallback or reach downstream, and does not
# not worsen the circuit breaker. Timeout/connection/5xx keep the existing
# unavailable/fallback behavior.
# ---------------------------------------------------------------------------


class RaisingAgent:
    """Backend stub whose runtime_evaluate raises a preset SDK exception."""

    did = AGENT_DID

    def __init__(self, exc: Exception):
        self.exc = exc
        self.calls: list[dict] = []

    def runtime_evaluate(self, **kwargs):
        self.calls.append(kwargs)
        raise self.exc

    def get_decision_receipt(self, audit_id: str) -> str:
        raise AssertionError("no receipt fetch expected on a rejected request")


def _all_allow_fallback() -> dict:
    return {
        "read": "allow",
        "write": "allow",
        "destructive": "allow",
        # claim-check: allow "production" is a fallback risk-class key in test config.
        "production": "allow",
        "financial": "allow",
        "unknown": "allow",
    }


_REACHED_4XX_SDK_ERRORS = [
    AVPValidationError(f"validation {SECRET}", 400, SECRET),
    AVPAuthError(f"auth failed {SECRET}", 401, SECRET),
    AVPAuthError(f"forbidden {SECRET}", 403, SECRET),
    AVPNotFoundError(f"not found {SECRET}", 404, SECRET),
    AVPValidationError(f"conflict {SECRET}", 409, SECRET),
    AVPRateLimitError(f"rate limited {SECRET}"),
    AVPError(f"teapot {SECRET}", 418, SECRET),
]


@pytest.mark.parametrize(
    "exc",
    _REACHED_4XX_SDK_ERRORS,
    ids=[str(getattr(e, "status_code", "?")) for e in _REACHED_4XX_SDK_ERRORS],
)
def test_reached_4xx_becomes_terminal_rejection_without_raw_detail(exc):
    # Pre-fix behavior reproduced as the regression under test: any exception
    # from runtime_evaluate() (including a reached 4xx) was converted to
    # RuntimeGateUnavailableError and would enter local fallback. After the
    # corrective, a reached 4xx becomes a distinct terminal rejection.
    config = _config()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    agent = RaisingAgent(exc)
    client = RuntimeGateClient(
        agent=agent,
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )

    with pytest.raises(RuntimeGateRejectedError) as excinfo:
        client.evaluate(_classification(config))

    err = excinfo.value
    assert not isinstance(err, RuntimeGateUnavailableError)
    assert err.status_code == exc.status_code
    # No raw exception detail leaks through the sanitized error.
    assert str(err) == "runtime gate rejected the request"
    assert SECRET not in str(err)
    # A reached 4xx must not count as Runtime Gate unavailability.
    assert breaker.state_change_count == 0


def test_reached_4xx_does_not_worsen_circuit_breaker_availability():
    config = _config()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    rejecting = RuntimeGateClient(
        agent=RaisingAgent(AVPValidationError("bad", 400, "x")),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )

    with pytest.raises(RuntimeGateRejectedError):
        rejecting.evaluate(_classification(config))

    # failures_before_open=1, so any recorded failure would open the breaker.
    assert breaker.state_change_count == 0

    healthy = RuntimeGateClient(
        agent=RecordingAgent(decision="ALLOW"),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )
    assert healthy.evaluate(_classification(config)).decision == "ALLOW"


def test_reached_4xx_passthrough_denies_terminally_and_never_falls_back(tmp_path):
    # This config permits fallback for the exercised write risk class: if a reached 4xx entered
    # fallback, the write would be forwarded downstream. It must not.
    config = _config(fallback=_all_allow_fallback())
    agent = RaisingAgent(AVPValidationError(f"rejected {SECRET}", 400, SECRET))
    gate = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_REJECTED
    # claim-check: allow bounded JSON-RPC status vocabulary asserted by this downstream-negative regression.
    assert response["error"]["data"]["status"] == "blocked"
    assert response["error"]["data"]["reason"] == "runtime_gate_rejected"
    assert response["error"]["data"]["target_reached"] is False
    assert response["error"]["data"]["approval_possible"] is False
    assert SECRET not in client_out.getvalue()
    # The gate was actually reached...
    assert len(agent.calls) == 1
    # ...and downstream mutation count is exactly 0 (no tools/call forwarded).
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("timeout while waiting"),
        httpx.ConnectError("connection refused"),
        AVPServerError("server error", 500, "detail"),
        AVPServerError("bad gateway", 503, "detail"),
    ],
    ids=["timeout", "connection", "500", "503"],
)
def test_timeout_connection_and_5xx_remain_unavailable(exc):
    config = _config()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    client = RuntimeGateClient(
        agent=RaisingAgent(exc),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )

    with pytest.raises(RuntimeGateUnavailableError) as excinfo:
        client.evaluate(_classification(config))

    assert not isinstance(excinfo.value, RuntimeGateRejectedError)
    # Existing unavailable path still records a circuit-breaker failure.
    assert breaker.state_change_count == 1


def test_5xx_passthrough_still_uses_fallback(tmp_path):
    config = _config(fallback={"write": "block"})
    gate = RuntimeGateClient(
        agent=RaisingAgent(AVPServerError("server error", 500, "detail")),
        config=config,
        control_grant={"id": "grant"},
    )
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_UNAVAILABLE
    assert response["error"]["data"] == {
        # claim-check: allow bounded unavailable status vocabulary asserted by the preserved fallback regression.
        "status": "blocked",
        "reason": "runtime_gate_unavailable",
    }
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_signed_allow_receipt_still_verifies_after_rejection_path_added():
    config = _config()
    agent = RecordingAgent(decision="ALLOW")
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})

    assert client.evaluate(_classification(config)).decision == "ALLOW"


# ---------------------------------------------------------------------------
# Runtime Gate outage sandbox bypass corrective:
# a true Runtime Gate outage must not silently forward read-only sandbox MCP
# tools downstream. Only explicit operator-configured fallback may allow reads.
# ---------------------------------------------------------------------------


def _block_all_fallback() -> dict:
    return {
        "read": "block",
        "write": "block",
        "destructive": "block",
        # claim-check: allow "production" is a fallback risk-class key in test config.
        "production": "block",
        "financial": "block",
        "unknown": "block",
    }


def _sandbox_read_ask_backend_config(
    *,
    fallback: dict | None = None,
    server: str = "filesystem",
    tool: str = "read_file",
) -> ProxyConfig:
    payload = {
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": [BACKEND_DID],
        },
        "mode": "protect",
        "privacy": {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "approval": {},
        "policy": {
            "id": f"{server}-{tool}-ask-backend",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "read",
            "rules": [
                {
                    "id": f"ask-{server}-{tool}",
                    "source": "user",
                    "decision": "ask_backend",
                    "match": {"server": [server], "tool": [tool]},
                    "risk_class": "read",
                }
            ],
        },
        "downstream": {},
    }
    if fallback is not None:
        payload["fallback"] = fallback
    return ProxyConfig.from_dict(payload)


def _filesystem_downstream(tmp_path: Path, log_path: Path, *, tool: str = "read_file") -> Path:
    return write_downstream(
        tmp_path,
        filename="runtime_gate_filesystem_echo.py",
        tools=[tool_entry(tool)],
        call_result_text="forwarded",
    )


def _filesystem_passthrough(
    tmp_path: Path,
    gate: object,
    config: ProxyConfig,
    *,
    server_name: str = "filesystem",
    tool: str = "read_file",
    approval_manager: ApprovalManager | None = None,
) -> tuple[McpPassthrough, Path]:
    log_path = tmp_path / "downstream.log"
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_filesystem_downstream(tmp_path, log_path, tool=tool))),
            name=server_name,
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(config, server_name=server_name),
        runtime_gate_factory=lambda: gate,
        approval_manager=approval_manager,
    )
    return passthrough, log_path


def _sandbox_read_tool_call(
    *,
    tool: str = "read_file",
    path: str = "notes.txt",
    arguments: dict | None = None,
) -> str:
    params_arguments = arguments if arguments is not None else {"path": path}
    return _json_line({
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {"name": tool, "arguments": params_arguments},
    })


def _downstream_call_count(log_path: Path) -> int:
    if not log_path.exists():
        return 0
    return sum(1 for line in log_path.read_text(encoding="utf-8").splitlines() if line == "tools/call")


def test_outage_sandbox_read_fallback_block_denies_without_downstream(tmp_path):
    # Baseline before fix (confirmed this session): outage + sandbox read_file +
    # fallback.read=block still reached downstream via the automatic bypass helper.
    config = _sandbox_read_ask_backend_config(fallback=_block_all_fallback())
    gate = StaticGate(RuntimeGateUnavailableError(f"timed out while handling {SECRET}"))
    passthrough, log_path = _filesystem_passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_sandbox_read_tool_call(path=SECRET)), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_UNAVAILABLE
    assert response["error"]["message"] == "AVP Runtime Gate unavailable"
    assert response["error"]["data"] == {
        # claim-check: allow bounded JSON-RPC status asserted by a downstream-negative outage regression.
        "status": "blocked",
        "reason": "runtime_gate_unavailable",
    }
    assert SECRET not in client_out.getvalue()
    assert _downstream_call_count(log_path) == 0


def test_outage_sandbox_read_fallback_approval_requires_approval_without_downstream(tmp_path):
    config = _sandbox_read_ask_backend_config(fallback={"read": "approval"})
    gate = StaticGate(RuntimeGateUnavailableError("runtime gate outage"))
    passthrough, log_path = _filesystem_passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_sandbox_read_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    data = response["error"]["data"]
    assert data["status"] == "approval_required"
    assert data["reason"] == "runtime_gate_unavailable"
    assert data["approval_possible"] is True
    assert data["retry_after_approval"] is True
    assert _downstream_call_count(log_path) == 0


def test_outage_sandbox_read_fallback_explicit_allow_forwards_once(tmp_path):
    config = _sandbox_read_ask_backend_config(fallback={"read": "allow"})
    gate = StaticGate(RuntimeGateUnavailableError("runtime gate outage"))
    passthrough, log_path = _filesystem_passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_sandbox_read_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["result"] == {
        "content": [{"type": "text", "text": "forwarded"}],
    }
    assert _downstream_call_count(log_path) == 1


def test_outage_product_sandbox_list_workspace_fallback_block_denies_without_downstream(tmp_path):
    # Legacy bypass helper also matched exact server="product". Outage must not
    # silently forward SANDBOX_READ_ONLY_MCP_TOOLS without explicit fallback.
    config = _sandbox_read_ask_backend_config(
        fallback=_block_all_fallback(),
        server="product",
        tool="list_workspace",
    )
    gate = StaticGate(RuntimeGateUnavailableError(f"timed out while handling {SECRET}"))
    passthrough, log_path = _filesystem_passthrough(
        tmp_path,
        gate,
        config,
        server_name="product",
        tool="list_workspace",
    )
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_sandbox_read_tool_call(tool="list_workspace", arguments={})),
        client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_UNAVAILABLE
    assert response["error"]["message"] == "AVP Runtime Gate unavailable"
    assert response["error"]["data"] == {
        # claim-check: allow bounded JSON-RPC status asserted by a downstream-negative outage regression.
        "status": "blocked",
        "reason": "runtime_gate_unavailable",
    }
    assert SECRET not in client_out.getvalue()
    assert _downstream_call_count(log_path) == 0


def test_outage_product_sandbox_list_workspace_fallback_approval_without_downstream(tmp_path):
    config = _sandbox_read_ask_backend_config(
        fallback={"read": "approval"},
        server="product",
        tool="list_workspace",
    )
    gate = StaticGate(RuntimeGateUnavailableError("runtime gate outage"))
    passthrough, log_path = _filesystem_passthrough(
        tmp_path,
        gate,
        config,
        server_name="product",
        tool="list_workspace",
    )
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_sandbox_read_tool_call(tool="list_workspace", arguments={})),
        client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    data = response["error"]["data"]
    assert data["status"] == "approval_required"
    assert data["reason"] == "runtime_gate_unavailable"
    assert data["approval_possible"] is True
    assert data["retry_after_approval"] is True
    assert _downstream_call_count(log_path) == 0


def test_outage_product_sandbox_list_workspace_fallback_explicit_allow_forwards_once(tmp_path):
    config = _sandbox_read_ask_backend_config(
        fallback={"read": "allow"},
        server="product",
        tool="list_workspace",
    )
    gate = StaticGate(RuntimeGateUnavailableError("runtime gate outage"))
    passthrough, log_path = _filesystem_passthrough(
        tmp_path,
        gate,
        config,
        server_name="product",
        tool="list_workspace",
    )
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_sandbox_read_tool_call(tool="list_workspace", arguments={})),
        client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["result"] == {
        "content": [{"type": "text", "text": "forwarded"}],
    }
    assert _downstream_call_count(log_path) == 1


def test_outage_non_sandbox_write_fallback_unchanged(tmp_path):
    config = _config(fallback={"write": "block"})
    gate = StaticGate(RuntimeGateUnavailableError(f"timed out while handling {SECRET}"))
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_UNAVAILABLE
    assert response["error"]["data"] == {
        # claim-check: allow bounded JSON-RPC status asserted by a downstream-negative outage regression.
        "status": "blocked",
        "reason": "runtime_gate_unavailable",
    }
    assert _downstream_call_count(log_path) == 0


def test_reached_4xx_sandbox_read_still_terminal_without_downstream(tmp_path):
    config = _sandbox_read_ask_backend_config(fallback={"read": "allow"})
    agent = RaisingAgent(AVPValidationError(f"rejected {SECRET}", 400, SECRET))
    gate = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    passthrough, log_path = _filesystem_passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_sandbox_read_tool_call(path=SECRET)), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_REJECTED
    assert response["error"]["data"]["reason"] == "runtime_gate_rejected"
    assert SECRET not in client_out.getvalue()
    assert _downstream_call_count(log_path) == 0


@pytest.mark.parametrize(
    "server_name",
    ["github", "fake-filesystem"],
)
def test_outage_fake_sandbox_labels_do_not_auto_bypass(tmp_path, server_name: str):
    # Tool name alone must not reopen downstream during outage. Only explicit
    # fallback.read=allow may forward a read-risk call.
    config = _sandbox_read_ask_backend_config(fallback=_block_all_fallback())
    gate = StaticGate(RuntimeGateUnavailableError("runtime gate outage"))
    passthrough, log_path = _filesystem_passthrough(
        tmp_path,
        gate,
        config,
        server_name=server_name,
    )
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_sandbox_read_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_UNAVAILABLE
    assert response["error"]["data"]["reason"] == "runtime_gate_unavailable"
    assert _downstream_call_count(log_path) == 0
