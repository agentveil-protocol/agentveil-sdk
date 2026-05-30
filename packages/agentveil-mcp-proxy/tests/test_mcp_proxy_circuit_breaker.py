"""P8 tests for Runtime Gate circuit breaker behavior."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import time

import base58
import jcs
import pytest
from nacl.signing import SigningKey

from agentveil.delegation import _public_key_to_did
from agentveil_mcp_proxy.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.cli import doctor_proxy, init_proxy
import agentveil_mcp_proxy.policy as policy_module
from agentveil_mcp_proxy.passthrough import (
    DownstreamConfig,
    JSONRPC_APPROVAL_REQUIRED,
    JSONRPC_RUNTIME_GATE_UNAVAILABLE,
    McpPassthrough,
)
from agentveil_mcp_proxy.policy import ProxyConfig, ProxyConfigError, builtin_policy_pack
from agentveil_mcp_proxy.runtime_gate import (
    RuntimeGateClient,
    RuntimeGateUnavailableError,
    RuntimeGateUntrustedError,
)


BACKEND_SEED = bytes.fromhex("11" * 32)
OTHER_BACKEND_SEED = bytes.fromhex("22" * 32)
AGENT_SEED = bytes.fromhex("44" * 32)
BACKEND_DID = _public_key_to_did(bytes(SigningKey(BACKEND_SEED).verify_key))
AGENT_DID = _public_key_to_did(bytes(SigningKey(AGENT_SEED).verify_key))
SECRET = "SECRET_CIRCUIT_PAYLOAD"
AUDIT_ID = "urn:uuid:11111111-1111-4111-8111-111111111111"
TEST_PASSPHRASE = "correct horse battery staple"


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


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


def _config(*, fallback: dict | None = None, circuit_breaker: dict | None = None) -> ProxyConfig:
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
    }
    if circuit_breaker is not None:
        payload["circuit_breaker"] = circuit_breaker
    return ProxyConfig.from_dict(payload)


def _classification(config: ProxyConfig):
    return ToolCallClassifier(config, server_name="github").classify(
        tool="create_issue",
        arguments={
            "owner": "acme",
            "repo": "private-repo",
            "title": SECRET,
            "token": "ghp_secret",
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


def _decision_receipt_body(request: dict) -> dict:
    return {
        "schema_version": "decision_receipt/2",
        "audit_id": AUDIT_ID,
        "agent_did": AGENT_DID,
        "action": request["action"],
        "resource": request["resource"],
        "environment": request["environment"],
        "decision": "ALLOW",
        "payload_hash": request["payload_hash"],
        "client_risk_class": request["risk_class"],
        "client_policy_context_hash": request["policy_context_hash"],
    }


def _decision_receipt(request: dict, *, seed: bytes = BACKEND_SEED) -> str:
    return _sign_jcs(_decision_receipt_body(request), seed=seed)


class RecordingAgent:
    did = AGENT_DID

    def __init__(self, *, seed: bytes = BACKEND_SEED, fail: bool = False):
        self.seed = seed
        self.fail = fail
        self.calls: list[dict] = []

    def runtime_evaluate(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise TimeoutError("backend unavailable")
        return {
            "audit_id": AUDIT_ID,
            "decision": "ALLOW",
            "decision_receipt_jcs": _decision_receipt(kwargs, seed=self.seed),
        }


_UNTRUSTED_FIELD_MISMATCHES = {
    "field_action_mismatch": "action",
    "field_resource_mismatch": "resource",
    "field_environment_mismatch": "environment",
    "field_payload_hash_mismatch": "payload_hash",
    "field_client_risk_class_mismatch": "client_risk_class",
    "field_client_policy_context_hash_mismatch": "client_policy_context_hash",
}

_UNTRUSTED_FIELD_MISSING = {
    "field_action_missing": "action",
    "field_resource_missing": "resource",
    "field_environment_missing": "environment",
    "field_payload_hash_missing": "payload_hash",
    "field_client_risk_class_missing": "client_risk_class",
    "field_client_policy_context_hash_missing": "client_policy_context_hash",
}


class UntrustedReceiptAgent:
    did = AGENT_DID

    def __init__(self, scenario: str):
        self.scenario = scenario
        self.calls: list[dict] = []
        self.receipt_jcs = ""

    def runtime_evaluate(self, **kwargs):
        self.calls.append(kwargs)
        if self.scenario == "receipt_missing_response":
            return {"decision": "ALLOW"}

        body = _decision_receipt_body(kwargs)
        response = {"audit_id": AUDIT_ID, "decision": "ALLOW"}
        seed = BACKEND_SEED

        if self.scenario == "receipt_fetch_empty":
            self.receipt_jcs = ""
            return response
        if self.scenario == "signature_fail":
            seed = OTHER_BACKEND_SEED
        elif self.scenario == "schema_unsupported":
            body["schema_version"] = "decision_receipt/99"
        elif self.scenario == "decision_unsupported":
            body["decision"] = "UNKNOWN"
            response["decision"] = "UNKNOWN"
        elif self.scenario == "audit_id_missing":
            body.pop("audit_id")
        elif self.scenario == "response_decision_mismatch":
            response["decision"] = "BLOCK"
        elif self.scenario == "response_audit_id_mismatch":
            response["audit_id"] = "urn:uuid:22222222-2222-4222-8222-222222222222"
        elif self.scenario == "agent_did_mismatch":
            body["agent_did"] = BACKEND_DID
        elif self.scenario in _UNTRUSTED_FIELD_MISMATCHES:
            body[_UNTRUSTED_FIELD_MISMATCHES[self.scenario]] = "mismatch"
        elif self.scenario in _UNTRUSTED_FIELD_MISSING:
            body.pop(_UNTRUSTED_FIELD_MISSING[self.scenario])
        elif self.scenario != "empty_trusted_signer_dids":
            raise AssertionError(f"unhandled untrusted scenario: {self.scenario}")

        self.receipt_jcs = _sign_jcs(body, seed=seed)
        return {**response, "decision_receipt_jcs": self.receipt_jcs}

    def get_decision_receipt(self, audit_id: str) -> str:
        assert audit_id == AUDIT_ID
        return self.receipt_jcs


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


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


def _echo_downstream(tmp_path: Path, log_path: Path) -> Path:
    script = tmp_path / "circuit_echo.py"
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
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"ok": True}}), flush=True)
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


def test_circuit_starts_closed():
    breaker = CircuitBreaker()

    assert breaker.state == CircuitState.CLOSED
    assert breaker.state_change_count == 0


def test_circuit_has_no_dead_cooldown_remaining_property():
    assert not hasattr(CircuitBreaker(), "cooldown_" + "remaining_seconds")


def test_events_deque_bounded_under_repeated_state_changes():
    clock = Clock()
    breaker = CircuitBreaker(
        CircuitBreakerConfig(failures_before_open=1, cooldown_seconds=1),
        time_func=clock,
    )

    for _ in range(334):
        breaker.record_failure()
        clock.advance(1)
        breaker.before_call()
        breaker.record_success()

    assert len(breaker._events) == 1000
    events = breaker.drain_events()
    assert events[0]["state_change_count"] == 3
    assert events[-1]["state_change_count"] == 1002


def test_circuit_opens_after_threshold_failures():
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=2))

    breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED

    breaker.record_failure()

    assert breaker.state == CircuitState.OPEN
    assert breaker.drain_events()[-1]["type"] == "circuit_breaker_opened"


def test_circuit_failure_window_excludes_old_failures():
    clock = Clock()
    breaker = CircuitBreaker(
        CircuitBreakerConfig(failures_before_open=2, window_seconds=10),
        time_func=clock,
    )

    breaker.record_failure()
    clock.advance(11)
    breaker.record_failure()

    assert breaker.state == CircuitState.CLOSED


def test_record_success_clears_failure_window_in_closed_state():
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=5))

    for _ in range(3):
        breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED

    breaker.record_success()

    for _ in range(4):
        breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED


def test_circuit_open_raises_runtime_gate_unavailable_immediately():
    config = _config()
    agent = RecordingAgent()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    breaker.record_failure()
    client = RuntimeGateClient(
        agent=agent,
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )

    started = time.monotonic()
    with pytest.raises(RuntimeGateUnavailableError):
        client.evaluate(_classification(config))

    assert time.monotonic() - started < 0.1
    assert agent.calls == []


def test_circuit_open_transitions_to_half_open_after_cooldown():
    clock = Clock()
    breaker = CircuitBreaker(
        CircuitBreakerConfig(failures_before_open=1, cooldown_seconds=10),
        time_func=clock,
    )
    breaker.record_failure()
    clock.advance(10)

    breaker.before_call()

    assert breaker.state == CircuitState.HALF_OPEN


def test_circuit_half_open_one_success_transitions_to_closed():
    clock = Clock()
    breaker = CircuitBreaker(
        CircuitBreakerConfig(failures_before_open=1, cooldown_seconds=1),
        time_func=clock,
    )
    breaker.record_failure()
    clock.advance(1)
    breaker.before_call()

    breaker.record_success()

    assert breaker.state == CircuitState.CLOSED


def test_circuit_half_open_failure_reopens_circuit():
    clock = Clock()
    breaker = CircuitBreaker(
        CircuitBreakerConfig(failures_before_open=1, cooldown_seconds=1),
        time_func=clock,
    )
    breaker.record_failure()
    clock.advance(1)
    breaker.before_call()

    breaker.record_failure()

    assert breaker.state == CircuitState.OPEN


def test_circuit_half_open_test_count_configurable():
    clock = Clock()
    breaker = CircuitBreaker(
        CircuitBreakerConfig(
            failures_before_open=1,
            cooldown_seconds=1,
            half_open_test_count=2,
        ),
        time_func=clock,
    )
    breaker.record_failure()
    clock.advance(1)
    breaker.before_call()

    breaker.record_success()
    assert breaker.state == CircuitState.HALF_OPEN

    breaker.record_success()
    assert breaker.state == CircuitState.CLOSED


def test_runtime_gate_client_records_success_to_circuit_breaker():
    config = _config()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    client = RuntimeGateClient(
        agent=RecordingAgent(),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )

    assert client.evaluate(_classification(config)).decision == "ALLOW"

    assert breaker.state == CircuitState.CLOSED
    assert breaker.state_change_count == 0


def test_runtime_gate_client_records_unavailable_failure_to_circuit_breaker():
    config = _config()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    client = RuntimeGateClient(
        agent=RecordingAgent(fail=True),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )

    with pytest.raises(RuntimeGateUnavailableError):
        client.evaluate(_classification(config))

    assert breaker.state == CircuitState.OPEN


def test_runtime_gate_client_does_not_count_untrusted_errors_as_circuit_failures():
    config = _config()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    client = RuntimeGateClient(
        agent=RecordingAgent(seed=OTHER_BACKEND_SEED),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )

    with pytest.raises(RuntimeGateUntrustedError):
        client.evaluate(_classification(config))

    assert breaker.state == CircuitState.CLOSED
    assert breaker.state_change_count == 0


@pytest.mark.parametrize("scenario", [
    "receipt_missing_response",
    "receipt_fetch_empty",
    "signature_fail",
    "schema_unsupported",
    "decision_unsupported",
    "audit_id_missing",
    "response_decision_mismatch",
    "response_audit_id_mismatch",
    "agent_did_mismatch",
    "field_action_mismatch",
    "field_resource_mismatch",
    "field_environment_mismatch",
    "field_payload_hash_mismatch",
    "field_client_risk_class_mismatch",
    "field_client_policy_context_hash_mismatch",
    "field_action_missing",
    "field_resource_missing",
    "field_environment_missing",
    "field_payload_hash_missing",
    "field_client_risk_class_missing",
    "field_client_policy_context_hash_missing",
    "empty_trusted_signer_dids",
])
def test_untrusted_boundary_does_not_trip_circuit_breaker_across_all_paths(scenario):
    config = _config()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    client = RuntimeGateClient(
        agent=UntrustedReceiptAgent(scenario),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )
    if scenario == "empty_trusted_signer_dids":
        client.trusted_signer_dids = ()

    with pytest.raises(RuntimeGateUntrustedError):
        client.evaluate(_classification(config))

    assert breaker.state == CircuitState.CLOSED
    assert breaker.state_change_count == 0


def test_open_circuit_skips_backend_call_entirely():
    config = _config()
    agent = RecordingAgent()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    breaker.record_failure()
    client = RuntimeGateClient(
        agent=agent,
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )

    with pytest.raises(RuntimeGateUnavailableError):
        client.evaluate(_classification(config))

    assert agent.calls == []


def test_circuit_breaker_config_validates_positive_integers():
    for field in (
        "failures_before_open",
        "window_seconds",
        "cooldown_seconds",
        "half_open_test_count",
    ):
        with pytest.raises(ProxyConfigError):
            _config(circuit_breaker={field: 0})
        with pytest.raises(ProxyConfigError):
            _config(circuit_breaker={field: True})


@pytest.mark.parametrize("field", [
    "failures_before_open",
    "window_seconds",
    "cooldown_seconds",
    "half_open_test_count",
])
@pytest.mark.parametrize("invalid_value", [-1, 5.0, 5.5, None, "5", [], {}])
def test_circuit_breaker_config_rejects_invalid_types_and_values(field, invalid_value):
    with pytest.raises(ProxyConfigError):
        _config(circuit_breaker={field: invalid_value})


def test_circuit_breaker_config_rejects_unknown_fields():
    with pytest.raises(ProxyConfigError, match="unknown"):
        _config(circuit_breaker={"unknown": 1})


def test_circuit_breaker_config_defaults_when_block_absent():
    config = _config()

    assert config.circuit_breaker.failures_before_open == 5
    assert config.circuit_breaker.window_seconds == 60
    assert config.circuit_breaker.cooldown_seconds == 30
    assert config.circuit_breaker.half_open_test_count == 1


def test_proxy_circuit_breaker_config_in_policy_all():
    assert "ProxyCircuitBreakerConfig" in policy_module.__all__


def test_open_circuit_cascades_to_existing_fallback_policy_per_risk_class(tmp_path):
    config = _config(fallback={"write": "allow"})
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    breaker.record_failure()
    gate = RuntimeGateClient(
        agent=RecordingAgent(),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    assert _responses(client_out.getvalue())[0]["result"] == {"ok": True}
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/call"]


def test_open_circuit_returns_sanitized_error_in_block_fallback(tmp_path):
    config = _config(fallback={"write": "block"})
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    breaker.record_failure()
    gate = RuntimeGateClient(
        agent=RecordingAgent(),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_RUNTIME_GATE_UNAVAILABLE
    assert response["error"]["data"] == {
        "status": "blocked",
        "reason": "runtime_gate_unavailable",
    }
    assert SECRET not in client_out.getvalue()
    assert not log_path.exists()


def _read_ask_backend_config(*, fallback: dict | None = None) -> ProxyConfig:
    """Config where any tool is read-risk and routes to ASK_BACKEND, so the
    Runtime Gate unavailable-fallback is exercised for a read tool call."""
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
            "id": "read-ask-backend",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "read",
            "rules": [],
        },
        "downstream": {},
    }
    if fallback is not None:
        payload["fallback"] = fallback
    return ProxyConfig.from_dict(payload)


def _read_tool_call() -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {"name": "get_file_contents", "arguments": {"path": SECRET}},
    })


def test_open_circuit_read_fallback_defaults_to_approval_not_forwarded(tmp_path):
    # B5 hardening: with the fallback omitted, a read tool call during a Gate
    # outage requires approval instead of being silently forwarded.
    config = _read_ask_backend_config()
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    breaker.record_failure()
    gate = RuntimeGateClient(
        agent=RecordingAgent(),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_read_tool_call()), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"] == {
        "status": "approval_required",
        "reason": "runtime_gate_unavailable",
    }
    assert not log_path.exists()
    assert SECRET not in client_out.getvalue()


def test_open_circuit_read_fallback_explicit_allow_forwards(tmp_path):
    # The remaining ALLOW path is an explicit operator-configured risk: when an
    # operator opts into read: allow, a read is forwarded during a Gate outage.
    config = _read_ask_backend_config(fallback={"read": "allow"})
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    breaker.record_failure()
    gate = RuntimeGateClient(
        agent=RecordingAgent(),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )
    passthrough, log_path = _passthrough(tmp_path, gate, config)
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO(_read_tool_call()), client_out) == 0

    assert _responses(client_out.getvalue())[0]["result"] == {"ok": True}
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/call"]


def test_circuit_state_change_emits_security_event_without_payload_data(tmp_path):
    config = _config(fallback={"write": "block"})
    breaker = CircuitBreaker(CircuitBreakerConfig(failures_before_open=1))
    gate = RuntimeGateClient(
        agent=RecordingAgent(fail=True),
        config=config,
        control_grant={"id": "grant"},
        circuit_breaker=breaker,
    )
    passthrough, _log_path = _passthrough(tmp_path, gate, config)

    assert passthrough.run_stdio(io.StringIO(_tool_call()), io.StringIO()) == 0

    rendered = json.dumps(passthrough.security_events, sort_keys=True)
    assert "circuit_breaker_opened" in rendered
    assert SECRET not in rendered
    assert "private-repo" not in rendered


def test_doctor_reports_circuit_state(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    out = io.StringIO()

    assert doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out) == 0

    assert "OK: circuit breaker thresholds" in out.getvalue()
    assert "closed" not in out.getvalue()
