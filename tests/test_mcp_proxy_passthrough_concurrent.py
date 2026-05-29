"""P9a concurrency coverage for MCP passthrough primitives."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable, Mapping

import pytest

from agentveil_mcp_proxy.approval import ApprovalOutcome
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.passthrough import (
    DownstreamConfig,
    DownstreamTimeoutError,
    McpPassthrough,
)
from agentveil_mcp_proxy.policy import ProxyConfig
from agentveil_mcp_proxy.runtime_gate import (
    DECISION_BLOCK,
    RuntimeGateDecision,
    RuntimeGateUnavailableError,
)

from tests.mcp_fake_downstream import seed_tool_schemas, tool_entry


def _json_line(message: dict[str, Any]) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _tool_call(request_id: str, tool: str = "write_file") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"path": f"/tmp/{request_id}.txt"}},
    })


def _config(
    *,
    default_decision: str,
    default_risk_class: str = "write",
    fallback: dict[str, str] | None = None,
) -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": ["did:key:test-signer"],
        },
        "mode": "protect",
        "privacy": {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "fallback": fallback or {
            "read": "block",
            "write": "block",
            "destructive": "block",
            "production": "block",
            "financial": "block",
            "unknown": "block",
        },
        "approval": {},
        "policy": {
            "id": "concurrency-test",
            "policy_schema_version": 1,
            "default_decision": default_decision,
            "default_risk_class": default_risk_class,
            "rules": [],
        },
        "downstream": {},
    })


def _classifier(config: ProxyConfig) -> ToolCallClassifier:
    return ToolCallClassifier(config, server_name="concurrent")


def _idle_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "idle_downstream.py"
    script.write_text(
        """
import sys

for _line in sys.stdin:
    pass
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _run_threads(count: int, worker: Callable[[int], None]) -> None:
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def guarded(index: int) -> None:
        try:
            worker(index)
        except BaseException as exc:
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=guarded, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5.0)
    assert all(not thread.is_alive() for thread in threads)
    assert not errors


class _RecordingApprovalManager:
    def __init__(self) -> None:
        self.results: list[tuple[str, str]] = []
        self.errors: list[tuple[str, str]] = []
        self._lock = threading.Lock()
        self.b_done = threading.Event()

    def request_approval(
        self,
        classification: Any,
        *,
        runtime_decision: Any = None,
        reason: str,
    ) -> ApprovalOutcome:
        return ApprovalOutcome(
            f"request-{classification.tool}",
            "approved",
            f"approved-{classification.tool}",
        )

    def record_execution_result(self, outcome: ApprovalOutcome, response: dict[str, Any]) -> None:
        with self._lock:
            self.results.append((outcome.request_id, str(response["id"])))
        if outcome.request_id == "request-tool-b":
            self.b_done.set()

    def record_execution_error(self, outcome: ApprovalOutcome, error_class: str) -> None:
        with self._lock:
            self.errors.append((outcome.request_id, error_class))


class _CoordinatedApprovalPassthrough(McpPassthrough):
    def __init__(self, approval_manager: _RecordingApprovalManager) -> None:
        super().__init__(
            DownstreamConfig(command=sys.executable, args=(), name="coordinated"),
            classifier=_classifier(_config(default_decision="approval")),
            approval_manager=approval_manager,
        )
        self.approval_manager = approval_manager
        self.a_waiting = threading.Event()

    def _send_downstream(self, message: Mapping[str, Any]) -> None:
        return None

    def _wait_downstream_response(self, expected_id: Any) -> dict[str, Any]:
        if expected_id == "a":
            self.a_waiting.set()
            assert self.approval_manager.b_done.wait(timeout=2.0)
            raise DownstreamTimeoutError("downstream response timed out")
        assert expected_id == "b"
        assert self.a_waiting.wait(timeout=2.0)
        return {"jsonrpc": "2.0", "id": expected_id, "result": {"ok": True}}


def test_concurrent_handle_client_line_does_not_misattribute_approval_outcome() -> None:
    manager = _RecordingApprovalManager()
    passthrough = _CoordinatedApprovalPassthrough(manager)
    # Subject is concurrent approval attribution, not schema discovery: model
    # the steady state where tool schemas are already known so the internal
    # tools/list probe is a cache hit and does not perturb the coordinated
    # downstream-response sequencing this test asserts.
    seed_tool_schemas(passthrough, [tool_entry("tool-a"), tool_entry("tool-b")])
    responses: dict[str, list[dict[str, Any]]] = {}
    errors: list[BaseException] = []

    def run_request(request_id: str, tool: str) -> None:
        try:
            responses[request_id] = passthrough.handle_client_line(_tool_call(request_id, tool))
        except BaseException as exc:
            errors.append(exc)

    thread_a = threading.Thread(target=run_request, args=("a", "tool-a"))
    thread_a.start()
    assert passthrough.a_waiting.wait(timeout=2.0)
    thread_b = threading.Thread(target=run_request, args=("b", "tool-b"))
    thread_b.start()
    thread_a.join(timeout=5.0)
    thread_b.join(timeout=5.0)

    assert not thread_a.is_alive()
    assert not thread_b.is_alive()
    assert not errors
    assert manager.results == [("request-tool-b", "b")]
    assert manager.errors == [("request-tool-a", "downstream_response_timeout")]
    assert responses["a"][0]["error"]["data"]["reason"] == "downstream_response_timeout"
    assert responses["b"] == [{"jsonrpc": "2.0", "id": "b", "result": {"ok": True}}]


def test_approval_outcome_is_per_request_local_not_instance_state() -> None:
    passthrough = McpPassthrough(DownstreamConfig(command=sys.executable, args=(), name="plain"))

    assert not hasattr(passthrough, "_current_approval_outcome")


class _FragmentingStdin:
    def __init__(self) -> None:
        self._chars: list[str] = []

    def write(self, value: str) -> int:
        for char in value:
            self._chars.append(char)
            time.sleep(0.0001)
        return len(value)

    def flush(self) -> None:
        return None

    def value(self) -> str:
        return "".join(self._chars)


class _FakeProcess:
    def __init__(self, stdin: _FragmentingStdin) -> None:
        self.stdin = stdin

    def poll(self) -> None:
        return None


def test_concurrent_downstream_writes_produce_complete_json_lines() -> None:
    stdin = _FragmentingStdin()
    passthrough = McpPassthrough(DownstreamConfig(command=sys.executable, args=(), name="downstream"))
    passthrough.process = _FakeProcess(stdin)  # type: ignore[assignment]

    def worker(index: int) -> None:
        passthrough._send_downstream({
            "jsonrpc": "2.0",
            "id": f"call-{index}",
            "method": "tools/list",
        })

    _run_threads(4, worker)

    lines = stdin.value().splitlines()
    assert len(lines) == 4
    parsed = [json.loads(line) for line in lines]
    assert sorted(message["id"] for message in parsed) == [
        "call-0",
        "call-1",
        "call-2",
        "call-3",
    ]


class _ExplodingClassifier:
    config = None

    def classify_jsonrpc(self, message: Mapping[str, Any]) -> None:
        raise RuntimeError("classification failed")


class _ImmediatePassthrough(McpPassthrough):
    def _send_downstream(self, message: Mapping[str, Any]) -> None:
        return None

    def _wait_downstream_response(self, expected_id: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": expected_id, "result": {"ok": True}}


class _TimeoutPassthrough(_ImmediatePassthrough):
    def _wait_downstream_response(self, expected_id: Any) -> dict[str, Any]:
        raise DownstreamTimeoutError("downstream response timed out")


def test_concurrent_counter_increments_record_all_classifier_errors() -> None:
    passthrough = _ImmediatePassthrough(
        DownstreamConfig(command=sys.executable, args=(), name="classifier"),
        classifier=_ExplodingClassifier(),
    )

    _run_threads(100, lambda index: passthrough.handle_client_line(_tool_call(f"call-{index}")))

    assert passthrough.classifier_errors == 100


class _UnavailableGate:
    def evaluate(self, classification: Any) -> RuntimeGateDecision:
        raise RuntimeGateUnavailableError("runtime gate unavailable")


def test_concurrent_counter_increments_record_all_runtime_gate_errors(tmp_path: Path) -> None:
    gate = _UnavailableGate()
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_idle_downstream(tmp_path))),
            name="gate-errors",
        ),
        classifier=_classifier(_config(default_decision="ask_backend")),
        runtime_gate_factory=lambda: gate,
    )
    # Subject is runtime-gate error counting, not schema discovery: seed the
    # schema cache so the idle downstream is not probed and each call reaches
    # the runtime gate.
    seed_tool_schemas(passthrough, [tool_entry("write_file")])
    try:
        passthrough.start()
        _run_threads(100, lambda index: passthrough.handle_client_line(_tool_call(f"call-{index}")))
    finally:
        passthrough.stop()

    assert passthrough.runtime_gate_errors == 100


def test_concurrent_counter_increments_record_all_downstream_timeouts() -> None:
    passthrough = _TimeoutPassthrough(
        DownstreamConfig(command=sys.executable, args=(), name="timeouts")
    )
    # Subject is downstream-timeout counting on the forwarded tools/call, not
    # schema discovery: seed the cache so the timeout is attributed to the
    # tools/call wait rather than the internal schema probe.
    seed_tool_schemas(passthrough, [tool_entry("write_file")])

    _run_threads(100, lambda index: passthrough.handle_client_line(_tool_call(f"call-{index}")))

    assert passthrough.downstream_timeouts == 100


def test_runtime_gate_initialized_eagerly_in_start(tmp_path: Path) -> None:
    gate = object()
    calls = 0

    def factory() -> object:
        nonlocal calls
        calls += 1
        return gate

    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_idle_downstream(tmp_path))),
            name="eager-gate",
        ),
        runtime_gate_factory=factory,
    )
    try:
        passthrough.start()
        assert passthrough._runtime_gate is gate
        assert calls == 1
    finally:
        passthrough.stop()


class _BlockingGate:
    def evaluate(self, classification: Any) -> RuntimeGateDecision:
        return RuntimeGateDecision(
            decision=DECISION_BLOCK,
            audit_id="audit-concurrency",
            approval_id=None,
            receipt_digest="sha256:" + "1" * 64,
            receipt_body={},
        )


def test_concurrent_first_call_does_not_double_init_runtime_gate(tmp_path: Path) -> None:
    gate = _BlockingGate()
    calls = 0
    calls_lock = threading.Lock()

    def factory() -> _BlockingGate:
        nonlocal calls
        with calls_lock:
            calls += 1
        return gate

    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_idle_downstream(tmp_path))),
            name="single-init-gate",
        ),
        classifier=_classifier(_config(default_decision="ask_backend")),
        runtime_gate_factory=factory,
    )
    try:
        passthrough.start()
        _run_threads(20, lambda index: passthrough.handle_client_line(_tool_call(f"call-{index}")))
    finally:
        passthrough.stop()

    assert calls == 1


def test_eager_init_factory_exception_surfaces_lazily_on_evaluate(tmp_path: Path) -> None:
    error = RuntimeGateUnavailableError("stored startup failure")

    def factory() -> object:
        raise error

    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_idle_downstream(tmp_path))),
            name="stored-error-gate",
        ),
        runtime_gate_factory=factory,
    )
    try:
        passthrough.start()
        with pytest.raises(RuntimeGateUnavailableError, match="stored startup failure") as exc:
            passthrough._runtime_gate_client()
        assert exc.value is error
    finally:
        passthrough.stop()
