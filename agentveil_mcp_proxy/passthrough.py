"""MCP stdio pass-through for the MCP proxy.

P5 applies local policy to MCP ``tools/call`` requests and, for
``ask_backend``, calls AVP Runtime Gate before forwarding. Approval UI, WAL
evidence, and circuit breaking remain future slices.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
from typing import Any, Callable, Deque, Mapping, TextIO

from agentveil_mcp_proxy.classification import ClassifiedToolCall, ToolCallClassifier
from agentveil_mcp_proxy.policy import PolicyDecision, ProxyConfig
from agentveil_mcp_proxy.runtime_gate import (
    DECISION_ALLOW,
    DECISION_BLOCK,
    DECISION_WAITING,
    RuntimeGateDecision,
    RuntimeGateError,
    RuntimeGateUnavailableError,
    RuntimeGateUntrustedError,
)


JSONRPC_VERSION = "2.0"
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_DOWNSTREAM_ERROR = -32000
JSONRPC_POLICY_BLOCKED = -32010
JSONRPC_APPROVAL_REQUIRED = -32011
JSONRPC_RUNTIME_GATE_UNAVAILABLE = -32012
JSONRPC_RUNTIME_GATE_UNTRUSTED = -32013
SAFE_ENV_KEYS = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
)


class PassthroughError(RuntimeError):
    """Raised for local MCP pass-through startup/runtime failures."""


@dataclass(frozen=True)
class DownstreamConfig:
    """Downstream stdio MCP server launch config."""

    command: str
    args: tuple[str, ...] = ()
    name: str = "downstream"
    env: Mapping[str, str] | None = None
    env_passthrough: tuple[str, ...] = ()

    @classmethod
    def from_proxy_config(cls, config: ProxyConfig) -> "DownstreamConfig":
        data = dict(config.downstream)
        command = data.get("command")
        if not isinstance(command, str) or not command.strip():
            raise PassthroughError("downstream.command is required to start MCP passthrough")

        args = data.get("args", [])
        if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
            raise PassthroughError("downstream.args must be a list of strings")

        name = data.get("name", "downstream")
        if not isinstance(name, str) or not name.strip():
            raise PassthroughError("downstream.name must be a non-empty string")

        env = data.get("env")
        if env is not None:
            if not isinstance(env, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in env.items()
            ):
                raise PassthroughError("downstream.env must be an object of string values")

        env_passthrough = data.get("env_passthrough", [])
        if not isinstance(env_passthrough, list) or any(
            not isinstance(item, str) or not item
            for item in env_passthrough
        ):
            raise PassthroughError("downstream.env_passthrough must be a list of strings")

        allowed = {"name", "command", "args", "env", "env_passthrough"}
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise PassthroughError(f"downstream has unknown field(s): {', '.join(unknown)}")

        return cls(
            command=command,
            args=tuple(args),
            name=name,
            env=env,
            env_passthrough=tuple(env_passthrough),
        )


def jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    *,
    data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC error response without sensitive diagnostics."""

    error: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data:
        error["data"] = dict(data)
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": error,
    }


def _blocked_error(
    request_id: Any,
    message: str,
    *,
    reason: str,
    decision: RuntimeGateDecision | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {"status": "blocked", "reason": reason}
    if decision is not None:
        data["decision"] = decision.decision
        if decision.audit_id is not None:
            data["audit_id"] = decision.audit_id
    return jsonrpc_error(request_id, JSONRPC_POLICY_BLOCKED, message, data=data)


def _approval_required_error(
    request_id: Any,
    *,
    reason: str,
    message: str = "approval required",
    decision: RuntimeGateDecision | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {"status": "approval_required", "reason": reason}
    if decision is not None:
        data["decision"] = decision.decision
        if decision.audit_id is not None:
            data["audit_id"] = decision.audit_id
        if decision.approval_id is not None:
            data["approval_id"] = decision.approval_id
    return jsonrpc_error(request_id, JSONRPC_APPROVAL_REQUIRED, message, data=data)


class McpPassthrough:
    """Synchronous stdio JSON-RPC pass-through to one downstream MCP server."""

    def __init__(
        self,
        downstream: DownstreamConfig,
        *,
        cwd: Path | None = None,
        classifier: ToolCallClassifier | None = None,
        on_tool_call: Callable[[ClassifiedToolCall], None] | None = None,
        runtime_gate_factory: Callable[[], Any] | None = None,
    ):
        self.downstream = downstream
        self.cwd = cwd
        self.classifier = classifier
        self.on_tool_call = on_tool_call
        self.runtime_gate_factory = runtime_gate_factory
        self.config = getattr(classifier, "config", None)
        self.process: subprocess.Popen[str] | None = None
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._stderr_bytes = 0
        self._stopping = False
        self._responses: dict[str, list[dict[str, Any]]] = {}
        self._downstream_error: PassthroughError | None = None
        self._stdout_condition = threading.Condition()
        self._notification_writer: Callable[[Mapping[str, Any]], None] | None = None
        self._write_lock = threading.Lock()
        self._classifier_errors = 0
        self._runtime_gate: Any | None = None
        self._runtime_gate_errors = 0
        self._security_events: Deque[Mapping[str, Any]] = deque(maxlen=1000)

    @property
    def stderr_bytes_drained(self) -> int:
        """Number of downstream stderr bytes drained without echoing content."""

        return self._stderr_bytes

    @property
    def classifier_errors(self) -> int:
        """Number of classifier/callback failures skipped without blocking passthrough."""

        return self._classifier_errors

    @property
    def runtime_gate_errors(self) -> int:
        """Number of Runtime Gate failures handled without leaking request data."""

        return self._runtime_gate_errors

    @property
    def security_events(self) -> tuple[Mapping[str, Any], ...]:
        """Sanitized in-memory security events for P5 failure handling."""

        return tuple(self._security_events)

    def start(self) -> None:
        """Start the downstream MCP server subprocess."""

        if self.process is not None:
            return

        env = self._minimal_env()
        for key in self.downstream.env_passthrough:
            if key in os.environ:
                env[key] = os.environ[key]
        if self.downstream.env:
            env.update(self.downstream.env)

        try:
            start_kwargs: dict[str, Any] = {}
            if os.name == "posix":
                start_kwargs["start_new_session"] = True
            self.process = subprocess.Popen(
                [self.downstream.command, *self.downstream.args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
                cwd=str(self.cwd) if self.cwd else None,
                env=env,
                **start_kwargs,
            )
        except OSError as exc:
            raise PassthroughError("downstream startup failed") from exc

        self._stderr_thread = threading.Thread(
            target=self._drain_stderr,
            name=f"agentveil-mcp-proxy-{self.downstream.name}-stderr",
            daemon=True,
        )
        self._stderr_thread.start()
        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            name=f"agentveil-mcp-proxy-{self.downstream.name}-stdout",
            daemon=True,
        )
        self._stdout_thread.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        """Terminate downstream cleanly, then kill if it does not exit."""

        self._stopping = True
        proc = self.process
        if proc is None:
            return

        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass

        if proc.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGTERM)
                else:
                    proc.terminate()
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
                proc.wait(timeout=timeout)
            except (OSError, ProcessLookupError):
                pass

        try:
            if proc.stdout:
                proc.stdout.close()
        except OSError:
            pass

        if self._stderr_thread:
            self._stderr_thread.join(timeout=timeout)
        if self._stdout_thread:
            self._stdout_thread.join(timeout=timeout)

    def run_stdio(self, client_in: TextIO, client_out: TextIO) -> int:
        """Run pass-through until client input EOF or a fatal startup error."""

        self._notification_writer = lambda message: self._write_client(client_out, message)
        self.start()
        try:
            for raw_line in client_in:
                if not raw_line.strip():
                    continue
                responses = self.handle_client_line(raw_line)
                for response in responses:
                    self._write_client(client_out, response)
            return 0
        finally:
            self.stop()

    def handle_client_line(self, raw_line: str) -> list[dict[str, Any]]:
        """Handle one newline-delimited JSON-RPC client message."""

        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError:
            return [jsonrpc_error(None, JSONRPC_PARSE_ERROR, "invalid JSON-RPC message")]

        if not isinstance(message, dict):
            return [jsonrpc_error(None, JSONRPC_INVALID_REQUEST, "JSON-RPC message must be an object")]

        request_id = message.get("id")
        has_id = "id" in message
        if message.get("jsonrpc") != JSONRPC_VERSION or not isinstance(message.get("method"), str):
            return [jsonrpc_error(request_id, JSONRPC_INVALID_REQUEST, "invalid JSON-RPC request")]

        try:
            classification = self._classify_for_local_metadata(message)
            policy_error = self._policy_error_response(classification, request_id)
            if policy_error is not None:
                return [policy_error] if has_id else []
            self._send_downstream(message)
            if not has_id:
                return []
            return [self._wait_downstream_response(request_id)]
        except PassthroughError:
            if not has_id:
                return []
            return [jsonrpc_error(
                request_id,
                JSONRPC_DOWNSTREAM_ERROR,
                "downstream MCP server unavailable",
            )]

    def _classify_for_local_metadata(self, message: Mapping[str, Any]) -> ClassifiedToolCall | None:
        if self.classifier is None:
            return None
        try:
            classification = self.classifier.classify_jsonrpc(message)
        except Exception:
            # P4 classification is advisory only. Future evidence slices can
            # consume this counter without logging sensitive request content.
            self._classifier_errors += 1
            return None
        if classification is not None and self.on_tool_call is not None:
            try:
                self.on_tool_call(classification)
            except Exception:
                self._classifier_errors += 1
        return classification

    def _policy_error_response(
        self,
        classification: ClassifiedToolCall | None,
        request_id: Any,
    ) -> dict[str, Any] | None:
        if classification is None:
            return None
        if not isinstance(classification, ClassifiedToolCall):
            return None
        evaluation = classification.policy_evaluation
        decision = evaluation.decision
        if decision in {PolicyDecision.ALLOW, PolicyDecision.OBSERVE}:
            return None
        if decision is PolicyDecision.BLOCK:
            return _blocked_error(
                request_id,
                "blocked by local MCP policy",
                reason="local_policy_block",
            )
        if decision is PolicyDecision.APPROVAL:
            return _approval_required_error(
                request_id,
                reason="local_approval_required",
            )
        if decision is PolicyDecision.ASK_BACKEND:
            if self.runtime_gate_factory is None:
                return None
            return self._runtime_gate_error_response(classification, request_id)
        return _blocked_error(
            request_id,
            "blocked by MCP policy",
            reason="unknown_policy_decision",
        )

    def _runtime_gate_error_response(
        self,
        classification: ClassifiedToolCall,
        request_id: Any,
    ) -> dict[str, Any] | None:
        try:
            decision = self._runtime_gate_client().evaluate(classification)
        except RuntimeGateUntrustedError:
            self._runtime_gate_errors += 1
            self._record_security_event({
                "type": "runtime_decision_untrusted",
                "action": "blocked",
                "reason": "untrusted_runtime_decision",
            })
            return jsonrpc_error(
                request_id,
                JSONRPC_RUNTIME_GATE_UNTRUSTED,
                "runtime decision receipt untrusted",
                data={"status": "blocked", "reason": "untrusted_runtime_decision"},
            )
        except RuntimeGateUnavailableError:
            self._runtime_gate_errors += 1
            return self._fallback_error_response(classification, request_id)
        except RuntimeGateError:
            self._runtime_gate_errors += 1
            return self._fallback_error_response(classification, request_id)

        if decision.decision == DECISION_ALLOW:
            return None
        if decision.decision == DECISION_WAITING:
            return _approval_required_error(
                request_id,
                reason="runtime_gate_waiting_for_human_approval",
                decision=decision,
            )
        if decision.decision == DECISION_BLOCK:
            return _blocked_error(
                request_id,
                "blocked by AVP Runtime Gate",
                reason="runtime_gate_block",
                decision=decision,
            )
        self._runtime_gate_errors += 1
        return jsonrpc_error(
            request_id,
            JSONRPC_RUNTIME_GATE_UNTRUSTED,
            "runtime decision unsupported",
            data={"status": "blocked", "reason": "unsupported_runtime_decision"},
        )

    def _fallback_error_response(
        self,
        classification: ClassifiedToolCall,
        request_id: Any,
    ) -> dict[str, Any] | None:
        config = self.config
        fallback = (
            config.fallback.for_risk(classification.risk_class)
            if isinstance(config, ProxyConfig)
            else PolicyDecision.BLOCK
        )
        if fallback is PolicyDecision.ALLOW:
            return None
        if fallback is PolicyDecision.APPROVAL:
            return _approval_required_error(
                request_id,
                reason="runtime_gate_unavailable",
                message="approval required because AVP Runtime Gate is unavailable",
            )
        return jsonrpc_error(
            request_id,
            JSONRPC_RUNTIME_GATE_UNAVAILABLE,
            "AVP Runtime Gate unavailable",
            data={"status": "blocked", "reason": "runtime_gate_unavailable"},
        )

    def _runtime_gate_client(self) -> Any:
        if self._runtime_gate is None:
            if self.runtime_gate_factory is None:
                raise RuntimeGateUnavailableError("runtime gate not configured")
            self._runtime_gate = self.runtime_gate_factory()
        return self._runtime_gate

    def _record_security_event(self, event: Mapping[str, Any]) -> None:
        self._security_events.append(dict(event))

    def _send_downstream(self, message: Mapping[str, Any]) -> None:
        proc = self._require_process()
        if proc.poll() is not None or proc.stdin is None:
            raise PassthroughError("downstream process is not running")
        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        try:
            proc.stdin.write(payload + "\n")
            proc.stdin.flush()
        except OSError as exc:
            raise PassthroughError("downstream write failed") from exc

    def _wait_downstream_response(self, expected_id: Any) -> dict[str, Any]:
        response_key = self._id_key(expected_id)
        with self._stdout_condition:
            while True:
                queued = self._responses.get(response_key)
                if queued:
                    response = queued.pop(0)
                    if not queued:
                        self._responses.pop(response_key, None)
                    return response
                if self._downstream_error is not None:
                    raise self._downstream_error
                self._stdout_condition.wait()

    def _read_stdout(self) -> None:
        proc = self._require_process()
        if proc.stdout is None:
            self._set_downstream_error(PassthroughError("downstream stdout unavailable"))
            return

        while True:
            try:
                raw_line = proc.stdout.readline()
            except OSError as exc:
                if not self._stopping:
                    self._set_downstream_error(PassthroughError("downstream read failed"))
                return
            if raw_line == "":
                if not self._stopping and proc.poll() is not None:
                    self._set_downstream_error(PassthroughError("downstream process exited"))
                elif not self._stopping:
                    self._set_downstream_error(PassthroughError("downstream closed stdout"))
                return
            try:
                response = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                self._set_downstream_error(PassthroughError("downstream sent invalid JSON"))
                return
            if not isinstance(response, dict):
                self._set_downstream_error(PassthroughError("downstream sent non-object JSON"))
                return
            if self._is_server_notification(response):
                if self._notification_writer is not None:
                    self._notification_writer(response)
                continue
            if "id" in response:
                with self._stdout_condition:
                    self._responses.setdefault(self._id_key(response.get("id")), []).append(response)
                    self._stdout_condition.notify_all()

    def _write_client(self, client_out: TextIO, message: Mapping[str, Any]) -> None:
        with self._write_lock:
            client_out.write(json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n")
            client_out.flush()

    def _drain_stderr(self) -> None:
        proc = self.process
        if proc is None or proc.stderr is None:
            return
        try:
            while True:
                chunk = proc.stderr.read(1024)
                if not chunk:
                    break
                self._stderr_bytes += len(chunk.encode("utf-8", errors="replace"))
        except OSError:
            return

    def _require_process(self) -> subprocess.Popen[str]:
        if self.process is None:
            raise PassthroughError("downstream process has not started")
        return self.process

    def _minimal_env(self) -> dict[str, str]:
        return {key: os.environ[key] for key in SAFE_ENV_KEYS if key in os.environ}

    def _is_server_notification(self, message: Mapping[str, Any]) -> bool:
        return (
            message.get("jsonrpc") == JSONRPC_VERSION
            and "id" not in message
            and isinstance(message.get("method"), str)
        )

    def _id_key(self, value: Any) -> str:
        return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    def _set_downstream_error(self, error: PassthroughError) -> None:
        with self._stdout_condition:
            if not self._stopping:
                self._downstream_error = error
            self._stdout_condition.notify_all()
