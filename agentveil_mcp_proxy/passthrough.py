"""MCP stdio pass-through for the MCP proxy.

P6 applies local policy to MCP ``tools/call`` requests and, for
``ask_backend``, calls AVP Runtime Gate before forwarding. Approval-required
decisions can be routed through the local approval manager before downstream
execution. Runtime Gate circuit breaker state changes are recorded as sanitized
security events.

Lifecycle behavior by platform:
  - Linux: downstream starts in its own process group and receives SIGTERM via
    ``prctl(PR_SET_PDEATHSIG)`` if the proxy process dies before ``stop()``.
  - Windows: downstream is assigned to a Job Object configured with
    ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` so the kernel terminates it when the
    proxy process exits.
  - macOS: graceful shutdown terminates the downstream process group, but a
    force-killed proxy can leave downstream running. Run the proxy under
    launchd or another supervisor when macOS ungraceful-termination cleanup is
    required.
"""

from __future__ import annotations

import codecs
from collections import deque
import ctypes
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Deque, Mapping, TextIO

from agentveil_mcp_proxy.approval import ApprovalFlowError, ApprovalOutcome
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
JSONRPC_DOWNSTREAM_TIMEOUT = -32014
DEFAULT_DOWNSTREAM_RESPONSE_TIMEOUT_SECONDS = 30.0
MAX_DOWNSTREAM_MESSAGE_BYTES = 1 * 1024 * 1024
MAX_CLIENT_MESSAGE_BYTES = 1 * 1024 * 1024
MAX_PENDING_RESPONSES = 1000
DEFAULT_TIMED_OUT_ID_RETENTION_SECONDS = 600.0
_ENV_PASSTHROUGH_BLOCKED_PREFIXES = ("AVP_",)
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
_LINUX_PR_SET_PDEATHSIG = 1
_LINUX_LIBC = ctypes.CDLL(None, use_errno=True) if sys.platform.startswith("linux") else None


def _linux_parent_death_preexec() -> None:
    """Ask Linux to SIGTERM the child if the proxy process disappears."""

    if _LINUX_LIBC is None:
        return
    result = _LINUX_LIBC.prctl(_LINUX_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    if os.getppid() == 1:
        os.kill(os.getpid(), signal.SIGTERM)


class _WindowsJobObject:
    """Kill-on-close Windows Job Object wrapper for one downstream process."""

    def __init__(self, process_handle: int):
        if os.name != "nt":
            raise RuntimeError("Windows Job Objects are only available on Windows")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self._kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        self._kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._kernel32.SetInformationJobObject.restype = ctypes.c_int
        self._kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        self._kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self._kernel32.CloseHandle.restype = ctypes.c_int
        self._handle = self._create_job()
        try:
            self._configure_kill_on_close()
            self._assign(process_handle)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        handle = self._handle
        if handle:
            self._handle = 0
            self._kernel32.CloseHandle(handle)

    def _create_job(self) -> int:
        handle = self._kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def _configure_kill_on_close(self) -> None:
        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x00002000
        ok = self._kernel32.SetInformationJobObject(
            self._handle,
            9,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def _assign(self, process_handle: int) -> None:
        ok = self._kernel32.AssignProcessToJobObject(self._handle, process_handle)
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())


class PassthroughError(RuntimeError):
    """Raised for local MCP pass-through startup/runtime failures."""


class DownstreamTimeoutError(PassthroughError):
    """Raised when downstream stays alive but does not answer one request."""


@dataclass(frozen=True)
class DownstreamConfig:
    """Downstream stdio MCP server launch config."""

    command: str
    args: tuple[str, ...] = ()
    name: str = "downstream"
    env: Mapping[str, str] | None = None
    env_passthrough: tuple[str, ...] = ()
    response_timeout_seconds: float = DEFAULT_DOWNSTREAM_RESPONSE_TIMEOUT_SECONDS

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
        for item in env_passthrough:
            if any(item.startswith(prefix) for prefix in _ENV_PASSTHROUGH_BLOCKED_PREFIXES):
                raise PassthroughError(
                    f"downstream.env_passthrough cannot forward {item!r}: "
                    "AVP_* prefix is reserved for proxy-internal secrets"
                )

        response_timeout = data.get(
            "response_timeout_seconds",
            DEFAULT_DOWNSTREAM_RESPONSE_TIMEOUT_SECONDS,
        )
        if (
            not isinstance(response_timeout, (int, float))
            or isinstance(response_timeout, bool)
            or not math.isfinite(response_timeout)
            or response_timeout <= 0
        ):
            raise PassthroughError("downstream.response_timeout_seconds must be a positive number")

        allowed = {
            "name",
            "command",
            "args",
            "env",
            "env_passthrough",
            "response_timeout_seconds",
        }
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise PassthroughError(f"downstream has unknown field(s): {', '.join(unknown)}")

        return cls(
            command=command,
            args=tuple(args),
            name=name,
            env=env,
            env_passthrough=tuple(env_passthrough),
            response_timeout_seconds=float(response_timeout),
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


def _read_bounded_line(client_in: TextIO, max_bytes: int) -> tuple[str | None, bool]:
    read = getattr(client_in, "read", None)
    if not callable(read):
        try:
            raw_line = next(client_in)  # type: ignore[arg-type]
        except StopIteration:
            return None, False
        raw_bytes = raw_line.encode("utf-8", errors="replace")
        if not raw_line.endswith("\n") or len(raw_bytes.rstrip(b"\n")) > max_bytes:
            return "", True
        return raw_line, False

    chunks: list[str] = []
    byte_count = 0
    while True:
        char = read(1)
        if char == "":
            if chunks:
                return "", True
            return None, False
        if char == "\n":
            return "".join(chunks) + "\n", False
        char_size = len(char.encode("utf-8", errors="replace"))
        if byte_count + char_size > max_bytes:
            _discard_line_remainder(client_in)
            return "", True
        chunks.append(char)
        byte_count += char_size


def _discard_line_remainder(client_in: TextIO) -> None:
    read = getattr(client_in, "read", None)
    if not callable(read):
        return
    while True:
        char = read(1)
        if char in {"", "\n"}:
            return


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
        approval_manager: Any | None = None,
    ):
        self.downstream = downstream
        self.cwd = cwd
        self.classifier = classifier
        self.on_tool_call = on_tool_call
        self.runtime_gate_factory = runtime_gate_factory
        self.approval_manager = approval_manager
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
        self._downstream_stdin_lock = threading.Lock()
        self._counters_lock = threading.Lock()
        self._classifier_errors = 0
        self._runtime_gate: Any | None = None
        self._runtime_gate_startup_error: Exception | None = None
        self._runtime_gate_errors = 0
        self._downstream_timeouts = 0
        self._client_oversized_messages = 0
        self._unsolicited_downstream_responses = 0
        self._security_events: Deque[Mapping[str, Any]] = deque(maxlen=1000)
        self._inflight_ids: set[str] = set()
        self._timed_out_response_ids: dict[str, float] = {}
        self._windows_job: _WindowsJobObject | None = None

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
    def downstream_timeouts(self) -> int:
        """Number of downstream requests that timed out without leaking payload data."""

        return self._downstream_timeouts

    @property
    def client_oversized_messages(self) -> int:
        """Number of oversized or unterminated client messages rejected."""

        return self._client_oversized_messages

    @property
    def unsolicited_downstream_responses(self) -> int:
        """Number of downstream responses dropped for unknown client request IDs."""

        return self._unsolicited_downstream_responses

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
            if sys.platform.startswith("linux"):
                start_kwargs["preexec_fn"] = _linux_parent_death_preexec
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
            if os.name == "nt":
                self._windows_job = _WindowsJobObject(int(self.process._handle))
        except (OSError, subprocess.SubprocessError) as exc:
            if self.process is not None and self.process.poll() is None:
                try:
                    self.process.kill()
                except OSError:
                    pass
            raise PassthroughError("downstream startup failed") from exc

        self._initialize_runtime_gate()

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
        if self._windows_job is not None:
            self._windows_job.close()
            self._windows_job = None

    def run_stdio(self, client_in: TextIO, client_out: TextIO) -> int:
        """Run pass-through until client input EOF or a fatal startup error."""

        self._notification_writer = lambda message: self._write_client(client_out, message)
        self.start()
        try:
            while True:
                raw_line, rejected = _read_bounded_line(client_in, MAX_CLIENT_MESSAGE_BYTES)
                if rejected:
                    self._increment_client_oversized_messages()
                    self._write_client(
                        client_out,
                        jsonrpc_error(
                            None,
                            JSONRPC_INVALID_REQUEST,
                            "client request exceeds maximum size",
                        ),
                    )
                    continue
                if raw_line is None:
                    break
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

        approval_outcome: ApprovalOutcome | None = None
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
            policy_error, approval_outcome = self._policy_error_response(classification, request_id)
            if policy_error is not None:
                return [policy_error] if has_id else []
            response_key = self._register_inflight_id(request_id) if has_id else None
            try:
                self._send_downstream(message)
                if not has_id:
                    return []
                response = self._wait_downstream_response(request_id)
                self._record_approval_result(approval_outcome, response)
                return [response]
            finally:
                if response_key is not None:
                    self._unregister_inflight_id(response_key)
        except DownstreamTimeoutError:
            self._increment_downstream_timeouts()
            self._record_approval_error(approval_outcome, "downstream_response_timeout")
            if not has_id:
                return []
            return [jsonrpc_error(
                request_id,
                JSONRPC_DOWNSTREAM_TIMEOUT,
                "downstream MCP server response timed out",
                data={"status": "timeout", "reason": "downstream_response_timeout"},
            )]
        except PassthroughError:
            self._record_approval_error(approval_outcome, "downstream_unavailable")
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
            self._increment_classifier_errors()
            return None
        if classification is not None and self.on_tool_call is not None:
            try:
                self.on_tool_call(classification)
            except Exception:
                self._increment_classifier_errors()
        return classification

    def _policy_error_response(
        self,
        classification: ClassifiedToolCall | None,
        request_id: Any,
    ) -> tuple[dict[str, Any] | None, ApprovalOutcome | None]:
        if classification is None:
            return None, None
        if not isinstance(classification, ClassifiedToolCall):
            return None, None
        evaluation = classification.policy_evaluation
        decision = evaluation.decision
        if decision in {PolicyDecision.ALLOW, PolicyDecision.OBSERVE}:
            return None, None
        if decision is PolicyDecision.BLOCK:
            return _blocked_error(
                request_id,
                "blocked by local MCP policy",
                reason="local_policy_block",
            ), None
        if decision is PolicyDecision.APPROVAL:
            return self._approval_flow_response(
                classification,
                request_id,
                reason="local_approval_required",
            )
        if decision is PolicyDecision.ASK_BACKEND:
            if self.runtime_gate_factory is None:
                return None, None
            return self._runtime_gate_error_response(classification, request_id)
        return _blocked_error(
            request_id,
            "blocked by MCP policy",
            reason="unknown_policy_decision",
        ), None

    def _runtime_gate_error_response(
        self,
        classification: ClassifiedToolCall,
        request_id: Any,
    ) -> tuple[dict[str, Any] | None, ApprovalOutcome | None]:
        try:
            decision = self._runtime_gate_client().evaluate(classification)
        except RuntimeGateUntrustedError:
            self._increment_runtime_gate_errors()
            self._record_runtime_gate_events()
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
            ), None
        except RuntimeGateUnavailableError:
            self._increment_runtime_gate_errors()
            self._record_runtime_gate_events()
            return self._fallback_error_response(classification, request_id)
        except RuntimeGateError:
            self._increment_runtime_gate_errors()
            self._record_runtime_gate_events()
            return self._fallback_error_response(classification, request_id)
        self._record_runtime_gate_events()

        if decision.decision == DECISION_ALLOW:
            return None, None
        if decision.decision == DECISION_WAITING:
            return self._approval_flow_response(
                classification,
                request_id,
                reason="runtime_gate_waiting_for_human_approval",
                runtime_decision=decision,
            )
        if decision.decision == DECISION_BLOCK:
            return _blocked_error(
                request_id,
                "blocked by AVP Runtime Gate",
                reason="runtime_gate_block",
                decision=decision,
            ), None
        self._increment_runtime_gate_errors()
        return jsonrpc_error(
            request_id,
            JSONRPC_RUNTIME_GATE_UNTRUSTED,
            "runtime decision unsupported",
            data={"status": "blocked", "reason": "unsupported_runtime_decision"},
        ), None

    def _fallback_error_response(
        self,
        classification: ClassifiedToolCall,
        request_id: Any,
    ) -> tuple[dict[str, Any] | None, ApprovalOutcome | None]:
        config = self.config
        fallback = (
            config.fallback.for_risk(classification.risk_class)
            if isinstance(config, ProxyConfig)
            else PolicyDecision.BLOCK
        )
        if fallback is PolicyDecision.ALLOW:
            return None, None
        if fallback is PolicyDecision.APPROVAL:
            return self._approval_flow_response(
                classification,
                request_id,
                reason="runtime_gate_unavailable",
                message="approval required because AVP Runtime Gate is unavailable",
            )
        return jsonrpc_error(
            request_id,
            JSONRPC_RUNTIME_GATE_UNAVAILABLE,
            "AVP Runtime Gate unavailable",
            data={"status": "blocked", "reason": "runtime_gate_unavailable"},
        ), None

    def _approval_flow_response(
        self,
        classification: ClassifiedToolCall,
        request_id: Any,
        *,
        reason: str,
        message: str = "approval required",
        runtime_decision: RuntimeGateDecision | None = None,
    ) -> tuple[dict[str, Any] | None, ApprovalOutcome | None]:
        if self.approval_manager is None:
            return _approval_required_error(
                request_id,
                reason=reason,
                message=message,
                decision=runtime_decision,
            ), None
        try:
            outcome = self.approval_manager.request_approval(
                classification,
                runtime_decision=runtime_decision,
                reason=reason,
            )
        except ApprovalFlowError:
            return jsonrpc_error(
                request_id,
                JSONRPC_APPROVAL_REQUIRED,
                "approval unavailable",
                data={"status": "blocked", "reason": "approval_evidence_unavailable"},
            ), None
        if outcome.approved:
            return None, outcome
        if outcome.status == "expired":
            return jsonrpc_error(
                request_id,
                JSONRPC_APPROVAL_REQUIRED,
                "approval timed out",
                data={"status": "timeout", "reason": outcome.reason},
            ), None
        return _blocked_error(
            request_id,
            "blocked by approval decision",
            reason=outcome.reason,
        ), None

    def _record_approval_result(
        self,
        outcome: ApprovalOutcome | None,
        response: dict[str, Any],
    ) -> None:
        if outcome is None or self.approval_manager is None:
            return
        self.approval_manager.record_execution_result(outcome, response)

    def _record_approval_error(self, outcome: ApprovalOutcome | None, error_class: str) -> None:
        if outcome is None or self.approval_manager is None:
            return
        self.approval_manager.record_execution_error(outcome, error_class)

    def _runtime_gate_client(self) -> Any:
        if self._runtime_gate is None:
            if self._runtime_gate_startup_error is not None:
                raise self._runtime_gate_startup_error
            raise RuntimeGateUnavailableError("runtime gate not configured")
        return self._runtime_gate

    def _initialize_runtime_gate(self) -> None:
        if self.runtime_gate_factory is None or self._runtime_gate is not None:
            return
        try:
            self._runtime_gate = self.runtime_gate_factory()
            self._runtime_gate_startup_error = None
        except Exception as exc:
            self._runtime_gate_startup_error = exc

    def _record_runtime_gate_events(self) -> None:
        gate = self._runtime_gate
        drain = getattr(gate, "drain_circuit_events", None)
        if not callable(drain):
            return
        try:
            for event in drain():
                self._record_security_event(event)
        except Exception:
            return

    def _record_security_event(self, event: Mapping[str, Any]) -> None:
        self._security_events.append(dict(event))

    def _send_downstream(self, message: Mapping[str, Any]) -> None:
        proc = self._require_process()
        if proc.poll() is not None or proc.stdin is None:
            raise PassthroughError("downstream process is not running")
        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        try:
            with self._downstream_stdin_lock:
                proc.stdin.write(payload + "\n")
                proc.stdin.flush()
        except OSError as exc:
            raise PassthroughError("downstream write failed") from exc

    def _increment_classifier_errors(self) -> None:
        with self._counters_lock:
            self._classifier_errors += 1

    def _increment_runtime_gate_errors(self) -> None:
        with self._counters_lock:
            self._runtime_gate_errors += 1

    def _increment_downstream_timeouts(self) -> None:
        with self._counters_lock:
            self._downstream_timeouts += 1

    def _increment_client_oversized_messages(self) -> None:
        with self._counters_lock:
            self._client_oversized_messages += 1

    def _increment_unsolicited_downstream_responses(self) -> None:
        with self._counters_lock:
            self._unsolicited_downstream_responses += 1

    def _register_inflight_id(self, request_id: Any) -> str:
        response_key = self._id_key(request_id)
        with self._stdout_condition:
            self._inflight_ids.add(response_key)
        return response_key

    def _unregister_inflight_id(self, response_key: str) -> None:
        with self._stdout_condition:
            self._inflight_ids.discard(response_key)
            self._prune_pending_responses_locked()

    def _wait_downstream_response(self, expected_id: Any) -> dict[str, Any]:
        response_key = self._id_key(expected_id)
        deadline = time.monotonic() + self.downstream.response_timeout_seconds
        with self._stdout_condition:
            while True:
                self._prune_timed_out_ids_locked()
                queued = self._responses.get(response_key)
                if queued:
                    response = queued.pop(0)
                    if not queued:
                        self._responses.pop(response_key, None)
                    return response
                if self._downstream_error is not None:
                    raise self._downstream_error
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._timed_out_response_ids[
                        response_key
                    ] = time.monotonic() + DEFAULT_TIMED_OUT_ID_RETENTION_SECONDS
                    raise DownstreamTimeoutError("downstream response timed out")
                self._stdout_condition.wait(timeout=remaining)

    def _read_stdout(self) -> None:
        proc = self._require_process()
        if proc.stdout is None:
            self._set_downstream_error(PassthroughError("downstream stdout unavailable"))
            return

        byte_stream = getattr(proc.stdout, "buffer", None)
        if byte_stream is None:
            self._set_downstream_error(PassthroughError("downstream stdout unavailable"))
            return

        text_decoder = codecs.getincrementaldecoder("utf-8")()
        json_decoder = json.JSONDecoder()
        buffer = ""
        read_chunk = getattr(byte_stream, "read1", byte_stream.read)

        while True:
            try:
                chunk = read_chunk(4096)
            except OSError as exc:
                if not self._stopping:
                    self._set_downstream_error(PassthroughError("downstream read failed"))
                return
            if not chunk:
                try:
                    tail = text_decoder.decode(b"", final=True)
                except UnicodeDecodeError:
                    self._set_downstream_error(PassthroughError("downstream sent invalid UTF-8"))
                    return
                if tail:
                    buffer += tail
                    if self._downstream_buffer_too_large(buffer):
                        self._set_downstream_error(
                            PassthroughError("downstream response exceeds maximum size")
                        )
                        return
                    try:
                        buffer = self._drain_downstream_buffer(buffer, json_decoder)
                    except PassthroughError as exc:
                        self._set_downstream_error(exc)
                        return
                if buffer.strip():
                    self._set_downstream_error(PassthroughError("downstream sent invalid JSON"))
                    return
                if not self._stopping and proc.poll() is not None:
                    self._set_downstream_error(PassthroughError("downstream process exited"))
                elif not self._stopping:
                    self._set_downstream_error(PassthroughError("downstream closed stdout"))
                return

            try:
                buffer += text_decoder.decode(chunk, final=False)
            except UnicodeDecodeError:
                self._set_downstream_error(PassthroughError("downstream sent invalid UTF-8"))
                return

            if self._downstream_buffer_too_large(buffer):
                self._set_downstream_error(
                    PassthroughError("downstream response exceeds maximum size")
                )
                return

            try:
                buffer = self._drain_downstream_buffer(buffer, json_decoder)
            except PassthroughError as exc:
                self._set_downstream_error(exc)
                return

    def _drain_downstream_buffer(self, buffer: str, decoder: json.JSONDecoder) -> str:
        while True:
            stripped = buffer.lstrip()
            if not stripped:
                return ""
            if stripped[0] != "{":
                raise PassthroughError("downstream sent invalid JSON")
            try:
                response, offset = decoder.raw_decode(stripped)
            except json.JSONDecodeError:
                return buffer
            self._handle_downstream_message(response)
            buffer = stripped[offset:]

    def _handle_downstream_message(self, response: Any) -> None:
        if not isinstance(response, dict):
            raise PassthroughError("downstream sent non-object JSON")
        if self._is_server_notification(response):
            if self._notification_writer is not None:
                self._notification_writer(response)
            return
        if "id" in response:
            with self._stdout_condition:
                self._prune_timed_out_ids_locked()
                response_key = self._id_key(response.get("id"))
                if response_key in self._timed_out_response_ids:
                    self._timed_out_response_ids.pop(response_key, None)
                    return
                if response_key not in self._inflight_ids:
                    self._increment_unsolicited_downstream_responses()
                    return
                self._responses.setdefault(response_key, []).append(response)
                self._prune_pending_responses_locked()
                self._stdout_condition.notify_all()

    def _prune_timed_out_ids_locked(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        expired = [
            response_key
            for response_key, expires_at in self._timed_out_response_ids.items()
            if expires_at <= now
        ]
        for response_key in expired:
            self._timed_out_response_ids.pop(response_key, None)

    def _prune_pending_responses_locked(self) -> None:
        pending_count = sum(len(responses) for responses in self._responses.values())
        while pending_count > MAX_PENDING_RESPONSES:
            dropped = False
            for response_key, responses in list(self._responses.items()):
                if response_key in self._inflight_ids:
                    continue
                if responses:
                    responses.pop(0)
                    pending_count -= 1
                    dropped = True
                if not responses:
                    self._responses.pop(response_key, None)
                if pending_count <= MAX_PENDING_RESPONSES:
                    return
            if not dropped:
                return

    def _downstream_buffer_too_large(self, buffer: str) -> bool:
        return len(buffer.encode("utf-8", errors="replace")) > MAX_DOWNSTREAM_MESSAGE_BYTES

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
