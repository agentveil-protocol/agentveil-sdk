"""T3 Workflow Guard: controlled runner and metadata-only JSONL event log.

Chains T1 classification and T2 role policy, then invokes an injected executor
only when policy allows. Does not register CLI commands or integrate with
Approval Center, Runtime Gate, or evidence databases.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
try:
    from enum import StrEnum
except ImportError:  # Python < 3.11
    from enum import Enum

    class StrEnum(str, Enum):
        pass
import json
from pathlib import Path
from typing import Any, Protocol

from agentveil_mcp_proxy.workflow_guard import WorkflowGuardClassifier
from agentveil_mcp_proxy.workflow_guard_policy import (
    PolicyDecisionType,
    WorkflowGuardPolicyEvaluator,
    WorkflowPolicyContext,
    WorkflowPolicyResult,
)


class RunnerOutputMode(StrEnum):
    COMPACT = "compact"
    PLAYBOOK = "playbook"


EventSink = str | Path | Callable[[dict[str, Any]], None] | Any


class SafeExecutorStatus(StrEnum):
    """Normalized executor outcome labels for metadata/event JSONL."""

    OK = "ok"
    FAILED = "failed"
    TIMEOUT = "timeout"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


_SAFE_EXECUTOR_STATUS_LABELS = frozenset(status.value for status in SafeExecutorStatus)


@dataclass(frozen=True)
class ExecutorResult:
    """Executor outcome hint; runner normalizes ``status`` before persisting."""

    status: str


class WorkflowCommandExecutor(Protocol):
    """Injected command executor; shell execution is outside this runner."""

    def execute(self, command: str) -> ExecutorResult:
        """Run the wrapped command when policy allows."""


@dataclass
class RecordingExecutor:
    """Test double that records invocation count without persisting command text."""

    call_count: int = 0

    def execute(self, command: str) -> ExecutorResult:
        del command
        self.call_count += 1
        return ExecutorResult(status="ok")


@dataclass(frozen=True)
class WorkflowGuardRunResult:
    """Structured outcome for one guarded run."""

    decision: PolicyDecisionType
    policy_rule_id: str
    executed: bool
    redirect_playbook_id: str | None
    compact_message: str
    event: dict[str, Any]
    full_message: str | None = None

    def to_metadata_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "decision": self.decision.value,
            "policy_rule_id": self.policy_rule_id,
            "executed": self.executed,
            "redirect_playbook_id": self.redirect_playbook_id,
            "compact_message": self.compact_message,
            "event": self.event,
        }
        if self.full_message is not None:
            payload["full_message"] = self.full_message
        return payload


class WorkflowGuardRunner:
    """Classify, apply role policy, optionally execute, and append metadata events."""

    def __init__(
        self,
        *,
        classifier: WorkflowGuardClassifier | None = None,
        evaluator: WorkflowGuardPolicyEvaluator | None = None,
        adapter: str = "workflow-guard-runner",
    ) -> None:
        self.classifier = classifier or WorkflowGuardClassifier()
        self.evaluator = evaluator or WorkflowGuardPolicyEvaluator()
        self.adapter = adapter

    def run(
        self,
        command: str,
        *,
        context: WorkflowPolicyContext,
        executor: WorkflowCommandExecutor,
        output_mode: RunnerOutputMode = RunnerOutputMode.COMPACT,
        event_sink: EventSink = None,
    ) -> WorkflowGuardRunResult:
        envelope = self.classifier.classify(
            command,
            role=context.role_profile.value,
            adapter=self.adapter,
        )
        policy = self.evaluator.evaluate(envelope, context)

        executed = False
        executor_status: str | None = None
        if policy.decision == PolicyDecisionType.ALLOW:
            executor_status = normalize_executor_status(
                executor.execute(command).status
            ).value
            executed = True

        redirect_playbook_id = (
            None if policy.redirect is None else policy.redirect.playbook_id
        )
        event = _build_event(
            envelope_metadata=envelope.to_metadata_dict(),
            policy=policy,
            executed=executed,
            executor_result_status=executor_status,
        )
        if event_sink is not None:
            append_workflow_guard_event(event_sink, event)

        compact_message = _format_compact_message(
            policy=policy,
            executed=executed,
            redirect_playbook_id=redirect_playbook_id,
        )
        full_message = None
        if output_mode == RunnerOutputMode.PLAYBOOK and policy.redirect is not None:
            full_message = policy.redirect.workflow_text

        return WorkflowGuardRunResult(
            decision=policy.decision,
            policy_rule_id=policy.policy_rule_id,
            executed=executed,
            redirect_playbook_id=redirect_playbook_id,
            compact_message=compact_message,
            event=event,
            full_message=full_message,
        )


def _build_event(
    *,
    envelope_metadata: dict[str, Any],
    policy: WorkflowPolicyResult,
    executed: bool,
    executor_result_status: str | None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "role_profile": policy.role_profile.value,
        "command_family": envelope_metadata["command_family"],
        "action_type": envelope_metadata["action_type"],
        "disposition": envelope_metadata["disposition"],
        "decision": policy.decision.value,
        "policy_rule_id": policy.policy_rule_id,
        "target_hash": envelope_metadata["target_hash"],
        "payload_hash": envelope_metadata["payload_hash"],
        "redirect_playbook_id": (
            None if policy.redirect is None else policy.redirect.playbook_id
        ),
        "executed": executed,
    }
    if executor_result_status is not None:
        event["executor_result_status"] = executor_result_status
    return event


def _format_compact_message(
    *,
    policy: WorkflowPolicyResult,
    executed: bool,
    redirect_playbook_id: str | None,
) -> str:
    lines = [
        f"Decision: {policy.decision.value}",
        f"Rule: {policy.policy_rule_id}",
        f"Executed: {'true' if executed else 'false'}",
    ]
    if redirect_playbook_id is not None:
        lines.append(f"Next: {redirect_playbook_id}")
    return "\n".join(lines)


def normalize_executor_status(raw_status: str) -> SafeExecutorStatus:
    """Map executor-provided status to a small allowlisted metadata label."""

    label = raw_status.strip().lower()
    if label in _SAFE_EXECUTOR_STATUS_LABELS:
        return SafeExecutorStatus(label)
    return SafeExecutorStatus.UNKNOWN


def append_workflow_guard_event(sink: EventSink, event: dict[str, Any]) -> None:
    """Append one metadata-only event to a JSONL sink."""

    if sink is None:
        return
    if callable(sink):
        sink(event)
        return
    line = json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n"
    if hasattr(sink, "write"):
        sink.write(line)
        flush = getattr(sink, "flush", None)
        if callable(flush):
            flush()
        return
    path = Path(sink)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)


__all__ = [
    "ExecutorResult",
    "RecordingExecutor",
    "RunnerOutputMode",
    "SafeExecutorStatus",
    "WorkflowCommandExecutor",
    "WorkflowGuardRunResult",
    "WorkflowGuardRunner",
    "append_workflow_guard_event",
    "normalize_executor_status",
]
