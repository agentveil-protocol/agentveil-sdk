"""Cursor hook stdin handler for bounded allow/deny decisions and evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from agentveil_mcp_proxy.cursor_setup import CursorSetupError, cursor_setup_paths

SAFE_MARKER = "AVP_HOOK_SAFE"
RISKY_MARKER = "AVP_HOOK_RISKY"
EVENT_NAME = "cursor_hook"
RISKY_TOOL_NAMES = frozenset({"Shell", "Write", "Delete", "StrReplace", "ApplyPatch", "Edit"})
MCP_READ_TOOLS = frozenset({"list_workspace", "read_file", "get_file_info"})
SAFE_FIRST_STEP_ID = "request_human_review"
REASON_RISKY_BLOCKED = "risky_blocked"
REASON_SAFE_MARKER = "safe_marker"
REASON_DEFAULT_ALLOW = "default_allow"
REASON_MCP_SAFE_READ = "mcp_safe_read"
REASON_MISSING_CLI = "missing_cli"

_PATH_MARKERS = ("/users/", "/private/", "/var/folders/", "/tmp/")
_SECRET_MARKERS = ("password", "token", "secret", "api_key", "private_key")


class CursorHookError(RuntimeError):
    """Raised when Cursor hook input or output is invalid."""


@dataclass(frozen=True)
class HookDecision:
    permission: str
    hook_event: str
    tool_class: str
    reason_code: str
    safe_first_step_id: str | None
    target_reached: bool | None
    user_message: str | None = None
    agent_message: str | None = None


def infer_hook_event(payload: Mapping[str, Any]) -> str:
    if "command" in payload:
        return "beforeShellExecution"
    if "tool_name" in payload and "arguments" in payload:
        return "beforeMCPExecution"
    if "tool_name" in payload:
        return "preToolUse"
    return "unknown"


def _digest(value: Any) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def _contains_marker(value: Any, marker: str) -> bool:
    if isinstance(value, str):
        return marker in value
    if isinstance(value, Mapping):
        return any(_contains_marker(item, marker) for item in value.values())
    if isinstance(value, list):
        return any(_contains_marker(item, marker) for item in value)
    return marker in repr(value)


def _deny(
    *,
    hook_event: str,
    tool_class: str,
    reason_code: str,
    user_message: str,
    agent_message: str,
) -> HookDecision:
    return HookDecision(
        permission="deny",
        hook_event=hook_event,
        tool_class=tool_class,
        reason_code=reason_code,
        safe_first_step_id=SAFE_FIRST_STEP_ID,
        target_reached=False,
        user_message=user_message,
        agent_message=agent_message,
    )


def _allow(
    *,
    hook_event: str,
    tool_class: str,
    reason_code: str,
) -> HookDecision:
    return HookDecision(
        permission="allow",
        hook_event=hook_event,
        tool_class=tool_class,
        reason_code=reason_code,
        safe_first_step_id=None,
        target_reached=None,
    )


def classify_cursor_hook(
    payload: Mapping[str, Any],
    *,
    hook_event: str | None = None,
) -> HookDecision:
    event = hook_event or infer_hook_event(payload)

    if event == "beforeShellExecution":
        command = str(payload.get("command") or "")
        if RISKY_MARKER in command:
            return _deny(
                hook_event=event,
                tool_class="shell",
                reason_code=REASON_RISKY_BLOCKED,
                user_message=(
                    "Blocked risky shell action. Review the request with a human before retrying."
                ),
                agent_message=f"reason_code={REASON_RISKY_BLOCKED}; safe_first_step_id={SAFE_FIRST_STEP_ID}",
            )
        if SAFE_MARKER in command:
            return _allow(
                hook_event=event,
                tool_class="shell",
                reason_code=REASON_SAFE_MARKER,
            )
        return _allow(
            hook_event=event,
            tool_class="shell",
            reason_code=REASON_DEFAULT_ALLOW,
        )

    if event == "beforeMCPExecution":
        tool_name = str(payload.get("tool_name") or "mcp")
        arguments = payload.get("arguments") or {}
        if _contains_marker(arguments, RISKY_MARKER):
            return _deny(
                hook_event=event,
                tool_class=tool_name,
                reason_code=REASON_RISKY_BLOCKED,
                user_message=(
                    "Blocked risky MCP action. Use a read-only tool or request human review first."
                ),
                agent_message=f"reason_code={REASON_RISKY_BLOCKED}; safe_first_step_id={SAFE_FIRST_STEP_ID}",
            )
        if tool_name in MCP_READ_TOOLS and not _contains_marker(arguments, RISKY_MARKER):
            return _allow(
                hook_event=event,
                tool_class=tool_name,
                reason_code=REASON_MCP_SAFE_READ,
            )
        if _contains_marker(arguments, SAFE_MARKER):
            return _allow(
                hook_event=event,
                tool_class=tool_name,
                reason_code=REASON_SAFE_MARKER,
            )
        return _deny(
            hook_event=event,
            tool_class=tool_name,
            reason_code=REASON_RISKY_BLOCKED,
            user_message=(
                "Blocked MCP mutation. Route write actions through approval or add explicit safe review."
            ),
            agent_message=f"reason_code={REASON_RISKY_BLOCKED}; safe_first_step_id={SAFE_FIRST_STEP_ID}",
        )

    tool_name = str(payload.get("tool_name") or "unknown")
    tool_input = payload.get("tool_input") or {}
    if tool_name not in RISKY_TOOL_NAMES:
        return _allow(
            hook_event=event,
            tool_class=tool_name,
            reason_code=REASON_DEFAULT_ALLOW,
        )

    if _contains_marker(tool_input, SAFE_MARKER):
        return _allow(
            hook_event=event,
            tool_class=tool_name,
            reason_code=REASON_SAFE_MARKER,
        )

    return _deny(
        hook_event=event,
        tool_class=tool_name,
        reason_code=REASON_RISKY_BLOCKED,
        user_message=(
            f"Blocked {tool_name} before mutation. Request human review, then retry with explicit approval."
        ),
        agent_message=f"reason_code={REASON_RISKY_BLOCKED}; safe_first_step_id={SAFE_FIRST_STEP_ID}",
    )


def format_cursor_hook_response(decision: HookDecision) -> dict[str, str]:
    payload: dict[str, str] = {"permission": decision.permission}
    if decision.user_message:
        payload["user_message"] = decision.user_message
    if decision.agent_message:
        payload["agent_message"] = decision.agent_message
    return payload


def build_evidence_row(decision: HookDecision) -> dict[str, Any]:
    return {
        "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "event": EVENT_NAME,
        "hook_event": decision.hook_event,
        "decision": decision.permission,
        "tool_class": decision.tool_class,
        "input_digest": _digest(
            {
                "hook_event": decision.hook_event,
                "tool_class": decision.tool_class,
                "reason_code": decision.reason_code,
            }
        ),
        "reason_code": decision.reason_code,
        "safe_first_step_id": decision.safe_first_step_id,
        "target_reached": decision.target_reached,
    }


def assert_evidence_row_is_bounded(row: Mapping[str, Any]) -> None:
    serialized = json.dumps(row, sort_keys=True)
    lowered = serialized.lower()
    for marker in _PATH_MARKERS + _SECRET_MARKERS:
        if marker in lowered:
            raise CursorHookError(f"evidence must not include {marker!r}")
    if '": "/' in serialized:
        raise CursorHookError("evidence must not include absolute local filesystem paths")
    for key in ("command", "tool_input", "arguments", "stdout", "stderr", "prompt"):
        if key in row:
            raise CursorHookError(f"evidence must not include raw {key!r}")


def append_hook_evidence(*, workspace: Path, row: Mapping[str, Any]) -> None:
    assert_evidence_row_is_bounded(row)
    paths = cursor_setup_paths(workspace)
    paths.cursor_dir.mkdir(parents=True, exist_ok=True)
    with paths.evidence_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(row), sort_keys=True, separators=(",", ":")) + "\n")


def parse_cursor_hook_input(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        raise CursorHookError("hook input must be a JSON object on stdin")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CursorHookError("hook input must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise CursorHookError("hook input must be a JSON object")
    return payload


def resolve_hook_workspace(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit.expanduser().resolve()
    env_root = os.environ.get("AGENTVEIL_CURSOR_WORKSPACE", "").strip()
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path.cwd().resolve()


def run_cursor_hook(
    *,
    stdin_text: str,
    workspace: Path | None = None,
    hook_event: str | None = None,
) -> tuple[dict[str, str], dict[str, Any]]:
    payload = parse_cursor_hook_input(stdin_text)
    event = hook_event or os.environ.get("CURSOR_HOOK_EVENT", "").strip() or None
    decision = classify_cursor_hook(payload, hook_event=event)
    response = format_cursor_hook_response(decision)
    evidence = build_evidence_row(decision)
    append_hook_evidence(workspace=resolve_hook_workspace(workspace), row=evidence)
    return response, evidence


def assert_cursor_hook_output_is_bounded(*texts: str) -> None:
    combined = "\n".join(texts).lower()
    for marker in _PATH_MARKERS + _SECRET_MARKERS:
        if marker in combined:
            raise CursorHookError(f"hook output must not include {marker!r}")
    if re.search(r'"\s*:\s*"/', combined):
        raise CursorHookError("hook output must not include absolute local filesystem paths")


__all__ = [
    "CursorHookError",
    "HookDecision",
    "RISKY_MARKER",
    "RISKY_TOOL_NAMES",
    "SAFE_MARKER",
    "append_hook_evidence",
    "assert_cursor_hook_output_is_bounded",
    "assert_evidence_row_is_bounded",
    "build_evidence_row",
    "classify_cursor_hook",
    "format_cursor_hook_response",
    "infer_hook_event",
    "parse_cursor_hook_input",
    "resolve_hook_workspace",
    "run_cursor_hook",
]
