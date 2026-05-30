"""Approval notification escalation helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os
import shutil
import subprocess
import sys
from typing import Callable

from agentveil_mcp_proxy.approval.server import ApprovalPrompt


@dataclass(frozen=True)
class NotificationResult:
    """Result of one notification attempt."""

    channel: str
    attempted: bool
    delivered: bool


class ApprovalNotifier:
    """Best-effort OS notification sender with sanitized content only."""

    def __init__(self, *, runner: Callable[..., subprocess.CompletedProcess] | None = None):
        self._runner = runner or subprocess.run

    def notify(self, prompt: ApprovalPrompt) -> NotificationResult:
        """Send a sanitized OS notification when the platform supports it."""

        title = f"Approval pending: {prompt.client_id} session {prompt.session_id[:8]}"
        body = f"{prompt.downstream_server}.{prompt.tool_name} {prompt.risk_class}"
        if sys.platform == "darwin":
            return self._notify_macos(title, body)
        if sys.platform.startswith("linux"):
            return self._notify_linux(title, body)
        return NotificationResult("os", attempted=False, delivered=False)

    def _notify_macos(self, title: str, body: str) -> NotificationResult:
        if shutil.which("osascript") is None:
            return NotificationResult("macos", attempted=False, delivered=False)
        script = (
            f'display notification "{_escape_applescript(body)}" '
            f'with title "{_escape_applescript(title)}"'
        )
        return self._run(["osascript", "-e", script], "macos")

    def _notify_linux(self, title: str, body: str) -> NotificationResult:
        if shutil.which("notify-send") is None:
            return NotificationResult("linux", attempted=False, delivered=False)
        return self._run(["notify-send", title, body], "linux")

    def _run(self, args: list[str], channel: str) -> NotificationResult:
        try:
            completed = self._runner(
                args,
                check=False,
                timeout=2.0,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ},
            )
        except Exception:
            return NotificationResult(channel, attempted=True, delivered=False)
        return NotificationResult(channel, attempted=True, delivered=completed.returncode == 0)


def _escape_applescript(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


__all__ = ["ApprovalNotifier", "NotificationResult"]
