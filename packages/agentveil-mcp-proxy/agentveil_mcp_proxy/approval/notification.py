"""Approval notification escalation helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os
import shutil
import subprocess
import sys
from typing import Callable
import webbrowser

from agentveil_mcp_proxy.approval.server import ApprovalPrompt


@dataclass(frozen=True)
class NotificationResult:
    """Result of one notification attempt."""

    channel: str
    attempted: bool
    delivered: bool


@dataclass(frozen=True)
class BrowserOpenResult:
    """Bounded result of one approval-browser delivery attempt."""

    attempted: bool
    delivered: bool
    channel: str


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


def open_approval_url_webbrowser(
    url: str,
    *,
    opener: Callable[[str], object] | None = None,
) -> BrowserOpenResult:
    """Open ``url`` through the stdlib webbrowser opener.

    Success requires an explicit truthy return. ``False`` and exceptions are
    failures so callers can retry and apply a native fallback.
    """

    open_fn = opener or webbrowser.open
    try:
        opened = open_fn(url)
    except Exception:
        return BrowserOpenResult(attempted=True, delivered=False, channel="webbrowser")
    return BrowserOpenResult(
        attempted=True,
        delivered=bool(opened),
        channel="webbrowser",
    )


def open_approval_url_macos_native(
    url: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
    enabled: bool | None = None,
) -> BrowserOpenResult:
    """Open ``url`` with the macOS ``open`` launcher when available."""

    if enabled is None:
        enabled = sys.platform == "darwin"
    if not enabled:
        return BrowserOpenResult(attempted=False, delivered=False, channel="macos-open")
    open_bin = shutil.which("open")
    if open_bin is None:
        return BrowserOpenResult(attempted=False, delivered=False, channel="macos-open")
    run = runner or subprocess.run
    try:
        completed = run(
            [open_bin, url],
            check=False,
            timeout=2.0,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ},
        )
    except Exception:
        return BrowserOpenResult(attempted=True, delivered=False, channel="macos-open")
    return BrowserOpenResult(
        attempted=True,
        delivered=completed.returncode == 0,
        channel="macos-open",
    )


def deliver_approval_browser_url(
    url: str,
    *,
    webbrowser_opener: Callable[[str], object] | None = None,
    native_runner: Callable[..., subprocess.CompletedProcess] | None = None,
    platform: str | None = None,
) -> BrowserOpenResult:
    """Deliver an approval URL via webbrowser, then bounded native fallback."""

    primary = open_approval_url_webbrowser(url, opener=webbrowser_opener)
    if primary.delivered:
        return primary
    host = sys.platform if platform is None else platform
    if host == "darwin":
        native = open_approval_url_macos_native(
            url,
            runner=native_runner,
            enabled=True,
        )
        if native.attempted:
            return native
    return primary


__all__ = [
    "ApprovalNotifier",
    "BrowserOpenResult",
    "NotificationResult",
    "deliver_approval_browser_url",
    "open_approval_url_macos_native",
    "open_approval_url_webbrowser",
]
