"""Approval Center lifecycle for the one-command Claude Code connector.

S5 added `setup claude-code --yes` to install the connector in one command, but
without an active local Approval Center the controlled MCP write path produces
URLs that hit a dead loopback port (``ERR_CONNECTION_REFUSED``) — the user sees
"empty windows with no approve". This module gives the public setup command
ownership of the Approval Center process lifecycle so the one-command promise
holds end-to-end:

- ``ensure_running``: idempotent start of a project-local Approval Center using
  the SAME ``--home`` / ``--config`` as the setup-managed proxy. If a manifest
  exists and points at a live, healthy process, reuse it. If the manifest is
  stale (no PID or PID is dead), restart. Returns a bounded status.
- ``check_status``: read-only health probe over the manifest + PID + loopback
  HTTP. Returns ``running`` / ``down`` / ``stale``.
- ``stop_if_managed``: terminate ONLY a process whose PID is in the manifest
  this module wrote. We will not kill someone else's center.

Public/private boundary: this module manages the generic local Approval Center
process. It does not add hosted auth, license activation, policy packs, or
private playbook logic.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentveil_mcp_proxy.approval.persistent import (
    ApprovalCenterManifest,
    is_process_alive,
    load_manifest,
    loopback_get_status,
    manifest_path,
)


# How long to wait for a freshly-spawned center to publish its manifest and
# answer a loopback health probe. Bounded so a stuck spawn cannot hang setup.
_START_TIMEOUT_SECONDS = 12.0
_POLL_INTERVAL_SECONDS = 0.2
_HEALTH_TIMEOUT_SECONDS = 1.5


def _proxy_dir(home: Path) -> Path:
    """Directory where the proxy + center share the manifest and config."""
    return Path(home) / "mcp-proxy"


def _center_health(manifest: ApprovalCenterManifest) -> bool:
    url = f"{manifest.approval_center_url()}/api/approvals"
    try:
        return loopback_get_status(url, timeout=_HEALTH_TIMEOUT_SECONDS) == 200
    except (OSError, TimeoutError, ValueError):
        return False


@dataclass(frozen=True)
class CenterStatus:
    """Bounded Approval Center status for setup reporting.

    ``state`` semantics:
    - ``running``: manifest present, PID alive, health-check passes.
    - ``down``: no manifest, or the manifest is structurally unreadable.
    - ``stale``: manifest present but PID missing/dead OR health-check fails.
    """

    state: str           # "running" | "down" | "stale"
    pid: int | None
    port: int | None
    url: str | None      # full approval URL when running, else None


def check_status(home: Path) -> CenterStatus:
    """Read-only Approval Center health probe."""
    manifest = load_manifest(_proxy_dir(home))
    if manifest is None:
        return CenterStatus(state="down", pid=None, port=None, url=None)
    alive = is_process_alive(manifest.pid)
    healthy = _center_health(manifest) if alive else False
    if alive and healthy:
        return CenterStatus(
            state="running",
            pid=manifest.pid,
            port=manifest.port,
            url=manifest.approval_center_url(),
        )
    return CenterStatus(state="stale", pid=manifest.pid, port=manifest.port, url=None)


@dataclass(frozen=True)
class EnsureRunningResult:
    """Outcome of an idempotent center start."""

    status: CenterStatus
    started: bool         # True if this call spawned a new center
    reused: bool          # True if an existing healthy center was reused
    restarted: bool       # True if a stale center was replaced
    reason: str           # short bounded reason string


def _spawn_center(
    *,
    proxy_command: str,
    home: Path,
    passphrase_file: Path | None = None,
) -> subprocess.Popen[bytes]:
    """Spawn `approval-center serve` as a detached background process.

    The center inherits the same ``--home`` and ``--config`` that the
    setup-managed proxy uses, so they share manifest + sqlite store. We detach
    stdio so the parent setup command can return without keeping a pipe open.
    """
    config_path = _proxy_dir(home) / "config.json"
    devnull = subprocess.DEVNULL
    # On POSIX, start_new_session detaches from the parent so the setup command
    # may exit while the center keeps running. On Windows, no-op kwargs.
    kwargs: dict[str, Any] = {
        "stdin": devnull,
        "stdout": devnull,
        "stderr": devnull,
        "close_fds": True,
    }
    if os.name == "posix":
        kwargs["start_new_session"] = True
    args = [
        proxy_command,
        "approval-center",
        "serve",
        "--home", str(home),
        "--config", str(config_path),
        "--port", "0",
    ]
    if passphrase_file is not None:
        args.extend(["--passphrase-file", str(passphrase_file)])
    return subprocess.Popen(  # noqa: S603 - args constructed from validated paths
        args,
        **kwargs,
    )


def _wait_for_running(home: Path, *, deadline: float) -> CenterStatus:
    """Poll manifest + health until running or deadline."""
    last = CenterStatus(state="down", pid=None, port=None, url=None)
    while time.monotonic() < deadline:
        last = check_status(home)
        if last.state == "running":
            return last
        time.sleep(_POLL_INTERVAL_SECONDS)
    return last


def ensure_running(
    *,
    home: Path,
    proxy_command: str,
    passphrase_file: Path | None = None,
) -> EnsureRunningResult:
    """Idempotently ensure a healthy project-local Approval Center is running.

    - If manifest, PID, and health check pass: reuse, do not respawn.
    - If manifest is stale (PID gone or unhealthy): respawn.
    - If no manifest: spawn.

    Returns a bounded status. If start fails the result's status.state stays
    ``down``/``stale`` and ``started`` is False, so the caller (setup) can
    refuse to claim ready/protected.
    """
    initial = check_status(home)
    if initial.state == "running":
        return EnsureRunningResult(
            status=initial, started=False, reused=True, restarted=False,
            reason="center already running and healthy",
        )

    restarted = initial.state == "stale"
    try:
        _spawn_center(
            proxy_command=proxy_command,
            home=home,
            passphrase_file=passphrase_file,
        )
    except (OSError, ValueError) as exc:
        return EnsureRunningResult(
            status=initial, started=False, reused=False, restarted=False,
            reason=f"could not spawn approval-center: {exc.__class__.__name__}",
        )

    deadline = time.monotonic() + _START_TIMEOUT_SECONDS
    final = _wait_for_running(home, deadline=deadline)
    if final.state == "running":
        return EnsureRunningResult(
            status=final, started=True, reused=False, restarted=restarted,
            reason="center restarted" if restarted else "center started",
        )
    return EnsureRunningResult(
        status=final, started=False, reused=False, restarted=False,
        reason="approval-center did not become healthy within the start timeout",
    )


def stop_if_managed(home: Path) -> dict[str, Any]:
    """Stop ONLY a center whose PID is in the project manifest.

    Bounded result; no raw paths leaked. Idempotent: if no manifest or PID is
    not ours, the call is a no-op.
    """
    proxy_dir = _proxy_dir(home)
    manifest = load_manifest(proxy_dir)
    if manifest is None or manifest.pid is None:
        return {"stopped": False, "reason": "no managed approval-center manifest"}

    if not is_process_alive(manifest.pid):
        # Process is already gone but the manifest lingered. Remove it so a
        # later setup does not see a stale running-looking record.
        try:
            manifest_path(proxy_dir).unlink(missing_ok=True)
        except OSError:
            pass
        return {"stopped": False, "reason": "managed pid not alive; manifest cleared"}

    if not _center_health(manifest):
        return {
            "stopped": False,
            "reason": "manifest pid is not a healthy AgentVeil Approval Center; not stopped",
        }

    try:
        os.kill(manifest.pid, signal.SIGTERM)
    except ProcessLookupError:
        return {"stopped": False, "reason": "managed pid already exited"}
    except PermissionError:
        return {"stopped": False, "reason": "no permission to stop managed pid"}

    # Best-effort wait for exit, then clear manifest.
    for _ in range(20):
        if not is_process_alive(manifest.pid):
            break
        time.sleep(0.1)
    try:
        manifest_path(proxy_dir).unlink(missing_ok=True)
    except OSError:
        pass
    return {"stopped": True, "reason": "managed approval-center stopped"}


__all__ = [
    "CenterStatus",
    "EnsureRunningResult",
    "check_status",
    "ensure_running",
    "stop_if_managed",
]
