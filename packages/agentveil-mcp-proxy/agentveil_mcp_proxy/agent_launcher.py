"""Managed runtime launch for agent runtime profiles.

This module is a thin launcher adapter: it prepares project-local AVP home,
starts/reuses the shared Approval Center, passes bounded MCP route env to a child
process, and tracks only processes it owns. Policy, approval, redirect, and
proof logic stay in the shared MCP proxy backend.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from agentveil_mcp_proxy.agent_runtime_profiles import (
    RuntimeProfileError,
    RuntimeProfileSpec,
    resolve_runtime_profile,
)
from agentveil_mcp_proxy.approval.persistent import (
    ApprovalCenterManifest,
    is_process_alive,
    load_manifest,
    loopback_get_status,
    manifest_path as approval_manifest_path,
)
from agentveil_mcp_proxy.client_config import (
    bounded_path_ref,
    build_run_args,
    format_bounded_run_args,
    resolve_proxy_command,
)


LAUNCH_MANIFEST_FILENAME = "runtime-launch.manifest.json"
LAUNCH_MANIFEST_SCHEMA_VERSION = 2
RUNTIME_ROUTE_FILENAME = "runtime-route.json"

AGENTVEIL_AVP_HOME_ENV = "AGENTVEIL_AVP_HOME"
AGENTVEIL_MCP_PROXY_COMMAND_ENV = "AGENTVEIL_MCP_PROXY_COMMAND"
AGENTVEIL_MCP_PROXY_RUN_ARGS_ENV = "AGENTVEIL_MCP_PROXY_RUN_ARGS"
AGENTVEIL_RUNTIME_PROFILE_ENV = "AGENTVEIL_RUNTIME_PROFILE"
AGENTVEIL_RUNTIME_SESSION_ENV = "AGENTVEIL_RUNTIME_SESSION_ID"

_CENTER_START_TIMEOUT_SECONDS = 12.0
_CENTER_POLL_INTERVAL_SECONDS = 0.2
_CENTER_HEALTH_TIMEOUT_SECONDS = 1.5

_PRESERVED_ENV_KEYS = (
    "PATH",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "PYTHONPATH",
    "PYTHONHOME",
    "VIRTUAL_ENV",
)


class AgentLauncherError(ValueError):
    """Bounded launcher error without leaking secrets or absolute paths."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class LaunchManifest:
    schema_version: int
    profile_id: str
    session_id: str
    child_pid: int | None
    child_argv0: str
    child_command_ref: str
    started_at: int
    project_dir_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "session_id": self.session_id,
            "child_pid": self.child_pid,
            "child_argv0": self.child_argv0,
            "child_command_ref": self.child_command_ref,
            "started_at": self.started_at,
            "project_dir_ref": self.project_dir_ref,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LaunchManifest:
        argv0 = str(data.get("child_argv0") or "").strip()
        command_ref = str(data.get("child_command_ref") or "").strip()
        if not argv0 or not command_ref:
            raise ValueError("child_argv0 and child_command_ref required")
        return cls(
            schema_version=int(data["schema_version"]),
            profile_id=str(data["profile_id"]),
            session_id=str(data["session_id"]),
            child_pid=None if data.get("child_pid") is None else int(data["child_pid"]),
            child_argv0=argv0,
            child_command_ref=command_ref,
            started_at=int(data["started_at"]),
            project_dir_ref=str(data["project_dir_ref"]),
        )


@dataclass(frozen=True)
class CenterStatus:
    state: str
    pid: int | None
    port: int | None


@dataclass(frozen=True)
class LaunchStatus:
    profile_id: str
    profile_status: str
    project_dir_ref: str
    session_id: str | None
    approval_center: CenterStatus
    child_running: bool
    child_pid: int | None
    evidence_enabled: bool
    scope: str
    host_wide_control_claim: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "profile_status": self.profile_status,
            "project_dir_ref": self.project_dir_ref,
            "session_id": self.session_id,
            "approval_center": {
                "state": self.approval_center.state,
                "pid": self.approval_center.pid,
                "port": self.approval_center.port,
            },
            "child_running": self.child_running,
            "child_pid": self.child_pid,
            "evidence_enabled": self.evidence_enabled,
            "scope": self.scope,
            "host_wide_control_claim": self.host_wide_control_claim,
        }


@dataclass(frozen=True)
class LaunchResult:
    status: LaunchStatus
    child_started: bool
    approval_center_started: bool
    proxy_initialized: bool
    reason: str


def project_avp_home(project_dir: Path) -> Path:
    return project_dir / ".avp"


def proxy_dir(home: Path) -> Path:
    return home / "mcp-proxy"


def launch_manifest_path(home: Path) -> Path:
    return proxy_dir(home) / LAUNCH_MANIFEST_FILENAME


def runtime_route_path(home: Path) -> Path:
    return proxy_dir(home) / RUNTIME_ROUTE_FILENAME


def resolve_project_dir(project_dir: Path | None) -> Path:
    target = (project_dir if project_dir is not None else Path.cwd()).resolve()
    if not target.exists():
        raise AgentLauncherError("project dir does not exist", exit_code=2)
    if not target.is_dir():
        raise AgentLauncherError("project dir must be a directory", exit_code=2)
    return target


def runtime_state_home(home: Path, profile_id: str, session_id: str) -> Path:
    """Project-local runtime HOME for a managed child process."""

    return home / "runtime" / profile_id / session_id / "home"


def bounded_command_metadata(command: Sequence[str]) -> dict[str, str]:
    """Return bounded argv metadata without persisting secrets from the full command line."""

    argv0_raw = command[0] if command else "unknown"
    argv0 = Path(str(argv0_raw)).name or "unknown"
    joined = "\0".join(str(item) for item in command)
    command_ref = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]
    return {
        "child_argv0": argv0,
        "child_command_ref": command_ref,
    }


def ensure_runtime_state_home(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _proxy_cli_argv(proxy_command: str, subcommand: list[str]) -> list[str]:
    """Build argv for a proxy CLI subcommand in a fresh interpreter when needed."""

    command_path = Path(proxy_command)
    name = command_path.name
    if name in {"python", "python3"} or name.startswith("python3."):
        # Avoid `python -m agentveil_mcp_proxy.cli` from a parent that already
        # imported cli; spawn a clean interpreter with an inline entrypoint.
        script = (
            "from agentveil_mcp_proxy.cli import main; "
            f"raise SystemExit(main({subcommand!r}))"
        )
        return [str(command_path), "-c", script]
    resolved = shutil.which(proxy_command)
    if resolved:
        return [resolved, *subcommand]
    return [proxy_command, *subcommand]


def _proxy_command_display(proxy_command: str) -> str:
    command_path = Path(proxy_command)
    name = command_path.name
    if name in {"python", "python3"} or name.startswith("python3."):
        return "agentveil-mcp-proxy"
    if command_path.is_absolute():
        return command_path.name
    return proxy_command


def normalize_child_command(argv: Sequence[str]) -> list[str]:
    tokens = [str(item) for item in argv if str(item)]
    while tokens and tokens[0] == "--":
        tokens.pop(0)
    if not tokens:
        raise AgentLauncherError(
            "child command required after '--'; example: launch --profile generic-process "
            "--project-dir . -- python script.py",
            exit_code=2,
        )
    return tokens


def load_launch_manifest(home: Path) -> LaunchManifest | None:
    path = launch_manifest_path(home)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        manifest = LaunchManifest.from_dict(data)
    except (KeyError, TypeError, ValueError):
        return None
    if manifest.schema_version != LAUNCH_MANIFEST_SCHEMA_VERSION:
        return None
    return manifest


def save_launch_manifest(home: Path, manifest: LaunchManifest) -> None:
    path = launch_manifest_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    payload = json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(payload)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def _center_health(manifest: ApprovalCenterManifest) -> bool:
    try:
        return (
            loopback_get_status(
                manifest.approval_center_url(),
                timeout=_CENTER_HEALTH_TIMEOUT_SECONDS,
            )
            == 200
        )
    except (OSError, TimeoutError, ValueError):
        return False


def check_approval_center_status(home: Path) -> CenterStatus:
    manifest = load_manifest(proxy_dir(home))
    if manifest is None:
        return CenterStatus(state="down", pid=None, port=None)
    if _center_health(manifest):
        return CenterStatus(state="running", pid=manifest.pid, port=manifest.port)
    return CenterStatus(state="stale", pid=manifest.pid, port=manifest.port)


def _spawn_approval_center(
    *,
    proxy_command: str,
    home: Path,
    passphrase_file: Path | None = None,
) -> subprocess.Popen[bytes]:
    config_path = proxy_dir(home) / "config.json"
    devnull = subprocess.DEVNULL
    kwargs: dict[str, Any] = {
        "stdin": devnull,
        "stdout": devnull,
        "stderr": devnull,
        "close_fds": True,
    }
    if os.name == "posix":
        kwargs["start_new_session"] = True
    subcommand = [
        "approval-center",
        "serve",
        "--home",
        str(home),
        "--config",
        str(config_path),
        "--port",
        "0",
    ]
    if passphrase_file is not None:
        subcommand.extend(["--passphrase-file", str(passphrase_file)])
    return subprocess.Popen(  # noqa: S603
        _proxy_cli_argv(proxy_command, subcommand),
        **kwargs,
    )


def _wait_for_center(home: Path, *, deadline: float) -> CenterStatus:
    last = CenterStatus(state="down", pid=None, port=None)
    while time.monotonic() < deadline:
        last = check_approval_center_status(home)
        if last.state == "running":
            return last
        time.sleep(_CENTER_POLL_INTERVAL_SECONDS)
    return last


def ensure_approval_center_running(
    *,
    home: Path,
    proxy_command: str,
    passphrase_file: Path | None = None,
) -> tuple[CenterStatus, bool, str]:
    initial = check_approval_center_status(home)
    if initial.state == "running":
        return initial, False, "approval center already running"

    try:
        _spawn_approval_center(
            proxy_command=proxy_command,
            home=home,
            passphrase_file=passphrase_file,
        )
    except (OSError, ValueError) as exc:
        return initial, False, f"could not spawn approval center: {exc.__class__.__name__}"

    deadline = time.monotonic() + _CENTER_START_TIMEOUT_SECONDS
    final = _wait_for_center(home, deadline=deadline)
    if final.state == "running":
        action = "restarted" if initial.state == "stale" else "started"
        return final, True, f"approval center {action}"
    return final, False, "approval center did not become healthy within the start timeout"


def _bounded_child_env(
    *,
    home: Path,
    runtime_home: Path,
    profile: RuntimeProfileSpec,
    session_id: str,
    proxy_command: str,
    run_args: list[str],
    parent_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    source = dict(parent_env or os.environ)
    env: dict[str, str] = {}
    for key in _PRESERVED_ENV_KEYS:
        value = source.get(key)
        if isinstance(value, str) and value:
            env[key] = value
    env["HOME"] = str(runtime_home)
    env[AGENTVEIL_AVP_HOME_ENV] = str(home)
    env[AGENTVEIL_MCP_PROXY_COMMAND_ENV] = proxy_command
    env[AGENTVEIL_MCP_PROXY_RUN_ARGS_ENV] = json.dumps(run_args, separators=(",", ":"))
    env[AGENTVEIL_RUNTIME_PROFILE_ENV] = profile.profile_id
    env[AGENTVEIL_RUNTIME_SESSION_ENV] = session_id
    return env


def write_runtime_route_config(
    *,
    home: Path,
    profile: RuntimeProfileSpec,
    session_id: str,
    proxy_command: str,
    run_args: list[str],
    runtime_home: Path | None = None,
) -> None:
    command_display = Path(proxy_command).name if Path(proxy_command).is_absolute() else proxy_command
    payload = {
        "schema_version": 1,
        "profile_id": profile.profile_id,
        "session_id": session_id,
        "proxy_command": command_display,
        "run_args": format_bounded_run_args(run_args),
        "home_ref": bounded_path_ref(home),
        "config_ref": bounded_path_ref(proxy_dir(home) / "config.json"),
        "evidence_enabled": True,
        "scope": "project",
        "host_wide_control_claim": False,
    }
    if runtime_home is not None:
        payload["runtime_home_ref"] = bounded_path_ref(runtime_home)
    path = runtime_route_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def build_launch_status(
    *,
    home: Path,
    profile: RuntimeProfileSpec,
    project_dir: Path,
) -> LaunchStatus:
    launch_manifest = load_launch_manifest(home)
    center = check_approval_center_status(home)
    child_pid = launch_manifest.child_pid if launch_manifest is not None else None
    child_running = is_process_alive(child_pid)
    config_exists = (proxy_dir(home) / "config.json").exists()
    profile_status = profile.default_status
    if child_running:
        profile_status = "running"
    elif launch_manifest is not None and not child_running:
        profile_status = "stopped"
    elif not config_exists:
        profile_status = "verify_only"
    return LaunchStatus(
        profile_id=profile.profile_id,
        profile_status=profile_status,
        project_dir_ref=bounded_path_ref(project_dir)["ref"] or "",
        session_id=launch_manifest.session_id if launch_manifest is not None else None,
        approval_center=center,
        child_running=child_running,
        child_pid=child_pid if child_running else None,
        evidence_enabled=config_exists,
        scope="project",
        host_wide_control_claim=False,
    )


def launch_managed_process(
    *,
    project_dir: Path,
    profile_id: str,
    child_command: Sequence[str],
    proxy_command: str | None = None,
    passphrase_file: Path | None = None,
    init_proxy_if_missing: Callable[..., Any] | None = None,
    sandbox_root: Path | None = None,
) -> LaunchResult:
    try:
        profile = resolve_runtime_profile(profile_id)
    except RuntimeProfileError as exc:
        raise AgentLauncherError(str(exc), exit_code=2) from exc

    target = resolve_project_dir(project_dir)
    command = normalize_child_command(child_command)
    home = project_avp_home(target)
    config_path = proxy_dir(home) / "config.json"
    proxy_initialized = False

    resolved_proxy_command = resolve_proxy_command(proxy_command)
    proxy_command_display = _proxy_command_display(resolved_proxy_command)
    run_args = build_run_args(home=home, config_path=config_path, passphrase_file=passphrase_file)

    if not config_path.exists():
        if init_proxy_if_missing is None:
            raise AgentLauncherError(
                "proxy route is not initialized; run init first",
                exit_code=1,
            )
        downstream_root = sandbox_root if sandbox_root is not None else target
        init_proxy_if_missing(
            home=home,
            policy_pack="filesystem",
            downstream_root=downstream_root,
            passphrase_file=passphrase_file,
        )
        proxy_initialized = True
        if not config_path.exists():
            raise AgentLauncherError("proxy route initialization did not create config", exit_code=1)

    center, center_started, center_reason = ensure_approval_center_running(
        home=home,
        proxy_command=resolved_proxy_command,
        passphrase_file=passphrase_file,
    )
    if center.state != "running":
        raise AgentLauncherError(
            f"preflight failed: {center_reason}; child process was not started",
            exit_code=1,
        )

    session_id = uuid.uuid4().hex
    runtime_home = runtime_state_home(home, profile.profile_id, session_id)
    ensure_runtime_state_home(runtime_home)
    write_runtime_route_config(
        home=home,
        profile=profile,
        session_id=session_id,
        proxy_command=proxy_command_display,
        run_args=run_args,
        runtime_home=runtime_home,
    )
    child_env = _bounded_child_env(
        home=home,
        runtime_home=runtime_home,
        profile=profile,
        session_id=session_id,
        proxy_command=proxy_command_display,
        run_args=run_args,
    )

    popen_kwargs: dict[str, Any] = {
        "cwd": str(target),
        "env": child_env,
        "close_fds": True,
    }
    if profile.child_detach:
        popen_kwargs["stdin"] = subprocess.DEVNULL
        popen_kwargs["stdout"] = subprocess.DEVNULL
        popen_kwargs["stderr"] = subprocess.DEVNULL
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(command, **popen_kwargs)  # noqa: S603
    except (OSError, ValueError) as exc:
        raise AgentLauncherError(
            f"could not start child process: {exc.__class__.__name__}",
            exit_code=1,
        ) from exc

    command_meta = bounded_command_metadata(command)
    manifest = LaunchManifest(
        schema_version=LAUNCH_MANIFEST_SCHEMA_VERSION,
        profile_id=profile.profile_id,
        session_id=session_id,
        child_pid=process.pid,
        child_argv0=command_meta["child_argv0"],
        child_command_ref=command_meta["child_command_ref"],
        started_at=int(time.time()),
        project_dir_ref=bounded_path_ref(target)["ref"] or "",
    )
    save_launch_manifest(home, manifest)

    status = build_launch_status(home=home, profile=profile, project_dir=target)
    return LaunchResult(
        status=status,
        child_started=True,
        approval_center_started=center_started,
        proxy_initialized=proxy_initialized,
        reason=center_reason,
    )


def stop_managed_launch(*, project_dir: Path) -> dict[str, Any]:
    target = resolve_project_dir(project_dir)
    home = project_avp_home(target)
    launch_manifest = load_launch_manifest(home)
    stopped_child = False
    stopped_center = False
    reasons: list[str] = []

    if launch_manifest is not None and launch_manifest.child_pid is not None:
        pid = launch_manifest.child_pid
        if is_process_alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
                stopped_child = True
                reasons.append("managed child stopped")
            except ProcessLookupError:
                reasons.append("managed child already exited")
            except PermissionError:
                reasons.append("no permission to stop managed child")
            else:
                for _ in range(20):
                    if not is_process_alive(pid):
                        break
                    time.sleep(0.1)
        else:
            reasons.append("managed child not running")
        try:
            launch_manifest_path(home).unlink(missing_ok=True)
        except OSError:
            pass
    else:
        reasons.append("no managed child manifest")

    center_manifest = load_manifest(proxy_dir(home))
    if center_manifest is not None and center_manifest.pid is not None:
        if _center_health(center_manifest) and is_process_alive(center_manifest.pid):
            try:
                os.kill(center_manifest.pid, signal.SIGTERM)
                stopped_center = True
                reasons.append("managed approval center stopped")
            except ProcessLookupError:
                reasons.append("managed approval center already exited")
            except PermissionError:
                reasons.append("no permission to stop managed approval center")
            else:
                for _ in range(20):
                    if not is_process_alive(center_manifest.pid):
                        break
                    time.sleep(0.1)
            try:
                approval_manifest_path(proxy_dir(home)).unlink(missing_ok=True)
            except OSError:
                pass
        elif not is_process_alive(center_manifest.pid):
            try:
                approval_manifest_path(proxy_dir(home)).unlink(missing_ok=True)
            except OSError:
                pass
            reasons.append("managed approval center manifest cleared")
    else:
        reasons.append("no managed approval center")

    return {
        "stopped_child": stopped_child,
        "stopped_center": stopped_center,
        "reasons": reasons,
    }


__all__ = [
    "AGENTVEIL_AVP_HOME_ENV",
    "AGENTVEIL_MCP_PROXY_COMMAND_ENV",
    "AGENTVEIL_MCP_PROXY_RUN_ARGS_ENV",
    "AGENTVEIL_RUNTIME_PROFILE_ENV",
    "AGENTVEIL_RUNTIME_SESSION_ENV",
    "AgentLauncherError",
    "CenterStatus",
    "LaunchManifest",
    "LaunchResult",
    "LaunchStatus",
    "bounded_command_metadata",
    "build_launch_status",
    "check_approval_center_status",
    "ensure_approval_center_running",
    "ensure_runtime_state_home",
    "launch_managed_process",
    "load_launch_manifest",
    "normalize_child_command",
    "project_avp_home",
    "resolve_project_dir",
    "runtime_state_home",
    "save_launch_manifest",
    "stop_managed_launch",
    "write_runtime_route_config",
]
