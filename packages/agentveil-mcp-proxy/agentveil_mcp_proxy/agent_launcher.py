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
from pathlib import PurePosixPath
from pathlib import PureWindowsPath
from typing import Any, Callable, Literal, Mapping, Sequence

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
from agentveil_mcp_proxy.evidence.events_show import LOCAL_PROOF_LAUNCHER_HINT
from agentveil_mcp_proxy.evidence.store import ApprovalEvidenceStore


LAUNCH_MANIFEST_FILENAME = "runtime-launch.manifest.json"
LAUNCH_MANIFEST_SCHEMA_VERSION = 2
RUNTIME_ROUTE_FILENAME = "runtime-route.json"

AGENTVEIL_AVP_HOME_ENV = "AGENTVEIL_AVP_HOME"
AGENTVEIL_MCP_PROXY_COMMAND_ENV = "AGENTVEIL_MCP_PROXY_COMMAND"
AGENTVEIL_MCP_PROXY_RUN_ARGS_ENV = "AGENTVEIL_MCP_PROXY_RUN_ARGS"
AGENTVEIL_RUNTIME_PROFILE_ENV = "AGENTVEIL_RUNTIME_PROFILE"
AGENTVEIL_RUNTIME_SESSION_ENV = "AGENTVEIL_RUNTIME_SESSION_ID"

HERMES_HOME_ENV = "HERMES_HOME"
HERMES_MCP_SERVER_NAME = "agentveil"
HERMES_MCP_TOOLSET = HERMES_MCP_SERVER_NAME
HERMES_CONFIG_FILENAME = "config.yaml"

# Best-effort native-tool suppression for Hermes CLI launches. Live proof is still
# required before claiming full containment; users should also pass
# `--toolsets agentveil` (configured MCP server name) on the Hermes command line.
_HERMES_DISABLED_NATIVE_TOOLSETS = (
    "terminal",
    "web",
    "browser",
    "memory",
    "session_search",
    "cronjob",
    "code_execution",
    "delegation",
)

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

_HERMES_PROVIDER_ENV_KEYS = (
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
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
    child_exit_code: int | None = None
    child_foreground: bool = False


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


def hermes_runtime_home(home: Path, profile_id: str, session_id: str) -> Path:
    """Project-local Hermes data directory for the hermes-cli profile."""

    return home / "runtime" / profile_id / session_id / "hermes-home"


def hermes_config_path(hermes_home: Path) -> Path:
    return hermes_home / HERMES_CONFIG_FILENAME


def _yaml_scalar(value: str) -> str:
    if value and not any(ch in value for ch in ":#\"'\\{}\n\t"):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _yaml_unquote_scalar(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return text


def _hermes_proxy_stdio_invocation(
    proxy_command: str,
    run_args: list[str],
) -> tuple[str, list[str]]:
    """Return Hermes stdio MCP command/args for the AgentVeil proxy."""

    resolved = resolve_proxy_command(proxy_command)
    name = Path(resolved).name
    if name in {"python", "python3"} or name.startswith("python3."):
        return str(resolved), ["-m", "agentveil_mcp_proxy.cli", *run_args]
    which = shutil.which(resolved)
    return (which or resolved), list(run_args)


def _hermes_proxy_uses_python_module(proxy_command: str) -> bool:
    resolved = resolve_proxy_command(proxy_command)
    name = Path(resolved).name
    return name in {"python", "python3"} or name.startswith("python3.")


def _hermes_mcp_server_env(
    *,
    avp_home: Path,
    proxy_command: str,
    parent_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build bounded env for the Hermes MCP stdio subprocess."""

    env: dict[str, str] = {AGENTVEIL_AVP_HOME_ENV: str(avp_home)}
    if not _hermes_proxy_uses_python_module(proxy_command):
        return env
    source = dict(parent_env or os.environ)
    pythonpath = source.get("PYTHONPATH")
    if isinstance(pythonpath, str) and pythonpath.strip():
        env["PYTHONPATH"] = pythonpath
    return env


def build_hermes_config_document(
    *,
    proxy_command: str,
    run_args: list[str],
    avp_home: Path,
    parent_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    command, args = _hermes_proxy_stdio_invocation(proxy_command, run_args)
    mcp_entry: dict[str, Any] = {
        "command": command,
        "args": args,
        "env": _hermes_mcp_server_env(
            avp_home=avp_home,
            proxy_command=proxy_command,
            parent_env=parent_env,
        ),
    }
    return {
        "mcp_servers": {
            HERMES_MCP_SERVER_NAME: mcp_entry,
        },
        "agent": {
            "disabled_toolsets": list(_HERMES_DISABLED_NATIVE_TOOLSETS),
        },
    }


def render_hermes_config_yaml(document: Mapping[str, Any]) -> str:
    """Render a minimal Hermes config.yaml without external YAML dependencies."""

    lines: list[str] = []

    mcp_servers = document.get("mcp_servers")
    if isinstance(mcp_servers, Mapping):
        lines.append("mcp_servers:")
        for server_name, server_cfg in mcp_servers.items():
            if not isinstance(server_cfg, Mapping):
                continue
            lines.append(f"  {_yaml_scalar(str(server_name))}:")
            command = server_cfg.get("command")
            if isinstance(command, str) and command:
                lines.append(f"    command: {_yaml_scalar(command)}")
            args = server_cfg.get("args")
            if isinstance(args, list) and args:
                lines.append("    args:")
                for arg in args:
                    lines.append(f"      - {_yaml_scalar(str(arg))}")
            env = server_cfg.get("env")
            if isinstance(env, Mapping) and env:
                lines.append("    env:")
                for key, value in env.items():
                    lines.append(f"      {_yaml_scalar(str(key))}: {_yaml_scalar(str(value))}")

    agent = document.get("agent")
    if isinstance(agent, Mapping):
        disabled = agent.get("disabled_toolsets")
        if isinstance(disabled, list) and disabled:
            lines.append("agent:")
            lines.append("  disabled_toolsets:")
            for item in disabled:
                lines.append(f"    - {_yaml_scalar(str(item))}")

    return "\n".join(lines) + "\n"


def write_hermes_config(
    *,
    hermes_home: Path,
    proxy_command: str,
    run_args: list[str],
    avp_home: Path,
    parent_env: Mapping[str, str] | None = None,
) -> Path:
    """Bootstrap project-local Hermes config with the AgentVeil stdio MCP route."""

    ensure_runtime_state_home(hermes_home)
    document = build_hermes_config_document(
        proxy_command=proxy_command,
        run_args=run_args,
        avp_home=avp_home,
        parent_env=parent_env,
    )
    path = hermes_config_path(hermes_home)
    tmp_path = path.with_name(f".{path.name}.tmp")
    payload = render_hermes_config_yaml(document)
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(payload)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)
    verify_hermes_config_bootstrap(hermes_home)
    return path


def hermes_native_tool_containment_note() -> str:
    return (
        "Hermes native tools are limited via disabled_toolsets and --toolsets "
        f"{HERMES_MCP_TOOLSET}; full host-wide containment is not claimed"
    )


def preflight_hermes_cli_executable(command: Sequence[str]) -> None:
    """Reject launch when the Hermes CLI is missing or the child command is wrong."""

    if not command:
        raise AgentLauncherError(
            "hermes-cli profile requires a Hermes child command after '--'",
            exit_code=2,
        )
    argv0 = str(command[0])
    name = Path(argv0).name
    if name != "hermes":
        raise AgentLauncherError(
            "hermes-cli profile expects the child command to invoke hermes; "
            "example: launch --profile hermes-cli -- hermes chat --toolsets agentveil -q \"…\"",
            exit_code=2,
        )
    resolved = argv0 if Path(argv0).is_absolute() else shutil.which(argv0)
    if not resolved or not Path(resolved).exists():
        raise AgentLauncherError(
            "hermes executable not found; install Hermes Agent before launching hermes-cli profile",
            exit_code=1,
        )


def preflight_hermes_cli_provider(parent_env: Mapping[str, str] | None = None) -> None:
    """Reject launch when no usable LLM provider key is present for Hermes."""

    source = dict(parent_env or os.environ)
    for key in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
        value = source.get(key)
        if isinstance(value, str) and value.strip():
            return
    raise AgentLauncherError(
        "hermes-cli requires an LLM provider key in the operator environment "
        "(set DEEPSEEK_API_KEY or OPENAI_API_KEY before launch)",
        exit_code=1,
    )


def _merge_hermes_provider_env(
    env: dict[str, str],
    parent_env: Mapping[str, str],
) -> None:
    for key in _HERMES_PROVIDER_ENV_KEYS:
        value = parent_env.get(key)
        if isinstance(value, str) and value:
            env[key] = value


def prepare_hermes_cli_command(command: Sequence[str]) -> list[str]:
    """Inject the recommended MCP-only toolset when the launch omits --toolsets."""

    tokens = [str(item) for item in command]
    if "--toolsets" in tokens:
        return tokens
    try:
        chat_index = tokens.index("chat")
    except ValueError:
        return tokens
    return [
        *tokens[: chat_index + 1],
        "--toolsets",
        HERMES_MCP_TOOLSET,
        *tokens[chat_index + 1 :],
    ]


def _hermes_proxy_run_args(args: Sequence[str]) -> list[str]:
    """Return the ``agentveil-mcp-proxy run`` argv from a Hermes MCP args block."""

    if not args:
        raise AgentLauncherError("hermes config missing AgentVeil MCP args", exit_code=1)
    if str(args[0]) == "run":
        return list(args)
    if (
        len(args) >= 3
        and str(args[0]) == "-m"
        and str(args[1]) == "agentveil_mcp_proxy.cli"
        and str(args[2]) == "run"
    ):
        return list(args[2:])
    raise AgentLauncherError(
        "hermes config AgentVeil MCP args must start with run or "
        "python -m agentveil_mcp_proxy.cli run",
        exit_code=1,
    )


def verify_hermes_config_bootstrap(hermes_home: Path) -> dict[str, Any]:
    """Reject launch when Hermes config is missing the AgentVeil stdio MCP route."""

    parsed = parse_hermes_agentveil_stdio_config(hermes_home)
    if not str(parsed.get("command", "")).strip():
        raise AgentLauncherError("hermes config missing AgentVeil MCP command", exit_code=1)
    _hermes_proxy_run_args(parsed.get("args", []))
    return parsed


def parse_hermes_agentveil_stdio_config(hermes_home: Path) -> dict[str, Any]:
    """Parse the AgentVeil stdio MCP block from a bootstrap-generated Hermes config."""

    path = hermes_config_path(hermes_home)
    if not path.is_file():
        raise AgentLauncherError("hermes config missing after bootstrap", exit_code=1)

    in_agentveil = False
    in_args = False
    in_env = False
    in_disabled = False
    command: str | None = None
    args: list[str] = []
    env: dict[str, str] = {}
    disabled: list[str] = []

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == f"{HERMES_MCP_SERVER_NAME}:":
            in_agentveil = True
            in_args = False
            in_env = False
            continue
        if stripped == "agent:":
            in_agentveil = False
            in_disabled = False
            continue
        if stripped == "disabled_toolsets:":
            in_disabled = True
            in_agentveil = False
            continue
        if in_disabled and stripped.startswith("- "):
            disabled.append(stripped[2:].strip().strip('"'))
            continue
        if not in_agentveil:
            continue
        if stripped.startswith("command:"):
            command = _yaml_unquote_scalar(stripped.split(":", 1)[1])
            in_args = False
            in_env = False
        elif stripped == "args:":
            in_args = True
            in_env = False
        elif stripped == "env:":
            in_env = True
            in_args = False
        elif in_args and stripped.startswith("- "):
            args.append(_yaml_unquote_scalar(stripped[2:]))
        elif in_env and ":" in stripped:
            key, _, value = stripped.partition(":")
            env[key.strip()] = _yaml_unquote_scalar(value)
        elif not raw_line.startswith("  "):
            in_agentveil = False

    if not command:
        raise AgentLauncherError("hermes config missing AgentVeil MCP command", exit_code=1)
    if not args:
        raise AgentLauncherError("hermes config missing AgentVeil MCP args", exit_code=1)

    return {
        "server_name": HERMES_MCP_SERVER_NAME,
        "command": command,
        "args": args,
        "env": env,
        "disabled_toolsets": disabled,
    }


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


def _command_name(proxy_command: str) -> str:
    if "\\" in proxy_command:
        return PureWindowsPath(proxy_command).name
    return Path(proxy_command).name


def _is_python_command_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in {"python", "python.exe", "python3", "python3.exe"}:
        return True
    if not lowered.startswith("python3."):
        return False
    version = lowered[len("python3.") :]
    if version.endswith(".exe"):
        version = version[:-4]
    if not version:
        return False
    for part in version.split("."):
        if not part.isdigit():
            return False
    return True


def _proxy_cli_argv(proxy_command: str, subcommand: list[str]) -> list[str]:
    """Build argv for a proxy CLI subcommand in a fresh interpreter when needed."""

    command_path = Path(proxy_command)
    if _is_python_command_name(_command_name(proxy_command)):
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
    name = _command_name(proxy_command)
    if "/" in proxy_command:
        name = PurePosixPath(proxy_command).name
    if _is_python_command_name(name):
        return "agentveil-mcp-proxy"
    if command_path.is_absolute() or "/" in proxy_command:
        return name
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
    from agentveil_mcp_proxy.approval.server import inspect_managed_approval_center

    managed = inspect_managed_approval_center(home)
    return CenterStatus(
        state=managed.state,
        pid=managed.pid,
        port=managed.port,
    )


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
    from agentveil_mcp_proxy.approval.server import ensure_managed_approval_center_running

    def spawn() -> None:
        _spawn_approval_center(
            proxy_command=proxy_command,
            home=home,
            passphrase_file=passphrase_file,
        )

    managed = ensure_managed_approval_center_running(home=home, spawn=spawn)
    center = CenterStatus(
        state=managed.status.state,
        pid=managed.status.pid,
        port=managed.status.port,
    )
    return center, managed.started, managed.reason


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
    if profile.profile_id == "hermes-cli":
        _merge_hermes_provider_env(env, source)
    return env


def write_runtime_route_config(
    *,
    home: Path,
    profile: RuntimeProfileSpec,
    session_id: str,
    proxy_command: str,
    run_args: list[str],
    runtime_home: Path | None = None,
    hermes_home: Path | None = None,
) -> None:
    command_display = Path(proxy_command).name if Path(proxy_command).is_absolute() else proxy_command
    payload: dict[str, Any] = {
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
    if hermes_home is not None:
        payload["hermes_home_ref"] = bounded_path_ref(hermes_home)
        payload["hermes_mcp_server"] = HERMES_MCP_SERVER_NAME
        payload["hermes_toolset"] = HERMES_MCP_TOOLSET
        payload["native_tool_containment"] = hermes_native_tool_containment_note()
    path = runtime_route_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def _write_proxy_config_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def ensure_interactive_connector_defaults(config_path: Path) -> None:
    """Enable bounded approval wait-mode for interactive MCP client launches."""

    if not config_path.is_file():
        return
    try:
        config_payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return
    if not isinstance(config_payload, dict):
        return
    approval = config_payload.get("approval")
    if not isinstance(approval, dict):
        approval = {}
        config_payload["approval"] = approval
    if approval.get("wait_for_decision") is True:
        return
    approval["wait_for_decision"] = True
    _write_proxy_config_json(config_path, config_payload)


def build_launch_status(
    *,
    home: Path,
    profile: RuntimeProfileSpec,
    project_dir: Path,
) -> LaunchStatus:
    launch_manifest = load_launch_manifest(home)
    manifest_profile_id = (
        getattr(launch_manifest, "profile_id", None) if launch_manifest is not None else None
    )
    if manifest_profile_id:
        try:
            profile = resolve_runtime_profile(manifest_profile_id)
        except RuntimeProfileError:
            pass
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
    if profile.profile_id == "hermes-cli":
        preflight_hermes_cli_executable(command)
        preflight_hermes_cli_provider()
        command = prepare_hermes_cli_command(command)
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

    if profile.profile_id == "hermes-cli":
        ensure_interactive_connector_defaults(config_path)

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
    hermes_home: Path | None = None
    if profile.profile_id == "hermes-cli":
        hermes_home = hermes_runtime_home(home, profile.profile_id, session_id)
        try:
            write_hermes_config(
                hermes_home=hermes_home,
                proxy_command=resolved_proxy_command,
                run_args=run_args,
                avp_home=home,
                parent_env=os.environ,
            )
        except OSError as exc:
            raise AgentLauncherError(
                f"hermes config bootstrap failed: {exc.__class__.__name__}",
                exit_code=1,
            ) from exc
        runtime_home = hermes_home
    else:
        runtime_home = runtime_state_home(home, profile.profile_id, session_id)
        ensure_runtime_state_home(runtime_home)
    write_runtime_route_config(
        home=home,
        profile=profile,
        session_id=session_id,
        proxy_command=proxy_command_display,
        run_args=run_args,
        runtime_home=runtime_home,
        hermes_home=hermes_home,
    )
    child_env = _bounded_child_env(
        home=home,
        runtime_home=runtime_home,
        profile=profile,
        session_id=session_id,
        proxy_command=proxy_command_display,
        run_args=run_args,
        parent_env=os.environ,
    )
    if hermes_home is not None:
        child_env[HERMES_HOME_ENV] = str(hermes_home)

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

    child_exit_code: int | None = None
    child_foreground = not profile.child_detach
    if child_foreground:
        child_exit_code = process.wait()

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
        child_exit_code=child_exit_code,
        child_foreground=child_foreground,
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

    from agentveil_mcp_proxy.approval.server import stop_managed_approval_center

    center_stop = stop_managed_approval_center(home, require_healthy=False)
    stopped_center = bool(center_stop.get("stopped"))
    center_reason = str(center_stop.get("reason") or "managed approval center stop attempted")
    reasons.append(center_reason)

    return {
        "stopped_child": stopped_child,
        "stopped_center": stopped_center,
        "reasons": reasons,
    }


ProtectionMode = Literal["controlled MCP route", "advisory", "not protected"]
McpRouteState = Literal["configured", "missing"]
EvidenceObservationState = Literal["observed", "ready_no_records", "not_initialized"]


@dataclass(frozen=True)
class LaunchStatusView:
    """Shared human/JSON launcher status view derived from runtime facts."""

    status: LaunchStatus
    profile: RuntimeProfileSpec
    mcp_route_state: McpRouteState
    evidence_state: EvidenceObservationState
    protection_mode: ProtectionMode
    proof_hint: str
    next_step: str
    diagnostics: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = self.status.to_dict()
        payload.update(
            {
                "profile_label": self.profile.display_name,
                "control_surface": self.profile.control_surface,
                "known_limitations": self.profile.known_limitations,
                "mcp_route_state": self.mcp_route_state,
                "evidence_state": self.evidence_state,
                "protection_mode": self.protection_mode,
                "proof_hint": self.proof_hint,
                "next_step": self.next_step,
                "diagnostics": list(self.diagnostics),
            }
        )
        return payload


def _evidence_record_count(home: Path) -> int:
    evidence_path = proxy_dir(home) / "evidence.sqlite"
    if not evidence_path.is_file():
        return 0
    try:
        with ApprovalEvidenceStore(evidence_path) as store:
            return len(store.list_records())
    except (OSError, ValueError, RuntimeError):
        return 0


def classify_mcp_route_state(home: Path) -> McpRouteState:
    if (proxy_dir(home) / "config.json").is_file():
        return "configured"
    return "missing"


def classify_evidence_state(*, home: Path, config_exists: bool) -> EvidenceObservationState:
    if not config_exists:
        return "not_initialized"
    if _evidence_record_count(home) > 0:
        return "observed"
    return "ready_no_records"


def derive_protection_mode(
    *,
    mcp_route_state: McpRouteState,
    center: CenterStatus,
    profile_id: str,
) -> ProtectionMode:
    if mcp_route_state == "missing":
        return "not protected"
    if center.state != "running":
        return "advisory"
    if profile_id == "hermes-cli":
        return "advisory"
    return "controlled MCP route"


def _profile_activity_label(profile_status: str) -> str:
    if profile_status == "running":
        return "running"
    if profile_status == "stopped":
        return "stopped"
    if profile_status == "verify_only":
        return "not launched yet"
    return "ready"


def _child_outcome_label(
    *,
    child_foreground: bool,
    child_started: bool,
    child_running: bool,
    child_exit_code: int | None,
) -> str:
    if child_foreground:
        if child_exit_code == 0:
            return "finished"
        if child_exit_code is not None:
            return "failed"
        return "running"
    if child_running:
        return "running"
    if child_started:
        return "started"
    return "not started"


def build_launch_diagnostics(
    *,
    status: LaunchStatus,
    mcp_route_state: McpRouteState,
    evidence_state: EvidenceObservationState,
    profile_id: str,
    protection_mode: ProtectionMode,
) -> tuple[str, ...]:
    diagnostics: list[str] = []
    center_state = status.approval_center.state
    if center_state == "down":
        diagnostics.append(
            "Approval center is down; pre-approval and controlled MCP writes may fail."
        )
    elif center_state == "stale":
        diagnostics.append(
            "Approval center looks stale; restart launch or run approval-center serve."
        )
    if mcp_route_state == "missing":
        diagnostics.append("MCP route is not configured for this project.")
    if evidence_state == "ready_no_records":
        diagnostics.append("No local proof recorded yet; run a routed MCP action first.")
    elif evidence_state == "not_initialized":
        diagnostics.append("Local proof store is not initialized.")
    if profile_id == "hermes-cli" and protection_mode == "advisory":
        diagnostics.append(
            "Native Hermes tools may bypass the MCP route; use --toolsets agentveil."
        )
    return tuple(diagnostics)


def build_launch_proof_hint(*, evidence_state: EvidenceObservationState) -> str:
    if evidence_state == "observed":
        return LOCAL_PROOF_LAUNCHER_HINT
    return ""


def build_launch_next_step(
    *,
    protection_mode: ProtectionMode,
    mcp_route_state: McpRouteState,
    center: CenterStatus,
    profile_status: str,
    child_running: bool,
    evidence_state: EvidenceObservationState,
) -> str:
    if mcp_route_state == "missing":
        return (
            "Initialize the project proxy route, then run "
            "`agentveil-mcp-proxy launch` again."
        )
    if evidence_state == "not_initialized":
        return (
            "Initialize the project proxy route, then run "
            "`agentveil-mcp-proxy launch` again."
        )
    if center.state != "running":
        return (
            "Start or restart the Approval Center, then retry a routed MCP action."
        )
    if profile_status == "verify_only":
        return (
            "Run `agentveil-mcp-proxy launch --profile <profile> --project-dir . -- <command>` "
            "to start a managed child."
        )
    if evidence_state == "ready_no_records":
        return (
            "Run a routed MCP action first; local proof will be recorded after "
            "the first action."
        )
    if evidence_state == "observed":
        return LOCAL_PROOF_LAUNCHER_HINT
    if child_running:
        return (
            "Let the managed child run routed MCP actions, then inspect local proof "
            "through your agent."
        )
    if protection_mode == "advisory":
        return (
            "Keep the child on the AgentVeil MCP route, then run a routed MCP action."
        )
    return (
        "Run a routed MCP action first; local proof will be recorded after "
        "the first action."
    )


def build_launch_status_view(
    *,
    home: Path,
    profile: RuntimeProfileSpec,
    project_dir: Path,
) -> LaunchStatusView:
    status = build_launch_status(home=home, profile=profile, project_dir=project_dir)
    config_exists = (proxy_dir(home) / "config.json").is_file()
    mcp_route_state = classify_mcp_route_state(home)
    evidence_state = classify_evidence_state(home=home, config_exists=config_exists)
    protection_mode = derive_protection_mode(
        mcp_route_state=mcp_route_state,
        center=status.approval_center,
        profile_id=profile.profile_id,
    )
    diagnostics = build_launch_diagnostics(
        status=status,
        mcp_route_state=mcp_route_state,
        evidence_state=evidence_state,
        profile_id=profile.profile_id,
        protection_mode=protection_mode,
    )
    proof_hint = build_launch_proof_hint(evidence_state=evidence_state)
    next_step = build_launch_next_step(
        protection_mode=protection_mode,
        mcp_route_state=mcp_route_state,
        center=status.approval_center,
        profile_status=status.profile_status,
        child_running=status.child_running,
        evidence_state=evidence_state,
    )
    return LaunchStatusView(
        status=status,
        profile=profile,
        mcp_route_state=mcp_route_state,
        evidence_state=evidence_state,
        protection_mode=protection_mode,
        proof_hint=proof_hint,
        next_step=next_step,
        diagnostics=diagnostics,
    )


def format_launch_status_human(view: LaunchStatusView) -> list[str]:
    status = view.status
    activity = _profile_activity_label(status.profile_status)
    lines = [
        "AgentVeil managed runtime status",
        f"Profile:         {view.profile.display_name} ({status.profile_id}) — {activity}",
        f"Protection:      {view.protection_mode}",
        f"Controls:        {view.profile.control_surface}",
        f"Limitation:      {view.profile.known_limitations}",
        f"Approval center: {status.approval_center.state}",
        f"MCP route:       {view.mcp_route_state}",
        f"Local proof:     {view.evidence_state.replace('_', ' ')}",
    ]
    if status.child_running:
        lines.append(f"Managed child:   running (pid {status.child_pid})")
    elif status.profile_status == "stopped":
        lines.append("Managed child:   stopped")
    lines.append(f"Next:            {view.next_step}")
    if view.diagnostics:
        lines.append("Notes:")
        lines.extend(f"  - {item}" for item in view.diagnostics)
    if view.proof_hint:
        lines.append(f"Proof hint:      {view.proof_hint}")
    return lines


def format_launch_result_human(
    *,
    result: LaunchResult,
    view: LaunchStatusView,
) -> list[str]:
    status = view.status
    child_label = _child_outcome_label(
        child_foreground=result.child_foreground,
        child_started=result.child_started,
        child_running=status.child_running,
        child_exit_code=result.child_exit_code,
    )
    lines = [
        "AgentVeil managed runtime launch",
        f"Profile:         {view.profile.display_name} ({status.profile_id})",
        f"Protection:      {view.protection_mode}",
        f"Controls:        {view.profile.control_surface}",
        f"Limitation:      {view.profile.known_limitations}",
        f"Managed child:   {child_label}",
        f"Approval center: {status.approval_center.state}",
        f"MCP route:       {view.mcp_route_state}",
        f"Local proof:     {view.evidence_state.replace('_', ' ')}",
    ]
    if result.proxy_initialized:
        lines.append("Proxy route:     initialized for this project")
    if result.child_foreground and result.child_exit_code is not None:
        lines.append(f"Exit code:       {result.child_exit_code}")
    lines.append(f"Next:            {view.next_step}")
    if view.diagnostics:
        lines.append("Notes:")
        lines.extend(f"  - {item}" for item in view.diagnostics)
    if view.proof_hint:
        lines.append(f"Proof hint:      {view.proof_hint}")
    return lines


def build_launch_result_payload(
    *,
    result: LaunchResult,
    view: LaunchStatusView,
) -> dict[str, Any]:
    status = view.status
    payload = view.to_dict()
    payload.update(
        {
            "ok": result.child_exit_code in (None, 0),
            "action": "launch",
            "child_started": result.child_started,
            "child_running": status.child_running,
            "child_foreground": result.child_foreground,
            "child_exit_code": result.child_exit_code,
            "child_outcome": _child_outcome_label(
                child_foreground=result.child_foreground,
                child_started=result.child_started,
                child_running=status.child_running,
                child_exit_code=result.child_exit_code,
            ),
            "proxy_initialized": result.proxy_initialized,
            "reason": result.reason,
        }
    )
    return payload


ProjectRouteState = Literal["ready", "missing"]
ApprovalWaitState = Literal["enabled", "not configured", "not applicable"]
ProviderKeyState = Literal["present", "missing", "not applicable"]


@dataclass(frozen=True)
class LaunchDoctorReport:
    """Read-only managed-runtime preflight report."""

    profile_id: str
    profile_label: str
    project_dir_ref: str
    project_route: ProjectRouteState
    approval_center: str
    approval_wait: ApprovalWaitState
    local_proof: str
    provider_key: ProviderKeyState
    evidence_state: EvidenceObservationState
    mcp_route_state: McpRouteState
    ready: bool
    blocking: tuple[str, ...]
    next_step: str
    diagnostics: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": "launch-doctor",
            "ok": self.ready,
            "profile_id": self.profile_id,
            "profile_label": self.profile_label,
            "project_dir_ref": self.project_dir_ref,
            "project_route": self.project_route,
            "approval_center": self.approval_center,
            "approval_wait": self.approval_wait,
            "local_proof": self.local_proof,
            "provider_key": self.provider_key,
            "evidence_state": self.evidence_state,
            "mcp_route_state": self.mcp_route_state,
            "ready": self.ready,
            "blocking": list(self.blocking),
            "next_step": self.next_step,
            "diagnostics": list(self.diagnostics),
        }


def _doctor_local_proof_label(state: EvidenceObservationState) -> str:
    if state == "observed":
        return "observed"
    if state == "ready_no_records":
        return "empty"
    return "not initialized"


def classify_approval_wait_mode(
    home: Path,
    profile: RuntimeProfileSpec,
) -> ApprovalWaitState:
    if profile.profile_id != "hermes-cli":
        return "not applicable"
    config_path = proxy_dir(home) / "config.json"
    if not config_path.is_file():
        return "not configured"
    try:
        config_payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return "not configured"
    if not isinstance(config_payload, dict):
        return "not configured"
    approval = config_payload.get("approval")
    if isinstance(approval, Mapping) and approval.get("wait_for_decision") is True:
        return "enabled"
    return "not configured"


def classify_provider_prerequisite(
    profile: RuntimeProfileSpec,
    parent_env: Mapping[str, str] | None = None,
) -> ProviderKeyState:
    if profile.profile_id != "hermes-cli":
        return "not applicable"
    source = dict(parent_env or os.environ)
    for key in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
        value = source.get(key)
        if isinstance(value, str) and value.strip():
            return "present"
    return "missing"


def _doctor_route_source_diagnostics(home: Path) -> tuple[str, ...]:
    route_path = runtime_route_path(home)
    if not route_path.is_file():
        return ()
    try:
        route_payload = json.loads(route_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return ()
    if not isinstance(route_payload, Mapping):
        return ()
    proxy_command = str(route_payload.get("proxy_command") or "").strip()
    if proxy_command in {"python", "python3", "agentveil-mcp-proxy"}:
        return (
            "Proxy route uses a module/source launch path; verify PYTHONPATH before launch.",
        )
    run_args = route_payload.get("run_args")
    if isinstance(run_args, list) and any(
        str(item) == "agentveil_mcp_proxy.cli" for item in run_args
    ):
        return (
            "Proxy route uses a module/source launch path; verify PYTHONPATH before launch.",
        )
    return ()


def build_launch_doctor_blocking(
    *,
    project_route: ProjectRouteState,
    approval_center: CenterStatus,
    approval_wait: ApprovalWaitState,
    provider_key: ProviderKeyState,
) -> tuple[str, ...]:
    blocking: list[str] = []
    if project_route == "missing":
        blocking.append("project_route")
    if approval_center.state != "running":
        blocking.append("approval_center")
    if approval_wait == "not configured":
        blocking.append("approval_wait")
    if provider_key == "missing":
        blocking.append("provider_key")
    return tuple(blocking)


def build_launch_doctor_next_step(
    *,
    profile: RuntimeProfileSpec,
    blocking: tuple[str, ...],
    ready: bool,
) -> str:
    if ready:
        return "Next: run `agentveil-mcp-proxy launch` normally."
    if "project_route" in blocking:
        return (
            f"Next: initialize the project route with "
            f"`agentveil-mcp-proxy launch --profile {profile.profile_id} ...`."
        )
    if "approval_center" in blocking:
        return "Next: start or restart the Approval Center, then rerun launch doctor."
    if "approval_wait" in blocking:
        return (
            "Next: enable approval wait mode for this project route, then rerun "
            "launch doctor."
        )
    if "provider_key" in blocking:
        return (
            "Next: set DEEPSEEK_API_KEY or OPENAI_API_KEY in your environment, "
            "then rerun launch doctor."
        )
    return "Next: resolve the blocking items above before launching."


def build_launch_doctor_diagnostics(
    *,
    approval_center: CenterStatus,
    project_route: ProjectRouteState,
    evidence_state: EvidenceObservationState,
    profile_id: str,
    home: Path,
) -> tuple[str, ...]:
    diagnostics: list[str] = []
    if approval_center.state == "down":
        diagnostics.append(
            "Approval Center is down; controlled MCP writes may fail until it is running."
        )
    elif approval_center.state == "stale":
        diagnostics.append(
            "Approval Center looks stale; restart it before launching an interactive agent."
        )
    if project_route == "missing":
        diagnostics.append("Project MCP route is not initialized for this folder.")
    if evidence_state == "ready_no_records":
        diagnostics.append("Local proof store is ready but no actions have been recorded yet.")
    elif evidence_state == "not_initialized":
        diagnostics.append("Local proof store is not initialized.")
    if profile_id == "hermes-cli":
        diagnostics.append(
            "Hermes launches require --toolsets agentveil to stay on the MCP route."
        )
    diagnostics.extend(_doctor_route_source_diagnostics(home))
    return tuple(diagnostics)


def build_launch_doctor_report(
    *,
    home: Path,
    profile: RuntimeProfileSpec,
    project_dir: Path,
    parent_env: Mapping[str, str] | None = None,
) -> LaunchDoctorReport:
    config_exists = (proxy_dir(home) / "config.json").is_file()
    mcp_route_state = classify_mcp_route_state(home)
    project_route: ProjectRouteState = (
        "ready" if mcp_route_state == "configured" else "missing"
    )
    approval_center = check_approval_center_status(home)
    evidence_state = classify_evidence_state(home=home, config_exists=config_exists)
    approval_wait = classify_approval_wait_mode(home, profile)
    provider_key = classify_provider_prerequisite(profile, parent_env=parent_env)
    blocking = build_launch_doctor_blocking(
        project_route=project_route,
        approval_center=approval_center,
        approval_wait=approval_wait,
        provider_key=provider_key,
    )
    ready = not blocking
    diagnostics = build_launch_doctor_diagnostics(
        approval_center=approval_center,
        project_route=project_route,
        evidence_state=evidence_state,
        profile_id=profile.profile_id,
        home=home,
    )
    next_step = build_launch_doctor_next_step(
        profile=profile,
        blocking=blocking,
        ready=ready,
    )
    return LaunchDoctorReport(
        profile_id=profile.profile_id,
        profile_label=profile.display_name,
        project_dir_ref=bounded_path_ref(project_dir)["ref"] or "",
        project_route=project_route,
        approval_center=approval_center.state,
        approval_wait=approval_wait,
        local_proof=_doctor_local_proof_label(evidence_state),
        provider_key=provider_key,
        evidence_state=evidence_state,
        mcp_route_state=mcp_route_state,
        ready=ready,
        blocking=blocking,
        next_step=next_step,
        diagnostics=diagnostics,
    )


def format_launch_doctor_human(report: LaunchDoctorReport) -> list[str]:
    lines = [
        "AgentVeil launcher doctor",
        "",
        f"Profile:          {report.profile_id}",
        f"Project route:    {report.project_route}",
        f"Approval Center:  {report.approval_center}",
        f"Approval wait:    {report.approval_wait}",
        f"Local proof:      {report.local_proof}",
    ]
    if report.provider_key != "not applicable":
        lines.append(f"Provider key:     {report.provider_key}")
    lines.append("")
    lines.append(report.next_step)
    if report.diagnostics:
        lines.append("Notes:")
        lines.extend(f"  - {item}" for item in report.diagnostics)
    return lines


__all__ = [
    "AGENTVEIL_AVP_HOME_ENV",
    "AGENTVEIL_MCP_PROXY_COMMAND_ENV",
    "AGENTVEIL_MCP_PROXY_RUN_ARGS_ENV",
    "AGENTVEIL_RUNTIME_PROFILE_ENV",
    "AGENTVEIL_RUNTIME_SESSION_ENV",
    "AgentLauncherError",
    "CenterStatus",
    "HERMES_HOME_ENV",
    "HERMES_MCP_SERVER_NAME",
    "HERMES_MCP_TOOLSET",
    "LaunchDoctorReport",
    "LaunchManifest",
    "LaunchResult",
    "LaunchStatus",
    "LaunchStatusView",
    "ProtectionMode",
    "bounded_command_metadata",
    "build_hermes_config_document",
    "build_launch_doctor_blocking",
    "build_launch_doctor_diagnostics",
    "build_launch_doctor_next_step",
    "build_launch_doctor_report",
    "build_launch_diagnostics",
    "build_launch_next_step",
    "build_launch_proof_hint",
    "build_launch_result_human",
    "build_launch_result_payload",
    "build_launch_status",
    "build_launch_status_view",
    "check_approval_center_status",
    "classify_approval_wait_mode",
    "classify_evidence_state",
    "classify_mcp_route_state",
    "classify_provider_prerequisite",
    "derive_protection_mode",
    "ensure_approval_center_running",
    "ensure_interactive_connector_defaults",
    "ensure_runtime_state_home",
    "format_launch_doctor_human",
    "format_launch_result_human",
    "format_launch_status_human",
    "hermes_config_path",
    "hermes_native_tool_containment_note",
    "hermes_runtime_home",
    "launch_managed_process",
    "load_launch_manifest",
    "normalize_child_command",
    "parse_hermes_agentveil_stdio_config",
    "preflight_hermes_cli_executable",
    "preflight_hermes_cli_provider",
    "prepare_hermes_cli_command",
    "project_avp_home",
    "render_hermes_config_yaml",
    "resolve_project_dir",
    "runtime_state_home",
    "save_launch_manifest",
    "stop_managed_launch",
    "verify_hermes_config_bootstrap",
    "write_hermes_config",
    "write_runtime_route_config",
]
