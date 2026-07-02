"""Project-local Cursor one-command setup (hooks, MCP route, Approval Center).

Public SDK surface for ``agentveil-mcp-proxy setup cursor --yes``. Writes merge-
preserving entries into ``.cursor/hooks.json`` and ``.cursor/mcp.json``,
initializes workspace-scoped ``.agentveil`` proxy home, owns the generic local
Approval Center lifecycle, and reports bounded ``Protected`` / ``Advisory`` /
``Unsafe`` status.
"""

from __future__ import annotations

import json
import os
import secrets
import shlex
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentveil_mcp_proxy.client_connect import resolve_cursor_global_mcp_json_path
from agentveil_mcp_proxy.cursor_hooks import AGENTVEIL_MCP_SERVER_KEY
from agentveil_mcp_proxy.cursor_user_mcp import (
    detect_unmanaged_user_mcp_route,
    install_user_mcp_route,
    remove_user_mcp_route,
    user_mcp_route_is_managed,
    user_mcp_route_present,
)
from agentveil_mcp_proxy.product_route import (
    PRODUCT_ROUTE_DOWNSTREAM_NAME,
    build_product_route_downstream_config,
    initialize_product_route_profile,
)

AGENTVEIL_HOOK_MARKER = "agentveil_mcp_proxy.cursor_hooks"
AGENTVEIL_HOOK_EVENTS = ("preToolUse", "beforeShellExecution", "beforeMCPExecution")
MATCHED_TOOL_CLASSES = ("Write", "Edit", "StrReplace", "ApplyPatch", "Delete", "Shell", "mcp__*")
MCP_ROUTE_ENV_KEYS = (
    "DOWNSTREAM_NAME",
    "AVP_HOME",
    "MCP_CONTENT_ROOT",
    "AVP_CURSOR_WORKSPACE",
    "PRODUCT_ROUTE_PROFILE_ROOT",
)
USER_MCP_BACKUP_DIRNAME = "cursor-setup/user-mcp-backups"
USER_MCP_BACKUP_PREFIX = "user-mcp.json"

BROAD_FOLDER_MESSAGE = (
    "This looks like a broad folder, not a project workspace.\n"
    "Choose a project folder instead."
)
SETUP_ADVISORY_NEXT_STEP = (
    "installed; waiting for Cursor reload / MCP confirmation"
)
_BROAD_CONTAINER_DIRNAMES = frozenset({".worktrees", "worktrees"})
_PROJECT_MARKERS = (
    ".git",
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pnpm-workspace.yaml",
    "composer.json",
)

_START_TIMEOUT_SECONDS = 12.0
_POLL_INTERVAL_SECONDS = 0.2
_HEALTH_TIMEOUT_SECONDS = 1.5


class CursorSetupError(RuntimeError):
    """Raised when install/uninstall cannot proceed safely."""


class BroadWorkspaceError(CursorSetupError):
    """Raised when the selected workspace is too broad for project setup."""


def has_project_markers(path: Path) -> bool:
    """True when *path* looks like a project root rather than a container folder."""
    for marker in _PROJECT_MARKERS:
        if (path / marker).exists():
            return True
    return False


def is_broad_workspace(path: Path) -> bool:
    """True for home/desktop/downloads/root and obvious non-project containers."""
    resolved = path.expanduser().resolve()
    home = Path.home().resolve()
    if resolved in {home, Path("/")}:
        return True
    if resolved in {home / "Desktop", home / "Downloads"}:
        return True
    if resolved.parent == Path("/Users") and resolved.name == home.name:
        return True
    if has_project_markers(resolved):
        return False
    if resolved.name in _BROAD_CONTAINER_DIRNAMES:
        return True
    return False


def format_setup_success_message(workspace: Path, *, status: dict[str, Any]) -> str:
    """User-facing success summary with honest next steps (no false protected claim)."""
    lines = [
        "AgentVeil is installed for:",
        f"  {workspace.resolve()}",
        "",
        "Next:",
        "1. Reopen Cursor in this folder.",
        "2. Open Settings -> Tools & MCPs.",
        "3. Confirm agentveil-mcp-proxy is enabled.",
        "4. Try: Create avp-test.txt with the text hello.",
    ]
    if status.get("status") == "protected" and status.get("mcp_route_observed"):
        lines.extend(["", "MCP route activity was observed in bounded evidence."])
    else:
        lines.extend([
            "",
            "Setup files are in place; Cursor must reload and enable the MCP server "
            "before writes are routed through AgentVeil.",
        ])
    return "\n".join(lines)


def setup_home(workspace: Path) -> Path:
    return Path(workspace).resolve() / ".agentveil"


def project_cursor_dir(workspace: Path) -> Path:
    return Path(workspace).resolve() / ".cursor"


def hooks_config_path(workspace: Path) -> Path:
    return project_cursor_dir(workspace) / "hooks.json"


def mcp_config_path(workspace: Path) -> Path:
    return project_cursor_dir(workspace) / "mcp.json"


def project_evidence_path(workspace: Path) -> Path:
    return project_cursor_dir(workspace) / "agentveil" / "evidence.jsonl"


def passphrase_path(home: Path) -> Path:
    return Path(home) / "passphrase"


def profile_root(home: Path) -> Path:
    return Path(home) / "product-profile"


def proxy_config_path(home: Path) -> Path:
    return Path(home) / "mcp-proxy" / "config.json"


def _proxy_dir(home: Path) -> Path:
    return Path(home) / "mcp-proxy"


def load_json_object(path: Path, *, label: str | None = None) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CursorSetupError(f"cannot read {label or path.name}: {exc.__class__.__name__}") from exc
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CursorSetupError(
            f"existing {label or path.name} is not valid JSON; refusing to overwrite"
        ) from exc
    if not isinstance(data, dict):
        raise CursorSetupError(f"existing {label or path.name} must be a JSON object")
    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def build_hook_command(
    *,
    python: str,
    workspace: Path,
    home: Path,
    evidence_path: Path,
    hook_event: str,
) -> str:
    return (
        f"{shlex.quote(python)} -m {AGENTVEIL_HOOK_MARKER} "
        f"--workspace {shlex.quote(str(workspace))} "
        f"--home {shlex.quote(str(home))} "
        f"--evidence-path {shlex.quote(str(evidence_path))} "
        f"--hook-event {shlex.quote(hook_event)}"
    )


def build_managed_hook_entry(
    *,
    python: str,
    workspace: Path,
    home: Path,
    evidence_path: Path,
    hook_event: str,
) -> dict[str, Any]:
    return {
        "command": build_hook_command(
            python=python,
            workspace=workspace,
            home=home,
            evidence_path=evidence_path,
            hook_event=hook_event,
        ),
        "failClosed": True,
    }


def is_managed_hook_command(command: str) -> bool:
    """True only for hooks installed by this module (exact module marker)."""
    return AGENTVEIL_HOOK_MARKER in str(command)


def _is_agentveil_hook_command(command: str) -> bool:
    return is_managed_hook_command(command)


def _ensure_passphrase(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        return
    path.write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _ensure_workspace_sandbox(profile: Path, workspace: Path, *, force: bool = False) -> None:
    from agentveil_mcp_proxy.product_route_local_fixtures import PRODUCT_ROUTE_WORKSPACE_DIRNAME

    profile.mkdir(parents=True, exist_ok=True)
    sandbox = profile / PRODUCT_ROUTE_WORKSPACE_DIRNAME
    workspace = workspace.resolve()
    if sandbox.is_symlink():
        if sandbox.resolve() != workspace:
            sandbox.unlink()
            sandbox.symlink_to(workspace, target_is_directory=True)
        return
    if sandbox.exists():
        if sandbox.resolve() == workspace:
            return
        if force and sandbox.is_dir() and not any(sandbox.iterdir()):
            sandbox.rmdir()
        elif force:
            import shutil

            if sandbox.is_dir():
                shutil.rmtree(sandbox)
            else:
                sandbox.unlink()
        else:
            raise CursorSetupError("product profile sandbox conflicts with workspace")
    sandbox.symlink_to(workspace, target_is_directory=True)


def build_mcp_server_entry(
    *,
    proxy_command: str,
    home: Path,
    config_path: Path,
    passphrase_file: Path,
    profile: Path,
    workspace: Path,
) -> dict[str, Any]:
    """Build a project MCP entry aligned with the working private product route."""
    resolved_home = Path(home).expanduser().resolve()
    resolved_workspace = Path(workspace).expanduser().resolve()
    resolved_profile = Path(profile).expanduser().resolve()
    executable = str(Path(proxy_command).expanduser().resolve())
    return {
        "type": "stdio",
        "command": executable,
        "args": [
            "run",
            "--home", str(resolved_home),
            "--config", str(Path(config_path).expanduser().resolve()),
            "--passphrase-file", str(Path(passphrase_file).expanduser().resolve()),
        ],
        "env": {
            "DOWNSTREAM_NAME": PRODUCT_ROUTE_DOWNSTREAM_NAME,
            "AVP_HOME": str(resolved_home),
            "MCP_CONTENT_ROOT": str(resolved_workspace),
            "AVP_CURSOR_WORKSPACE": str(resolved_workspace),
            "PRODUCT_ROUTE_PROFILE_ROOT": str(resolved_profile),
        },
    }


def _entry_mentions_agentveil(entry: dict[str, Any]) -> bool:
    return "agentveil" in json.dumps(entry).lower()


def _agentveil_mcp_server_keys(servers: dict[str, Any]) -> tuple[str, ...]:
    keys: list[str] = []
    for key, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        if key == AGENTVEIL_MCP_SERVER_KEY or _entry_mentions_agentveil(entry):
            keys.append(str(key))
    return tuple(sorted(keys))


def user_mcp_backup_dir(workspace: Path) -> Path:
    return setup_home(workspace) / USER_MCP_BACKUP_DIRNAME


def _backup_timestamp() -> str:
    from datetime import datetime, timezone

    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
        .replace(":", "-")
    )


@dataclass(frozen=True)
class NeutralizeGlobalRouteResult:
    changed: bool
    removed_server_keys: tuple[str, ...] = ()
    backup_basename: str | None = None
    reload_required: bool = False


def neutralize_competing_global_route(workspace: Path) -> NeutralizeGlobalRouteResult:
    """Backup and remove user/global AgentVeil MCP entries that split the route."""
    user_config_path = resolve_cursor_global_mcp_json_path()
    if not user_config_path.is_file():
        return NeutralizeGlobalRouteResult(changed=False)

    payload = load_json_object(user_config_path, label="~/.cursor/mcp.json")
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict):
        raise CursorSetupError("existing ~/.cursor/mcp.json mcpServers must be an object")

    agentveil_keys = _agentveil_mcp_server_keys(servers)
    if not agentveil_keys:
        return NeutralizeGlobalRouteResult(changed=False)

    backup_dir = user_mcp_backup_dir(workspace)
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"{USER_MCP_BACKUP_PREFIX}.{_backup_timestamp()}.backup"
    backup_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        backup_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    merged_servers = {
        key: value for key, value in servers.items() if str(key) not in agentveil_keys
    }
    other_top_level = {key: value for key, value in payload.items() if key != "mcpServers"}
    if not merged_servers and not other_top_level:
        user_config_path.unlink()
    else:
        updated = dict(other_top_level)
        if merged_servers:
            updated["mcpServers"] = merged_servers
        user_config_path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")

    return NeutralizeGlobalRouteResult(
        changed=True,
        removed_server_keys=agentveil_keys,
        backup_basename=backup_path.name,
        reload_required=True,
    )


def load_project_mcp_server_entry(workspace: Path) -> dict[str, Any] | None:
    try:
        payload = load_json_object(mcp_config_path(workspace), label=".cursor/mcp.json")
    except CursorSetupError:
        return None
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict):
        return None
    entry = servers.get(AGENTVEIL_MCP_SERVER_KEY)
    return entry if isinstance(entry, dict) else None


def mcp_route_entry_has_private_parity(entry: dict[str, Any]) -> bool:
    env = entry.get("env")
    if not isinstance(env, dict):
        return False
    if set(env.keys()) != set(MCP_ROUTE_ENV_KEYS):
        return False
    command = str(entry.get("command") or "").strip()
    if not command:
        return False
    return Path(command).is_absolute()


@dataclass(frozen=True)
class InstallHooksResult:
    hooks_path: Path
    evidence_path: Path
    created_hooks: bool
    replaced_existing_managed: bool
    reload_required: bool = True


@dataclass(frozen=True)
class InstallMcpResult:
    config_path: Path
    created_config: bool
    replaced_existing_managed: bool


@dataclass(frozen=True)
class UninstallResult:
    hooks_removed: int
    mcp_removed: bool
    reload_required: bool


@dataclass
class StatusResult:
    scope: str = "project"
    status: str = "unsafe"
    state: str = "missing"
    hooks_present: bool = False
    managed_hooks_present: bool = False
    mcp_route_present: bool = False
    proxy_home_initialized: bool = False
    proxy_doctor_ok: bool = False
    approval_center: str = "down"
    competing_global_route: bool = False
    reload_required: bool = False
    matched_tool_classes: tuple[str, ...] = field(default_factory=lambda: MATCHED_TOOL_CLASSES)
    notes: tuple[str, ...] = ()


def _merge_hooks(workspace: Path, *, python: str, home: Path, evidence_path: Path) -> tuple[bool, bool]:
    path = hooks_config_path(workspace)
    created = not path.exists()
    payload = load_json_object(path, label=".cursor/hooks.json")
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}

    replaced = False
    merged_hooks: dict[str, Any] = dict(hooks)
    changed = False
    workspace = workspace.resolve()

    for event in AGENTVEIL_HOOK_EVENTS:
        existing = merged_hooks.get(event)
        if existing is None:
            merged_hooks[event] = [
                build_managed_hook_entry(
                    python=python,
                    workspace=workspace,
                    home=home,
                    evidence_path=evidence_path,
                    hook_event=event,
                )
            ]
            changed = True
            continue
        if not isinstance(existing, list):
            raise CursorSetupError(".cursor/hooks.json hooks entries must be arrays")
        kept = [
            item for item in existing
            if not (isinstance(item, dict) and _is_agentveil_hook_command(str(item.get("command") or "")))
        ]
        if len(kept) != len(existing):
            replaced = True
        desired = [
            *kept,
            build_managed_hook_entry(
                python=python,
                workspace=workspace,
                home=home,
                evidence_path=evidence_path,
                hook_event=event,
            ),
        ]
        if desired != existing:
            changed = True
        merged_hooks[event] = desired

    if not changed and not created:
        return created, replaced

    payload["hooks"] = merged_hooks
    payload.setdefault("version", 1)
    _write_json(path, payload)
    return created, replaced


def install_hooks(
    workspace: Path,
    *,
    python: str | None = None,
    home: Path | None = None,
    evidence_path: Path | None = None,
) -> InstallHooksResult:
    workspace = workspace.resolve()
    resolved_home = home or setup_home(workspace)
    resolved_python = python or sys.executable
    resolved_evidence = evidence_path or project_evidence_path(workspace)
    created, replaced = _merge_hooks(
        workspace,
        python=resolved_python,
        home=resolved_home,
        evidence_path=resolved_evidence,
    )
    return InstallHooksResult(
        hooks_path=hooks_config_path(workspace),
        evidence_path=resolved_evidence,
        created_hooks=created,
        replaced_existing_managed=replaced,
    )


def install_mcp_route(
    workspace: Path,
    *,
    proxy_command: str,
    home: Path | None = None,
) -> InstallMcpResult:
    workspace = workspace.resolve()
    resolved_home = home or setup_home(workspace)
    path = mcp_config_path(workspace)
    created = not path.exists()
    payload = load_json_object(path, label=".cursor/mcp.json")
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    _ensure_passphrase(passphrase_path(resolved_home))
    prof = profile_root(resolved_home)
    entry = build_mcp_server_entry(
        proxy_command=proxy_command,
        home=resolved_home,
        config_path=proxy_config_path(resolved_home),
        passphrase_file=passphrase_path(resolved_home),
        profile=prof,
        workspace=workspace,
    )
    previous = servers.get(AGENTVEIL_MCP_SERVER_KEY)
    servers[AGENTVEIL_MCP_SERVER_KEY] = entry
    payload["mcpServers"] = servers
    _write_json(path, payload)
    install_user_mcp_route(workspace, python=sys.executable, proxy_command=proxy_command)
    return InstallMcpResult(
        config_path=path,
        created_config=created,
        replaced_existing_managed=previous != entry,
    )


def remove_hooks(workspace: Path) -> int:
    path = hooks_config_path(workspace)
    if not path.is_file():
        return 0
    payload = load_json_object(path, label=".cursor/hooks.json")
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    merged_hooks: dict[str, Any] = {}
    removed = 0
    for event, commands in hooks.items():
        if not isinstance(commands, list):
            merged_hooks[event] = commands
            continue
        kept = [
            item for item in commands
            if not (isinstance(item, dict) and _is_agentveil_hook_command(str(item.get("command") or "")))
        ]
        removed += len(commands) - len(kept)
        if kept:
            merged_hooks[event] = kept
    if removed == 0:
        return 0
    other = {key: value for key, value in payload.items() if key != "hooks"}
    if not merged_hooks and not other:
        path.unlink()
        return removed
    payload = dict(other)
    payload["hooks"] = merged_hooks
    payload.setdefault("version", 1)
    _write_json(path, payload)
    return removed


def remove_mcp_route(workspace: Path) -> bool:
    project_removed = False
    path = mcp_config_path(workspace)
    if path.is_file():
        payload = load_json_object(path, label=".cursor/mcp.json")
        servers = payload.get("mcpServers")
        if isinstance(servers, dict) and AGENTVEIL_MCP_SERVER_KEY in servers:
            servers.pop(AGENTVEIL_MCP_SERVER_KEY, None)
            other = {key: value for key, value in payload.items() if key != "mcpServers"}
            if not servers and not other:
                path.unlink()
            else:
                payload = dict(other)
                payload["mcpServers"] = servers
                _write_json(path, payload)
            project_removed = True
    user_removed = remove_user_mcp_route().removed
    return project_removed or user_removed


def mcp_route_present(workspace: Path) -> bool:
    try:
        payload = load_json_object(mcp_config_path(workspace), label=".cursor/mcp.json")
    except CursorSetupError:
        return False
    servers = payload.get("mcpServers")
    return isinstance(servers, dict) and AGENTVEIL_MCP_SERVER_KEY in servers


def detect_competing_global_route() -> bool:
    if detect_unmanaged_user_mcp_route():
        return True
    path = resolve_cursor_global_mcp_json_path()
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    servers = payload.get("mcpServers") if isinstance(payload, dict) else None
    if not isinstance(servers, dict):
        return False
    for key, entry in servers.items():
        if key == AGENTVEIL_MCP_SERVER_KEY:
            return True
        if isinstance(entry, dict) and "agentveil" in json.dumps(entry).lower():
            return True
    return False


@dataclass(frozen=True)
class CenterStatus:
    state: str
    pid: int | None
    port: int | None


def check_approval_center_status(home: Path) -> CenterStatus:
    from agentveil_mcp_proxy.approval.server import inspect_managed_approval_center

    managed = inspect_managed_approval_center(home)
    return CenterStatus(state=managed.state, pid=managed.pid, port=managed.port)


@dataclass(frozen=True)
class EnsureCenterResult:
    status: CenterStatus
    started: bool
    reused: bool
    restarted: bool
    reason: str


def ensure_approval_center_running(
    *,
    home: Path,
    proxy_command: str,
    passphrase_file: Path | None = None,
) -> EnsureCenterResult:
    from agentveil_mcp_proxy.approval.server import ensure_managed_approval_center_for_cli

    managed = ensure_managed_approval_center_for_cli(
        home=home,
        proxy_command=proxy_command,
        passphrase_file=passphrase_file,
    )
    status = CenterStatus(
        state=managed.status.state,
        pid=managed.status.pid,
        port=managed.status.port,
    )
    return EnsureCenterResult(
        status=status,
        started=managed.started,
        reused=managed.reused,
        restarted=managed.restarted,
        reason=managed.reason,
    )


def stop_managed_approval_center(home: Path) -> dict[str, Any]:
    from agentveil_mcp_proxy.approval.server import stop_managed_approval_center as stop

    return stop(home, require_healthy=True)


def _hook_observation_state(workspace: Path, hooks_path: Path) -> tuple[bool, bool]:
    evidence = project_evidence_path(workspace)
    if not evidence.is_file() or not hooks_path.is_file():
        return False, False
    try:
        if evidence.stat().st_size <= 0 or evidence.stat().st_mtime <= hooks_path.stat().st_mtime:
            return False, False
    except OSError:
        return False, False

    hook_observed = False
    mcp_route_observed = False
    try:
        lines = evidence.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False, False
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        hook_observed = True
        tool_name = str(row.get("tool_name") or "")
        hook_event = str(row.get("hook_event") or "")
        server = str(row.get("server") or "")
        if (
            server == AGENTVEIL_MCP_SERVER_KEY
            or tool_name.startswith("MCP:")
            or hook_event == "beforeMCPExecution"
        ):
            mcp_route_observed = True
    return hook_observed, mcp_route_observed


def prepare_proxy_home(workspace: Path, *, force: bool = False) -> Path:
    workspace = workspace.resolve()
    home = setup_home(workspace)
    home.mkdir(parents=True, exist_ok=True)
    _ensure_workspace_sandbox(profile_root(home), workspace, force=force)
    _ensure_passphrase(passphrase_path(home))
    return home


def connector_status(workspace: Path, *, home: Path | None = None) -> dict[str, Any]:
    workspace = workspace.resolve()
    resolved_home = home or setup_home(workspace)
    hooks_path = hooks_config_path(workspace)
    hooks_present = hooks_path.is_file()
    managed = False
    hook_state = "missing"
    if hooks_present:
        try:
            payload = load_json_object(hooks_path, label=".cursor/hooks.json")
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                for event in AGENTVEIL_HOOK_EVENTS:
                    commands = hooks.get(event)
                    if isinstance(commands, list) and any(
                        isinstance(item, dict)
                        and AGENTVEIL_HOOK_MARKER in str(item.get("command") or "")
                        for item in commands
                    ):
                        managed = True
                        break
            hook_state = "installed" if managed else "stale"
        except CursorSetupError:
            hook_state = "stale"

    route_present = mcp_route_present(workspace)
    route_entry = load_project_mcp_server_entry(workspace) if route_present else None
    route_parity_ok = (
        route_entry is not None and mcp_route_entry_has_private_parity(route_entry)
    )
    mcp_state = "configured" if route_present and route_parity_ok else (
        "partial" if route_present else "missing"
    )
    config_exists = proxy_config_path(resolved_home).is_file()
    proxy_state = "configured" if config_exists else "missing"
    center = check_approval_center_status(resolved_home)
    competing = detect_competing_global_route()
    user_mcp_present = user_mcp_route_present()
    user_mcp_managed = user_mcp_route_is_managed()
    user_mcp_state = (
        "configured" if user_mcp_present and user_mcp_managed else
        ("partial" if user_mcp_present else "missing")
    )

    hook_observed = False
    mcp_route_observed = False
    if managed:
        hook_observed, mcp_route_observed = _hook_observation_state(workspace, hooks_path)

    ready = (
        managed
        and route_present
        and route_parity_ok
        and config_exists
        and center.state == "running"
        and user_mcp_managed
        and not competing
    )
    if not managed or not route_present or not config_exists or not route_parity_ok:
        status = "unsafe"
    elif center.state != "running" or competing or not user_mcp_managed:
        status = "advisory"
    elif mcp_route_observed and user_mcp_managed:
        status = "protected"
    else:
        status = "advisory"

    if not managed or not route_present or not config_exists or not route_parity_ok:
        restart_required: bool | None = None
        next_step = "run `agentveil-mcp-proxy setup cursor --yes`"
    elif center.state != "running":
        restart_required = None
        next_step = "Approval Center is not running; rerun setup cursor --yes"
    elif competing:
        restart_required = True
        next_step = (
            "Competing unmanaged user/global AgentVeil MCP route detected; "
            "rerun setup cursor --yes to replace it with the managed wrapper, then reload Cursor"
        )
    elif not user_mcp_managed:
        restart_required = True
        next_step = (
            "User/Home MCP route is missing or not managed; "
            "rerun setup cursor --yes, then reload Cursor"
        )
    elif not route_parity_ok:
        restart_required = True
        next_step = "Project MCP route is stale; rerun setup cursor --yes, then reload Cursor"
    elif status == "protected":
        restart_required = False
        next_step = "connector active; nothing to do"
    elif ready:
        restart_required = True
        next_step = SETUP_ADVISORY_NEXT_STEP
    else:
        restart_required = True
        next_step = SETUP_ADVISORY_NEXT_STEP

    return {
        "scope": "project",
        "status": status,
        "hook": hook_state,
        "mcp_route": mcp_state,
        "mcp_route_parity_ok": route_parity_ok,
        "user_mcp_route": user_mcp_state,
        "user_mcp_route_managed": user_mcp_managed,
        "proxy_route": proxy_state,
        "proxy_home": "initialized" if config_exists else "missing",
        "proxy_doctor_ok": config_exists,
        "approval_center": center.state,
        "competing_global_route": competing,
        "hook_observed": hook_observed,
        "mcp_route_observed": mcp_route_observed,
        "restart_required": restart_required,
        "matched_tool_classes": list(MATCHED_TOOL_CLASSES),
        "next_step": next_step,
    }


__all__ = [
    "AGENTVEIL_HOOK_MARKER",
    "AGENTVEIL_HOOK_EVENTS",
    "AGENTVEIL_MCP_SERVER_KEY",
    "BROAD_FOLDER_MESSAGE",
    "MATCHED_TOOL_CLASSES",
    "MCP_ROUTE_ENV_KEYS",
    "SETUP_ADVISORY_NEXT_STEP",
    "BroadWorkspaceError",
    "CenterStatus",
    "CursorSetupError",
    "EnsureCenterResult",
    "InstallHooksResult",
    "InstallMcpResult",
    "NeutralizeGlobalRouteResult",
    "StatusResult",
    "UninstallResult",
    "build_hook_command",
    "build_managed_hook_entry",
    "build_mcp_server_entry",
    "format_setup_success_message",
    "has_project_markers",
    "is_broad_workspace",
    "check_approval_center_status",
    "connector_status",
    "detect_competing_global_route",
    "ensure_approval_center_running",
    "hooks_config_path",
    "install_hooks",
    "install_mcp_route",
    "is_managed_hook_command",
    "load_json_object",
    "load_project_mcp_server_entry",
    "mcp_config_path",
    "mcp_route_entry_has_private_parity",
    "mcp_route_present",
    "neutralize_competing_global_route",
    "prepare_proxy_home",
    "project_evidence_path",
    "remove_hooks",
    "remove_mcp_route",
    "setup_home",
    "stop_managed_approval_center",
    "user_mcp_backup_dir",
]
