"""Managed user-level Cursor MCP wrapper for Home / User settings activation.

Cursor 3.6+ stores user-visible MCP servers in ``User/settings.json`` under
``mcp.servers`` (also writable via ``cursor --add-mcp``). This module provides
an intentionally scoped stdio wrapper that resolves a prepared project workspace at
runtime and execs ``agentveil-mcp-proxy run`` with that workspace's ``.agentveil``
home instead of a stale global workspace pointer.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentveil_mcp_proxy.client_connect import (
    merge_cursor_settings_server_entry,
    remove_cursor_settings_server_entry,
    resolve_cursor_user_data_dir,
)
from agentveil_mcp_proxy.cursor_hooks import AGENTVEIL_MCP_SERVER_KEY
from agentveil_mcp_proxy.product_route import PRODUCT_ROUTE_DOWNSTREAM_NAME

USER_MCP_MODULE = "agentveil_mcp_proxy.cursor_user_mcp"
USER_MCP_MARKER_ENV = "AGENTVEIL_USER_MCP_MARKER"
USER_MCP_MARKER_VALUE = USER_MCP_MODULE
USER_MCP_PROXY_COMMAND_ENV = "AGENTVEIL_USER_MCP_PROXY_COMMAND"
USER_SETTINGS_BACKUP_DIRNAME = "cursor-setup/user-settings-backups"
USER_SETTINGS_BACKUP_PREFIX = "settings.json"


class UserMcpError(RuntimeError):
    """Raised when user-level MCP settings cannot be updated safely."""


def cursor_settings_path() -> Path:
    return resolve_cursor_user_data_dir() / "User" / "settings.json"


def _load_settings_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UserMcpError(f"cannot read settings.json: {exc.__class__.__name__}") from exc
    if not isinstance(payload, dict):
        raise UserMcpError("settings.json must be a JSON object")
    return payload


def _write_settings(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _settings_mcp_servers(payload: dict[str, Any]) -> dict[str, Any]:
    mcp = payload.get("mcp")
    if not isinstance(mcp, dict):
        return {}
    servers = mcp.get("servers")
    return servers if isinstance(servers, dict) else {}


def entry_mentions_agentveil(entry: dict[str, Any]) -> bool:
    return "agentveil" in json.dumps(entry).lower()


def is_managed_user_mcp_entry(entry: dict[str, Any]) -> bool:
    env = entry.get("env")
    if isinstance(env, dict) and env.get(USER_MCP_MARKER_ENV) == USER_MCP_MARKER_VALUE:
        return True
    args = entry.get("args") or []
    if isinstance(args, list):
        blob = " ".join(str(item) for item in args)
        if USER_MCP_MODULE in blob:
            return True
    command = str(entry.get("command") or "")
    return USER_MCP_MODULE in command


def build_user_mcp_server_entry(*, python: str, proxy_command: str, workspace: Path) -> dict[str, Any]:
    """Build the managed user-level MCP entry (``settings.json`` shape)."""
    return {
        "command": str(Path(python).expanduser().resolve()),
        "args": ["-m", USER_MCP_MODULE],
        "env": {
            USER_MCP_MARKER_ENV: USER_MCP_MARKER_VALUE,
            USER_MCP_PROXY_COMMAND_ENV: str(Path(proxy_command).expanduser().resolve()),
            "AVP_CURSOR_WORKSPACE": str(Path(workspace).expanduser().resolve()),
        },
    }


def load_user_mcp_server_entry() -> dict[str, Any] | None:
    payload = _load_settings_object(cursor_settings_path())
    entry = _settings_mcp_servers(payload).get(AGENTVEIL_MCP_SERVER_KEY)
    return entry if isinstance(entry, dict) else None


def user_mcp_route_present() -> bool:
    return load_user_mcp_server_entry() is not None


def user_mcp_route_is_managed() -> bool:
    entry = load_user_mcp_server_entry()
    return entry is not None and is_managed_user_mcp_entry(entry)


def detect_unmanaged_user_mcp_route() -> bool:
    entry = load_user_mcp_server_entry()
    if entry is None:
        return False
    if is_managed_user_mcp_entry(entry):
        return False
    return entry_mentions_agentveil(entry) or AGENTVEIL_MCP_SERVER_KEY in json.dumps(entry)


def is_prepared_workspace(workspace: Path) -> bool:
    root = workspace.expanduser().resolve()
    home = root / ".agentveil"
    if not (home / "mcp-proxy" / "config.json").is_file():
        return False
    mcp_path = root / ".cursor" / "mcp.json"
    if not mcp_path.is_file():
        return False
    try:
        payload = json.loads(mcp_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    servers = payload.get("mcpServers") if isinstance(payload, dict) else None
    return isinstance(servers, dict) and AGENTVEIL_MCP_SERVER_KEY in servers


def find_prepared_workspace(start: Path | None = None) -> Path | None:
    """Walk parents from *start* (or cwd) to find a prepared AgentVeil workspace."""
    current = (start or Path.cwd()).expanduser()
    try:
        current = current.resolve()
    except OSError:
        return None
    for candidate in (current, *current.parents):
        if is_prepared_workspace(candidate):
            return candidate
    hinted = os.environ.get("AVP_CURSOR_WORKSPACE", "").strip()
    if hinted:
        hinted_path = Path(hinted).expanduser()
        if is_prepared_workspace(hinted_path):
            return hinted_path.resolve()
    return None


def build_proxy_exec_argv(
    workspace: Path,
    *,
    proxy_command: str | None = None,
) -> tuple[str, list[str], dict[str, str]]:
    root = workspace.expanduser().resolve()
    home = root / ".agentveil"
    pinned_proxy = os.environ.get(USER_MCP_PROXY_COMMAND_ENV, "").strip()
    proxy = proxy_command or pinned_proxy or shutil.which("agentveil-mcp-proxy")
    if not proxy:
        raise UserMcpError("agentveil-mcp-proxy console script not on PATH")
    proxy_path = str(Path(proxy).expanduser().resolve())
    argv = [
        proxy_path,
        "run",
        "--home", str(home),
        "--config", str(home / "mcp-proxy" / "config.json"),
        "--passphrase-file", str(home / "passphrase"),
    ]
    env = os.environ.copy()
    env.update({
        "DOWNSTREAM_NAME": PRODUCT_ROUTE_DOWNSTREAM_NAME,
        "AVP_HOME": str(home),
        "MCP_CONTENT_ROOT": str(root),
        "AVP_CURSOR_WORKSPACE": str(root),
        "PRODUCT_ROUTE_PROFILE_ROOT": str(home / "product-profile"),
    })
    return proxy_path, argv, env


def _backup_timestamp() -> str:
    from datetime import datetime, timezone

    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
        .replace(":", "-")
    )


def _settings_backup_dir(workspace: Path) -> Path:
    return workspace.expanduser().resolve() / ".agentveil" / USER_SETTINGS_BACKUP_DIRNAME


def _backup_settings(workspace: Path, payload: dict[str, Any]) -> str | None:
    backup_dir = _settings_backup_dir(workspace)
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"{USER_SETTINGS_BACKUP_PREFIX}.{_backup_timestamp()}.backup"
    backup_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        backup_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return backup_path.name


@dataclass(frozen=True)
class InstallUserMcpResult:
    changed: bool
    settings_path: Path
    replaced_existing_managed: bool
    removed_unmanaged_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemoveUserMcpResult:
    removed: bool
    reload_required: bool = False


def _remove_unmanaged_agentveil_settings_entries(payload: dict[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
    servers = dict(_settings_mcp_servers(payload))
    removed: list[str] = []
    for key, entry in list(servers.items()):
        if not isinstance(entry, dict):
            continue
        if key == AGENTVEIL_MCP_SERVER_KEY or entry_mentions_agentveil(entry):
            if not is_managed_user_mcp_entry(entry):
                removed.append(str(key))
                servers.pop(key, None)
    if not removed:
        return payload, ()
    cleaned = remove_cursor_settings_server_entry(payload, server_name=AGENTVEIL_MCP_SERVER_KEY)
    for key in removed:
        if key != AGENTVEIL_MCP_SERVER_KEY:
            cleaned = remove_cursor_settings_server_entry(cleaned, server_name=key)
    return cleaned, tuple(sorted(removed))


def install_user_mcp_route(
    workspace: Path,
    *,
    python: str | None = None,
    proxy_command: str,
) -> InstallUserMcpResult:
    """Install the managed user-level MCP wrapper into ``User/settings.json``."""
    workspace = workspace.expanduser().resolve()
    settings_path = cursor_settings_path()
    payload = _load_settings_object(settings_path)
    cleaned, removed_keys = _remove_unmanaged_agentveil_settings_entries(payload)
    if cleaned != payload:
        payload = cleaned

    entry = build_user_mcp_server_entry(
        python=python or sys.executable,
        proxy_command=proxy_command,
        workspace=workspace,
    )
    previous = _settings_mcp_servers(payload).get(AGENTVEIL_MCP_SERVER_KEY)
    merged = merge_cursor_settings_server_entry(
        payload,
        server_name=AGENTVEIL_MCP_SERVER_KEY,
        entry=entry,
    )
    changed = merged != payload or previous != entry
    replaced = previous is not None and previous != entry
    if changed:
        if settings_path.is_file():
            _backup_settings(workspace, _load_settings_object(settings_path))
        _write_settings(settings_path, merged)
    return InstallUserMcpResult(
        changed=changed,
        settings_path=settings_path,
        replaced_existing_managed=replaced,
        removed_unmanaged_keys=removed_keys,
    )


def remove_user_mcp_route() -> RemoveUserMcpResult:
    """Remove only the managed AgentVeil user-level MCP entry."""
    settings_path = cursor_settings_path()
    payload = _load_settings_object(settings_path)
    entry = _settings_mcp_servers(payload).get(AGENTVEIL_MCP_SERVER_KEY)
    if not isinstance(entry, dict) or not is_managed_user_mcp_entry(entry):
        return RemoveUserMcpResult(removed=False, reload_required=False)
    cleaned = remove_cursor_settings_server_entry(payload, server_name=AGENTVEIL_MCP_SERVER_KEY)
    _write_settings(settings_path, cleaned)
    return RemoveUserMcpResult(removed=True, reload_required=True)


def main(argv: list[str] | None = None) -> int:
    del argv
    workspace = find_prepared_workspace()
    if workspace is None:
        sys.stderr.write(
            "agentveil user MCP: no prepared workspace with .agentveil proxy home; failing closed\n"
        )
        return 1
    try:
        _executable, argv_exec, env = build_proxy_exec_argv(workspace)
    except UserMcpError as exc:
        sys.stderr.write(f"agentveil user MCP: {exc}\n")
        return 1
    os.execvpe(argv_exec[0], argv_exec, env)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
