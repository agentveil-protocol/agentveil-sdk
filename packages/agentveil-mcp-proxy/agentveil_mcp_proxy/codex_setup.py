"""Project-local Codex connector setup helpers.

This module does not implement a new control path. It wraps the existing Codex
client-config/connect TOML support with the same project-local proxy home and
Approval Center lifecycle used by the public connector setup commands.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from agentveil_mcp_proxy.client_config import DEFAULT_SERVER_NAME
from agentveil_mcp_proxy.client_connect import (
    build_connect_status_payload,
    build_disconnect_payload,
)
from agentveil_mcp_proxy.client_connect import resolve_client_config_location


CODEX_CONNECTOR_ID = "codex"


def setup_home(project_dir: Path) -> Path:
    """Project-local proxy home for the Codex connector."""

    return Path(project_dir).resolve() / ".avp"


def proxy_config_path(home: Path) -> Path:
    return Path(home) / "mcp-proxy" / "config.json"


def codex_config_path(project_dir: Path | None = None) -> Path:
    """Return the Codex user config path for the current HOME."""

    root = Path(project_dir).resolve() if project_dir is not None else Path.cwd()
    return resolve_client_config_location(CODEX_CONNECTOR_ID, project_root=root).config_path


def connect_status(
    *,
    project_dir: Path,
    home: Path,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
) -> dict[str, Any]:
    """Return bounded Codex route status using the existing connect status logic."""

    return build_connect_status_payload(
        client_id=CODEX_CONNECTOR_ID,
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=proxy_command,
        server_name=server_name,
        project_root=project_dir,
    )


def connector_status(
    *,
    project_dir: Path,
    center_state: str,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
) -> dict[str, Any]:
    """Build bounded product status for the project-local Codex connector."""

    target = Path(project_dir).resolve()
    home = setup_home(target)
    proxy_route_present = proxy_config_path(home).is_file()
    route = connect_status(
        project_dir=target,
        home=home,
        passphrase_file=passphrase_file,
        proxy_command=proxy_command,
        server_name=server_name,
    )
    route_present = bool(route.get("config_entry_present"))
    route_launch_proved = bool(route.get("route_launch_proved"))

    if proxy_route_present and route_present and center_state == "running" and route_launch_proved:
        status = "protected"
        next_step = "Codex route launches through AgentVeil; routed MCP calls can use the local approval/proof loop."
    elif proxy_route_present and route_present and center_state == "running":
        status = "advisory"
        next_step = "Restart Codex so it reloads MCP config, then use AgentVeil MCP tools for controlled actions."
    elif proxy_route_present or route_present:
        status = "advisory"
        next_step = "Finish setup or restart the managed Approval Center before relying on the Codex route."
    else:
        status = "unsafe"
        next_step = "Run `agentveil-mcp-proxy setup codex --yes` for this project."

    return {
        "ok": True,
        "connector": CODEX_CONNECTOR_ID,
        "scope": "project",
        "status": status,
        "proxy_route": "present" if proxy_route_present else "missing",
        "mcp_route": "present" if route_present else "missing",
        "route_launch_proved": route_launch_proved,
        "doctor_status": route.get("doctor_status", "skipped"),
        "approval_center": center_state,
        "restart_required": status != "protected",
        "next_step": next_step,
        "codex_config_ref": route.get("config_ref"),
        "privacy_bounded": True,
    }


def disconnect(
    *,
    project_dir: Path,
    home: Path,
    server_name: str = DEFAULT_SERVER_NAME,
    write: bool,
) -> dict[str, Any]:
    """Remove the AgentVeil Codex MCP route via existing disconnect logic."""

    return build_disconnect_payload(
        client_id=CODEX_CONNECTOR_ID,
        home=home,
        server_name=server_name,
        project_root=project_dir,
        write=write,
    )


def managed_route_present(payload: Mapping[str, Any]) -> bool:
    return bool(payload.get("config_entry_present"))


__all__ = [
    "CODEX_CONNECTOR_ID",
    "codex_config_path",
    "connect_status",
    "connector_status",
    "disconnect",
    "managed_route_present",
    "proxy_config_path",
    "setup_home",
]
