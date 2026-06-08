"""Dry-run MCP client config rendering for AgentVeil MCP Proxy onboarding."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
from typing import Any, Mapping

DEFAULT_PROXY_COMMAND = "agentveil-mcp-proxy"
DEFAULT_SERVER_NAME = "agentveil-mcp-proxy"


class ClientConfigError(ValueError):
    """Raised when client config rendering inputs are invalid."""


@dataclass(frozen=True)
class ClientTarget:
    """One supported MCP desktop client and where operators paste config."""

    client_id: str
    display_name: str
    config_path_hint: str


CLIENT_TARGETS: dict[str, ClientTarget] = {
    "cursor": ClientTarget(
        client_id="cursor",
        display_name="Cursor",
        config_path_hint=".cursor/mcp.json (project root)",
    ),
    "claude_desktop": ClientTarget(
        client_id="claude_desktop",
        display_name="Claude Desktop",
        config_path_hint=(
            "~/Library/Application Support/Claude/claude_desktop_config.json (macOS) "
            "or %APPDATA%/Claude/claude_desktop_config.json (Windows)"
        ),
    ),
}


def resolve_proxy_command(command: str | None = None) -> str:
    """Return the proxy executable path for MCP client config."""

    if command is not None:
        trimmed = command.strip()
        if not trimmed:
            raise ClientConfigError("proxy command must not be empty")
        return trimmed
    resolved = shutil.which(DEFAULT_PROXY_COMMAND)
    return resolved if resolved is not None else DEFAULT_PROXY_COMMAND


def build_run_args(
    *,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
) -> list[str]:
    """Build ``agentveil-mcp-proxy run`` CLI args for MCP client config."""

    args = ["run"]
    if home is not None:
        args.extend(["--home", str(home.expanduser())])
    if config_path is not None:
        args.extend(["--config", str(config_path.expanduser())])
    if passphrase_file is not None:
        args.extend(["--passphrase-file", str(passphrase_file.expanduser())])
    return args


def build_mcp_server_entry(
    *,
    command: str,
    run_args: list[str],
    home: Path | None = None,
) -> dict[str, Any]:
    """Build one MCP server entry for Cursor/Claude Desktop style clients."""

    entry: dict[str, Any] = {
        "command": command,
        "args": run_args,
    }
    env = build_proxy_env(home=home)
    if env:
        entry["env"] = env
    return entry


def build_proxy_env(*, home: Path | None = None) -> dict[str, str]:
    """Return non-secret env vars only when home differs from the default."""

    if home is None:
        return {}
    expanded = home.expanduser()
    default = Path(os.environ.get("AVP_HOME", "~/.avp")).expanduser()
    if expanded == default:
        return {}
    return {"AVP_HOME": str(expanded)}


def build_mcp_servers_document(
    *,
    server_name: str,
    command: str,
    run_args: list[str],
    home: Path | None = None,
) -> dict[str, Any]:
    """Build the top-level MCP client JSON document (``mcpServers`` wrapper)."""

    trimmed_name = server_name.strip()
    if not trimmed_name:
        raise ClientConfigError("server name must not be empty")
    return {
        "mcpServers": {
            trimmed_name: build_mcp_server_entry(
                command=command,
                run_args=run_args,
                home=home,
            ),
        },
    }


def render_client_configs(
    *,
    clients: list[str],
    server_name: str = DEFAULT_SERVER_NAME,
    command: str | None = None,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Render dry-run MCP client config documents keyed by client id."""

    if passphrase_file is not None and not passphrase_file.expanduser().is_file():
        raise ClientConfigError(
            f"passphrase file does not exist: {passphrase_file.expanduser()}"
        )

    resolved_command = resolve_proxy_command(command)
    run_args = build_run_args(
        home=home,
        config_path=config_path,
        passphrase_file=passphrase_file,
    )
    selected = _normalize_client_ids(clients)
    rendered: dict[str, dict[str, Any]] = {}
    for client_id in selected:
        rendered[client_id] = build_mcp_servers_document(
            server_name=server_name,
            command=resolved_command,
            run_args=run_args,
            home=home,
        )
    return rendered


def format_client_config_text(
    rendered: Mapping[str, Mapping[str, Any]],
) -> str:
    """Format rendered configs as copy-pasteable stdout text with path hints."""

    blocks: list[str] = []
    for client_id, document in rendered.items():
        target = CLIENT_TARGETS[client_id]
        blocks.append(
            f"# {target.display_name} — paste into {target.config_path_hint}\n"
            f"{json.dumps(document, indent=2, sort_keys=True)}\n"
        )
    return "\n".join(blocks)


def read_role_preset_from_config(config_path: Path | None) -> str | None:
    """Return the stored role preset name from a proxy config file, if present."""

    if config_path is None:
        return None
    try:
        payload = json.loads(config_path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    preset = payload.get("role_preset")
    return preset if isinstance(preset, str) and preset.strip() else None


def format_client_config_json_payload(
    rendered: Mapping[str, Mapping[str, Any]],
    *,
    command: str,
    run_args: list[str],
    config_path: Path | None = None,
    role_preset: str | None = None,
) -> dict[str, Any]:
    """Return structured JSON for ``client-config print --json``."""

    clients_payload: dict[str, Any] = {}
    for client_id, document in rendered.items():
        target = CLIENT_TARGETS[client_id]
        clients_payload[client_id] = {
            "display_name": target.display_name,
            "config_path_hint": target.config_path_hint,
            "document": document,
            "rendered": json.dumps(document, indent=2, sort_keys=True) + "\n",
        }
    payload: dict[str, Any] = {
        "ok": True,
        "dry_run": True,
        "writes_user_config": False,
        "command": command,
        "args": run_args,
        "clients": clients_payload,
        "privacy": {
            "includes_secrets": False,
            "includes_passphrase": False,
            "includes_private_key": False,
        },
    }
    if config_path is not None:
        payload["config_path"] = str(config_path.expanduser())
    if role_preset is not None:
        payload["role_preset"] = role_preset
    return payload


def assert_rendered_config_is_privacy_safe(
    payload: Mapping[str, Any],
    *,
    forbidden_substrings: tuple[str, ...] = (),
) -> None:
    """Raise when rendered config text would leak sensitive material."""

    serialized = json.dumps(payload, sort_keys=True)
    for fragment in forbidden_substrings:
        if fragment and fragment in serialized:
            raise ClientConfigError("rendered config must not include sensitive values")


def _normalize_client_ids(clients: list[str]) -> list[str]:
    if not clients:
        raise ClientConfigError("at least one client must be selected")
    if len(clients) == 1 and clients[0] == "all":
        return list(CLIENT_TARGETS)
    unknown = [client for client in clients if client not in CLIENT_TARGETS]
    if unknown:
        supported = ", ".join(sorted((*CLIENT_TARGETS, "all")))
        raise ClientConfigError(
            f"unsupported client(s): {', '.join(unknown)}; supported: {supported}"
        )
    # Preserve order while deduplicating.
    seen: set[str] = set()
    ordered: list[str] = []
    for client in clients:
        if client not in seen:
            seen.add(client)
            ordered.append(client)
    return ordered


__all__ = [
    "CLIENT_TARGETS",
    "ClientConfigError",
    "ClientTarget",
    "assert_rendered_config_is_privacy_safe",
    "build_mcp_server_entry",
    "build_mcp_servers_document",
    "build_proxy_env",
    "build_run_args",
    "format_client_config_json_payload",
    "format_client_config_text",
    "read_role_preset_from_config",
    "render_client_configs",
    "resolve_proxy_command",
]
