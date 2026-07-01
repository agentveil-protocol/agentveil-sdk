"""Client compatibility pack metadata for Cursor, Claude Code, Codex, and Gemini CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

SupportStatus = Literal["supported", "manual", "unsupported"]
ConfigSurface = Literal[
    "cursor_settings_json",
    "mcp_servers_json",
    "claude_settings_json",
    "codex_config_toml",
    "codex_config_toml_manual",
    "gemini_settings_json",
]

CLIENT_PACK_IDS: tuple[str, ...] = ("cursor", "claude_code", "codex", "gemini_cli")


@dataclass(frozen=True)
class ClientPack:
    """One lightweight client compatibility pack."""

    client_id: str
    display_name: str
    config_surface: ConfigSurface
    config_path_hint: str
    guidance_summary: str
    health_check_capabilities: tuple[str, ...]
    known_limitations: tuple[str, ...]
    support_status: SupportStatus
    renders_runnable_config: bool


CLIENT_PACKS: dict[str, ClientPack] = {
    "cursor": ClientPack(
        client_id="cursor",
        display_name="Cursor",
        config_surface="mcp_servers_json",
        config_path_hint="~/.cursor/mcp.json (user-level MCP config)",
        guidance_summary=(
            "Run `agentveil-mcp-proxy connect cursor --write` to add AgentVeil MCP settings, "
            "then ask the agent to use AgentVeil MCP tools for protected actions."
        ),
        health_check_capabilities=(
            "config_render",
            "tools_list",
            "routed_read_action",
            "list_only_diagnostic",
        ),
        known_limitations=(
            "Provider-native Cursor tools stay outside AgentVeil routing.",
            "Browser Approval Center UX is optional; use terminal/none modes in tests.",
        ),
        support_status="supported",
        renders_runnable_config=True,
    ),
    "claude_code": ClientPack(
        client_id="claude_code",
        display_name="Claude Code",
        config_surface="claude_settings_json",
        config_path_hint=".mcp.json (project root)",
        guidance_summary=(
            "Run `agentveil-mcp-proxy connect claude_code --write` for project-local MCP settings, "
            "then route protected work through AgentVeil tools."
        ),
        health_check_capabilities=(
            "config_render",
            "tools_list",
            "routed_read_action",
            "list_only_diagnostic",
        ),
        known_limitations=(
            "Claude Code CLI must be installed separately.",
            "Only project-local .mcp.json auto-write is supported by this client pack.",
        ),
        support_status="supported",
        renders_runnable_config=True,
    ),
    "codex": ClientPack(
        client_id="codex",
        display_name="Codex",
        config_surface="codex_config_toml",
        config_path_hint="~/.codex/config.toml",
        guidance_summary=(
            "Run `agentveil-mcp-proxy connect codex --write` to merge AgentVeil MCP settings into "
            "~/.codex/config.toml, then route protected actions through AgentVeil MCP tools."
        ),
        health_check_capabilities=(
            "config_render",
            "tools_list",
            "routed_read_action",
            "list_only_diagnostic",
        ),
        known_limitations=(
            "Codex uses TOML MCP config under ~/.codex/config.toml.",
            "Provider-native Codex tools stay outside AgentVeil routing.",
        ),
        support_status="supported",
        renders_runnable_config=True,
    ),
    "gemini_cli": ClientPack(
        client_id="gemini_cli",
        display_name="Gemini CLI",
        config_surface="gemini_settings_json",
        config_path_hint=".gemini/settings.json (project root)",
        guidance_summary=(
            "Run `agentveil-mcp-proxy setup gemini-cli --project-dir <path> --yes` "
            "(or `--choose-folder --yes`) for project-local Gemini settings, then route "
            "configured work through AgentVeil MCP tools."
        ),
        health_check_capabilities=(
            "config_render",
            "tools_list",
            "routed_read_action",
            "list_only_diagnostic",
        ),
        known_limitations=(
            "Gemini CLI must trust the project folder before loading project settings.",
            "Provider-native Gemini tools stay outside AgentVeil routing until hook evidence.",
        ),
        support_status="supported",
        renders_runnable_config=True,
    ),
}


class ClientPackError(ValueError):
    """Raised when client pack inputs are invalid."""


def normalize_client_pack_ids(client_ids: list[str] | None) -> list[str]:
    """Return ordered unique client pack ids."""

    if client_ids is None or not client_ids:
        return list(CLIENT_PACK_IDS)
    if len(client_ids) == 1 and client_ids[0] == "all":
        return list(CLIENT_PACK_IDS)
    unknown = [item for item in client_ids if item not in CLIENT_PACKS]
    if unknown:
        supported = ", ".join((*CLIENT_PACK_IDS, "all"))
        raise ClientPackError(
            f"unsupported client pack(s): {', '.join(unknown)}; supported: {supported}"
        )
    seen: set[str] = set()
    ordered: list[str] = []
    for item in client_ids:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def get_client_pack(client_id: str) -> ClientPack:
    """Return one client pack or raise."""

    try:
        return CLIENT_PACKS[client_id]
    except KeyError as exc:
        supported = ", ".join(CLIENT_PACK_IDS)
        raise ClientPackError(
            f"unsupported client pack {client_id!r}; supported: {supported}"
        ) from exc


def client_pack_to_dict(pack: ClientPack) -> dict[str, Any]:
    """Return bounded JSON-serializable pack metadata."""

    return {
        "client_id": pack.client_id,
        "display_name": pack.display_name,
        "config_surface": pack.config_surface,
        "config_path_hint": pack.config_path_hint,
        "guidance_summary": pack.guidance_summary,
        "health_check_capabilities": list(pack.health_check_capabilities),
        "known_limitations": list(pack.known_limitations),
        "support_status": pack.support_status,
        "renders_runnable_config": pack.renders_runnable_config,
    }


def build_client_packs_payload(*, client_ids: list[str] | None = None) -> dict[str, Any]:
    """Return structured metadata for one or more client packs."""

    selected = normalize_client_pack_ids(client_ids)
    packs = {client_id: client_pack_to_dict(CLIENT_PACKS[client_id]) for client_id in selected}
    return {
        "ok": True,
        "pack_count": len(packs),
        "packs": packs,
        "privacy_bounded": True,
    }


def assert_client_packs_payload_is_privacy_safe(payload: Mapping[str, Any]) -> None:
    """Reject pack metadata that could leak absolute local paths."""

    from agentveil_mcp_proxy.client_config import assert_proxy_cli_json_is_privacy_safe

    assert_proxy_cli_json_is_privacy_safe(payload)


__all__ = [
    "CLIENT_PACK_IDS",
    "CLIENT_PACKS",
    "ClientPack",
    "ClientPackError",
    "ConfigSurface",
    "SupportStatus",
    "assert_client_packs_payload_is_privacy_safe",
    "build_client_packs_payload",
    "client_pack_to_dict",
    "get_client_pack",
    "normalize_client_pack_ids",
]
