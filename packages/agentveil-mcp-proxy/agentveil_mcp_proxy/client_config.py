"""Dry-run MCP client config rendering for AgentVeil MCP Proxy onboarding."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Mapping

from agentveil_mcp_proxy.client_packs import (
    CLIENT_PACK_IDS,
    CLIENT_PACKS,
    ClientPackError,
    get_client_pack,
    normalize_client_pack_ids,
)

DEFAULT_PROXY_COMMAND = "agentveil-mcp-proxy"
DEFAULT_SERVER_NAME = "agentveil-mcp-proxy"


class ClientConfigError(ValueError):
    """Raised when client config rendering inputs are invalid."""


def bounded_path_ref(path: str | Path | None) -> dict[str, str | None]:
    """Return basename + short hash for one local path without exposing full path."""

    if path is None:
        return {"basename": None, "ref": None}
    value = str(Path(path).expanduser())
    return {
        "basename": Path(value).name,
        "ref": hashlib.sha256(value.encode("utf-8")).hexdigest()[:16],
    }


def _looks_like_absolute_path(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if text.startswith("/") or text.startswith("~"):
        return True
    return len(text) > 1 and text[1] == ":"


def sanitize_json_paths(value: Any) -> Any:
    """Replace absolute path strings in JSON payloads with bounded refs."""

    if isinstance(value, dict):
        return {key: sanitize_json_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_json_paths(item) for item in value]
    if isinstance(value, str) and _looks_like_absolute_path(value):
        return bounded_path_ref(value)
    return value


def format_bounded_run_args(run_args: list[str]) -> list[str | dict[str, str | None]]:
    """Return run args with path values replaced by bounded basenames for JSON output."""

    bounded: list[str | dict[str, str | None]] = []
    skip_next = False
    for token in run_args:
        if skip_next:
            skip_next = False
            if _looks_like_absolute_path(token):
                ref = bounded_path_ref(token)
                bounded.append(ref["basename"] or "path")
            else:
                bounded.append(token)
            continue
        if token in {"--home", "--config", "--passphrase-file"}:
            bounded.append(token)
            skip_next = True
            continue
        if _looks_like_absolute_path(token):
            ref = bounded_path_ref(token)
            bounded.append(ref["basename"] or "path")
            continue
        bounded.append(token)
    return bounded


def assert_proxy_cli_output_is_privacy_safe(text: str) -> None:
    """Reject user-visible CLI output that leaks absolute local paths."""

    lowered = text.lower()
    for marker in ("/users/", "/private/", "/var/folders/", "/tmp/"):
        if marker in lowered:
            raise ClientConfigError(f"CLI output must not include {marker!r}")
    if '": "/' in text or "': '/" in text:
        raise ClientConfigError("CLI output must not include absolute local filesystem paths")


def assert_proxy_cli_json_is_privacy_safe(payload: Mapping[str, Any]) -> None:
    """Reject structured CLI JSON that could leak absolute local paths."""

    assert_proxy_cli_output_is_privacy_safe(json.dumps(payload, sort_keys=True))


@dataclass(frozen=True)
class ClientTarget:
    """One supported MCP desktop client and where operators paste config."""

    client_id: str
    display_name: str
    config_path_hint: str


def _client_target_from_pack(client_id: str) -> ClientTarget:
    pack = CLIENT_PACKS[client_id]
    return ClientTarget(
        client_id=pack.client_id,
        display_name=pack.display_name,
        config_path_hint=pack.config_path_hint,
    )


CLIENT_TARGETS: dict[str, ClientTarget] = {
    client_id: _client_target_from_pack(client_id)
    for client_id in CLIENT_PACK_IDS
}
CLIENT_TARGETS["gemini-cli"] = _client_target_from_pack("gemini_cli")
CLIENT_TARGETS["claude_desktop"] = ClientTarget(
    client_id="claude_desktop",
    display_name="Claude Desktop",
    config_path_hint=(
        "~/Library/Application Support/Claude/claude_desktop_config.json (macOS) "
        "or %APPDATA%/Claude/claude_desktop_config.json (Windows)"
    ),
)


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


def build_downstream_startup_preview(downstream: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a bounded preview of local MCP downstream startup command/env shape."""

    if not isinstance(downstream, Mapping) or not downstream:
        return {"configured": False}
    command = downstream.get("command")
    if not isinstance(command, str) or not command.strip():
        return {"configured": False}
    command_path = Path(command.strip())
    args_raw = downstream.get("args")
    args = list(args_raw) if isinstance(args_raw, list) else []
    env_raw = downstream.get("env")
    env = env_raw if isinstance(env_raw, Mapping) else {}
    bounded_args: list[dict[str, Any]] = []
    for arg in args[:12]:
        if not isinstance(arg, str):
            continue
        if _looks_like_absolute_path(arg):
            ref = bounded_path_ref(arg)
            bounded_args.append({"kind": "path_ref", "basename": ref["basename"], "ref": ref["ref"]})
        else:
            bounded_args.append({"kind": "literal", "token": arg[:48]})
    command_name = command_path.name or command.strip()
    if command_name.startswith("python") or command.strip().endswith("python"):
        command_category = "python"
    else:
        command_category = "executable"
    return {
        "configured": True,
        "command_basename": command_name,
        "command_category": command_category,
        "arg_count": len(args),
        "bounded_args": bounded_args,
        "env_key_count": len(env),
        "env_keys": sorted(str(key) for key in env.keys())[:16],
    }


def downstream_startup_fingerprint(downstream: Mapping[str, Any] | None) -> str | None:
    """Return a stable hash for one bounded downstream startup preview."""

    preview = build_downstream_startup_preview(downstream)
    if not preview.get("configured"):
        return None
    return hashlib.sha256(
        json.dumps(preview, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _toml_string_literal(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


_TOML_SECTION_HEADER = re.compile(r"^\[([^\]]+)\]\s*$")
_TOML_STRING_VALUE = re.compile(r'^"((?:\\.|[^"\\])*)"$')
_TOML_STRING_ARRAY = re.compile(r"^\[(.*)\]$")
CODEX_DEFAULT_TOOLS_APPROVAL_MODE = "approve"


def _parse_toml_string_value(raw: str) -> str:
    trimmed = raw.strip()
    match = _TOML_STRING_VALUE.match(trimmed)
    if not match:
        raise ClientConfigError("codex config contains invalid TOML string value")
    return match.group(1).replace('\\"', '"').replace("\\\\", "\\")


def _parse_toml_string_array(raw: str) -> list[str]:
    trimmed = raw.strip()
    match = _TOML_STRING_ARRAY.match(trimmed)
    if match is None:
        raise ClientConfigError("codex config contains invalid TOML string array")
    inner = match.group(1).strip()
    if not inner:
        return []
    items: list[str] = []
    for part in inner.split(","):
        part = part.strip()
        if part:
            items.append(_parse_toml_string_value(part))
    return items


def _parse_toml_inline_string_map(raw: str) -> dict[str, str]:
    trimmed = raw.strip()
    if not trimmed.startswith("{") or not trimmed.endswith("}"):
        raise ClientConfigError("codex config contains invalid TOML inline table")
    inner = trimmed[1:-1].strip()
    if not inner:
        return {}
    env: dict[str, str] = {}
    for part in inner.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        env[key.strip()] = _parse_toml_string_value(value.strip())
    return env


def _codex_mcp_server_section_name(server_name: str) -> str:
    trimmed = server_name.strip()
    if not trimmed:
        raise ClientConfigError("server name must not be empty")
    return f"mcp_servers.{trimmed}"


def _find_codex_section_span(text: str, server_name: str) -> tuple[int, int] | None:
    section = _codex_mcp_server_section_name(server_name)
    lines = text.splitlines(keepends=True)
    start_line = None
    for index, line in enumerate(lines):
        if line.strip() == f"[{section}]":
            start_line = index
            break
    if start_line is None:
        return None
    end_line = len(lines)
    for index in range(start_line + 1, len(lines)):
        if _TOML_SECTION_HEADER.match(lines[index].strip()):
            end_line = index
            break
    start_offset = sum(len(item) for item in lines[:start_line])
    end_offset = sum(len(item) for item in lines[:end_line])
    return start_offset, end_offset


def remove_codex_mcp_server_section(text: str, *, server_name: str) -> str:
    """Remove one Codex ``[mcp_servers.<name>]`` block without touching other content."""

    span = _find_codex_section_span(text, server_name)
    if span is None:
        return text
    start, end = span
    updated = text[:start] + text[end:]
    return updated.rstrip("\n")


def build_codex_mcp_server_section(
    *,
    server_name: str,
    command: str,
    run_args: list[str],
    home: Path | None = None,
) -> str:
    """Build one Codex MCP server TOML section without unrelated config."""

    trimmed_name = server_name.strip()
    if not trimmed_name:
        raise ClientConfigError("server name must not be empty")
    lines = [
        f"[{_codex_mcp_server_section_name(trimmed_name)}]",
        f"command = {_toml_string_literal(command)}",
        f"args = [{', '.join(_toml_string_literal(item) for item in run_args)}]",
        f"default_tools_approval_mode = {_toml_string_literal(CODEX_DEFAULT_TOOLS_APPROVAL_MODE)}",
    ]
    env = build_proxy_env(home=home)
    if env:
        env_items = ", ".join(
            f"{key} = {_toml_string_literal(value)}" for key, value in env.items()
        )
        lines.append(f"env = {{ {env_items} }}")
    return "\n".join(lines)


def merge_codex_mcp_server_into_text(
    text: str,
    *,
    server_name: str,
    command: str,
    run_args: list[str],
    home: Path | None = None,
) -> str:
    """Insert or replace one AgentVeil MCP server block in Codex config text."""

    cleaned = remove_codex_mcp_server_section(text, server_name=server_name).rstrip()
    block = build_codex_mcp_server_section(
        server_name=server_name,
        command=command,
        run_args=run_args,
        home=home,
    )
    if cleaned:
        return cleaned + "\n\n" + block + "\n"
    return block + "\n"


def parse_codex_mcp_server_entry(text: str, *, server_name: str) -> dict[str, Any] | None:
    """Parse one Codex MCP server block from config text."""

    span = _find_codex_section_span(text, server_name)
    if span is None:
        return None
    section_text = text[span[0]:span[1]]
    entry: dict[str, Any] = {}
    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("["):
            continue
        if stripped.startswith("command ="):
            entry["command"] = _parse_toml_string_value(stripped.split("=", 1)[1].strip())
            continue
        if stripped.startswith("args ="):
            entry["args"] = _parse_toml_string_array(stripped.split("=", 1)[1].strip())
            continue
        if stripped.startswith("env ="):
            entry["env"] = _parse_toml_inline_string_map(stripped.split("=", 1)[1].strip())
            continue
        if stripped.startswith("default_tools_approval_mode ="):
            entry["default_tools_approval_mode"] = _parse_toml_string_value(
                stripped.split("=", 1)[1].strip()
            )
    if "command" not in entry:
        return None
    entry.setdefault("args", [])
    entry.setdefault("env", {})
    return entry


def codex_mcp_server_entry_matches_launch_spec(
    entry: Mapping[str, Any],
    launch_spec: Mapping[str, Any],
) -> bool:
    """Return whether one parsed Codex MCP block matches the generated launch spec."""

    command = launch_spec.get("command")
    args = launch_spec.get("args")
    env = launch_spec.get("env")
    if not isinstance(command, str) or not isinstance(args, list):
        return False
    if entry.get("command") != command:
        return False
    if entry.get("args") != args:
        return False
    entry_env = entry.get("env", {})
    if entry_env is None:
        entry_env = {}
    if not isinstance(entry_env, dict):
        return False
    if env != entry_env:
        return False
    if entry.get("default_tools_approval_mode") != CODEX_DEFAULT_TOOLS_APPROVAL_MODE:
        return False
    return True


def build_codex_manual_config_toml(
    *,
    server_name: str,
    command: str,
    run_args: list[str],
    home: Path | None = None,
) -> str:
    """Build a copy-paste Codex MCP TOML snippet for manual merge."""

    trimmed_name = server_name.strip()
    if not trimmed_name:
        raise ClientConfigError("server name must not be empty")
    lines = [
        "# AgentVeil MCP proxy — merge into Codex MCP settings (~/.codex/config.toml)",
        build_codex_mcp_server_section(
            server_name=server_name,
            command=command,
            run_args=run_args,
            home=home,
        ),
    ]
    return "\n".join(lines) + "\n"


def build_generated_launch_spec(
    *,
    command: str,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
) -> dict[str, Any]:
    """Return the command/args/env tuple embedded in generated client config."""

    trimmed_command = command.strip()
    if not trimmed_command:
        raise ClientConfigError("proxy command must not be empty")
    return {
        "command": trimmed_command,
        "args": build_run_args(
            home=home,
            config_path=config_path,
            passphrase_file=passphrase_file,
        ),
        "env": build_proxy_env(home=home),
    }


def build_generic_mcp_route_fields(
    *,
    client_id: str,
    home: Path | None = None,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    known_client: bool = True,
) -> dict[str, Any]:
    """Return bounded generic MCP route fields for runtime attach fallbacks."""

    resolved_command = resolve_proxy_command(proxy_command)
    run_args = build_run_args(
        home=home,
        config_path=config_path,
        passphrase_file=passphrase_file,
    )
    command_display = (
        Path(resolved_command).name
        if _looks_like_absolute_path(resolved_command)
        else resolved_command
    )
    if known_client and client_id in CLIENT_PACK_IDS:
        route_via = f"agentveil-mcp-proxy client-config print --client {client_id}"
    else:
        route_via = "agentveil-mcp-proxy client-config print"
    fields: dict[str, Any] = {
        "generic_route_available": True,
        "route_via": route_via,
        "route_command": command_display,
        "route_args": format_bounded_run_args(run_args),
    }
    if home is not None:
        fields["home_ref"] = bounded_path_ref(home)
    if config_path is not None:
        fields["config_ref"] = bounded_path_ref(config_path)
    return fields


def generated_command_is_available(command: str) -> bool:
    """Return whether the generated MCP client config command can be executed."""

    trimmed = command.strip()
    if not trimmed:
        return False
    if trimmed.startswith("/") or trimmed.startswith("~") or (
        len(trimmed) > 1 and trimmed[1] == ":"
    ):
        expanded = Path(trimmed).expanduser()
        return expanded.is_file() and os.access(expanded, os.X_OK)
    return shutil.which(trimmed) is not None


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
        pack = get_client_pack(client_id) if client_id in CLIENT_PACKS else None
        if pack is not None and pack.config_surface in {"codex_config_toml_manual", "codex_config_toml"}:
            rendered[client_id] = {
                "manual_config_toml": build_codex_manual_config_toml(
                    server_name=server_name,
                    command=resolved_command,
                    run_args=run_args,
                    home=home,
                ),
            }
        else:
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

    blocks: list[str] = [
        "# AgentVeil client-config print (dry-run; does not edit IDE files)",
        "# Privacy-bounded summary: use `client-config print --json` and read summary/privacy.",
        "# Runnable local client config below (surface=local_client_config; may include local paths).",
        "",
    ]
    for client_id, document in rendered.items():
        target = CLIENT_TARGETS[client_id]
        if "manual_config_toml" in document:
            blocks.append(
                f"# {target.display_name} — local runnable manual config (may include local paths)\n"
                f"# Merge into {target.config_path_hint}\n"
                f"{document['manual_config_toml']}\n"
            )
        else:
            blocks.append(
                f"# {target.display_name} — local runnable client config (may include local paths)\n"
                f"# Paste into {target.config_path_hint}\n"
                f"{json.dumps(document, indent=2, sort_keys=True)}\n"
            )
    return "\n".join(blocks)


def setup_client_config_path(home: Path, client_id: str) -> Path:
    """Return the setup-managed MCP client config path for one client id."""

    if client_id not in CLIENT_TARGETS:
        supported = ", ".join(sorted(CLIENT_TARGETS))
        raise ClientConfigError(f"unsupported client {client_id!r}; supported: {supported}")
    return home.expanduser() / "mcp-proxy" / "clients" / f"{client_id}-mcp.json"


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


def assert_client_config_summary_is_privacy_safe(summary: Mapping[str, Any]) -> None:
    """Reject bounded client-config summary fields that leak absolute local paths."""

    assert_proxy_cli_output_is_privacy_safe(json.dumps(summary, sort_keys=True))


def assert_mcp_client_document_is_runnable(document: Mapping[str, Any]) -> None:
    """Ensure one MCP client config document is structurally copy-paste runnable."""

    servers = document.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        raise ClientConfigError("local client config must include mcpServers")
    for entry in servers.values():
        if not isinstance(entry, dict):
            raise ClientConfigError("local client config entry must be an object")
        command = entry.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ClientConfigError("local client config command must be a non-empty string")
        args = entry.get("args", [])
        # claim-check: allow Python all() type guard; not a coverage claim.
        if not isinstance(args, list) or not args or not all(isinstance(item, str) for item in args):
            raise ClientConfigError("local client config args must be a non-empty string list")
        env = entry.get("env", {})
        if env is not None:
            # claim-check: allow Python all() type guard; not a coverage claim.
            if not isinstance(env, dict) or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in env.items()
            ):
                raise ClientConfigError("local client config env values must be strings")


def format_client_config_json_payload(
    rendered: Mapping[str, Mapping[str, Any]],
    *,
    command: str,
    run_args: list[str],
    config_path: Path | None = None,
    home: Path | None = None,
    role_preset: str | None = None,
    downstream: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return structured JSON for ``client-config print --json``."""

    from agentveil_mcp_proxy.client_packs import client_pack_to_dict

    clients_payload: dict[str, Any] = {}
    for client_id, document in rendered.items():
        target = CLIENT_TARGETS[client_id]
        pack_payload = (
            client_pack_to_dict(get_client_pack(client_id))
            if client_id in CLIENT_PACKS
            else None
        )
        if "manual_config_toml" in document:
            manual_text = str(document["manual_config_toml"])
            clients_payload[client_id] = {
                "display_name": target.display_name,
                "config_path_hint": target.config_path_hint,
                "surface": "local_manual_config",
                "local_manual_config": manual_text,
                "copy_paste_text": manual_text,
                "manual_merge_required": True,
                "pack": pack_payload,
            }
        else:
            assert_mcp_client_document_is_runnable(document)
            clients_payload[client_id] = {
                "display_name": target.display_name,
                "config_path_hint": target.config_path_hint,
                "surface": "local_client_config",
                "local_client_config": dict(document),
                "copy_paste_text": json.dumps(document, indent=2, sort_keys=True) + "\n",
                "manual_merge_required": False,
                "pack": pack_payload,
            }
    summary: dict[str, Any] = {
        "command": Path(command).name if _looks_like_absolute_path(command) else command,
        "client_count": len(clients_payload),
        "privacy_bounded": True,
    }
    if config_path is not None:
        summary["config_ref"] = bounded_path_ref(config_path)
    if home is not None:
        summary["home_ref"] = bounded_path_ref(home)
    if role_preset is not None:
        summary["role_preset"] = role_preset
    if downstream is not None:
        summary["downstream_startup_preview"] = build_downstream_startup_preview(downstream)
    assert_client_config_summary_is_privacy_safe(summary)
    return {
        "ok": True,
        "dry_run": True,
        "writes_user_config": False,
        "summary": summary,
        "clients": clients_payload,
        "privacy": {
            "includes_secrets": False,
            "includes_passphrase": False,
            "includes_private_key": False,
            "summary_is_privacy_bounded": True,
            "local_client_config_may_include_local_paths": True,
        },
    }


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
    try:
        pack_ids = normalize_client_pack_ids(clients)
    except ClientPackError:
        pack_ids = None
    if pack_ids is not None and set(pack_ids) == set(clients):
        return pack_ids
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
    "assert_client_config_summary_is_privacy_safe",
    "assert_mcp_client_document_is_runnable",
    "assert_proxy_cli_json_is_privacy_safe",
    "assert_proxy_cli_output_is_privacy_safe",
    "assert_rendered_config_is_privacy_safe",
    "bounded_path_ref",
    "build_codex_manual_config_toml",
    "build_codex_mcp_server_section",
    "build_generic_mcp_route_fields",
    "build_generated_launch_spec",
    "build_mcp_server_entry",
    "build_mcp_servers_document",
    "build_proxy_env",
    "build_run_args",
    "codex_mcp_server_entry_matches_launch_spec",
    "format_bounded_run_args",
    "format_client_config_json_payload",
    "format_client_config_text",
    "generated_command_is_available",
    "merge_codex_mcp_server_into_text",
    "parse_codex_mcp_server_entry",
    "read_role_preset_from_config",
    "remove_codex_mcp_server_section",
    "render_client_configs",
    "resolve_proxy_command",
    "sanitize_json_paths",
    "setup_client_config_path",
]
