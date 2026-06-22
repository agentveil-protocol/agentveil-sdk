"""Guided auto-connect for supported MCP desktop clients."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal, Mapping

from agentveil_mcp_proxy.client_config import (
    DEFAULT_SERVER_NAME,
    ClientConfigError,
    assert_mcp_client_document_is_runnable,
    assert_proxy_cli_json_is_privacy_safe,
    assert_proxy_cli_output_is_privacy_safe,
    bounded_path_ref,
    build_generated_launch_spec,
    build_mcp_server_entry,
    build_run_args,
    codex_mcp_server_entry_matches_launch_spec,
    generated_command_is_available,
    merge_codex_mcp_server_into_text,
    parse_codex_mcp_server_entry,
    remove_codex_mcp_server_section,
    render_client_configs,
    resolve_proxy_command,
    sanitize_json_paths,
)
from agentveil_mcp_proxy.client_doctor import build_client_doctor_report
from agentveil_mcp_proxy.client_packs import CLIENT_PACK_IDS, ClientPackError, get_client_pack

ConnectMode = Literal["auto_connect", "manual_fallback"]
ConnectSupportLevel = Literal["auto_write", "manual_fallback", "unsupported"]
DoctorStatus = Literal["ok", "skipped", "failed"]
ALL_CLIENTS_TARGET = "all"  # claim-check: allow "all" is a CLI target literal, not a coverage claim.


class ClientConnectError(ValueError):
    """Bounded client-connect error without raw filesystem paths in messages."""


@dataclass(frozen=True)
class ClientConfigLocation:
    client_id: str
    config_path: Path
    config_surface: str
    support_level: ConnectSupportLevel
    fallback_reason: str | None = None

    @property
    def auto_connect_supported(self) -> bool:
        return self.support_level == "auto_write"


class ClientConnectAdapter(ABC):
    """Client-specific connect adapter for one MCP desktop client."""

    client_id: str
    support_level: ConnectSupportLevel
    requires_restart_after_write: bool = True
    uses_codex_toml: bool = False
    uses_cursor_settings_json: bool = False

    @abstractmethod
    def resolve_config_location(self, *, project_root: Path) -> ClientConfigLocation:
        """Return the deterministic config location for this client."""

    def load_document(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {"mcpServers": {}}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ClientConnectError("client config is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ClientConnectError("client config must be a JSON object")
        servers = payload.get("mcpServers", {})
        if servers is None:
            payload["mcpServers"] = {}
        elif not isinstance(payload["mcpServers"], dict):
            raise ClientConnectError("client config mcpServers must be an object")
        return payload

    def write_document(self, path: Path, document: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def resolve_cursor_user_data_dir() -> Path:
    """Return Cursor user-data root (``User/settings.json`` parent parent)."""

    configured = os.environ.get("CURSOR_USER_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / "Library" / "Application Support" / "Cursor").expanduser().resolve()


def resolve_cursor_global_mcp_json_path() -> Path:
    """Return Cursor user-level MCP config path (``~/.cursor/mcp.json``)."""

    return (Path.home() / ".cursor" / "mcp.json").expanduser().resolve()


def _cursor_settings_mcp_servers(document: Mapping[str, Any]) -> dict[str, Any]:
    mcp = document.get("mcp")
    if mcp is None:
        return {}
    if not isinstance(mcp, dict):
        raise ClientConnectError("settings mcp must be an object")
    servers = mcp.get("servers")
    if servers is None:
        return {}
    if not isinstance(servers, dict):
        raise ClientConnectError("settings mcp.servers must be an object")
    return servers


def merge_cursor_settings_server_entry(
    document: Mapping[str, Any],
    *,
    server_name: str,
    entry: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(document)
    mcp = dict(merged.get("mcp") or {})
    servers = dict(_cursor_settings_mcp_servers(merged))
    servers[server_name] = dict(entry)
    assert_mcp_client_document_is_runnable({"mcpServers": {server_name: servers[server_name]}})
    mcp["servers"] = servers
    merged["mcp"] = mcp
    return merged


def remove_cursor_settings_server_entry(
    document: Mapping[str, Any],
    *,
    server_name: str,
) -> dict[str, Any]:
    merged = dict(document)
    mcp = dict(merged.get("mcp") or {})
    servers = dict(_cursor_settings_mcp_servers(merged))
    servers.pop(server_name, None)
    if servers:
        mcp["servers"] = servers
        merged["mcp"] = mcp
    elif "mcp" in merged and isinstance(merged["mcp"], dict):
        cleaned_mcp = dict(merged["mcp"])
        cleaned_mcp.pop("servers", None)
        if cleaned_mcp:
            merged["mcp"] = cleaned_mcp
        else:
            merged.pop("mcp", None)
    return merged


def cleanup_legacy_cursor_settings_agentveil_entry(
    *,
    server_name: str = DEFAULT_SERVER_NAME,
) -> dict[str, str | None] | None:
    """Remove a stale generated ``settings.json`` MCP entry without touching other settings."""

    settings_path = resolve_cursor_user_data_dir() / "User" / "settings.json"
    if not settings_path.exists():
        return None
    try:
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ClientConnectError(
            "legacy Cursor settings cleanup failed: settings.json is not valid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise ClientConnectError(
            "legacy Cursor settings cleanup failed: settings.json must be a JSON object"
        )
    if server_name not in _cursor_settings_mcp_servers(payload):
        return None
    backup = create_config_backup(settings_path)
    cleaned = remove_cursor_settings_server_entry(payload, server_name=server_name)
    _write_client_config_text(
        settings_path,
        json.dumps(cleaned, indent=2, sort_keys=True) + "\n",
    )
    return backup


class CursorConnectAdapter(ClientConnectAdapter):
    client_id = "cursor"
    support_level: ConnectSupportLevel = "auto_write"

    def resolve_config_location(self, *, project_root: Path) -> ClientConfigLocation:
        pack = get_client_pack(self.client_id)
        del project_root  # Cursor user MCP config is global, not project-local.
        mcp_json_path = resolve_cursor_global_mcp_json_path()
        return ClientConfigLocation(
            client_id=self.client_id,
            config_path=mcp_json_path,
            config_surface=pack.config_surface,
            support_level=self.support_level,
        )


class ClaudeCodeConnectAdapter(ClientConnectAdapter):
    client_id = "claude_code"
    support_level: ConnectSupportLevel = "auto_write"

    def resolve_config_location(self, *, project_root: Path) -> ClientConfigLocation:
        pack = get_client_pack(self.client_id)
        return ClientConfigLocation(
            client_id=self.client_id,
            config_path=project_root / ".mcp.json",
            config_surface=pack.config_surface,
            support_level=self.support_level,
        )


class CodexConnectAdapter(ClientConnectAdapter):
    client_id = "codex"
    support_level: ConnectSupportLevel = "auto_write"
    uses_codex_toml = True

    def resolve_config_location(self, *, project_root: Path) -> ClientConfigLocation:
        pack = get_client_pack(self.client_id)
        del project_root  # Codex config is user-global.
        return ClientConfigLocation(
            client_id=self.client_id,
            config_path=(Path.home() / ".codex" / "config.toml").expanduser(),
            config_surface=pack.config_surface,
            support_level=self.support_level,
        )


CONNECT_ADAPTERS: dict[str, ClientConnectAdapter] = {
    adapter.client_id: adapter
    for adapter in (
        CursorConnectAdapter(),
        ClaudeCodeConnectAdapter(),
        CodexConnectAdapter(),
    )
}


def get_connect_adapter(client_id: str) -> ClientConnectAdapter:
    normalized = normalize_connect_client_id(client_id)
    return CONNECT_ADAPTERS[normalized]


def normalize_connect_client_id(client_id: str) -> str:
    trimmed = str(client_id or "").strip()
    if trimmed not in CLIENT_PACK_IDS:
        supported = ", ".join(CLIENT_PACK_IDS)
        raise ClientConnectError(f"unsupported client {trimmed!r}; supported: {supported}")
    return trimmed


def resolve_client_config_location(
    client_id: str,
    *,
    project_root: Path | None = None,
) -> ClientConfigLocation:
    """Return the deterministic client config path for supported auto-connect."""

    adapter = get_connect_adapter(client_id)
    root = (project_root or Path.cwd()).resolve()
    return adapter.resolve_config_location(project_root=root)


def _read_client_config_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _write_client_config_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if text:
        path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    elif path.exists():
        path.unlink()


def _current_server_entry(
    adapter: ClientConnectAdapter,
    path: Path,
    *,
    server_name: str,
) -> dict[str, Any] | None:
    if adapter.uses_codex_toml:
        return parse_codex_mcp_server_entry(
            _read_client_config_text(path),
            server_name=server_name,
        )
    document = adapter.load_document(path)
    entry = (document.get("mcpServers") or {}).get(server_name)
    return dict(entry) if isinstance(entry, dict) else None


def _server_entries_match(left: Mapping[str, Any] | None, right: Mapping[str, Any]) -> bool:
    if left is None:
        return False
    return (
        left.get("command") == right.get("command")
        and left.get("args") == right.get("args")
        and (left.get("env") or {}) == (right.get("env") or {})
    )


def _merge_client_config_text(
    adapter: ClientConnectAdapter,
    path: Path,
    *,
    server_name: str,
    entry: Mapping[str, Any],
    home: Path,
) -> str:
    if adapter.uses_codex_toml:
        command = entry.get("command")
        args = entry.get("args")
        if not isinstance(command, str) or not isinstance(args, list):
            raise ClientConnectError("generated Codex MCP server entry is invalid")
        return merge_codex_mcp_server_into_text(
            _read_client_config_text(path),
            server_name=server_name,
            command=command,
            run_args=[str(item) for item in args],
            home=home,
        )
    merged = merge_agentveil_server_entry(
        adapter.load_document(path),
        server_name=server_name,
        entry=entry,
    )
    return json.dumps(merged, indent=2, sort_keys=True) + "\n"


def _remove_client_config_entry(
    adapter: ClientConnectAdapter,
    path: Path,
    *,
    server_name: str,
) -> str:
    if adapter.uses_codex_toml:
        return remove_codex_mcp_server_section(
            _read_client_config_text(path),
            server_name=server_name,
        ).rstrip()
    merged = remove_agentveil_server_entry(adapter.load_document(path), server_name=server_name)
    return json.dumps(merged, indent=2, sort_keys=True).rstrip()


def _config_entry_matches_launch_spec(
    adapter: ClientConnectAdapter,
    path: Path,
    *,
    server_name: str,
    launch_spec: Mapping[str, Any],
) -> bool:
    entry = _current_server_entry(adapter, path, server_name=server_name)
    if entry is None:
        return False
    if adapter.uses_codex_toml:
        return codex_mcp_server_entry_matches_launch_spec(entry, launch_spec)
    if not isinstance(launch_spec.get("command"), str) or not isinstance(launch_spec.get("args"), list):
        return False
    return (
        entry.get("command") == launch_spec.get("command")
        and entry.get("args") == launch_spec.get("args")
        and (entry.get("env") or {}) == (launch_spec.get("env") or {})
    )


def create_config_backup(path: Path) -> dict[str, str | None] | None:
    if not path.exists():
        return None
    backup_dir = path.parent / ".agentveil-connect-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    content = path.read_text(encoding="utf-8")
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    backup_path = backup_dir / f"{path.name}.{digest}.bak"
    backup_path.write_text(content, encoding="utf-8")
    return bounded_path_ref(backup_path)


def merge_agentveil_server_entry(
    document: Mapping[str, Any],
    *,
    server_name: str,
    entry: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(document)
    servers = dict(merged.get("mcpServers") or {})
    servers[server_name] = dict(entry)
    merged["mcpServers"] = servers
    assert_mcp_client_document_is_runnable({"mcpServers": {server_name: servers[server_name]}})
    return merged


def remove_agentveil_server_entry(
    document: Mapping[str, Any],
    *,
    server_name: str,
) -> dict[str, Any]:
    merged = dict(document)
    servers = dict(merged.get("mcpServers") or {})
    servers.pop(server_name, None)
    merged["mcpServers"] = servers
    return merged


def _build_server_entry(
    *,
    command: str,
    home: Path,
    config_path: Path,
    passphrase_file: Path | None,
) -> dict[str, Any]:
    run_args = build_run_args(
        home=home,
        config_path=config_path,
        passphrase_file=passphrase_file,
    )
    return build_mcp_server_entry(command=command, run_args=run_args, home=home)


def _bounded_preview_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    return sanitize_json_paths(dict(entry))


def _doctor_status_from_report(report: Mapping[str, Any] | None) -> DoctorStatus:
    if report is None:
        return "skipped"
    if report.get("diagnostic_status") == "ok" and report.get("ok") is True:
        return "ok"
    return "failed"


def _run_client_doctor(
    *,
    client_id: str,
    home: Path,
    config_path: Path,
    passphrase_file: Path | None,
    proxy_command: str,
) -> tuple[dict[str, Any] | None, DoctorStatus]:
    """Probe the generated launch path via client-doctor and bound failures."""

    try:
        report = build_client_doctor_report(
            client_id=client_id,
            home=home,
            config_path=config_path,
            passphrase_file=passphrase_file,
            proxy_command=proxy_command,
        )
    except Exception:
        return None, "failed"
    return report, _doctor_status_from_report(report)


def _doctor_summary(report: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if report is None:
        return None
    return {
        "diagnostic_status": report.get("diagnostic_status"),
        "proof_mode": report.get("proof_mode"),
        "provider_native_client_proof": report.get("provider_native_client_proof"),
    }


def _rollback_command(client_id: str) -> str:
    return f"agentveil-mcp-proxy disconnect {client_id} --write"


def _agent_assist_fields(
    *,
    adapter: ClientConnectAdapter,
    write_required: bool,
    will_write: bool,
    backup_planned: bool,
    include_rollback: bool = False,
) -> dict[str, Any]:
    """Structured fields that let an AI assistant drive the install path."""

    fields: dict[str, Any] = {
        "support_status": adapter.support_level,
        "write_required": write_required,
        "will_write": will_write,
        "backup_planned": backup_planned,
        "restart_required": adapter.requires_restart_after_write,
    }
    if include_rollback:
        fields["rollback_command"] = _rollback_command(adapter.client_id)
    return fields


def _native_connect_contract_fields(
    *,
    client_config_mutation: bool,
    route_launch_proved: bool = False,
) -> dict[str, Any]:
    """Explicit preview/write semantics for native client config connect."""

    return {
        "client_config_mutation": client_config_mutation,
        "route_launch_proved": route_launch_proved,
    }


def _manual_config_via(client_id: str) -> str:
    return f"agentveil-mcp-proxy client-config print --client {client_id}"


def _manual_fallback_status_next_step(client_id: str) -> str:
    config_via = _manual_config_via(client_id)
    return (
        f"Manual merge required; run `{config_via}` and merge the bounded config "
        "into the client settings."
    )


def _connect_matrix_row(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return one bounded row for the client matrix commands."""

    row: dict[str, Any] = {
        "client_id": payload.get("client_id"),
        "support_status": payload.get("support_status"),
        "will_write": payload.get("will_write", False),
        "wrote": payload.get("wrote", False),
        "config_entry_present": payload.get("config_entry_present", False),
        "route_launch_proved": payload.get("route_launch_proved", False),
        "client_config_mutation": payload.get("client_config_mutation", False),
        "doctor_status": payload.get("doctor_status", "skipped"),
        "connected": payload.get("connected", False),
        "next_step": payload.get("next_step", ""),
        "ok": payload.get("ok", True),
    }
    if payload.get("config_via"):
        row["config_via"] = payload["config_via"]
    elif payload.get("mode") == "manual_fallback":
        manual = payload.get("manual_fallback") or {}
        config_via = manual.get("config_via")
        if config_via:
            row["config_via"] = config_via
    if payload.get("rollback_command"):
        row["rollback_command"] = payload["rollback_command"]
    if "removed_entry" in payload:
        row["removed_entry"] = payload["removed_entry"]
    return row


def normalize_connect_target(client_id: str) -> list[str]:
    """Return the requested client ids for connect matrix commands."""

    trimmed = str(client_id or "").strip()
    if trimmed == ALL_CLIENTS_TARGET:
        return list(CLIENT_PACK_IDS)
    return [normalize_connect_client_id(trimmed)]


def is_connect_all_target(client_id: str) -> bool:
    return str(client_id or "").strip() == ALL_CLIENTS_TARGET


def _manual_fallback_payload(
    *,
    adapter: ClientConnectAdapter,
    location: ClientConfigLocation,
    reason: str,
    home: Path,
    config_path: Path,
    passphrase_file: Path | None,
    proxy_command: str | None,
    server_name: str,
) -> dict[str, Any]:
    client_id = adapter.client_id
    rendered = render_client_configs(
        clients=[client_id],
        command=resolve_proxy_command(proxy_command),
        home=home,
        config_path=config_path,
        passphrase_file=passphrase_file,
        server_name=server_name,
    )
    document = rendered[client_id]
    payload = {
        "ok": True,
        "mode": "manual_fallback",
        "connected": False,
        "config_entry_present": False,
        "dry_run": True,
        "wrote": False,
        "client_id": client_id,
        "doctor_status": "skipped",
        "manual_fallback_reason": reason,
        "config_ref": bounded_path_ref(location.config_path),
        "next_step": "Run `agentveil-mcp-proxy client-config print --client "
        f"{client_id}` and merge the bounded manual config.",
        "manual_fallback": {
            "surface": "local_manual_config" if "manual_config_toml" in document else "local_client_config",
            "config_via": f"agentveil-mcp-proxy client-config print --client {client_id}",
        },
        **_agent_assist_fields(
            adapter=adapter,
            write_required=True,
            will_write=False,
            backup_planned=False,
            include_rollback=False,
        ),
        **_native_connect_contract_fields(client_config_mutation=False),
        "summary": {
            "client_id": client_id,
            "mode": "manual_fallback",
            "connected": False,
            "support_status": adapter.support_level,
            "privacy_bounded": True,
        },
        "privacy_bounded": True,
    }
    assert_proxy_cli_json_is_privacy_safe(payload)
    return payload


def build_connect_payload(
    *,
    client_id: str,
    home: Path,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
    project_root: Path | None = None,
    write: bool = False,
) -> dict[str, Any]:
    from agentveil_mcp_proxy.cli import load_proxy_config, proxy_paths

    normalized = normalize_connect_client_id(client_id)
    pack = get_client_pack(normalized)
    adapter = get_connect_adapter(normalized)
    paths = proxy_paths(home, config_path)
    location = adapter.resolve_config_location(project_root=(project_root or Path.cwd()).resolve())
    resolved_command = resolve_proxy_command(proxy_command)
    command_available = generated_command_is_available(resolved_command)
    dry_run = not write

    if location.support_level != "auto_write":
        return _manual_fallback_payload(
            adapter=adapter,
            location=location,
            reason=location.fallback_reason or "Auto-connect is not supported for this client.",
            home=paths.home,
            config_path=paths.config_path,
            passphrase_file=passphrase_file,
            proxy_command=proxy_command,
            server_name=server_name,
        )

    config_exists = location.config_path.exists()

    if not command_available:
        payload = {
            "ok": False,
            "mode": "auto_connect",
            "connected": False,
            "config_entry_present": False,
            "dry_run": dry_run,
            "wrote": False,
            "client_id": normalized,
            "doctor_status": "skipped",
            "config_ref": bounded_path_ref(location.config_path),
            "next_step": "Install agentveil-mcp-proxy on PATH or pass --proxy-command, then retry.",
            "errors": ["generated proxy command is not available"],
            **_agent_assist_fields(
                adapter=adapter,
                write_required=True,
                will_write=False,
                backup_planned=config_exists,
                include_rollback=False,
            ),
            **_native_connect_contract_fields(client_config_mutation=False),
            "summary": {
                "client_id": normalized,
                "connected": False,
                "command_available": False,
                "privacy_bounded": True,
            },
            "privacy_bounded": True,
        }
        assert_proxy_cli_json_is_privacy_safe(payload)
        return payload

    effective_passphrase_file = passphrase_file
    if effective_passphrase_file is None:
        try:
            config = load_proxy_config(paths.config_path)
        except Exception:
            config = None
        if config is not None:
            from agentveil_mcp_proxy.cli import _stored_passphrase_file

            effective_passphrase_file = _stored_passphrase_file(config)

    entry = _build_server_entry(
        command=resolved_command,
        home=paths.home,
        config_path=paths.config_path,
        passphrase_file=effective_passphrase_file,
    )
    current_entry = _current_server_entry(adapter, location.config_path, server_name=server_name)
    preview_entry = _bounded_preview_entry(entry)
    backup_ref = bounded_path_ref(location.config_path) if config_exists else None
    write_required = not _server_entries_match(current_entry, entry)

    if dry_run:
        payload = {
            "ok": True,
            "mode": "auto_connect",
            "connected": False,
            "config_entry_present": _server_entries_match(current_entry, entry),
            "dry_run": True,
            "wrote": False,
            "client_id": normalized,
            "doctor_status": "skipped",
            "config_ref": bounded_path_ref(location.config_path),
            "existing_config_ref": backup_ref,
            "preview": {
                "server_name": server_name,
                "entry": preview_entry,
            },
            "next_step": "Re-run with --write to apply this AgentVeil MCP server entry.",
            **_agent_assist_fields(
                adapter=adapter,
                write_required=write_required,
                will_write=False,
                backup_planned=config_exists,
                include_rollback=False,
            ),
            **_native_connect_contract_fields(client_config_mutation=False),
            "summary": {
                "client_id": normalized,
                "connected": False,
                "dry_run": True,
                "write_required": write_required,
                "support_status": adapter.support_level,
                "privacy_bounded": True,
            },
            "privacy_bounded": True,
        }
        assert_proxy_cli_json_is_privacy_safe(payload)
        return payload

    backup = create_config_backup(location.config_path)
    merged_text = _merge_client_config_text(
        adapter,
        location.config_path,
        server_name=server_name,
        entry=entry,
        home=paths.home,
    )
    _write_client_config_text(location.config_path, merged_text)
    if normalized == "cursor":
        cleanup_legacy_cursor_settings_agentveil_entry(server_name=server_name)
    doctor_report, doctor_status = _run_client_doctor(
        client_id=normalized,
        home=paths.home,
        config_path=paths.config_path,
        passphrase_file=effective_passphrase_file,
        proxy_command=resolved_command,
    )

    connected = doctor_status == "ok"
    route_launch_proved = connected
    if doctor_status == "ok":
        next_step = "AgentVeil MCP server entry written and launch verified. Restart the client to load AgentVeil tools."
    elif doctor_status == "failed":
        next_step = (
            "Config was written, but client-doctor did not pass. "
            "Run `agentveil-mcp-proxy client-doctor --client "
            f"{normalized}` for bounded diagnostics."
        )
    else:
        next_step = (
            "Config was written; launch was not verified. "
            f"Run `agentveil-mcp-proxy connect status {normalized}` to confirm."
        )

    payload = {
        "ok": doctor_status != "failed",
        "mode": "auto_connect",
        "connected": connected,
        "route_launch_proved": route_launch_proved,
        "config_entry_present": True,
        "dry_run": False,
        "wrote": True,
        "client_id": normalized,
        "display_name": pack.display_name,
        "doctor_status": doctor_status,
        "config_ref": bounded_path_ref(location.config_path),
        "backup_ref": backup,
        "preview": {
            "server_name": server_name,
            "entry": preview_entry,
        },
        "next_step": next_step,
        **_agent_assist_fields(
            adapter=adapter,
            write_required=False,
            will_write=True,
            backup_planned=config_exists,
            include_rollback=True,
        ),
        **_native_connect_contract_fields(
            client_config_mutation=True,
            route_launch_proved=route_launch_proved,
        ),
        "summary": {
            "client_id": normalized,
            "connected": connected,
            "route_launch_proved": route_launch_proved,
            "config_entry_present": True,
            "wrote": True,
            "doctor_status": doctor_status,
            "support_status": adapter.support_level,
            "privacy_bounded": True,
        },
        "privacy_bounded": True,
    }
    doctor_summary = _doctor_summary(doctor_report)
    if doctor_summary is not None:
        payload["doctor_summary"] = doctor_summary
    assert_proxy_cli_json_is_privacy_safe(payload)
    return payload


def _disconnect_matrix_fields(
    *,
    adapter: ClientConnectAdapter,
    will_write: bool,
    client_config_mutation: bool,
    config_entry_present: bool = False,
) -> dict[str, Any]:
    """Stable matrix row fields shared by disconnect preview and write payloads."""

    return {
        "support_status": adapter.support_level,
        "will_write": will_write,
        "config_entry_present": config_entry_present,
        **_native_connect_contract_fields(
            client_config_mutation=client_config_mutation,
            route_launch_proved=False,
        ),
    }


def build_disconnect_payload(
    *,
    client_id: str,
    home: Path,
    config_path: Path | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
    project_root: Path | None = None,
    write: bool = False,
) -> dict[str, Any]:
    normalized = normalize_connect_client_id(client_id)
    adapter = get_connect_adapter(normalized)
    location = adapter.resolve_config_location(project_root=(project_root or Path.cwd()).resolve())
    dry_run = not write

    if location.support_level != "auto_write":
        payload = {
            "ok": True,
            "mode": "manual_fallback",
            "connected": False,
            "dry_run": dry_run,
            "wrote": False,
            "client_id": normalized,
            "doctor_status": "skipped",
            "config_ref": bounded_path_ref(location.config_path),
            "manual_fallback_reason": location.fallback_reason,
            "next_step": "Remove the AgentVeil MCP entry manually from the client settings.",
            **_disconnect_matrix_fields(
                adapter=adapter,
                will_write=False,
                client_config_mutation=False,
            ),
            "summary": {
                "client_id": normalized,
                "connected": False,
                "privacy_bounded": True,
            },
            "privacy_bounded": True,
        }
        assert_proxy_cli_json_is_privacy_safe(payload)
        return payload

    if not location.config_path.exists():
        payload = {
            "ok": True,
            "mode": "auto_connect",
            "connected": False,
            "dry_run": dry_run,
            "wrote": False,
            "client_id": normalized,
            "doctor_status": "skipped",
            "config_ref": bounded_path_ref(location.config_path),
            "next_step": "No client config file found; nothing to disconnect.",
            **_disconnect_matrix_fields(
                adapter=adapter,
                will_write=False,
                client_config_mutation=False,
                config_entry_present=False,
            ),
            "summary": {
                "client_id": normalized,
                "connected": False,
                "privacy_bounded": True,
            },
            "privacy_bounded": True,
        }
        assert_proxy_cli_json_is_privacy_safe(payload)
        return payload

    current_entry = _current_server_entry(adapter, location.config_path, server_name=server_name)
    had_entry = current_entry is not None

    if dry_run:
        payload = {
            "ok": True,
            "mode": "auto_connect",
            "connected": False,
            "config_entry_present": had_entry,
            "dry_run": True,
            "wrote": False,
            "client_id": normalized,
            "doctor_status": "skipped",
            "config_ref": bounded_path_ref(location.config_path),
            "next_step": "Re-run with --write to remove the AgentVeil MCP server entry.",
            **_disconnect_matrix_fields(
                adapter=adapter,
                will_write=False,
                client_config_mutation=False,
                config_entry_present=had_entry,
            ),
            "summary": {
                "client_id": normalized,
                "would_remove_entry": had_entry,
                "config_entry_present": had_entry,
                "connected": False,
                "route_launch_proved": False,
                "privacy_bounded": True,
            },
            "privacy_bounded": True,
        }
        assert_proxy_cli_json_is_privacy_safe(payload)
        return payload

    backup = create_config_backup(location.config_path)
    updated_text = _remove_client_config_entry(
        adapter,
        location.config_path,
        server_name=server_name,
    )
    _write_client_config_text(location.config_path, updated_text)
    payload = {
        "ok": True,
        "mode": "auto_connect",
        "connected": False,
        "dry_run": False,
        "wrote": True,
        "client_id": normalized,
        "doctor_status": "skipped",
        "removed_entry": had_entry,
        "config_ref": bounded_path_ref(location.config_path),
        "backup_ref": backup,
        "next_step": "AgentVeil MCP server entry removed when present.",
        **_disconnect_matrix_fields(
            adapter=adapter,
            will_write=True,
            client_config_mutation=True,
            config_entry_present=False,
        ),
        "summary": {
            "client_id": normalized,
            "connected": False,
            "removed_entry": had_entry,
            "privacy_bounded": True,
        },
        "privacy_bounded": True,
    }
    assert_proxy_cli_json_is_privacy_safe(payload)
    return payload


def build_disconnect_all_payload(
    *,
    home: Path,
    config_path: Path | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
    project_root: Path | None = None,
    write: bool = False,
) -> dict[str, Any]:
    """Return a per-client disconnect matrix."""

    rows: list[dict[str, Any]] = []
    for client_id in CLIENT_PACK_IDS:
        client_payload = build_disconnect_payload(
            client_id=client_id,
            home=home,
            config_path=config_path,
            server_name=server_name,
            project_root=project_root,
            write=write,
        )
        rows.append(_connect_matrix_row(client_payload))

    removed_count = sum(1 for row in rows if row.get("removed_entry"))
    wrote_count = sum(1 for row in rows if row["wrote"])

    payload = {
        "ok": not any(row.get("ok") is False for row in rows),
        "mode": "matrix",
        "target": ALL_CLIENTS_TARGET,
        "dry_run": not write,
        "any_connected": False,
        "client_config_mutation": wrote_count > 0,
        "clients": rows,
        "summary": {
            "client_count": len(rows),
            "removed_count": removed_count,
            "wrote_count": wrote_count,
            "connected_count": 0,
            "privacy_bounded": True,
        },
        "privacy_bounded": True,
    }
    assert_proxy_cli_json_is_privacy_safe(payload)
    return payload


def build_connect_status_payload(
    *,
    client_id: str,
    home: Path,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
    project_root: Path | None = None,
) -> dict[str, Any]:
    from agentveil_mcp_proxy.cli import load_proxy_config, proxy_paths

    normalized = normalize_connect_client_id(client_id)
    adapter = get_connect_adapter(normalized)
    paths = proxy_paths(home, config_path)
    location = adapter.resolve_config_location(project_root=(project_root or Path.cwd()).resolve())
    resolved_command = resolve_proxy_command(proxy_command)
    command_available = generated_command_is_available(resolved_command)

    if location.support_level != "auto_write":
        config_via = _manual_config_via(normalized)
        payload = {
            "ok": True,
            "client_id": normalized,
            "connected": False,
            "config_entry_present": False,
            "command_available": command_available,
            "mode": "manual_fallback",
            "support_status": adapter.support_level,
            "config_ref": bounded_path_ref(location.config_path),
            "doctor_status": "skipped",
            "next_step": _manual_fallback_status_next_step(normalized),
            "config_via": config_via,
            **_native_connect_contract_fields(client_config_mutation=False),
            "summary": {
                "client_id": normalized,
                "connected": False,
                "route_launch_proved": False,
                "config_entry_present": False,
                "doctor_status": "skipped",
                "support_status": adapter.support_level,
                "privacy_bounded": True,
            },
            "privacy_bounded": True,
        }
        assert_proxy_cli_json_is_privacy_safe(payload)
        return payload

    effective_passphrase_file = passphrase_file
    if effective_passphrase_file is None:
        try:
            config = load_proxy_config(paths.config_path)
        except Exception:
            config = None
        if config is not None:
            from agentveil_mcp_proxy.cli import _stored_passphrase_file

            effective_passphrase_file = _stored_passphrase_file(config)

    launch_spec = build_generated_launch_spec(
        command=resolved_command,
        home=paths.home,
        config_path=paths.config_path,
        passphrase_file=effective_passphrase_file,
    )

    config_entry_present = False
    if location.support_level == "auto_write" and location.config_path.exists():
        config_entry_present = _config_entry_matches_launch_spec(
            adapter,
            location.config_path,
            server_name=server_name,
            launch_spec=launch_spec,
        )

    # `connected` means the client path can actually launch AgentVeil, not just
    # that a matching config entry is present. Prove it via the doctor probe.
    doctor_report: dict[str, Any] | None = None
    doctor_status: DoctorStatus = "skipped"
    if config_entry_present and command_available:
        doctor_report, doctor_status = _run_client_doctor(
            client_id=normalized,
            home=paths.home,
            config_path=paths.config_path,
            passphrase_file=effective_passphrase_file,
            proxy_command=resolved_command,
        )

    connected = config_entry_present and doctor_status == "ok"
    route_launch_proved = connected
    if not config_entry_present:
        next_step = (
            f"AgentVeil MCP entry not found; run `agentveil-mcp-proxy connect {normalized} --write`."
        )
    elif not command_available:
        next_step = "Install agentveil-mcp-proxy on PATH or pass --proxy-command, then re-check status."
    elif doctor_status == "ok":
        next_step = "AgentVeil client path launches and routes; no action needed."
    else:
        next_step = (
            "Config entry is present but the launch probe did not pass. "
            f"Run `agentveil-mcp-proxy client-doctor --client {normalized}` for diagnostics."
        )

    payload = {
        "ok": True,
        "client_id": normalized,
        "connected": connected,
        "route_launch_proved": route_launch_proved,
        "config_entry_present": config_entry_present,
        "command_available": command_available,
        "mode": "auto_connect" if location.support_level == "auto_write" else "manual_fallback",
        "support_status": adapter.support_level,
        "config_ref": bounded_path_ref(location.config_path),
        "doctor_status": doctor_status,
        "next_step": next_step,
        **_native_connect_contract_fields(client_config_mutation=False, route_launch_proved=route_launch_proved),
        "summary": {
            "client_id": normalized,
            "connected": connected,
            "route_launch_proved": route_launch_proved,
            "config_entry_present": config_entry_present,
            "doctor_status": doctor_status,
            "support_status": adapter.support_level,
            "privacy_bounded": True,
        },
        "privacy_bounded": True,
    }
    if config_entry_present and location.support_level == "auto_write":
        payload["rollback_command"] = _rollback_command(normalized)
    doctor_summary = _doctor_summary(doctor_report)
    if doctor_summary is not None:
        payload["doctor_summary"] = doctor_summary
    assert_proxy_cli_json_is_privacy_safe(payload)
    return payload


def build_connect_all_payload(
    *,
    home: Path,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
    project_root: Path | None = None,
    write: bool = False,
) -> dict[str, Any]:
    """Return a per-client connect matrix."""

    rows: list[dict[str, Any]] = []
    for client_id in CLIENT_PACK_IDS:
        client_payload = build_connect_payload(
            client_id=client_id,
            home=home,
            config_path=config_path,
            passphrase_file=passphrase_file,
            proxy_command=proxy_command,
            server_name=server_name,
            project_root=project_root,
            write=write,
        )
        rows.append(_connect_matrix_row(client_payload))

    connected_count = sum(1 for row in rows if row["connected"])
    wrote_count = sum(1 for row in rows if row["wrote"])
    auto_write_count = sum(1 for row in rows if row["support_status"] == "auto_write")
    manual_fallback_count = sum(1 for row in rows if row["support_status"] == "manual_fallback")

    ok = True
    if write:
        for row in rows:
            if row["support_status"] == "auto_write" and row["doctor_status"] == "failed":
                ok = False

    payload = {
        "ok": ok,
        "mode": "matrix",
        "target": ALL_CLIENTS_TARGET,
        "dry_run": not write,
        "any_connected": connected_count > 0,
        "client_config_mutation": wrote_count > 0,
        "clients": rows,
        "summary": {
            "client_count": len(rows),
            "connected_count": connected_count,
            "wrote_count": wrote_count,
            "auto_write_count": auto_write_count,
            "manual_fallback_count": manual_fallback_count,
            "privacy_bounded": True,
        },
        "privacy_bounded": True,
    }
    assert_proxy_cli_json_is_privacy_safe(payload)
    return payload


def build_connect_status_all_payload(
    *,
    home: Path,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    server_name: str = DEFAULT_SERVER_NAME,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Return a per-client connect status matrix."""

    rows: list[dict[str, Any]] = []
    for client_id in CLIENT_PACK_IDS:
        client_payload = build_connect_status_payload(
            client_id=client_id,
            home=home,
            config_path=config_path,
            passphrase_file=passphrase_file,
            proxy_command=proxy_command,
            server_name=server_name,
            project_root=project_root,
        )
        rows.append(_connect_matrix_row(client_payload))

    connected_count = sum(1 for row in rows if row["connected"])
    payload = {
        "ok": True,
        "mode": "matrix",
        "target": ALL_CLIENTS_TARGET,
        "any_connected": connected_count > 0,
        "clients": rows,
        "summary": {
            "client_count": len(rows),
            "connected_count": connected_count,
            "privacy_bounded": True,
        },
        "privacy_bounded": True,
    }
    assert_proxy_cli_json_is_privacy_safe(payload)
    return payload


def format_connect_payload(payload: Mapping[str, Any]) -> str:
    if payload.get("mode") == "matrix":
        return format_connect_matrix_payload(payload)
    lines = [
        f"Client connect — {payload.get('client_id', 'client')}",
        f"Mode: {payload.get('mode', 'unknown')}",
        f"Connected: {payload.get('connected', False)}",
        f"Route launch proved: {payload.get('route_launch_proved', False)}",
        f"Client config mutation: {payload.get('client_config_mutation', False)}",
        f"Dry run: {payload.get('dry_run', True)}",
        f"Doctor status: {payload.get('doctor_status', 'skipped')}",
        f"Next step: {payload.get('next_step', '')}",
    ]
    if payload.get("manual_fallback_reason"):
        lines.append(f"Manual fallback: {payload['manual_fallback_reason']}")
    for error in payload.get("errors", ()):
        lines.append(f"ERROR: {error}")
    text = "\n".join(lines) + "\n"
    assert_proxy_cli_output_is_privacy_safe(text)
    return text


def format_connect_matrix_payload(payload: Mapping[str, Any]) -> str:
    lines = ["Client connect matrix"]
    for row in payload.get("clients", ()):
        lines.append(
            f"- {row.get('client_id')}: support={row.get('support_status')} "
            f"connected={row.get('connected')} wrote={row.get('wrote')} "
            f"doctor={row.get('doctor_status')}"
        )
        lines.append(f"  next: {row.get('next_step', '')}")
    summary = payload.get("summary", {})
    lines.append(
        f"Summary: any_connected={payload.get('any_connected', False)} "
        f"connected={summary.get('connected_count', 0)}/"
        f"{summary.get('client_count', 0)}"
    )
    text = "\n".join(lines) + "\n"
    assert_proxy_cli_output_is_privacy_safe(text)
    return text


__all__ = [
    "CONNECT_ADAPTERS",
    "ClientConfigLocation",
    "ClientConnectAdapter",
    "ClientConnectError",
    "ALL_CLIENTS_TARGET",
    "ConnectSupportLevel",
    "build_connect_all_payload",
    "build_connect_payload",
    "build_connect_status_all_payload",
    "build_connect_status_payload",
    "build_disconnect_all_payload",
    "build_disconnect_payload",
    "cleanup_legacy_cursor_settings_agentveil_entry",
    "create_config_backup",
    "format_connect_matrix_payload",
    "format_connect_payload",
    "get_connect_adapter",
    "is_connect_all_target",
    "merge_agentveil_server_entry",
    "merge_cursor_settings_server_entry",
    "normalize_connect_target",
    "remove_agentveil_server_entry",
    "remove_cursor_settings_server_entry",
    "resolve_client_config_location",
    "resolve_cursor_global_mcp_json_path",
    "resolve_cursor_user_data_dir",
]
