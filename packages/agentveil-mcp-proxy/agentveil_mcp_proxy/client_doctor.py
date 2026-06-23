"""Optional client-pack health checks for generated MCP client config paths."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
import re
from typing import Any, Literal, Mapping

from agentveil_mcp_proxy.client_config import (
    ClientConfigError,
    DEFAULT_SERVER_NAME,
    build_generated_launch_spec,
    generated_command_is_available,
    parse_codex_mcp_server_entry,
    render_client_configs,
    resolve_proxy_command,
)
from agentveil_mcp_proxy.client_guidance import LIST_ONLY_NEXT_STEP
from agentveil_mcp_proxy.client_packs import ClientPackError, get_client_pack

DiagnosticStatus = Literal[
    "ok",
    "config_missing",
    "config_command_unavailable",
    "tools_list_only",
    "client_bypasses_agentveil",
    "downstream_unavailable",
    "routed_action_failed",
]

CLIENT_DOCTOR_INITIALIZE_ID = "avp-client-doctor-initialize"
CLIENT_DOCTOR_TOOLS_LIST_ID = "avp-client-doctor-tools-list"
CLIENT_DOCTOR_ROUTED_READ_ID = "avp-client-doctor-routed-read"
DEFAULT_ROUTED_READ_TOOL = "list_workspace"
GENERATED_CONFIG_PROBE_TIMEOUT_SECONDS = 120


class ClientDoctorError(ValueError):
    """Bounded client-doctor error without raw filesystem paths in messages."""


def assert_client_doctor_output_is_privacy_safe(payload: Mapping[str, Any]) -> None:
    """Reject client-doctor output that could leak secrets or absolute local paths."""

    from agentveil_mcp_proxy.client_config import assert_proxy_cli_json_is_privacy_safe

    assert_proxy_cli_json_is_privacy_safe(payload)


def _client_doctor_probe_input(*, include_routed_read: bool) -> str:
    initialize = {
        "jsonrpc": "2.0",
        "id": CLIENT_DOCTOR_INITIALIZE_ID,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "agentveil-client-doctor", "version": "0"},
        },
    }
    initialized = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    tools_list = {
        "jsonrpc": "2.0",
        "id": CLIENT_DOCTOR_TOOLS_LIST_ID,
        "method": "tools/list",
        "params": {},
    }
    messages = [initialize, initialized, tools_list]
    if include_routed_read:
        messages.append({
            "jsonrpc": "2.0",
            "id": CLIENT_DOCTOR_ROUTED_READ_ID,
            "method": "tools/call",
            "params": {"name": DEFAULT_ROUTED_READ_TOOL, "arguments": {}},
        })
    return "\n".join(json.dumps(item, separators=(",", ":")) for item in messages) + "\n"


def _parse_probe_responses(raw_output: str) -> dict[str, Mapping[str, Any]]:
    responses: dict[str, Mapping[str, Any]] = {}
    for line in raw_output.splitlines():
        if not line.strip():
            continue
        message = json.loads(line)
        if not isinstance(message, Mapping):
            continue
        request_id = message.get("id")
        if request_id is not None:
            responses[str(request_id)] = message
    return responses


def _tool_count_from_tools_list(response: Mapping[str, Any]) -> int:
    result = response.get("result")
    if not isinstance(result, Mapping):
        raise ClientDoctorError("tools/list response missing result")
    tools = result.get("tools", [])
    if not isinstance(tools, list):
        raise ClientDoctorError("tools/list result.tools must be a list")
    return len(tools)


def _path_basename(value: str) -> str:
    return re.split(r"[\\/]", str(value))[-1]


def _is_windows_batch_command(command: str) -> bool:
    return os.name == "nt" and Path(command).suffix.lower() in {".bat", ".cmd"}


def _entry_routes_through_proxy(entry: Mapping[str, Any], *, proxy_command: str) -> bool:
    command = entry.get("command")
    if not isinstance(command, str) or not command.strip():
        return False
    if _path_basename(command.strip()) != _path_basename(proxy_command):
        return False
    args = entry.get("args", [])
    return isinstance(args, list) and args and args[0] == "run"


def _config_routes_through_proxy(
    document: Mapping[str, Any],
    *,
    proxy_command: str,
) -> bool:
    servers = document.get("mcpServers")
    if not isinstance(servers, Mapping) or not servers:
        return False
    return any(
        isinstance(entry, Mapping) and _entry_routes_through_proxy(entry, proxy_command=proxy_command)
        for entry in servers.values()
    )


def _launch_spec_matches_rendered_config(
    launch_spec: Mapping[str, Any],
    document: Mapping[str, Any],
    *,
    config_surface: str,
) -> bool:
    command = launch_spec.get("command")
    args = launch_spec.get("args")
    env = launch_spec.get("env")
    if not isinstance(command, str) or not isinstance(args, list):
        return False
    if config_surface in {"codex_config_toml_manual", "codex_config_toml"}:
        manual = str(document.get("manual_config_toml", ""))
        entry = parse_codex_mcp_server_entry(manual, server_name=DEFAULT_SERVER_NAME)
        if entry is None:
            return False
        entry_env = entry.get("env", {})
        if entry_env is None:
            entry_env = {}
        return entry.get("command") == command and entry.get("args") == args and entry_env == env
    servers = document.get("mcpServers")
    if not isinstance(servers, Mapping) or not servers:
        return False
    for entry in servers.values():
        if not isinstance(entry, Mapping):
            continue
        if entry.get("command") != command:
            continue
        if entry.get("args") != args:
            continue
        entry_env = entry.get("env", {})
        if entry_env is None:
            entry_env = {}
        if not isinstance(entry_env, dict):
            return False
        if env != entry_env:
            continue
        return True
    return False


def _run_generated_config_probe(
    *,
    launch_spec: Mapping[str, Any],
    include_routed_read: bool,
) -> dict[str, Any]:
    command = launch_spec.get("command")
    args = launch_spec.get("args")
    env = launch_spec.get("env")
    if not isinstance(command, str) or not isinstance(args, list):
        raise ClientDoctorError("generated launch spec is invalid")
    if not args or args[0] != "run":
        raise ClientDoctorError("generated launch spec must invoke proxy run")
    # claim-check: allow all() validates argument type shape, not behavioral coverage.
    if not all(isinstance(item, str) for item in args):
        raise ClientDoctorError("generated launch args must be strings")

    proc_env = os.environ.copy()
    if isinstance(env, Mapping):
        for key, value in env.items():
            if isinstance(key, str) and isinstance(value, str):
                proc_env[key] = value

    try:
        command_line = [command, *args]
        run_args: list[str] | str = command_line
        use_shell = False
        if _is_windows_batch_command(command):
            run_args = subprocess.list2cmdline(command_line)
            use_shell = True
        completed = subprocess.run(
            run_args,
            input=_client_doctor_probe_input(include_routed_read=include_routed_read),
            capture_output=True,
            text=True,
            env=proc_env,
            shell=use_shell,
            timeout=GENERATED_CONFIG_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClientDoctorError("generated config command probe failed") from exc

    if completed.returncode != 0:
        raise ClientDoctorError("generated config command probe failed")

    responses = _parse_probe_responses(completed.stdout)
    tools_response = responses.get(CLIENT_DOCTOR_TOOLS_LIST_ID)
    if tools_response is None or "error" in tools_response:
        raise ClientDoctorError("tools/list unreachable through generated config command")
    tool_count = _tool_count_from_tools_list(tools_response)
    routed_ok = False
    if include_routed_read:
        routed_response = responses.get(CLIENT_DOCTOR_ROUTED_READ_ID)
        if routed_response is None or "error" in routed_response:
            raise ClientDoctorError("routed read action did not reach target")
        routed_ok = "result" in routed_response
        if not routed_ok:
            raise ClientDoctorError("routed read action did not reach target")
    return {
        "tool_count": tool_count,
        "routed_read_tool": DEFAULT_ROUTED_READ_TOOL if include_routed_read else None,
        "routed_read_reached_target": routed_ok if include_routed_read else None,
    }


def build_client_doctor_report(
    *,
    client_id: str,
    home: Path,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    list_only: bool = False,
) -> dict[str, Any]:
    """Build one bounded client-pack health report from generated config command proof."""

    from agentveil_mcp_proxy.cli import load_proxy_config, proxy_paths

    pack = get_client_pack(client_id)
    paths = proxy_paths(home, config_path)
    resolved_command = resolve_proxy_command(proxy_command)
    errors: list[str] = []
    checks: dict[str, Any] = {}
    diagnostic_status: DiagnosticStatus = "ok"
    proof_mode = "generated_config_proxy_path"
    next_step = "Paste the generated client config, then use AgentVeil MCP tools for protected actions."
    launch_spec: dict[str, Any] | None = None
    document: dict[str, Any] | None = None

    try:
        rendered = render_client_configs(
            clients=[client_id],
            command=resolved_command,
            home=home,
            config_path=paths.config_path,
            passphrase_file=passphrase_file,
        )
        document = rendered[client_id]
        launch_spec = build_generated_launch_spec(
            command=resolved_command,
            home=home,
            config_path=paths.config_path,
            passphrase_file=passphrase_file,
        )
        checks["config_generated"] = {"ok": True, "config_surface": pack.config_surface}
        if not _launch_spec_matches_rendered_config(
            launch_spec,
            document,
            config_surface=pack.config_surface,
        ):
            diagnostic_status = "config_missing"
            errors.append("generated launch spec does not match rendered client config")
            next_step = "Regenerate client-config print output, then rerun client-doctor."
        if pack.config_surface in {"codex_config_toml_manual", "codex_config_toml"}:
            manual = str(document.get("manual_config_toml", ""))
            routes = "command =" in manual and "run" in manual
            checks["client_routes_through_agentveil"] = {
                "ok": routes,
                "manual_merge_required": True,
            }
            if not routes:
                diagnostic_status = "client_bypasses_agentveil"
                errors.append("generated Codex manual config does not include proxy run command")
        else:
            routes = _config_routes_through_proxy(document, proxy_command=resolved_command)
            checks["client_routes_through_agentveil"] = {"ok": routes}
            if not routes:
                diagnostic_status = "client_bypasses_agentveil"
                errors.append("generated client config does not route through AgentVeil proxy")
                next_step = (
                    "Regenerate client config and ensure the MCP server command runs "
                    "agentveil-mcp-proxy with run args."
                )
    except (ClientConfigError, ClientPackError) as exc:
        checks["config_generated"] = {"ok": False}
        diagnostic_status = "config_missing"
        errors.append(str(exc))
        next_step = "Run init and client-config print before client-doctor."

    if launch_spec is not None:
        command_ok = generated_command_is_available(str(launch_spec["command"]))
        checks["generated_command_available"] = {"ok": command_ok}
        if not command_ok:
            diagnostic_status = "config_command_unavailable"
            errors.append("generated client config command is unavailable")
            next_step = (
                "Install agentveil-mcp-proxy on PATH or pass a valid --proxy-command path, "
                "then regenerate client-config print."
            )

    config: Any = None
    if paths.config_path.is_file():
        try:
            config = load_proxy_config(paths.config_path)
        except Exception as exc:  # noqa: BLE001 — bounded doctor aggregates setup failures
            errors.append(str(exc))
            if diagnostic_status == "ok":
                diagnostic_status = "downstream_unavailable"
    else:
        errors.append("proxy config missing")
        diagnostic_status = "config_missing"

    if config is not None and not config.downstream:
        checks["downstream_configured"] = {"ok": False}
        if diagnostic_status == "ok":
            diagnostic_status = "downstream_unavailable"
        errors.append("downstream is not configured")
        next_step = "Run init --quickstart-filesystem or configure downstream before client-doctor."
    elif config is not None:
        checks["downstream_configured"] = {"ok": True}

    if not errors and config is not None and launch_spec is not None:
        try:
            probe_result = _run_generated_config_probe(
                launch_spec=launch_spec,
                include_routed_read=not list_only,
            )
            checks["generated_command_probe"] = {"ok": True, "proof_mode": proof_mode}
            checks["tools_list_reachable"] = {
                "ok": True,
                "tool_count": probe_result["tool_count"],
            }
            if list_only:
                checks["routed_read_action"] = {"ok": False, "observed": False, "skipped": True}
                diagnostic_status = "tools_list_only"
                next_step = LIST_ONLY_NEXT_STEP
            else:
                checks["routed_read_action"] = {
                    "ok": True,
                    "tool": probe_result["routed_read_tool"],
                    "target_reached": probe_result["routed_read_reached_target"],
                }
                next_step = "Client path is ready; use AgentVeil MCP tools for protected actions."
        except ClientDoctorError as exc:
            checks["generated_command_probe"] = {"ok": False, "proof_mode": proof_mode}
            if list_only and "tools/list unreachable" not in str(exc):
                checks["tools_list_reachable"] = {"ok": True}
                checks["routed_read_action"] = {"ok": False, "observed": False}
                diagnostic_status = "tools_list_only"
                next_step = LIST_ONLY_NEXT_STEP
            elif "tools/list unreachable" in str(exc) or "generated config command probe failed" in str(exc):
                checks["tools_list_reachable"] = {"ok": False}
                if diagnostic_status == "ok":
                    diagnostic_status = "downstream_unavailable"
                errors.append(str(exc))
                next_step = "Fix downstream/proxy setup or generated command path, then rerun client-doctor."
            else:
                checks["routed_read_action"] = {"ok": False, "target_reached": False}
                diagnostic_status = "routed_action_failed"
                errors.append(str(exc))
                next_step = LIST_ONLY_NEXT_STEP

    ok = not errors and diagnostic_status in {"ok", "tools_list_only"}
    payload: dict[str, Any] = {
        "ok": ok,
        "client_id": pack.client_id,
        "display_name": pack.display_name,
        "support_status": pack.support_status,
        "proof_mode": proof_mode,
        "provider_native_client_proof": False,
        "diagnostic_status": diagnostic_status,
        "checks": checks,
        "errors": errors,
        "next_step": next_step,
        "privacy_bounded": True,
        "summary": {
            "client_id": pack.client_id,
            "support_status": pack.support_status,
            "diagnostic_status": diagnostic_status,
            "proof_mode": proof_mode,
            "privacy_bounded": True,
        },
    }
    assert_client_doctor_output_is_privacy_safe(payload)
    return payload


def format_client_doctor_report(payload: Mapping[str, Any]) -> str:
    """Render human-readable client-doctor output."""

    lines = [
        f"Client doctor — {payload.get('display_name', 'client')}",
        f"Proof mode: {payload.get('proof_mode', 'generated_config_proxy_path')} "
        "(executes generated command/args; not provider-native client proof)",
        f"Diagnostic status: {payload.get('diagnostic_status', 'unknown')}",
        f"Next step: {payload.get('next_step', '')}",
    ]
    checks = payload.get("checks", {})
    if isinstance(checks, Mapping):
        for name, result in checks.items():
            if isinstance(result, Mapping):
                status = "OK" if result.get("ok") else "FAIL"
                lines.append(f"{status}: {name}")
    for error in payload.get("errors", ()):
        lines.append(f"ERROR: {error}")
    return "\n".join(lines) + "\n"


__all__ = [
    "CLIENT_DOCTOR_INITIALIZE_ID",
    "CLIENT_DOCTOR_ROUTED_READ_ID",
    "CLIENT_DOCTOR_TOOLS_LIST_ID",
    "DEFAULT_ROUTED_READ_TOOL",
    "ClientDoctorError",
    "DiagnosticStatus",
    "assert_client_doctor_output_is_privacy_safe",
    "build_client_doctor_report",
    "format_client_doctor_report",
]
