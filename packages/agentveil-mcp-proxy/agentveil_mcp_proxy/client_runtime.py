"""Non-invasive runtime attach planning for MCP desktop clients."""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

from agentveil_mcp_proxy.client_config import (
    assert_proxy_cli_json_is_privacy_safe,
    assert_proxy_cli_output_is_privacy_safe,
    build_run_args,
    build_generic_mcp_route_fields,
    resolve_proxy_command,
)
from agentveil_mcp_proxy.client_packs import CLIENT_PACK_IDS

REASON_NON_INVASIVE_ATTACH_UNAVAILABLE = "non_invasive_attach_unavailable"
REASON_CODEX_AGENT_TOOL_CALL_UNVERIFIED = "codex_agent_tool_call_unverified"
REASON_CODEX_CLI_UNAVAILABLE = "codex_cli_unavailable"
REASON_CODEX_MCP_OVERRIDE_UNRECOGNIZED = "codex_mcp_override_unrecognized"
REASON_CODEX_PROMPT_REQUIRED = "codex_prompt_required"
CODEX_MCP_OVERRIDE_METHOD = "codex_mcp_config_override"


class ClientRuntimeError(ValueError):
    """Bounded client-runtime error without raw filesystem paths in messages."""


@dataclass(frozen=True)
class RuntimeAttachAdapter:
    """One runtime attach adapter for a primary MCP desktop client."""

    client_id: str
    display_name: str
    runtime_attach_supported: bool
    attach_method: str | None
    launch_command: str | None
    required_env: tuple[tuple[str, str], ...]
    limitations: tuple[str, ...]
    doctor_supported: bool
    unavailable_reason: str | None

    def adapter_payload(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "display_name": self.display_name,
            "runtime_attach_supported": self.runtime_attach_supported,
            "attach_method": self.attach_method,
            "launch_command": self.launch_command,
            "required_env": {key: value for key, value in self.required_env},
            "limitations": list(self.limitations),
            "doctor_supported": self.doctor_supported,
            "unavailable_reason": self.unavailable_reason,
        }


def _unsupported_primary_adapter(
    *,
    client_id: str,
    display_name: str,
    unavailable_reason: str,
    limitations: tuple[str, ...],
) -> RuntimeAttachAdapter:
    return RuntimeAttachAdapter(
        client_id=client_id,
        display_name=display_name,
        runtime_attach_supported=False,
        attach_method=None,
        launch_command=None,
        required_env=(),
        limitations=limitations,
        doctor_supported=True,
        unavailable_reason=unavailable_reason,
    )


RUNTIME_ATTACH_ADAPTERS: dict[str, RuntimeAttachAdapter] = {
    "cursor": _unsupported_primary_adapter(
        client_id="cursor",
        display_name="Cursor",
        unavailable_reason=(
            "Cursor does not expose a documented non-invasive CLI runtime attach path in this release."
        ),
        limitations=(
            "Use client-config print for a bounded activation snippet.",
            "Provider-native Cursor tools stay outside AgentVeil routing.",
        ),
    ),
    "claude_code": _unsupported_primary_adapter(
        client_id="claude_code",
        display_name="Claude Code",
        unavailable_reason=(
            "Claude Code runtime MCP attach requires client-specific flags or config mutation "
            "that is not proven non-invasive in this release."
        ),
        limitations=(
            "Use client-config print for a bounded activation snippet.",
            "Claude Code CLI must be installed separately.",
        ),
    ),
    "codex": _unsupported_primary_adapter(
        client_id="codex",
        display_name="Codex",
        unavailable_reason=(
            "Codex exposes per-run config overrides for MCP servers, but full agent tool-call "
            "routing through that path is not proven in this release."
        ),
        limitations=(
            "Codex MCP override recognition is checked without editing config files.",
            "Provider-native Codex action routing stays unclaimed until an agent tool-call proof passes.",
        ),
    ),
}


def normalize_runtime_client_id(client_id: str) -> tuple[str, bool]:
    """Return normalized client id and whether it is a known primary pack."""

    trimmed = str(client_id or "").strip()
    if not trimmed:
        raise ClientRuntimeError("client id required")
    return trimmed, trimmed in CLIENT_PACK_IDS


def get_runtime_attach_adapter(client_id: str) -> RuntimeAttachAdapter | None:
    """Return a primary runtime attach adapter when registered."""

    normalized, is_known = normalize_runtime_client_id(client_id)
    if not is_known:
        return None
    return RUNTIME_ATTACH_ADAPTERS[normalized]


def _generic_adapter(client_id: str) -> RuntimeAttachAdapter:
    return RuntimeAttachAdapter(
        client_id=client_id,
        display_name=client_id.replace("_", " ").title() or "Unknown client",
        runtime_attach_supported=False,
        attach_method=None,
        launch_command=None,
        required_env=(),
        limitations=(
            "No client-specific runtime attach adapter is registered for this id.",
            "Use the generic MCP route package below.",
        ),
        doctor_supported=False,
        unavailable_reason="No runtime attach adapter registered for this client id.",
    )


def _resolve_adapter(client_id: str) -> tuple[RuntimeAttachAdapter, bool]:
    normalized, is_known = normalize_runtime_client_id(client_id)
    adapter = get_runtime_attach_adapter(normalized)
    if adapter is not None:
        return adapter, True
    return _generic_adapter(normalized), False


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _toml_string_array(values: list[str]) -> str:
    return "[" + ",".join(_toml_string(item) for item in values) + "]"


def _codex_mcp_override_args(*, command: str, run_args: list[str]) -> list[str]:
    return [
        "-c",
        f"mcp_servers.agentveil.command={_toml_string(command)}",
        "-c",
        f"mcp_servers.agentveil.args={_toml_string_array(run_args)}",
    ]


def _codex_headless_run_args(run_args: list[str]) -> list[str]:
    """Return proxy run args with headless approval handling for Codex live proof."""

    if "--approval-ui-mode" in run_args:
        return list(run_args)
    return [*run_args, "--approval-ui-mode", "none"]


def _run_json_command(cmd: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 30) -> dict[str, Any]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if proc.returncode != 0:
        return {"ok": False, "exit_code": proc.returncode, "records": []}
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "exit_code": proc.returncode, "records": []}
    records = payload.get("events") or payload.get("records") or []
    return {
        "ok": bool(payload.get("ok", True)),
        "exit_code": proc.returncode,
        "records": records if isinstance(records, list) else [],
    }


def _bounded_label(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    if not trimmed:
        return None
    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
    if len(trimmed) <= 96 and all(char in safe_chars for char in trimmed):  # claim-check: allow "all" is Python quantifier use.
        return trimmed
    digest = hashlib.sha256(trimmed.encode("utf-8")).hexdigest()[:16]
    return f"ref:{digest}"


def _codex_jsonl_agentveil_tool_names(text: str) -> list[str]:
    tool_names: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = payload.get("item")
        if not isinstance(item, dict):
            continue
        if item.get("type") == "mcp_tool_call" and item.get("server") == "agentveil":
            tool_name = _bounded_label(item.get("tool"))
            if tool_name and tool_name not in tool_names:
                tool_names.append(tool_name)
    return tool_names


def _codex_jsonl_agentveil_tool_events(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = payload.get("item")
        if not isinstance(item, dict):
            continue
        item_type = _bounded_label(item.get("type"))
        if item.get("server") != "agentveil" and item.get("server_name") != "agentveil":
            continue
        if item_type not in {"mcp_tool_call", "mcp_tool_call_result"}:
            continue
        summary: dict[str, Any] = {"item_type": item_type}
        for key in ("tool", "name", "status", "decision", "error_code", "reason"):
            value = _bounded_label(item.get(key))
            if value:
                summary[key] = value
        for key in ("is_error", "success"):
            value = item.get(key)
            if isinstance(value, bool):
                summary[key] = value
        result = item.get("result")
        if isinstance(result, dict):
            for key in ("status", "decision", "error_code", "reason"):
                value = _bounded_label(result.get(key))
                if value:
                    summary[f"result_{key}"] = value
            for key in ("is_error", "success"):
                value = result.get(key)
                if isinstance(value, bool):
                    summary[f"result_{key}"] = value
        error = item.get("error")
        if isinstance(error, dict):
            for key in ("code", "status", "reason"):
                value = _bounded_label(error.get(key))
                if value:
                    summary[f"error_{key}"] = value
        if len(summary) > 1:
            events.append(summary)
    return events


def _record_target_reached(record: Mapping[str, Any]) -> bool | None:
    explicit = record.get("target_reached")
    if isinstance(explicit, bool):
        return explicit
    status = str(record.get("status") or record.get("decision") or "").lower()
    event_kind = str(record.get("event_kind") or record.get("kind") or "").lower()
    if status in {"blocked", "denied", "rejected"}:  # claim-check: allow "blocked" is a bounded status label.
        return False
    if event_kind in {"policy_deny", "approval_denied", "blocked"}:  # claim-check: allow "blocked" is a bounded event label.
        return False
    return None


def _bounded_evidence_summary(record: Mapping[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in ("tool", "tool_name", "status", "decision", "event_kind", "policy_rule", "reason"):
        value = _bounded_label(record.get(key))
        if value:
            summary[key] = value
    target_reached = _record_target_reached(record)
    if target_reached is not None:
        summary["target_reached"] = target_reached
    return summary


def _codex_tool_failure_seen(events: list[Mapping[str, Any]]) -> bool:
    for event in events:
        status = event.get("status")
        if status in {"failed", "blocked", "denied", "rejected"}:  # claim-check: allow "blocked" is a bounded status label.
            return True
        if event.get("is_error") is True or event.get("result_is_error") is True:
            return True
    return False


def _codex_live_launch(
    *,
    prompt: str,
    command: str,
    run_args: list[str],
    home: Path,
    cwd: Path,
) -> dict[str, Any]:
    """Run Codex through an ephemeral AgentVeil MCP override and summarize bounded proof."""

    codex = shutil.which("codex")
    if codex is None:
        return {
            "executed": False,
            "codex_exit": None,
            "routed_action_reached": False,
            "agentveil_tool_call_seen": False,
            "evidence_count_before": 0,
            "evidence_count_after": 0,
            "evidence_count_delta": 0,
            "target_reached_values": [],
            "launch_error_code": REASON_CODEX_CLI_UNAVAILABLE,
        }

    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    events_before = _run_json_command(
        [command, "events", "list", "--home", str(home), "--json"],
        cwd=cwd,
        env=env,
    )
    before_records = events_before["records"]
    headless_run_args = _codex_headless_run_args(run_args)
    with tempfile.TemporaryDirectory(prefix="avp-codex-live-") as temp_dir:
        last_message = Path(temp_dir) / "last-message.txt"
        try:
            proc = subprocess.run(
                [
                    codex,
                    "-a",
                    "never",  # claim-check: allow Codex CLI approval-policy literal, not a coverage claim.
                    "-s",
                    "read-only",
                    "--disable",
                    "plugins",
                    "exec",
                    "--ignore-user-config",
                    "--ignore-rules",
                    "--ephemeral",
                    "--skip-git-repo-check",
                    "--json",
                    "--output-last-message",
                    str(last_message),
                    "-C",
                    str(cwd),
                    *_codex_mcp_override_args(command=command, run_args=headless_run_args),
                    "-c",
                    'mcp_servers.agentveil.default_tools_approval_mode="approve"',
                    prompt,
                ],
                cwd=str(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                text=True,
                capture_output=True,
                check=False,
                timeout=240,
            )
        except subprocess.TimeoutExpired:
            return {
                "executed": False,
                "codex_exit": None,
                "routed_action_reached": False,
                "agentveil_tool_call_seen": False,
                "agentveil_tool_names": [],
                "codex_tool_events": [],
                "evidence_count_before": len(before_records),
                "evidence_count_after": len(before_records),
                "evidence_count_delta": 0,
                "target_reached_values": [],
                "blocked_or_denied_action_seen": False,
                "bounded_evidence": [],
                "launch_error_code": "codex_exec_timeout",
            }
    events_after = {"records": []}
    after_records: list[Any] = []
    for _attempt in range(8):
        events_after = _run_json_command(
            [command, "events", "list", "--home", str(home), "--json"],
            cwd=cwd,
            env=env,
        )
        after_records = events_after["records"]
        if len(after_records) > len(before_records):
            break
        time.sleep(0.25)
    delta = max(0, len(after_records) - len(before_records))
    new_records = after_records[len(before_records):] if delta else []
    new_record_mappings = [item for item in new_records if isinstance(item, dict)]
    target_reached_values = [
        value
        for item in new_record_mappings
        for value in [_record_target_reached(item)]
        if value is not None
    ]
    evidence_summaries = [
        summary
        for item in new_record_mappings
        for summary in [_bounded_evidence_summary(item)]
        if summary
    ]
    tool_names = _codex_jsonl_agentveil_tool_names(proc.stdout)
    codex_tool_events = _codex_jsonl_agentveil_tool_events(proc.stdout)
    evidence_tool_names = [
        value
        for item in new_record_mappings
        for value in [_bounded_label(item.get("tool") or item.get("tool_name"))]
        if value
    ]
    for value in evidence_tool_names:
        if value not in tool_names:
            tool_names.append(value)
    tool_call_seen = bool(tool_names)
    routed_action_reached = bool(delta and any(value is True for value in target_reached_values))
    blocked_or_denied_seen = any(value is False for value in target_reached_values) or _codex_tool_failure_seen(
        codex_tool_events
    )
    return {
        "executed": proc.returncode == 0,
        "codex_exit": proc.returncode,
        "routed_action_reached": routed_action_reached,
        "agentveil_tool_call_seen": tool_call_seen,
        "agentveil_tool_names": tool_names,
        "codex_tool_events": codex_tool_events,
        "evidence_count_before": len(before_records),
        "evidence_count_after": len(after_records),
        "evidence_count_delta": delta,
        "target_reached_values": target_reached_values,
        "blocked_or_denied_action_seen": blocked_or_denied_seen,
        "bounded_evidence": evidence_summaries,
        "launch_error_code": None if proc.returncode == 0 else "codex_exec_failed",
    }


def _codex_override_probe(*, command: str, run_args: list[str]) -> dict[str, Any]:
    """Check whether local Codex CLI recognizes a per-run MCP override."""

    codex = shutil.which("codex")
    if codex is None:
        return {
            "codex_cli_available": False,
            "codex_mcp_override_supported": False,
            "codex_mcp_override_status": "codex_cli_unavailable",
            "codex_mcp_override_source": "local_codex_cli",
        }

    with tempfile.TemporaryDirectory(prefix="avp-codex-runtime-") as temp_dir:
        env = os.environ.copy()
        env["CODEX_HOME"] = temp_dir
        proc = subprocess.run(
            [
                codex,
                "mcp",
                "list",
                "--json",
                *_codex_mcp_override_args(command=command, run_args=run_args),
            ],
            env=env,
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    recognized = False
    if proc.returncode == 0:
        try:
            entries = json.loads(proc.stdout)
        except json.JSONDecodeError:
            entries = []
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict) or entry.get("name") != "agentveil":
                continue
            transport = entry.get("transport")
            if not isinstance(transport, dict):
                continue
            recognized = (
                transport.get("type") == "stdio"
                and transport.get("command") == command
                and transport.get("args") == run_args
            )
            if recognized:
                break
    return {
        "codex_cli_available": True,
        "codex_mcp_override_supported": recognized,
        "codex_mcp_override_status": "recognized" if recognized else "not_recognized",
        "codex_mcp_override_source": "local_codex_cli",
        "codex_mcp_override_probe": "codex mcp list --json",
    }


def build_client_runtime_payload(
    *,
    client_id: str,
    home: Path,
    config_path: Path | None = None,
    passphrase_file: Path | None = None,
    proxy_command: str | None = None,
    launch: bool = False,
    prompt: str | None = None,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Build one bounded runtime attach or generic route payload."""

    adapter, is_known_pack = _resolve_adapter(client_id)
    route_fields = build_generic_mcp_route_fields(
        client_id=adapter.client_id,
        home=home,
        config_path=config_path,
        passphrase_file=passphrase_file,
        proxy_command=proxy_command,
        known_client=is_known_pack,
    )
    launch_command = resolve_proxy_command(proxy_command)
    run_args = build_run_args(
        home=home,
        config_path=config_path,
        passphrase_file=passphrase_file,
    )
    codex_probe: dict[str, Any] | None = None
    if adapter.client_id == "codex":
        codex_probe = _codex_override_probe(command=launch_command, run_args=run_args)

    executed = False
    launch_error: str | None = None
    codex_launch: dict[str, Any] | None = None
    if launch:
        if adapter.client_id == "codex":
            if not prompt or not prompt.strip():
                launch_error = "Codex runtime launch requires --prompt."
            elif codex_probe and codex_probe.get("codex_mcp_override_supported"):
                codex_launch = _codex_live_launch(
                    prompt=prompt.strip(),
                    command=launch_command,
                    run_args=run_args,
                    home=home,
                    cwd=cwd or Path.cwd(),
                )
                executed = bool(codex_launch.get("executed"))
            else:
                launch_error = "Codex runtime launch requires a recognized MCP override."
        elif not adapter.runtime_attach_supported:
            launch_error = "Runtime attach launch requested but attach is not supported for this client."
        elif not adapter.launch_command:
            launch_error = "Runtime attach launch requested but no launch command is configured."
        else:
            try:
                env = dict(adapter.required_env)
                completed = subprocess.run(
                    adapter.launch_command.split(),
                    env=env or None,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                executed = completed.returncode == 0
                if not executed:
                    launch_error = "Runtime attach launch command did not succeed."
            except (OSError, subprocess.SubprocessError):
                executed = False
                launch_error = "Runtime attach launch command failed."

    supported = adapter.runtime_attach_supported
    reason_code = None if supported else REASON_NON_INVASIVE_ATTACH_UNAVAILABLE
    next_step = (
        "Re-run with the shown launch command through AgentVeil when runtime attach is supported."
        if supported
        else "Use the generic MCP route package or choose a supported runtime attach client."
    )
    if codex_probe is not None:
        if codex_probe["codex_mcp_override_status"] == "codex_cli_unavailable":
            reason_code = REASON_CODEX_CLI_UNAVAILABLE
            next_step = "Install Codex CLI or use the generic MCP route package."
        elif codex_probe["codex_mcp_override_supported"]:
            reason_code = REASON_CODEX_AGENT_TOOL_CALL_UNVERIFIED
            next_step = (
                "Codex accepts a non-invasive MCP config override. Keep using the generic route "
                "until an agent tool-call proof verifies routed execution."
            )
        else:
            reason_code = REASON_CODEX_MCP_OVERRIDE_UNRECOGNIZED
            next_step = (
                "Codex CLI did not recognize the generated MCP override. Use the generic route "
                "package and keep runtime attach unsupported."
            )
    payload: dict[str, Any] = {
        "ok": supported and (not launch or executed),
        "client_id": adapter.client_id,
        "mode": "runtime_attach",
        "runtime_attach_supported": supported,
        "reason_code": reason_code,
        "generic_route_available": True,
        "provider_native_client_proof": False,
        "client_config_mutation": False,
        "runtime_attach_method": CODEX_MCP_OVERRIDE_METHOD if codex_probe is not None else adapter.attach_method,
        "dry_run": not launch,
        "executed": executed,
        "routed_action_reached": False,
        "agentveil_tool_call_seen": False,
        "agentveil_tool_names": [],
        "codex_tool_events": [],
        "evidence_count_delta": 0,
        "target_reached_values": [],
        "blocked_or_denied_action_seen": False,
        "bounded_evidence": [],
        "adapter": adapter.adapter_payload(),
        "next_step": next_step,
        "privacy_bounded": True,
        **route_fields,
    }
    if codex_probe is not None:
        payload.update(codex_probe)
    if codex_launch is not None:
        payload.update(codex_launch)
        payload["ok"] = bool(codex_launch.get("routed_action_reached"))
        payload["runtime_attach_supported"] = True
        payload["reason_code"] = None if payload["ok"] else "codex_routed_action_not_reached"
        payload["next_step"] = (
            "Codex routed one AgentVeil action successfully."
            if payload["ok"]
            else "Codex launched but did not reach an AgentVeil target action."
        )
    if launch_error is not None:
        payload["errors"] = [launch_error]
    if not supported and codex_launch is None:
        payload["ok"] = False
    assert_proxy_cli_json_is_privacy_safe(payload)
    return payload


def format_client_runtime_payload(payload: Mapping[str, Any]) -> str:
    """Render human-readable runtime attach output."""

    adapter = payload.get("adapter") or {}
    lines = [
        f"Client runtime attach — {payload.get('client_id', 'client')}",
        f"Runtime attach supported: {payload.get('runtime_attach_supported', False)}",
        f"Generic route available: {payload.get('generic_route_available', False)}",
        f"Client config mutation: {payload.get('client_config_mutation', False)}",
        f"Dry run: {payload.get('dry_run', True)}",
        f"Executed: {payload.get('executed', False)}",
        f"Route via: {payload.get('route_via', '')}",
        f"Route command: {payload.get('route_command', '')}",
        f"Next step: {payload.get('next_step', '')}",
    ]
    reason_code = payload.get("reason_code")
    if reason_code:
        lines.append(f"Reason code: {reason_code}")
    unavailable = adapter.get("unavailable_reason")
    if unavailable:
        lines.append(f"Unavailable: {unavailable}")
    for error in payload.get("errors", ()):
        lines.append(f"ERROR: {error}")
    text = "\n".join(lines) + "\n"
    assert_proxy_cli_output_is_privacy_safe(text)
    return text


__all__ = [
    "CODEX_MCP_OVERRIDE_METHOD",
    "REASON_CODEX_AGENT_TOOL_CALL_UNVERIFIED",
    "REASON_CODEX_CLI_UNAVAILABLE",
    "REASON_CODEX_MCP_OVERRIDE_UNRECOGNIZED",
    "REASON_NON_INVASIVE_ATTACH_UNAVAILABLE",
    "RUNTIME_ATTACH_ADAPTERS",
    "ClientRuntimeError",
    "RuntimeAttachAdapter",
    "build_client_runtime_payload",
    "format_client_runtime_payload",
    "get_runtime_attach_adapter",
    "normalize_runtime_client_id",
]
