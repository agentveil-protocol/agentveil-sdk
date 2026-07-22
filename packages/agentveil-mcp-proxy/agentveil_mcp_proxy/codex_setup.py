"""Project-local Codex connector setup helpers.

This module does not implement a new control path. It wraps the existing Codex
client-config/connect TOML support with the same project-local proxy home and
Approval Center lifecycle used by the public connector setup commands.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Mapping

from agentveil_mcp_proxy.client_config import DEFAULT_SERVER_NAME
from agentveil_mcp_proxy.client_connect import (
    build_connect_status_payload,
    build_disconnect_payload,
)
from agentveil_mcp_proxy.client_connect import resolve_client_config_location


CODEX_CONNECTOR_ID = "codex"
AGENTVEIL_CODEX_HOOK_MARKER = "agentveil_mcp_proxy.codex_hook"
HOOK_MATCHER = "Bash|apply_patch|Edit|Write|mcp__.*"
MATCHED_TOOL_CLASSES = ("Bash", "apply_patch", "Edit", "Write", "mcp__*")
CODEX_HOOK_TRUST_MESSAGE = (
    "Codex requires one-time review/trust for project-local hooks. "
    "Open Codex in this folder, trust the AgentVeil hook if prompted, then retry."
)


class CodexSetupError(RuntimeError):
    """Raised when Codex setup cannot safely merge project-local config."""


def setup_home(project_dir: Path) -> Path:
    """Project-local proxy home for the Codex connector."""

    return Path(project_dir).resolve() / ".avp"


def proxy_config_path(home: Path) -> Path:
    return Path(home) / "mcp-proxy" / "config.json"


def codex_config_path(project_dir: Path | None = None) -> Path:
    """Return the Codex user config path for the current HOME."""

    root = Path(project_dir).resolve() if project_dir is not None else Path.cwd()
    return resolve_client_config_location(CODEX_CONNECTOR_ID, project_root=root).config_path


def project_codex_dir(project_dir: Path) -> Path:
    return Path(project_dir).resolve() / ".codex"


def hooks_path(project_dir: Path) -> Path:
    return project_codex_dir(project_dir) / "hooks.json"


def evidence_path(project_dir: Path) -> Path:
    return project_codex_dir(project_dir) / "agentveil" / "evidence.jsonl"


def build_hook_command(*, python: str, home: Path, evidence: Path) -> str:
    return (
        f"{shlex.quote(python)} -m {AGENTVEIL_CODEX_HOOK_MARKER} "
        f"--home {shlex.quote(str(home))} "
        f"--evidence-path {shlex.quote(str(evidence))}"
    )


def build_managed_hook_entry(*, python: str, home: Path, evidence: Path) -> dict[str, Any]:
    return {
        "matcher": HOOK_MATCHER,
        "hooks": [
            {
                "type": "command",
                "command": build_hook_command(python=python, home=home, evidence=evidence),
                "statusMessage": "AgentVeil checking Codex tool use",
            }
        ],
    }


def _load_hooks_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CodexSetupError(f"cannot read {path}: {exc}") from exc
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CodexSetupError(f"existing {path} is not valid JSON; refusing to overwrite ({exc})") from exc
    if not isinstance(payload, dict):
        raise CodexSetupError(f"existing {path} must be a JSON object")
    return payload


def _write_hooks_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def command_invokes_managed_hook(command: str) -> bool:
    """Return true only for the exact installed module command.

    Avoid substring ownership checks: user hooks may mention
    ``agentveil_mcp_proxy.codex_hook`` in comments/arguments. The managed hook
    is identified by a shell-parsed ``-m agentveil_mcp_proxy.codex_hook`` pair.
    """

    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    return any(
        part == "-m" and index + 1 < len(parts) and parts[index + 1] == AGENTVEIL_CODEX_HOOK_MARKER
        for index, part in enumerate(parts)
    )


def _hook_is_agentveil(hook: Any) -> bool:
    return isinstance(hook, dict) and command_invokes_managed_hook(str(hook.get("command", "")))


def _strip_managed_from_group(group: Any) -> tuple[Any, int]:
    if not isinstance(group, dict):
        return group, 0
    hooks = group.get("hooks")
    if not isinstance(hooks, list):
        return group, 0
    kept = [hook for hook in hooks if not _hook_is_agentveil(hook)]
    removed = len(hooks) - len(kept)
    if removed == 0:
        return group, 0
    if not kept:
        return None, removed
    updated = dict(group)
    updated["hooks"] = kept
    return updated, removed


def _strip_managed_groups(groups: Any) -> tuple[list[Any], int]:
    if groups is None:
        return [], 0
    if not isinstance(groups, list):
        raise CodexSetupError(".codex/hooks.json hooks.PreToolUse must be a list")
    cleaned: list[Any] = []
    removed = 0
    for group in groups:
        updated, count = _strip_managed_from_group(group)
        removed += count
        if updated is not None:
            cleaned.append(updated)
    return cleaned, removed


def install_hook(*, project_dir: Path, python: str) -> dict[str, Any]:
    target = Path(project_dir).resolve()
    path = hooks_path(target)
    payload = _load_hooks_json(path)
    hooks = payload.get("hooks")
    if hooks is None:
        hooks = {}
    if not isinstance(hooks, dict):
        raise CodexSetupError(".codex/hooks.json hooks must be an object")
    existing_pre = hooks.get("PreToolUse")
    cleaned, removed = _strip_managed_groups(existing_pre)
    cleaned.append(build_managed_hook_entry(
        python=python,
        home=setup_home(target),
        evidence=evidence_path(target),
    ))
    updated_hooks = dict(hooks)
    updated_hooks["PreToolUse"] = cleaned
    updated_payload = dict(payload)
    updated_payload["hooks"] = updated_hooks
    _write_hooks_json(path, updated_payload)
    return {
        "hooks_path": path,
        "evidence_path": evidence_path(target),
        "replaced_existing_managed": removed > 0,
        "reload_required": True,
    }


def validate_hook_config(*, project_dir: Path) -> None:
    """Validate existing hook config before setup writes MCP route state."""

    target = Path(project_dir).resolve()
    payload = _load_hooks_json(hooks_path(target))
    hooks = payload.get("hooks")
    if hooks is None:
        return
    if not isinstance(hooks, dict):
        raise CodexSetupError(".codex/hooks.json hooks must be an object")
    if "PreToolUse" in hooks:
        _strip_managed_groups(hooks.get("PreToolUse"))


def remove_hook(*, project_dir: Path) -> dict[str, Any]:
    target = Path(project_dir).resolve()
    path = hooks_path(target)
    if not path.exists():
        return {"hooks_path": path, "removed_entries": 0, "reload_required": False}
    payload = _load_hooks_json(path)
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return {"hooks_path": path, "removed_entries": 0, "reload_required": False}
    cleaned, removed = _strip_managed_groups(hooks.get("PreToolUse"))
    updated_hooks = dict(hooks)
    if cleaned:
        updated_hooks["PreToolUse"] = cleaned
    else:
        updated_hooks.pop("PreToolUse", None)
    updated_payload = dict(payload)
    if updated_hooks:
        updated_payload["hooks"] = updated_hooks
    else:
        updated_payload.pop("hooks", None)
    if updated_payload:
        _write_hooks_json(path, updated_payload)
    else:
        path.unlink()
    return {"hooks_path": path, "removed_entries": removed, "reload_required": removed > 0}


def hook_status(*, project_dir: Path) -> dict[str, Any]:
    target = Path(project_dir).resolve()
    path = hooks_path(target)
    evidence = evidence_path(target)
    if not path.exists():
        return {
            "state": "missing",
            "present": False,
            "evidence_observed": False,
            "reload_required": True,
            "matched_tool_classes": list(MATCHED_TOOL_CLASSES),
        }
    try:
        payload = _load_hooks_json(path)
    except CodexSetupError:
        return {
            "state": "invalid-json",
            "present": False,
            "evidence_observed": False,
            "reload_required": True,
            "matched_tool_classes": list(MATCHED_TOOL_CLASSES),
        }
    groups = payload.get("hooks", {}).get("PreToolUse", []) if isinstance(payload.get("hooks"), dict) else []
    present = False
    points_to_module = False
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            for hook in group.get("hooks", []) or []:
                if _hook_is_agentveil(hook):
                    present = True
                if command_invokes_managed_hook(str(hook.get("command", ""))):
                    points_to_module = True
    evidence_observed = False
    if present and evidence.exists() and evidence.stat().st_size > 0:
        try:
            evidence_observed = evidence.stat().st_mtime > path.stat().st_mtime
        except OSError:
            evidence_observed = False
    if not present:
        state = "missing"
    elif not points_to_module:
        state = "stale"
    elif evidence_observed:
        state = "protected"
    else:
        state = "advisory"
    return {
        "state": state,
        "present": present,
        "points_to_module": points_to_module,
        "evidence_observed": evidence_observed,
        "reload_required": state != "protected",
        "matched_tool_classes": list(MATCHED_TOOL_CLASSES),
    }


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
    hook = hook_status(project_dir=target)

    if (
        proxy_route_present
        and route_present
        and center_state == "running"
        and hook.get("state") == "protected"
    ):
        status = "protected"
        next_step = "Codex hook evidence observed; native tools are contained and routed MCP calls use AgentVeil."
    elif proxy_route_present and route_present and center_state == "running" and hook.get("present"):
        status = "advisory"
        next_step = (
            "Open or restart Codex in this project, trust the AgentVeil hook if prompted, "
            "then retry once so hook evidence can mark this connector protected."
        )
    elif proxy_route_present or route_present:
        status = "advisory"
        next_step = "Finish setup or restart the managed Approval Center before relying on the Codex connector."
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
        "hook": "present" if hook.get("present") else "missing",
        "hook_state": hook.get("state"),
        "hook_evidence_observed": bool(hook.get("evidence_observed")),
        "hook_trust_required": bool(hook.get("present")) and hook.get("state") != "protected",
        "hook_trust_message": CODEX_HOOK_TRUST_MESSAGE,
        "matched_tool_classes": hook.get("matched_tool_classes", []),
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
    "CODEX_HOOK_TRUST_MESSAGE",
    "CodexSetupError",
    "AGENTVEIL_CODEX_HOOK_MARKER",
    "codex_config_path",
    "command_invokes_managed_hook",
    "connect_status",
    "connector_status",
    "disconnect",
    "evidence_path",
    "hook_status",
    "hooks_path",
    "install_hook",
    "managed_route_present",
    "remove_hook",
    "proxy_config_path",
    "setup_home",
    "validate_hook_config",
]
