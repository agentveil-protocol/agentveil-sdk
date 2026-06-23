"""Project-local Cursor hook setup, status, and removal for configured workspaces."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
from typing import Any, Mapping

from agentveil_mcp_proxy.client_connect import (
    resolve_cursor_global_mcp_json_path,
    resolve_cursor_user_data_dir,
)
from agentveil_mcp_proxy.config_wizard import assert_setup_output_is_privacy_safe

CURSOR_SETUP_MANIFEST_VERSION = 2
CURSOR_SETUP_MANIFEST_NAME = ".agentveil-cursor-hooks.json"
HOOKS_DIR_NAME = "hooks"
HOOKS_JSON_NAME = "hooks.json"
HOOK_SHIM_NAME = "agentveil-cursor-hook.sh"
EVIDENCE_FILE_NAME = "agentveil-hook-evidence.jsonl"
AGENTVEIL_HOOK_ID = "agentveil-cursor-hook-v1"
AGENTVEIL_HOOK_EVENTS = ("preToolUse", "beforeShellExecution", "beforeMCPExecution")
RELOAD_MESSAGE = (
    "Reload or restart Cursor (Developer -> Reload Window) so hook changes take effect."
)


class CursorSetupError(RuntimeError):
    """Raised when Cursor hook setup inputs or state are invalid."""


@dataclass(frozen=True)
class CursorSetupPaths:
    workspace: Path
    cursor_dir: Path
    hooks_json: Path
    hooks_dir: Path
    hook_shim: Path
    manifest_path: Path
    evidence_path: Path


@dataclass(frozen=True)
class CursorSetupResult:
    ok: bool
    action: str
    workspace_ref: dict[str, str | None]
    managed_files: tuple[str, ...]
    reload_required: bool
    message: str
    hook_cli_resolved: bool = False
    hook_cli_ref: dict[str, str | None] | None = None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class CursorSetupStatus:
    installed: bool
    stale: bool
    workspace_ref: dict[str, str | None]
    hook_state: str
    boundary: str
    managed_files: tuple[str, ...]
    reload_required: bool
    message: str
    hook_cli_resolved: bool = False
    hook_cli_ref: dict[str, str | None] | None = None


@dataclass(frozen=True)
class CursorRemoveResult:
    ok: bool
    removed_files: tuple[str, ...]
    reload_required: bool
    message: str
    errors: tuple[str, ...] = ()


def resolve_workspace_root(workspace: Path | None = None) -> Path:
    root = (workspace or Path.cwd()).expanduser().resolve()
    if not root.is_dir():
        raise CursorSetupError("workspace must be an existing directory")
    return root


def cursor_setup_paths(workspace: Path | None = None) -> CursorSetupPaths:
    root = resolve_workspace_root(workspace)
    cursor_dir = root / ".cursor"
    hooks_dir = cursor_dir / HOOKS_DIR_NAME
    return CursorSetupPaths(
        workspace=root,
        cursor_dir=cursor_dir,
        hooks_json=cursor_dir / HOOKS_JSON_NAME,
        hooks_dir=hooks_dir,
        hook_shim=hooks_dir / HOOK_SHIM_NAME,
        manifest_path=cursor_dir / CURSOR_SETUP_MANIFEST_NAME,
        evidence_path=cursor_dir / EVIDENCE_FILE_NAME,
    )


def global_cursor_config_paths() -> tuple[Path, Path]:
    return (
        resolve_cursor_global_mcp_json_path(),
        resolve_cursor_user_data_dir() / "User" / "settings.json",
    )


def _workspace_ref(workspace: Path) -> dict[str, str | None]:
    from agentveil_mcp_proxy.client_config import bounded_path_ref

    return bounded_path_ref(workspace)


def _shim_relative_path() -> str:
    return f".cursor/{HOOKS_DIR_NAME}/{HOOK_SHIM_NAME}"


def _managed_file_paths() -> tuple[str, ...]:
    return (
        f".cursor/{HOOKS_DIR_NAME}/{HOOK_SHIM_NAME}",
        f".cursor/{CURSOR_SETUP_MANIFEST_NAME}",
    )


def build_hook_shim_script(*, cli_path: Path) -> str:
    quoted = shlex.quote(str(cli_path))
    return f"""#!/usr/bin/env bash
set -euo pipefail
exec {quoted} hook cursor
"""


def resolve_setup_cli_path(
    *,
    setup_cli_path: Path | str | None = None,
    setup_argv0: str | None = None,
) -> Path:
    """Resolve the executable used to embed into the Cursor hook shim."""

    if setup_cli_path is not None:
        candidate = Path(setup_cli_path).expanduser().resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        raise CursorSetupError("setup CLI path is not an executable file")

    if setup_argv0:
        candidate = Path(setup_argv0).expanduser()
        if candidate.is_file():
            resolved = candidate.resolve()
            if os.access(resolved, os.X_OK):
                return resolved

    which_path = shutil.which("agentveil-mcp-proxy")
    if which_path:
        resolved = Path(which_path).expanduser().resolve()
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved

    raise CursorSetupError(
        "Could not resolve agentveil-mcp-proxy for Cursor hook setup. "
        "Install the package or rerun setup from the intended console script."
    )


def _hook_cli_ref(cli_path: Path) -> dict[str, str | None]:
    from agentveil_mcp_proxy.client_config import bounded_path_ref

    return bounded_path_ref(cli_path)


def read_shim_cli_path(shim_path: Path) -> Path | None:
    if not shim_path.is_file():
        return None
    for line in shim_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("exec "):
            parts = shlex.split(stripped)
            if len(parts) >= 2:
                return Path(parts[1]).expanduser()
    return None


def shim_cli_is_resolved(*, shim_path: Path, hook_cli_ref: Mapping[str, Any] | None = None) -> bool:
    cli_path = read_shim_cli_path(shim_path)
    if cli_path is None or not cli_path.is_file() or not os.access(cli_path, os.X_OK):
        return False
    if hook_cli_ref is None:
        return True
    return _hook_cli_ref(cli_path) == dict(hook_cli_ref)


def build_agentveil_hook_entries(*, shim_relative_path: str) -> dict[str, list[dict[str, Any]]]:
    return {
        "preToolUse": [
            {
                "command": shim_relative_path,
                "matcher": "Shell|Write|Delete|StrReplace|ApplyPatch|Edit",
                "failClosed": True,
                "agentveilHookId": AGENTVEIL_HOOK_ID,
            }
        ],
        "beforeShellExecution": [
            {
                "command": shim_relative_path,
                "failClosed": True,
                "agentveilHookId": AGENTVEIL_HOOK_ID,
            }
        ],
        "beforeMCPExecution": [
            {
                "command": shim_relative_path,
                "failClosed": True,
                "agentveilHookId": AGENTVEIL_HOOK_ID,
            }
        ],
    }


def build_hooks_document(*, shim_relative_path: str) -> dict[str, Any]:
    entries = build_agentveil_hook_entries(shim_relative_path=shim_relative_path)
    return {
        "version": 1,
        "hooks": entries,
    }


def build_setup_manifest(
    *,
    managed_files: tuple[str, ...],
    hooks_json_origin: str,
    hook_cli_ref: dict[str, str | None],
) -> dict[str, Any]:
    return {
        "version": CURSOR_SETUP_MANIFEST_VERSION,
        "agentveil_hook_id": AGENTVEIL_HOOK_ID,
        "hooks_json_origin": hooks_json_origin,
        "managed_events": list(AGENTVEIL_HOOK_EVENTS),
        "managed_files": list(managed_files),
        "evidence_file": f".cursor/{EVIDENCE_FILE_NAME}",
        "hook_cli_ref": dict(hook_cli_ref),
    }


def _load_manifest(paths: CursorSetupPaths) -> dict[str, Any] | None:
    if not paths.manifest_path.is_file():
        return None
    try:
        payload = json.loads(paths.manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CursorSetupError("Cursor hook manifest is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise CursorSetupError("Cursor hook manifest must be a JSON object")
    return payload


def _manifest_hooks_json_origin(manifest: Mapping[str, Any]) -> str:
    origin = manifest.get("hooks_json_origin")
    if origin in {"created", "merged"}:
        return str(origin)
    return "created"


def _manifest_hook_id(manifest: Mapping[str, Any]) -> str:
    hook_id = manifest.get("agentveil_hook_id")
    return str(hook_id) if isinstance(hook_id, str) and hook_id else AGENTVEIL_HOOK_ID


def _load_hooks_document(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"version": 1, "hooks": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CursorSetupError("Cursor hooks.json is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise CursorSetupError("Cursor hooks.json must be a JSON object")
    hooks = payload.get("hooks")
    if hooks is None:
        payload = {**payload, "hooks": {}}
    elif not isinstance(hooks, dict):
        raise CursorSetupError("Cursor hooks.json hooks field must be an object")
    if "version" not in payload:
        payload = {**payload, "version": 1}
    return payload


def _is_agentveil_hook_entry(entry: Any, *, hook_id: str, shim_relative_path: str) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry.get("agentveilHookId") == hook_id:
        return True
    return entry.get("command") == shim_relative_path


def _count_agentveil_entries(
    document: Mapping[str, Any],
    *,
    hook_id: str,
    shim_relative_path: str,
) -> int:
    hooks = document.get("hooks") or {}
    count = 0
    if not isinstance(hooks, dict):
        return 0
    for event in AGENTVEIL_HOOK_EVENTS:
        entries = hooks.get(event) or []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if _is_agentveil_hook_entry(entry, hook_id=hook_id, shim_relative_path=shim_relative_path):
                count += 1
    return count


def merge_agentveil_hooks(
    document: Mapping[str, Any],
    *,
    shim_relative_path: str,
) -> tuple[dict[str, Any], bool]:
    merged: dict[str, Any] = dict(document)
    existing_hooks = document.get("hooks") or {}
    if not isinstance(existing_hooks, dict):
        raise CursorSetupError("Cursor hooks.json hooks field must be an object")

    agentveil_entries = build_agentveil_hook_entries(shim_relative_path=shim_relative_path)
    changed = False
    merged_hooks: dict[str, list[Any]] = {}

    for event, existing_entries in existing_hooks.items():
        if isinstance(existing_entries, list):
            merged_hooks[event] = list(existing_entries)

    for event, new_entries in agentveil_entries.items():
        current = list(merged_hooks.get(event) or [])
        for entry in new_entries:
            if any(
                _is_agentveil_hook_entry(item, hook_id=AGENTVEIL_HOOK_ID, shim_relative_path=shim_relative_path)
                for item in current
            ):
                continue
            current.append(dict(entry))
            changed = True
        merged_hooks[event] = current

    merged["hooks"] = merged_hooks
    return merged, changed


def unmerge_agentveil_hooks(
    document: Mapping[str, Any],
    *,
    hook_id: str,
    shim_relative_path: str,
) -> tuple[dict[str, Any], bool]:
    existing_hooks = document.get("hooks") or {}
    if not isinstance(existing_hooks, dict):
        return dict(document), False

    changed = False
    merged_hooks: dict[str, list[Any]] = {}
    for event, entries in existing_hooks.items():
        if not isinstance(entries, list):
            merged_hooks[event] = entries
            continue
        kept = [
            entry
            for entry in entries
            if not _is_agentveil_hook_entry(entry, hook_id=hook_id, shim_relative_path=shim_relative_path)
        ]
        if len(kept) != len(entries):
            changed = True
        if kept:
            merged_hooks[event] = kept

    merged = dict(document)
    merged["hooks"] = merged_hooks
    return merged, changed


def hooks_document_is_empty(document: Mapping[str, Any]) -> bool:
    hooks = document.get("hooks") or {}
    if not isinstance(hooks, dict) or not hooks:
        return True
    for entries in hooks.values():
        if isinstance(entries, list) and entries:
            return False
    return True


def _ensure_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    _write_text_atomic(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def setup_cursor_hooks(
    *,
    workspace: Path | None = None,
    yes: bool = False,
    setup_cli_path: Path | str | None = None,
    setup_argv0: str | None = None,
) -> CursorSetupResult:
    paths = cursor_setup_paths(workspace)
    managed = _managed_file_paths()
    if not yes:
        return CursorSetupResult(
            ok=False,
            action="setup_cursor",
            workspace_ref=_workspace_ref(paths.workspace),
            managed_files=managed,
            reload_required=True,
            message="Pass --yes to install project-local Cursor hooks.",
            errors=("confirmation_required",),
        )

    try:
        resolved_cli = resolve_setup_cli_path(
            setup_cli_path=setup_cli_path,
            setup_argv0=setup_argv0,
        )
    except CursorSetupError as exc:
        return CursorSetupResult(
            ok=False,
            action="setup_cursor",
            workspace_ref=_workspace_ref(paths.workspace),
            managed_files=managed,
            reload_required=True,
            message=str(exc),
            hook_cli_resolved=False,
            errors=("hook_cli_unresolved",),
        )

    cli_ref = _hook_cli_ref(resolved_cli)
    shim_relative = _shim_relative_path()
    hooks_existed = paths.hooks_json.is_file()
    existing_document = _load_hooks_document(paths.hooks_json)
    merged_document, hooks_changed = merge_agentveil_hooks(
        existing_document,
        shim_relative_path=shim_relative,
    )

    paths.hooks_dir.mkdir(parents=True, exist_ok=True)
    _write_text_atomic(paths.hook_shim, build_hook_shim_script(cli_path=resolved_cli))
    _ensure_executable(paths.hook_shim)

    if hooks_changed or not paths.hooks_json.is_file():
        _write_json_atomic(paths.hooks_json, merged_document)

    origin = "merged" if hooks_existed else "created"
    _write_json_atomic(
        paths.manifest_path,
        build_setup_manifest(
            managed_files=managed,
            hooks_json_origin=origin,
            hook_cli_ref=cli_ref,
        ),
    )

    if hooks_existed and not hooks_changed:
        message = f"AgentVeil Cursor hooks already present in existing hooks.json. {RELOAD_MESSAGE}"
    elif hooks_existed:
        message = f"Merged AgentVeil Cursor hooks into existing hooks.json. {RELOAD_MESSAGE}"
    else:
        message = f"Installed project-local Cursor hooks. {RELOAD_MESSAGE}"

    return CursorSetupResult(
        ok=True,
        action="setup_cursor",
        workspace_ref=_workspace_ref(paths.workspace),
        managed_files=managed,
        reload_required=True,
        message=message,
        hook_cli_resolved=True,
        hook_cli_ref=cli_ref,
    )


def derive_cursor_setup_status(*, workspace: Path | None = None) -> CursorSetupStatus:
    paths = cursor_setup_paths(workspace)
    manifest = _load_manifest(paths)
    managed = _managed_file_paths()
    boundary = (
        "Project-local Cursor hooks only. Does not configure host-wide Cursor control "
        "or actions outside this workspace."
    )

    if manifest is None:
        return CursorSetupStatus(
            installed=False,
            stale=False,
            workspace_ref=_workspace_ref(paths.workspace),
            hook_state="not_installed",
            boundary=boundary,
            managed_files=(),
            reload_required=False,
            message="Cursor hooks are not installed for this workspace.",
            hook_cli_resolved=False,
        )

    shim_relative = _shim_relative_path()
    hook_id = _manifest_hook_id(manifest)
    manifest_cli_ref = manifest.get("hook_cli_ref")
    hook_cli_ref = dict(manifest_cli_ref) if isinstance(manifest_cli_ref, dict) else None
    missing_files = [rel for rel in managed if not (paths.workspace / rel).is_file()]
    if missing_files:
        return CursorSetupStatus(
            installed=False,
            stale=True,
            workspace_ref=_workspace_ref(paths.workspace),
            hook_state="stale",
            boundary=boundary,
            managed_files=tuple(rel for rel in managed if (paths.workspace / rel).is_file()),
            reload_required=True,
            message=(
                "Cursor hook setup is stale or incomplete. "
                f"Re-run setup cursor --yes or remove and reinstall. {RELOAD_MESSAGE}"
            ),
            hook_cli_resolved=False,
            hook_cli_ref=hook_cli_ref,
        )

    if not paths.hooks_json.is_file():
        return CursorSetupStatus(
            installed=False,
            stale=True,
            workspace_ref=_workspace_ref(paths.workspace),
            hook_state="stale",
            boundary=boundary,
            managed_files=managed,
            reload_required=True,
            message=f"Cursor hooks.json is missing. {RELOAD_MESSAGE}",
            hook_cli_resolved=False,
            hook_cli_ref=hook_cli_ref,
        )

    document = _load_hooks_document(paths.hooks_json)
    installed_count = _count_agentveil_entries(
        document,
        hook_id=hook_id,
        shim_relative_path=shim_relative,
    )
    hook_cli_resolved = shim_cli_is_resolved(
        shim_path=paths.hook_shim,
        hook_cli_ref=hook_cli_ref,
    )
    if installed_count < len(AGENTVEIL_HOOK_EVENTS):
        return CursorSetupStatus(
            installed=False,
            stale=True,
            workspace_ref=_workspace_ref(paths.workspace),
            hook_state="stale",
            boundary=boundary,
            managed_files=managed,
            reload_required=True,
            message=f"AgentVeil hook entries are missing from hooks.json. {RELOAD_MESSAGE}",
            hook_cli_resolved=hook_cli_resolved,
            hook_cli_ref=hook_cli_ref,
        )

    if not hook_cli_resolved:
        return CursorSetupStatus(
            installed=False,
            stale=True,
            workspace_ref=_workspace_ref(paths.workspace),
            hook_state="stale",
            boundary=boundary,
            managed_files=managed,
            reload_required=True,
            message=(
                "AgentVeil hook CLI path is missing or changed. "
                f"Re-run setup cursor --yes. {RELOAD_MESSAGE}"
            ),
            hook_cli_resolved=False,
            hook_cli_ref=hook_cli_ref,
        )

    return CursorSetupStatus(
        installed=True,
        stale=False,
        workspace_ref=_workspace_ref(paths.workspace),
        hook_state="installed",
        boundary=boundary,
        managed_files=managed,
        reload_required=True,
        message=f"Cursor hooks are installed for this workspace. {RELOAD_MESSAGE}",
        hook_cli_resolved=True,
        hook_cli_ref=hook_cli_ref,
    )


def remove_cursor_hooks(*, workspace: Path | None = None, yes: bool = False) -> CursorRemoveResult:
    paths = cursor_setup_paths(workspace)
    if not yes:
        return CursorRemoveResult(
            ok=False,
            removed_files=(),
            reload_required=True,
            message="Pass --yes to remove project-local Cursor hooks.",
            errors=("confirmation_required",),
        )

    manifest = _load_manifest(paths)
    if manifest is None:
        return CursorRemoveResult(
            ok=True,
            removed_files=(),
            reload_required=True,
            message=f"No AgentVeil Cursor hook setup found. {RELOAD_MESSAGE}",
        )

    removed: list[str] = []
    shim_relative = _shim_relative_path()
    hook_id = _manifest_hook_id(manifest)
    origin = _manifest_hooks_json_origin(manifest)

    if paths.hooks_json.is_file():
        document = _load_hooks_document(paths.hooks_json)
        updated, changed = unmerge_agentveil_hooks(
            document,
            hook_id=hook_id,
            shim_relative_path=shim_relative,
        )
        if changed:
            if origin == "created" and hooks_document_is_empty(updated):
                paths.hooks_json.unlink()
                removed.append(str(paths.hooks_json.relative_to(paths.workspace)))
            else:
                _write_json_atomic(paths.hooks_json, updated)

    if paths.hook_shim.is_file():
        rel = str(paths.hook_shim.relative_to(paths.workspace))
        paths.hook_shim.unlink()
        removed.append(rel)

    if paths.manifest_path.is_file():
        rel = str(paths.manifest_path.relative_to(paths.workspace))
        paths.manifest_path.unlink()
        removed.append(rel)

    if paths.hooks_dir.is_dir() and not any(paths.hooks_dir.iterdir()):
        paths.hooks_dir.rmdir()

    return CursorRemoveResult(
        ok=True,
        removed_files=tuple(removed),
        reload_required=True,
        message=(
            "Removed AgentVeil Cursor hook entries from this workspace. "
            f"{RELOAD_MESSAGE}"
        ),
    )


def cursor_setup_result_to_dict(result: CursorSetupResult) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": result.ok,
        "action": result.action,
        "workspace_ref": dict(result.workspace_ref),
        "managed_files": list(result.managed_files),
        "reload_required": result.reload_required,
        "message": result.message,
        "boundary": (
            "Project-local Cursor hooks only. Does not configure host-wide Cursor control."
        ),
        "hook_cli_resolved": result.hook_cli_resolved,
        "errors": list(result.errors),
    }
    if result.hook_cli_ref is not None:
        payload["hook_cli_ref"] = dict(result.hook_cli_ref)
    return payload


def cursor_setup_status_to_dict(status: CursorSetupStatus) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "installed": status.installed,
        "stale": status.stale,
        "workspace_ref": dict(status.workspace_ref),
        "hook_state": status.hook_state,
        "boundary": status.boundary,
        "managed_files": list(status.managed_files),
        "reload_required": status.reload_required,
        "message": status.message,
        "hook_cli_resolved": status.hook_cli_resolved,
    }
    if status.hook_cli_ref is not None:
        payload["hook_cli_ref"] = dict(status.hook_cli_ref)
    return payload


def cursor_remove_result_to_dict(result: CursorRemoveResult) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "removed_files": list(result.removed_files),
        "reload_required": result.reload_required,
        "message": result.message,
        "errors": list(result.errors),
    }


def assert_cursor_setup_output_is_privacy_safe(payload: Mapping[str, Any]) -> None:
    assert_setup_output_is_privacy_safe(payload)


__all__ = [
    "AGENTVEIL_HOOK_ID",
    "CURSOR_SETUP_MANIFEST_NAME",
    "CursorRemoveResult",
    "CursorSetupError",
    "CursorSetupPaths",
    "CursorSetupResult",
    "CursorSetupStatus",
    "RELOAD_MESSAGE",
    "assert_cursor_setup_output_is_privacy_safe",
    "build_agentveil_hook_entries",
    "build_hook_shim_script",
    "build_hooks_document",
    "build_setup_manifest",
    "cursor_remove_result_to_dict",
    "cursor_setup_paths",
    "cursor_setup_result_to_dict",
    "cursor_setup_status_to_dict",
    "derive_cursor_setup_status",
    "global_cursor_config_paths",
    "hooks_document_is_empty",
    "merge_agentveil_hooks",
    "read_shim_cli_path",
    "remove_cursor_hooks",
    "resolve_setup_cli_path",
    "resolve_workspace_root",
    "setup_cursor_hooks",
    "shim_cli_is_resolved",
    "unmerge_agentveil_hooks",
]
