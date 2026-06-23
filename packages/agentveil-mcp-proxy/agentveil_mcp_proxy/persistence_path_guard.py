"""TrapDoor T4: persistence/backdoor filesystem paths require approval before write."""

from __future__ import annotations

import hashlib
import posixpath
from pathlib import Path

HASH_PREFIX = "sha256:"
PERSISTENCE_PATH_WRITE_REQUIRES_APPROVAL = "persistence_path_write_requires_approval"
INSTRUCTION_SURFACE_RISK_MESSAGE = (
    "Repo instruction files detected; risky changes need approval."
)
INSTRUCTION_SURFACE_RULE_ID = "instruction_surface_detected"
_WRITE_PATH_TOOL_LEAVES = frozenset({
    "write_file",
    "edit_file",
    "move_file",
    "copy_file",
    "chmod_file",
    "create_symlink",
})
_INSTRUCTION_SURFACE_BASENAMES = frozenset({
    "agents.md",
    "claude.md",
    ".cursorrules",
})
_COPILOT_INSTRUCTIONS_PATH = (".github", "copilot-instructions.md")
_SHELL_RC_BASENAMES = frozenset({
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zprofile",
    ".zshrc",
})
_LAUNCHD_SEGMENTS = frozenset({"launchagents", "launchdaemons"})


def is_filesystem_mutation_tool(tool: str) -> bool:
    """Return True when the tool leaf can mutate filesystem paths."""

    leaf = tool.rsplit(".", 1)[-1]
    return leaf in _WRITE_PATH_TOOL_LEAVES


def persistence_path_write_reason(path: str) -> str | None:
    """Return a trapdoor reason when ``path`` targets a persistence/backdoor location."""

    normalized = path.replace("\\", "/")
    resolved = posixpath.normpath(normalized)
    segments = [
        segment for segment in resolved.split("/") if segment and segment != "."
    ]
    lowered = [segment.lower() for segment in segments]
    if not lowered:
        return None
    basename = lowered[-1]
    if basename == "authorized_keys":
        return PERSISTENCE_PATH_WRITE_REQUIRES_APPROVAL
    if basename in _SHELL_RC_BASENAMES:
        return PERSISTENCE_PATH_WRITE_REQUIRES_APPROVAL
    if _matches_git_hooks_path(lowered):
        return PERSISTENCE_PATH_WRITE_REQUIRES_APPROVAL
    if _matches_cron_path(lowered):
        return PERSISTENCE_PATH_WRITE_REQUIRES_APPROVAL
    if _matches_systemd_path(lowered):
        return PERSISTENCE_PATH_WRITE_REQUIRES_APPROVAL
    if _matches_launchd_path(lowered):
        return PERSISTENCE_PATH_WRITE_REQUIRES_APPROVAL
    return None


def _matches_git_hooks_path(lowered: list[str]) -> bool:
    for index, segment in enumerate(lowered):
        if (
            segment == ".git"
            and index + 1 < len(lowered)
            and lowered[index + 1] == "hooks"
        ):
            return True
    return False


def _matches_cron_path(lowered: list[str]) -> bool:
    if lowered[-1] == "crontab":
        return True
    if "cron.d" in lowered:
        return True
    for index, segment in enumerate(lowered):
        if segment != "cron" or index == 0:
            continue
        if lowered[index - 1] in {"etc", "spool", ".config"}:
            return True
    return False


def _matches_systemd_path(lowered: list[str]) -> bool:
    for index, segment in enumerate(lowered):
        if segment != "systemd" or index == 0:
            continue
        if lowered[index - 1] in {".config", "etc"}:
            return True
    return False


def _matches_launchd_path(lowered: list[str]) -> bool:
    if not lowered[-1].endswith(".plist"):
        return False
    return any(segment in _LAUNCHD_SEGMENTS for segment in lowered)


def instruction_surface_type_for_path(path: str) -> str | None:
    """Return a bounded instruction-surface type label for ``path``, if any."""

    normalized = path.replace("\\", "/")
    resolved = posixpath.normpath(normalized)
    segments = [
        segment for segment in resolved.split("/") if segment and segment != "."
    ]
    lowered = [segment.lower() for segment in segments]
    if not lowered:
        return None
    basename = lowered[-1]
    if basename in _INSTRUCTION_SURFACE_BASENAMES:
        return basename.replace(".", "_")
    if len(lowered) >= 2 and tuple(lowered[-2:]) == _COPILOT_INSTRUCTIONS_PATH:
        return "github_copilot_instructions"
    for index, segment in enumerate(lowered):
        if (
            segment == ".cursor"
            and index + 1 < len(lowered)
            and lowered[index + 1] == "rules"
        ):
            return "cursor_rules"
    return None


def _size_bucket(byte_count: int) -> str:
    if byte_count <= 4096:
        return "small"
    if byte_count <= 65536:
        return "medium"
    return "large"


def scan_instruction_surfaces(root: Path) -> list[dict[str, str]]:
    """Scan ``root`` for instruction files using metadata only (no content reads)."""

    if not root.is_dir():
        return []
    surfaces: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in sorted(root.rglob("*")):
        if not item.is_file():
            continue
        relative = item.relative_to(root).as_posix()
        surface_type = instruction_surface_type_for_path(relative)
        if surface_type is None:
            continue
        stat = item.stat()
        basename = item.name
        ref = HASH_PREFIX + hashlib.sha256(
            f"{surface_type}:{basename}:{stat.st_size}".encode("utf-8")
        ).hexdigest()
        key = (surface_type, basename)
        if key in seen:
            continue
        seen.add(key)
        surfaces.append({
            "surface_type": surface_type,
            "basename": basename,
            "size_bucket": _size_bucket(stat.st_size),
            "ref": ref,
            "rule_id": INSTRUCTION_SURFACE_RULE_ID,
        })
    return surfaces


def summarize_instruction_surface_risk(surfaces: list[dict[str, str]]) -> dict[str, object]:
    """Return bounded instruction-surface status for user-visible summaries."""

    detected = bool(surfaces)
    return {
        "instruction_surfaces_detected": detected,
        "instruction_surface_count": len(surfaces),
        "instruction_surface_risk_message": (
            INSTRUCTION_SURFACE_RISK_MESSAGE if detected else None
        ),
        "instruction_surfaces": list(surfaces),
    }
