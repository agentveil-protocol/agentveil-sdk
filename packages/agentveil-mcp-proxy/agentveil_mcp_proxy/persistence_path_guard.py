"""TrapDoor T4: persistence/backdoor filesystem paths require approval before write."""

from __future__ import annotations

import posixpath

PERSISTENCE_PATH_WRITE_REQUIRES_APPROVAL = "persistence_path_write_requires_approval"
_WRITE_PATH_TOOL_LEAVES = frozenset({"write_file", "edit_file", "move_file"})
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
