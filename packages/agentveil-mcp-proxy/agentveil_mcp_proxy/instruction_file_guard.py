"""TrapDoor T2: detect filesystem writes targeting agent instruction files."""

from __future__ import annotations

import posixpath

_INSTRUCTION_BASENAMES = frozenset({
    "claude.md",
    "agents.md",
    ".cursorrules",
})
_COPILOT_INSTRUCTIONS_PATH = (".github", "copilot-instructions.md")
_INSTRUCTION_WRITE_REASON = "instruction_file_write_requires_approval"
_WRITE_PATH_TOOL_LEAVES = frozenset({"write_file", "edit_file", "move_file"})


def is_instruction_file_write_tool(tool: str) -> bool:
    """Return True when the tool leaf can mutate filesystem instruction targets."""

    leaf = tool.rsplit(".", 1)[-1]
    return leaf in _WRITE_PATH_TOOL_LEAVES


def instruction_file_write_reason(path: str) -> str | None:
    """Return a trapdoor reason when ``path`` targets a guarded instruction file."""

    normalized = path.replace("\\", "/")
    resolved = posixpath.normpath(normalized)
    segments = [
        segment for segment in resolved.split("/") if segment and segment != "."
    ]
    lowered = [segment.lower() for segment in segments]
    if not lowered:
        return None
    basename = lowered[-1]
    if basename in _INSTRUCTION_BASENAMES:
        return _INSTRUCTION_WRITE_REASON
    if len(lowered) >= 2 and tuple(lowered[-2:]) == _COPILOT_INSTRUCTIONS_PATH:
        return _INSTRUCTION_WRITE_REASON
    for index, segment in enumerate(lowered):
        if (
            segment == ".cursor"
            and index + 1 < len(lowered)
            and lowered[index + 1] == "rules"
        ):
            return _INSTRUCTION_WRITE_REASON
    return None
