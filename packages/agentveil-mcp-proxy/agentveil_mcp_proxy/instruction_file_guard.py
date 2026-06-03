"""TrapDoor T2/T3 guards for agent instruction-file writes."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import posixpath

_INSTRUCTION_BASENAMES = frozenset({
    "claude.md",
    "agents.md",
    ".cursorrules",
})
_COPILOT_INSTRUCTIONS_PATH = (".github", "copilot-instructions.md")
INSTRUCTION_FILE_WRITE_REQUIRES_APPROVAL = "instruction_file_write_requires_approval"
HIDDEN_UNICODE_INSTRUCTION_FILE_BLOCKED = "hidden_unicode_instruction_file_blocked"
_WRITE_PATH_TOOL_LEAVES = frozenset({"write_file", "edit_file", "move_file"})
_PATH_ARG_KEYS = ("path", "paths", "source", "destination")
_CONTENT_ARG_KEYS = frozenset({
    "content",
    "old_string",
    "new_string",
    "oldText",
    "newText",
    "text",
})
_HIDDEN_UNICODE_CODEPOINTS = frozenset({
    0x200B,
    0x200C,
    0x200D,
    0x2060,
    0xFEFF,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
})


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
        return INSTRUCTION_FILE_WRITE_REQUIRES_APPROVAL
    if len(lowered) >= 2 and tuple(lowered[-2:]) == _COPILOT_INSTRUCTIONS_PATH:
        return INSTRUCTION_FILE_WRITE_REQUIRES_APPROVAL
    for index, segment in enumerate(lowered):
        if (
            segment == ".cursor"
            and index + 1 < len(lowered)
            and lowered[index + 1] == "rules"
        ):
            return INSTRUCTION_FILE_WRITE_REQUIRES_APPROVAL
    return None


def contains_hidden_unicode(text: str) -> bool:
    """Return True when ``text`` includes a zero-width or bidi control character."""

    return any(ord(character) in _HIDDEN_UNICODE_CODEPOINTS for character in text)


def iter_tool_content_strings(arguments: Mapping[str, object]) -> Iterable[str]:
    """Yield string payload fields from write/edit tool arguments."""

    for key, value in arguments.items():
        if key in _CONTENT_ARG_KEYS and isinstance(value, str):
            yield value
        elif key == "edits" and isinstance(value, list):
            for item in value:
                if not isinstance(item, Mapping):
                    continue
                for content_key in _CONTENT_ARG_KEYS:
                    nested = item.get(content_key)
                    if isinstance(nested, str):
                        yield nested


def hidden_unicode_instruction_file_block_reason(
    tool: str,
    arguments: Mapping[str, object],
) -> str | None:
    """Return a hard-deny reason when guarded instruction content carries hidden Unicode."""

    if not is_instruction_file_write_tool(tool):
        return None
    if not any(
        instruction_file_write_reason(candidate) is not None
        for candidate in _candidate_file_paths(arguments)
    ):
        return None
    if not any(contains_hidden_unicode(text) for text in iter_tool_content_strings(arguments)):
        return None
    return HIDDEN_UNICODE_INSTRUCTION_FILE_BLOCKED


def _candidate_file_paths(arguments: Mapping[str, object]) -> list[str]:
    candidates: list[str] = []
    for key in _PATH_ARG_KEYS:
        value = arguments.get(key)
        if key == "paths" and isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    candidates.append(item)
        elif isinstance(value, str):
            candidates.append(value)
    return candidates
