"""TrapDoor T6: package-manager mutation commands require approval before execution."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import shlex
from typing import Any

PACKAGE_MANAGER_ACTION_REQUIRES_APPROVAL = "package_manager_action_requires_approval"

_PACKAGE_MANAGERS = frozenset({
    "bun",
    "cargo",
    "composer",
    "gem",
    "go",
    "npm",
    "pip",
    "pip3",
    "pnpm",
    "poetry",
    "uv",
    "yarn",
})
_MUTATION_VERBS = frozenset({
    "add",
    "ci",
    "get",
    "install",
    "remove",
    "require",
    "sync",
    "uninstall",
    "update",
    "upgrade",
})
_COMMAND_ARG_KEYS = (
    "command",
    "cmd",
    "script",
    "shell_command",
    "executable_and_args",
)
_COMMAND_TOOL_LEAVES = frozenset({
    "bash",
    "command",
    "execute",
    "run",
    "run_command",
    "run_terminal_cmd",
    "shell",
    "terminal",
})
_COMMAND_TOOL_PREFIXES = ("run", "execute", "shell", "command", "terminal", "bash")


def is_command_execution_tool(tool: str) -> bool:
    """Return True when the tool leaf can run a shell-style command."""

    leaf = tool.rsplit(".", 1)[-1].lower()
    if leaf in _COMMAND_TOOL_LEAVES:
        return True
    return any(
        leaf == prefix or leaf.startswith(f"{prefix}_")
        for prefix in _COMMAND_TOOL_PREFIXES
    )


def iter_command_strings(arguments: Mapping[str, Any]) -> Iterable[str]:
    """Yield command strings from common MCP tool argument shapes."""

    for key in _COMMAND_ARG_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            yield value.strip()
    for key in ("args", "argv"):
        value = arguments.get(key)
        if isinstance(value, list) and value:
            yield " ".join(str(item) for item in value)


def package_manager_action_reason_from_command(command: str) -> str | None:
    """Return a trapdoor reason when ``command`` looks like a package-manager mutation."""

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    if not tokens:
        return PACKAGE_MANAGER_ACTION_REQUIRES_APPROVAL
    lowered = [token.lower() for token in tokens]
    for index, token in enumerate(lowered):
        if token in _PACKAGE_MANAGERS:
            if any(part in _MUTATION_VERBS for part in lowered[index + 1 :]):
                return PACKAGE_MANAGER_ACTION_REQUIRES_APPROVAL
        if token == "pip" and index >= 2 and lowered[index - 1] == "-m":
            if index + 1 < len(lowered) and lowered[index + 1] in _MUTATION_VERBS:
                return PACKAGE_MANAGER_ACTION_REQUIRES_APPROVAL
        if token == "poetry" and index >= 2 and lowered[index - 1] == "-m":
            if index + 1 < len(lowered) and lowered[index + 1] in _MUTATION_VERBS:
                return PACKAGE_MANAGER_ACTION_REQUIRES_APPROVAL
    return None


def package_manager_action_reason_from_tool(tool: str) -> str | None:
    """Return a trapdoor reason when the tool name itself encodes a mutation."""

    leaf = tool.rsplit(".", 1)[-1].lower()
    parts = [segment for segment in leaf.replace("-", "_").split("_") if segment]
    if not parts:
        return None
    if parts[0] not in _PACKAGE_MANAGERS:
        return None
    if any(part in _MUTATION_VERBS for part in parts[1:]):
        return PACKAGE_MANAGER_ACTION_REQUIRES_APPROVAL
    return None


def package_manager_action_reason(
    tool: str,
    arguments: Mapping[str, Any],
) -> str | None:
    """Return a trapdoor reason for package-manager install/update style commands."""

    reason = package_manager_action_reason_from_tool(tool)
    if reason is not None:
        return reason
    if not is_command_execution_tool(tool):
        return None
    commands = list(iter_command_strings(arguments))
    if not commands:
        return PACKAGE_MANAGER_ACTION_REQUIRES_APPROVAL
    for command in commands:
        reason = package_manager_action_reason_from_command(command)
        if reason is not None:
            return reason
    return None
