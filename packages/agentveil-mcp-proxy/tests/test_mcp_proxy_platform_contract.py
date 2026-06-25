"""Platform contract for Cursor setup tests across Windows/macOS/Linux.

The current Cursor connector installs project-local hooks that invoke the
Python module directly. Older releases wrote platform-specific shim scripts;
the contract here intentionally verifies the current direct command shape
without reviving shim files.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from agentveil_mcp_proxy.cursor_setup import (
    AGENTVEIL_HOOK_EVENTS,
    AGENTVEIL_HOOK_MARKER,
    MATCHED_TOOL_CLASSES,
    build_hook_command,
    is_managed_hook_command,
)
from conftest import (
    PLATFORM_POSIX,
    PLATFORM_WINDOWS,
    installed_cli_filename,
    is_windows_runtime,
    runtime_platform_name,
    venv_scripts_dirname,
    write_runnable_proxy_command,
)


def test_runtime_platform_contract_matches_cursor_setup() -> None:
    assert AGENTVEIL_HOOK_MARKER == "agentveil_mcp_proxy.cursor_hooks"
    assert "Write" in MATCHED_TOOL_CLASSES
    assert "Shell" in MATCHED_TOOL_CLASSES
    assert "mcp__*" in MATCHED_TOOL_CLASSES


@pytest.mark.parametrize(
    ("platform_name", "shim_name", "cli_name", "scripts_dir"),
    [
        (PLATFORM_WINDOWS, ".cmd", "agentveil-mcp-proxy.exe", "Scripts"),
        (PLATFORM_POSIX, "", "agentveil-mcp-proxy", "bin"),
    ],
)
def test_declared_platform_contract(
    platform_name: str,
    shim_name: str,
    cli_name: str,
    scripts_dir: str,
) -> None:
    assert shim_name in {"", ".cmd"}
    assert installed_cli_filename(platform_name=platform_name) == cli_name
    assert venv_scripts_dirname(platform_name=platform_name) == scripts_dir


@pytest.mark.parametrize("hook_event", AGENTVEIL_HOOK_EVENTS)
def test_build_hook_command_uses_direct_python_module(tmp_path: Path, hook_event: str) -> None:
    workspace = tmp_path / "workspace with spaces"
    home = workspace / ".agentveil"
    evidence = workspace / ".cursor" / "agentveil" / "evidence.jsonl"
    python = tmp_path / "venv bin" / "python"

    command = build_hook_command(
        python=str(python),
        workspace=workspace,
        home=home,
        evidence_path=evidence,
        hook_event=hook_event,
    )

    parts = shlex.split(command)
    assert parts[:3] == [str(python), "-m", AGENTVEIL_HOOK_MARKER]
    assert parts[parts.index("--workspace") + 1] == str(workspace)
    assert parts[parts.index("--home") + 1] == str(home)
    assert parts[parts.index("--evidence-path") + 1] == str(evidence)
    assert parts[parts.index("--hook-event") + 1] == hook_event
    assert is_managed_hook_command(command)


def test_write_runnable_proxy_command_matches_platform_contract(tmp_path: Path) -> None:
    windows_cli = write_runnable_proxy_command(tmp_path / "win", platform_name=PLATFORM_WINDOWS)
    assert windows_cli.name == "agentveil-mcp-proxy.exe"
    assert windows_cli.suffix.lower() == ".exe"

    posix_cli = write_runnable_proxy_command(tmp_path / "posix", platform_name=PLATFORM_POSIX)
    assert posix_cli.name == "agentveil-mcp-proxy"
    assert posix_cli.suffix == ""
    if not is_windows_runtime():
        assert posix_cli.stat().st_mode & 0o111


def test_runtime_platform_name_is_supported() -> None:
    assert runtime_platform_name() in {PLATFORM_WINDOWS, PLATFORM_POSIX, "java"}
