"""Shared pytest fixtures and Cursor hook platform test contract."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PLATFORM_WINDOWS = "nt"
PLATFORM_POSIX = "posix"
HOOK_SHIM_WINDOWS = "agentveil-cursor-hook.cmd"
HOOK_SHIM_POSIX = "agentveil-cursor-hook.sh"
CONSOLE_SCRIPT_BASENAME = "agentveil-mcp-proxy"
HOOK_SUBPROCESS_TIMEOUT = 30


def runtime_platform_name() -> str:
    return os.name


def is_windows_runtime() -> bool:
    return os.name == PLATFORM_WINDOWS


def expected_hook_shim_name(*, platform_name: str | None = None) -> str:
    name = platform_name or os.name
    return HOOK_SHIM_WINDOWS if name == PLATFORM_WINDOWS else HOOK_SHIM_POSIX


def hook_shim_relative_path(*, platform_name: str | None = None) -> str:
    return f".cursor/hooks/{expected_hook_shim_name(platform_name=platform_name)}"


def installed_cli_filename(*, platform_name: str | None = None) -> str:
    name = platform_name or os.name
    return f"{CONSOLE_SCRIPT_BASENAME}.exe" if name == PLATFORM_WINDOWS else CONSOLE_SCRIPT_BASENAME


def venv_scripts_dirname(*, platform_name: str | None = None) -> str:
    return "Scripts" if (platform_name or os.name) == PLATFORM_WINDOWS else "bin"


def privacy_home_markers() -> tuple[str, ...]:
    return ("/users/", "\\users\\")


def write_runnable_proxy_command(directory: Path, *, platform_name: str | None = None) -> Path:
    """Create a platform-shaped wrapper that runs the in-tree CLI via ``python -m``."""

    directory.mkdir(parents=True, exist_ok=True)
    proxy_root = Path(__file__).resolve().parents[1]
    repo_root = proxy_root.parents[1]
    pythonpath = os.pathsep.join((str(repo_root), str(proxy_root)))
    platform = platform_name or os.name
    if platform == PLATFORM_WINDOWS:
        # This helper creates a runnable test wrapper, not an installed console
        # script. A text file named .exe is not executable on Windows, so use a
        # batch shim and let launch code exercise its .cmd shell path.
        command = directory / f"{CONSOLE_SCRIPT_BASENAME}.cmd"
        command.write_text(
            "@echo off\r\n"
            f'set "PYTHONPATH={pythonpath}"\r\n'
            f'"{sys.executable}" -m agentveil_mcp_proxy.cli %*\r\n',
            encoding="utf-8",
        )
        return command
    command = directory / installed_cli_filename(platform_name=PLATFORM_POSIX)
    command.write_text(
        "#!/bin/sh\n"
        f"PYTHONPATH={json.dumps(pythonpath)} "
        f"exec {json.dumps(sys.executable)} -m agentveil_mcp_proxy.cli "
        '"$@"\n',
        encoding="utf-8",
    )
    command.chmod(0o755)
    return command


def assert_hook_shim_platform_contract(shim_path: Path, *, platform_name: str | None = None) -> None:
    """Assert hook shim shape for the requested or runtime platform."""

    platform = platform_name or os.name
    assert shim_path.name == expected_hook_shim_name(platform_name=platform)
    if platform == PLATFORM_WINDOWS:
        assert shim_path.suffix.lower() == ".cmd"
        return
    if is_windows_runtime():
        assert shim_path.suffix.lower() == ".sh"
        return
    assert shim_path.stat().st_mode & 0o111


def run_hook_shim_subprocess(
    shim_path: Path,
    *,
    workspace: Path,
    payload: str,
    timeout: int = HOOK_SUBPROCESS_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    """Run one bounded hook shim invocation using the runtime platform contract."""

    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "USERPROFILE": os.environ.get("USERPROFILE", os.environ.get("HOME", "/tmp")),
        "AGENTVEIL_CURSOR_WORKSPACE": str(workspace),
    }
    if is_windows_runtime():
        cmd = ["cmd", "/c", str(shim_path)]
    else:
        cmd = [str(shim_path)]
        env = {**env, "PATH": "/usr/bin:/bin"}
    return subprocess.run(
        cmd,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
        env=env,
        timeout=timeout,
    )


@pytest.fixture
def runnable_proxy_command(tmp_path: Path) -> str:
    """Return a temp executable that launches ``agentveil_mcp_proxy.cli`` from source."""

    return str(write_runnable_proxy_command(tmp_path / "bin"))


@pytest.fixture
def proxy_cli_bin(tmp_path: Path) -> Path:
    """Return a temp platform-shaped AgentVeil CLI wrapper for Cursor setup tests."""

    venv_cli = Path("/private/tmp/agentveil-sdk/.test-venv/bin/agentveil-mcp-proxy")
    if not is_windows_runtime() and venv_cli.is_file():
        return venv_cli.resolve()
    return write_runnable_proxy_command(tmp_path / "bin").resolve()


@pytest.fixture(autouse=True)
def _isolated_cursor_connect_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate Cursor global MCP config and legacy settings cleanup paths."""

    home = tmp_path / "user-home"
    home.mkdir()
    (home / ".cursor").mkdir(parents=True, exist_ok=True)
    cursor_user_data = tmp_path / "cursor-user-data"
    cursor_user_data.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("CURSOR_USER_DATA_DIR", str(cursor_user_data))
    return home


@pytest.fixture
def isolated_cursor_user_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point legacy Cursor settings cleanup at an isolated user-data directory."""

    root = tmp_path / "cursor-user-data-legacy"
    root.mkdir()
    monkeypatch.setenv("CURSOR_USER_DATA_DIR", str(root))
    return root


@pytest.fixture
def isolated_home(_isolated_cursor_connect_paths: Path) -> Path:
    """Point Codex auto-connect at the isolated HOME directory."""

    return _isolated_cursor_connect_paths


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    return workspace_root
