"""Shared pytest fixtures for client connect/doctor unit tests."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest


def write_runnable_proxy_command(directory: Path) -> Path:
    """Create an executable wrapper that runs the in-tree CLI via ``python -m``."""

    directory.mkdir(parents=True, exist_ok=True)
    proxy_root = Path(__file__).resolve().parents[1]
    repo_root = proxy_root.parents[1]
    pythonpath = os.pathsep.join((str(repo_root), str(proxy_root)))
    if os.name == "nt":
        command = directory / "agentveil-mcp-proxy.cmd"
        command.write_text(
            "@echo off\r\n"
            f"set \"PYTHONPATH={pythonpath}\"\r\n"
            f"\"{sys.executable}\" -m agentveil_mcp_proxy.cli %*\r\n",
            encoding="utf-8",
        )
        return command
    command = directory / "agentveil-mcp-proxy"
    command.write_text(
        "#!/bin/sh\n"
        f"PYTHONPATH={json.dumps(pythonpath)} "
        f"exec {json.dumps(sys.executable)} -m agentveil_mcp_proxy.cli "
        '"$@"\n',
        encoding="utf-8",
    )
    command.chmod(0o755)
    return command


@pytest.fixture
def runnable_proxy_command(tmp_path: Path) -> str:
    """Return a temp executable that launches ``agentveil_mcp_proxy.cli`` from source."""

    return str(write_runnable_proxy_command(tmp_path / "bin"))


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
