"""Platform contract for Cursor hook setup tests across Windows/macOS/Linux."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentveil_mcp_proxy.cursor_setup import (
    build_hook_shim_script,
    normalize_cli_basename,
    read_shim_cli_path,
    resolved_hook_shim_name,
)
from conftest import (
    CONSOLE_SCRIPT_BASENAME,
    HOOK_SHIM_POSIX,
    HOOK_SHIM_WINDOWS,
    PLATFORM_POSIX,
    PLATFORM_WINDOWS,
    assert_hook_shim_platform_contract,
    expected_hook_shim_name,
    hook_shim_relative_path,
    installed_cli_filename,
    is_windows_runtime,
    runtime_platform_name,
    venv_scripts_dirname,
    write_runnable_proxy_command,
)


def test_runtime_platform_contract_matches_cursor_setup() -> None:
    assert expected_hook_shim_name() == resolved_hook_shim_name()
    if is_windows_runtime():
        assert expected_hook_shim_name() == HOOK_SHIM_WINDOWS
    else:
        assert expected_hook_shim_name() == HOOK_SHIM_POSIX


@pytest.mark.parametrize(
    ("platform_name", "shim_name", "cli_name", "scripts_dir"),
    [
        (PLATFORM_WINDOWS, HOOK_SHIM_WINDOWS, "agentveil-mcp-proxy.exe", "Scripts"),
        (PLATFORM_POSIX, HOOK_SHIM_POSIX, "agentveil-mcp-proxy", "bin"),
    ],
)
def test_declared_platform_contract(
    platform_name: str,
    shim_name: str,
    cli_name: str,
    scripts_dir: str,
) -> None:
    assert expected_hook_shim_name(platform_name=platform_name) == shim_name
    assert hook_shim_relative_path(platform_name=platform_name) == f".cursor/hooks/{shim_name}"
    assert installed_cli_filename(platform_name=platform_name) == cli_name
    assert venv_scripts_dirname(platform_name=platform_name) == scripts_dir


def test_normalize_cli_basename_is_stable_without_os_monkeypatch() -> None:
    assert normalize_cli_basename(Path("C:/Tools/agentveil-mcp-proxy.exe")) == CONSOLE_SCRIPT_BASENAME
    assert normalize_cli_basename(Path("/tmp/agentveil-mcp-proxy.cmd")) == CONSOLE_SCRIPT_BASENAME
    assert normalize_cli_basename(Path("/tmp/__main__.py")) == CONSOLE_SCRIPT_BASENAME


def test_build_hook_shim_script_windows_shape(tmp_path: Path) -> None:
    cli = tmp_path / "agentveil-mcp-proxy.exe"
    cli.write_text("", encoding="utf-8")
    script = build_hook_shim_script(cli_path=cli, platform_name=PLATFORM_WINDOWS)
    assert script.startswith("@echo off")
    assert f'"{cli}" hook cursor %*' in script


def test_build_hook_shim_script_posix_shape(tmp_path: Path) -> None:
    cli = tmp_path / "agentveil-mcp-proxy"
    cli.write_text("", encoding="utf-8")
    script = build_hook_shim_script(cli_path=cli, platform_name=PLATFORM_POSIX)
    assert script.startswith("#!/usr/bin/env bash")
    assert "exec" in script
    assert str(cli) in script


def test_read_shim_cli_path_parses_windows_cmd_shim(tmp_path: Path) -> None:
    cli = tmp_path / "agentveil-mcp-proxy.exe"
    cli.write_text("", encoding="utf-8")
    shim = tmp_path / HOOK_SHIM_WINDOWS
    shim.write_text(f'@echo off\r\n"{cli}" hook cursor %*\r\n', encoding="utf-8")
    assert read_shim_cli_path(shim) == cli


def test_write_runnable_proxy_command_matches_platform_contract(tmp_path: Path) -> None:
    windows_cli = write_runnable_proxy_command(tmp_path / "win", platform_name=PLATFORM_WINDOWS)
    assert windows_cli.name == "agentveil-mcp-proxy.exe"
    assert windows_cli.suffix.lower() == ".exe"

    posix_cli = write_runnable_proxy_command(tmp_path / "posix", platform_name=PLATFORM_POSIX)
    assert posix_cli.name == "agentveil-mcp-proxy"
    assert posix_cli.stat().st_mode & 0o111


def test_assert_hook_shim_platform_contract_posix(tmp_path: Path) -> None:
    shim = tmp_path / HOOK_SHIM_POSIX
    shim.write_text("#!/bin/sh\n", encoding="utf-8")
    shim.chmod(0o755)
    assert_hook_shim_platform_contract(shim, platform_name=PLATFORM_POSIX)


def test_assert_hook_shim_platform_contract_windows(tmp_path: Path) -> None:
    shim = tmp_path / HOOK_SHIM_WINDOWS
    shim.write_text("@echo off\r\n", encoding="utf-8")
    assert_hook_shim_platform_contract(shim, platform_name=PLATFORM_WINDOWS)


def test_runtime_platform_name_is_supported() -> None:
    assert runtime_platform_name() in {PLATFORM_WINDOWS, PLATFORM_POSIX, "java"}
