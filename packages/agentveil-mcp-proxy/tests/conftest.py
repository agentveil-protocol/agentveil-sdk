"""Shared pytest fixtures and Cursor hook platform test contract."""

from __future__ import annotations

import json
import os
import site
import subprocess
import sys
from pathlib import Path

import pytest
import webbrowser


_OPERATOR_APPROVAL_URLS: dict[str, str] = {}


def operator_approval_url(record_id: str) -> str:
    """Return a URL captured from the operator-side ApprovalServer register path."""

    return _OPERATOR_APPROVAL_URLS[record_id]

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
def managed_approval_center_server():
    """Start one test-owned HTTP Approval Center with fixture cleanup."""

    from agentveil_mcp_proxy.approval.persistent import (
        build_manifest_for_server,
        create_persistent_server,
        save_manifest,
    )
    from agentveil_mcp_proxy.approval.manager import ApprovalManager
    from agentveil_mcp_proxy.approval.server import clear_managed_approval_center_manifest
    from agentveil_mcp_proxy.cli import load_proxy_config
    from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore

    started = []

    def start(*, home: Path):
        proxy_dir = home / "mcp-proxy"
        assert (proxy_dir / "config.json").is_file()
        store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
        server = create_persistent_server(
            proxy_dir=proxy_dir,
            evidence_store=store,
        )
        manager = ApprovalManager(
            evidence_store=store,
            approval_server=server,
            config=load_proxy_config(proxy_dir / "config.json"),
            client_id="pytest:managed-approval-center",
            headless=True,
            wait_for_decision=False,
        )
        manifest = build_manifest_for_server(server)
        save_manifest(proxy_dir, manifest)
        started.append((server, store, manager, home))
        return manifest

    yield start

    for server, store, _manager, home in reversed(started):
        server.stop()
        store.close()
        clear_managed_approval_center_manifest(home)


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
def _block_approval_browser_and_detached_spawn(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not open a real browser or spawn detached approval-center serve in tests."""

    from agentveil_mcp_proxy.approval.notification import BrowserOpenResult
    from agentveil_mcp_proxy.approval.server import ApprovalServer

    _OPERATOR_APPROVAL_URLS.clear()
    original_register = ApprovalServer.register

    def _register_and_capture(server: ApprovalServer, prompt):
        url = original_register(server, prompt)
        _OPERATOR_APPROVAL_URLS[prompt.request_id] = url
        return url

    monkeypatch.setattr(ApprovalServer, "register", _register_and_capture)

    monkeypatch.setattr(webbrowser, "open", lambda _url: False)

    allow_demo_spawn = request.node.get_closest_marker("allow_demo_managed_approval_center")
    if not allow_demo_spawn:
        def _spawn_blocked(**_kwargs):
            raise OSError("test: real managed approval-center spawn disabled")  # claim-check: allow test guard

        monkeypatch.setattr(
            "agentveil_mcp_proxy.approval.client.spawn_managed_approval_center_process",
            _spawn_blocked,
        )
        monkeypatch.setattr(
            "agentveil_mcp_proxy.approval.server.spawn_managed_approval_center_process",
            _spawn_blocked,
        )

    if request.node.get_closest_marker("allow_approval_browser_delivery"):
        return

    def _browser_blocked(_url: str, **_kwargs) -> BrowserOpenResult:
        return BrowserOpenResult(attempted=True, delivered=False, channel="webbrowser")

    def _macos_blocked(_url: str, **_kwargs) -> BrowserOpenResult:
        return BrowserOpenResult(attempted=False, delivered=False, channel="macos-open")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.notification.deliver_approval_browser_url",
        _browser_blocked,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.notification.open_approval_url_macos_native",
        _macos_blocked,
    )


@pytest.fixture(autouse=True)
def _isolated_cursor_connect_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate Cursor global MCP config and legacy settings cleanup paths."""

    parent_pythonpath = os.environ.get("PYTHONPATH")
    user_site = site.getusersitepackages()
    if Path(user_site).is_dir():
        monkeypatch.setenv(
            "PYTHONPATH",
            os.pathsep.join(filter(None, (parent_pythonpath, user_site))),
        )
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
