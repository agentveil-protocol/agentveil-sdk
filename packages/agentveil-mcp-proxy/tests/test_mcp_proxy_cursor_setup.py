"""Unit tests for Cursor hook setup, status, and removal."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentveil_mcp_proxy.cli import main
from agentveil_mcp_proxy.cursor_hooks import run_cursor_hook
from agentveil_mcp_proxy.cursor_setup import (
    AGENTVEIL_HOOK_ID,
    build_hooks_document,
    cursor_setup_paths,
    derive_cursor_setup_status,
    global_cursor_config_paths,
    merge_agentveil_hooks,
    read_shim_cli_path,
    remove_cursor_hooks,
    setup_cursor_hooks,
    unmerge_agentveil_hooks,
)


def _snapshot(path: Path) -> tuple[int, str | None]:
    if not path.exists():
        return 0, None
    return path.stat().st_mtime_ns, path.read_text(encoding="utf-8")


def _existing_user_hooks() -> dict:
    return {
        "version": 1,
        "hooks": {
            "afterFileEdit": [
                {"command": ".cursor/hooks/user-format.sh"},
            ],
            "beforeShellExecution": [
                {"command": ".cursor/hooks/user-shell.sh", "matcher": "curl"},
            ],
        },
    }


def _agentveil_entry_count(document: dict) -> int:
    hooks = document.get("hooks") or {}
    count = 0
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("agentveilHookId") == AGENTVEIL_HOOK_ID:
                count += 1
    return count


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    return workspace_root


@pytest.fixture
def proxy_cli_bin(tmp_path: Path) -> Path:
    venv_cli = Path("/private/tmp/agentveil-sdk/.test-venv/bin/agentveil-mcp-proxy")
    if venv_cli.is_file():
        return venv_cli.resolve()

    package_root = Path(__file__).resolve().parents[1]
    repo_root = package_root.parent.parent
    bindir = tmp_path / "bin"
    bindir.mkdir()
    cli = bindir / "agentveil-mcp-proxy"
    cli.write_text(
        "#!/bin/sh\n"
        f"PYTHONPATH={json.dumps(str(repo_root))}:{json.dumps(str(package_root))} "
        f"exec {json.dumps(sys.executable)} -m agentveil_mcp_proxy.cli "
        '"$@"\n',
        encoding="utf-8",
    )
    cli.chmod(0o755)
    return cli.resolve()


@pytest.fixture
def isolated_global_cursor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    home = tmp_path / "home"
    home.mkdir()
    cursor_dir = home / ".cursor"
    cursor_dir.mkdir()
    user_data = tmp_path / "cursor-user-data" / "User"
    user_data.mkdir(parents=True)
    mcp_path = cursor_dir / "mcp.json"
    settings_path = user_data / "settings.json"
    mcp_path.write_text('{"mcpServers": {}}\n', encoding="utf-8")
    settings_path.write_text('{"workbench.colorTheme": "Default Dark Modern"}\n', encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CURSOR_USER_DATA_DIR", str(user_data.parent.parent / "cursor-user-data"))
    return mcp_path, settings_path


def _setup(workspace: Path, proxy_cli_bin: Path, **kwargs):
    return setup_cursor_hooks(
        workspace=workspace,
        yes=True,
        setup_cli_path=proxy_cli_bin,
        **kwargs,
    )


def test_setup_cursor_requires_yes(workspace: Path, isolated_global_cursor) -> None:
    mcp_before, settings_before = map(_snapshot, isolated_global_cursor)
    result = setup_cursor_hooks(workspace=workspace, yes=False)
    assert result.ok is False
    assert result.errors == ("confirmation_required",)
    assert not cursor_setup_paths(workspace).hooks_json.exists()
    assert _snapshot(isolated_global_cursor[0]) == mcp_before
    assert _snapshot(isolated_global_cursor[1]) == settings_before


def test_setup_writes_shim_with_absolute_cli_path(workspace: Path, proxy_cli_bin: Path) -> None:
    result = _setup(workspace, proxy_cli_bin)
    paths = cursor_setup_paths(workspace)
    assert result.ok is True
    assert result.hook_cli_resolved is True
    assert result.hook_cli_ref is not None
    assert result.hook_cli_ref["basename"] == "agentveil-mcp-proxy"
    shim_cli = read_shim_cli_path(paths.hook_shim)
    assert shim_cli == proxy_cli_bin
    assert str(proxy_cli_bin) in paths.hook_shim.read_text(encoding="utf-8")


def test_shim_works_with_empty_path(workspace: Path, proxy_cli_bin: Path) -> None:
    _setup(workspace, proxy_cli_bin)
    paths = cursor_setup_paths(workspace)
    payload = json.dumps({"tool_name": "Write", "tool_input": {"path": "x", "contents": "y"}})
    proc = subprocess.run(
        [str(paths.hook_shim)],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": os.environ.get("HOME", "/tmp"),
            "AGENTVEIL_CURSOR_WORKSPACE": str(workspace),
        },
    )
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout)
    assert body["permission"] == "deny"
    assert "missing_cli" not in body.get("agent_message", "")


def test_setup_and_status_output_do_not_leak_raw_cli_path(
    workspace: Path,
    proxy_cli_bin: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("PATH", str(proxy_cli_bin.parent))
    assert main(["setup", "cursor", "--yes", "--json"]) == 0
    setup_out = capsys.readouterr().out
    assert str(proxy_cli_bin) not in setup_out
    assert "/users/" not in setup_out.lower()

    assert main(["setup", "status", "--json"]) == 0
    status_payload = json.loads(capsys.readouterr().out)
    assert status_payload["hook_cli_resolved"] is True
    assert status_payload["hook_cli_ref"]["basename"] == "agentveil-mcp-proxy"
    assert str(proxy_cli_bin) not in json.dumps(status_payload)


def test_setup_cursor_creates_project_local_files_only(
    workspace: Path,
    isolated_global_cursor,
    proxy_cli_bin: Path,
) -> None:
    mcp_before, settings_before = map(_snapshot, isolated_global_cursor)
    result = _setup(workspace, proxy_cli_bin)
    paths = cursor_setup_paths(workspace)

    assert result.ok is True
    assert paths.hooks_json.is_file()
    assert paths.hook_shim.is_file()
    assert paths.manifest_path.is_file()
    assert paths.hook_shim.stat().st_mode & 0o111

    hooks_doc = json.loads(paths.hooks_json.read_text(encoding="utf-8"))
    assert hooks_doc["version"] == 1
    assert _agentveil_entry_count(hooks_doc) == 3
    manifest = json.loads(paths.manifest_path.read_text(encoding="utf-8"))
    assert manifest["hooks_json_origin"] == "created"
    assert manifest["hook_cli_ref"]["basename"] == "agentveil-mcp-proxy"

    assert _snapshot(isolated_global_cursor[0]) == mcp_before
    assert _snapshot(isolated_global_cursor[1]) == settings_before


def test_setup_preserves_existing_hooks_json(workspace: Path, proxy_cli_bin: Path) -> None:
    paths = cursor_setup_paths(workspace)
    paths.cursor_dir.mkdir(parents=True)
    existing = _existing_user_hooks()
    paths.hooks_json.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")

    _setup(workspace, proxy_cli_bin)
    merged = json.loads(paths.hooks_json.read_text(encoding="utf-8"))

    assert merged["hooks"]["afterFileEdit"] == existing["hooks"]["afterFileEdit"]
    assert merged["hooks"]["beforeShellExecution"][0]["command"] == ".cursor/hooks/user-shell.sh"
    assert _agentveil_entry_count(merged) == 3
    manifest = json.loads(paths.manifest_path.read_text(encoding="utf-8"))
    assert manifest["hooks_json_origin"] == "merged"


def test_setup_and_remove_preserve_unknown_top_level_fields(workspace: Path, proxy_cli_bin: Path) -> None:
    paths = cursor_setup_paths(workspace)
    paths.cursor_dir.mkdir(parents=True)
    existing = {
        "version": 1,
        "customTopLevel": {"keep": True},
        "hooks": {
            "afterFileEdit": [{"command": ".cursor/hooks/user-format.sh"}],
        },
    }
    paths.hooks_json.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")

    _setup(workspace, proxy_cli_bin)
    after_setup = json.loads(paths.hooks_json.read_text(encoding="utf-8"))
    assert after_setup["customTopLevel"] == {"keep": True}
    assert _agentveil_entry_count(after_setup) == 3

    remove_cursor_hooks(workspace=workspace, yes=True)
    after_remove = json.loads(paths.hooks_json.read_text(encoding="utf-8"))
    assert after_remove["customTopLevel"] == {"keep": True}
    assert after_remove["hooks"]["afterFileEdit"] == existing["hooks"]["afterFileEdit"]
    assert _agentveil_entry_count(after_remove) == 0


def test_setup_adds_agentveil_beside_existing_entries(workspace: Path, proxy_cli_bin: Path) -> None:
    paths = cursor_setup_paths(workspace)
    paths.cursor_dir.mkdir(parents=True)
    paths.hooks_json.write_text(json.dumps(_existing_user_hooks(), indent=2) + "\n", encoding="utf-8")

    _setup(workspace, proxy_cli_bin)
    merged = json.loads(paths.hooks_json.read_text(encoding="utf-8"))
    shell_entries = merged["hooks"]["beforeShellExecution"]
    assert len(shell_entries) == 2
    assert shell_entries[0]["command"] == ".cursor/hooks/user-shell.sh"
    assert shell_entries[1]["agentveilHookId"] == AGENTVEIL_HOOK_ID


def test_setup_is_idempotent_without_duplicates(workspace: Path, proxy_cli_bin: Path) -> None:
    paths = cursor_setup_paths(workspace)
    paths.cursor_dir.mkdir(parents=True)
    paths.hooks_json.write_text(json.dumps(_existing_user_hooks(), indent=2) + "\n", encoding="utf-8")

    _setup(workspace, proxy_cli_bin)
    first = json.loads(paths.hooks_json.read_text(encoding="utf-8"))
    _setup(workspace, proxy_cli_bin)
    second = json.loads(paths.hooks_json.read_text(encoding="utf-8"))

    assert _agentveil_entry_count(first) == 3
    assert _agentveil_entry_count(second) == 3
    assert len(second["hooks"]["beforeShellExecution"]) == len(first["hooks"]["beforeShellExecution"])


def test_remove_preserves_existing_hooks_after_merge(workspace: Path, proxy_cli_bin: Path) -> None:
    paths = cursor_setup_paths(workspace)
    paths.cursor_dir.mkdir(parents=True)
    paths.hooks_json.write_text(json.dumps(_existing_user_hooks(), indent=2) + "\n", encoding="utf-8")

    _setup(workspace, proxy_cli_bin)
    result = remove_cursor_hooks(workspace=workspace, yes=True)

    assert result.ok is True
    assert paths.hooks_json.is_file()
    remaining = json.loads(paths.hooks_json.read_text(encoding="utf-8"))
    assert remaining["hooks"]["afterFileEdit"] == _existing_user_hooks()["hooks"]["afterFileEdit"]
    assert len(remaining["hooks"]["beforeShellExecution"]) == 1
    assert _agentveil_entry_count(remaining) == 0
    assert not paths.hook_shim.exists()
    assert not paths.manifest_path.exists()


def test_remove_deletes_only_agentveil_entries_on_created_hooks_json(
    workspace: Path,
    proxy_cli_bin: Path,
) -> None:
    _setup(workspace, proxy_cli_bin)
    paths = cursor_setup_paths(workspace)
    result = remove_cursor_hooks(workspace=workspace, yes=True)

    assert result.ok is True
    assert not paths.hooks_json.exists()
    assert not paths.hook_shim.exists()
    assert not paths.manifest_path.exists()


def test_agentveil_hook_works_after_merge(workspace: Path, proxy_cli_bin: Path) -> None:
    paths = cursor_setup_paths(workspace)
    paths.cursor_dir.mkdir(parents=True)
    paths.hooks_json.write_text(json.dumps(_existing_user_hooks(), indent=2) + "\n", encoding="utf-8")
    _setup(workspace, proxy_cli_bin)

    response, evidence = run_cursor_hook(
        stdin_text=json.dumps({"tool_name": "Write", "tool_input": {"path": "x", "contents": "y"}}),
        workspace=workspace,
        hook_event="preToolUse",
    )
    assert response["permission"] == "deny"
    assert evidence["decision"] == "deny"


def test_setup_status_reports_installed_and_stale(workspace: Path, proxy_cli_bin: Path) -> None:
    _setup(workspace, proxy_cli_bin)
    installed = derive_cursor_setup_status(workspace=workspace)
    assert installed.installed is True
    assert installed.stale is False
    assert installed.hook_state == "installed"
    assert installed.hook_cli_resolved is True

    paths = cursor_setup_paths(workspace)
    paths.hook_shim.unlink()
    stale = derive_cursor_setup_status(workspace=workspace)
    assert stale.installed is False
    assert stale.stale is True
    assert stale.hook_state == "stale"


def test_remove_cursor_requires_reload_message(workspace: Path, proxy_cli_bin: Path) -> None:
    _setup(workspace, proxy_cli_bin)
    result = remove_cursor_hooks(workspace=workspace, yes=True)
    assert "reload" in result.message.lower() or "restart" in result.message.lower()


def test_hooks_document_uses_expected_matchers() -> None:
    doc = build_hooks_document(shim_relative_path=".cursor/hooks/agentveil-cursor-hook.sh")
    matcher = doc["hooks"]["preToolUse"][0]["matcher"]
    assert "Write" in matcher
    assert "Delete" in matcher
    assert "StrReplace" in matcher
    assert doc["hooks"]["beforeShellExecution"][0]["failClosed"] is True


def test_merge_and_unmerge_helpers_are_bounded() -> None:
    existing = _existing_user_hooks()
    merged, changed = merge_agentveil_hooks(
        existing,
        shim_relative_path=".cursor/hooks/agentveil-cursor-hook.sh",
    )
    assert changed is True
    assert _agentveil_entry_count(merged) == 3

    restored, removed = unmerge_agentveil_hooks(
        merged,
        hook_id=AGENTVEIL_HOOK_ID,
        shim_relative_path=".cursor/hooks/agentveil-cursor-hook.sh",
    )
    assert removed is True
    assert restored["hooks"]["afterFileEdit"] == existing["hooks"]["afterFileEdit"]
    assert _agentveil_entry_count(restored) == 0


def test_global_cursor_paths_are_outside_workspace(workspace: Path) -> None:
    mcp_path, settings_path = global_cursor_config_paths()
    assert workspace not in mcp_path.parents
    assert workspace not in settings_path.parents
