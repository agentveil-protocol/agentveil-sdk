#!/usr/bin/env python3
"""P10D.12 installed-path smoke: Cursor hook setup/status/remove/hook CLI."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = ROOT
SDK_ROOT = PACKAGE_ROOT.parent.parent
SECRET = "SECRET_CURSOR_HOOK_SMOKE"
PRIVACY_MARKERS = (
    "/users/",
    "\\users\\",
    "/private/",
    "/var/folders/",
    "/tmp/",
    SECRET.lower(),
    "library/caches/pip",
)


def _clean_env(tmp_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "PYTHONPATH",
        "PYTHONHOME",
        "PIP_USER",
        "PIP_USER_INSTALL",
        "PYTHONUSERBASE",
    ):
        env.pop(key, None)
    home = tmp_root / "home"
    home.mkdir(parents=True, exist_ok=True)
    pip_cache = tmp_root / "pip-cache"
    pip_cache.mkdir(parents=True, exist_ok=True)
    xdg_cache = tmp_root / "xdg-cache"
    xdg_cache.mkdir(parents=True, exist_ok=True)
    env["HOME"] = str(home)
    env["PIP_NO_CACHE_DIR"] = "1"
    env["PIP_CACHE_DIR"] = str(pip_cache)
    env["XDG_CACHE_HOME"] = str(xdg_cache)
    return env


def _resolved_hook_shim_name() -> str:
    return "agentveil-cursor-hook.cmd" if sys.platform == "win32" else "agentveil-cursor-hook.sh"


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _installed_cli(venv: Path) -> Path:
    return venv / ("Scripts/agentveil-mcp-proxy.exe" if sys.platform == "win32" else "bin/agentveil-mcp-proxy")


def _record_output(surfaces: list[str], *chunks: str) -> None:
    for chunk in chunks:
        if chunk:
            surfaces.append(chunk)


def _privacy_clean(text: str) -> None:
    lowered = text.lower()
    for marker in PRIVACY_MARKERS:
        assert marker not in lowered, f"privacy leak: {marker!r}"


def _run(
    cmd: list[str],
    *,
    env: dict[str, str],
    surfaces: list[str],
    cwd: str | None = None,
    text_input: str | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        input=text_input,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    _record_output(surfaces, proc.stdout, proc.stderr)
    return proc


def _build_installed_cli(tmp_root: Path, surfaces: list[str]) -> tuple[Path, Path]:
    env = _clean_env(tmp_root)
    wheelhouse = tmp_root / "wheels"
    wheelhouse.mkdir()
    for cmd in (
        [sys.executable, "-m", "pip", "wheel", str(SDK_ROOT), "-w", str(wheelhouse), "-q"],
        [sys.executable, "-m", "pip", "wheel", str(PACKAGE_ROOT), "-w", str(wheelhouse), "--no-deps", "-q"],
    ):
        proc = _run(cmd, env=env, surfaces=surfaces, cwd=str(tmp_root))
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())

    venv = tmp_root / "venv"
    create = _run([sys.executable, "-m", "venv", str(venv)], env=env, surfaces=surfaces, cwd=str(tmp_root))
    if create.returncode != 0:
        raise RuntimeError(create.stderr.strip() or create.stdout.strip())

    pip = _venv_python(venv).parent / ("pip.exe" if sys.platform == "win32" else "pip")
    install = _run(
        [str(pip), "install", "--no-index", f"--find-links={wheelhouse}", "agentveil", "agentveil-mcp-proxy", "-q"],
        env=env,
        surfaces=surfaces,
        cwd=str(tmp_root),
    )
    if install.returncode != 0:
        raise RuntimeError(install.stderr.strip() or install.stdout.strip())

    module_probe = _run(
        [str(_venv_python(venv)), "-c", "import agentveil_mcp_proxy.cli as c; print('ok')"],
        env=env,
        surfaces=surfaces,
    )
    if module_probe.returncode != 0:
        raise RuntimeError(module_probe.stderr.strip() or module_probe.stdout.strip())
    assert module_probe.stdout.strip() == "ok"
    return _installed_cli(venv), venv


def _write_existing_hooks(workspace: Path) -> None:
    cursor_dir = workspace / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    (cursor_dir / "hooks.json").write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [{"command": ".cursor/hooks/user-format.sh"}],
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="avp-cursor-hook-smoke-"))
    surfaces: list[str] = []
    final_lines: list[str] = []
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    try:
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            env = _clean_env(temp_root)
            cli, _venv = _build_installed_cli(temp_root, surfaces)
            workspace = temp_root / "workspace"
            workspace.mkdir()
            _write_existing_hooks(workspace)

            setup = _run(
                [str(cli), "setup", "cursor", "--yes", "--json"],
                env=env,
                surfaces=surfaces,
                cwd=str(workspace),
            )
            assert setup.returncode == 0, setup.stderr
            setup_payload = json.loads(setup.stdout)
            assert setup_payload["ok"] is True
            hooks_doc = json.loads((workspace / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
            assert hooks_doc["hooks"]["afterFileEdit"][0]["command"] == ".cursor/hooks/user-format.sh"
            assert any(
                entry.get("agentveilHookId") == "agentveil-cursor-hook-v1"
                for entries in hooks_doc["hooks"].values()
                for entry in entries
            )

            setup_repeat = _run(
                [str(cli), "setup", "cursor", "--yes", "--json"],
                env=env,
                surfaces=surfaces,
                cwd=str(workspace),
            )
            assert setup_repeat.returncode == 0, setup_repeat.stderr
            hooks_after_repeat = json.loads((workspace / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
            assert len(json.dumps(hooks_after_repeat, sort_keys=True)) == len(json.dumps(hooks_doc, sort_keys=True))

            status = _run(
                [str(cli), "setup", "status", "--json"],
                env=env,
                surfaces=surfaces,
                cwd=str(workspace),
            )
            assert status.returncode == 0, status.stderr
            status_payload = json.loads(status.stdout)
            assert status_payload["installed"] is True
            assert status_payload["hook_cli_resolved"] is True

            shim_path = workspace / ".cursor" / "hooks" / _resolved_hook_shim_name()
            if sys.platform == "win32":
                shim_cmd = ["cmd", "/c", str(shim_path)]
                shim_env = {
                    "PATH": env.get("PATH", ""),
                    "HOME": env["HOME"],
                    "AGENTVEIL_CURSOR_WORKSPACE": str(workspace),
                }
            else:
                shim_cmd = [str(shim_path)]
                shim_env = {
                    "PATH": "/usr/bin:/bin",
                    "HOME": env["HOME"],
                    "AGENTVEIL_CURSOR_WORKSPACE": str(workspace),
                }
            shim_proc = _run(
                shim_cmd,
                env=shim_env,
                surfaces=surfaces,
                cwd=str(workspace),
                text_input=json.dumps({"tool_name": "Write", "tool_input": {"path": "x", "contents": "y"}}),
            )
            assert shim_proc.returncode == 0, shim_proc.stderr
            shim_payload = json.loads(shim_proc.stdout)
            assert shim_payload["permission"] == "deny"
            assert "missing_cli" not in shim_payload.get("agent_message", "")

            hook = _run(
                [str(cli), "hook", "cursor", "--workspace", str(workspace)],
                env=env,
                surfaces=surfaces,
                cwd=str(workspace),
                text_input=json.dumps({"tool_name": "Write", "tool_input": {"path": "x", "contents": "y"}}),
            )
            assert hook.returncode == 0, hook.stderr
            hook_payload = json.loads(hook.stdout)
            assert hook_payload["permission"] == "deny"

            remove = _run(
                [str(cli), "setup", "remove", "cursor", "--yes", "--json"],
                env=env,
                surfaces=surfaces,
                cwd=str(workspace),
            )
            assert remove.returncode == 0, remove.stderr
            remove_payload = json.loads(remove.stdout)
            assert remove_payload["ok"] is True
            assert "reload" in remove_payload["message"].lower()
            remaining = json.loads((workspace / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
            assert remaining["hooks"]["afterFileEdit"][0]["command"] == ".cursor/hooks/user-format.sh"
            assert not any(
                entry.get("agentveilHookId") == "agentveil-cursor-hook-v1"
                for entries in remaining["hooks"].values()
                for entry in entries
            )

            created_workspace = temp_root / "created-workspace"
            created_workspace.mkdir()
            created_setup = _run(
                [str(cli), "setup", "cursor", "--yes", "--json"],
                env=env,
                surfaces=surfaces,
                cwd=str(created_workspace),
            )
            assert created_setup.returncode == 0, created_setup.stderr
            created_remove = _run(
                [str(cli), "setup", "remove", "cursor", "--yes", "--json"],
                env=env,
                surfaces=surfaces,
                cwd=str(created_workspace),
            )
            assert created_remove.returncode == 0, created_remove.stderr
            assert not (created_workspace / ".cursor" / "hooks.json").exists()

            final_lines.append("P10D12_CURSOR_HOOK_INSTALLED_SMOKE: ok")

        _record_output(surfaces, stdout_buffer.getvalue(), stderr_buffer.getvalue())
        combined = "\n".join(surfaces + final_lines)
        _privacy_clean(combined)
        for line in final_lines:
            print(line)
        return 0
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
