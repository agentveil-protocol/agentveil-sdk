"""Fresh wheel + venv bootstrap for installed-path live smokes."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
SDK_ROOT = PACKAGE_ROOT.parent.parent
BOOTSTRAP_ENV = "AVP_INSTALLED_WHEEL_SMOKE_BOOTSTRAPPED"
WORK_ENV = "AVP_INSTALLED_WHEEL_SMOKE_WORK"


def clean_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    return env


def _venv_paths(venv: Path) -> tuple[Path, Path, Path]:
    if os.name == "nt":
        return (
            venv / "Scripts/python.exe",
            venv / "Scripts/pip.exe",
            venv / "Scripts/agentveil-mcp-proxy.exe",
        )
    return venv / "bin/python", venv / "bin/pip", venv / "bin/agentveil-mcp-proxy"


def build_installed_runtime(work_root: Path) -> tuple[Path, Path]:
    """Build wheels, install into a fresh venv, return ``(cli, python)``."""
    work_root.mkdir(parents=True, exist_ok=True)
    wheelhouse = work_root / "wheels"
    wheelhouse.mkdir(parents=True, exist_ok=True)
    env = clean_env()
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(SDK_ROOT), "-w", str(wheelhouse), "-q"],
        check=True,
        env=env,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            str(PACKAGE_ROOT),
            "-w",
            str(wheelhouse),
            "--no-deps",
            "-q",
        ],
        check=True,
        env=env,
    )
    venv = work_root / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    _python, pip, cli = _venv_paths(venv)
    subprocess.run(
        [
            str(pip),
            "install",
            "--no-index",
            f"--find-links={wheelhouse}",
            "agentveil",
            "agentveil-mcp-proxy",
            "-q",
        ],
        check=True,
        env=env,
    )
    show = subprocess.run(
        [str(pip), "show", "agentveil-mcp-proxy"],
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )
    if "Editable project location" in show.stdout:
        raise RuntimeError("installed smoke must not use editable install")
    if not cli.is_file():
        raise RuntimeError(f"installed CLI missing: {cli}")
    module_probe = subprocess.run(
        [str(_python), "-c", "import agentveil, agentveil_mcp_proxy.cli as c; print(c.__file__)"],
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )
    if "site-packages" not in module_probe.stdout:
        raise RuntimeError(f"package not installed in site-packages: {module_probe.stdout}")
    if str(PACKAGE_ROOT.resolve()) in module_probe.stdout:
        raise RuntimeError("installed smoke must not import worktree source")
    return cli, _python


def bootstrap_reexec(script_path: Path) -> int | None:
    """Re-exec ``script_path`` in a fresh wheel-installed venv when not bootstrapped."""
    if os.environ.get(BOOTSTRAP_ENV) == "1":
        return None
    work = Path(tempfile.mkdtemp(prefix="avp-installed-wheel-smoke-"))
    _cli, python = build_installed_runtime(work)
    env = clean_env()
    env[BOOTSTRAP_ENV] = "1"
    env[WORK_ENV] = str(work)
    completed = subprocess.run([str(python), str(script_path), *sys.argv[1:]], env=env, check=False)
    return completed.returncode


def cleanup_bootstrap_workdir() -> None:
    work = os.environ.get(WORK_ENV)
    if not work:
        return
    import shutil

    shutil.rmtree(work, ignore_errors=True)
