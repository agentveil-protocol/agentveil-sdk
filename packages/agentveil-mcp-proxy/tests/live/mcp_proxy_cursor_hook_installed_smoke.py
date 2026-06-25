#!/usr/bin/env python3
"""Installed-path smoke for public Cursor one-command setup."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = Path(__file__).resolve().parents[1]
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

from installed_wheel_env import build_installed_runtime, clean_env


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def main() -> int:
    env = clean_env()
    with tempfile.TemporaryDirectory(prefix="avp-cursor-installed-smoke-") as tmp:
        install_root = Path(tmp) / "install"
        cli, python = build_installed_runtime(install_root)

        workspace = Path(tmp) / "workspace"
        workspace.mkdir()

        setup = _run(
            [str(cli), "setup", "cursor", "--workspace", str(workspace), "--yes", "--json"],
            cwd=workspace,
            env=env,
        )
        if setup.returncode != 0:
            print(setup.stdout)
            print(setup.stderr, file=sys.stderr)
            return setup.returncode

        payload = json.loads(setup.stdout)
        assert payload["ok"] is True, payload
        assert payload["approval_center"]["state"] == "running"
        assert "url" not in payload["approval_center"]
        assert (workspace / ".cursor" / "hooks.json").is_file()
        assert (workspace / ".cursor" / "mcp.json").is_file()

        manifest_probe = _run(
            [
                str(python),
                "-c",
                (
                    "from pathlib import Path; "
                    "from agentveil_mcp_proxy.approval.persistent import load_manifest; "
                    "home = Path('.agentveil/mcp-proxy'); "
                    "assert load_manifest(home) is not None"
                ),
            ],
            cwd=workspace,
            env=env,
        )
        assert manifest_probe.returncode == 0, manifest_probe.stderr

        status = _run(
            [str(cli), "setup", "status", "--workspace", str(workspace), "--json"],
            cwd=workspace,
            env=env,
        )
        assert status.returncode == 0, status.stderr
        status_payload = json.loads(status.stdout)
        assert status_payload["approval_center"] == "running"

        remove = _run(
            [str(cli), "setup", "remove", "cursor", "--workspace", str(workspace), "--yes", "--json"],
            cwd=workspace,
            env=env,
        )
        assert remove.returncode == 0, remove.stderr
        remove_payload = json.loads(remove.stdout)
        assert remove_payload["ok"] is True
        assert remove_payload["approval_center_stopped"] is True or not (
            workspace / ".agentveil" / "mcp-proxy" / "approval-center.manifest.json"
        ).exists()

    print("P10D14_CURSOR_HOOK_INSTALLED_SMOKE: ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
