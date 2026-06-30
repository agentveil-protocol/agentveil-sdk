#!/usr/bin/env python3
"""Installed-path smoke for public Codex one-command setup."""

from __future__ import annotations

import json
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
    with tempfile.TemporaryDirectory(prefix="avp-codex-installed-smoke-") as tmp:
        isolated_home = Path(tmp) / "home"
        env["HOME"] = str(isolated_home)
        install_root = Path(tmp) / "install"
        cli, _python = build_installed_runtime(install_root)

        project = Path(tmp) / "project"
        project.mkdir()
        codex_config = isolated_home / ".codex" / "config.toml"

        setup = _run(
            [str(cli), "setup", "codex", "--project-dir", str(project), "--yes", "--json"],
            cwd=project,
            env=env,
        )
        if setup.returncode != 0:
            print(setup.stdout)
            print(setup.stderr, file=sys.stderr)
            return setup.returncode

        payload = json.loads(setup.stdout)
        assert payload["ok"] is True, payload
        assert payload["action"] == "setup-codex"
        assert payload["approval_center"]["state"] == "running"
        assert "url" not in payload["approval_center"]
        assert codex_config.is_file()
        text = codex_config.read_text(encoding="utf-8")
        assert "[mcp_servers.agentveil-mcp-proxy]" in text
        assert 'default_tools_approval_mode = "approve"' in text
        assert (project / ".avp" / "mcp-proxy" / "config.json").is_file()

        status = _run(
            [str(cli), "setup", "status", "--client", "codex", "--project-dir", str(project), "--json"],
            cwd=project,
            env=env,
        )
        assert status.returncode == 0, status.stderr
        status_payload = json.loads(status.stdout)
        assert status_payload["connector"] == "codex"
        assert status_payload["mcp_route"] == "present"
        assert status_payload["approval_center"] == "running"

        remove = _run(
            [str(cli), "setup", "remove", "codex", "--project-dir", str(project), "--yes", "--json"],
            cwd=project,
            env=env,
        )
        assert remove.returncode == 0, remove.stderr
        remove_payload = json.loads(remove.stdout)
        assert remove_payload["ok"] is True
        assert remove_payload["mcp_route_removed"] is True
        assert remove_payload["approval_center_stopped"] is True or not (
            project / ".avp" / "mcp-proxy" / "approval-center.manifest.json"
        ).exists()
        if codex_config.exists():
            assert "[mcp_servers.agentveil-mcp-proxy]" not in codex_config.read_text(encoding="utf-8")

    print("P0_7_CODEX_SETUP_INSTALLED_SMOKE: ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
