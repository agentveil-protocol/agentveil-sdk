#!/usr/bin/env python3
"""Installed-path smoke for public Gemini CLI one-command setup."""

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
    with tempfile.TemporaryDirectory(prefix="avp-gemini-installed-smoke-") as tmp:
        isolated_home = Path(tmp) / "home"
        env["HOME"] = str(isolated_home)
        install_root = Path(tmp) / "install"
        cli, _python = build_installed_runtime(install_root)

        project = Path(tmp) / "project"
        project.mkdir()
        settings_path = project / ".gemini" / "settings.json"
        real_user_gemini = Path.home() / ".gemini" / "settings.json"
        user_gemini_before = (
            real_user_gemini.read_text(encoding="utf-8") if real_user_gemini.is_file() else None
        )

        setup = _run(
            [str(cli), "setup", "gemini-cli", "--project-dir", str(project), "--yes", "--json"],
            cwd=project,
            env=env,
        )
        if setup.returncode != 0:
            print(setup.stdout)
            print(setup.stderr, file=sys.stderr)
            return setup.returncode

        payload = json.loads(setup.stdout)
        assert payload["ok"] is True, payload
        assert payload["action"] == "setup-gemini-cli"
        assert payload["approval_center"]["state"] == "running"
        assert "url" not in payload["approval_center"]
        assert payload["gemini_folder_trust_required"] is True
        assert "trust" in payload["gemini_folder_trust_message"].lower()
        assert payload["status"]["status"] == "advisory"
        assert payload["status"]["hook_trust_required"] is True
        assert settings_path.is_file()
        if user_gemini_before is None:
            assert not real_user_gemini.is_file()
        else:
            assert real_user_gemini.read_text(encoding="utf-8") == user_gemini_before
        text = settings_path.read_text(encoding="utf-8")
        assert "agentveil-mcp-proxy" in text
        assert "agentveil_mcp_proxy.gemini_hook" in text
        assert (
            "write_file|replace|run_shell_command|read_file|read_many_files|"
            "list_directory|glob|grep_search|mcp_.*"
        ) in text
        assert (project / ".avp" / "mcp-proxy" / "config.json").is_file()

        status = _run(
            [str(cli), "setup", "status", "--client", "gemini-cli", "--project-dir", str(project), "--json"],
            cwd=project,
            env=env,
        )
        assert status.returncode == 0, status.stderr
        status_payload = json.loads(status.stdout)
        assert status_payload["connector"] == "gemini-cli"
        assert status_payload["hook"] == "present"
        assert status_payload["hook_state"] == "advisory"
        assert status_payload["hook_trust_required"] is True
        assert "trust" in status_payload["next_step"].lower()
        assert status_payload["mcp_route"] == "present"
        assert status_payload["approval_center"] == "running"

        remove = _run(
            [str(cli), "setup", "remove", "gemini-cli", "--project-dir", str(project), "--yes", "--json"],
            cwd=project,
            env=env,
        )
        assert remove.returncode == 0, remove.stderr
        remove_payload = json.loads(remove.stdout)
        assert remove_payload["ok"] is True
        assert remove_payload["hook_entries_removed"] == 1
        assert remove_payload["mcp_route_removed"] is True
        assert remove_payload["approval_center_stopped"] is True or not (
            project / ".avp" / "mcp-proxy" / "approval-center.manifest.json"
        ).exists()
        if settings_path.exists():
            remaining = settings_path.read_text(encoding="utf-8")
            assert "agentveil_mcp_proxy.gemini_hook" not in remaining
            assert "agentveil-mcp-proxy" not in remaining

    print("P0_9_GEMINI_SETUP_HOOK_INSTALLED_SMOKE: ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
