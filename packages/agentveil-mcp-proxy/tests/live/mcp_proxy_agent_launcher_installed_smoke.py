#!/usr/bin/env python3
"""P0.12 installed-path smoke: managed generic-process runtime via wheel + console script."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parents[1]
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

from installed_wheel_env import build_installed_runtime, clean_env

SECRET_COMMAND_TOKEN = "SECRET_TOKEN_DO_NOT_PERSIST_IN_INSTALLED_SMOKE"


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _write_fake_agent(project: Path) -> Path:
    script = project / "fake_agent.py"
    script.write_text(
        textwrap.dedent(
            """
            import json
            import os
            import sys
            from pathlib import Path

            runtime_home = Path(os.environ["HOME"])
            marker = Path(sys.argv[1])
            host_home = Path(sys.argv[2])
            payload = {
                "profile": os.environ["AGENTVEIL_RUNTIME_PROFILE"],
                "runtime_home_is_project_local": "/.avp/runtime/generic-process/" in str(runtime_home).replace("\\\\", "/"),
                "host_home_leaked": str(runtime_home) == str(host_home),
            }
            marker.write_text(json.dumps(payload), encoding="utf-8")
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return script


def main() -> int:
    env = clean_env()
    with tempfile.TemporaryDirectory(prefix="avp-agent-launcher-installed-smoke-") as tmp:
        original_cwd = Path.cwd()
        os.chdir(tmp)
        try:
            host_home = Path(tmp) / "operator-home"
            host_home.mkdir()
            env["HOME"] = str(host_home)

            install_root = Path(tmp) / "install"
            cli, python = build_installed_runtime(install_root)

            project = Path(tmp) / "project"
            project.mkdir()
            marker = project / "marker.json"
            fake_agent = _write_fake_agent(project)

            launch = _run(
                [
                    str(cli),
                    "launch",
                    "--profile",
                    "generic-process",
                    "--project-dir",
                    str(project),
                    "--json",
                    "--",
                    str(python),
                    str(fake_agent),
                    str(marker),
                    str(host_home),
                    f"--api-key={SECRET_COMMAND_TOKEN}",
                ],
                cwd=project,
                env=env,
            )
            if launch.returncode != 0:
                print(launch.stdout)
                print(launch.stderr, file=sys.stderr)
                return launch.returncode

            payload = json.loads(launch.stdout)
            assert payload["ok"] is True, payload
            assert payload["profile_id"] == "generic-process"
            assert payload["host_wide_control_claim"] is False
            assert SECRET_COMMAND_TOKEN not in launch.stdout

            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not marker.exists():
                time.sleep(0.05)
            assert marker.exists(), "installed fake agent did not write marker"
            marker_payload = json.loads(marker.read_text(encoding="utf-8"))
            assert marker_payload["runtime_home_is_project_local"] is True
            assert marker_payload["host_home_leaked"] is False

            manifest_path = project / ".avp" / "mcp-proxy" / "runtime-launch.manifest.json"
            route_path = project / ".avp" / "mcp-proxy" / "runtime-route.json"
            manifest_text = manifest_path.read_text(encoding="utf-8")
            route_text = route_path.read_text(encoding="utf-8")
            assert SECRET_COMMAND_TOKEN not in manifest_text
            assert SECRET_COMMAND_TOKEN not in route_text
            assert '"child_command":' not in manifest_text

            status = _run(
                [str(cli), "launch", "status", "--project-dir", str(project), "--json"],
                cwd=project,
                env=env,
            )
            assert status.returncode == 0, status.stderr
            status_payload = json.loads(status.stdout)
            assert status_payload["profile_id"] == "generic-process"
            assert SECRET_COMMAND_TOKEN not in status.stdout

            stop = _run(
                [str(cli), "launch", "stop", "--project-dir", str(project), "--json"],
                cwd=project,
                env=env,
            )
            assert stop.returncode == 0, stop.stderr
            stop_payload = json.loads(stop.stdout)
            assert stop_payload["ok"] is True
        finally:
            os.chdir(original_cwd)

    print("mcp_proxy_agent_launcher_installed_smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
