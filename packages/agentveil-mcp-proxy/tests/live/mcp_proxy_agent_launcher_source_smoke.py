#!/usr/bin/env python3
"""P0.12 source-tree smoke: managed generic-process runtime launch without connector edits."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, TESTS_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from agentveil_mcp_proxy.agent_launcher import launch_manifest_path, runtime_route_path
from agentveil_mcp_proxy.cli import main as cli_main

SECRET_COMMAND_TOKEN = "SECRET_TOKEN_DO_NOT_PERSIST_IN_SOURCE_SMOKE"
CONNECTOR_PATHS = (
    ".mcp.json",
    ".claude/settings.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    ".cursor/mcp.json",
)


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _write_fake_agent(project: Path) -> Path:
    script = project / "fake_agent.py"
    script.write_text(
        textwrap.dedent(
            """
            import json
            import os
            import sys
            from pathlib import Path

            required = [
                "AGENTVEIL_AVP_HOME",
                "AGENTVEIL_MCP_PROXY_COMMAND",
                "AGENTVEIL_MCP_PROXY_RUN_ARGS",
                "AGENTVEIL_RUNTIME_PROFILE",
                "HOME",
            ]
            missing = [key for key in required if not os.environ.get(key)]
            if missing:
                raise SystemExit(f"missing env: {missing}")
            runtime_home = Path(os.environ["HOME"])
            marker = Path(sys.argv[1])
            host_home = Path(sys.argv[2])
            payload = {
                "profile": os.environ["AGENTVEIL_RUNTIME_PROFILE"],
                "runtime_home": str(runtime_home),
                "runtime_home_is_project_local": "/.avp/runtime/generic-process/" in str(runtime_home).replace("\\\\", "/"),
                "host_home_leaked": str(runtime_home) == str(host_home),
            }
            marker.write_text(json.dumps(payload), encoding="utf-8")
            print("fake-agent-ok")
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return script


def _assert_connectors_untouched(project: Path) -> None:
    for rel in CONNECTOR_PATHS:
        assert not (project / rel).exists(), f"connector file touched: {rel}"


def _http_reachable(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="avp-agent-launcher-source-smoke-") as tmp:
        host_home = Path(tmp) / "operator-home"
        host_home.mkdir()
        os.environ["HOME"] = str(host_home)

        project = Path(tmp) / "project"
        project.mkdir()
        marker = project / "fake-agent-marker.json"
        fake_agent = _write_fake_agent(project)
        launch_base = [
            "launch",
            "--profile",
            "generic-process",
            "--project-dir",
            str(project),
            "--json",
            "--",
        ]

        assert (
            cli_main([
                *launch_base,
                sys.executable,
                str(fake_agent),
                str(marker),
                str(host_home),
                f"--api-key={SECRET_COMMAND_TOKEN}",
            ])
            == 0
        ), "fake process launch failed"

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.05)
        assert marker.exists(), "fake agent did not write marker"
        payload = json.loads(marker.read_text(encoding="utf-8"))
        assert payload["profile"] == "generic-process"
        assert payload["runtime_home_is_project_local"] is True
        assert payload["host_home_leaked"] is False
        manifest_text = launch_manifest_path(project / ".avp").read_text(encoding="utf-8")
        route_text = runtime_route_path(project / ".avp").read_text(encoding="utf-8")
        assert SECRET_COMMAND_TOKEN not in manifest_text
        assert SECRET_COMMAND_TOKEN not in route_text
        _assert_connectors_untouched(project)

        port = _pick_free_port()
        assert (
            cli_main([
                *launch_base,
                sys.executable,
                "-m",
                "http.server",
                str(port),
            ])
            == 0
        ), "http.server launch failed"

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not _http_reachable(port):
            time.sleep(0.05)
        assert _http_reachable(port), "http.server did not become reachable"

        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            assert cli_main(["launch", "status", "--project-dir", str(project), "--json"]) == 0
        status_payload = json.loads(buffer.getvalue())
        assert status_payload["child_running"] is True
        assert status_payload["approval_center"]["state"] == "running"
        assert SECRET_COMMAND_TOKEN not in json.dumps(status_payload)

        assert cli_main(["launch", "stop", "--project-dir", str(project), "--json"]) == 0

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _http_reachable(port):
            time.sleep(0.05)
        assert not _http_reachable(port), "managed http.server still reachable after stop"

    print("mcp_proxy_agent_launcher_source_smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
