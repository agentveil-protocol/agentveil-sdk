#!/usr/bin/env python3
"""P10A.7 live smoke: config wizard routes MCP tools through the proxy."""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, TESTS_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from agentveil_mcp_proxy.cli import main as cli_main, run_proxy
from agentveil_mcp_proxy.config_wizard import build_safe_config_wizard_result

SECRET = "SECRET_CONFIG_WIZARD_SMOKE"


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _write_call() -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "wizard-smoke-write",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "smoke.txt", "content": "smoke-ok"},
        },
    })


def _list_call() -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "wizard-smoke-list",
        "method": "tools/call",
        "params": {"name": "list_workspace", "arguments": {}},
    })


def main() -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="avp-config-wizard-smoke-"))
    try:
        review_home = temp_root / "review-home"
        review_sandbox = temp_root / "review-sandbox"
        build_home = temp_root / "build-home"
        build_sandbox = temp_root / "build-sandbox"

        assert cli_main([
            "wizard",
            "print",
            "--template",
            "review",
            "--home",
            str(review_home),
            "--sandbox",
            str(review_sandbox),
            "--init",
        ]) == 0

        review_result = build_safe_config_wizard_result(
            "review",
            home=review_home,
            sandbox_root=review_sandbox,
            ensure_initialized=False,
        )
        review_entry = review_result.rendered["cursor"]["mcpServers"]["agentveil-mcp-proxy"]
        assert review_entry["args"][0] == "run"
        assert "quickstart_filesystem" not in json.dumps(review_result.rendered)

        review_out = io.StringIO()
        assert run_proxy(
            home=review_home,
            config_path=review_result.config_path,
            client_in=io.StringIO(_write_call()),
            out=review_out,
            approval_ui_mode="none",
        ) == 0
        review_data = _responses(review_out.getvalue())[0]["error"]["data"]
        assert review_data["reason"] == "role_authority_denied"

        assert cli_main([
            "wizard",
            "print",
            "--template",
            "build",
            "--home",
            str(build_home),
            "--sandbox",
            str(build_sandbox),
            "--init",
        ]) == 0
        build_result = build_safe_config_wizard_result(
            "build",
            home=build_home,
            sandbox_root=build_sandbox,
            ensure_initialized=False,
        )
        build_out = io.StringIO()
        assert run_proxy(
            home=build_home,
            config_path=build_result.config_path,
            client_in=io.StringIO(_list_call()),
            out=build_out,
            approval_ui_mode="none",
        ) == 0
        assert "error" not in _responses(build_out.getvalue())[0]

        unsafe_path = temp_root / "unsafe-mcp.json"
        unsafe_path.write_text(json.dumps({
            "mcpServers": {
                "filesystem": {
                    "command": sys.executable,
                    "args": ["quickstart_filesystem.py", str(build_sandbox)],
                }
            }
        }), encoding="utf-8")
        assert cli_main(["wizard", "validate", "--input", str(unsafe_path)]) == 2

        combined = review_out.getvalue() + build_out.getvalue()
        assert SECRET not in combined

        print("P10A7_CONFIG_WIZARD_SMOKE: ok")
        return 0
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
