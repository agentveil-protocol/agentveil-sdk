#!/usr/bin/env python3
"""P10A.5 live smoke: explain/redirect guidance and role doctor CLI."""

from __future__ import annotations

import io
import json
import os
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
from mcp_fake_downstream import fake_target_reached, tool_entry, write_downstream

SECRET = "SECRET_ROLE_DOCTOR_SMOKE"


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _tool_call(tool: str) -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": f"smoke-{tool}",
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"path": "workspace/smoke.txt", "secret": SECRET},
        },
    })


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)


def _attach_fake_downstream(
    config_path: Path,
    *,
    root: Path,
    log_path: Path,
    outcome_path: Path,
    fixture_id: str,
) -> None:
    downstream = write_downstream(
        root,
        tools=[tool_entry("write_file")],
        controlled_path=True,
    )
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "fake-downstream",
        "command": sys.executable,
        "args": ["-u", str(downstream)],
        "env": {
            "DOWNSTREAM_LOG": str(log_path),
            "FAKE_TARGET_OUTCOME_LOG": str(outcome_path),
            "FAKE_TARGET_FIXTURE": fixture_id,
        },
    }
    config["policy"] = {
        "id": "role-doctor-smoke",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": fixture_id,
            "source": "user",
            "decision": "allow",
            "risk_class": "write",
            "match": {"server": "fake-downstream", "tool": "write_file"},
        }],
    }
    _write_json(config_path, config)


def main() -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="avp-role-doctor-smoke-"))
    try:
        home = temp_root / "home"
        log_path = temp_root / "downstream.log"
        outcome_path = temp_root / "outcome.jsonl"

        assert cli_main([
            "init",
            "--role", "reviewer",
            "--home", str(home),
            "--agent-name", "proxy",
            "--plaintext",
        ]) == 0

        config_path = home / "mcp-proxy" / "config.json"
        _attach_fake_downstream(
            config_path,
            root=temp_root,
            log_path=log_path,
            outcome_path=outcome_path,
            fixture_id="role-doctor-smoke-reviewer",
        )

        assert cli_main([
            "explain",
            "role",
            "--home", str(home),
            "--config", str(config_path),
        ]) == 0

        client_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("write_file")),
            out=client_out,
            approval_ui_mode="none",
        ) == 0

        response = _responses(client_out.getvalue())[0]
        data = response["error"]["data"]
        assert data["reason"] == "role_authority_denied"
        assert "Review Agent cannot write files" in data["explanation"]
        assert data["redirect_playbook_id"] == "create_implementer_task"
        assert not fake_target_reached(outcome_path)
        assert SECRET not in client_out.getvalue()

        print("P10A5_ROLE_DOCTOR_SMOKE: ok")
        return 0
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
