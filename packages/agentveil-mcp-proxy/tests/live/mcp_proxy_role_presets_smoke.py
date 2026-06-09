#!/usr/bin/env python3
"""P10A.4 live smoke: init role presets without hand-edited role_authority JSON."""

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

from agentveil_mcp_proxy.cli import main as cli_main, proxy_paths, run_proxy
from agentveil_mcp_proxy.client_config import build_run_args, read_role_preset_from_config
from mcp_fake_downstream import fake_target_reached, tool_entry, write_downstream

SECRET = "SECRET_ROLE_PRESET_SMOKE"


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
    tool: str,
) -> None:
    downstream = write_downstream(
        root,
        tools=[tool_entry("read_file"), tool_entry("write_file")],
        call_result_text="role-preset-smoke-ok",
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
        "id": "role-preset-smoke",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": fixture_id,
            "source": "user",
            "decision": "allow",
            "risk_class": "write" if tool == "write_file" else "read",
            "match": {"server": "fake-downstream", "tool": tool},
        }],
    }
    _write_json(config_path, config)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="avp-role-preset-smoke-") as tmp:
        root = Path(tmp)
        home = root / "home"

        assert cli_main([
            "init",
            "--role", "reviewer",
            "--home", str(home),
            "--agent-name", "proxy",
            "--plaintext",
        ]) == 0
        paths = proxy_paths(home)
        config = json.loads(paths.config_path.read_text(encoding="utf-8"))
        assert config["role_preset"] == "reviewer"
        assert config["role_authority"]["role"] == "reviewer"
        assert SECRET not in paths.config_path.read_text(encoding="utf-8")

        run_args = build_run_args(home=home, config_path=paths.config_path)
        assert "--config" in run_args
        assert str(paths.config_path) in run_args
        assert read_role_preset_from_config(paths.config_path) == "reviewer"

        log_path = root / "downstream.log"
        outcome_path = root / "outcome.jsonl"
        _attach_fake_downstream(
            paths.config_path,
            root=root,
            log_path=log_path,
            outcome_path=outcome_path,
            fixture_id="smoke-reviewer-write",
            tool="write_file",
        )
        block_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("write_file")),
            out=block_out,
            approval_ui_mode="none",
        ) == 0
        assert _responses(block_out.getvalue())[0]["error"]["data"]["reason"] == "role_authority_denied"
        assert not fake_target_reached(outcome_path)

        shutil.rmtree(home)
        assert cli_main([
            "init",
            "--role", "readonly",
            "--home", str(home),
            "--agent-name", "proxy",
            "--plaintext",
        ]) == 0
        paths = proxy_paths(home)
        outcome_path.unlink(missing_ok=True)
        log_path.write_text("", encoding="utf-8")
        _attach_fake_downstream(
            paths.config_path,
            root=root,
            log_path=log_path,
            outcome_path=outcome_path,
            fixture_id="smoke-readonly-write",
            tool="write_file",
        )
        readonly_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("write_file")),
            out=readonly_out,
            approval_ui_mode="none",
        ) == 0
        assert _responses(readonly_out.getvalue())[0]["error"]["data"]["reason"] == "role_authority_denied"
        assert not fake_target_reached(outcome_path)

        shutil.rmtree(home)
        assert cli_main([
            "init",
            "--role", "implementer",
            "--home", str(home),
            "--agent-name", "proxy",
            "--plaintext",
        ]) == 0
        paths = proxy_paths(home)
        outcome_path.unlink(missing_ok=True)
        log_path.write_text("", encoding="utf-8")
        _attach_fake_downstream(
            paths.config_path,
            root=root,
            log_path=log_path,
            outcome_path=outcome_path,
            fixture_id="smoke-implementer-write",
            tool="write_file",
        )
        allow_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("write_file")),
            out=allow_out,
            approval_ui_mode="none",
        ) == 0
        assert "result" in _responses(allow_out.getvalue())[0]
        assert fake_target_reached(outcome_path)

    print("P10A4_ROLE_PRESETS_SMOKE: ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
