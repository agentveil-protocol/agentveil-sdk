#!/usr/bin/env python3
"""P10A.2 live smoke: fake-target controlled MCP tool path proof."""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, TESTS_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from agentveil_mcp_proxy.cli import init_proxy, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata
from mcp_fake_downstream import fake_target_reached, tool_entry, write_downstream

SECRET = "SECRET_FAKE_TARGET_SMOKE"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)


class _StagedStdin(io.TextIOBase):
    def __init__(self, lines: list[str]) -> None:
        self._lines = [
            line if line.endswith("\n") else f"{line}\n"
            for line in lines
        ]
        self._line_index = 0
        self._char_index = 0
        self._gate = threading.Event()
        self._gate.set()

    def read(self, size: int = -1) -> str:
        if size not in (-1, 1):
            raise io.UnsupportedOperation("only single-character reads are supported")
        if self._line_index >= len(self._lines):
            return ""
        self._gate.wait(timeout=30)
        if self._line_index >= len(self._lines):
            return ""
        line = self._lines[self._line_index]
        char = line[self._char_index]
        self._char_index += 1
        if self._char_index >= len(line):
            self._line_index += 1
            self._char_index = 0
            self._gate.clear()
        return char

    def release_next(self) -> None:
        self._gate.set()


def _tool_call(tool: str, *, call_id: str) -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"path": "workspace/smoke.txt", "secret": SECRET},
        },
    })


def _configure_downstream(
    config_path: Path,
    script: Path,
    *,
    log_path: Path,
    outcome_path: Path,
    fixture_id: str,
) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "fake-downstream",
        "command": sys.executable,
        "args": ["-u", str(script)],
        "env": {
            "DOWNSTREAM_LOG": str(log_path),
            "FAKE_TARGET_OUTCOME_LOG": str(outcome_path),
            "FAKE_TARGET_FIXTURE": fixture_id,
        },
    }
    _write_json(config_path, config)


def _set_policy(config_path: Path, *, decision: str, tool: str, rule_id: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "fake-target-smoke",
        "policy_schema_version": 1,
        "default_decision": "allow" if decision == "block" else "block",
        "default_risk_class": "read",
        "rules": [{
            "id": rule_id,
            "source": "user",
            "decision": decision,
            "risk_class": "write" if decision != "allow" else "read",
            "match": {"server": "fake-downstream", "tool": tool},
        }],
    }
    _write_json(config_path, config)


def _assert_private(*parts: str) -> None:
    blob = "\n".join(parts)
    assert SECRET not in blob
    assert "stdout" not in blob.lower()
    assert "stderr" not in blob.lower()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="avp-fake-target-smoke-") as tmp:
        root = Path(tmp)
        home = root / "home"
        init = init_proxy(home=home, agent_name="proxy", plaintext=True)
        log_path = root / "downstream.log"
        outcome_path = root / "outcome.jsonl"
        downstream = write_downstream(
            root,
            tools=[tool_entry("read_file"), tool_entry("write_file")],
            call_result_text="fake-target-smoke-ok",
            controlled_path=True,
        )

        # ALLOW
        allow_fixture = "smoke-allow-read"
        _configure_downstream(
            init.config_path,
            downstream,
            log_path=log_path,
            outcome_path=outcome_path,
            fixture_id=allow_fixture,
        )
        _set_policy(init.config_path, decision="allow", tool="read_file", rule_id=allow_fixture)
        allow_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("read_file", call_id="allow")),
            out=allow_out,
            approval_ui_mode="none",
        ) == 0
        allow_response = _responses(allow_out.getvalue())[0]
        assert "result" in allow_response
        assert fake_target_reached(outcome_path)

        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            allow_meta = parse_controlled_path_metadata(store.list_records()[-1])
            assert allow_meta is not None and allow_meta["target_reached"] is True

        # BLOCK
        block_fixture = "smoke-block-write"
        outcome_path.unlink(missing_ok=True)
        log_path.write_text("", encoding="utf-8")
        _set_policy(init.config_path, decision="block", tool="write_file", rule_id=block_fixture)
        block_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("write_file", call_id="block")),
            out=block_out,
            approval_ui_mode="none",
        ) == 0
        block_response = _responses(block_out.getvalue())[0]
        assert block_response["error"]["data"]["reason"] == "local_policy_block"
        assert not fake_target_reached(outcome_path)

        # APPROVAL pending + retry
        approval_fixture = "smoke-approval-write"
        outcome_path.unlink(missing_ok=True)
        log_path.write_text("", encoding="utf-8")
        _set_policy(init.config_path, decision="approval", tool="write_file", rule_id=approval_fixture)
        staged_in = _StagedStdin([
            _tool_call("write_file", call_id="approval-pending"),
            _tool_call("write_file", call_id="approval-retry"),
        ])
        approval_out = io.StringIO()
        worker = threading.Thread(
            target=lambda: run_proxy(
                home=home,
                client_in=staged_in,
                out=approval_out,
                approval_ui_mode="none",
            ),
            daemon=True,
        )
        worker.start()
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not approval_out.getvalue().strip():
                time.sleep(0.02)
            responses = _responses(approval_out.getvalue())
            pending = responses[0]
            assert pending["error"]["data"]["status"] == "approval_required"
            assert not fake_target_reached(outcome_path)

            approval_url = pending["error"]["data"]["approval_url"]
            with httpx.Client() as client:
                page = client.get(approval_url)
                page.raise_for_status()
                match = CSRF_RE.search(page.text)
                if match is None:
                    raise RuntimeError("CSRF token missing from approval page")
                client.post(approval_url, data={
                    "decision": "approve",
                    "approval_scope": "exact",
                    "csrf_token": match.group(1),
                }).raise_for_status()

            record_id = pending["error"]["data"]["record_id"]
            with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
                approved_deadline = time.monotonic() + 5
                record = store.get_pending(record_id)
                while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < approved_deadline:
                    time.sleep(0.02)
                    record = store.get_pending(record_id)
                assert record.status == ApprovalStatus.APPROVED.value

            staged_in.release_next()
            worker.join(timeout=10)
            if worker.is_alive():
                raise RuntimeError("proxy did not finish approval retry")

            retry_responses = _responses(approval_out.getvalue())
            assert len(retry_responses) == 2
            assert "result" in retry_responses[1]
            assert fake_target_reached(outcome_path)

            with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
                executed = [
                    row for row in store.list_records()
                    if row.status == ApprovalStatus.EXECUTED.value
                ]
                assert len(executed) >= 1
                retry_meta = parse_controlled_path_metadata(executed[-1])
                assert retry_meta is not None and retry_meta["target_reached"] is True
                bundle_text = json.dumps({
                    "records": [parse_controlled_path_metadata(row) for row in store.list_records()],
                })
                _assert_private(
                    outcome_path.read_text(encoding="utf-8") if outcome_path.exists() else "",
                    bundle_text,
                    approval_out.getvalue(),
                )
        finally:
            staged_in.release_next()
            worker.join(timeout=1)

    print("P10A2_FAKE_TARGET_CONTROLLED_PATH_SMOKE: ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
