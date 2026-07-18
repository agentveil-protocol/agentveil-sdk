#!/usr/bin/env python3
"""P10A.9 live smoke for the stable local Approval Center product path."""

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

from agentveil_mcp_proxy.approval.persistent import load_manifest
from agentveil_mcp_proxy.cli import init_proxy, run_proxy, serve_approval_center
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from mcp_fake_downstream import fake_target_reached, tool_entry, write_downstream

SECRET = "SECRET_PERSISTENT_APPROVAL_CENTER_SMOKE"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)


def _tool_call(tool: str) -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": f"persistent-smoke-{tool}",
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"path": "workspace/smoke.txt", "secret": SECRET},
        },
    })


def _configure(
    config_path: Path,
    *,
    downstream: Path,
    log_path: Path,
    outcome_path: Path,
    fixture_id: str,
) -> None:
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
        "id": "persistent-approval-smoke",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": fixture_id,
            "source": "user",
            "decision": "approval",
            "risk_class": "write",
            "match": {"server": "fake-downstream", "tool": "write_file"},
        }],
    }
    _write_json(config_path, config)


def _assert_privacy(text: str, *, session_token: str | None = None) -> None:
    lowered = text.lower()
    assert SECRET not in text
    assert "<form" not in lowered
    assert 'name="csrf_token"' not in lowered
    if session_token:
        assert session_token not in text


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="avp-persistent-approval-smoke-") as tmp:
        root = Path(tmp)
        home = root / "home"
        init = init_proxy(home=home, agent_name="proxy", plaintext=True)
        downstream = write_downstream(
            root,
            tools=[tool_entry("write_file")],
            call_result_text="persistent-approval-smoke-ok",
            controlled_path=True,
        )
        log_path = root / "downstream.log"
        outcome_path = root / "outcome.jsonl"
        fixture_id = "smoke-persistent-approval-write"
        _configure(
            init.config_path,
            downstream=downstream,
            log_path=log_path,
            outcome_path=outcome_path,
            fixture_id=fixture_id,
        )

        serve_error = io.StringIO()
        serve_thread = threading.Thread(
            target=lambda: serve_approval_center(home=home, err=serve_error),
            name="persistent-approval-center-serve",
            daemon=True,
        )
        serve_thread.start()
        deadline = time.monotonic() + 5
        manifest = None
        while time.monotonic() < deadline:
            manifest = load_manifest(home / "mcp-proxy")
            if manifest is not None:
                break
            time.sleep(0.05)
        assert manifest is not None, serve_error.getvalue()

        pending_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("write_file")),
            out=pending_out,
            err=io.StringIO(),
            approval_ui_mode="none",
        ) == 0
        pending_response = _responses(pending_out.getvalue())[0]
        assert pending_response["error"]["data"]["status"] == "approval_required"
        assert not fake_target_reached(outcome_path)
        record_id = pending_response["error"]["data"]["record_id"]
        approval_url = f"{manifest.approval_center_url()}/pending/{record_id}"
        assert "approval_url" not in pending_response["error"]["data"]
        assert approval_url not in json.dumps(pending_response)
        assert approval_url.startswith(f"http://127.0.0.1:{manifest.port}")

        with httpx.Client() as client:
            csrf_match = CSRF_RE.search(client.get(approval_url).text)
            assert csrf_match is not None
            csrf = csrf_match.group(1)
            assert client.post(
                approval_url,
                data={
                    "decision": "approve",
                    "csrf_token": csrf,
                    "approval_scope": "exact",
                },
            ).status_code == 200

            retry_out = io.StringIO()
            assert run_proxy(
                home=home,
                client_in=io.StringIO(_tool_call("write_file")),
                out=retry_out,
                err=io.StringIO(),
                approval_ui_mode="none",
            ) == 0
            retry_response = _responses(retry_out.getvalue())[0]
            assert "result" in retry_response
            assert fake_target_reached(outcome_path)

            stale = client.get(approval_url)
            assert stale.status_code == 410
            assert "Approved" in stale.text
            assert "This request was already approved." in stale.text
            assert "Already decided" not in stale.text
            _assert_privacy(stale.text, session_token=manifest.session_token)

        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            approved = [
                record for record in store.list_records()
                if record.status == ApprovalStatus.APPROVED.value
            ]
            assert approved
            bundle = json.dumps({
                "records": [
                    {
                        "request_id": record.request_id,
                        "status": record.status,
                        "tool_name": record.tool_name,
                    }
                    for record in store.list_records()
                ],
            })
            _assert_privacy(bundle, session_token=manifest.session_token)

    print("P10A9_PERSISTENT_APPROVAL_CENTER_SMOKE: ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
