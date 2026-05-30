#!/usr/bin/env python3
"""Local P6 approval UX smoke for the MCP proxy.

This script starts the approval server and a fake downstream MCP server,
triggers a local approval-required ``tools/call``, submits an approval through
the authenticated loopback HTTP flow, and verifies that the downstream call
resumes with durable evidence written.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import time

import httpx

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentveil_mcp_proxy.approval import ApprovalManager, ApprovalServer
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough
from agentveil_mcp_proxy.policy import ProxyConfig


CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def write_downstream(tmp_path: Path, log_path: Path) -> Path:
    script = tmp_path / "approval_smoke_downstream.py"
    script.write_text(
        """
import json
import os
import sys

log_path = os.environ["DOWNSTREAM_LOG"]
for line in sys.stdin:
    msg = json.loads(line)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(msg.get("method", "") + "\\n")
    if "id" not in msg:
        continue
    print(json.dumps({
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {"content": [{"type": "text", "text": "approval-smoke-ok"}]},
    }), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def config() -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
        },
        "mode": "protect",
        "privacy": {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "fallback": {
            "read": "allow",
            "write": "approval",
            "destructive": "block",
            "production": "block",
            "financial": "block",
            "unknown": "approval",
        },
        "approval": {"approval_timeout_seconds": 30, "on_timeout": "deny"},
        "policy": {
            "id": "approval-smoke",
            "policy_schema_version": 1,
            "default_decision": "approval",
            "default_risk_class": "write",
            "rules": [],
        },
        "downstream": {},
    })


def submit_approval(server: ApprovalServer) -> str:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        prompts = server.pending_prompts()
        if prompts:
            prompt = prompts[0]
            url = server.approval_url(prompt.request_id)
            with httpx.Client() as client:
                page = client.get(url)
                page.raise_for_status()
                match = CSRF_RE.search(page.text)
                if match is None:
                    raise RuntimeError("CSRF token missing from approval page")
                response = client.post(url, data={
                    "decision": "approve",
                    "approval_scope": "exact",
                    "csrf_token": match.group(1),
                })
                response.raise_for_status()
            return prompt.request_id
        time.sleep(0.02)
    raise RuntimeError("timed out waiting for approval prompt")


def main() -> int:
    tmp_path = Path(tempfile.mkdtemp(prefix="avp-mcp-approval-smoke-"))
    cfg = config()
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer()
    server.start()
    log_path = tmp_path / "downstream.log"
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=cfg,
        client_id="approval-smoke:pid",
        session_id="approval-smoke-session",
        cli_out=io.StringIO(),
        browser_open=lambda _url: False,
    )
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(write_downstream(tmp_path, log_path))),
            name="github",
            env={"DOWNSTREAM_LOG": str(log_path)},
        ),
        classifier=ToolCallClassifier(cfg, server_name="github"),
        approval_manager=manager,
    )
    client_out = io.StringIO()
    request = json.dumps({
        "jsonrpc": "2.0",
        "id": "approval-smoke-call",
        "method": "tools/call",
        "params": {
            "name": "create_issue",
            "arguments": {"owner": "agentveil", "repo": "smoke", "title": "approval smoke"},
        },
    }, separators=(",", ":")) + "\n"
    worker = threading.Thread(
        target=lambda: passthrough.run_stdio(io.StringIO(request), client_out),
        daemon=True,
    )
    worker.start()
    try:
        request_id = submit_approval(server)
        worker.join(timeout=5)
        if worker.is_alive():
            raise RuntimeError("passthrough did not finish after approval")
        responses = [json.loads(line) for line in client_out.getvalue().splitlines()]
        if responses[0]["result"]["content"][0]["text"] != "approval-smoke-ok":
            raise RuntimeError("downstream response mismatch")
        record = store.get_pending(request_id)
        if record is None or record.status != ApprovalStatus.EXECUTED.value:
            raise RuntimeError("approval evidence was not marked executed")
        if log_path.read_text(encoding="utf-8").splitlines() != ["tools/call"]:
            raise RuntimeError("downstream call log mismatch")
        print(f"P6_APPROVAL_SMOKE: ok db={store.db_path} request_id={request_id}", flush=True)
        return 0
    finally:
        passthrough.stop()
        server.stop()
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
