#!/usr/bin/env python3
"""P10A.6 live smoke: one-command review/build/readonly agent templates."""

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

from agentveil_mcp_proxy.agent_templates import build_template_commands
from agentveil_mcp_proxy.cli import main as cli_main, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata

SECRET = "SECRET_AGENT_TEMPLATE_SMOKE"


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _write_call() -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "template-smoke-write",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "smoke.txt", "content": "smoke-ok"},
        },
    })


def _list_call() -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "template-smoke-list",
        "method": "tools/call",
        "params": {"name": "list_workspace", "arguments": {}},
    })


def _evidence_store(home: Path) -> ApprovalEvidenceStore:
    return ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite")


def main() -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="avp-agent-template-smoke-"))
    try:
        review_home = temp_root / "review-home"
        review_sandbox = temp_root / "review-sandbox"
        build_home = temp_root / "build-home"
        build_sandbox = temp_root / "build-sandbox"
        readonly_home = temp_root / "readonly-home"
        readonly_sandbox = temp_root / "readonly-sandbox"

        review_plan = build_template_commands(
            "review",
            home=review_home,
            sandbox_root=review_sandbox,
        )
        build_plan = build_template_commands(
            "build",
            home=build_home,
            sandbox_root=build_sandbox,
        )
        readonly_plan = build_template_commands(
            "readonly",
            home=readonly_home,
            sandbox_root=readonly_sandbox,
        )

        for plan in (review_plan, build_plan, readonly_plan):
            assert cli_main(list(plan.commands[0].argv)) == 0
            assert cli_main(list(plan.commands[1].argv)) == 0

        review_out = io.StringIO()
        assert run_proxy(
            home=review_home,
            config_path=review_plan.config_path,
            client_in=io.StringIO(_write_call()),
            out=review_out,
            approval_ui_mode="none",
        ) == 0
        review_response = _responses(review_out.getvalue())[0]
        assert review_response["error"]["data"]["reason"] == "role_authority_denied"
        with _evidence_store(review_home) as store:
            assert parse_controlled_path_metadata(store.list_records()[0])["target_reached"] is False

        readonly_out = io.StringIO()
        assert run_proxy(
            home=readonly_home,
            config_path=readonly_plan.config_path,
            client_in=io.StringIO(_write_call()),
            out=readonly_out,
            approval_ui_mode="none",
        ) == 0
        readonly_response = _responses(readonly_out.getvalue())[0]
        assert readonly_response["error"]["data"]["reason"] == "role_authority_denied"

        build_out = io.StringIO()
        assert run_proxy(
            home=build_home,
            config_path=build_plan.config_path,
            client_in=io.StringIO(_list_call()),
            out=build_out,
            approval_ui_mode="none",
        ) == 0
        build_response = _responses(build_out.getvalue())[0]
        assert "error" not in build_response
        with _evidence_store(build_home) as store:
            assert parse_controlled_path_metadata(store.list_records()[-1])["target_reached"] is True

        combined = review_out.getvalue() + readonly_out.getvalue() + build_out.getvalue()
        assert SECRET not in combined

        print("P10A6_AGENT_TEMPLATES_SMOKE: ok")
        return 0
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
