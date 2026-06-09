#!/usr/bin/env python3
"""P10A.3 live smoke for role/authority policy gate on brokered MCP tools/call."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, TESTS_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from agentveil_mcp_proxy.cli import init_proxy, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata
from agentveil_mcp_proxy.evidence.proof import verify_evidence_bundle
from mcp_fake_downstream import fake_target_reached, tool_entry, write_downstream

SECRET = "SECRET_ROLE_AUTHORITY_SMOKE"


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
        "id": f"role-smoke-{tool}",
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"path": "workspace/smoke.txt", "secret": SECRET},
        },
    })


def _find_controlled_path_metadata(
    records: list,
    *,
    tool: str,
    target_reached: bool,
    policy_decision: str,
    execution_status: str,
) -> dict:
    matches: list[dict] = []
    for record in records:
        metadata = parse_controlled_path_metadata(record)
        if metadata is None:
            continue
        if metadata.get("tool") != tool:
            continue
        if metadata.get("target_reached") is not target_reached:
            continue
        if metadata.get("policy_decision") != policy_decision:
            continue
        if metadata.get("execution_status") != execution_status:
            continue
        matches.append(metadata)
    assert len(matches) == 1, (
        f"expected one metadata match for tool={tool!r}, target_reached={target_reached}, "
        f"policy_decision={policy_decision!r}, execution_status={execution_status!r}; "
        f"got {len(matches)}"
    )
    return matches[0]


def _configure(
    config_path: Path,
    *,
    downstream: Path,
    log_path: Path,
    outcome_path: Path,
    fixture_id: str,
    role: str,
    authority: str,
    tool: str,
) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["role_authority"] = {"mode": "enforce", "role": role, "authority": authority}
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
        "id": "role-authority-smoke",
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
    with tempfile.TemporaryDirectory(prefix="avp-role-authority-smoke-") as tmp:
        root = Path(tmp)
        home = root / "home"
        init = init_proxy(home=home, agent_name="proxy", plaintext=True)
        downstream = write_downstream(
            root,
            tools=[tool_entry("read_file"), tool_entry("write_file")],
            call_result_text="role-authority-smoke-ok",
            controlled_path=True,
        )
        log_path = root / "downstream.log"
        outcome_path = root / "outcome.jsonl"

        _configure(
            init.config_path,
            downstream=downstream,
            log_path=log_path,
            outcome_path=outcome_path,
            fixture_id="smoke-reviewer-write-block",
            role="reviewer",
            authority="review_only",
            tool="write_file",
        )
        block_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("write_file")),
            out=block_out,
            approval_ui_mode="none",
        ) == 0
        block_response = _responses(block_out.getvalue())[0]
        assert block_response["error"]["data"]["reason"] == "role_authority_denied"
        assert not fake_target_reached(outcome_path)

        outcome_path.unlink(missing_ok=True)
        log_path.write_text("", encoding="utf-8")
        _configure(
            init.config_path,
            downstream=downstream,
            log_path=log_path,
            outcome_path=outcome_path,
            fixture_id="smoke-reviewer-read-allow",
            role="reviewer",
            authority="review_only",
            tool="read_file",
        )
        allow_out = io.StringIO()
        assert run_proxy(
            home=home,
            client_in=io.StringIO(_tool_call("read_file")),
            out=allow_out,
            approval_ui_mode="none",
        ) == 0
        allow_response = _responses(allow_out.getvalue())[0]
        assert "result" in allow_response
        assert fake_target_reached(outcome_path)

        with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
            records = store.list_records()
            assert len(records) >= 2
            denied = _find_controlled_path_metadata(
                records,
                tool="write_file",
                target_reached=False,
                policy_decision="block",
                execution_status="not_reached",
            )
            allowed = _find_controlled_path_metadata(
                records,
                tool="read_file",
                target_reached=True,
                policy_decision="allow",
                execution_status="executed",
            )
            assert denied["role"] == "reviewer"
            assert denied["authority"] == "review_only"
            assert denied["action_family"] == "write"
            assert allowed["role"] == "reviewer"
            assert allowed["authority"] == "review_only"
            assert allowed["action_family"] == "read"
            from agentveil_mcp_proxy.evidence import build_evidence_bundle
            bundle = build_evidence_bundle(store, proxy_identity_did=None, trusted_signer_dids=[])
            verify_evidence_bundle(bundle, trusted_signer_dids=[], strict=True)
            rendered = json.dumps(bundle)
            assert SECRET not in rendered

    print("P10A3_ROLE_AUTHORITY_POLICY_SMOKE: ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
