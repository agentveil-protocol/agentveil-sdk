#!/usr/bin/env python3
"""P0.13b source smoke: Hermes config bootstrap + AgentVeil MCP approval path.

Simulates what Hermes CLI would do after reading project-local config.yaml:
spawn the configured AgentVeil stdio MCP server, discover tools, perform a
risky write through approval, verify target reached, and call local_proof.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, TESTS_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from agentveil_mcp_proxy.agent_launcher import (  # noqa: E402
    HERMES_HOME_ENV,
    HERMES_MCP_SERVER_NAME,
    ensure_approval_center_running,
    hermes_runtime_home,
    parse_hermes_agentveil_stdio_config,
    prepare_hermes_cli_command,
    project_avp_home,
    verify_hermes_config_bootstrap,
    write_hermes_config,
)
from agentveil_mcp_proxy.cli import _launch_init_proxy  # noqa: E402
from agentveil_mcp_proxy.approval.persistent import load_manifest  # noqa: E402
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus  # noqa: E402
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata  # noqa: E402

PROOF_FILENAME = "hermes-agentveil-proof.txt"
PROOF_CONTENT = "HERMES_AGENTVEIL_PROOF"
SECRET = "SECRET_HERMES_CLI_SMOKE"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
SENTINEL = "P0_13B_HERMES_CLI_SOURCE_SMOKE_OK"


def _source_pythonpath() -> str:
    proxy_root = ROOT
    repo_root = proxy_root.parents[1]
    parts = [str(repo_root), str(proxy_root)]
    existing = os.environ.get("PYTHONPATH", "")
    if existing:
        parts.append(existing)
    return os.pathsep.join(parts)


def _json_line(message: dict[str, Any]) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _read_json_line(stream) -> dict[str, Any]:
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("unexpected EOF from AgentVeil MCP subprocess")
        line = line.strip()
        if line:
            return json.loads(line)


def _set_write_file_policy(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "hermes-cli-smoke",
        "policy_schema_version": 1,
        "default_decision": "block",
        "default_risk_class": "read",
        "rules": [
            {
                "id": "hermes-smoke-write",
                "source": "user",
                "decision": "approval",
                "risk_class": "write",
                "match": {"server": "filesystem", "tool": "write_file"},
            },
            {
                "id": "hermes-smoke-proof",
                "source": "user",
                "decision": "allow",
                "risk_class": "read",
                "match": {"server": "filesystem", "tool": "local_proof"},
            },
        ],
    }
    tmp = config_path.with_name(f".{config_path.name}.tmp")
    tmp.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, config_path)


def _tool_call(tool: str, *, call_id: str, arguments: dict[str, Any]) -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    })


def _assert_hermes_config_uses_python_module_route(hermes_home: Path, *, expected_command: str) -> None:
    route = parse_hermes_agentveil_stdio_config(hermes_home)
    assert route["command"] == expected_command
    assert route["args"][:2] == ["-m", "agentveil_mcp_proxy.cli"]
    assert route["args"][2] == "run"
    stale_global_suffix = f"{os.sep}.local{os.sep}bin{os.sep}agentveil-mcp-proxy"
    assert stale_global_suffix not in route["command"]
    assert Path(route["command"]).name.startswith("python")


def _spawn_agentveil_from_hermes_config(
    hermes_home: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.Popen[str]:
    route = parse_hermes_agentveil_stdio_config(hermes_home)
    env = os.environ.copy()
    env.update(route["env"])
    env[HERMES_HOME_ENV] = str(hermes_home)
    env["PYTHONPATH"] = _source_pythonpath()
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(  # noqa: S603
        [route["command"], *route["args"]],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        close_fds=True,
    )


def _initialize_session(process: subprocess.Popen[str]) -> list[str]:
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(_json_line({
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "hermes-cli-fake", "version": "smoke"},
        },
    }))
    process.stdin.flush()
    init_response = _read_json_line(process.stdout)
    assert "result" in init_response, init_response
    process.stdin.write(_json_line({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    process.stdin.flush()
    process.stdin.write(_json_line({"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}}))
    process.stdin.flush()
    list_response = _read_json_line(process.stdout)
    assert "result" in list_response, list_response
    tool_names = [item["name"] for item in list_response["result"].get("tools", [])]
    assert "write_file" in tool_names, tool_names
    assert "local_proof" in tool_names, tool_names
    return tool_names


def _assert_bounded(text: str) -> None:
    for forbidden in (SECRET, "/Users/", "stdout", "stderr"):
        assert forbidden not in text, f"bounded output leak: {forbidden!r}"


def _approve_via_center(approval_url: str, record_id: str, home: Path) -> None:
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

    with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
        deadline = time.monotonic() + 8.0
        record = store.get_pending(record_id)
        while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
            time.sleep(0.05)
            record = store.get_pending(record_id)
        assert record.status == ApprovalStatus.APPROVED.value


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="avp-hermes-cli-smoke-") as tmp:
        root = Path(tmp)
        project = root / "project"
        project.mkdir()
        home = project_avp_home(project)
        session_id = "hermes-cli-smoke"

        _launch_init_proxy(
            home=home,
            policy_pack="filesystem",
            downstream_root=project,
            passphrase_file=None,
        )
        _set_write_file_policy(home / "mcp-proxy" / "config.json")

        proxy_command = sys.executable
        center, _, center_reason = ensure_approval_center_running(
            home=home,
            proxy_command=proxy_command,
        )
        if center.state != "running":
            raise RuntimeError(f"approval center unavailable: {center_reason}")

        config_path = home / "mcp-proxy" / "config.json"
        run_args = ["run", "--home", str(home), "--config", str(config_path)]
        hermes_home = hermes_runtime_home(home, "hermes-cli", session_id)
        write_hermes_config(
            hermes_home=hermes_home,
            proxy_command=proxy_command,
            run_args=run_args,
            avp_home=home,
        )
        verify_hermes_config_bootstrap(hermes_home)
        _assert_hermes_config_uses_python_module_route(
            hermes_home,
            expected_command=proxy_command,
        )

        child_argv = prepare_hermes_cli_command([
            "hermes",
            "chat",
            "-q",
            f"write proof file with secret {SECRET}",
        ])
        assert child_argv[2:4] == ["--toolsets", HERMES_MCP_SERVER_NAME]
        assert "mcp-agentveil" not in child_argv

        process = _spawn_agentveil_from_hermes_config(hermes_home)
        try:
            _initialize_session(process)
            assert process.stdin is not None
            assert process.stdout is not None

            write_args = {"path": PROOF_FILENAME, "content": PROOF_CONTENT}
            process.stdin.write(_tool_call("write_file", call_id="write-pending", arguments=write_args))
            process.stdin.flush()
            pending = _read_json_line(process.stdout)
            assert "error" in pending, pending
            assert pending["error"]["data"]["status"] == "approval_required"
            assert not (project / PROOF_FILENAME).exists()

            record_id = pending["error"]["data"]["record_id"]
            manifest = load_manifest(home / "mcp-proxy")
            assert manifest is not None
            approval_url = f"{manifest.approval_center_url()}/pending/{record_id}"
            assert approval_url not in json.dumps(pending)
            _approve_via_center(approval_url, record_id, home)

            process.stdin.write(_tool_call("write_file", call_id="write-retry", arguments=write_args))
            process.stdin.flush()
            approved = _read_json_line(process.stdout)
            assert "result" in approved, approved
            assert (project / PROOF_FILENAME).read_text(encoding="utf-8") == PROOF_CONTENT

            process.stdin.write(_tool_call(
                "local_proof",
                call_id="local-proof",
                arguments={"format": "text", "last": 5, "verify": True},
            ))
            process.stdin.flush()
            proof_response = _read_json_line(process.stdout)
            assert "result" in proof_response, proof_response
            proof_text = proof_response["result"]["content"][0]["text"]
            assert proof_text.startswith("AgentVeil proof"), proof_text[:200]
            assert "Verification:" in proof_text, proof_text[:400]
            assert (
                "target reached" in proof_text.lower()
                or "write approved and completed" in proof_text.lower()
            ), proof_text[:600]
            _assert_bounded(proof_text)

            with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
                matches = [
                    meta
                    for record in store.list_records()
                    if (meta := parse_controlled_path_metadata(record)) is not None
                    and meta.get("tool") == "write_file"
                    and meta.get("target_reached") is True
                ]
                assert matches, "expected controlled-path metadata with target_reached=true"
                proof_meta = matches[0]
                assert proof_meta.get("policy_decision") == "approval"
                assert proof_meta.get("execution_status") == ApprovalStatus.EXECUTED.value

        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()

        summary = {
            "ok": True,
            "profile_id": "hermes-cli",
            "hermes_home_set": True,
            "mcp_server": HERMES_MCP_SERVER_NAME,
            "toolset": HERMES_MCP_SERVER_NAME,
            "approval_path": "pass",
            "target_reached": True,
            "local_proof": "mcp_tools_call",
            "native_tool_containment": "limited_not_live_verified",
        }
        rendered = json.dumps(summary, sort_keys=True)
        _assert_bounded(rendered)
        print(f"{SENTINEL}: {rendered}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
