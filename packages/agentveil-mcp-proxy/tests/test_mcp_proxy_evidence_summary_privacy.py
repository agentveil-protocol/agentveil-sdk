"""Privacy tests for default agentveil-mcp-proxy evidence CLI output."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import evidence_summary, init_proxy, list_events, proxy_paths, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore
from agentveil_mcp_proxy.evidence.summary import (
    assert_bounded_evidence_cli_output,
    evidence_summary_record,
    privacy_markers_in_text,
)
from agentveil_mcp_proxy.passthrough import JSONRPC_POLICY_BLOCKED

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SDK_ROOT = PACKAGE_ROOT.parent.parent


def _clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)


def _set_downstream(config_path: Path, script: Path, *, log_path: Path | None = None) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    env = {}
    if log_path is not None:
        env["DOWNSTREAM_LOG"] = str(log_path)
    config["downstream"] = {
        "name": "fake-downstream",
        "command": sys.executable,
        "args": ["-u", str(script), "/Users/example/tmp/leak-root", "/tmp/evidence-leak"],
        "env": {"SECRET_TOKEN": "must-not-leak", "DOWNSTREAM_LOG": str(log_path or "")},
    }
    _write_json(config_path, config)


def _normal_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "fake_downstream.py"
    script.write_text(
        """
import json
import os
import sys

TOOLS = [
    {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
]
log_path = os.environ.get("DOWNSTREAM_LOG")

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(method + "\\n")
    if "id" not in msg:
        continue
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-downstream", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    else:
        result = {"content": [{"type": "text", "text": "ok"}]}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\\n")
    sys.stdout.flush()
""",
        encoding="utf-8",
    )
    return script


def _set_allow_policy(config_path: Path, *, server: str, tool: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "allow-test",
        "policy_schema_version": 1,
        "default_decision": "ask_backend",
        "default_risk_class": "unknown",
        "rules": [
            {
                "id": "allow-tool",
                "source": "user",
                "decision": "allow",
                "risk_class": "read",
                "match": {"server": server, "tool": tool},
            }
        ],
    }
    _write_json(config_path, config)


def _seed_terminal_deny(home: Path, *, request_id: str) -> None:
    paths = proxy_paths(home)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.record_terminal_deny(
            request_id=request_id,
            session_id="session-1",
            client_id="cursor:test",
            downstream_server="fake-downstream",
            tool_name="read_file",
            risk_class="read",
            policy_id="allow-test",
            policy_rule_id="allow-tool",
            policy_context_hash="c" * 64,
            payload_hash="sha256:" + "a" * 64,
            resource_hash="sha256:" + "b" * 64,
            created_at=1_700_000_000,
            reason="secret_path_blocked",
        )


def _build_wheel_installed_cli(tmp_path: Path) -> tuple[Path, Path, Path]:
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    env = _clean_env()
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(SDK_ROOT), "-w", str(wheelhouse), "-q"],
        check=True,
        env=env,
        cwd=str(tmp_path),
    )
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(PACKAGE_ROOT), "-w", str(wheelhouse), "--no-deps", "-q"],
        check=True,
        env=env,
        cwd=str(tmp_path),
    )
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    pip = venv / ("Scripts/pip" if os.name == "nt" else "bin/pip")
    subprocess.run(
        [str(pip), "install", "--no-index", f"--find-links={wheelhouse}", "agentveil", "agentveil-mcp-proxy", "-q"],
        check=True,
        env=env,
        cwd=str(tmp_path),
    )
    show = subprocess.run(
        [str(pip), "show", "agentveil-mcp-proxy"],
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )
    assert "Editable project location" not in show.stdout
    python = venv / ("Scripts/python" if os.name == "nt" else "bin/python")
    cli = venv / ("Scripts/agentveil-mcp-proxy" if os.name == "nt" else "bin/agentveil-mcp-proxy")
    module_probe = subprocess.run(
        [str(python), "-c", "import agentveil_mcp_proxy.cli as c; print(c.__file__)"],
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )
    assert "site-packages" in module_probe.stdout
    assert str(PACKAGE_ROOT.resolve()) not in module_probe.stdout
    return venv, python, cli


def test_default_evidence_summary_json_is_privacy_bounded(tmp_path: Path) -> None:
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=tmp_path / "downstream.log")
    _seed_terminal_deny(home, request_id="req-summary-privacy")

    out = io.StringIO()
    summary = evidence_summary(home=home, out=out)
    rendered = out.getvalue()
    assert_bounded_evidence_cli_output(rendered)
    record = summary["records"][0]
    assert record["request_id"] == "req-summary-privacy"
    assert record["action_family"]
    # claim-check: allow "blocked" is the bounded decision enum under test.
    assert record["decision"] == "blocked"
    assert record["target_reached"] is False
    assert record["target_ref"]
    assert record["client_name"] == "cursor"
    assert summary["downstream"]["args_count"] == 4
    assert summary["downstream"]["command_basename"] == Path(sys.executable).name
    assert summary["downstream"]["has_env"] is True
    assert summary["downstream"]["env_keys_count"] >= 1


def test_events_list_json_is_privacy_bounded(tmp_path: Path) -> None:
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=tmp_path / "downstream.log")
    _seed_terminal_deny(home, request_id="req-events-list")

    out = io.StringIO()
    count = list_events(home=home, output_json=True, out=out)
    rendered = out.getvalue()
    assert count == 1
    assert_bounded_evidence_cli_output(rendered)
    payload = json.loads(rendered)
    assert payload["downstream"]["downstream_kind"] == "fake-downstream"
    assert payload["downstream"]["command_ref"]
    assert payload["downstream"]["command_basename"]
    assert payload["events"][0]["record_id"] == "req-events-list"


def test_evidence_summary_error_path_stays_bounded(tmp_path: Path) -> None:
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    paths = proxy_paths(home)
    db_path = paths.proxy_dir / "evidence.sqlite"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text("not-a-database", encoding="utf-8")

    out = io.StringIO()
    summary = evidence_summary(home=home, out=out)
    rendered = out.getvalue()
    assert_bounded_evidence_cli_output(rendered)
    assert summary["ok"] is False
    assert summary["errors"] == ["evidence_store_unavailable"]
    assert str(db_path) not in rendered


def test_routed_mcp_action_summary_uses_real_evidence_record(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="read_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("path policy must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": ".env.local"}},
        })),
        out=client_out,
    ) == 0
    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED

    summary_out = io.StringIO()
    summary = evidence_summary(home=home, out=summary_out)
    events_out = io.StringIO()
    list_events(home=home, output_json=True, out=events_out)
    assert_bounded_evidence_cli_output(summary_out.getvalue(), events_out.getvalue())
    assert summary["record_count"] == 1
    record = summary["records"][0]
    assert record["tool_name"] == "read_file"
    # claim-check: allow "blocked" is the bounded decision enum under test.
    assert record["decision"] == "blocked"
    assert record["reason"] == "secret_path_blocked"
    assert ".env.local" not in summary_out.getvalue()


def test_wheel_installed_cli_evidence_commands_are_privacy_bounded(tmp_path: Path) -> None:
    _venv, _python, cli = _build_wheel_installed_cli(tmp_path)
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(init.config_path, _normal_downstream(tmp_path))
    _seed_terminal_deny(home, request_id="req-wheel-cli")

    env = _clean_env()
    summary_proc = subprocess.run(
        [str(cli), "evidence-summary", "--home", str(home), "--json"],
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=str(tmp_path),
    )
    events_proc = subprocess.run(
        [str(cli), "events", "list", "--home", str(home), "--json"],
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=str(tmp_path),
    )
    assert summary_proc.returncode == 0, summary_proc.stderr
    assert events_proc.returncode == 0, events_proc.stderr
    assert_bounded_evidence_cli_output(summary_proc.stdout, summary_proc.stderr)
    assert_bounded_evidence_cli_output(events_proc.stdout, events_proc.stderr)
    summary_payload = json.loads(summary_proc.stdout)
    events_payload = json.loads(events_proc.stdout)
    assert summary_payload["records"][0]["request_id"] == "req-wheel-cli"
    assert events_payload["events"][0]["record_id"] == "req-wheel-cli"
    assert privacy_markers_in_text(summary_proc.stdout + events_proc.stdout) == []


def test_evidence_summary_record_exports_bounded_authority() -> None:
    from agentveil_mcp_proxy.evidence import PendingApproval

    metadata = json.dumps({
        "policy_decision": "approval",
        "approval_status": "pending",
        "target_reached": False,
        "action_family": "write",
        "request_id": "req-summary-auth",
        "authority_record": {
            "authority_status": "missing",
            "authority_source": "none",
            "authority_reason_id": "risky_authority_missing",
            "risk_family": "write",
            "safe_first_step_id": "request_approval",
            "target_reached": False,
        },
    }, sort_keys=True)
    record = PendingApproval(
        request_id="req-summary-auth",
        session_id="session-1",
        client_id="cursor:session-1",
        downstream_server="fake-downstream",
        tool_name="write_file",
        action_class="write",
        risk_class="write",
        resource_hash="sha256:" + "b" * 64,
        payload_hash="sha256:" + "a" * 64,
        policy_id="approval-test",
        policy_rule_id="approval-tool",
        policy_context_hash="c" * 64,
        status="pending",
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        action_gate_metadata_jcs=metadata,
    )

    summary = evidence_summary_record(record)
    assert summary["authority"]["authority_status"] == "missing"
    assert summary["authority"]["safe_first_step_id"] == "request_approval"
    assert "safe_first_step" not in summary
    assert "safe_first_step" not in summary["authority"]
    assert privacy_markers_in_text(json.dumps(summary)) == []
