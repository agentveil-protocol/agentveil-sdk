"""P3 tests for MCP stdio pass-through skeleton."""

from __future__ import annotations

import ctypes
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import threading
import time

import pytest
import webbrowser

import agentveil_mcp_proxy.passthrough as passthrough_module
import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import ProxyCliError, init_proxy, run_proxy
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore
from agentveil_mcp_proxy.evidence.observability import (
    enrich_mcp_error_contract,
    mcp_error_user_message,
    parse_controlled_path_metadata,
)
from agentveil_mcp_proxy.evidence.summary import evidence_summary_record
from agentveil_mcp_proxy.policy import ProxyConfig
from agentveil_mcp_proxy.passthrough import (
    JSONRPC_APPROVAL_REQUIRED,
    JSONRPC_DOWNSTREAM_TIMEOUT,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_POLICY_BLOCKED,
    MAX_PENDING_RESPONSES,
    DownstreamConfig,
    McpPassthrough,
)

from mcp_fake_downstream import fake_target_reached, seed_tool_schemas, tool_entry, write_downstream, write_github_downstream


SECRET = "SECRET_DOWNSTREAM_TOKEN"


def _assert_policy_denied_contract(data: dict, *, reason: str) -> None:
    assert data["status"] == "policy_denied"
    assert data["reason"] == reason
    assert data["approval_possible"] is False
    assert data["retry_after_approval"] is False
    assert isinstance(data["reason_code"], str) and data["reason_code"]
    assert isinstance(data["next_step"], str) and data["next_step"]


def _assert_blocked_contract(data: dict, *, reason: str) -> None:
    assert data["status"] == "blocked"  # claim-check: allow bounded JSON-RPC status vocabulary; negative tests assert no downstream execution.
    assert data["reason"] == reason
    assert data["approval_possible"] is False
    assert data["retry_after_approval"] is False
    assert isinstance(data["reason_code"], str) and data["reason_code"]
    assert isinstance(data["next_step"], str) and data["next_step"]


def _assert_approval_retry_contract(data: dict) -> None:
    assert data["status"] == "approval_required"
    assert data["approval_possible"] is True
    assert data["retry_after_approval"] is True
    assert data["retry_contract"] == "same_tool_call"
    assert data["retry_same_tool_call"] is True
    assert data["approved_retry_requires_same_tool"] is True
    assert data["approved_retry_requires_same_resource"] is True
    assert data["approved_retry_requires_same_payload"] is True
    assert isinstance(data.get("reason_code"), str) and data["reason_code"]
    assert isinstance(data.get("next_step"), str) and data["next_step"]
    assert "auto-resume" not in json.dumps(data).lower()
    assert "automatic rerouting" not in json.dumps(data).lower()


def test_enrich_mcp_error_contract_adds_approval_retry_fields() -> None:
    data = enrich_mcp_error_contract(
        {"status": "approval_required", "reason": "local_approval_required"},
        tool_name="github.create_issue",
    )
    _assert_approval_retry_contract(data)
    assert data["reason_code"] == "approval_required"
    assert data["suggested_tool"] == "create_issue"
    assert "without changing tool, target, or payload" in data["next_step"]


def test_mcp_error_user_message_distinguishes_actionable_outcomes():
    approval = mcp_error_user_message({
        "status": "approval_required",
        "reason": "local_approval_required",
    })
    outside = mcp_error_user_message({
        "status": "policy_denied",
        "reason": "path_outside_workspace",
    })
    missing_tool = mcp_error_user_message({
        # claim-check: allow "blocked" as bounded JSON-RPC status vocabulary in
        # this message-format unit test.
        "status": "blocked",  # claim-check: allow bounded JSON-RPC status vocabulary in this unit test.
        "reason": "unknown_tool",
    })
    secret = mcp_error_user_message({
        "status": "policy_denied",
        "reason": "secret_path_blocked",
    })
    classifier = mcp_error_user_message({
        "status": "blocked",  # claim-check: allow bounded JSON-RPC status vocabulary in this unit test.
        "reason": "classifier_error",
    })
    runtime_sanity = mcp_error_user_message({
        "status": "blocked",  # claim-check: allow bounded JSON-RPC status vocabulary in this unit test.
        "reason": "untrusted_runtime_decision",
    })
    policy_stop = mcp_error_user_message({
        "status": "blocked",  # claim-check: allow bounded JSON-RPC status vocabulary in this unit test.
        "reason": "local_policy_block",
    })

    assert "approve or deny" in approval
    assert "same MCP tool call" in approval
    assert "without changing tool, target, or payload" in approval
    assert "sandbox" in outside.lower()
    assert "MCP tool is not available" in missing_tool
    assert "Approval will not help" in secret
    assert "could not classify" in classifier.lower()
    assert "Stopped by policy" not in classifier
    assert "Proxy/runtime decision error" in runtime_sanity
    assert "Stopped by policy" not in runtime_sanity
    assert "Stopped by policy" in policy_stop


@pytest.fixture(autouse=True)
def _suppress_approval_browser_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep local pytest runs from opening real Approval Center browser tabs."""

    monkeypatch.setattr(webbrowser, "open", lambda *_args, **_kwargs: False)


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _pending_approval_count(home: Path) -> int:
    # Counts records still awaiting a decision (status='pending'), matching this
    # helper's approval-prompt call sites. Terminal evidence rows live in the
    # same table but are not pending approvals.
    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    if not evidence_path.exists():
        return 0
    with sqlite3.connect(evidence_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending'"
        ).fetchone()
    return int(row[0])


def _evidence_records(home: Path) -> list[dict[str, object]]:
    # Read evidence rows for terminal-record assertions.
    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    if not evidence_path.exists():
        return []
    with sqlite3.connect(evidence_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM pending_approvals ORDER BY created_at, request_id"
        ).fetchall()
    return [dict(row) for row in rows]


def _padded_json_line(message: dict, target_bytes: int) -> str:
    message = dict(message)
    params = dict(message.get("params") or {})
    params["pad"] = ""
    message["params"] = params
    payload = json.dumps(message, separators=(",", ":"))
    pad_len = target_bytes - len(payload.encode("utf-8"))
    assert pad_len >= 0
    params["pad"] = "x" * pad_len
    payload = json.dumps(message, separators=(",", ":"))
    assert len(payload.encode("utf-8")) == target_bytes
    return payload + "\n"


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)


def _config_with_env_passthrough(env_passthrough: list[str]) -> ProxyConfig:
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
        "fallback": {},
        "approval": {},
        "policy": {
            "id": "test-policy",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "unknown",
            "rules": [],
        },
        "downstream": {
            "name": "env-test",
            "command": sys.executable,
            "args": [],
            "env_passthrough": env_passthrough,
        },
    })


def _set_downstream(config_path: Path, script: Path, *, log_path: Path | None = None) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    env = {}
    if log_path is not None:
        env["DOWNSTREAM_LOG"] = str(log_path)
    config["downstream"] = {
        "name": "fake-downstream",
        "command": sys.executable,
        "args": ["-u", str(script)],
        "env": env,
    }
    _write_json(config_path, config)


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


def _set_approval_policy(config_path: Path, *, server: str, tool: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "approval-test",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [
            {
                "id": "approval-tool",
                "source": "user",
                "decision": "approval",
                "risk_class": "write",
                "match": {"server": server, "tool": tool},
            }
        ],
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
    {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
]
log_path = os.environ.get("DOWNSTREAM_LOG")

def log(method):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(method + "\\n")

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    log(method)
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
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "called"}]}
    else:
        result = {"ok": True, "method": method}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _filesystem_schema_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "fake_schema_downstream.py"
    script.write_text(
        """
import json
import os
import sys

TOOLS = [
    {
        "name": "write_file",
        "description": "Write a file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    }
]
log_path = os.environ.get("DOWNSTREAM_LOG")

def log(method):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(method + "\\n")

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    log(method)
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
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "called"}]}
    else:
        result = {"ok": True, "method": method}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _crashing_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "crashing_downstream.py"
    script.write_text(
        f"""
import json
import sys

line = sys.stdin.readline()
msg = json.loads(line)
print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"ok": True}}}}), flush=True)
sys.stderr.write("{SECRET}\\n")
sys.stderr.flush()
sys.exit(17)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _env_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "env_downstream.py"
    script.write_text(
        """
import json
import os
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    result = {
        "secret": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "explicit": os.environ.get("EXPLICIT_DOWNSTREAM_ENV"),
        "passthrough": os.environ.get("MY_TOOL_ALLOWED_ENV"),
    }
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _notifying_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "notifying_downstream.py"
    script.write_text(
        """
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    print(json.dumps({
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed",
        "params": {"reason": "test"},
    }), flush=True)
    print(json.dumps({
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {"tools": [{"name": "dynamic_tool"}]},
    }), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _startup_notification_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "startup_notification_downstream.py"
    script.write_text(
        """
import json
import sys
import time

print(json.dumps({
    "jsonrpc": "2.0",
    "method": "notifications/tools/list_changed",
    "params": {"reason": "startup"},
}), flush=True)

for _line in sys.stdin:
    pass
time.sleep(30)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _idle_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "idle_downstream.py"
    script.write_text(
        """
import sys
import time

for _line in sys.stdin:
    pass
time.sleep(30)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _slow_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "slow_downstream.py"
    script.write_text(
        """
import json
import sys
import time

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    params = msg.get("params") or {}
    if params.get("sleep"):
        time.sleep(2.0)
    print(json.dumps({
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {"ok": True, "method": msg.get("method")},
    }), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _multiline_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "multiline_downstream.py"
    script.write_text(
        """
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    print(json.dumps({
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {"ok": True, "format": "pretty"},
    }, indent=2), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _oversized_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "oversized_downstream.py"
    script.write_text(
        """
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    payload = {
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {"blob": "x" * (1024 * 1024 + 1)},
    }
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _ungraceful_child_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "ungraceful_child_downstream.py"
    script.write_text(
        """
from pathlib import Path
import os
import sys
import time

Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")
if len(sys.argv) > 2:
    Path(sys.argv[2]).write_text("ready", encoding="utf-8")
while True:
    time.sleep(1)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _ungraceful_proxy_parent(tmp_path: Path, downstream_script: Path) -> Path:
    script = tmp_path / "ungraceful_proxy_parent.py"
    script.write_text(
        f"""
from pathlib import Path
import os
import sys
import time

sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})

from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough

pid_file = Path(sys.argv[1])
ready_file = Path(sys.argv[2])
passthrough = McpPassthrough(DownstreamConfig(
    command=sys.executable,
    args=("-u", {str(downstream_script)!r}, str(pid_file)),
    name="ungraceful-child",
))
passthrough.start()
ready_file.write_text(str(os.getpid()), encoding="utf-8")
while True:
    time.sleep(1)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _graceful_proxy_parent(tmp_path: Path) -> Path:
    script = tmp_path / "graceful_proxy_parent.py"
    script.write_text(
        f"""
from pathlib import Path
import sys

sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})

from agentveil_mcp_proxy.cli import run_proxy

home = Path(sys.argv[1])
ready_file = Path(sys.argv[2])
ready_file.write_text("ready", encoding="utf-8")
raise SystemExit(run_proxy(home=home))
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _wait_for_file(path: Path, timeout: float = 2.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            value = ""
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path}")


def _wait_for_file_or_process(path: Path, proc: subprocess.Popen[str], timeout: float = 30.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            value = ""
        if value:
            return value
        if proc.poll() is not None:
            stdout, stderr = proc.communicate(timeout=1.0)
            raise AssertionError(
                f"process exited before {path}: "
                f"returncode={proc.returncode}, stdout={stdout!r}, stderr={stderr!r}"
            )
        time.sleep(0.02)
    raise AssertionError(
        f"timed out waiting for {path}; process returncode={proc.poll()}"
    )


def _process_is_running(pid: int) -> bool:
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.WaitForSingleObject.restype = ctypes.c_uint32
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(0x00100000, False, pid)
        if not handle:
            return False
        try:
            status = kernel32.WaitForSingleObject(handle, 0)
            return status == 0x00000102
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_exit(pid: int, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_is_running(pid):
            return True
        time.sleep(0.05)
    return not _process_is_running(pid)


def test_run_mirrors_initialize_initialized_and_tools_list(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)

    client_in = io.StringIO(
        _json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + _json_line({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        + _json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    )
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=client_in,
        out=client_out,
    ) == 0
    responses = _responses(client_out.getvalue())

    assert [response["id"] for response in responses] == [1, 2]
    assert responses[0]["result"]["serverInfo"] == {"name": "fake-downstream", "version": "1.0.0"}
    assert responses[1]["result"] == {
        "tools": [
            {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
            {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
        ]
    }
    assert log_path.read_text(encoding="utf-8").splitlines() == [
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
    assert "OK:" not in client_out.getvalue()


def test_run_passthrough_forwards_local_allow_without_backend_or_gate(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="read_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("local allow must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    client_in = io.StringIO(
        _json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "a.txt"}},
        })
    )
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=client_in,
        out=client_out,
    ) == 0
    responses = _responses(client_out.getvalue())

    assert responses == [{
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {"content": [{"type": "text", "text": "called"}]},
    }]
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]


def _action_gate_metadata(home: Path, *, index: int = -1) -> dict:
    row = _evidence_records(home)[index]
    raw = row.get("action_gate_metadata_jcs")
    assert isinstance(raw, str) and raw
    return json.loads(raw)


def test_allow_read_path_attaches_read_only_authority_record(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="read_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("local allow must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "a.txt"}},
        })),
        out=client_out,
    ) == 0

    metadata = _action_gate_metadata(home)
    authority = metadata["authority_record"]
    assert authority["authority_status"] == "allowed"
    assert authority["authority_source"] == "read_only"
    assert authority["target_reached"] is True
    assert "safe_first_step" not in metadata
    assert "safe_first_step" not in authority


def test_approval_pending_attaches_missing_authority_record(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("local approval must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "a.txt"}},
        })),
        out=client_out,
    ) == 0

    metadata = _action_gate_metadata(home)
    authority = metadata["authority_record"]
    assert authority["authority_status"] == "missing"
    assert authority["authority_source"] == "none"
    assert authority["target_reached"] is False
    assert authority["safe_first_step_id"] == "request_approval"


def test_policy_block_attaches_policy_block_authority_record(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_block_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("local block must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "CLAUDE.md", "content": "x"},
            },
        })),
        out=client_out,
    ) == 0

    metadata = _action_gate_metadata(home)
    authority = metadata["authority_record"]
    assert authority["authority_status"] == "blocked"  # claim-check: allow "blocked" as authority_status enum value.
    assert authority["authority_source"] == "policy_block"
    assert authority["target_reached"] is False
    assert authority["authority_source"] != "policy_grant"


def test_get_secret_block_exports_secret_authority_record(tmp_path, monkeypatch):
    home = tmp_path / "home"
    content_root = tmp_path / "content"
    state_dir = tmp_path / "state"
    outcome_log = tmp_path / "github-outcome.jsonl"
    downstream = write_github_downstream(tmp_path, state_dir, content_root)
    init_proxy(
        home=home,
        plaintext=True,
        policy_pack="github",
        downstream_config={
            "name": "github",
            "command": sys.executable,
            "args": ["-u", str(downstream), str(state_dir), str(content_root)],
            "env": {"GITHUB_OUTCOME_LOG": str(outcome_log)},
        },
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("secret block must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "secret-1",
            "method": "tools/call",
            "params": {
                "name": "get_secret",
                "arguments": {
                    "owner": "acme",
                    "repo": "demo-repo",
                    "repo_root": str(content_root),
                    "secret_name": "DEPLOY_KEY",
                },
            },
        })),
        out=out,
        approval_ui_mode="none",
    ) == 0

    with ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite") as store:
        records = store.list_records()
        metadata_matches = [
            parsed
            for record in records
            if (parsed := parse_controlled_path_metadata(record)) is not None
            and parsed.get("tool") == "get_secret"
        ]
        assert metadata_matches
        metadata = metadata_matches[-1]
        secret_record = next(record for record in records if record.tool_name == "get_secret")

    authority = metadata["authority_record"]
    assert metadata["policy_rule"] == "github-secrets-block"
    assert authority["authority_status"] == "blocked"  # claim-check: allow "blocked" as authority_status enum value.
    assert authority["authority_source"] == "policy_block"
    assert authority["authority_reason_id"] == "secret_access_blocked"
    assert authority["risk_family"] == "secret"
    assert authority["target_reached"] is False

    summary = evidence_summary_record(secret_record)
    assert summary["authority"]["authority_reason_id"] == "secret_access_blocked"
    assert summary["authority"]["risk_family"] == "secret"
    assert "safe_first_step" not in summary
    assert "safe_first_step" not in summary["authority"]


def test_run_returns_approval_required_without_waiting_or_forwarding(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("local approval must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "a.txt"}},
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["status"] == "approval_required"
    assert response["error"]["data"]["reason"] == "local_approval_required"
    assert response["error"]["data"]["record_status"] == "pending"
    assert response["error"]["data"]["record_id"]
    approval_url = response["error"]["data"]["approval_url"]
    assert approval_url.startswith("http://127.0.0.1:")
    assert approval_url in response["error"]["message"]
    assert "Approval required" in response["error"]["message"]
    assert "same MCP tool call" in response["error"]["message"]
    assert "without changing tool, target, or payload" in response["error"]["message"]
    assert response["error"]["data"]["instructions"] == (
        "Approval required. Open the approval page, approve or deny, then retry the same "
        "MCP tool call without changing tool, target, or payload."
    )
    _assert_approval_retry_contract(response["error"]["data"])
    assert response["error"]["data"]["reason"] == "local_approval_required"
    assert response["error"]["data"]["reason_code"] == "approval_required"
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_invalid_write_file_args_do_not_create_approval(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("schema validation must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "file_path": "agentveil-onboarding-friction-pack/evidence/schema-fix-user-retest.md",
                        "content": "schema fix retest",
                    },
                },
            })
        ),
        out=client_out,
    ) == 0

    responses = _responses(client_out.getvalue())
    assert responses[0]["result"]["tools"][0]["name"] == "write_file"
    response = responses[1]
    assert response["error"]["code"] == JSONRPC_INVALID_PARAMS
    assert response["error"]["message"] == "invalid tool arguments"
    assert response["error"]["data"]["status"] == "invalid_tool_arguments"
    assert response["error"]["data"]["tool"] == "write_file"
    assert response["error"]["data"]["details"] == [
        "missing required argument: path",
        "unknown argument: file_path",
    ]
    assert "approval_url" not in response["error"]["data"]
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_invalid_write_file_args_fetch_schema_before_approval(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("schema validation must happen before AVPAgent construction")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "file_path": "agentveil-onboarding-friction-pack/evidence/schema-fix-user-retest.md",
                    "content": "schema fix retest",
                },
            },
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_INVALID_PARAMS
    assert response["error"]["data"]["status"] == "invalid_tool_arguments"
    assert response["error"]["data"]["details"] == [
        "missing required argument: path",
        "unknown argument: file_path",
    ]
    assert "approval_url" not in response["error"]["data"]
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_valid_write_file_args_still_create_approval(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("local approval must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "path": "agentveil-onboarding-friction-pack/evidence/ok.md",
                        "content": "ok",
                    },
                },
            })
        ),
        out=client_out,
    ) == 0

    responses = _responses(client_out.getvalue())
    response = responses[1]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["status"] == "approval_required"
    assert response["error"]["data"]["reason"] == "local_approval_required"
    assert response["error"]["data"]["record_status"] == "pending"
    assert response["error"]["data"]["record_id"]
    assert response["error"]["data"]["approval_url"].startswith("http://127.0.0.1:")
    assert _pending_approval_count(home) == 1
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_path_traversal_write_file_fails_before_approval(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")

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
            "params": {
                "name": "write_file",
                "arguments": {"path": "../outside-regression-51194bd.md", "content": "boundary check"},
            },
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    data = response["error"]["data"]
    assert data["status"] == "policy_denied"
    assert data["reason"] == "path_outside_workspace"
    assert data["approval_possible"] is False
    assert data["retry_after_approval"] is False
    assert data["reason_code"] == "path_outside_sandbox"
    assert data["safe_path_hint"]
    assert data["suggested_tool"] == "write_file"
    assert "sandbox" in response["error"]["message"].lower()
    assert "approval_url" not in data
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_absolute_outside_path_hard_denies_before_approval(tmp_path, monkeypatch):
    # Bug 4: an absolute path escapes the workspace boundary the proxy enforces
    # for relative filesystem tool arguments. It must hard-deny locally before
    # any approval flow. The assertions below cover response fields, pending
    # count, and downstream log shape under an approval policy.
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")

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
            "params": {
                "name": "write_file",
                "arguments": {"path": "/etc/outside-abs-regression.txt", "content": "x"},
            },
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    data = response["error"]["data"]
    assert data["status"] == "policy_denied"
    assert data["reason"] == "path_outside_workspace"
    assert data["approval_possible"] is False
    assert data["retry_after_approval"] is False
    assert data["reason_code"] == "path_outside_sandbox"
    assert data["safe_path_hint"]
    assert data["suggested_tool"] == "write_file"
    assert "sandbox" in response["error"]["message"].lower()
    assert "approval_url" not in data
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    # Downstream log contains only the schema-probe tools/list.
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_normalized_inside_path_is_not_falsely_denied(tmp_path, monkeypatch):
    # Bug 5: a relative path that uses ".." but normalizes back inside the
    # workspace must NOT be hard denied as path_outside_workspace. It proceeds to
    # the existing policy path -- here an approval policy -- reaching the approval
    # flow rather than a local hard-deny.
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("local approval must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "path": "subdir/../notes-inside-regression.md",
                    "content": "x",
                },
            },
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    # Reaches the approval policy path instead of a local hard-deny.
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["status"] == "approval_required"
    assert response["error"]["data"]["reason"] == "local_approval_required"
    assert response["error"]["data"]["record_status"] == "pending"
    assert response["error"]["data"]["approval_url"].startswith("http://127.0.0.1:")
    # And it was not falsely classified as escaping the workspace.
    assert response["error"]["data"].get("reason") != "path_outside_workspace"


def test_secret_read_file_path_fails_before_downstream_read(tmp_path, monkeypatch):
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
            "params": {"name": "read_file", "arguments": {"path": ".env"}},
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    _assert_policy_denied_contract(response["error"]["data"], reason="secret_path_blocked")
    assert "approval_url" not in response["error"]["data"]
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_secret_path_in_paths_list_blocks_broadened_tool(tmp_path):
    # read_multiple_files carries paths in a list arg key; a secret entry must be
    # denied before downstream, and the value must not appear in proxy output.
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_normal_downstream(tmp_path))),
            name="fake-downstream",
        ),
    )
    seed_tool_schemas(passthrough, [tool_entry("read_multiple_files")])
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "read_multiple_files",
                "arguments": {"paths": ["ok.txt", "/home/user/.ssh/id_rsa"]},
            },
        })),
        client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    _assert_policy_denied_contract(response["error"]["data"], reason="secret_path_blocked")
    # Not forwarded downstream: the fake downstream "called" result is absent.
    assert "called" not in client_out.getvalue()
    # Sanitized: the raw secret path does not appear in proxy output.
    assert "/home/user/.ssh/id_rsa" not in client_out.getvalue()
    assert passthrough.security_events == (
        {
            "type": "unsafe_file_path",
            "action": "blocked_pre_approval",
            "reason": "secret_path_blocked",
            "tool": "read_multiple_files",
        },
    )


def test_secret_destination_blocks_move_file(tmp_path):
    # move_file carries source/destination path keys; a secret destination
    # (credential directory segment) is denied before downstream.
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_normal_downstream(tmp_path))),
            name="fake-downstream",
        ),
    )
    seed_tool_schemas(passthrough, [tool_entry("move_file")])
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "move_file",
                "arguments": {
                    "source": "ok.txt",
                    "destination": "/home/user/.aws/config",
                },
            },
        })),
        client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    _assert_policy_denied_contract(response["error"]["data"], reason="secret_path_blocked")
    assert "called" not in client_out.getvalue()
    assert passthrough.security_events == (
        {
            "type": "unsafe_file_path",
            "action": "blocked_pre_approval",
            "reason": "secret_path_blocked",
            "tool": "move_file",
        },
    )


def test_normal_paths_allowed_for_broadened_tool(tmp_path):
    # Normal workspace paths on a broadened filesystem tool proceed downstream
    # with no path security event recorded.
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_normal_downstream(tmp_path))),
            name="fake-downstream",
        ),
    )
    seed_tool_schemas(passthrough, [tool_entry("read_multiple_files")])
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "read_multiple_files",
                "arguments": {"paths": ["docs/a.txt", "workspace/notes.md"]},
            },
        })),
        client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["result"] == {"content": [{"type": "text", "text": "called"}]}
    assert passthrough.security_events == ()


def test_secret_segment_write_file_fails_before_approval(tmp_path, monkeypatch):
    # A path that descends into a credential directory (.aws) whose leaf name is
    # not itself a secret is denied before approval and before downstream.
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="write_file")

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
            "params": {
                "name": "write_file",
                "arguments": {"path": ".aws/config", "content": "x"},
            },
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    _assert_policy_denied_contract(response["error"]["data"], reason="secret_path_blocked")
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


@pytest.mark.parametrize("tool", ["delete_file", "rm", "unlink_file", "rmdir_recursive"])
def test_secret_path_blocks_destructive_file_tools(tmp_path, tool):
    # Destructive filesystem tools (exact name, prefix, and bare alias) carry a
    # path; a secret target is denied before downstream with a sanitized event.
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_normal_downstream(tmp_path))),
            name="fake-downstream",
        ),
    )
    seed_tool_schemas(passthrough, [tool_entry(tool)])
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": tool, "arguments": {"path": "/home/user/.ssh/id_rsa"}},
        })),
        client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    _assert_policy_denied_contract(response["error"]["data"], reason="secret_path_blocked")
    assert "called" not in client_out.getvalue()
    assert "/home/user/.ssh/id_rsa" not in client_out.getvalue()
    assert passthrough.security_events == (
        {
            "type": "unsafe_file_path",
            "action": "blocked_pre_approval",
            "reason": "secret_path_blocked",
            "tool": tool,
        },
    )


def test_secret_delete_file_fails_before_approval(tmp_path, monkeypatch):
    # A destructive filesystem tool (delete_file) targeting a secret path is
    # denied before approval and before downstream, independent of policy config.
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    downstream = write_downstream(
        tmp_path,
        filename="delete_downstream.py",
        tools=[tool_entry("delete_file")],
    )
    _set_downstream(init.config_path, downstream, log_path=log_path)
    _set_approval_policy(init.config_path, server="fake-downstream", tool="delete_file")

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
            "params": {"name": "delete_file", "arguments": {"path": "/home/user/.ssh/id_rsa"}},
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    _assert_policy_denied_contract(response["error"]["data"], reason="secret_path_blocked")
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_secret_path_hard_deny_writes_terminal_blocked_evidence(tmp_path, monkeypatch):
    # Bug 3 regression coverage: hard-deny evidence, approval fields, and raw
    # path privacy. claim-check: allow tested terminal/policy block assertions
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
    _assert_policy_denied_contract(response["error"]["data"], reason="secret_path_blocked")
    # Approval prompt fields stay absent for the hard-deny response.
    assert "approval_url" not in response["error"]["data"]
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0

    # Terminal evidence record carrying the deny reason.
    records = _evidence_records(home)
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "blocked"  # claim-check: allow tested status
    assert record["error_class"] == "secret_path_blocked"
    assert record["result_status"] == "blocked"  # claim-check: allow tested status
    assert record["tool_name"] == "read_file"
    assert record["expires_at"] is None
    assert record["approval_token_hash"] is None
    assert record["decision_audit_id"] is None
    # Privacy check: persisted record omits the raw secret path.
    assert ".env.local" not in json.dumps(record)
    assert str(record["resource_hash"]).startswith("sha256:")
    # Downstream receives no file-read call.
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


@pytest.mark.parametrize(
    ("secret_basename", "tool_path"),
    [
        (".npmrc", "/home/user/.npmrc"),
        (".pypirc", "/home/user/.pypirc"),
        (".netrc", "/home/user/.netrc"),
    ],
)
def test_trapdoor_package_credential_paths_hard_deny_before_approval(
    tmp_path,
    monkeypatch,
    secret_basename,
    tool_path,
):
    # T1 TrapDoor: package-manager credential files are denied before approval,
    # downstream, and evidence must not echo the raw path.
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
            "params": {"name": "read_file", "arguments": {"path": tool_path}},
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    _assert_policy_denied_contract(response["error"]["data"], reason="secret_path_blocked")
    assert "approval_url" not in response["error"]["data"]
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    assert tool_path not in client_out.getvalue()
    assert secret_basename not in client_out.getvalue()

    records = _evidence_records(home)
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "blocked"  # claim-check: allow tested status
    assert record["error_class"] == "secret_path_blocked"
    assert record["result_status"] == "blocked"  # claim-check: allow tested status
    assert record["tool_name"] == "read_file"
    assert record["expires_at"] is None
    assert record["approval_token_hash"] is None
    assert record["decision_audit_id"] is None
    record_json = json.dumps(record)
    assert tool_path not in record_json
    assert secret_basename not in record_json
    assert str(record["resource_hash"]).startswith("sha256:")
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_schema_deny_records_documented_validation_event(tmp_path):
    # Bug 3: a schema-deny (write_file called with file_path instead of path)
    # records a documented validation event: argument NAMES only, no values.
    # claim-check: allow tested validation-event privacy assertions
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_normal_downstream(tmp_path))),
            name="fake-downstream",
        ),
    )
    write_file_schema = {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path"],
        "additionalProperties": False,
    }
    seed_tool_schemas(passthrough, [tool_entry("write_file", write_file_schema)])
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "file_path": "config/prod.txt",
                    "content": "deadbeef-secret-value",
                },
            },
        })),
        client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_INVALID_PARAMS
    assert response["error"]["data"]["status"] == "invalid_tool_arguments"
    assert "approval_url" not in response["error"]["data"]
    # Documented validation event: terminal pre-approval block, arg NAMES only.
    assert passthrough.security_events == (
        {
            "type": "invalid_tool_arguments",
            "action": "blocked_pre_approval",
            "reason": "invalid_tool_arguments",
            "tool": "write_file",
            "missing_arguments": ["path"],
            "unknown_arguments": ["file_path"],
        },
    )
    # Privacy check: the raw argument VALUE is absent from the event stream.
    assert "deadbeef-secret-value" not in json.dumps(passthrough.security_events)
    # Not forwarded downstream.
    assert "called" not in client_out.getvalue()


def test_unknown_tool_hard_deny_writes_terminal_blocked_evidence(tmp_path, monkeypatch):
    # Pre-approval deny evidence: a tool name absent from the downstream
    # tools/list surface is blocked before approval AND records exactly one
    # terminal evidence row, without storing raw arguments.
    # claim-check: allow tested terminal/policy block assertions
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)
    # An allow policy isolates the unknown-tool gate: a known tool would forward.
    _set_allow_policy(init.config_path, server="fake-downstream", tool="read_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("unknown-tool deny must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "totally_unknown_tool",
                "arguments": {"secret": "deadbeef-secret-value"},
            },
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    _assert_blocked_contract(response["error"]["data"], reason="unknown_tool")  # claim-check: allow "blocked" is expected JSON-RPC error data vocabulary.
    assert "MCP tool is not available" in response["error"]["message"]
    assert "approval" not in response["error"]["message"].lower()
    # No approval surface is offered for the hard-deny.
    assert "approval_url" not in response["error"]["data"]
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0

    # Exactly one terminal evidence record carrying the deny reason.
    records = _evidence_records(home)
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "blocked"  # claim-check: allow tested status
    assert record["error_class"] == "unknown_tool"
    assert record["result_status"] == "blocked"  # claim-check: allow tested status
    assert record["tool_name"] == "totally_unknown_tool"
    assert record["downstream_server"] == "fake-downstream"
    assert record["expires_at"] is None
    assert record["approval_token_hash"] is None
    assert record["decision_audit_id"] is None
    # No resource is extracted before classification.
    assert record["resource_hash"] is None
    assert str(record["payload_hash"]).startswith("sha256:")
    # Privacy assertion: the representative raw argument value is absent.
    assert "deadbeef-secret-value" not in json.dumps(record)
    # Negative-path assertion: downstream receives only the schema-probe tools/list.
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_schema_deny_writes_terminal_blocked_evidence(tmp_path, monkeypatch):
    # Pre-approval deny evidence: arguments that fail the downstream tool schema
    # are blocked before approval AND record exactly one terminal evidence row,
    # without storing raw argument values.
    # claim-check: allow tested terminal/policy block assertions
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(
        init.config_path,
        _filesystem_schema_downstream(tmp_path),
        log_path=log_path,
    )
    # An allow policy isolates the schema gate: valid arguments would forward.
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("schema deny must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "file_path": "config/prod.txt",
                    "content": "deadbeef-secret-value",
                },
            },
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_INVALID_PARAMS
    assert response["error"]["data"]["status"] == "invalid_tool_arguments"
    # No approval surface is offered for the schema deny.
    assert "approval_url" not in response["error"]["data"]
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0

    # Exactly one terminal evidence record carrying the deny reason.
    records = _evidence_records(home)
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "blocked"  # claim-check: allow tested status
    assert record["error_class"] == "invalid_tool_arguments"
    assert record["result_status"] == "blocked"  # claim-check: allow tested status
    assert record["tool_name"] == "write_file"
    assert record["downstream_server"] == "fake-downstream"
    assert record["expires_at"] is None
    assert record["approval_token_hash"] is None
    assert record["resource_hash"] is None
    assert str(record["payload_hash"]).startswith("sha256:")
    # Privacy: neither the raw argument value nor the bad argument name's value
    # reaches the persisted record.
    assert "deadbeef-secret-value" not in json.dumps(record)
    # Negative-path assertion: downstream receives only the schema-probe tools/list.
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_run_passthrough_does_not_construct_avp_agent_or_call_backend(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(init.config_path, _normal_downstream(tmp_path))

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("run must not construct AVPAgent in P3")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})),
        out=client_out,
    ) == 0
    assert _responses(client_out.getvalue())[0]["result"]["tools"][0]["name"] == "read_file"


def test_downstream_env_is_minimal_by_default_and_explicit_only(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SECRET)
    monkeypatch.setenv("MY_TOOL_ALLOWED_ENV", "allowed")
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "env-test",
        "command": sys.executable,
        "args": ["-u", str(_env_downstream(tmp_path))],
        "env": {"EXPLICIT_DOWNSTREAM_ENV": "explicit"},
        "env_passthrough": ["MY_TOOL_ALLOWED_ENV"],
    }
    _write_json(init.config_path, config)

    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})),
        out=client_out,
    ) == 0
    result = _responses(client_out.getvalue())[0]["result"]
    assert result == {
        "secret": None,
        "explicit": "explicit",
        "passthrough": "allowed",
    }


def test_downstream_config_rejects_avp_passphrase_in_env_passthrough():
    config = _config_with_env_passthrough(["AVP_PROXY_PASSPHRASE"])

    with pytest.raises(passthrough_module.PassthroughError, match="AVP_\\* prefix"):
        DownstreamConfig.from_proxy_config(config)


def test_downstream_config_rejects_other_avp_var_in_env_passthrough():
    config = _config_with_env_passthrough(["AVP_HOME"])

    with pytest.raises(passthrough_module.PassthroughError, match="AVP_\\* prefix"):
        DownstreamConfig.from_proxy_config(config)


def test_downstream_config_accepts_non_avp_env_passthrough():
    config = _config_with_env_passthrough(["MY_TOOL_VAR", "HOME"])

    parsed = DownstreamConfig.from_proxy_config(config)

    assert parsed.env_passthrough == ("MY_TOOL_VAR", "HOME")


def test_downstream_config_accepts_lowercase_avp_var():
    config = _config_with_env_passthrough(["avp_internal"])

    parsed = DownstreamConfig.from_proxy_config(config)

    assert parsed.env_passthrough == ("avp_internal",)


def test_downstream_config_rejects_avp_var_among_safe_vars():
    config = _config_with_env_passthrough(["HOME", "AVP_PROXY_PASSPHRASE", "PATH"])

    with pytest.raises(passthrough_module.PassthroughError, match="AVP_PROXY_PASSPHRASE"):
        DownstreamConfig.from_proxy_config(config)


def test_downstream_notifications_are_forwarded_before_matching_response(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(init.config_path, _notifying_downstream(tmp_path))

    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})),
        out=client_out,
    ) == 0

    responses = _responses(client_out.getvalue())
    assert responses[0] == {
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed",
        "params": {"reason": "test"},
    }
    assert responses[1] == {
        "jsonrpc": "2.0",
        "id": 7,
        "result": {"tools": [{"name": "dynamic_tool"}]},
    }


def test_downstream_async_notification_is_forwarded_without_pending_request(tmp_path):
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_startup_notification_downstream(tmp_path))),
        name="notify",
    ))
    notification_seen = threading.Event()

    class EventWriter(io.StringIO):
        def write(self, value):
            written = super().write(value)
            if "notifications/tools/list_changed" in self.getvalue():
                notification_seen.set()
            return written

    client_out = EventWriter()

    def eof_after_notification():
        assert notification_seen.wait(timeout=2.0)
        if False:
            yield ""

    assert passthrough.run_stdio(eof_after_notification(), client_out) == 0
    assert _responses(client_out.getvalue()) == [{
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed",
        "params": {"reason": "startup"},
    }]


def test_classifier_exception_on_tool_call_fails_closed(tmp_path):
    class ExplodingClassifier:
        def classify_jsonrpc(self, message):
            raise RuntimeError("boom")

    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_normal_downstream(tmp_path))),
            name="fake-downstream",
        ),
        classifier=ExplodingClassifier(),
    )
    seed_tool_schemas(passthrough, [tool_entry("read_file")])
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/a.txt"}},
        })),
        client_out,
    ) == 0

    # claim-check: allow this comment describes the asserted fail-closed response; verified by this test
    # Fail closed: an unclassified tool call is blocked, never forwarded
    # downstream (the downstream "called" result is not returned).
    response = _responses(client_out.getvalue())[0]
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == "call-1"
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    assert "could not classify" in response["error"]["message"].lower()
    assert "Stopped by policy" not in response["error"]["message"]
    _assert_blocked_contract(response["error"]["data"], reason="classifier_error")
    assert passthrough.classifier_errors == 1
    # claim-check: allow "never"/"blocked" describe the sanitized expected response asserted below
    # Sanitized: raw tool arguments never appear in the blocked response.
    assert "/tmp/a.txt" not in client_out.getvalue()


def test_classifier_callback_exception_does_not_break_passthrough(tmp_path):
    class StaticClassifier:
        def classify_jsonrpc(self, message):
            return object()

    def exploding_callback(classification):
        raise RuntimeError("boom")

    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_normal_downstream(tmp_path))),
            name="fake-downstream",
        ),
        classifier=StaticClassifier(),
        on_tool_call=exploding_callback,
    )
    seed_tool_schemas(passthrough, [tool_entry("read_file")])
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "a.txt"}},
        })),
        client_out,
    ) == 0

    assert _responses(client_out.getvalue()) == [{
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {"content": [{"type": "text", "text": "called"}]},
    }]
    assert passthrough.classifier_errors == 1


def test_downstream_startup_failure_is_sanitized(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "missing",
        "command": str(tmp_path / "missing-server"),
        "args": [],
    }
    _write_json(init.config_path, config)

    try:
        run_proxy(
            home=home,
            client_in=io.StringIO(""),
            out=io.StringIO(),
        )
    except ProxyCliError as exc:
        assert exc.exit_code == 1
        assert "downstream startup failed" in str(exc)
        assert SECRET not in str(exc)
    else:
        raise AssertionError("expected downstream startup failure")


def test_downstream_crash_mid_run_returns_sanitized_jsonrpc_error(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(init.config_path, _crashing_downstream(tmp_path))

    client_in = io.StringIO(
        _json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + _json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    )
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=client_in,
        out=client_out,
    ) == 0
    responses = _responses(client_out.getvalue())

    assert responses[0] == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    assert responses[1]["id"] == 2
    assert responses[1]["error"]["code"] == -32000
    assert "downstream MCP server unavailable" == responses[1]["error"]["message"]
    assert SECRET not in client_out.getvalue()


def test_downstream_process_is_cleaned_up_on_client_eof(tmp_path):
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_idle_downstream(tmp_path))),
        name="idle",
    ))

    assert passthrough.run_stdio(io.StringIO(""), io.StringIO()) == 0
    assert passthrough.process is not None
    assert passthrough.process.poll() is not None


def test_run_proxy_responds_to_sigterm_with_clean_shutdown(tmp_path):
    if os.name == "nt":
        pytest.skip("Windows termination semantics differ from POSIX SIGTERM")

    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    downstream_pid_file = tmp_path / "downstream.pid"
    downstream_ready_file = tmp_path / "downstream.ready"
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "graceful-child",
        "command": sys.executable,
        "args": [
            "-u",
            str(_ungraceful_child_downstream(tmp_path)),
            str(downstream_pid_file),
            str(downstream_ready_file),
        ],
    }
    _write_json(init.config_path, config)

    ready_file = tmp_path / "proxy.ready"
    proxy_script = _graceful_proxy_parent(tmp_path)
    proc = subprocess.Popen(
        [sys.executable, "-u", str(proxy_script), str(home), str(ready_file)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    downstream_pid: int | None = None
    try:
        _wait_for_file_or_process(ready_file, proc, timeout=10.0)
        _wait_for_file_or_process(downstream_ready_file, proc, timeout=60.0)
        downstream_pid = int(_wait_for_file(downstream_pid_file))
        assert _process_is_running(downstream_pid)

        proc.terminate()
        proc.wait(timeout=3.0)

        assert proc.returncode == 0
        assert _wait_for_process_exit(downstream_pid, timeout=2.0)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2.0)
        if downstream_pid is not None and _process_is_running(downstream_pid):
            os.kill(downstream_pid, signal.SIGKILL)


def test_signal_handlers_are_restored_after_run_proxy(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    _set_downstream(init.config_path, _idle_downstream(tmp_path))
    before_term = signal.getsignal(signal.SIGTERM)
    before_int = signal.getsignal(signal.SIGINT)

    assert run_proxy(
        home=home,
        client_in=io.StringIO(""),
        out=io.StringIO(),
    ) == 0

    assert signal.getsignal(signal.SIGTERM) == before_term
    assert signal.getsignal(signal.SIGINT) == before_int


def test_downstream_dies_when_proxy_is_killed_ungracefully(tmp_path):
    if sys.platform == "darwin":
        pytest.skip(
            "macOS ungraceful proxy termination requires an external supervisor"
        )

    downstream_pid_file = tmp_path / "downstream.pid"
    ready_file = tmp_path / "proxy.ready"
    downstream_script = _ungraceful_child_downstream(tmp_path)
    proxy_script = _ungraceful_proxy_parent(tmp_path, downstream_script)
    proc = subprocess.Popen(
        [sys.executable, "-u", str(proxy_script), str(downstream_pid_file), str(ready_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    downstream_pid: int | None = None
    try:
        _wait_for_file(ready_file)
        downstream_pid = int(_wait_for_file(downstream_pid_file))
        assert _process_is_running(downstream_pid)

        if os.name == "nt":
            proc.kill()
        else:
            os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=2.0)

        assert _wait_for_process_exit(downstream_pid, timeout=2.0)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2.0)
        if downstream_pid is not None and _process_is_running(downstream_pid):
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(downstream_pid), "/T", "/F"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                os.kill(downstream_pid, signal.SIGKILL)


def test_downstream_starts_in_own_process_group_on_posix(tmp_path):
    if os.name != "posix":
        return
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_idle_downstream(tmp_path))),
        name="idle",
    ))
    try:
        passthrough.start()
        assert passthrough.process is not None
        assert os.getpgid(passthrough.process.pid) == passthrough.process.pid
    finally:
        passthrough.stop()


def test_multiline_json_downstream_response_is_parsed_correctly(tmp_path):
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_multiline_downstream(tmp_path))),
        name="multiline",
    ))
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO(_json_line({"jsonrpc": "2.0", "id": "pretty-1", "method": "tools/list"})),
        client_out,
    ) == 0

    assert _responses(client_out.getvalue()) == [{
        "jsonrpc": "2.0",
        "id": "pretty-1",
        "result": {"ok": True, "format": "pretty"},
    }]


def test_oversized_downstream_response_is_rejected_safely(tmp_path):
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_oversized_downstream(tmp_path))),
        name="oversized",
        response_timeout_seconds=2.0,
    ))
    try:
        passthrough.start()
        start = time.monotonic()
        response = passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": "large-1",
            "method": "tools/list",
            "params": {"token": SECRET},
        }))[0]
        elapsed = time.monotonic() - start

        assert elapsed < 1.0
        assert response["id"] == "large-1"
        assert response["error"]["code"] == -32000
        assert response["error"]["message"] == "downstream MCP server unavailable"
        rendered = json.dumps(response)
        assert SECRET not in rendered
        assert "blob" not in rendered
    finally:
        passthrough.stop()


def test_oversized_client_message_rejected_with_jsonrpc_error(tmp_path, monkeypatch):
    monkeypatch.setattr(passthrough_module, "MAX_CLIENT_MESSAGE_BYTES", 64)
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_normal_downstream(tmp_path))),
        name="client-oversized",
    ))
    client_out = io.StringIO()

    assert passthrough.run_stdio(io.StringIO("x" * 65 + "\n"), client_out) == 0

    responses = _responses(client_out.getvalue())
    assert responses == [{
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": JSONRPC_INVALID_REQUEST,
            "message": "client request exceeds maximum size",
        },
    }]


def test_oversized_client_message_increments_counter(tmp_path, monkeypatch):
    monkeypatch.setattr(passthrough_module, "MAX_CLIENT_MESSAGE_BYTES", 64)
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_normal_downstream(tmp_path))),
        name="client-oversized",
    ))

    assert passthrough.run_stdio(io.StringIO("x" * 65 + "\n"), io.StringIO()) == 0

    assert passthrough.client_oversized_messages == 1


def test_oversized_client_message_does_not_block_subsequent_valid_messages(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(passthrough_module, "MAX_CLIENT_MESSAGE_BYTES", 256)
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_normal_downstream(tmp_path))),
        name="client-oversized",
    ))
    client_out = io.StringIO()
    valid = _json_line({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})

    assert passthrough.run_stdio(io.StringIO("x" * 257 + "\n" + valid), client_out) == 0

    responses = _responses(client_out.getvalue())
    assert responses[0]["error"]["code"] == JSONRPC_INVALID_REQUEST
    assert responses[1]["id"] == 7
    assert responses[1]["result"]["tools"][0]["name"] == "read_file"


def test_partial_line_at_eof_rejected_as_oversized(tmp_path, monkeypatch):
    monkeypatch.setattr(passthrough_module, "MAX_CLIENT_MESSAGE_BYTES", 256)
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_normal_downstream(tmp_path))),
        name="client-partial",
    ))
    client_out = io.StringIO()

    assert passthrough.run_stdio(
        io.StringIO('{"jsonrpc":"2.0","id":1,"method":"tools/list"}'),
        client_out,
    ) == 0

    assert _responses(client_out.getvalue())[0]["error"]["code"] == JSONRPC_INVALID_REQUEST


def test_exact_max_size_message_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(passthrough_module, "MAX_CLIENT_MESSAGE_BYTES", 512)
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_normal_downstream(tmp_path))),
        name="client-exact-max",
    ))
    client_out = io.StringIO()
    line = _padded_json_line(
        {"jsonrpc": "2.0", "id": "exact", "method": "tools/list", "params": {}},
        512,
    )

    assert passthrough.run_stdio(io.StringIO(line), client_out) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["id"] == "exact"
    assert response["result"]["tools"][0]["name"] == "read_file"


def test_downstream_response_timeout_returns_sanitized_error_and_continues(tmp_path):
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_slow_downstream(tmp_path))),
        name="slow",
        response_timeout_seconds=0.5,
    ))
    seed_tool_schemas(passthrough, [tool_entry("slow_tool")])
    try:
        passthrough.start()
        start = time.monotonic()
        timeout_response = passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": "slow-1",
            "method": "tools/call",
            "params": {"name": "slow_tool", "sleep": True, "arguments": {"token": SECRET}},
        }))[0]
        elapsed = time.monotonic() - start

        assert elapsed < 1.0
        assert timeout_response["id"] == "slow-1"
        assert timeout_response["error"]["code"] == JSONRPC_DOWNSTREAM_TIMEOUT
        assert timeout_response["error"]["message"] == "downstream MCP server response timed out"
        assert timeout_response["error"]["data"] == {
            "status": "timeout",
            "reason": "downstream_response_timeout",
        }
        assert SECRET not in json.dumps(timeout_response)
        assert passthrough.downstream_timeouts == 1
        assert passthrough.process is not None
        assert passthrough.process.poll() is None

        time.sleep(2.2)
        fast_response = passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": "fast-1",
            "method": "tools/list",
            "params": {},
        }))[0]
        assert fast_response == {
            "jsonrpc": "2.0",
            "id": "fast-1",
            "result": {"ok": True, "method": "tools/list"},
        }
    finally:
        passthrough.stop()


def test_downstream_response_timeout_does_not_leak_request_data(tmp_path):
    passthrough = McpPassthrough(DownstreamConfig(
        command=sys.executable,
        args=("-u", str(_slow_downstream(tmp_path))),
        name="slow",
        response_timeout_seconds=0.5,
    ))
    seed_tool_schemas(passthrough, [tool_entry("slow_tool")])
    try:
        passthrough.start()
        responses = passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": "secret-timeout",
            "method": "tools/call",
            "params": {
                "name": "slow_tool",
                "sleep": True,
                "arguments": {
                    "prompt": f"never echo {SECRET}",
                    "source_code": "print('sensitive')",
                },
            },
        }))
        rendered = json.dumps(responses)
        assert responses[0]["error"]["code"] == JSONRPC_DOWNSTREAM_TIMEOUT
        assert SECRET not in rendered
        assert "source_code" not in rendered
        assert "sensitive" not in rendered
    finally:
        passthrough.stop()


def test_downstream_config_rejects_unknown_fields(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "bad",
        "command": sys.executable,
        "args": [],
        "stderr_log": str(tmp_path / "stderr.log"),
    }
    _write_json(init.config_path, config)

    try:
        run_proxy(
            home=home,
            client_in=io.StringIO(""),
            out=io.StringIO(),
        )
    except ProxyCliError as exc:
        assert exc.exit_code == 1
        assert "unknown field" in str(exc)
        assert "stderr_log" in str(exc)
    else:
        raise AssertionError("expected downstream config validation failure")


def test_downstream_config_accepts_response_timeout_seconds(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "timed",
        "command": sys.executable,
        "args": [],
        "response_timeout_seconds": 0.5,
    }
    _write_json(init.config_path, config)

    parsed = DownstreamConfig.from_proxy_config(ProxyConfig.from_dict(config))
    assert parsed.response_timeout_seconds == 0.5


def test_unsolicited_downstream_response_dropped_and_counted():
    passthrough = McpPassthrough(DownstreamConfig(command=sys.executable, name="plain"))

    passthrough._handle_downstream_message({"jsonrpc": "2.0", "id": "fabricated", "result": {}})

    assert passthrough.unsolicited_downstream_responses == 1
    assert passthrough._responses == {}


def test_timed_out_response_ids_pruned_after_retention_window():
    passthrough = McpPassthrough(DownstreamConfig(command=sys.executable, name="plain"))
    with passthrough._stdout_condition:
        passthrough._timed_out_response_ids["expired"] = time.monotonic() - 1.0
        passthrough._prune_timed_out_ids_locked()

    assert passthrough._timed_out_response_ids == {}


def test_responses_dict_caps_at_max_pending():
    passthrough = McpPassthrough(DownstreamConfig(command=sys.executable, name="plain"))
    with passthrough._stdout_condition:
        for index in range(MAX_PENDING_RESPONSES + 1):
            passthrough._responses[f"stale-{index}"] = [{
                "jsonrpc": "2.0",
                "id": index,
                "result": {},
            }]
        passthrough._prune_pending_responses_locked()

    assert sum(len(items) for items in passthrough._responses.values()) == MAX_PENDING_RESPONSES
    assert "stale-0" not in passthrough._responses


def test_in_flight_responses_protected_from_cap_drop():
    passthrough = McpPassthrough(DownstreamConfig(command=sys.executable, name="plain"))
    protected_key = passthrough._id_key("protected")
    with passthrough._stdout_condition:
        passthrough._inflight_ids.add(protected_key)
        passthrough._responses[protected_key] = [{
            "jsonrpc": "2.0",
            "id": "protected",
            "result": {},
        }]
        for index in range(MAX_PENDING_RESPONSES):
            passthrough._responses[f"stale-{index}"] = [{
                "jsonrpc": "2.0",
                "id": index,
                "result": {},
            }]
        passthrough._prune_pending_responses_locked()

    assert protected_key in passthrough._responses
    assert sum(len(items) for items in passthrough._responses.values()) == MAX_PENDING_RESPONSES


def _set_block_policy(config_path: Path, *, server: str, tool: str) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "block-test",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [
            {
                "id": "block-tool",
                "source": "user",
                "decision": "block",
                "risk_class": "write",
                "match": {"server": server, "tool": tool},
            }
        ],
    }
    _write_json(config_path, config)


@pytest.mark.parametrize(
    "instruction_path",
    [
        "CLAUDE.md",
        "AGENTS.md",
        ".cursorrules",
        ".cursor/rules/project.mdc",
        ".github/copilot-instructions.md",
    ],
)
def test_instruction_file_write_requires_approval_before_downstream(
    tmp_path,
    monkeypatch,
    instruction_path,
):
    # T2 TrapDoor: instruction-file writes require approval before downstream even
    # when local policy would allow the same tool to a normal workspace path.
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("instruction trapdoor must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": instruction_path, "content": "x"},
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["status"] == "approval_required"
    assert response["error"]["data"]["reason"] == "instruction_file_write_requires_approval"
    assert response["error"]["data"]["approval_url"].startswith("http://127.0.0.1:")
    assert instruction_path not in client_out.getvalue()
    assert _pending_approval_count(home) == 1
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_non_instruction_write_allowed_with_allow_policy(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "path": "workspace/notes/ok.md",
                        "content": "ok",
                    },
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["result"] == {"content": [{"type": "text", "text": "called"}]}
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]


def test_non_github_copilot_instructions_path_allowed_with_allow_policy(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "path": "docs/copilot-instructions.md",
                        "content": "ok",
                    },
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["result"] == {"content": [{"type": "text", "text": "called"}]}
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]


def test_read_instruction_file_allowed_with_allow_policy(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="read_file")
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "CLAUDE.md"}},
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["result"] == {"content": [{"type": "text", "text": "called"}]}
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]


def _instruction_write_tools_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "instruction_tools_downstream.py"
    script.write_text(
        """
import json
import os
import sys

TOOLS = [
    {"name": "edit_file", "description": "Edit", "inputSchema": {"type": "object"}},
    {"name": "move_file", "description": "Move", "inputSchema": {"type": "object"}},
]
log_path = os.environ.get("DOWNSTREAM_LOG")

def log(method):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(method + "\\n")

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    log(method)
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
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "called"}]}
    else:
        result = {"ok": True, "method": method}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _set_allow_policy_for_tools(config_path: Path, *, server: str, tools: list[str]) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "allow-test",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [
            {
                "id": f"allow-{tool}",
                "source": "user",
                "decision": "allow",
                "risk_class": "write",
                "match": {"server": server, "tool": tool},
            }
            for tool in tools
        ],
    }
    _write_json(config_path, config)


def test_instruction_file_edit_requires_approval_before_downstream(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(
        init.config_path,
        _instruction_write_tools_downstream(tmp_path),
        log_path=log_path,
    )
    _set_allow_policy_for_tools(
        init.config_path,
        server="fake-downstream",
        tools=["edit_file"],
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("instruction trapdoor must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "edit_file",
                    "arguments": {"path": "AGENTS.md", "content": "x"},
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["reason"] == "instruction_file_write_requires_approval"
    assert _pending_approval_count(home) == 1
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_instruction_file_move_destination_requires_approval(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(
        init.config_path,
        _instruction_write_tools_downstream(tmp_path),
        log_path=log_path,
    )
    _set_allow_policy_for_tools(
        init.config_path,
        server="fake-downstream",
        tools=["move_file"],
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("instruction trapdoor must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "move_file",
                    "arguments": {
                        "source": "draft.txt",
                        "destination": ".cursor/rules/guard.mdc",
                    },
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["reason"] == "instruction_file_write_requires_approval"
    assert _pending_approval_count(home) == 1
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_instruction_file_write_honors_local_block_policy(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_block_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("local block must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "CLAUDE.md", "content": "x"},
            },
        })),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[0]
    assert response["error"]["data"]["reason"] == "local_policy_block"
    assert "approval_url" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


_HIDDEN_UNICODE_CHAR = "\u200b"
_BIDI_HIDDEN_UNICODE_CHAR = "\u202e"
_TAINTED_WRITE_CONTENT = f"visible-write-marker{_HIDDEN_UNICODE_CHAR}"


@pytest.mark.parametrize("hidden_unicode_char", [_HIDDEN_UNICODE_CHAR, _BIDI_HIDDEN_UNICODE_CHAR])
def test_hidden_unicode_write_claude_md_hard_deny_before_approval(
    tmp_path,
    monkeypatch,
    hidden_unicode_char,
):
    # T3 TrapDoor: hidden Unicode in instruction-file write content is hard-denied
    # before approval, downstream, and without leaking raw tool arguments.
    # claim-check: allow tested terminal/policy block assertions
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("hidden unicode trapdoor must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    tainted = f"visible-write-marker{hidden_unicode_char}"

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "path": "CLAUDE.md",
                        "content": tainted,
                    },
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    _assert_policy_denied_contract(
        response["error"]["data"],
        reason="hidden_unicode_instruction_file_blocked",
    )
    assert "approval_url" not in response["error"]["data"]
    assert "record_id" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    assert tainted not in client_out.getvalue()
    assert hidden_unicode_char not in client_out.getvalue()
    assert "CLAUDE.md" not in client_out.getvalue()

    records = _evidence_records(home)
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "blocked"  # claim-check: allow tested status
    assert record["error_class"] == "hidden_unicode_instruction_file_blocked"
    assert record["tool_name"] == "write_file"
    record_json = json.dumps(record)
    assert tainted not in record_json
    assert hidden_unicode_char not in record_json
    assert "CLAUDE.md" not in record_json
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_hidden_unicode_edit_agents_md_hard_deny_before_approval(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    tainted = f"visible-edit-marker{_HIDDEN_UNICODE_CHAR}"
    _set_downstream(
        init.config_path,
        _instruction_write_tools_downstream(tmp_path),
        log_path=log_path,
    )
    _set_allow_policy_for_tools(
        init.config_path,
        server="fake-downstream",
        tools=["edit_file"],
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("hidden unicode trapdoor must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "edit_file",
                    "arguments": {"path": "AGENTS.md", "content": tainted},
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    assert response["error"]["data"]["reason"] == "hidden_unicode_instruction_file_blocked"
    assert "approval_url" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    assert tainted not in client_out.getvalue()
    assert _HIDDEN_UNICODE_CHAR not in client_out.getvalue()
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_hidden_unicode_instruction_file_cursor_rule_still_requires_approval(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    instruction_path = ".cursor/rules/x.mdc"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("instruction trapdoor must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": instruction_path, "content": "clean content"},
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["reason"] == "instruction_file_write_requires_approval"
    assert response["error"]["data"]["approval_url"].startswith("http://127.0.0.1:")
    assert _pending_approval_count(home) == 1
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_hidden_unicode_non_instruction_write_not_guarded(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "path": "workspace/notes.md",
                        "content": _TAINTED_WRITE_CONTENT,
                    },
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["result"] == {"content": [{"type": "text", "text": "called"}]}
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]


@pytest.mark.parametrize(
    "persistence_path",
    [
        ".git/hooks/pre-commit",
        ".bashrc",
        ".zshrc",
        ".config/systemd/user/evil.service",
        "Library/LaunchAgents/com.evil.agent.plist",
    ],
)
def test_persistence_path_write_requires_approval_before_downstream(
    tmp_path,
    monkeypatch,
    persistence_path,
):
    # T4 TrapDoor: persistence/backdoor path writes require approval before downstream
    # even when local policy would allow the same tool to a normal workspace path.
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("persistence trapdoor must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": persistence_path, "content": "hook body"},
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["status"] == "approval_required"
    assert response["error"]["data"]["reason"] == "persistence_path_write_requires_approval"
    assert response["error"]["data"]["approval_url"].startswith("http://127.0.0.1:")
    assert persistence_path not in client_out.getvalue()
    assert "hook body" not in client_out.getvalue()
    assert _pending_approval_count(home) == 1
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_persistence_path_move_destination_requires_approval(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    destination = ".git/hooks/pre-commit"
    _set_downstream(
        init.config_path,
        _instruction_write_tools_downstream(tmp_path),
        log_path=log_path,
    )
    _set_allow_policy_for_tools(
        init.config_path,
        server="fake-downstream",
        tools=["move_file"],
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("persistence trapdoor must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "move_file",
                    "arguments": {
                        "source": "draft.txt",
                        "destination": destination,
                    },
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["reason"] == "persistence_path_write_requires_approval"
    assert _pending_approval_count(home) == 1
    assert destination not in client_out.getvalue()
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_persistence_path_non_persistence_write_allowed_with_allow_policy(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": "workspace/notes.md", "content": "ok"},
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["result"] == {"content": [{"type": "text", "text": "called"}]}
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]


def test_persistence_path_ssh_authorized_keys_stays_secret_path_blocked(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _filesystem_schema_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="write_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("secret path guard must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {
                        "path": ".ssh/authorized_keys",
                        "content": "ssh-rsa AAAA...",
                    },
                },
            })
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_POLICY_BLOCKED
    _assert_policy_denied_contract(response["error"]["data"], reason="secret_path_blocked")
    assert "approval_url" not in response["error"]["data"]
    assert _pending_approval_count(home) == 0
    assert ".ssh/authorized_keys" not in client_out.getvalue()
    assert "ssh-rsa" not in client_out.getvalue()
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def _command_tool_downstream(tmp_path: Path) -> Path:
    schema = {
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
        "additionalProperties": False,
    }
    return write_downstream(
        tmp_path,
        filename="command_tool_downstream.py",
        tools=[tool_entry("run_terminal_cmd", schema)],
        call_result_text="pkg-ok",
    )


def _package_manager_tool_call(command: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "run_terminal_cmd",
            "arguments": {"command": command},
        },
    }


@pytest.mark.parametrize(
    "command",
    [
        "npm install left-pad",
        "yarn add left-pad",
        "pnpm add left-pad",
        "pip install requests",
        "poetry add pandas",
        "uv pip install httpx",
        "cargo install ripgrep",
        "go install example.com/tool@latest",
        "composer require symfony/console",
    ],
)
def test_package_manager_mutation_requires_approval_before_downstream(
    tmp_path,
    monkeypatch,
    command,
):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(
        init.config_path,
        _command_tool_downstream(tmp_path),
        log_path=log_path,
    )
    _set_allow_policy(init.config_path, server="fake-downstream", tool="run_terminal_cmd")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("package manager trapdoor must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line(_package_manager_tool_call(command=command))
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["status"] == "approval_required"
    assert response["error"]["data"]["reason"] == "package_manager_action_requires_approval"
    assert response["error"]["data"]["approval_url"].startswith("http://127.0.0.1:")
    output = client_out.getvalue()
    assert command not in output
    for secret_fragment in ("left-pad", "requests", "pandas", "httpx", "ripgrep", "marker-pkg"):
        assert secret_fragment not in output
    assert _pending_approval_count(home) == 1
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_package_manager_safe_command_allowed_with_allow_policy(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(
        init.config_path,
        _command_tool_downstream(tmp_path),
        log_path=log_path,
    )
    _set_allow_policy(init.config_path, server="fake-downstream", tool="run_terminal_cmd")
    client_out = io.StringIO()

    assert run_proxy(
        home=home,
        client_in=io.StringIO(
            _json_line({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
            + _json_line(_package_manager_tool_call(command="pip list"))
        ),
        out=client_out,
    ) == 0

    response = _responses(client_out.getvalue())[1]
    assert response["result"] == {"content": [{"type": "text", "text": "pkg-ok"}]}
    assert _pending_approval_count(home) == 0
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list", "tools/call"]


def _set_controlled_downstream(
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


def _tool_call_args(tool: str, arguments: dict, *, call_id: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def _redirect_metadata_for_request(home: Path, request_id: str) -> dict | None:
    for row in _evidence_records(home):
        if row["request_id"] != request_id:
            continue
        raw = row.get("action_gate_metadata_jcs")
        if not isinstance(raw, str) or not raw:
            return None
        metadata = json.loads(raw)
        return metadata if isinstance(metadata, dict) else None
    return None


def test_redirect_follow_up_read_reaches_downstream_after_reviewer_write_deny(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(
        tmp_path,
        filename="redirect_allow_ds.py",
        tools=[tool_entry("read_file"), tool_entry("write_file")],
        controlled_path=True,
    )
    _set_controlled_downstream(
        init.config_path,
        downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="redirect-allow-read",
    )
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "redirect-allow",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [],
    }
    _write_json(init.config_path, config)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("redirect follow-up must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    deny_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {"path": "workspace/note.txt", "content": "probe"},
            call_id="orig-write",
        ))),
        out=deny_out,
        approval_ui_mode="none",
    ) == 0
    deny_response = _responses(deny_out.getvalue())[0]
    deny_data = deny_response["error"]["data"]
    assert deny_data["reason"] == "role_authority_denied"
    assert deny_data["redirect_context"]["redirect_playbook_id"] == "create_implementer_task"
    assert not fake_target_reached(outcome_path)
    original_meta = _redirect_metadata_for_request(home, "orig-write")
    assert original_meta is not None
    assert original_meta["redirect_role"] == "original"
    assert original_meta["target_reached"] is False

    follow_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {
                "path": "workspace/note.txt",
                "redirect_context": {
                    "original_request_id": "orig-write",
                    "redirect_playbook_id": "create_implementer_task",
                },
            },
            call_id="follow-read",
        ))),
        out=follow_out,
        approval_ui_mode="none",
    ) == 0
    follow_response = _responses(follow_out.getvalue())[0]
    assert "result" in follow_response
    assert fake_target_reached(outcome_path)
    follow_meta = _redirect_metadata_for_request(home, "follow-read")
    assert follow_meta is not None
    assert follow_meta["redirect_role"] == "follow_up"
    assert follow_meta["target_reached"] is True
    assert follow_meta["original_request_id"] == "orig-write"
    assert SECRET not in follow_out.getvalue()


def test_redirect_follow_up_policy_block_does_not_reach_downstream(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(
        tmp_path,
        filename="redirect_block_ds.py",
        tools=[tool_entry("read_file"), tool_entry("write_file")],
        controlled_path=True,
    )
    _set_controlled_downstream(
        init.config_path,
        downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="redirect-block-read",
    )
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "redirect-block",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [{
            "id": "block-read",
            "source": "user",
            "decision": "block",
            "risk_class": "read",
            "match": {"server": "fake-downstream", "tool": "read_file"},
        }],
    }
    _write_json(init.config_path, config)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("redirect block follow-up must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {"path": "workspace/note.txt", "content": "probe"},
            call_id="orig-write",
        ))),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    block_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {
                "path": "workspace/note.txt",
                "redirect_context": {
                    "original_request_id": "orig-write",
                    "redirect_playbook_id": "create_implementer_task",
                },
            },
            call_id="follow-read",
        ))),
        out=block_out,
        approval_ui_mode="none",
    ) == 0
    block_response = _responses(block_out.getvalue())[0]
    assert block_response["error"]["data"]["reason"] == "local_policy_block"
    assert not fake_target_reached(outcome_path)
    follow_meta = _redirect_metadata_for_request(home, "follow-read")
    assert follow_meta is not None
    assert follow_meta["redirect_role"] == "follow_up"
    assert follow_meta["target_reached"] is False


def test_redirect_malformed_context_fails_closed_without_downstream(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(
        tmp_path,
        filename="redirect_malformed_ds.py",
        tools=[tool_entry("read_file")],
        controlled_path=True,
    )
    _set_controlled_downstream(
        init.config_path,
        downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="redirect-malformed",
    )

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("malformed redirect must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {
                "path": "workspace/note.txt",
                "redirect_context": {
                    "original_request_id": "",
                    "redirect_playbook_id": "create_implementer_task",
                },
            },
            call_id="malformed-follow",
        ))),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_INVALID_PARAMS
    assert response["error"]["data"] == {
        "status": "invalid_redirect_context",
        "reason": "invalid_redirect_context",
    }
    assert not fake_target_reached(outcome_path)
    assert "tools/call" not in log_path.read_text(encoding="utf-8")


def test_redirect_unsupported_playbook_does_not_execute_follow_up(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="implementer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(
        tmp_path,
        filename="redirect_unsupported_ds.py",
        tools=[tool_entry("mystery_action"), tool_entry("read_file")],
        controlled_path=True,
    )
    _set_controlled_downstream(
        init.config_path,
        downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="redirect-unsupported",
    )
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "redirect-unknown",
        "policy_schema_version": 1,
        "default_decision": "block",
        "default_risk_class": "unknown",
        "rules": [{
            "id": "unknown-action",
            "source": "user",
            "decision": "block",
            "risk_class": "unknown",
            "match": {"server": "fake-downstream", "tool": "mystery_action"},
        }],
    }
    _write_json(init.config_path, config)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("unsupported redirect must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args("mystery_action", {}, call_id="orig-unknown"))),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {
                "path": "workspace/note.txt",
                "redirect_context": {
                    "original_request_id": "orig-unknown",
                    "redirect_playbook_id": "stop_and_classify_unknown_action",
                },
            },
            call_id="unsupported-follow",
        ))),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    response = _responses(client_out.getvalue())[0]
    _assert_blocked_contract(
        response["error"]["data"],
        reason="unsupported_redirect_playbook",
    )
    assert not fake_target_reached(outcome_path)


STRICT_READ_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
    "additionalProperties": False,
}

STRICT_WRITE_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "content": {"type": "string"},
    },
    "required": ["path", "content"],
    "additionalProperties": False,
}


def test_redirect_strict_schema_follow_up_reaches_downstream(tmp_path, monkeypatch):
    """Follow-up redirect_context must strip before strict schema validation."""

    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(
        tmp_path,
        filename="redirect_strict_ds.py",
        tools=[
            tool_entry("read_file", STRICT_READ_SCHEMA),
            tool_entry("write_file", STRICT_WRITE_SCHEMA),
        ],
        controlled_path=True,
    )
    _set_controlled_downstream(
        init.config_path,
        downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="redirect-strict-schema",
    )
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "redirect-strict",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [],
    }
    _write_json(init.config_path, config)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("strict-schema redirect must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {"path": "workspace/note.txt", "content": "probe"},
            call_id="orig-write",
        ))),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    follow_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {
                "path": "workspace/note.txt",
                "redirect_context": {
                    "original_request_id": "orig-write",
                    "redirect_playbook_id": "create_implementer_task",
                },
            },
            call_id="follow-read",
        ))),
        out=follow_out,
        approval_ui_mode="none",
    ) == 0
    follow_response = _responses(follow_out.getvalue())[0]
    assert "result" in follow_response, follow_response
    assert fake_target_reached(outcome_path)
    assert "tools/call" in log_path.read_text(encoding="utf-8")
    follow_meta = _redirect_metadata_for_request(home, "follow-read")
    assert follow_meta is not None
    assert follow_meta["redirect_role"] == "follow_up"
    assert follow_meta["target_reached"] is True
    assert SECRET not in follow_out.getvalue()


def test_redirect_follow_up_rejects_non_redirect_original_record(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(
        tmp_path,
        filename="redirect_link_integrity_ds.py",
        tools=[tool_entry("read_file"), tool_entry("write_file")],
        controlled_path=True,
    )
    _set_controlled_downstream(
        init.config_path,
        downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="redirect-link-non-original",
    )
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "redirect-link",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [],
    }
    _write_json(init.config_path, config)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("redirect link integrity must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {"path": "workspace/note.txt"},
            call_id="allow-baseline",
        ))),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    assert fake_target_reached(outcome_path)

    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {"path": "workspace/note.txt", "content": "probe"},
            call_id="orig-write",
        ))),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0

    follow_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {
                "path": "workspace/note.txt",
                "redirect_context": {
                    "original_request_id": "allow-baseline",
                    "redirect_playbook_id": "create_implementer_task",
                },
            },
            call_id="follow-bad-original",
        ))),
        out=follow_out,
        approval_ui_mode="none",
    ) == 0
    follow_response = _responses(follow_out.getvalue())[0]
    assert follow_response["error"]["data"]["reason"] == "invalid_redirect_context"
    allow_meta = _redirect_metadata_for_request(home, "allow-baseline")
    assert allow_meta is None or allow_meta.get("redirect_role") != "original"
    assert _redirect_metadata_for_request(home, "follow-bad-original") is None


def test_redirect_follow_up_rejects_mismatched_redirect_playbook(tmp_path, monkeypatch):
    home = tmp_path / "home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True, role_preset="reviewer")
    log_path = tmp_path / "downstream.log"
    outcome_path = tmp_path / "outcome.jsonl"
    downstream = write_downstream(
        tmp_path,
        filename="redirect_playbook_mismatch_ds.py",
        tools=[tool_entry("read_file"), tool_entry("write_file")],
        controlled_path=True,
    )
    _set_controlled_downstream(
        init.config_path,
        downstream,
        log_path=log_path,
        outcome_path=outcome_path,
        fixture_id="redirect-link-playbook",
    )
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["policy"] = {
        "id": "redirect-link",
        "policy_schema_version": 1,
        "default_decision": "allow",
        "default_risk_class": "read",
        "rules": [],
    }
    _write_json(init.config_path, config)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("redirect playbook mismatch must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    deny_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "write_file",
            {"path": "workspace/note.txt", "content": "probe"},
            call_id="orig-write",
        ))),
        out=deny_out,
        approval_ui_mode="none",
    ) == 0
    deny_data = _responses(deny_out.getvalue())[0]["error"]["data"]
    assert deny_data["redirect_playbook_id"] == "create_implementer_task"

    follow_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line(_tool_call_args(
            "read_file",
            {
                "path": "workspace/note.txt",
                "redirect_context": {
                    "original_request_id": "orig-write",
                    "redirect_playbook_id": "use_read_only_tool",
                },
            },
            call_id="follow-playbook-mismatch",
        ))),
        out=follow_out,
        approval_ui_mode="none",
    ) == 0
    follow_response = _responses(follow_out.getvalue())[0]
    assert follow_response["error"]["data"]["reason"] == "invalid_redirect_context"
    assert _redirect_metadata_for_request(home, "follow-playbook-mismatch") is None


def test_read_file_allow_policy_reaches_downstream_without_approval(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy", plaintext=True)
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)
    _set_allow_policy(init.config_path, server="fake-downstream", tool="read_file")

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("local allow must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_json_line({
            "jsonrpc": "2.0",
            "id": "read-1",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "a.txt"}},
        })),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    response = _responses(client_out.getvalue())[0]
    assert "error" not in response
    assert log_path.read_text(encoding="utf-8").splitlines()[-1] == "tools/call"


def test_differentiated_user_messages_for_approval_block_and_redirect() -> None:
    from agentveil_mcp_proxy.passthrough import (
        APPROVAL_REQUIRED_USER_MESSAGE,
        HARD_BLOCK_USER_MESSAGE,
        _approval_required_error,
        _blocked_error,
    )

    classification = ToolCallClassifier(
        ProxyConfig.from_dict({
            "proxy_config_schema_version": 1,
            "avp": {
                "base_url": "https://agentveil.dev",
                "agent_name": "proxy",
                "trusted_signer_dids": ["did:example:test"],
            },
            "role_authority": {"mode": "enforce", "role": "reviewer", "authority": "review"},
            "policy": {
                "id": "test",
                "policy_schema_version": 1,
                "default_decision": "approval",
                "default_risk_class": "write",
                "rules": [{
                    "id": "write-approval",
                    "source": "user",
                    "decision": "approval",
                    "match": {"server": ["github"], "tool": ["create_issue"]},
                }],
            },
        }),
        server_name="github",
    ).classify(tool="create_issue", arguments={"owner": "acme", "repo": "demo"})

    approval = _approval_required_error(
        "req-1",
        reason="local_approval_required",
        classification=classification,
    )
    block = _blocked_error(
        "req-2",
        HARD_BLOCK_USER_MESSAGE,
        reason="local_policy_block",
        classification=classification,
        enrich_guidance=True,
    )
    redirect = _blocked_error(
        "req-3",
        # claim-check: allow "blocked" as a legacy test fixture message.
        "blocked",
        reason="role_authority_denied",
        classification=classification,
        enrich_guidance=True,
    )

    assert approval["error"]["message"] == APPROVAL_REQUIRED_USER_MESSAGE
    _assert_approval_retry_contract(approval["error"]["data"])
    assert approval["error"]["data"]["reason_code"] == "approval_required"
    assert block["error"]["message"] == HARD_BLOCK_USER_MESSAGE
    assert block["error"]["data"]["approval_possible"] is False
    assert block["error"]["data"]["retry_after_approval"] is False
    assert redirect["error"]["message"] != approval["error"]["message"]
    assert redirect["error"]["message"] != block["error"]["message"]
    assert "Review Agent cannot write" in redirect["error"]["message"]
