"""P3 tests for MCP stdio pass-through skeleton."""

from __future__ import annotations

import ctypes
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest

import agentveil_mcp_proxy.passthrough as passthrough_module
import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import ProxyCliError, init_proxy, run_proxy
from agentveil_mcp_proxy.policy import ProxyConfig
from agentveil_mcp_proxy.passthrough import (
    JSONRPC_DOWNSTREAM_TIMEOUT,
    JSONRPC_INVALID_REQUEST,
    MAX_PENDING_RESPONSES,
    DownstreamConfig,
    McpPassthrough,
)


SECRET = "SECRET_DOWNSTREAM_TOKEN"


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


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


def _normal_downstream(tmp_path: Path) -> Path:
    script = tmp_path / "fake_downstream.py"
    script.write_text(
        """
import json
import os
import sys

TOOLS = [{"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}}]
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
        "tools": [{"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}}]
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
            "params": {"name": "read_file", "arguments": {"path": "/tmp/a.txt"}},
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
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/call"]


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


def test_classifier_exception_does_not_break_passthrough(tmp_path):
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

    assert _responses(client_out.getvalue()) == [{
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {"content": [{"type": "text", "text": "called"}]},
    }]
    assert passthrough.classifier_errors == 1


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
    try:
        passthrough.start()
        start = time.monotonic()
        timeout_response = passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": "slow-1",
            "method": "tools/call",
            "params": {"sleep": True, "arguments": {"token": SECRET}},
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
    try:
        passthrough.start()
        responses = passthrough.handle_client_line(_json_line({
            "jsonrpc": "2.0",
            "id": "secret-timeout",
            "method": "tools/call",
            "params": {
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
