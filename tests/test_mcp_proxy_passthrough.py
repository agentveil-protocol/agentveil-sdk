"""P3 tests for MCP stdio pass-through skeleton."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys
import time

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import ProxyCliError, init_proxy, run_proxy
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough


SECRET = "SECRET_DOWNSTREAM_TOKEN"


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
        "passthrough": os.environ.get("AVP_TEST_ALLOWED_ENV"),
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


def test_run_mirrors_initialize_initialized_and_tools_list(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy")
    log_path = tmp_path / "downstream.log"
    _set_downstream(init.config_path, _normal_downstream(tmp_path), log_path=log_path)

    client_in = io.StringIO(
        _json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + _json_line({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        + _json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    )
    client_out = io.StringIO()

    assert run_proxy(home=home, client_in=client_in, out=client_out) == 0
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
    init = init_proxy(home=home, agent_name="proxy")
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

    assert run_proxy(home=home, client_in=client_in, out=client_out) == 0
    responses = _responses(client_out.getvalue())

    assert responses == [{
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {"content": [{"type": "text", "text": "called"}]},
    }]
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/call"]


def test_run_passthrough_does_not_construct_avp_agent_or_call_backend(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy")
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
    monkeypatch.setenv("AVP_TEST_ALLOWED_ENV", "allowed")
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy")
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "env-test",
        "command": sys.executable,
        "args": ["-u", str(_env_downstream(tmp_path))],
        "env": {"EXPLICIT_DOWNSTREAM_ENV": "explicit"},
        "env_passthrough": ["AVP_TEST_ALLOWED_ENV"],
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


def test_downstream_notifications_are_forwarded_before_matching_response(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy")
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
    client_out = io.StringIO()

    def delayed_eof():
        time.sleep(0.2)
        if False:
            yield ""

    assert passthrough.run_stdio(delayed_eof(), client_out) == 0
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
    init = init_proxy(home=home, agent_name="proxy")
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "missing",
        "command": str(tmp_path / "missing-server"),
        "args": [],
    }
    _write_json(init.config_path, config)

    try:
        run_proxy(home=home, client_in=io.StringIO(""), out=io.StringIO())
    except ProxyCliError as exc:
        assert exc.exit_code == 1
        assert "downstream startup failed" in str(exc)
        assert SECRET not in str(exc)
    else:
        raise AssertionError("expected downstream startup failure")


def test_downstream_crash_mid_run_returns_sanitized_jsonrpc_error(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy")
    _set_downstream(init.config_path, _crashing_downstream(tmp_path))

    client_in = io.StringIO(
        _json_line({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + _json_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    )
    client_out = io.StringIO()

    assert run_proxy(home=home, client_in=client_in, out=client_out) == 0
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


def test_downstream_config_rejects_unknown_fields(tmp_path):
    home = tmp_path / "avp-home"
    init = init_proxy(home=home, agent_name="proxy")
    config = json.loads(init.config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "bad",
        "command": sys.executable,
        "args": [],
        "stderr_log": str(tmp_path / "stderr.log"),
    }
    _write_json(init.config_path, config)

    try:
        run_proxy(home=home, client_in=io.StringIO(""), out=io.StringIO())
    except ProxyCliError as exc:
        assert exc.exit_code == 1
        assert "unknown field" in str(exc)
        assert "stderr_log" in str(exc)
    else:
        raise AssertionError("expected downstream config validation failure")
