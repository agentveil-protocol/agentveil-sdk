"""P10A.7 proxy-routed MCP client config generation and validation."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.agent_templates import AGENT_TEMPLATE_NAMES
from agentveil_mcp_proxy.config_wizard import (
    build_safe_config_wizard_result,
    detect_direct_downstream_bypass,
    document_contains_direct_downstream_command,
    is_proxy_routed_mcp_entry,
    load_mcp_client_document,
    validate_mcp_client_document,
)
from agentveil_mcp_proxy.cli import main, run_proxy


SECRET = "SECRET_CONFIG_WIZARD_PAYLOAD"


@pytest.fixture(autouse=True)
def _suppress_browser_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webbrowser, "open", lambda *_args, **_kwargs: False)


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _filesystem_write_call() -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "wizard-write",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "note.txt", "content": "wizard-ok"},
        },
    })


def _filesystem_list_call() -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "wizard-list",
        "method": "tools/call",
        "params": {"name": "list_workspace", "arguments": {}},
    })


def _wizard_init(template_id: str, home: Path, sandbox: Path) -> None:
    assert main([
        "wizard",
        "print",
        "--template",
        template_id,
        "--home",
        str(home),
        "--sandbox",
        str(sandbox),
        "--init",
        "--json",
    ]) == 0


def _wizard_document(template_id: str, home: Path, sandbox: Path, proxy_command: Path) -> dict:
    result = build_safe_config_wizard_result(
        template_id,
        home=home,
        sandbox_root=sandbox,
        proxy_command=str(proxy_command),
        ensure_initialized=True,
    )
    return result.rendered["cursor"]


def _entry_from_document(document: dict) -> dict:
    return document["mcpServers"]["agentveil-mcp-proxy"]


def test_reject_proxy_run_without_config_argument():
    document = {
        "mcpServers": {
            "avp": {
                "command": "agentveil-mcp-proxy",
                "args": ["run"],
            }
        }
    }
    validation = validate_mcp_client_document(document)
    assert validation.ok is False
    assert validation.bypass_detected is True
    assert "must include --config" in validation.issues[0]
    assert is_proxy_routed_mcp_entry(document["mcpServers"]["avp"]) is False


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("evil-mcp-wrapper", ["run", "--config", "/tmp/proxy.json"]),
        ("npx", ["run", "--config", "/tmp/proxy.json"]),
    ],
)
def test_reject_arbitrary_command_with_run_config(command: str, args: list[str]):
    document = {
        "mcpServers": {
            "avp": {
                "command": command,
                "args": args,
            }
        }
    }
    validation = validate_mcp_client_document(document)
    assert validation.ok is False
    assert validation.bypass_detected is True
    assert "does not route through agentveil-mcp-proxy" in validation.issues[0]


def test_accept_default_proxy_command_with_config(tmp_path):
    config_path = tmp_path / "proxy.json"
    document = {
        "mcpServers": {
            "avp": {
                "command": "agentveil-mcp-proxy",
                "args": ["run", "--config", str(config_path)],
            }
        }
    }
    validation = validate_mcp_client_document(document)
    assert validation.ok is True
    assert validation.bypass_detected is False
    assert is_proxy_routed_mcp_entry(document["mcpServers"]["avp"], config_path=config_path)


def test_reject_proxy_run_with_empty_config_value():
    document = {
        "mcpServers": {
            "avp": {
                "command": "agentveil-mcp-proxy",
                "args": ["run", "--config"],
            }
        }
    }
    validation = validate_mcp_client_document(document)
    assert validation.ok is False
    assert validation.bypass_detected is True
    assert "must include --config" in validation.issues[0]


def test_unsafe_direct_downstream_config_is_detected(tmp_path):
    unsafe = {
        "mcpServers": {
            "filesystem": {
                "command": sys.executable,
                "args": [
                    str(tmp_path / "quickstart_filesystem.py"),
                    str(tmp_path / "sandbox"),
                ],
            }
        }
    }
    validation = validate_mcp_client_document(unsafe)
    assert validation.ok is False
    assert validation.bypass_detected is True
    assert document_contains_direct_downstream_command(unsafe) is True
    assert "direct downstream" in validation.issues[0]


def test_wizard_validate_cli_rejects_unsafe_config(tmp_path, capsys):
    unsafe_path = tmp_path / "unsafe-mcp.json"
    unsafe_path.write_text(json.dumps({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)],
            }
        }
    }), encoding="utf-8")

    assert main(["wizard", "validate", "--input", str(unsafe_path)]) == 2
    output = capsys.readouterr().out + capsys.readouterr().err
    assert "FAIL" in output or "unsafe" in output.lower()
    assert SECRET not in output


@pytest.mark.parametrize("template_id", AGENT_TEMPLATE_NAMES)
def test_wizard_print_routes_through_proxy(tmp_path, template_id, capsys):
    home = tmp_path / f"{template_id}-home"
    sandbox = tmp_path / f"{template_id}-sandbox"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")

    _wizard_init(template_id, home, sandbox)
    assert main([
        "wizard",
        "print",
        "--template",
        template_id,
        "--home",
        str(home),
        "--sandbox",
        str(sandbox),
        "--proxy-command",
        str(proxy_command),
    ]) == 0

    output = capsys.readouterr().out
    document = _wizard_document(template_id, home, sandbox, proxy_command)
    entry = _entry_from_document(document)
    assert entry["command"] == str(proxy_command)
    assert entry["args"][0] == "run"
    assert "--config" in entry["args"]
    assert str(home / "mcp-proxy" / "config.json") in entry["args"]
    assert is_proxy_routed_mcp_entry(
        entry,
        proxy_command=str(proxy_command),
        config_path=home / "mcp-proxy" / "config.json",
    )
    joined = json.dumps(document)
    assert "quickstart_filesystem" not in joined
    assert SECRET not in output
    assert SECRET not in joined


def test_review_wizard_config_denies_write_before_target(tmp_path, monkeypatch):
    home = tmp_path / "review-home"
    sandbox = tmp_path / "review-sandbox"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    _wizard_init("review", home, sandbox)
    document = _wizard_document("review", home, sandbox, proxy_command)
    entry = _entry_from_document(document)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("review wizard path must deny write before downstream")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    proxy_out = io.StringIO()
    assert run_proxy(
        home=home,
        config_path=Path(entry["args"][entry["args"].index("--config") + 1]),
        client_in=io.StringIO(_filesystem_write_call()),
        out=proxy_out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(proxy_out.getvalue())[0]
    data = response["error"]["data"]
    assert data["reason"] == "role_authority_denied"
    assert "Review Agent cannot write files" in data["explanation"]
    assert data["redirect_playbook_id"] == "create_implementer_task"


def test_readonly_wizard_config_denies_mutation_before_target(tmp_path, monkeypatch):
    home = tmp_path / "readonly-home"
    sandbox = tmp_path / "readonly-sandbox"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    _wizard_init("readonly", home, sandbox)
    document = _wizard_document("readonly", home, sandbox, proxy_command)
    entry = _entry_from_document(document)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("readonly wizard path must deny mutation before downstream")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    proxy_out = io.StringIO()
    assert run_proxy(
        home=home,
        config_path=Path(entry["args"][entry["args"].index("--config") + 1]),
        client_in=io.StringIO(_filesystem_write_call()),
        out=proxy_out,
        approval_ui_mode="none",
    ) == 0

    data = _responses(proxy_out.getvalue())[0]["error"]["data"]
    assert data["reason"] == "role_authority_denied"
    assert "Read-only Agent cannot modify files" in data["explanation"]
    assert data["redirect_playbook_id"] == "use_read_only_tool"


def test_build_wizard_config_reaches_quickstart_list_target(tmp_path, monkeypatch):
    home = tmp_path / "build-home"
    sandbox = tmp_path / "build-sandbox"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    _wizard_init("build", home, sandbox)
    document = _wizard_document("build", home, sandbox, proxy_command)
    entry = _entry_from_document(document)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("build wizard path must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    proxy_out = io.StringIO()
    assert run_proxy(
        home=home,
        config_path=Path(entry["args"][entry["args"].index("--config") + 1]),
        client_in=io.StringIO(_filesystem_list_call()),
        out=proxy_out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(proxy_out.getvalue())[0]
    assert "error" not in response


def test_wizard_validate_accepts_generated_proxy_config(tmp_path):
    home = tmp_path / "build-home"
    sandbox = tmp_path / "build-sandbox"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    document = _wizard_document("build", home, sandbox, proxy_command)
    generated_path = tmp_path / "generated-mcp.json"
    generated_path.write_text(json.dumps(document), encoding="utf-8")

    loaded = load_mcp_client_document(generated_path)
    validation = validate_mcp_client_document(
        loaded,
        proxy_command=str(proxy_command),
        config_path=home / "mcp-proxy" / "config.json",
    )
    assert validation.ok is True
    assert validation.bypass_detected is False
    assert detect_direct_downstream_bypass(loaded).ok is True


def test_wizard_print_json_summary_is_bounded(tmp_path, capsys):
    home = tmp_path / "review-home"
    sandbox = tmp_path / "review-sandbox"
    assert main([
        "wizard",
        "print",
        "--template",
        "review",
        "--home",
        str(home),
        "--sandbox",
        str(sandbox),
        "--init",
        "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["summary"]["proxy_routed"] is True
    assert payload["summary"]["bypass_detected"] is False
    assert payload["summary"]["role_preset"] == "reviewer"
    assert SECRET not in json.dumps(payload)
