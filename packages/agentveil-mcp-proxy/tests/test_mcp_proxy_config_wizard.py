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


def test_accept_windows_proxy_exe_name_with_config(tmp_path, monkeypatch):
    config_path = tmp_path / "proxy.json"
    monkeypatch.setattr(
        "agentveil_mcp_proxy.config_wizard.resolve_proxy_command",
        lambda command=None: "C:\\Tools\\agentveil-mcp-proxy.EXE"
        if command is None
        else command,
    )
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


def _review_inventory_path(tmp_path: Path) -> Path:
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps([
            {"tool_name": "read_file", "server_label": "filesystem", "capabilities": ["read"]},
            {"tool_name": "write_file", "server_label": "filesystem", "capabilities": ["write"]},
            {"tool_name": "git_status", "server_label": "git", "capabilities": ["read"]},
            {"tool_name": "git_push", "server_label": "git", "capabilities": ["write"]},
        ]),
        encoding="utf-8",
    )
    return inventory_path


def test_setup_normal_path_writes_valid_proxy_and_routed_client_config(tmp_path):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    inventory_path = _review_inventory_path(tmp_path)

    from agentveil_mcp_proxy.config_wizard import (
        derive_setup_status,
        resolve_setup_paths,
        run_setup_wizard,
    )
    from agentveil_mcp_proxy.policy import ProxyConfig

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    from agentveil_mcp_proxy.config_wizard import parse_tool_inventory

    result = run_setup_wizard(
        home=home,
        inventory=parse_tool_inventory(inventory),
        requested_mode="review",
        proxy_command=str(proxy_command),
    )
    paths = resolve_setup_paths(home)
    assert result.proxy_config_written is True
    assert result.client_config_written is True
    assert result.setup_status == "protected"
    assert result.summary["mode"] == "review"
    assert result.summary["role_preset"] == "reviewer"
    assert result.summary["client_config_routes_through_agentveil"] is True

    proxy_payload = json.loads(paths.proxy_config_path.read_text(encoding="utf-8"))
    ProxyConfig.from_dict(proxy_payload)
    assert proxy_payload["role_preset"] == "reviewer"

    client_document = json.loads(paths.client_config_path.read_text(encoding="utf-8"))
    entry = client_document["mcpServers"]["agentveil-mcp-proxy"]
    assert entry["command"] == str(proxy_command)
    assert entry["args"] == ["run", "--home", str(home), "--config", str(paths.proxy_config_path)]

    status = derive_setup_status(home=home, proxy_command=str(proxy_command))
    assert status.setup_status == "protected"
    assert status.proxy_config_valid is True
    assert status.client_config_routes_through_agentveil is True
    assert SECRET not in json.dumps(result.summary)


def test_setup_summary_matches_generated_configs(tmp_path):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    from agentveil_mcp_proxy.config_wizard import parse_tool_inventory, resolve_setup_paths, run_setup_wizard

    inventory = parse_tool_inventory(json.loads(_review_inventory_path(tmp_path).read_text(encoding="utf-8")))
    result = run_setup_wizard(
        home=home,
        inventory=inventory,
        requested_mode="review",
        proxy_command=str(proxy_command),
    )
    paths = resolve_setup_paths(home)
    proxy_payload = json.loads(paths.proxy_config_path.read_text(encoding="utf-8"))
    client_document = json.loads(paths.client_config_path.read_text(encoding="utf-8"))

    assert result.summary["role_preset"] == proxy_payload["role_preset"]
    assert result.summary["proxy_config_valid"] is True
    assert "mode=review" in "\n".join(result.summary["summary_lines"])
    entry = client_document["mcpServers"]["agentveil-mcp-proxy"]
    assert str(paths.proxy_config_path) in entry["args"]


def test_setup_status_reports_bypass_for_direct_downstream_client_config(tmp_path):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    from agentveil_mcp_proxy.config_wizard import derive_setup_status, parse_tool_inventory, resolve_setup_paths, run_setup_wizard

    inventory = parse_tool_inventory(json.loads(_review_inventory_path(tmp_path).read_text(encoding="utf-8")))
    run_setup_wizard(
        home=home,
        inventory=inventory,
        requested_mode="review",
        proxy_command=str(proxy_command),
    )
    paths = resolve_setup_paths(home)
    paths.client_config_path.write_text(
        json.dumps({
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)],
                }
            }
        }),
        encoding="utf-8",
    )
    status = derive_setup_status(home=home, proxy_command=str(proxy_command))
    assert status.setup_status == "bypass"
    assert status.client_config_routes_through_agentveil is False
    assert status.direct_downstream_entries_count == 1


def test_setup_backup_and_restore_bytes(tmp_path):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    from agentveil_mcp_proxy.config_wizard import (
        derive_setup_status,
        parse_tool_inventory,
        resolve_setup_paths,
        restore_setup_files,
        run_setup_wizard,
    )

    inventory = parse_tool_inventory(json.loads(_review_inventory_path(tmp_path).read_text(encoding="utf-8")))
    first = run_setup_wizard(
        home=home,
        inventory=inventory,
        requested_mode="review",
        proxy_command=str(proxy_command),
    )
    paths = resolve_setup_paths(home)
    first_proxy_bytes = paths.proxy_config_path.read_bytes()

    second = run_setup_wizard(
        home=home,
        inventory=inventory,
        requested_mode="build",
        proxy_command=str(proxy_command),
    )
    assert second.proxy_config_written is True
    assert second.backup_refs
    assert paths.proxy_config_path.read_bytes() != first_proxy_bytes

    # claim-check: allow "all" is a restore target enum value, not a coverage claim.
    restore = restore_setup_files(home=home, target="all")
    assert restore.ok is True
    assert paths.proxy_config_path.read_bytes() == first_proxy_bytes

    proxy_payload = json.loads(paths.proxy_config_path.read_text(encoding="utf-8"))
    status = derive_setup_status(home=home, proxy_command=str(proxy_command))
    assert status.role_preset == proxy_payload["role_preset"]
    assert status.mode == "review"
    assert status.setup_status == "protected"


def test_setup_status_aligns_with_proxy_config_after_restore_cli(tmp_path, capsys):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    inventory_path = _review_inventory_path(tmp_path)

    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(inventory_path),
        "--mode",
        "review",
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    capsys.readouterr()

    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(inventory_path),
        "--mode",
        "build",
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    capsys.readouterr()

    assert main([
        "setup",
        "restore",
        "--home",
        str(home),
        "--target",
        # claim-check: allow "all" is a restore target enum value, not a coverage claim.
        "all",
        "--json",
    ]) == 0
    capsys.readouterr()

    proxy_payload = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    assert proxy_payload["role_preset"] == "reviewer"

    assert main([
        "setup",
        "status",
        "--home",
        str(home),
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    status_payload = json.loads(capsys.readouterr().out)
    assert status_payload["role_preset"] == proxy_payload["role_preset"]
    assert status_payload["mode"] == "review"
    assert status_payload["setup_status"] == "protected"


def test_setup_write_failure_leaves_old_config_intact(tmp_path, monkeypatch):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    from agentveil_mcp_proxy.config_wizard import (
        _atomic_write_bytes,
        parse_tool_inventory,
        resolve_setup_paths,
        run_setup_wizard,
    )

    inventory = parse_tool_inventory(json.loads(_review_inventory_path(tmp_path).read_text(encoding="utf-8")))
    first = run_setup_wizard(
        home=home,
        inventory=inventory,
        requested_mode="review",
        proxy_command=str(proxy_command),
    )
    paths = resolve_setup_paths(home)
    original_proxy = paths.proxy_config_path.read_bytes()
    original_client = paths.client_config_path.read_bytes()

    real_atomic = _atomic_write_bytes

    def flaky_atomic(target_path, content, *, backup_dir):
        if target_path.name.endswith("-mcp.json"):
            raise OSError("simulated client write failure")
        return real_atomic(target_path, content, backup_dir=backup_dir)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.config_wizard._atomic_write_bytes",
        flaky_atomic,
    )
    failed = run_setup_wizard(
        home=home,
        inventory=inventory,
        requested_mode="build",
        proxy_command=str(proxy_command),
    )
    assert failed.ok is False
    assert failed.client_config_written is False
    assert paths.proxy_config_path.read_bytes() == original_proxy
    assert paths.client_config_path.read_bytes() == original_client


def test_setup_json_output_does_not_leak_local_paths(tmp_path, capsys):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    inventory_path = _review_inventory_path(tmp_path)

    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(inventory_path),
        "--mode",
        "review",
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    serialized = json.dumps(payload)

    assert "proxy_config_path" not in payload["summary"]
    assert "proxy_config_ref" in payload["summary"]
    assert payload["summary"]["proxy_config_ref"]["basename"] == "config.json"
    assert payload["summary"]["proxy_config_ref"]["hash"].startswith("sha256:")
    for forbidden in (str(tmp_path), str(home), "/private/", "/var/folders/", "/Users/"):
        assert forbidden not in serialized


def test_restore_json_and_human_output_do_not_leak_local_paths(tmp_path, capsys):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    inventory_path = _review_inventory_path(tmp_path)

    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(inventory_path),
        "--mode",
        "review",
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    capsys.readouterr()

    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(inventory_path),
        "--mode",
        "build",
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    capsys.readouterr()

    assert main([
        "setup",
        "restore",
        "--home",
        str(home),
        "--target",
        # claim-check: allow "all" is a restore target enum value, not a coverage claim.
        "all",
        "--json",
    ]) == 0
    restore_json = capsys.readouterr().out
    restore_payload = json.loads(restore_json)
    assert restore_payload["restored_targets"] == ["proxy", "client"]
    assert restore_payload["restored_refs"][0]["target"] == "proxy"
    assert restore_payload["restored_refs"][0]["basename"] == "config.json"
    for forbidden in (str(tmp_path), str(home), "/private/", "/var/folders/", "/Users/"):
        assert forbidden not in restore_json

    assert main([
        "setup",
        "restore",
        "--home",
        str(home),
        "--target",
        "all",
    ]) == 0
    restore_human = capsys.readouterr().out
    assert "restored: proxy" in restore_human
    assert "restored: client" in restore_human
    for forbidden in (str(tmp_path), str(home), "/private/", "/var/folders/", "/Users/"):
        assert forbidden not in restore_human


def _assert_no_local_path_leaks(serialized: str, *, tmp_path: Path, home: Path) -> None:
    for forbidden in (str(tmp_path), str(home), "/private/", "/var/folders/", "/Users/"):
        assert forbidden not in serialized


def test_setup_missing_inventory_json_error_is_bounded(tmp_path, capsys):
    home = tmp_path / "setup-home"
    missing_inventory = tmp_path / "missing-inventory.json"

    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(missing_inventory),
        "--mode",
        "review",
        "--json",
    ]) == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["target"] == "inventory"
    assert payload["basename"] == "missing-inventory.json"
    assert "unable to read tool inventory" in payload["error"]
    _assert_no_local_path_leaks(captured.out + captured.err, tmp_path=tmp_path, home=home)


def test_setup_missing_inventory_human_error_is_bounded(tmp_path, capsys):
    home = tmp_path / "setup-home"
    missing_inventory = tmp_path / "missing-inventory.json"

    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(missing_inventory),
        "--mode",
        "review",
    ]) == 2
    captured = capsys.readouterr()
    assert "unable to read tool inventory: missing-inventory.json" in captured.err
    _assert_no_local_path_leaks(captured.out + captured.err, tmp_path=tmp_path, home=home)


def test_restore_missing_backup_errors_are_bounded(tmp_path, capsys):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    inventory_path = _review_inventory_path(tmp_path)

    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(inventory_path),
        "--mode",
        "review",
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    capsys.readouterr()
    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(inventory_path),
        "--mode",
        "build",
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    capsys.readouterr()

    from agentveil_mcp_proxy.config_wizard import resolve_setup_paths

    paths = resolve_setup_paths(home)
    for backup_file in paths.backup_dir.glob("*.bak"):
        backup_file.unlink()

    assert main([
        "setup",
        "restore",
        "--home",
        str(home),
        "--target",
        # claim-check: allow "all" is a restore target enum value, not a coverage claim.
        "all",
        "--json",
    ]) == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert "backup not found" in " ".join(payload["errors"])
    _assert_no_local_path_leaks(captured.out + captured.err, tmp_path=tmp_path, home=home)

    assert main([
        "setup",
        "restore",
        "--home",
        str(home),
        "--target",
        # claim-check: allow "all" is a restore target enum value, not a coverage claim.
        "all",
    ]) == 2
    captured = capsys.readouterr()
    assert "backup not found" in captured.out
    _assert_no_local_path_leaks(captured.out + captured.err, tmp_path=tmp_path, home=home)


def test_non_validatable_setup_does_not_write_protected_config(tmp_path):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    from agentveil_mcp_proxy.config_wizard import derive_setup_status, parse_tool_inventory, resolve_setup_paths, run_setup_wizard

    inventory = parse_tool_inventory([
        {"tool_name": "write_file", "server_label": "filesystem", "capabilities": ["write"]},
    ])
    result = run_setup_wizard(
        home=home,
        inventory=inventory,
        requested_mode="build",
        overlays=["docs_write_only"],
        proxy_command=str(proxy_command),
    )
    paths = resolve_setup_paths(home)
    assert result.setup_status == "incomplete"
    assert result.proxy_config_written is False
    assert result.client_config_written is False
    assert "docs_write_only" in result.errors[0]
    status = derive_setup_status(home=home, proxy_command=str(proxy_command))
    assert status.setup_status == "incomplete"
    assert not paths.proxy_config_path.is_file() or status.proxy_config_valid is False
