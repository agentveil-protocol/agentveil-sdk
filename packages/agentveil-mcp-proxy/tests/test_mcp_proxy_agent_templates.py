"""P10A.6 one-command agent templates for review/build/readonly starters."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.agent_templates import (
    AGENT_TEMPLATE_NAMES,
    assert_template_output_is_privacy_safe,
    build_template_commands,
    format_agent_template_text,
    resolve_agent_template,
    run_agent_template_init,
)
from agentveil_mcp_proxy.cli import main, print_client_configs, proxy_paths, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, build_evidence_bundle
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata
from agentveil_mcp_proxy.evidence.proof import verify_evidence_bundle


SECRET = "SECRET_AGENT_TEMPLATE_PAYLOAD"


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
        "id": "template-write",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "note.txt", "content": "template-ok"},
        },
    })


def _filesystem_list_call() -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": "template-list",
        "method": "tools/call",
        "params": {"name": "list_workspace", "arguments": {}},
    })


def _evidence_store(home: Path) -> ApprovalEvidenceStore:
    return ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite")


def _privacy_clean(*, template_text: str, response_text: str, evidence_text: str) -> None:
    assert SECRET not in template_text
    assert SECRET not in response_text
    assert SECRET not in evidence_text


@pytest.mark.parametrize("template_id", AGENT_TEMPLATE_NAMES)
def test_templates_print_emits_normal_cli_commands(tmp_path, template_id, capsys):
    home = tmp_path / f"{template_id}-home"
    sandbox = tmp_path / f"{template_id}-sandbox"
    assert main([
        "templates",
        "print",
        "--template",
        template_id,
        "--home",
        str(home),
        "--sandbox",
        str(sandbox),
    ]) == 0
    output = capsys.readouterr().out
    spec = resolve_agent_template(template_id)
    assert f"--role {spec.role_preset}" in output
    assert "client-config print" in output
    assert "explain role" in output
    assert " run " in output
    assert str(home) in output
    assert str(home / "mcp-proxy" / "config.json") in output
    assert_template_output_is_privacy_safe(output)
    _privacy_clean(template_text=output, response_text="", evidence_text="")


def test_templates_print_json_is_bounded(tmp_path, capsys):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    assert main([
        "templates",
        "print",
        "--template",
        "build",
        "--home",
        str(home),
        "--sandbox",
        str(sandbox),
        "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["template_id"] == "build"
    assert payload["role_preset"] == "implementer"
    assert len(payload["commands"]) == 4
    rendered = json.dumps(payload)
    assert SECRET not in rendered


def test_review_template_init_client_config_and_deny_write(tmp_path, monkeypatch):
    home = tmp_path / "review-home"
    sandbox = tmp_path / "review-sandbox"
    plan = build_template_commands("review", home=home, sandbox_root=sandbox)
    assert main(list(plan.commands[0].argv)) == 0

    client_out = io.StringIO()
    print_client_configs(
        clients=["cursor"],
        home=home,
        config_path=plan.config_path,
        out=client_out,
    )
    client_config_text = client_out.getvalue()
    assert "run" in client_config_text
    assert json.dumps(str(plan.config_path))[1:-1] in client_config_text

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("review template must deny write before downstream")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    proxy_out = io.StringIO()
    assert run_proxy(
        home=home,
        config_path=plan.config_path,
        client_in=io.StringIO(_filesystem_write_call()),
        out=proxy_out,
        approval_ui_mode="none",
    ) == 0

    response_text = proxy_out.getvalue()
    response = _responses(response_text)[0]
    assert response["error"]["data"]["reason"] == "role_authority_denied"
    assert "Review Agent cannot write files" in response["error"]["data"]["explanation"]
    assert response["error"]["data"]["redirect_playbook_id"] == "create_implementer_task"

    with _evidence_store(home) as store:
        records = store.list_records()
        assert len(records) == 1
        metadata = parse_controlled_path_metadata(records[0])
        assert metadata["role"] == "reviewer"
        assert metadata["target_reached"] is False
        bundle = build_evidence_bundle(store, proxy_identity_did=None, trusted_signer_dids=[])
        verify_evidence_bundle(bundle, trusted_signer_dids=[], strict=True)
        _privacy_clean(
            template_text=format_agent_template_text(plan),
            response_text=response_text,
            evidence_text=json.dumps(bundle),
        )


def test_readonly_template_blocks_mutation_before_target(tmp_path, monkeypatch):
    home = tmp_path / "readonly-home"
    sandbox = tmp_path / "readonly-sandbox"
    run_agent_template_init("readonly", home=home, sandbox_root=sandbox)
    paths = proxy_paths(home)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("readonly template must deny mutation before downstream")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    proxy_out = io.StringIO()
    assert run_proxy(
        home=home,
        config_path=paths.config_path,
        client_in=io.StringIO(_filesystem_write_call()),
        out=proxy_out,
        approval_ui_mode="none",
    ) == 0

    response_text = proxy_out.getvalue()
    data = _responses(response_text)[0]["error"]["data"]
    assert data["reason"] == "role_authority_denied"
    assert "Read-only Agent cannot modify files" in data["explanation"]
    assert data["redirect_playbook_id"] == "use_read_only_tool"

    with _evidence_store(home) as store:
        metadata = parse_controlled_path_metadata(store.list_records()[0])
        assert metadata["role"] == "readonly"
        assert metadata["target_reached"] is False


def test_build_template_reaches_quickstart_target_and_allows_write_role(tmp_path, monkeypatch):
    home = tmp_path / "build-home"
    sandbox = tmp_path / "build-sandbox"
    init = run_agent_template_init("build", home=home, sandbox_root=sandbox)

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("build template must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)

    allow_out = io.StringIO()
    assert run_proxy(
        home=home,
        config_path=init.config_path,
        client_in=io.StringIO(_filesystem_list_call()),
        out=allow_out,
        approval_ui_mode="none",
    ) == 0
    allow_response = _responses(allow_out.getvalue())[0]
    assert "error" not in allow_response

    write_out = io.StringIO()
    assert run_proxy(
        home=home,
        config_path=init.config_path,
        client_in=io.StringIO(_filesystem_write_call()),
        out=write_out,
        approval_ui_mode="none",
    ) == 0
    write_data = _responses(write_out.getvalue())[0]["error"]["data"]
    assert write_data["status"] == "approval_required"
    assert write_data.get("reason") != "role_authority_denied"
    assert write_data["redirect_playbook_id"] == "request_approval"

    response_text = allow_out.getvalue() + write_out.getvalue()
    with _evidence_store(home) as store:
        records = store.list_records()
        assert records
        metadata_items = [
            parse_controlled_path_metadata(record)
            for record in records
        ]
        allow_metadata = next(
            item
            for item in metadata_items
            if item is not None and item["target_reached"] is True
        )
        assert allow_metadata["role"] == "implementer"
        bundle = build_evidence_bundle(store, proxy_identity_did=None, trusted_signer_dids=[])
        verify_evidence_bundle(bundle, trusted_signer_dids=[], strict=True)
        _privacy_clean(
            template_text=format_agent_template_text(
                build_template_commands("build", home=home, sandbox_root=sandbox),
            ),
            response_text=response_text,
            evidence_text=json.dumps(bundle),
        )


def test_template_init_via_cli_matches_helper(tmp_path):
    home = tmp_path / "cli-home"
    sandbox = tmp_path / "cli-sandbox"
    plan = build_template_commands("build", home=home, sandbox_root=sandbox)
    assert main(["templates", "print", "--template", "build", "--home", str(home), "--sandbox", str(sandbox)]) == 0
    assert main(list(plan.commands[0].argv)) == 0
    config = json.loads(plan.config_path.read_text(encoding="utf-8"))
    assert config["role_preset"] == "implementer"
    assert config["downstream"]["name"] == "filesystem"
