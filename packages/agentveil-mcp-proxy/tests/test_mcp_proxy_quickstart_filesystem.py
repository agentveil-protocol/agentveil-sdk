"""Product-route quickstart filesystem pack proof through the MCP proxy."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata

SECRET = "SECRET_QUICKSTART_FS_PAYLOAD"
LOCAL_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/", "/tmp/")


@pytest.fixture(autouse=True)
def _suppress_browser_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webbrowser, "open", lambda *_args, **_kwargs: False)


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _tool_call(tool: str, arguments: dict, *, call_id: str = "call-1") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    })


def _init_quickstart(home: Path, sandbox: Path):
    return init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )


def _sandbox_files(sandbox: Path) -> set[str]:
    return {
        item.relative_to(sandbox).as_posix()
        for item in sandbox.rglob("*")
        if item.is_file()
    }


def _seed_sandbox_file(sandbox: Path, relative_path: str, content: str) -> None:
    target = sandbox / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _evidence_store(home: Path) -> ApprovalEvidenceStore:
    return ApprovalEvidenceStore(home / "mcp-proxy" / "evidence.sqlite")


def _assert_no_local_path_leaks(*parts: str) -> None:
    blob = "\n".join(parts)
    for marker in LOCAL_PATH_MARKERS:
        assert marker not in blob, f"unexpected local path marker {marker!r} in captured output"
    assert SECRET not in blob


def _metadata_for_tool(home: Path, *, tool: str) -> dict:
    with _evidence_store(home) as store:
        matches = [
            parse_controlled_path_metadata(record)
            for record in store.list_records()
            if parse_controlled_path_metadata(record) is not None
            and parse_controlled_path_metadata(record).get("tool") == tool
        ]
    assert len(matches) == 1, f"expected one metadata row for {tool!r}, got {len(matches)}"
    return matches[0]


def _block_avp_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("quickstart filesystem pack must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)


def test_quickstart_list_workspace_reaches_real_sandbox(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_sandbox_file(sandbox, "seed.txt", "hello")
    _block_avp_agent(monkeypatch)

    before = _sandbox_files(sandbox)
    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("list_workspace", {}, call_id="list-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert "result" in response
    listing = response["result"]["content"][0]["text"]
    assert "seed.txt" in listing
    assert _sandbox_files(sandbox) == before == {"seed.txt"}

    metadata = _metadata_for_tool(home, tool="list_workspace")
    assert metadata["policy_decision"] == "allow"
    assert metadata["target_reached"] is True
    assert metadata["execution_status"] == ApprovalStatus.EXECUTED.value
    _assert_no_local_path_leaks(out.getvalue(), json.dumps(metadata))


def test_quickstart_write_file_requires_approval_before_mutation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    before = _sandbox_files(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "write_file",
            {"path": "probe.txt", "content": SECRET},
            call_id="write-pending",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["status"] == "approval_required"
    assert _sandbox_files(sandbox) == before
    assert not (sandbox / "probe.txt").exists()

    metadata = _metadata_for_tool(home, tool="write_file")
    assert metadata["policy_decision"] == "approval"
    assert metadata["target_reached"] is False
    assert metadata["execution_status"] == "not_reached"
    _assert_no_local_path_leaks(out.getvalue(), json.dumps(metadata))


def test_quickstart_delete_file_blocked_before_mutation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_sandbox_file(sandbox, "keep.txt", "stay")
    before = _sandbox_files(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "delete_file",
            {"path": "keep.txt"},
            call_id="delete-denied",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["reason"] == "local_policy_block"
    assert _sandbox_files(sandbox) == before
    assert (sandbox / "keep.txt").read_text(encoding="utf-8") == "stay"

    metadata = _metadata_for_tool(home, tool="delete_file")
    assert metadata["policy_decision"] == "block"
    assert metadata["policy_rule"] == "filesystem-delete"
    assert metadata["target_reached"] is False
    assert metadata["execution_status"] == "not_reached"
    _assert_no_local_path_leaks(out.getvalue(), json.dumps(metadata))


def test_quickstart_rmdir_tree_blocked_before_mutation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_sandbox_file(sandbox, "tree/nested/keep.txt", "stay")
    before = _sandbox_files(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "rmdir_tree",
            {"path": "tree"},
            call_id="rmdir-denied",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["reason"] == "local_policy_block"
    assert _sandbox_files(sandbox) == before
    assert (sandbox / "tree" / "nested" / "keep.txt").read_text(encoding="utf-8") == "stay"

    metadata = _metadata_for_tool(home, tool="rmdir_tree")
    assert metadata["policy_decision"] == "block"
    assert metadata["policy_rule"] == "filesystem-delete"
    assert metadata["target_reached"] is False
    assert metadata["execution_status"] == "not_reached"
    _assert_no_local_path_leaks(out.getvalue(), json.dumps(metadata))
