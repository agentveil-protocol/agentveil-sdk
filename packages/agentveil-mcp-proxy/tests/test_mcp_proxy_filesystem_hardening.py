"""Product-route filesystem hardening proofs through the MCP proxy."""

from __future__ import annotations

import io
import json
import os
import re
import threading
import time
from pathlib import Path

import httpx
import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import init_proxy, quickstart_filesystem_downstream, run_proxy
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.evidence.observability import parse_controlled_path_metadata
from agentveil_mcp_proxy.persistence_path_guard import INSTRUCTION_SURFACE_RISK_MESSAGE

SECRET = "SECRET_FILESYSTEM_HARDENING_PAYLOAD"
LOCAL_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/", "/tmp/")
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


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


def _set_role_authority(config_path: Path, *, role: str = "implementer", authority: str = "implement") -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["role_authority"] = {
        "mode": "enforce",
        "role": role,
        "authority": authority,
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(config_path, 0o600)


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


def _metadata_for_tool(home: Path, tool: str) -> dict:
    with _evidence_store(home) as store:
        matches = [
            parse_controlled_path_metadata(record)
            for record in store.list_records()
            if parse_controlled_path_metadata(record) is not None
            and parse_controlled_path_metadata(record).get("tool") == tool
        ]
    assert matches, f"expected metadata row for {tool!r}"
    return matches[-1]


def _executed_metadata_for_tool(home: Path, tool: str) -> dict:
    with _evidence_store(home) as store:
        for record in reversed(store.list_records()):
            if record.status != ApprovalStatus.EXECUTED.value:
                continue
            metadata = parse_controlled_path_metadata(record)
            if metadata is not None and metadata.get("tool") == tool:
                return metadata
    raise AssertionError(f"expected executed metadata row for {tool!r}")


def _assert_no_local_path_leaks(*parts: str) -> None:
    blob = "\n".join(parts)
    for marker in LOCAL_PATH_MARKERS:
        assert marker not in blob, f"unexpected local path marker {marker!r}"
    assert SECRET not in blob


def _block_avp_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("filesystem hardening must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)


class _StagedStdin(io.TextIOBase):
    """Char-oriented stdin that gates each line after the first."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = [
            line if line.endswith("\n") else f"{line}\n"
            for line in lines
        ]
        self._line_index = 0
        self._char_index = 0
        self._gate = threading.Event()
        self._gate.set()

    def read(self, size: int = -1) -> str:
        if size not in (-1, 1):
            raise io.UnsupportedOperation("only single-character reads are supported")
        if self._line_index >= len(self._lines):
            return ""
        self._gate.wait(timeout=30)
        if self._line_index >= len(self._lines):
            return ""
        line = self._lines[self._line_index]
        char = line[self._char_index]
        self._char_index += 1
        if self._char_index >= len(line):
            self._line_index += 1
            self._char_index = 0
            self._gate.clear()
        return char

    def release_next(self) -> None:
        self._gate.set()


def _approve_first_pending(home: Path, response: dict) -> None:
    approval_url = response["error"]["data"]["approval_url"]
    with httpx.Client() as client:
        page = client.get(approval_url)
        page.raise_for_status()
        match = CSRF_RE.search(page.text)
        assert match is not None
        client.post(approval_url, data={
            "decision": "approve",
            "approval_scope": "exact",
            "csrf_token": match.group(1),
        }).raise_for_status()
    pending_id = response["error"]["data"]["record_id"]
    deadline = time.monotonic() + 5
    with _evidence_store(home) as store:
        record = store.get_pending(pending_id)
        while record.status != ApprovalStatus.APPROVED.value and time.monotonic() < deadline:
            time.sleep(0.02)
            record = store.get_pending(pending_id)
        assert record.status == ApprovalStatus.APPROVED.value


def test_instruction_surface_status_reports_bounded_risk(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_sandbox_file(sandbox, "AGENTS.md", "do not leak this instruction body")
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("instruction_surface_status", {}, call_id="instr-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["instruction_surfaces_detected"] is True
    assert payload["instruction_surface_risk_message"] == INSTRUCTION_SURFACE_RISK_MESSAGE
    assert payload["instruction_surfaces"][0]["basename"] == "AGENTS.md"
    assert "do not leak" not in out.getvalue()
    metadata = _metadata_for_tool(home, tool="instruction_surface_status")
    assert metadata["target_reached"] is True
    _assert_no_local_path_leaks(out.getvalue(), json.dumps(metadata))


def test_traversal_write_blocked_before_mutation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    before = _sandbox_files(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "write_file",
            {"path": "../outside.txt", "content": SECRET},
            call_id="escape-1",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["reason"] == "path_outside_workspace"
    assert outside.read_text(encoding="utf-8") == "outside"
    assert _sandbox_files(sandbox) == before
    _assert_no_local_path_leaks(out.getvalue())


def test_symlink_escape_write_blocked_before_mutation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("outside", encoding="utf-8")
    link = sandbox / "escape-link.txt"
    link.symlink_to(outside)
    _init_quickstart(home, sandbox)
    before = _sandbox_files(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "write_file",
            {"path": "escape-link.txt", "content": SECRET},
            call_id="symlink-1",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["status"] == "approval_required"
    assert outside.read_text(encoding="utf-8") == "outside"
    assert _sandbox_files(sandbox) == before
    metadata = _metadata_for_tool(home, tool="write_file")
    assert metadata["target_reached"] is False


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("move_file", {"source": "seed.txt", "destination": "moved.txt"}),
        ("copy_file", {"source": "seed.txt", "destination": "copy.txt"}),
        ("chmod_file", {"path": "seed.txt", "mode": 0o600}),
        ("create_symlink", {"path": "link.txt", "target": "seed.txt"}),
    ],
)
def test_mutation_like_tools_require_approval_before_change(
    tmp_path,
    monkeypatch,
    tool: str,
    arguments: dict,
):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_sandbox_file(sandbox, "seed.txt", "seed")
    before = _sandbox_files(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(tool, arguments, call_id=f"{tool}-pending")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["status"] == "approval_required"
    assert _sandbox_files(sandbox) == before
    metadata = _metadata_for_tool(home, tool=tool)
    assert metadata["target_reached"] is False
    _assert_no_local_path_leaks(out.getvalue(), json.dumps(metadata))


def test_approved_write_mutates_only_approved_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    init = _init_quickstart(home, sandbox)
    _set_role_authority(init.config_path)
    _seed_sandbox_file(sandbox, "sibling.txt", "stay")
    before = _sandbox_files(sandbox)
    _block_avp_agent(monkeypatch)

    staged_in = _StagedStdin([
        _tool_call(
            "write_file",
            {"path": "approved/target.txt", "content": "approved-body"},
            call_id="write-pending",
        ),
        _tool_call(
            "write_file",
            {"path": "approved/target.txt", "content": "approved-body"},
            call_id="write-retry",
        ),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=staged_in,
            out=client_out,
            approval_ui_mode="none",
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        assert first["error"]["data"]["status"] == "approval_required"
        assert _sandbox_files(sandbox) == before
        _approve_first_pending(home, first)
        staged_in.release_next()
        worker.join(timeout=10)
        responses = _responses(client_out.getvalue())
        assert len(responses) == 2
        assert "result" in responses[1]
        after = _sandbox_files(sandbox)
        assert "approved/target.txt" in after
        assert "sibling.txt" in after
        assert (sandbox / "approved" / "target.txt").read_text(encoding="utf-8") == "approved-body"
        metadata = _executed_metadata_for_tool(home, tool="write_file")
        assert metadata["target_reached"] is True
        assert metadata["execution_status"] == ApprovalStatus.EXECUTED.value
        _assert_no_local_path_leaks(client_out.getvalue(), json.dumps(metadata))
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def test_denied_write_leaves_filesystem_unchanged(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    init = _init_quickstart(home, sandbox)
    _set_role_authority(init.config_path)
    before = _sandbox_files(sandbox)
    _block_avp_agent(monkeypatch)

    staged_in = _StagedStdin([
        _tool_call(
            "write_file",
            {"path": "denied.txt", "content": SECRET},
            call_id="write-deny",
        ),
        _tool_call(
            "write_file",
            {"path": "denied.txt", "content": SECRET},
            call_id="write-unused",
        ),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=staged_in,
            out=client_out,
            approval_ui_mode="none",
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        approval_url = first["error"]["data"]["approval_url"]
        with httpx.Client() as client:
            page = client.get(approval_url)
            match = CSRF_RE.search(page.text)
            client.post(approval_url, data={
                "decision": "deny",
                "approval_scope": "exact",
                "csrf_token": match.group(1),
            }).raise_for_status()
        staged_in.release_next()
        worker.join(timeout=10)
        assert _sandbox_files(sandbox) == before
        assert not (sandbox / "denied.txt").exists()
        metadata = _metadata_for_tool(home, tool="write_file")
        assert metadata["target_reached"] is False
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def test_exact_scope_approval_cannot_reuse_for_sibling_path(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    init = _init_quickstart(home, sandbox)
    _set_role_authority(init.config_path)
    _block_avp_agent(monkeypatch)

    staged_in = _StagedStdin([
        _tool_call(
            "write_file",
            {"path": "scope/a.txt", "content": "a"},
            call_id="scope-a-pending",
        ),
        _tool_call(
            "write_file",
            {"path": "scope/a.txt", "content": "a"},
            call_id="scope-a-retry",
        ),
        _tool_call(
            "write_file",
            {"path": "scope/b.txt", "content": "b"},
            call_id="scope-b-pending",
        ),
    ])
    client_out = io.StringIO()
    worker = threading.Thread(
        target=lambda: run_proxy(
            home=home,
            client_in=staged_in,
            out=client_out,
            approval_ui_mode="none",
        ),
        daemon=True,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not client_out.getvalue().strip():
            time.sleep(0.02)
        first = _responses(client_out.getvalue())[0]
        _approve_first_pending(home, first)
        staged_in.release_next()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and client_out.getvalue().count("\n") < 2:
            time.sleep(0.02)
        second = _responses(client_out.getvalue())[1]
        assert "result" in second
        assert (sandbox / "scope" / "a.txt").read_text(encoding="utf-8") == "a"
        staged_in.release_next()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and client_out.getvalue().count("\n") < 3:
            time.sleep(0.02)
        third = _responses(client_out.getvalue())[2]
        assert third["error"]["data"]["status"] == "approval_required"
        assert not (sandbox / "scope" / "b.txt").exists()
        worker.join(timeout=10)
    finally:
        staged_in.release_next()
        worker.join(timeout=1)


def test_instruction_file_write_requires_approval_before_mutation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_sandbox_file(sandbox, "AGENTS.md", "instruction body must not leak")
    before = _sandbox_files(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "write_file",
            {"path": "AGENTS.md", "content": "changed"},
            call_id="agents-write",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert response["error"]["data"]["reason"] == "instruction_file_write_requires_approval"
    assert _sandbox_files(sandbox) == before
    assert (sandbox / "AGENTS.md").read_text(encoding="utf-8") == "instruction body must not leak"
    assert "instruction body must not leak" not in out.getvalue()
    metadata = _metadata_for_tool(home, tool="write_file")
    assert metadata["target_reached"] is False
