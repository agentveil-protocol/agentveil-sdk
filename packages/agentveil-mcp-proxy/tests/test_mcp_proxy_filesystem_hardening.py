"""Product-route filesystem hardening proofs through the MCP proxy."""

from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path

import httpx
import pytest
import webbrowser

import agentveil_mcp_proxy.cli as proxy_cli
from conftest import operator_approval_url
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


def _evidence_records(home: Path) -> list[dict]:
    evidence_path = home / "mcp-proxy" / "evidence.sqlite"
    if not evidence_path.exists():
        return []
    with sqlite3.connect(evidence_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM pending_approvals ORDER BY created_at, request_id"
        ).fetchall()
    return [dict(row) for row in rows]


def _assert_terminal_deny_record(
    home: Path,
    *,
    tool: str,
    reason: str,
    forbidden: str,
) -> None:
    records = _evidence_records(home)
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "blocked"
    assert record["error_class"] == reason
    assert record["result_status"] == "blocked"
    assert record["tool_name"] == tool
    assert forbidden not in json.dumps(record)


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
    pending_id = response["error"]["data"]["record_id"]
    approval_url = operator_approval_url(pending_id)
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
        pending_id = first["error"]["data"]["record_id"]
        approval_url = operator_approval_url(pending_id)
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


FIXTURE_SESSION_TOKEN = "FIXTURE_SESSION_TOKEN_DO_NOT_LEAK_001"
FIXTURE_REGISTER_TOKEN = "FIXTURE_REGISTER_TOKEN_DO_NOT_LEAK_002"
MANIFEST_REL = ".avp/mcp-proxy/approval-center.manifest.json"
NESTED_CONTROL_REL = ".avp/mcp-proxy/nested/evidence.sqlite"


def _seed_agentveil_control_artifacts(sandbox: Path) -> None:
    manifest_dir = sandbox / ".avp" / "mcp-proxy"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "approval-center.manifest.json").write_text(
        json.dumps(
            {
                "session_token": FIXTURE_SESSION_TOKEN,
                "internal_register_token": FIXTURE_REGISTER_TOKEN,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    nested = manifest_dir / "nested"
    nested.mkdir(parents=True, exist_ok=True)
    (nested / "evidence.sqlite").write_bytes(b"fixture-evidence-db")


def test_list_workspace_excludes_agentveil_control_artifacts(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_sandbox_file(sandbox, "ordinary.txt", "visible")
    _seed_agentveil_control_artifacts(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("list_workspace", {}, call_id="list-control-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    listing = response["result"]["content"][0]["text"]
    assert "ordinary.txt" in listing
    assert MANIFEST_REL not in listing
    assert NESTED_CONTROL_REL not in listing
    assert ".avp/mcp-proxy" not in listing
    assert FIXTURE_SESSION_TOKEN not in out.getvalue()
    assert FIXTURE_REGISTER_TOKEN not in out.getvalue()

    metadata = _metadata_for_tool(home, tool="list_workspace")
    assert metadata["target_reached"] is True
    _assert_no_local_path_leaks(out.getvalue(), json.dumps(metadata))


def test_list_workspace_hides_git_and_avp_metadata_but_keeps_useful_paths(
    tmp_path,
    monkeypatch,
):
    """AV-08: list_workspace must not disclose .git/** or .avp/** metadata."""

    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_sandbox_file(sandbox, "ordinary.txt", "visible")
    _seed_sandbox_file(sandbox, ".env.example", "ENV=example")
    _seed_sandbox_file(sandbox, ".github/workflows/ci.yml", "name: ci")
    _seed_sandbox_file(sandbox, "docs/avp-guide.md", "guide")
    _seed_sandbox_file(sandbox, "docs/my.git.notes", "notes")
    _seed_sandbox_file(sandbox, "docs/approval-center.manifest.json", '{"note":"user"}')
    _seed_sandbox_file(sandbox, ".git/config", "secret-git-config")
    _seed_sandbox_file(sandbox, ".avp/state.json", "secret-avp-state")
    _seed_agentveil_control_artifacts(sandbox)
    (sandbox / "alias-git").symlink_to(sandbox / ".git", target_is_directory=True)
    (sandbox / "alias-avp-state.json").symlink_to(sandbox / ".avp" / "state.json")
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("list_workspace", {}, call_id="list-av08")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    listing = response["result"]["content"][0]["text"]
    listed = [line for line in listing.splitlines() if line.strip()]
    for expected in (
        "ordinary.txt",
        ".env.example",
        ".github/workflows/ci.yml",
        "docs/avp-guide.md",
        "docs/my.git.notes",
        "docs/approval-center.manifest.json",
    ):
        assert expected in listed, listed
    for forbidden in (
        ".git/config",
        ".avp/state.json",
        MANIFEST_REL,
        "alias-git/config",
        "alias-avp-state.json",
    ):
        assert forbidden not in listed, listed
        assert forbidden not in listing
    assert "secret-git-config" not in out.getvalue()
    assert "secret-avp-state" not in out.getvalue()
    assert FIXTURE_SESSION_TOKEN not in out.getvalue()
    _assert_no_local_path_leaks(out.getvalue())

    # Read/write outside .avp/mcp-proxy remain unchanged by the listing filter.
    read_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "read_file",
            {"path": ".git/config"},
            call_id="read-git-still-allowed",
        )),
        out=read_out,
        approval_ui_mode="none",
    ) == 0
    read_response = _responses(read_out.getvalue())[0]
    assert "error" not in read_response, read_response
    assert read_response["result"]["content"][0]["text"] == "secret-git-config"


@pytest.mark.parametrize(
    "manifest_path",
    [
        MANIFEST_REL,
        ".AVP/MCP-PROXY/approval-center.manifest.json",
        "./.avp/mcp-proxy/approval-center.manifest.json",
        ".avp//mcp-proxy/approval-center.manifest.json",
        NESTED_CONTROL_REL,
    ],
)
def test_read_file_rejects_agentveil_control_paths(
    tmp_path,
    monkeypatch,
    manifest_path: str,
):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_agentveil_control_artifacts(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "read_file",
            {"path": manifest_path},
            call_id=f"read-control-{manifest_path}",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert response["error"]["code"] == -32010
    assert response["error"]["data"]["status"] == "policy_denied"
    assert response["error"]["data"]["reason"] == "agentveil_control_path_blocked"
    assert response["error"]["data"]["approval_possible"] is False
    assert FIXTURE_SESSION_TOKEN not in out.getvalue()
    assert FIXTURE_REGISTER_TOKEN not in out.getvalue()

    _assert_terminal_deny_record(
        home,
        tool="read_file",
        reason="agentveil_control_path_blocked",
        forbidden=FIXTURE_SESSION_TOKEN,
    )


def test_similarly_named_user_manifest_outside_control_dir_still_readable(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    user_manifest = "docs/approval-center.manifest.json"
    _seed_sandbox_file(
        sandbox,
        user_manifest,
        json.dumps({"note": "user-owned manifest copy", "session_token": "user-copy-not-control"}),
    )
    _seed_agentveil_control_artifacts(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "read_file",
            {"path": user_manifest},
            call_id="read-user-manifest",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert "result" in response
    assert FIXTURE_SESSION_TOKEN not in response["result"]["content"][0]["text"]
    assert "user-owned manifest copy" in response["result"]["content"][0]["text"]


def _seed_control_symlink_aliases(sandbox: Path) -> tuple[str, str]:
    _seed_agentveil_control_artifacts(sandbox)
    alias_dir = sandbox / "alias"
    alias_dir.symlink_to(sandbox / ".avp" / "mcp-proxy", target_is_directory=True)
    alias_file = sandbox / "alias-manifest.json"
    alias_file.symlink_to(sandbox / ".avp" / "mcp-proxy" / "approval-center.manifest.json")
    return "alias/approval-center.manifest.json", "alias-manifest.json"


def test_list_workspace_excludes_symlink_aliases_to_control_directory(tmp_path, monkeypatch):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_sandbox_file(sandbox, "ordinary.txt", "visible")
    manifest_alias, file_alias = _seed_control_symlink_aliases(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("list_workspace", {}, call_id="list-symlink-alias")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    listing = _responses(out.getvalue())[0]["result"]["content"][0]["text"]
    assert "ordinary.txt" in listing
    assert MANIFEST_REL not in listing
    assert manifest_alias not in listing
    assert file_alias not in listing
    assert FIXTURE_SESSION_TOKEN not in out.getvalue()


@pytest.mark.parametrize(
    "alias_path",
    [
        "alias/approval-center.manifest.json",
        "alias-manifest.json",
    ],
)
def test_read_file_rejects_symlink_aliases_to_control_artifacts(
    tmp_path,
    monkeypatch,
    alias_path: str,
):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    _seed_control_symlink_aliases(sandbox)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "read_file",
            {"path": alias_path},
            call_id=f"read-symlink-{alias_path}",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert response["error"]["code"] == -32010
    assert response["error"]["data"]["reason"] == "agentveil_control_path_blocked"
    assert FIXTURE_SESSION_TOKEN not in out.getvalue()
    assert FIXTURE_REGISTER_TOKEN not in out.getvalue()
    _assert_terminal_deny_record(
        home,
        tool="read_file",
        reason="agentveil_control_path_blocked",
        forbidden=FIXTURE_SESSION_TOKEN,
    )
