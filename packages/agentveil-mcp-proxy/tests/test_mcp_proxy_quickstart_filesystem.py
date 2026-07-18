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


def test_listing_filter_exact_metadata_components_only():
    from agentveil_mcp_proxy.quickstart_filesystem import (
        filter_workspace_listing_paths,
        is_hidden_listing_relative_path,
    )

    assert is_hidden_listing_relative_path(".git/config") is True
    assert is_hidden_listing_relative_path(".avp/state.json") is True
    assert is_hidden_listing_relative_path("docs/my.git.notes") is False
    assert is_hidden_listing_relative_path("docs/avp-guide.md") is False
    assert is_hidden_listing_relative_path(".github/workflows/ci.yml") is False
    assert is_hidden_listing_relative_path(".env.example") is False

    filtered = filter_workspace_listing_paths(
        None,
        [
            ".git/config",
            ".avp/state.json",
            ".avp/mcp-proxy/approval-center.manifest.json",
            "docs/my.git.notes",
            "docs/avp-guide.md",
            ".github/workflows/ci.yml",
            ".env.example",
        ],
    )
    assert filtered == [
        "docs/my.git.notes",
        "docs/avp-guide.md",
        ".github/workflows/ci.yml",
        ".env.example",
    ]


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


def test_safe_internal_dotdot_read_via_stdio_proxy(tmp_path, monkeypatch):
    """AV-07: ``ops/../ops/file`` stays inside the workspace after canonicalize."""

    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    content = '{"incident":true}'
    _seed_sandbox_file(sandbox, "ops/incident.json", content)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "read_file",
            {"path": "ops/../ops/incident.json"},
            call_id="dotdot-read",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert "error" not in response, response
    assert response["result"]["content"][0]["text"] == content
    metadata = _metadata_for_tool(home, tool="read_file")
    assert metadata["target_reached"] is True
    _assert_no_local_path_leaks(out.getvalue(), json.dumps(metadata))


@pytest.mark.parametrize(
    "safe_path",
    [
        "ops/../ops/incident.json",
        "./ops/./incident.json",
        "ops//incident.json",
        r"ops\..\ops\incident.json",
    ],
)
def test_safe_internal_path_variants_reach_same_file(tmp_path, safe_path):
    from agentveil_mcp_proxy.quickstart_filesystem import _handle_tools_call

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    content = "canonical-ok"
    _seed_sandbox_file(sandbox, "ops/incident.json", content)

    response = _handle_tools_call(
        sandbox,
        "canonical-variant",
        {"name": "read_file", "arguments": {"path": safe_path}},
    )
    assert "error" not in response, response
    assert response["result"]["content"][0]["text"] == content


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("get_file_info", {"path": "ops/../ops/incident.json"}),
        ("write_file", {"path": "ops/../ops/new.json", "content": '{"n":1}'}),
        ("delete_file", {"path": "ops/../ops/incident.json"}),
        ("rmdir_tree", {"path": "ops/../ops/removable"}),
        (
            "create_symlink",
            {"path": "ops/../ops/alias.json", "target": "incident.json"},
        ),
    ],
)
def test_safe_internal_dotdot_works_for_path_taking_tools(tmp_path, tool, arguments):
    from agentveil_mcp_proxy.quickstart_filesystem import _handle_tools_call

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside-marker.txt"
    outside.write_text("outside-stay", encoding="utf-8")
    _seed_sandbox_file(sandbox, "ops/incident.json", "seed")
    removable = sandbox / "ops" / "removable"
    removable.mkdir(parents=True, exist_ok=True)
    (removable / "nested.txt").write_text("remove-me", encoding="utf-8")
    before_outside = {
        path.name: path.read_text(encoding="utf-8") if path.is_file() else None
        for path in tmp_path.iterdir()
        if path != sandbox
    }

    response = _handle_tools_call(
        sandbox,
        f"canonical-{tool}",
        {"name": tool, "arguments": arguments},
    )
    assert "error" not in response, response
    blob = json.dumps(response)
    assert not any(marker in blob for marker in LOCAL_PATH_MARKERS)
    assert outside.read_text(encoding="utf-8") == "outside-stay"
    after_outside = {
        path.name: path.read_text(encoding="utf-8") if path.is_file() else None
        for path in tmp_path.iterdir()
        if path != sandbox
    }
    assert after_outside == before_outside
    if tool == "write_file":
        assert (sandbox / "ops" / "new.json").read_text(encoding="utf-8") == '{"n":1}'
    if tool == "delete_file":
        assert not (sandbox / "ops" / "incident.json").exists()
    if tool == "rmdir_tree":
        assert not removable.exists()
        assert (sandbox / "ops" / "incident.json").read_text(encoding="utf-8") == "seed"
        assert "ops/removable/nested.txt" not in _sandbox_files(sandbox)
    if tool == "create_symlink":
        assert (sandbox / "ops" / "alias.json").is_symlink()
    if tool == "get_file_info":
        payload = json.loads(response["result"]["content"][0]["text"])
        assert payload["path"] == "ops/incident.json"


@pytest.mark.parametrize(
    "bad_path",
    [
        "../outside.txt",
        "ops/../../outside.txt",
        "/etc/passwd",
        r"..\outside.txt",
        "ops/../../../outside.txt",
    ],
)
def test_escape_paths_remain_denied_after_canonicalize(tmp_path, monkeypatch, bad_path):
    home = tmp_path / "home"
    sandbox = tmp_path / "sandbox"
    _init_quickstart(home, sandbox)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside-secret", encoding="utf-8")
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call(
            "read_file",
            {"path": bad_path},
            call_id="escape-read",
        )),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert "error" in response
    serialized = json.dumps(response) + out.getvalue()
    assert "outside-secret" not in serialized
    _assert_no_local_path_leaks(serialized)
    assert outside.read_text(encoding="utf-8") == "outside-secret"


def test_symlink_escape_and_control_alias_remain_denied(tmp_path):
    from agentveil_mcp_proxy.quickstart_filesystem import _handle_tools_call

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("secret-bytes", encoding="utf-8")
    (sandbox / "looks-ok.txt").symlink_to(outside)
    control = sandbox / ".avp" / "mcp-proxy"
    control.mkdir(parents=True)
    (control / "approval-center.manifest.json").write_text(
        json.dumps({"session_token": "fixture-session-token-not-real"}),
        encoding="utf-8",
    )
    (sandbox / "alias-control").symlink_to(control, target_is_directory=True)

    escape = _handle_tools_call(
        sandbox,
        "sym-escape",
        {"name": "read_file", "arguments": {"path": "looks-ok.txt"}},
    )
    assert "error" in escape
    assert "secret-bytes" not in json.dumps(escape)

    direct = _handle_tools_call(
        sandbox,
        "ctrl-direct",
        {
            "name": "read_file",
            "arguments": {"path": ".avp/mcp-proxy/approval-center.manifest.json"},
        },
    )
    assert "error" in direct
    assert "fixture-session-token-not-real" not in json.dumps(direct)

    alias = _handle_tools_call(
        sandbox,
        "ctrl-alias",
        {
            "name": "read_file",
            "arguments": {"path": "alias-control/approval-center.manifest.json"},
        },
    )
    assert "error" in alias
    assert "fixture-session-token-not-real" not in json.dumps(alias)

    listed = _handle_tools_call(
        sandbox,
        "list-1",
        {"name": "list_workspace", "arguments": {}},
    )
    listing = listed["result"]["content"][0]["text"]
    assert ".avp/mcp-proxy" not in listing
    assert "alias-control" not in listing


def _symlinked_sandbox(tmp_path: Path) -> tuple[Path, Path]:
    """Create ``product-profile/workspace -> real-workspace`` like public setup."""

    real = tmp_path / "real-workspace"
    real.mkdir()
    link = tmp_path / "product-profile" / "workspace"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(real, target_is_directory=True)
    return real, link


def test_symlink_sandbox_root_write_file_returns_relative_success(tmp_path):
    """Approved write under a symlinked sandbox root must not fail after mutation."""

    from agentveil_mcp_proxy.quickstart_filesystem import _handle_tools_call

    real, link = _symlinked_sandbox(tmp_path)
    canary = "ops/existing.json"
    content = '{"updated":true}'

    response = _handle_tools_call(
        link,
        "symlink-write",
        {"name": "write_file", "arguments": {"path": canary, "content": content}},
    )
    assert "error" not in response, response
    text = response["result"]["content"][0]["text"]
    assert text == f"wrote {canary}"
    assert not any(marker in text for marker in LOCAL_PATH_MARKERS)
    assert (real / canary).read_text(encoding="utf-8") == content


def test_symlink_sandbox_root_create_and_update_canaries(tmp_path):
    from agentveil_mcp_proxy.quickstart_filesystem import _handle_tools_call

    real, link = _symlinked_sandbox(tmp_path)
    create_path = ".agentveil-test/canary.txt"
    update_path = "ops/existing.json"
    (real / "ops").mkdir()
    (real / update_path).write_text('{"seed":true}', encoding="utf-8")

    created = _handle_tools_call(
        link,
        "create-1",
        {"name": "write_file", "arguments": {"path": create_path, "content": "canary-create"}},
    )
    assert "error" not in created, created
    assert (real / create_path).read_text(encoding="utf-8") == "canary-create"

    updated = _handle_tools_call(
        link,
        "update-1",
        {"name": "write_file", "arguments": {"path": update_path, "content": '{"updated":true}'}},
    )
    assert "error" not in updated, updated
    assert (real / update_path).read_text(encoding="utf-8") == '{"updated":true}'


def test_symlink_sandbox_root_get_file_info_read_list(tmp_path):
    from agentveil_mcp_proxy.quickstart_filesystem import _handle_tools_call

    real, link = _symlinked_sandbox(tmp_path)
    (real / "probe.txt").write_text("probe", encoding="utf-8")

    info = _handle_tools_call(
        link,
        "info-1",
        {"name": "get_file_info", "arguments": {"path": "probe.txt"}},
    )
    assert "error" not in info, info
    payload = json.loads(info["result"]["content"][0]["text"])
    assert payload["path"] == "probe.txt"
    assert not any(marker in payload["path"] for marker in LOCAL_PATH_MARKERS)

    read = _handle_tools_call(
        link,
        "read-1",
        {"name": "read_file", "arguments": {"path": "probe.txt"}},
    )
    assert read["result"]["content"][0]["text"] == "probe"

    listing = _handle_tools_call(link, "list-1", {"name": "list_workspace", "arguments": {}})
    assert "probe.txt" in listing["result"]["content"][0]["text"]


def test_symlink_sandbox_root_delete_file_and_rmdir_tree(tmp_path):
    from agentveil_mcp_proxy.quickstart_filesystem import _handle_tools_call

    real, link = _symlinked_sandbox(tmp_path)
    (real / "gone.txt").write_text("x", encoding="utf-8")
    (real / "tree" / "nested").mkdir(parents=True)
    (real / "tree" / "nested" / "keep.txt").write_text("y", encoding="utf-8")

    deleted = _handle_tools_call(
        link,
        "del-1",
        {"name": "delete_file", "arguments": {"path": "gone.txt"}},
    )
    assert "error" not in deleted, deleted
    assert deleted["result"]["content"][0]["text"] == "deleted gone.txt"
    assert not (real / "gone.txt").exists()

    removed = _handle_tools_call(
        link,
        "rmdir-1",
        {"name": "rmdir_tree", "arguments": {"path": "tree"}},
    )
    assert "error" not in removed, removed
    assert removed["result"]["content"][0]["text"] == "removed tree"
    assert not (real / "tree").exists()


def test_symlink_sandbox_root_keeps_escape_and_control_denials(tmp_path):
    from agentveil_mcp_proxy.quickstart_filesystem import _handle_tools_call

    real, link = _symlinked_sandbox(tmp_path)
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("secret", encoding="utf-8")
    (real / "escape-link.txt").symlink_to(outside)
    control = real / ".avp" / "mcp-proxy"
    control.mkdir(parents=True)
    (control / "approval-center.manifest.json").write_text(
        json.dumps({"session_token": "fixture-session-token-not-real"}),
        encoding="utf-8",
    )
    (real / "alias-control").symlink_to(control, target_is_directory=True)
    (real / "docs").mkdir()
    (real / "docs" / "approval-center.manifest.json").write_text(
        json.dumps({"note": "user-owned"}),
        encoding="utf-8",
    )

    escape = _handle_tools_call(
        link,
        "escape-1",
        {"name": "write_file", "arguments": {"path": "escape-link.txt", "content": "nope"}},
    )
    assert "error" in escape
    assert outside.read_text(encoding="utf-8") == "secret"

    denied = _handle_tools_call(
        link,
        "ctrl-1",
        {
            "name": "read_file",
            "arguments": {"path": ".avp/mcp-proxy/approval-center.manifest.json"},
        },
    )
    assert "error" in denied

    alias = _handle_tools_call(
        link,
        "alias-1",
        {"name": "read_file", "arguments": {"path": "alias-control/approval-center.manifest.json"}},
    )
    assert "error" in alias

    listing = _handle_tools_call(link, "list-ctrl", {"name": "list_workspace", "arguments": {}})
    listed = listing["result"]["content"][0]["text"]
    assert ".avp/mcp-proxy" not in listed
    assert "alias-control" not in listed

    user_manifest = _handle_tools_call(
        link,
        "user-manifest",
        {"name": "read_file", "arguments": {"path": "docs/approval-center.manifest.json"}},
    )
    assert "user-owned" in user_manifest["result"]["content"][0]["text"]
