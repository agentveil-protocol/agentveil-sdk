"""Tests for product route catalog and policy (Product route catalog)."""

from __future__ import annotations

import io
import json
import os
import webbrowser
from pathlib import Path

import pytest

import agentveil_mcp_proxy.cli as proxy_cli
from agentveil_mcp_proxy.cli import init_proxy, load_proxy_config, main, proxy_paths, run_proxy
from agentveil_mcp_proxy.policy import PolicyDecision
from agentveil_mcp_proxy.product_route import (
    FILESYSTEM_PRODUCT_TOOLS,
    GITHUB_PRODUCT_TOOLS,
    GIT_PRODUCT_TOOLS,
    PACKAGE_PRODUCT_TOOLS,
    PRODUCT_ROUTE_ACCEPTED_PACKS,
    PRODUCT_ROUTE_DOWNSTREAM_NAME,
    PRODUCT_ROUTE_POLICY_ID,
    PRODUCT_ROUTE_SETUP_PROFILE,
    PRODUCT_ROUTE_TOOL_CATALOG,
    PRODUCT_ROUTE_TOOL_PACK,
    PRODUCT_ROUTE_WORKSPACE_DIRNAME,
    SANDBOX_READ_ONLY_MCP_TOOLS,
    _pack_policy_expectation,
    build_product_route_downstream_config,
    build_product_route_policy,
    build_product_route_policy_expectations,
    evaluate_product_route_tool,
    initialize_product_route_profile,
    product_route_rule_id,
    product_route_tool_pack,
)
from agentveil_mcp_proxy.product_route_tool_schemas import build_product_route_tool_entries
from mcp_fake_downstream import (
    GITHUB_PACK_TOOL_NAMES,
    GIT_PACK_TOOL_NAMES,
    PACKAGE_INSTALL_TOOL_NAMES,
)


QUICKSTART_FILESYSTEM_TOOL_NAMES: tuple[str, ...] = (
    "list_workspace",
    "read_file",
    "get_file_info",
    "instruction_surface_status",
    "write_file",
    "delete_file",
    "rmdir_tree",
    "move_file",
    "copy_file",
    "chmod_file",
    "create_symlink",
)


@pytest.mark.parametrize(
    ("pack_tools", "pack_name"),
    [
        (FILESYSTEM_PRODUCT_TOOLS, "filesystem"),
        (GIT_PRODUCT_TOOLS, "git"),
        (PACKAGE_PRODUCT_TOOLS, "package"),
        (GITHUB_PRODUCT_TOOLS, "github"),
    ],
)
def test_product_route_pack_constants_are_subset_of_catalog(
    pack_tools: tuple[str, ...],
    pack_name: str,
) -> None:
    assert pack_name in PRODUCT_ROUTE_ACCEPTED_PACKS
    for tool in pack_tools:
        assert tool in PRODUCT_ROUTE_TOOL_CATALOG
    owned = [tool for tool in pack_tools if product_route_tool_pack(tool) == pack_name]
    assert owned, f"expected at least one {pack_name}-owned tool"


def test_product_route_catalog_matches_existing_pack_constants() -> None:
    assert FILESYSTEM_PRODUCT_TOOLS == QUICKSTART_FILESYSTEM_TOOL_NAMES
    assert GIT_PRODUCT_TOOLS == GIT_PACK_TOOL_NAMES
    assert PACKAGE_PRODUCT_TOOLS == PACKAGE_INSTALL_TOOL_NAMES
    assert GITHUB_PRODUCT_TOOLS == GITHUB_PACK_TOOL_NAMES


def test_product_route_catalog_is_complete_and_deduplicated() -> None:
    assert len(PRODUCT_ROUTE_TOOL_CATALOG) == len(set(PRODUCT_ROUTE_TOOL_CATALOG))
    assert len(PRODUCT_ROUTE_TOOL_CATALOG) == 70
    assert PRODUCT_ROUTE_TOOL_CATALOG.count("instruction_surface_status") == 1
    assert product_route_tool_pack("instruction_surface_status") == "filesystem"


def test_product_route_policy_metadata() -> None:
    policy = build_product_route_policy()
    assert policy.id == PRODUCT_ROUTE_POLICY_ID
    assert len(policy.rules) == len(PRODUCT_ROUTE_TOOL_CATALOG)
    assert all(rule.match.server == () for rule in policy.rules)  # claim-check: allow "all" is test quantifier over rules.
    assert all(len(rule.match.tool) == 1 for rule in policy.rules)  # claim-check: allow "all" is test quantifier over rules.


def test_product_route_expectations_cover_full_catalog() -> None:
    expectations = build_product_route_policy_expectations()
    assert {item.tool for item in expectations} == set(PRODUCT_ROUTE_TOOL_CATALOG)
    assert len(expectations) == len(PRODUCT_ROUTE_TOOL_CATALOG)


@pytest.mark.parametrize(
    ("tool", "pack", "decision", "source_rule_suffix"),
    [
        ("list_workspace", "filesystem", PolicyDecision.ALLOW, "filesystem-read"),
        ("read_file", "filesystem", PolicyDecision.ALLOW, "filesystem-read"),
        ("get_file_info", "filesystem", PolicyDecision.ALLOW, "filesystem-read"),
        ("list_issues", "github", PolicyDecision.ALLOW, "github-read"),
        ("list_files", "github", PolicyDecision.ALLOW, "github-read"),
        ("instruction_surface_status", "filesystem", PolicyDecision.ALLOW, "filesystem-read"),
        ("get_repository", "github", PolicyDecision.ALLOW, "github-read"),
        ("get_ci_job", "github", PolicyDecision.ALLOW, "github-read"),
        ("get_secret", "github", PolicyDecision.BLOCK, "github-secrets-block"),
        ("git_add", "git", PolicyDecision.APPROVAL, "git-write"),
        ("add_labels", "github", PolicyDecision.APPROVAL, "github-write"),
        ("remove_labels", "github", PolicyDecision.APPROVAL, "github-write"),
        ("write_file", "filesystem", PolicyDecision.APPROVAL, "filesystem-write"),
        ("delete_file", "filesystem", PolicyDecision.BLOCK, "filesystem-delete"),
        ("pip_install", "package", PolicyDecision.APPROVAL, "package-write"),
        ("merge_pull_request", "github", PolicyDecision.APPROVAL, "github-write"),
        ("deploy_release", "github", PolicyDecision.APPROVAL, "github-write"),
        ("ci_repo_target_snapshot", "github", PolicyDecision.ALLOW, "github-read"),
    ],
)
def test_product_route_policy_collision_tools(
    tool: str,
    pack: str,
    decision: PolicyDecision,
    source_rule_suffix: str,
) -> None:
    evaluation = evaluate_product_route_tool(tool)
    assert product_route_tool_pack(tool) == pack
    assert evaluation.decision == decision
    assert evaluation.policy_rule_id == product_route_rule_id(pack=pack, tool=tool)
    expectations = {
        item.tool: item for item in build_product_route_policy_expectations()
    }
    assert expectations[tool].source_pack_rule_id == source_rule_suffix


def test_product_route_policy_uses_product_downstream_server() -> None:
    evaluation = evaluate_product_route_tool("git_status")
    assert evaluation.policy_rule_id == product_route_rule_id(pack="git", tool="git_status")
    assert evaluation.decision == PolicyDecision.ALLOW


def test_product_route_setup_profile_constant_is_stable() -> None:
    assert PRODUCT_ROUTE_SETUP_PROFILE == "product_route"
    assert PRODUCT_ROUTE_DOWNSTREAM_NAME == "product"


def test_product_route_profile_unifies_filesystem_and_git_workspace(tmp_path) -> None:
    profile_root = tmp_path / "profile"
    profile = initialize_product_route_profile(profile_root)
    workspace = (profile_root / PRODUCT_ROUTE_WORKSPACE_DIRNAME).resolve()
    assert profile.filesystem_sandbox == profile.git_repo == workspace
    assert (workspace / "README.md").is_file()
    assert (workspace / "seed.txt").read_text(encoding="utf-8") == "seed\n"


def test_product_route_init_does_not_persist_role_authority(tmp_path) -> None:
    profile_root = tmp_path / "profile"
    home = tmp_path / "home"
    initialize_product_route_profile(profile_root)
    downstream = build_product_route_downstream_config(profile_root)
    result = init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="product_route",
        setup_profile=PRODUCT_ROUTE_SETUP_PROFILE,
        downstream_config=downstream,
    )
    config = load_proxy_config(result.config_path)
    assert config.setup_profile == PRODUCT_ROUTE_SETUP_PROFILE
    assert config.role_preset is None
    assert not config.role_authority.is_enforced()
    raw_config = json.loads(result.config_path.read_text(encoding="utf-8"))
    assert "role_preset" not in raw_config
    assert "role_authority" not in raw_config


def test_product_route_init_json_omits_role_fields(tmp_path, capsys) -> None:
    profile_root = tmp_path / "profile"
    home = tmp_path / "home"
    passphrase_file = tmp_path / "pass.txt"
    passphrase_file.write_text("product-route-passphrase-12345", encoding="utf-8")
    passphrase_file.chmod(0o600)

    exit_code = main([
        "init",
        "--product-route-profile",
        str(profile_root),
        "--home",
        str(home),
        "--agent-name",
        "proxy",
        "--passphrase-file",
        str(passphrase_file),
        "--json",
    ])
    out, err = capsys.readouterr()
    assert exit_code == 0
    assert err == ""
    payload = json.loads(out)
    assert payload["setup_profile"] == PRODUCT_ROUTE_SETUP_PROFILE
    assert "role_preset" not in payload
    assert "role_authority" not in payload
    raw_config = json.loads(proxy_paths(home).config_path.read_text(encoding="utf-8"))
    assert "role_preset" not in raw_config
    assert "role_authority" not in raw_config


def test_unknown_tool_is_not_in_catalog() -> None:
    with pytest.raises(KeyError, match="not in PRODUCT_ROUTE_TOOL_CATALOG"):
        evaluate_product_route_tool("definitely_missing_tool")


@pytest.mark.parametrize("tool", sorted(SANDBOX_READ_ONLY_MCP_TOOLS))
def test_sandbox_read_only_tools_allow_on_filesystem_pack(tool: str) -> None:
    from agentveil_mcp_proxy.classification import infer_risk_class

    assert infer_risk_class(f"filesystem.{tool}", tool=tool, resource=None, arguments={}).value == "read"
    expectation = _pack_policy_expectation(pack="filesystem", tool=tool)
    assert expectation.decision == PolicyDecision.ALLOW
    assert expectation.source_pack_rule_id == "filesystem-read"


def test_product_route_pack_schemas_default_profile_paths_without_requirements() -> None:
    entries = {entry["name"]: entry for entry in build_product_route_tool_entries()}
    for name in GIT_PRODUCT_TOOLS:
        if name not in entries:
            continue
        schema = entries[name]["inputSchema"]
        assert "repo_path" not in schema.get("required", [])
    for name in PACKAGE_PRODUCT_TOOLS:
        schema = entries[name]["inputSchema"]
        assert "project_path" not in schema.get("required", [])
    for name in GITHUB_PRODUCT_TOOLS:
        schema = entries[name]["inputSchema"]
        assert "owner" not in schema.get("required", [])
        assert "repo" not in schema.get("required", [])


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


def _tools_list_request(*, call_id: str = "list-1") -> str:
    return _json_line({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/list",
        "params": {},
    })


def _workspace_pythonpath() -> str:
    proxy_root = Path(__file__).resolve().parents[1]
    repo_root = proxy_root.parents[1]
    return os.pathsep.join((str(repo_root), str(proxy_root)))


def _init_product_route_proxy(home, profile_root):
    initialize_product_route_profile(profile_root)
    downstream = build_product_route_downstream_config(profile_root)
    env = dict(downstream.get("env", {}))
    pythonpath = _workspace_pythonpath()
    if env.get("PYTHONPATH"):
        pythonpath = f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
    env["PYTHONPATH"] = pythonpath
    downstream["env"] = env
    return init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="product_route",
        setup_profile=PRODUCT_ROUTE_SETUP_PROFILE,
        downstream_config=downstream,
    )


def _block_avp_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("product route proxy must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)


def test_product_route_tools_list_includes_read_only_filesystem_tools(
    tmp_path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    profile_root = tmp_path / "profile"
    _init_product_route_proxy(home, profile_root)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tools_list_request()),
        out=out,
        approval_ui_mode="none",
    ) == 0

    tools = _responses(out.getvalue())[0]["result"]["tools"]
    tool_names = [entry["name"] for entry in tools]
    assert tool_names == list(PRODUCT_ROUTE_TOOL_CATALOG)
    assert "read_file" in tool_names
    assert "get_file_info" in tool_names


def test_product_route_read_file_succeeds_without_approval(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    profile_root = tmp_path / "profile"
    _init_product_route_proxy(home, profile_root)
    probe = profile_root / PRODUCT_ROUTE_WORKSPACE_DIRNAME / "probe.txt"
    probe.write_text("read-me\n", encoding="utf-8")
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("read_file", {"path": "probe.txt"}, call_id="read-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert "error" not in response
    assert response["result"]["content"][0]["text"] == "read-me\n"


def test_product_route_get_file_info_succeeds_without_approval(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    profile_root = tmp_path / "profile"
    _init_product_route_proxy(home, profile_root)
    probe = profile_root / PRODUCT_ROUTE_WORKSPACE_DIRNAME / "probe.txt"
    probe.write_text("meta\n", encoding="utf-8")
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("get_file_info", {"path": "probe.txt"}, call_id="info-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert "error" not in response
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["path"] == "probe.txt"
    assert payload["size_bytes"] == len("meta\n")


@pytest.mark.parametrize("bad_path", ["../outside.txt", "/etc/passwd", "nested/../../outside.txt"])
def test_product_route_read_file_blocks_path_traversal(
    tmp_path,
    monkeypatch,
    bad_path: str,
) -> None:
    home = tmp_path / "home"
    profile_root = tmp_path / "profile"
    _init_product_route_proxy(home, profile_root)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("read_file", {"path": bad_path}, call_id="traversal-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    assert "error" in response
    assert response["error"]["code"] in {-32010, -32602}


def test_product_route_unknown_tool_call_fails_closed(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    profile_root = tmp_path / "profile"
    _init_product_route_proxy(home, profile_root)
    _block_avp_agent(monkeypatch)

    out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_tool_call("definitely_missing_tool", {}, call_id="unknown-1")),
        out=out,
        approval_ui_mode="none",
    ) == 0

    response = _responses(out.getvalue())[0]
    # claim-check: allow "blocked" as the expected fail-closed JSON-RPC status for unknown tools.
    data = response["error"]["data"]
    assert data["status"] == "blocked"  # claim-check: allow bounded JSON-RPC status vocabulary; this test asserts fail-closed handling.
    assert data["reason"] == "unknown_tool"
    assert data["approval_possible"] is False
    assert data["retry_after_approval"] is False
    assert data["reason_code"] == "unknown_tool"
    assert data["next_step"]
