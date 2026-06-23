"""Tests for product route catalog and policy (Product route catalog)."""

from __future__ import annotations

import json

import pytest

from agentveil_mcp_proxy.cli import init_proxy, load_proxy_config, main, proxy_paths
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
    assert len(PRODUCT_ROUTE_TOOL_CATALOG) == 68
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
