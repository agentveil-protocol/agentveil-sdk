"""Regression proofs for compact product-route GitHub tool schemas."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from agentveil_mcp_proxy.product_route import (
    GITHUB_PRODUCT_TOOLS,
    PRODUCT_ROUTE_TOOL_CATALOG,
    PRODUCT_ROUTE_TOOL_PACK,
)
from agentveil_mcp_proxy.product_route_tool_schemas import (
    build_product_route_tool_entries,
    measure_product_route_tools_list_size,
)
from agentveil_mcp_proxy.tool_schema_validation import validate_arguments

FIXTURES = Path(__file__).with_name("fixtures")
SIZE_BASELINE_PATH = FIXTURES / "product_route_tool_schema_size_baseline.json"
CATALOG_CONTRACT_PATH = FIXTURES / "product_route_tool_catalog_contract.json"

# Fields from the legacy shared GitHub schema.
_SHARED_GITHUB_FIELDS = frozenset({
    "owner",
    "repo",
    "repo_root",
    "issue_number",
    "pull_number",
    "comment_body",
    "branch",
    "secret_name",
    "visibility",
    "tag_name",
    "workflow_run_id",
})

_REPO_TARGET = frozenset({"owner", "repo", "repo_root"})

# Exact advertised property sets after compaction. Keep this exhaustive for the
# GitHub pack so schema compaction cannot silently drop a handler-relevant arg.
_EXPECTED_GITHUB_PROPERTIES: dict[str, frozenset[str]] = {
    "get_repository": _REPO_TARGET,
    "list_issues": _REPO_TARGET,
    "get_issue": _REPO_TARGET | frozenset({"issue_number"}),
    "list_pull_requests": _REPO_TARGET,
    "get_pull_request": _REPO_TARGET | frozenset({"pull_number"}),
    "list_comments": _REPO_TARGET | frozenset({"issue_number", "pull_number"}),
    "list_branches": _REPO_TARGET,
    "list_files": _REPO_TARGET,
    "list_secret_names": _REPO_TARGET,
    "get_repository_settings": _REPO_TARGET,
    "list_workflow_runs": _REPO_TARGET,
    "list_workflows": _REPO_TARGET,
    "get_workflow": _REPO_TARGET,
    "list_ci_jobs": _REPO_TARGET,
    "get_ci_job": _REPO_TARGET,
    "get_package_metadata": _REPO_TARGET,
    "untrusted_context_status": _REPO_TARGET,
    "github_target_snapshot": _REPO_TARGET,
    "ci_repo_target_snapshot": _REPO_TARGET,
    "create_issue": _REPO_TARGET,
    "create_comment": _REPO_TARGET | frozenset({"issue_number", "pull_number", "comment_body"}),
    "update_issue": _REPO_TARGET | frozenset({"issue_number"}),
    "add_labels": _REPO_TARGET | frozenset({"issue_number"}),
    "remove_labels": _REPO_TARGET | frozenset({"issue_number"}),
    "request_review": _REPO_TARGET | frozenset({"pull_number"}),
    "merge_pull_request": _REPO_TARGET | frozenset({"pull_number"}),
    "close_issue": _REPO_TARGET | frozenset({"issue_number"}),
    "delete_branch": _REPO_TARGET | frozenset({"branch"}),
    "create_release": _REPO_TARGET | frozenset({"tag_name"}),
    "update_repository_settings": _REPO_TARGET | frozenset({"visibility"}),
    "manage_secret": _REPO_TARGET | frozenset({"secret_name"}),
    "rerun_workflow": _REPO_TARGET | frozenset({"workflow_run_id"}),
    "cancel_workflow": _REPO_TARGET | frozenset({"workflow_run_id"}),
    "dispatch_workflow": _REPO_TARGET | frozenset({"branch"}),
    "publish_package": _REPO_TARGET,
    "deploy_release": _REPO_TARGET,
    "run_remote_command": _REPO_TARGET,
    "get_secret": _REPO_TARGET | frozenset({"secret_name"}),
    "get_env_secret": _REPO_TARGET | frozenset({"secret_name"}),
}

# Negative cases: fields that must not appear on these tools.
_FORBIDDEN_ON_TOOL: dict[str, frozenset[str]] = {
    "list_issues": frozenset({
        "issue_number", "pull_number", "comment_body", "secret_name",
        "tag_name", "visibility", "workflow_run_id", "branch",
    }),
    "create_comment": frozenset({
        "secret_name", "tag_name", "visibility", "workflow_run_id", "branch",
    }),
    "create_release": frozenset({
        "issue_number", "pull_number", "comment_body", "secret_name",
        "visibility", "workflow_run_id", "branch",
    }),
    "manage_secret": frozenset({
        "issue_number", "pull_number", "comment_body", "tag_name",
        "visibility", "workflow_run_id", "branch",
    }),
    "dispatch_workflow": frozenset({
        "issue_number", "pull_number", "comment_body", "secret_name",
        "tag_name", "visibility", "workflow_run_id",
    }),
}


def _tool_names_hash(names: list[str]) -> str:
    payload = json.dumps(names, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_size_baseline() -> dict[str, object]:
    return json.loads(SIZE_BASELINE_PATH.read_text(encoding="utf-8"))


def _load_catalog_contract() -> dict[str, object]:
    return json.loads(CATALOG_CONTRACT_PATH.read_text(encoding="utf-8"))


def test_catalog_contract_unchanged_after_schema_compaction() -> None:
    contract = _load_catalog_contract()
    expected_tools = contract["tools"]
    assert isinstance(expected_tools, list)
    expected_names = [row["name"] for row in expected_tools]
    expected_packs = {row["name"]: row["pack"] for row in expected_tools}
    actual_names = list(PRODUCT_ROUTE_TOOL_CATALOG)

    assert contract["catalog_count"] == 71
    assert len(actual_names) == 71
    assert actual_names == expected_names
    assert {
        name: PRODUCT_ROUTE_TOOL_PACK[name]
        for name in actual_names
    } == expected_packs
    assert dict(Counter(expected_packs.values())) == contract["pack_counts"]
    assert _tool_names_hash(actual_names) == contract["tool_names_sha256"]


def test_tools_list_and_schema_bytes_shrink_vs_baseline() -> None:
    baseline = _load_size_baseline()
    measured = measure_product_route_tools_list_size()

    assert measured["tool_count"] == baseline["tool_count"] == 71
    assert measured["tools_list_bytes"] < int(baseline["tools_list_bytes"])
    assert measured["schema_bytes"] < int(baseline["schema_bytes"])
    assert measured["github_schema_bytes"] < int(baseline["github_schema_bytes"])
    # GitHub pack was the dominant schema cost; require a material drop.
    github_saved = int(baseline["github_schema_bytes"]) - measured["github_schema_bytes"]
    assert github_saved >= 10_000
    assert measured["github_schema_bytes"] <= int(baseline["github_schema_bytes"]) // 2


def test_github_tools_no_longer_advertise_unrelated_fields() -> None:
    entries = {entry["name"]: entry for entry in build_product_route_tool_entries()}
    assert set(_EXPECTED_GITHUB_PROPERTIES) == set(GITHUB_PRODUCT_TOOLS)
    full_shared_bag = 0
    for name in GITHUB_PRODUCT_TOOLS:
        props = frozenset(entries[name]["inputSchema"]["properties"])
        schema = entries[name]["inputSchema"]
        assert schema.get("additionalProperties") is True
        assert schema.get("required") == []
        assert _REPO_TARGET <= props
        assert props <= _SHARED_GITHUB_FIELDS
        if props == _SHARED_GITHUB_FIELDS:
            full_shared_bag += 1
        assert props == _EXPECTED_GITHUB_PROPERTIES[name]
        if name in _FORBIDDEN_ON_TOOL:
            assert props.isdisjoint(_FORBIDDEN_ON_TOOL[name]), name
    assert full_shared_bag == 0


def test_existing_valid_payloads_still_pass_schema_validation() -> None:
    entries = {entry["name"]: entry for entry in build_product_route_tool_entries()}

    examples: list[tuple[str, dict]] = [
        ("read_file", {"path": "README.md"}),
        ("write_file", {"path": "probe.txt", "content": "ok"}),
        ("git_status", {}),
        ("git_diff", {"staged": True}),
        ("git_add", {"files": ["README.md"]}),
        ("package_list_manifest", {}),
        ("pip_install", {}),
        ("pip_install", {"package_name": "agentveil-route-test-pkg"}),
        ("get_repository", {}),
        ("get_repository", {"owner": "acme", "repo": "demo-repo"}),
        ("list_issues", {"owner": "acme", "repo": "demo-repo"}),
        (
            "create_comment",
            {
                "owner": "acme",
                "repo": "demo-repo",
                "issue_number": 1,
                "comment_body": "approved-comment",
            },
        ),
        (
            "create_release",
            {"owner": "acme", "repo": "demo-repo", "tag_name": "v9.9.9"},
        ),
        (
            "dispatch_workflow",
            {"owner": "acme", "repo": "demo-repo", "branch": "main"},
        ),
        (
            "manage_secret",
            {"owner": "acme", "repo": "demo-repo", "secret_name": "DEPLOY_KEY"},
        ),
        ("merge_pull_request", {"pull_number": 1}),
        # additionalProperties:true must keep unknown keys from failing validation
        ("list_issues", {"owner": "acme", "repo": "demo-repo", "state": "open"}),
    ]

    for tool, arguments in examples:
        assert tool in entries, tool
        details = validate_arguments(entries[tool]["inputSchema"], arguments)
        assert details == [], (tool, arguments, details)


def test_non_github_pack_schemas_remain_intact() -> None:
    entries = {entry["name"]: entry for entry in build_product_route_tool_entries()}
    for name in PRODUCT_ROUTE_TOOL_CATALOG:
        pack = PRODUCT_ROUTE_TOOL_PACK[name]
        props = entries[name]["inputSchema"]["properties"]
        if pack == "git":
            assert "repo_path" in props
            assert "staged" in props
        elif pack == "package":
            assert "project_path" in props
            assert "package_name" in props
        elif pack == "filesystem":
            assert entries[name]["inputSchema"]["type"] == "object"
        elif pack == "github":
            assert {"owner", "repo"} <= set(props)
