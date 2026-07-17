"""Product route phase 2: composite product route downstream proofs.

These tests exercise the raw composite ``product`` stdio downstream directly.
They do **not** prove proxy-enforced product behavior. Dangerous tools such as
``get_secret`` may reach the raw downstream in routing tests labeled
``raw_downstream_capability``; Phase 3 installed smoke must prove the proxy
blocks them and that stdout contains no secret bodies.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agentveil_mcp_proxy.policy import PolicyDecision
from agentveil_mcp_proxy.product_route import (
    PRODUCT_ROUTE_DOWNSTREAM_NAME,
    PRODUCT_ROUTE_TOOL_CATALOG,
    build_product_route_downstream_config,
    evaluate_product_route_tool,
    initialize_product_route_profile,
)
from agentveil_mcp_proxy.product_route_downstream import ProductRouteRuntime, handle_message
from agentveil_mcp_proxy.product_route_local_fixtures import prepare_product_route_profile
from agentveil_mcp_proxy.product_route_offline_wheel import PRODUCT_ROUTE_TEST_WHEEL_NAME
from agentveil_mcp_proxy.product_route_tool_schemas import (
    build_product_route_tool_entries,
    product_route_tool_catalog_hash,
)

pytestmark = pytest.mark.product_route_phase2


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _tool_result_text(response: dict) -> dict:
    assert "result" in response, response
    content = response["result"]["content"]
    assert content and content[0]["type"] == "text"
    return json.loads(content[0]["text"])


@pytest.fixture(scope="module")
def profile_root(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("product-route-profile")
    initialize_product_route_profile(root)
    return root


@pytest.fixture
def runtime(profile_root: Path) -> ProductRouteRuntime:
    return ProductRouteRuntime.from_profile_root(profile_root)


def test_tools_list_exact_catalog_in_process(runtime: ProductRouteRuntime) -> None:
    response = handle_message(
        runtime,
        {"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}},
    )
    assert response is not None
    tools = response["result"]["tools"]
    assert [entry["name"] for entry in tools] == list(PRODUCT_ROUTE_TOOL_CATALOG)
    assert len(tools) == len(PRODUCT_ROUTE_TOOL_CATALOG)


def test_tools_list_stable_schema_fingerprint() -> None:
    first = product_route_tool_catalog_hash()
    second = product_route_tool_catalog_hash()
    assert first == second
    assert len(first) == 64
    entries = build_product_route_tool_entries()
    assert len(entries) == len(PRODUCT_ROUTE_TOOL_CATALOG)


def test_downstream_config_names_product_and_points_at_profile(profile_root: Path) -> None:
    config = build_product_route_downstream_config(profile_root)
    assert config["name"] == PRODUCT_ROUTE_DOWNSTREAM_NAME
    assert config["args"][-1] == str(profile_root.resolve())
    assert config["env"]["PRODUCT_ROUTE_PROFILE_ROOT"] == str(profile_root.resolve())
    assert Path(config["env"]["LOCAL_DIST_DIR"]).name == "dist"


def test_product_route_profile_bootstrap_is_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pip_install_attempts: list[list[str]] = []

    original_run = subprocess.run

    def guarded_run(cmd, *args, **kwargs):
        argv = [str(part) for part in cmd]
        if "-m" in argv and "pip" in argv and "install" in argv:
            pip_install_attempts.append(argv)
            raise AssertionError(f"offline product route fixture must not run pip install: {argv}")
        return original_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded_run)
    profile = prepare_product_route_profile(tmp_path / "offline-profile")
    wheels = sorted(profile.package_dist.glob("*.whl"))
    assert len(wheels) == 1
    assert wheels[0].name == PRODUCT_ROUTE_TEST_WHEEL_NAME
    assert not (profile.root / "package" / "build-venv").exists()
    assert pip_install_attempts == []


def test_stdio_tools_list_exact_catalog(profile_root: Path) -> None:
    server = Path(__file__).resolve().parents[1] / "agentveil_mcp_proxy" / "product_route_downstream.py"
    env = os.environ.copy()
    env.update(build_product_route_downstream_config(profile_root)["env"])
    proc = subprocess.run(
        [sys.executable, str(server), str(profile_root)],
        input=_json_line({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    response = _responses(proc.stdout)[0]
    assert [entry["name"] for entry in response["result"]["tools"]] == list(PRODUCT_ROUTE_TOOL_CATALOG)


def test_product_route_policy_blocks_secret_tools_before_downstream() -> None:
    for tool in ("get_secret", "get_env_secret"):
        evaluation = evaluate_product_route_tool(
            tool,
            arguments={"owner": "acme", "repo": "demo-repo", "secret_name": "DEPLOY_KEY"},
        )
        assert evaluation.decision is PolicyDecision.BLOCK
        assert evaluation.policy_rule_id == f"product_route::github::{tool}"


@pytest.mark.parametrize(
    ("tool", "arguments", "expected_key", "expected_value"),
    [
        ("list_workspace", {}, None, None),
        ("write_file", {"path": "probe.txt", "content": "ok"}, None, None),
        ("git_status", {}, "dirty", True),
        ("git_add", {"files": ["README.md"]}, "staged", True),
        ("package_list_manifest", {}, "dependency_count", 0),
        ("pip_install", {}, "target_installed", True),
        ("get_repository", {}, "name", "demo-repo"),
        ("merge_pull_request", {"pull_number": 1}, "merged", True),
        ("ci_repo_target_snapshot", {}, "owner", "acme"),
        ("deploy_release", {}, "deploy_active", True),
    ],
)
def test_representative_dispatch_routing(
    runtime: ProductRouteRuntime,
    tool: str,
    arguments: dict,
    expected_key: str | None,
    expected_value: object,
) -> None:
    profile = runtime.profile
    response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": f"call-{tool}",
            "method": "tools/call",
            "params": {"name": tool, "arguments": dict(arguments)},
        },
    )
    assert response is not None
    assert "error" not in response, response
    if tool == "list_workspace":
        listing = response["result"]["content"][0]["text"]
        assert "seed.txt" in listing
        return
    if tool == "write_file":
        assert (profile.filesystem_sandbox / "probe.txt").read_text(encoding="utf-8") == "ok"
        assert (profile.git_repo / "probe.txt").read_text(encoding="utf-8") == "ok"
        return
    parsed = _tool_result_text(response)
    assert parsed.get("tool") == tool
    if expected_key is None:
        return
    assert parsed.get(expected_key) == expected_value


def test_product_route_workspace_coherence_write_file_then_git_add(
    runtime: ProductRouteRuntime,
) -> None:
    probe_name = "route_workspace_coherence.txt"
    workspace = runtime.profile.filesystem_sandbox
    assert workspace == runtime.profile.git_repo

    write_response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "write-coherence",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": probe_name, "content": "workspace-coherent\n"},
            },
        },
    )
    assert write_response is not None and "error" not in write_response
    assert (workspace / probe_name).read_text(encoding="utf-8") == "workspace-coherent\n"

    add_response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "git-add-coherence",
            "method": "tools/call",
            "params": {"name": "git_add", "arguments": {"files": [probe_name]}},
        },
    )
    assert add_response is not None and "error" not in add_response
    add_payload = _tool_result_text(add_response)
    assert add_payload.get("staged") is True

    status_response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "git-status-coherence",
            "method": "tools/call",
            "params": {"name": "git_status", "arguments": {}},
        },
    )
    status_payload = _tool_result_text(status_response)
    assert status_payload.get("staged_count", 0) >= 1
    assert probe_name in status_payload.get("staged_basenames", [])

    diff_response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "git-diff-coherence",
            "method": "tools/call",
            "params": {"name": "git_diff", "arguments": {"staged": True}},
        },
    )
    diff_payload = _tool_result_text(diff_response)
    assert diff_payload.get("staged") is True
    assert diff_payload.get("diff_stat_lines", 0) >= 1 or probe_name in diff_payload.get(
        "changed_basenames",
        [],
    )
    assert probe_name in diff_payload.get("changed_basenames", [])


def test_write_file_path_traversal_is_blocked(runtime: ProductRouteRuntime) -> None:
    outside = runtime.profile.root / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "write-traversal",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "../outside.txt", "content": "escape"},
            },
        },
    )
    assert response is not None
    assert "error" in response
    assert "path escapes" in response["error"]["message"]
    assert outside.read_text(encoding="utf-8") == "outside\n"


def test_read_file_reads_sandbox_file(runtime: ProductRouteRuntime) -> None:
    probe = runtime.profile.filesystem_sandbox / "read_probe.txt"
    probe.write_text("read-me\n", encoding="utf-8")

    response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "read-probe",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "read_probe.txt"}},
        },
    )
    assert response is not None
    assert "error" not in response, response
    assert response["result"]["content"][0]["text"] == "read-me\n"


def test_get_file_info_returns_bounded_metadata(runtime: ProductRouteRuntime) -> None:
    probe = runtime.profile.filesystem_sandbox / "info_probe.txt"
    content = b"meta\n"
    probe.write_bytes(content)

    response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "info-probe",
            "method": "tools/call",
            "params": {"name": "get_file_info", "arguments": {"path": "info_probe.txt"}},
        },
    )
    assert response is not None
    assert "error" not in response, response
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["path"] == "info_probe.txt"
    assert payload["size_bytes"] == len(content)
    assert payload["size_bucket"] in {"tiny", "small", "medium", "large"}


@pytest.mark.parametrize(
    ("tool", "bad_path"),
    [
        ("read_file", "../outside.txt"),
        ("read_file", "/etc/passwd"),
        ("get_file_info", "../outside.txt"),
        ("get_file_info", "nested/../../outside.txt"),
    ],
)
def test_read_tools_path_traversal_is_blocked(
    runtime: ProductRouteRuntime,
    tool: str,
    bad_path: str,
) -> None:
    outside = runtime.profile.root / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")

    response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": f"{tool}-traversal",
            "method": "tools/call",
            "params": {"name": tool, "arguments": {"path": bad_path}},
        },
    )
    assert response is not None
    assert "error" in response
    assert "path escapes" in response["error"]["message"]
    assert outside.read_text(encoding="utf-8") == "outside\n"


def test_git_add_staging_visible_in_status_and_staged_diff(runtime: ProductRouteRuntime) -> None:
    repo = runtime.profile.git_repo
    probe_name = "observability-probe.txt"
    (repo / probe_name).write_text("probe\n", encoding="utf-8")
    repo_path_text = str(repo.resolve())

    add_response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "git-add-probe",
            "method": "tools/call",
            "params": {"name": "git_add", "arguments": {"files": [probe_name]}},
        },
    )
    assert add_response is not None and "error" not in add_response
    add_payload = _tool_result_text(add_response)
    assert add_payload.get("staged") is True

    status_response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "git-status-after-add",
            "method": "tools/call",
            "params": {"name": "git_status", "arguments": {}},
        },
    )
    assert status_response is not None and "error" not in status_response
    status_payload = _tool_result_text(status_response)
    assert status_payload.get("staged_count", 0) >= 1
    assert probe_name in status_payload.get("staged_basenames", [])
    status_text = json.dumps(status_payload)
    assert repo_path_text not in status_text
    assert "/Users/" not in status_text

    diff_response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "git-diff-staged",
            "method": "tools/call",
            "params": {"name": "git_diff", "arguments": {"staged": True}},
        },
    )
    assert diff_response is not None and "error" not in diff_response
    diff_payload = _tool_result_text(diff_response)
    assert diff_payload.get("staged") is True
    assert diff_payload.get("diff_stat_lines", 0) >= 1 or probe_name in diff_payload.get(
        "changed_basenames",
        [],
    )
    assert probe_name in diff_payload.get("changed_basenames", [])
    diff_text = json.dumps(diff_payload)
    assert repo_path_text not in diff_text
    assert "/Users/" not in diff_text


@pytest.mark.raw_downstream_capability
def test_raw_downstream_get_secret_is_not_product_safe_output(runtime: ProductRouteRuntime) -> None:
    """Routing proof only: raw downstream may return secret bodies; proxy must block in Phase 3."""

    response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "raw-secret",
            "method": "tools/call",
            "params": {
                "name": "get_secret",
                "arguments": {
                    "secret_name": "DEPLOY_KEY",
                },
            },
        },
    )
    assert response is not None and "error" not in response
    parsed = _tool_result_text(response)
    assert parsed.get("tool") == "get_secret"
    assert parsed.get("secret_value")
    assert evaluate_product_route_tool("get_secret").decision is PolicyDecision.BLOCK


@pytest.mark.parametrize(
    ("tool", "arguments", "expected_message"),
    [
        ("git_status", {"repo_path": "/tmp/agentveil-wrong-git-repo"}, "repo_path outside"),
        ("package_list_manifest", {"project_path": "/tmp/agentveil-wrong-package-root"}, "project_path outside"),
        ("get_repository", {"owner": "wrong-owner", "repo": "demo-repo"}, "owner/repo mismatch"),
        ("ci_repo_target_snapshot", {"owner": "acme", "repo": "wrong-repo"}, "owner/repo mismatch"),
        (
            "ci_repo_target_snapshot",
            {"repo_root": "/tmp/agentveil-wrong-github-content"},
            "repo_root outside",
        ),
    ],
)
def test_explicit_wrong_profile_path_rejects(
    runtime: ProductRouteRuntime,
    tool: str,
    arguments: dict,
    expected_message: str,
) -> None:
    response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": f"reject-{tool}",
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        },
    )
    assert response is not None
    assert "error" in response, response
    assert expected_message in response["error"]["message"]


def test_tool_schemas_do_not_require_profile_paths() -> None:
    entries = {entry["name"]: entry for entry in build_product_route_tool_entries()}
    for name in PRODUCT_ROUTE_TOOL_CATALOG:
        if name.startswith("git_"):
            schema = entries[name]["inputSchema"]
            assert "repo_path" not in schema.get("required", [])
        elif name.startswith("package_") or name.startswith("pip_"):
            schema = entries[name]["inputSchema"]
            assert "project_path" not in schema.get("required", [])
        elif name in {
            "get_repository",
            "list_issues",
            "get_issue",
            "list_pull_requests",
            "get_pull_request",
            "list_comments",
            "list_branches",
            "list_files",
            "list_secret_names",
            "get_repository_settings",
            "list_workflow_runs",
            "list_workflows",
            "get_workflow",
            "list_ci_jobs",
            "get_ci_job",
            "get_package_metadata",
            "untrusted_context_status",
            "github_target_snapshot",
            "ci_repo_target_snapshot",
            "create_comment",
            "create_issue",
            "update_issue",
            "add_labels",
            "remove_labels",
            "request_review",
            "merge_pull_request",
            "close_issue",
            "delete_branch",
            "create_release",
            "update_repository_settings",
            "manage_secret",
            "rerun_workflow",
            "cancel_workflow",
            "dispatch_workflow",
            "publish_package",
            "deploy_release",
            "run_remote_command",
            "get_secret",
            "get_env_secret",
        }:
            schema = entries[name]["inputSchema"]
            assert "owner" not in schema.get("required", [])
            assert "repo" not in schema.get("required", [])


def test_unknown_catalog_tool_is_rejected(runtime: ProductRouteRuntime) -> None:
    response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "bad-tool",
            "method": "tools/call",
            "params": {"name": "not_in_catalog", "arguments": {}},
        },
    )
    assert response is not None
    assert response["error"]["code"] == -32601


def test_product_route_write_through_symlinked_workspace(tmp_path: Path) -> None:
    """Public setup uses ``product-profile/workspace`` → real workspace symlink."""

    profile_root = tmp_path / "product-profile"
    initialize_product_route_profile(profile_root)
    workspace = profile_root / "workspace"
    real = tmp_path / "real-workspace"
    shutil.move(str(workspace), str(real))
    workspace.symlink_to(real, target_is_directory=True)
    (real / "ops").mkdir(exist_ok=True)
    (real / "ops" / "existing.json").write_text('{"seed":true}', encoding="utf-8")

    runtime = ProductRouteRuntime.from_profile_root(profile_root)
    assert runtime.profile.filesystem_sandbox.is_symlink()

    response = handle_message(
        runtime,
        {
            "jsonrpc": "2.0",
            "id": "symlink-product-write",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "ops/existing.json", "content": '{"updated":true}'},
            },
        },
    )
    assert response is not None
    assert "error" not in response, response
    text = response["result"]["content"][0]["text"]
    assert text == "wrote ops/existing.json"
    assert "/Users/" not in text and "/private/" not in text and "/var/" not in text
    assert (real / "ops" / "existing.json").read_text(encoding="utf-8") == '{"updated":true}'
