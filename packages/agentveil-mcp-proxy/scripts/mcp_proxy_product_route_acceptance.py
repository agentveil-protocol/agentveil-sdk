#!/usr/bin/env python3
"""Full product-route acceptance for the installed AgentVeil MCP Proxy wheel.

Builds or consumes a candidate wheel, installs it into a clean virtualenv under an
isolated AVP home, initializes the composite ``product_route`` profile, exercises
safe reads, approval/deny/block flows over MCP stdio, and verifies evidence,
timeline, and privacy boundaries. Emits a final bounded JSON report.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp_proxy_acceptance_lib import (
    AcceptanceError,
    CSRF_RE,
    JsonRpcClient,
    JSONRPC_APPROVAL_REQUIRED,
    REPO_ROOT,
    approve_url,
    assert_installed_from_wheel,
    assert_tool_success,
    build_wheel,
    install_wheel,
    log,
    privacy_scan_events,
    privacy_scan_text,
    resolve_git_sha,
    run,
    run_cli_json,
    scrub_install_env,
)

PRODUCT_ROUTE_PACKAGE_NAME = "agentveil-route-test-pkg"
EXPECTED_TOOL_COUNT = 68
EXPECTED_VERSION = "0.7.22"
RUN_NONINTERACTIVE_UI_ARGS = ["--approval-ui-mode", "none"]

SAFE_READ_TOOLS = (
    "list_workspace",
    "git_status",
    "package_inspect_state",
    "get_repository",
    "ci_repo_target_snapshot",
)

APPROVE_WRITE_NAME = "product-route-approve.txt"
DENY_WRITE_NAME = "product-route-deny.txt"
WRITE_CONTENT = "product route acceptance write\n"
GIT_STAGE_NAME = "product-route-stage.txt"

GITHUB_RISKY_TOOLS: tuple[tuple[str, dict[str, Any], str, str], ...] = (
    ("merge_pull_request", {"pull_number": 1}, "repo_admin_or_merge", "repo_change_review"),
    ("deploy_release", {}, "deploy_release", "release_readiness_check"),
    ("dispatch_workflow", {"workflow": "deploy.yml"}, "ci_workflow_mutation", "workflow_review"),
    ("run_remote_command", {"command": "echo probe"}, "remote_command", "remote_command_review"),
)

PRIVACY_PATH_MARKERS = ("/Users/", "/private/", "/var/folders/")
FAKE_SECRET_MARKERS = (
    "ghp_FAKE_NOT_A_REAL_GITHUB_TOKEN_00000000",
    "ci_FAKE_NOT_A_REAL_ENV_SECRET_00000000",
)


def deny_url(approval_url: str) -> None:
    opener = build_opener(HTTPCookieProcessor())
    with opener.open(approval_url, timeout=10) as response:
        page = response.read().decode("utf-8")
    match = CSRF_RE.search(page)
    if match is None:
        raise AcceptanceError("approval page did not contain a CSRF token")
    body = urlencode({
        "decision": "deny",
        "approval_scope": "exact",
        "csrf_token": match.group(1),
    }).encode("utf-8")
    request = Request(
        approval_url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise AcceptanceError(f"deny POST returned HTTP {response.status}")


def profile_layout(profile_root: Path) -> dict[str, Path]:
    workspace = profile_root / "workspace"
    return {
        "profile_root": profile_root,
        "workspace": workspace,
        "package_venv": profile_root / "package" / "venv",
        "github_state": profile_root / "github" / "state" / "state.json",
        "git_outcome_log": profile_root / "logs" / "git-outcome.jsonl",
        "package_outcome_log": profile_root / "logs" / "package-outcome.jsonl",
        "github_outcome_log": profile_root / "logs" / "github-outcome.jsonl",
    }


def git_staged_files(repo: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AcceptanceError(f"git diff --cached failed: {proc.stderr.strip()}")
    return [line for line in proc.stdout.splitlines() if line.strip()]


def package_installed(venv_dir: Path, package_name: str = PRODUCT_ROUTE_PACKAGE_NAME) -> bool:
    python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    proc = subprocess.run(
        [str(python), "-m", "pip", "show", package_name],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def github_merge_state(state_path: Path) -> bool:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    return bool(state.get("pull_requests", {}).get("1", {}).get("merged"))


def tool_result_text(response: dict[str, Any]) -> str:
    result = response.get("result")
    if not isinstance(result, dict):
        return json.dumps(response, sort_keys=True)
    content = result.get("content")
    if isinstance(content, list) and content:
        first = content[0]
        if isinstance(first, dict) and first.get("type") == "text":
            return str(first.get("text", ""))
    return json.dumps(result, sort_keys=True)


def assert_approval_required(
    response: dict[str, Any],
    *,
    tool: str,
    risk_family: str,
    redirect_playbook: str,
    target_path: Path | None = None,
) -> dict[str, Any]:
    error = response.get("error")
    if not isinstance(error, dict) or error.get("code") != JSONRPC_APPROVAL_REQUIRED:
        raise AcceptanceError(f"{tool}: expected approval_required error: {response}")
    data = error.get("data")
    if not isinstance(data, dict):
        raise AcceptanceError(f"{tool}: approval_required data missing: {response}")
    if data.get("status") != "approval_required":
        raise AcceptanceError(f"{tool}: unexpected approval status: {data}")
    if data.get("risk_family") != risk_family:
        raise AcceptanceError(f"{tool}: expected risk_family={risk_family!r}, got {data.get('risk_family')!r}")
    playbook_id = data.get("redirect_playbook_id")
    if playbook_id != redirect_playbook:
        raise AcceptanceError(
            f"{tool}: expected redirect_playbook_id={redirect_playbook!r}, got {playbook_id!r}",
        )
    if not data.get("safe_first_step_id"):
        raise AcceptanceError(f"{tool}: safe_first_step_id missing from approval data")
    message = str(error.get("message", ""))
    if "Safe first step:" not in message and "safe_first_step_id" not in data:
        raise AcceptanceError(f"{tool}: safe first step guidance missing from approval surface")
    if target_path is not None and target_path.exists():
        raise AcceptanceError(f"{tool}: target reached before approval: {target_path.name}")
    if not data.get("record_id") or not data.get("approval_url"):
        raise AcceptanceError(f"{tool}: approval_required missing record_id or approval_url")
    if data.get("target_reached") is True:
        raise AcceptanceError(f"{tool}: target_reached=true before approval")
    return data


def assert_blocked(
    response: dict[str, Any],
    *,
    tool: str,
    risk_family: str,
    redirect_playbook: str,
) -> dict[str, Any]:
    error = response.get("error")
    if not isinstance(error, dict):
        raise AcceptanceError(f"{tool}: expected JSON-RPC error: {response}")
    data = error.get("data")
    if not isinstance(data, dict):
        raise AcceptanceError(f"{tool}: blocked data missing: {response}")
    if data.get("status") not in {"blocked", "policy_denied"}:
        raise AcceptanceError(f"{tool}: expected blocked status: {data}")
    if data.get("risk_family") != risk_family:
        raise AcceptanceError(f"{tool}: expected risk_family={risk_family!r}, got {data.get('risk_family')!r}")
    if data.get("redirect_playbook_id") != redirect_playbook:
        raise AcceptanceError(
            f"{tool}: expected redirect_playbook_id={redirect_playbook!r}, got {data.get('redirect_playbook_id')!r}",
        )
    if data.get("target_reached") is True:
        raise AcceptanceError(f"{tool}: blocked path reported target_reached=true")
    rendered = json.dumps(response, sort_keys=True)
    for marker in FAKE_SECRET_MARKERS:
        if marker in rendered:
            raise AcceptanceError(f"{tool}: secret value leaked in blocked response")
    return data


def events_for_tool(events: list[dict[str, Any]], tool: str) -> list[dict[str, Any]]:
    return [event for event in events if isinstance(event, dict) and event.get("tool") == tool]


def events_with_status(events: list[dict[str, Any]], tool: str, status: str) -> list[dict[str, Any]]:
    return [
        event
        for event in events_for_tool(events, tool)
        if isinstance(event, dict) and event.get("status") == status
    ]


def require_event(events: list[dict[str, Any]], tool: str, status: str) -> dict[str, Any]:
    matches = events_with_status(events, tool, status)
    if not matches:
        raise AcceptanceError(f"no evidence event for tool={tool!r} status={status!r}")
    return matches[-1]



def event_redirect_fields(event: dict[str, Any]) -> tuple[str | None, str | None]:
    risk_family = event.get("risk_family")
    playbook = event.get("redirect_playbook_id")
    controlled = event.get("controlled_path")
    if isinstance(controlled, dict):
        risk_family = risk_family or controlled.get("risk_family")
        playbook = playbook or controlled.get("redirect_playbook_id")
    return risk_family, playbook


def run_product_route_acceptance(args: argparse.Namespace) -> dict[str, Any]:
    work_root = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix="avp-mcp-product-route-"))
    work_root.mkdir(parents=True, exist_ok=True)
    output_sink: list[str] = []
    git_root = Path(args.git_root).resolve() if args.git_root else REPO_ROOT
    scenario_results: dict[str, bool] = {}

    try:
        log(f"work directory: {work_root}")
        wheel = Path(args.wheel).resolve() if args.wheel else build_wheel(work_root, args.python, output_sink=output_sink)
        wheel_sha256 = sha256(wheel.read_bytes()).hexdigest()
        candidate_git_sha = args.git_sha or resolve_git_sha(git_root)

        install_python, proxy = install_wheel(work_root, wheel, args.python, output_sink=output_sink)
        gate_env = scrub_install_env(dict(os.environ))
        gate_env["BROWSER"] = "/bin/true"
        gate_env["AVP_MCP_PROXY_TEST_MODE"] = "1"
        install_info = assert_installed_from_wheel(
            install_python,
            wheel,
            work_dir=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        if install_info["version"] != EXPECTED_VERSION:
            raise AcceptanceError(
                f"expected installed version {EXPECTED_VERSION!r}, got {install_info['version']!r}",
            )

        home = work_root / "avp-home"
        profile_root = work_root / "product-profile"
        passphrase_file = work_root / "passphrase.txt"
        passphrase_secret = secrets.token_urlsafe(32)
        passphrase_file.write_text(passphrase_secret + "\n", encoding="utf-8")
        passphrase_file.chmod(0o600)
        secret_values = (passphrase_secret, *FAKE_SECRET_MARKERS)

        path_args = ["--home", str(home)]
        identity_args = [*path_args, "--passphrase-file", str(passphrase_file)]

        init_payload = run_cli_json(
            proxy,
            [
                "init",
                "--home",
                str(home),
                "--product-route-profile",
                str(profile_root),
                "--passphrase-file",
                str(passphrase_file),
                "--json",
            ],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        if init_payload.get("setup_profile") != "product_route":
            raise AcceptanceError(f"init did not configure product_route profile: {init_payload}")

        doctor_payload = run_cli_json(
            proxy,
            ["doctor", *identity_args, "--full", "--json"],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        downstream = doctor_payload.get("downstream", {})
        doctor_tool_count = int(downstream.get("tool_count") or 0)
        if doctor_payload.get("ok") is not True:
            raise AcceptanceError(f"doctor --full returned ok=false: {doctor_payload}")
        if downstream.get("smoke_ok") is not True:
            raise AcceptanceError(f"doctor --full smoke_ok is not true: {doctor_payload}")
        if doctor_tool_count != EXPECTED_TOOL_COUNT:
            raise AcceptanceError(
                f"doctor --full expected tool_count={EXPECTED_TOOL_COUNT}, got {doctor_tool_count}",
            )

        layout = profile_layout(profile_root)
        workspace = layout["workspace"]
        approve_file = workspace / APPROVE_WRITE_NAME
        deny_file = workspace / DENY_WRITE_NAME
        git_stage_file = workspace / GIT_STAGE_NAME
        git_stage_file.write_text("stage me\n", encoding="utf-8")

        client = JsonRpcClient(
            [str(proxy), "run", *identity_args, *RUN_NONINTERACTIVE_UI_ARGS],
            env=gate_env,
            cwd=work_root,
        )
        try:
            initialize = assert_tool_success(
                client.call(
                    "initialize-1",
                    "initialize",
                    {"clientInfo": {"name": "product-route-acceptance"}},
                ),
                "initialize-1",
            )
            server_name = initialize.get("serverInfo", {}).get("name")
            if server_name not in {"product", "agentveil-product-route-downstream"}:
                raise AcceptanceError(f"initialize returned unexpected downstream serverInfo: {initialize}")

            client.notify("notifications/initialized", {})

            tools_result = assert_tool_success(client.call("tools-list-1", "tools/list", {}), "tools-list-1")
            tool_names = {tool.get("name") for tool in tools_result.get("tools", [])}
            if len(tool_names) != EXPECTED_TOOL_COUNT:
                raise AcceptanceError(f"tools/list count mismatch: expected {EXPECTED_TOOL_COUNT}, got {len(tool_names)}")

            for tool in SAFE_READ_TOOLS:
                response = assert_tool_success(
                    client.call(f"safe-{tool}", "tools/call", {"name": tool, "arguments": {}}),
                    f"safe-{tool}",
                )
                rendered = tool_result_text(response)
                if "redirect_playbook_id" in rendered or "risk_family" in rendered:
                    raise AcceptanceError(f"{tool}: safe read leaked redirect metadata")
            scenario_results["safe_read"] = True

            write_args = {
                "name": "write_file",
                "arguments": {"path": APPROVE_WRITE_NAME, "content": WRITE_CONTENT},
            }
            risky = client.call("write-pre-1", "tools/call", write_args)
            assert_approval_required(
                risky,
                tool="write_file",
                risk_family="file_write",
                redirect_playbook="inspect_before_write",
                target_path=approve_file,
            )
            scenario_results["write_pre_approval"] = True

            approve_url(str(risky["error"]["data"]["approval_url"]))
            retry = assert_tool_success(client.call("write-post-1", "tools/call", write_args), "write-post-1")
            if not approve_file.exists():
                raise AcceptanceError("approved write_file retry did not create target file")
            if approve_file.read_text(encoding="utf-8") != WRITE_CONTENT:
                raise AcceptanceError("approved write_file content mismatch")
            if "target_reached" in tool_result_text(retry) and "true" not in tool_result_text(retry).lower():
                raise AcceptanceError("approved write_file retry did not report target_reached=true")
            scenario_results["write_approved"] = True

            deny_args = {
                "name": "write_file",
                "arguments": {"path": DENY_WRITE_NAME, "content": "deny probe\n"},
            }
            deny_pending = client.call("write-deny-1", "tools/call", deny_args)
            deny_data = assert_approval_required(
                deny_pending,
                tool="write_file",
                risk_family="file_write",
                redirect_playbook="inspect_before_write",
                target_path=deny_file,
            )
            deny_url(str(deny_data["approval_url"]))
            deny_retry = client.call("write-deny-2", "tools/call", deny_args)
            if deny_file.exists():
                raise AcceptanceError("denied write_file retry reached target file")
            deny_error = deny_retry.get("error")
            if not isinstance(deny_error, dict):
                raise AcceptanceError(f"denied write_file retry did not return an error: {deny_retry}")
            scenario_results["write_denied"] = True

            git_before = git_staged_files(workspace)
            git_args = {
                "name": "git_add",
                "arguments": {"files": [GIT_STAGE_NAME]},
            }
            git_pending = client.call("git-add-1", "tools/call", git_args)
            assert_approval_required(
                git_pending,
                tool="git_add",
                risk_family="git_mutation",
                redirect_playbook="show_git_status_and_diff",
            )
            if git_staged_files(workspace) != git_before:
                raise AcceptanceError("git_add reached staging before approval")
            approve_url(str(git_pending["error"]["data"]["approval_url"]))
            git_retry = assert_tool_success(client.call("git-add-2", "tools/call", git_args), "git-add-2")
            staged_after = git_staged_files(workspace)
            if GIT_STAGE_NAME not in staged_after:
                raise AcceptanceError("approved git_add did not stage target file")
            if "target_reached" in tool_result_text(git_retry) and "true" not in tool_result_text(git_retry).lower():
                raise AcceptanceError("approved git_add did not report target_reached=true")
            scenario_results["git_add"] = True

            if package_installed(layout["package_venv"]):
                raise AcceptanceError("pip_install target package already installed before scenario")
            pip_pending = client.call("pip-install-1", "tools/call", {"name": "pip_install", "arguments": {}})
            assert_approval_required(
                pip_pending,
                tool="pip_install",
                risk_family="package_mutation",
                redirect_playbook="inspect_package_risk",
            )
            if package_installed(layout["package_venv"]):
                raise AcceptanceError("pip_install reached target before approval")
            approve_url(str(pip_pending["error"]["data"]["approval_url"]))
            pip_retry = assert_tool_success(
                client.call("pip-install-2", "tools/call", {"name": "pip_install", "arguments": {}}),
                "pip-install-2",
            )
            if not package_installed(layout["package_venv"]):
                raise AcceptanceError("approved pip_install did not install target package")
            if "target_reached" in tool_result_text(pip_retry) and "true" not in tool_result_text(pip_retry).lower():
                raise AcceptanceError("approved pip_install did not report target_reached=true")
            scenario_results["pip_install"] = True

            for tool in ("get_secret", "get_env_secret"):
                secret_args = (
                    {"owner": "acme", "repo": "demo-repo", "secret_name": "DEPLOY_KEY"}
                    if tool == "get_secret"
                    else {"secret_name": "DEPLOY_TOKEN"}
                )
                blocked = client.call(f"{tool}-1", "tools/call", {"name": tool, "arguments": secret_args})
                assert_blocked(
                    blocked,
                    tool=tool,
                    risk_family="secret_access",
                    redirect_playbook="secret_posture_only",
                )
            scenario_results["secret_block"] = True

            merge_before = github_merge_state(layout["github_state"])
            for tool, arguments, risk_family, redirect_playbook in GITHUB_RISKY_TOOLS:
                risky_response = client.call(
                    f"github-{tool}",
                    "tools/call",
                    {"name": tool, "arguments": dict(arguments)},
                )
                assert_approval_required(
                    risky_response,
                    tool=tool,
                    risk_family=risk_family,
                    redirect_playbook=redirect_playbook,
                )
            if github_merge_state(layout["github_state"]) != merge_before:
                raise AcceptanceError("GitHub/CI-like risky tool reached target before approval")
            scenario_results["github_ci_like"] = True
        finally:
            client.close()

        timeline_payload = run_cli_json(
            proxy,
            ["control", "timeline", *path_args, "--json"],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        summary_payload = run_cli_json(
            proxy,
            ["evidence-summary", *path_args, "--json"],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        events_payload = run_cli_json(
            proxy,
            ["events", "list", *path_args, "--limit", "200", "--json"],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        events = events_payload.get("events", [])
        if not isinstance(events, list) or not events:
            raise AcceptanceError("events list did not return evidence records")

        write_executed = require_event(events, "write_file", "executed")
        if write_executed.get("target_reached") is not True:
            raise AcceptanceError("write_file executed evidence target_reached is not true")

        write_denied = require_event(events, "write_file", "denied")
        if write_denied.get("target_reached") is True:
            raise AcceptanceError("denied write_file evidence reported target_reached=true")

        for tool in ("get_secret", "get_env_secret"):
            secret_event = require_event(events, tool, "blocked")
            if secret_event.get("target_reached") is True:
                raise AcceptanceError(f"{tool} blocked evidence reported target_reached=true")

        for tool, _args, risk_family, redirect_playbook in GITHUB_RISKY_TOOLS:
            event = require_event(events, tool, "pending")
            observed_risk_family, observed_playbook = event_redirect_fields(event)
            if observed_risk_family != risk_family:
                raise AcceptanceError(f"{tool}: evidence missing risk_family={risk_family!r}")
            if observed_playbook != redirect_playbook:
                raise AcceptanceError(
                    f"{tool}: evidence missing redirect_playbook_id={redirect_playbook!r}",
                )
            if event.get("target_reached") is True:
                raise AcceptanceError(f"{tool} risky evidence reported target_reached=true before approval")

        privacy_scan_events(events_payload, secret_values=secret_values)
        runner_output = "".join(output_sink)
        privacy_scan_text("runner_output", runner_output, secret_values=secret_values)
        for label, text in {
            "timeline": json.dumps(timeline_payload, sort_keys=True),
            "evidence_summary": json.dumps(summary_payload, sort_keys=True),
            "events": json.dumps(events_payload, sort_keys=True),
        }.items():
            privacy_scan_text(label, text, secret_values=secret_values)
            for marker in PRIVACY_PATH_MARKERS:
                if marker in text:
                    raise AcceptanceError(f"privacy scan failed for {label}: found path marker {marker!r}")

        return {
            "ok": True,
            "candidate_git_sha": candidate_git_sha,
            "wheel_sha256": wheel_sha256,
            "installed_package_version": install_info["version"],
            "doctor_tool_count": doctor_tool_count,
            "doctor_smoke_ok": downstream.get("smoke_ok"),
            "scenarios": scenario_results,
            "evidence_count": events_payload.get("evidence_count"),
            "timeline_event_count": timeline_payload.get("event_count"),
            "summary_record_count": summary_payload.get("record_count"),
            "privacy_scan": "clean",
            "target_proof": {
                "safe_read": scenario_results.get("safe_read") is True,
                "write_pre_approval": scenario_results.get("write_pre_approval") is True,
                "write_approved": scenario_results.get("write_approved") is True,
                "write_denied": scenario_results.get("write_denied") is True,
                "git_add": scenario_results.get("git_add") is True,
                "pip_install": scenario_results.get("pip_install") is True,
                "secret_block": scenario_results.get("secret_block") is True,
                "github_ci_like": scenario_results.get("github_ci_like") is True,
            },
        }
    finally:
        if not args.keep_tmp and args.work_dir is None:
            shutil.rmtree(work_root, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, default=None, help="Use an existing wheel instead of building one")
    parser.add_argument("--work-dir", type=Path, default=None, help="Keep artifacts under this directory")
    parser.add_argument("--keep-tmp", action="store_true", help="Do not delete the temporary work directory")
    parser.add_argument("--python", default=sys.executable, help="Python executable used to build venvs")
    parser.add_argument("--git-root", type=Path, default=None, help="Git repository root for candidate SHA resolution")
    parser.add_argument("--git-sha", default=None, help="Override candidate git SHA in the report")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = run_product_route_acceptance(args)
    except AcceptanceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), flush=True)
        return 1
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
