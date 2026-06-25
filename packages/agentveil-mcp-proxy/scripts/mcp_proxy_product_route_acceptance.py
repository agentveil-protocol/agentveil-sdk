#!/usr/bin/env python3
"""Public product-route smoke for the installed AgentVeil MCP Proxy wheel.

This runner checks the public contract without publishing the full internal
acceptance matrix: install the candidate wheel, initialize the product route,
verify safe reads, one routed approval path, one denied path, one blocked path,
bounded evidence, and privacy-clean output.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
from typing import Any
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

sys_path_inserted = False
if __name__ == "__main__" or __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys_path_inserted = True

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
    run_cli_json,
    scrub_install_env,
)

EXPECTED_TOOL_COUNT = 68
EXPECTED_VERSION = "0.7.23"
RUN_NONINTERACTIVE_UI_ARGS = ["--approval-ui-mode", "none"]

SAFE_READ_TOOL = "list_workspace"
APPROVE_WRITE_NAME = "product-route-approve.txt"
DENY_WRITE_NAME = "product-route-deny.txt"
WRITE_CONTENT = "product route acceptance write\n"
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
    return {
        "profile_root": profile_root,
        "workspace": profile_root / "workspace",
    }


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
    for key in ("risk_family", "redirect_playbook_id", "safe_first_step_id"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise AcceptanceError(f"{tool}: {key} missing from approval data")
    if target_path is not None and target_path.exists():
        raise AcceptanceError(f"{tool}: target reached before approval: {target_path.name}")
    if not data.get("record_id") or not data.get("approval_url"):
        raise AcceptanceError(f"{tool}: approval_required missing record_id or approval_url")
    if data.get("target_reached") is True:
        raise AcceptanceError(f"{tool}: target_reached=true before approval")
    return data


def assert_blocked(response: dict[str, Any], *, tool: str) -> dict[str, Any]:
    error = response.get("error")
    if not isinstance(error, dict):
        raise AcceptanceError(f"{tool}: expected JSON-RPC error: {response}")
    data = error.get("data")
    if not isinstance(data, dict):
        raise AcceptanceError(f"{tool}: blocked data missing: {response}")
    if data.get("status") not in {"blocked", "policy_denied"}:
        raise AcceptanceError(f"{tool}: expected blocked status: {data}")
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
                    {"clientInfo": {"name": "product-route-public-smoke"}},
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

            response = assert_tool_success(
                client.call(f"safe-{SAFE_READ_TOOL}", "tools/call", {"name": SAFE_READ_TOOL, "arguments": {}}),
                f"safe-{SAFE_READ_TOOL}",
            )
            rendered = tool_result_text(response)
            if "redirect_playbook_id" in rendered or "risk_family" in rendered:
                raise AcceptanceError(f"{SAFE_READ_TOOL}: safe read leaked redirect metadata")
            scenario_results["safe_read"] = True

            write_args = {
                "name": "write_file",
                "arguments": {"path": APPROVE_WRITE_NAME, "content": WRITE_CONTENT},
            }
            risky = client.call("write-pre-1", "tools/call", write_args)
            assert_approval_required(risky, tool="write_file", target_path=approve_file)
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
            deny_data = assert_approval_required(deny_pending, tool="write_file", target_path=deny_file)
            deny_url(str(deny_data["approval_url"]))
            deny_retry = client.call("write-deny-2", "tools/call", deny_args)
            if deny_file.exists():
                raise AcceptanceError("denied write_file retry reached target file")
            deny_error = deny_retry.get("error")
            if not isinstance(deny_error, dict):
                raise AcceptanceError(f"denied write_file retry did not return an error: {deny_retry}")
            scenario_results["write_denied"] = True

            blocked = client.call(
                "secret-1",
                "tools/call",
                {
                    "name": "get_secret",
                    "arguments": {"owner": "acme", "repo": "demo-repo", "secret_name": "DEPLOY_KEY"},
                },
            )
            assert_blocked(blocked, tool="get_secret")
            scenario_results["secret_block"] = True
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

        secret_event = require_event(events, "get_secret", "blocked")
        if secret_event.get("target_reached") is True:
            raise AcceptanceError("get_secret blocked evidence reported target_reached=true")

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
            "wheel": {
                "filename": wheel.name,
                "sha256": wheel_sha256,
            },
            "installed_package_version": install_info["version"],
            "doctor_tool_count": doctor_tool_count,
            "scenarios": scenario_results,
            "evidence_record_count": len(events),
            "privacy_scan": "clean",
        }
    finally:
        if not args.keep_tmp and args.work_dir is None:
            import shutil

            shutil.rmtree(work_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=None, help="Keep all acceptance artifacts under this directory")
    parser.add_argument("--wheel", type=Path, default=None, help="Candidate wheel to install instead of building one")
    parser.add_argument("--python", default=sys.executable if sys_path_inserted else None, help="Python interpreter for build/install")
    parser.add_argument("--git-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--git-sha", default=None)
    parser.add_argument("--keep-tmp", action="store_true")
    args = parser.parse_args(argv)
    if args.python is None:
        args.python = sys.executable

    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    try:
        with redirect_stdout(captured_stdout), redirect_stderr(captured_stderr):
            report = run_product_route_acceptance(args)
    except AcceptanceError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
