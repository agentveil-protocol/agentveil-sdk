#!/usr/bin/env python3
"""Onboarding stage gate for the AgentVeil MCP Proxy cold-client product path.

Builds or consumes a candidate wheel, installs it into a clean virtualenv under an
isolated AVP home, exercises init/doctor/smoke/client-config print/run, approval + deny
flows, evidence export/verify, and privacy scans. Emits a final JSON report.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp_proxy_acceptance_lib import (
    AcceptanceError,
    JsonRpcClient,
    JSONRPC_APPROVAL_REQUIRED,
    REPO_ROOT,
    approve_url,
    assert_client_config_print_payload,
    assert_approval_token_absent,
    assert_installed_from_wheel,
    assert_tool_success,
    approval_session_token_from_url,
    build_wheel,
    check_approval_center_api,
    install_wheel,
    log,
    privacy_scan_bundle,
    privacy_scan_events,
    privacy_scan_text,
    resolve_git_sha,
    run,
    run_cli_json,
    scrub_install_env,
    trusted_signer_dids_for_base_url,
    verification_signer_dids,
)


APPROVE_WRITE_NAME = "onboarding-approve.txt"
DENY_WRITE_NAME = "onboarding-deny-probe.txt"
WRITE_CONTENT = "onboarding stage gate write\n"
ACCEPTANCE_ROLE_CHOICES = ("reviewer", "readonly", "implementer", "build")
# Non-interactive approval UI: no browser tabs or OS notifications during gate runs.
RUN_NONINTERACTIVE_UI_ARGS = ["--approval-ui-mode", "none"]


def assert_approval_required(response: dict[str, Any], *, sandbox_file: Path) -> dict[str, Any]:
    error = response.get("error")
    if not isinstance(error, dict) or error.get("code") != JSONRPC_APPROVAL_REQUIRED:
        raise AcceptanceError(f"expected approval_required error: {response}")
    data = error.get("data")
    if not isinstance(data, dict):
        raise AcceptanceError(f"approval_required data missing: {response}")
    approval_url = data.get("approval_url")
    record_id = data.get("record_id")
    if data.get("status") != "approval_required" or not record_id or not approval_url:
        raise AcceptanceError(f"approval_required response missing fields: {data}")
    if sandbox_file.exists():
        raise AcceptanceError(f"target reached before approval: {sandbox_file}")
    return data


def count_executed_write_events(events: list[dict[str, Any]], tool_name: str = "write_file") -> int:
    return sum(
        1
        for event in events
        if event.get("tool") == tool_name and event.get("status") == "executed"
    )


def run_stage_gate(args: argparse.Namespace) -> dict[str, Any]:
    work_root = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix="avp-mcp-onboarding-"))
    work_root.mkdir(parents=True, exist_ok=True)
    output_sink: list[str] = []
    git_root = Path(args.git_root).resolve() if args.git_root else REPO_ROOT
    try:
        log(f"work directory: {work_root}")
        wheel = Path(args.wheel).resolve() if args.wheel else build_wheel(work_root, args.python, output_sink=output_sink)
        wheel_sha256 = sha256(wheel.read_bytes()).hexdigest()
        candidate_git_sha = args.git_sha or resolve_git_sha(git_root)
        log(f"wheel under test: {wheel}")
        log(f"candidate git sha: {candidate_git_sha}")

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

        home = work_root / "avp-home"
        sandbox = work_root / "sandbox"
        passphrase_file = work_root / "passphrase.txt"
        bundle_path = work_root / "evidence-bundle.json"
        passphrase_secret = secrets.token_urlsafe(32)
        passphrase_file.write_text(passphrase_secret + "\n", encoding="utf-8")
        passphrase_file.chmod(0o600)
        secret_values = (passphrase_secret,)

        agent_name = f"{args.agent_name_prefix}-{int(time.time())}-{secrets.token_hex(4)}"
        path_args = ["--home", str(home)]
        identity_args = [*path_args, "--passphrase-file", str(passphrase_file)]

        init_payload = run_cli_json(
            proxy,
            [
                "init",
                "--home",
                str(home),
                "--agent-name",
                agent_name,
                "--base-url",
                args.base_url,
                "--role",
                args.role,
                "--passphrase-file",
                str(passphrase_file),
                "--quickstart-filesystem",
                str(sandbox),
                "--json",
            ],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        if init_payload.get("downstream", {}).get("configured") is not True:
            raise AcceptanceError("init did not configure quickstart downstream")

        doctor_payload = run_cli_json(
            proxy,
            ["doctor", *identity_args, "--full", "--json"],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        doctor_tool_count = int(doctor_payload.get("downstream", {}).get("tool_count") or 0)
        if doctor_tool_count < 1:
            raise AcceptanceError("doctor --full did not report downstream tool_count")

        smoke_payload = run_cli_json(
            proxy,
            ["smoke", *path_args, "--json"],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        smoke_tool_count = int(smoke_payload.get("downstream", {}).get("tool_count") or 0)
        if smoke_tool_count < 1:
            raise AcceptanceError("smoke did not report downstream tool_count")

        client_config_payload = run_cli_json(
            proxy,
            [
                "client-config",
                "print",
                *path_args,
                "--passphrase-file",
                str(passphrase_file),
                "--proxy-command",
                str(proxy),
                "--client",
                "cursor",
                "--client",
                "claude_desktop",
                "--json",
            ],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        assert_client_config_print_payload(
            client_config_payload,
            home=home,
            passphrase_file=passphrase_file,
            proxy_command=proxy,
            secret_values=secret_values,
        )

        registered = False
        if not args.skip_backend:
            register_payload = run_cli_json(
                proxy,
                ["register", *identity_args, "--json"],
                cwd=work_root,
                env=gate_env,
                output_sink=output_sink,
            )
            if register_payload.get("registered") is not True:
                raise AcceptanceError("register --json did not report registered=true")
            backend_payload = run_cli_json(
                proxy,
                ["doctor", *identity_args, "--check-backend", "--json"],
                cwd=work_root,
                env=gate_env,
                output_sink=output_sink,
            )
            if backend_payload.get("backend", {}).get("ok") is not True:
                raise AcceptanceError("doctor --check-backend did not report backend.ok=true")
            registered = True
        else:
            log("skipping backend register/check because --skip-backend was passed")

        approve_file = sandbox / APPROVE_WRITE_NAME
        deny_file = sandbox / DENY_WRITE_NAME
        risky_args = {
            "name": "write_file",
            "arguments": {
                "path": APPROVE_WRITE_NAME,
                "content": WRITE_CONTENT,
            },
        }
        deny_args = {
            "name": "write_file",
            "arguments": {
                "path": DENY_WRITE_NAME,
                "content": "deny probe\n",
            },
        }

        approval_center: dict[str, Any] = {"status": "not_run"}
        approval_token: str | None = None
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
                    {"clientInfo": {"name": "onboarding-stage-gate"}},
                ),
                "initialize-1",
            )
            if initialize.get("serverInfo", {}).get("name") != "agentveil-quickstart-filesystem":
                raise AcceptanceError("initialize returned unexpected downstream serverInfo")
            client.notify("notifications/initialized", {})

            tools_result = assert_tool_success(client.call("tools-list-1", "tools/list", {}), "tools-list-1")
            tool_names = {tool.get("name") for tool in tools_result.get("tools", [])}
            if {"list_workspace", "write_file"} - tool_names:
                raise AcceptanceError(f"expected quickstart tools missing: {tool_names}")

            assert_tool_success(
                client.call("workspace-list-1", "tools/call", {"name": "list_workspace", "arguments": {}}),
                "workspace-list-1",
            )

            risky = client.call("risky-write-1", "tools/call", risky_args)
            approval_data = assert_approval_required(risky, sandbox_file=approve_file)
            approval_url = str(approval_data["approval_url"])
            approval_token = approval_session_token_from_url(approval_url)
            approval_center = check_approval_center_api(
                approval_url,
                record_id=str(approval_data["record_id"]),
            )
            assert_approval_token_absent(
                approval_token,
                surfaces={"runner_output": "".join(output_sink)},
            )

            approve_url(approval_url)
            retry_result = assert_tool_success(
                client.call("risky-write-2", "tools/call", risky_args),
                "risky-write-2",
            )
            rendered_retry = json.dumps(retry_result, sort_keys=True)
            if APPROVE_WRITE_NAME not in rendered_retry and "wrote" not in rendered_retry:
                raise AcceptanceError(f"retry did not report downstream write: {retry_result}")
            if not approve_file.exists():
                raise AcceptanceError("approved retry did not create sandbox file")
            if approve_file.read_text(encoding="utf-8") != WRITE_CONTENT:
                raise AcceptanceError("approved retry wrote unexpected sandbox content")

            third = client.call("risky-write-3", "tools/call", risky_args)
            if "result" in third:
                raise AcceptanceError(
                    f"third write executed without a new approval (would break single-retry proof): {third}",
                )
            third_error = third.get("error")
            if not isinstance(third_error, dict):
                raise AcceptanceError(f"expected third write to require approval or return an error: {third}")
        finally:
            client.close()

        deny_client = JsonRpcClient(
            [
                str(proxy),
                "run",
                *identity_args,
                *RUN_NONINTERACTIVE_UI_ARGS,
                "--headless",
                "--auto-deny",
            ],
            cwd=work_root,
            env=gate_env,
        )
        try:
            assert_tool_success(
                deny_client.call(
                    "deny-init-1",
                    "initialize",
                    {"clientInfo": {"name": "onboarding-stage-gate-deny"}},
                ),
                "deny-init-1",
            )
            deny_client.notify("notifications/initialized", {})
            deny_response = deny_client.call("deny-write-1", "tools/call", deny_args)
            deny_error = deny_response.get("error")
            if not isinstance(deny_error, dict):
                raise AcceptanceError(f"expected deny path to return JSON-RPC error: {deny_response}")
            deny_data = deny_error.get("data")
            if isinstance(deny_data, dict) and deny_data.get("status") not in {"blocked", "policy_denied"}:
                raise AcceptanceError(f"unexpected deny path status: {deny_data}")
            if deny_file.exists():
                raise AcceptanceError("deny path reached downstream unexpectedly")
        finally:
            deny_client.close()

        events_payload = run_cli_json(
            proxy,
            ["events", "list", *path_args, "--limit", "50", "--json"],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        events = events_payload.get("events", [])
        if not isinstance(events, list):
            raise AcceptanceError("events list did not return events array")
        statuses = {event.get("status") for event in events if isinstance(event, dict)}
        if "approved" not in statuses or "executed" not in statuses:
            raise AcceptanceError(f"events list did not include approved/executed: {statuses}")
        if "denied" not in statuses:
            raise AcceptanceError(f"events list did not include denied status: {statuses}")

        executed_write_count = count_executed_write_events(events)
        if executed_write_count != 1:
            raise AcceptanceError(
                f"expected exactly one executed write_file record, found {executed_write_count}",
            )

        run(
            [str(proxy), "export-evidence", *identity_args, str(bundle_path)],
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        backend_signer_dids = trusted_signer_dids_for_base_url(
            install_python,
            args.base_url,
            work_dir=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        agent_did = init_payload.get("agent_did")
        if not isinstance(agent_did, str) or not agent_did:
            raise AcceptanceError("init did not return agent_did for verification pins")
        signer_dids = verification_signer_dids(agent_did, backend_signer_dids)
        verify_args = ["verify", str(bundle_path), "--output", "json"]
        for signer_did in signer_dids:
            verify_args += ["--trusted-signer-did", signer_did]
        verify_payload = run_cli_json(
            proxy,
            verify_args,
            cwd=work_root,
            env=gate_env,
            output_sink=output_sink,
        )
        if verify_payload.get("status") != "ok":
            raise AcceptanceError(f"verify did not return ok: {verify_payload}")

        privacy_scan_events(events_payload, secret_values=secret_values)
        privacy_scan_bundle(bundle_path, secret_values=secret_values)
        runner_output = "".join(output_sink)
        events_json = json.dumps(events_payload, sort_keys=True)
        bundle_text = bundle_path.read_text(encoding="utf-8")
        privacy_scan_text("runner_output", runner_output, secret_values=secret_values)

        metrics = {
            "ok": True,
            "candidate_git_sha": candidate_git_sha,
            "wheel": str(wheel),
            "wheel_sha256": wheel_sha256,
            "installed_package_path": install_info["module_path"],
            "installed_package_version": install_info["version"],
            "install_location": install_info.get("install_location"),
            "home": str(home),
            "sandbox": str(sandbox),
            "bundle": str(bundle_path),
            "registered": registered,
            "doctor_tool_count": doctor_tool_count,
            "smoke_tool_count": smoke_tool_count,
            "client_config_print_ok": True,
            "client_config_clients": sorted(client_config_payload.get("clients", {}).keys()),
            "target_not_reached_before_approval": True,
            "retry_executed_write_count": executed_write_count,
            "deny_target_reached": deny_file.exists(),
            "events_statuses": sorted(statuses),
            "approval_center_api": approval_center,
            "verify_status": verify_payload.get("status"),
            "signed_receipt_count": verify_payload.get("signed_receipt_count"),
            "record_count": verify_payload.get("record_count"),
            "privacy_scan": "clean",
        }
        if metrics["deny_target_reached"]:
            raise AcceptanceError("deny path created sandbox file")
        final_report = json.dumps(metrics, sort_keys=True)
        assert_approval_token_absent(
            approval_token,
            surfaces={
                "final_report": final_report,
                "runner_output": runner_output,
                "events": events_json,
                "bundle": bundle_text,
            },
        )
        privacy_scan_text("final_report", final_report, secret_values=secret_values)
        return metrics
    finally:
        if not args.keep_tmp and args.work_dir is None:
            shutil.rmtree(work_root, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, default=None, help="Use an existing wheel instead of building one")
    parser.add_argument("--work-dir", type=Path, default=None, help="Keep artifacts under this directory")
    parser.add_argument("--keep-tmp", action="store_true", help="Do not delete the temporary work directory")
    parser.add_argument("--python", default=sys.executable, help="Python executable used to build venvs")
    parser.add_argument("--base-url", default="https://agentveil.dev", help="Backend base URL for registration")
    parser.add_argument(
        "--role",
        choices=ACCEPTANCE_ROLE_CHOICES,
        default="build",
        help="Role preset for init; build preserves read/list allow plus write approval path",
    )
    parser.add_argument(
        "--agent-name-prefix",
        default="agentveil-mcp-proxy-onboarding-stage-gate",
        help="Prefix for the temporary backend registration identity",
    )
    parser.add_argument(
        "--skip-backend",
        action="store_true",
        help="Skip register/doctor --check-backend (local iteration only)",
    )
    parser.add_argument("--git-root", type=Path, default=None, help="Git repository root for candidate SHA resolution")
    parser.add_argument("--git-sha", default=None, help="Override candidate git SHA in the report")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = run_stage_gate(args)
    except AcceptanceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), flush=True)
        return 1
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
