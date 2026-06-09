#!/usr/bin/env python3
"""Release acceptance runner for the AgentVeil MCP Proxy customer path.

This script is intentionally heavier than unit tests. It builds or consumes a
wheel, installs it into a clean venv, registers a fresh proxy identity with the
configured backend, drives the MCP proxy over stdio, approves a risky action
through the loopback approval UI, retries the action, and verifies evidence.
"""

from __future__ import annotations

import argparse
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener


REPO_ROOT = Path(__file__).resolve().parents[1]
JSONRPC_APPROVAL_REQUIRED = -32011
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
ACCEPTANCE_ROLE_CHOICES = ("reviewer", "readonly", "implementer", "build")


class AcceptanceError(RuntimeError):
    """Raised when the release acceptance path fails."""


def log(message: str) -> None:
    print(f"==> {message}", flush=True)


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    rendered = " ".join(command)
    log(rendered)
    result = subprocess.run(
        command,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if check and result.returncode != 0:
        raise AcceptanceError(f"command failed with exit {result.returncode}: {rendered}")
    return result


def parse_json_output(result: subprocess.CompletedProcess[str], command_name: str) -> dict[str, Any]:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AcceptanceError(f"{command_name} did not return JSON") from exc
    if not isinstance(payload, dict):
        raise AcceptanceError(f"{command_name} JSON was not an object")
    if payload.get("ok") is not True and payload.get("status") != "ok":
        raise AcceptanceError(f"{command_name} returned non-ok JSON: {payload}")
    return payload


def venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def venv_bin(venv_dir: Path, command: str) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / f"{command}.exe"
    return venv_dir / "bin" / command


def create_venv(venv_dir: Path, python: str) -> Path:
    run([python, "-m", "venv", str(venv_dir)])
    python = venv_python(venv_dir)
    if not python.exists():
        raise AcceptanceError(f"venv python not found: {python}")
    return python


def build_wheel(work_dir: Path, python: str) -> Path:
    build_venv = work_dir / "build-venv"
    build_python = create_venv(build_venv, python)
    run([str(build_python), "-m", "pip", "install", "--quiet", "--upgrade", "pip", "build"])
    dist_dir = work_dir / "dist"
    dist_dir.mkdir()
    run([str(build_python), "-m", "build", "--wheel", "--outdir", str(dist_dir)], cwd=REPO_ROOT)
    wheels = sorted(dist_dir.glob("agentveil_mcp_proxy-*-py3-none-any.whl"))
    if len(wheels) != 1:
        raise AcceptanceError(f"expected one built wheel, found {len(wheels)} in {dist_dir}")
    return wheels[0]


def install_wheel(work_dir: Path, wheel: Path, python: str) -> tuple[Path, Path]:
    install_venv = work_dir / "install-venv"
    install_python = create_venv(install_venv, python)
    run([str(install_python), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
    run([str(install_python), "-m", "pip", "install", str(wheel)])
    proxy = venv_bin(install_venv, "agentveil-mcp-proxy")
    if not proxy.exists():
        raise AcceptanceError("agentveil-mcp-proxy console script missing from wheel install")
    return install_python, proxy


def run_cli_json(proxy: Path, args: list[str], *, env: dict[str, str] | None = None) -> dict[str, Any]:
    result = run([str(proxy), *args], env=env)
    return parse_json_output(result, "agentveil-mcp-proxy " + " ".join(args))


def trusted_signer_dids_for_base_url(
    python: Path, base_url: str, *, env: dict[str, str] | None = None
) -> list[str]:
    """Resolve the SDK's pinned trusted signer DID(s) for a backend base URL.

    Strict offline verification must pin the signer out of band, so the release
    gate asks the installed package for the trusted signers of the backend it
    registered against rather than trusting the signer list embedded in the
    exported bundle.
    """
    code = (
        "import json, sys; "
        "from agentveil_mcp_proxy.cli import trusted_signers_for_base_url; "
        "print(json.dumps(list(trusted_signers_for_base_url(sys.argv[1]))))"
    )
    result = run([str(python), "-c", code, base_url], env=env)
    return list(json.loads(result.stdout.strip() or "[]"))


def verification_signer_dids(proxy_identity_did: str, backend_signer_dids: list[str]) -> list[str]:
    """Return external signer pins required by strict bundle verification.

    Decision receipts are signed by the backend trusted signers. Local approval
    grants are signed by the proxy identity itself, so the release acceptance
    verifier must pin both trust roots explicitly.
    """
    pins: list[str] = []
    for signer_did in [proxy_identity_did, *backend_signer_dids]:
        if signer_did and signer_did not in pins:
            pins.append(signer_did)
    return pins


class JsonRpcClient:
    def __init__(self, command: list[str], *, env: dict[str, str]) -> None:
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        self.stdout_queue: queue.Queue[str] = queue.Queue()
        self.stderr_lines: list[str] = []
        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.stdout_queue.put(line)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.stderr_lines.append(line.rstrip("\n"))

    def call(self, request_id: str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.process.stdin is not None
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        return self._read_response(request_id)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        assert self.process.stdin is not None
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def _read_response(self, request_id: str, timeout: float = 20.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                raw = self.stdout_queue.get(timeout=0.2)
            except queue.Empty:
                if self.process.poll() is not None:
                    raise AcceptanceError(
                        f"proxy exited early with {self.process.returncode}; stderr={self.stderr_lines}"
                    )
                continue
            response = json.loads(raw)
            if response.get("id") == request_id:
                return response
        raise AcceptanceError(f"timed out waiting for JSON-RPC response id={request_id}")

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def approve_url(approval_url: str) -> None:
    opener = build_opener(HTTPCookieProcessor(CookieJar()))
    with opener.open(approval_url, timeout=10) as response:
        page = response.read().decode("utf-8")
    match = CSRF_RE.search(page)
    if match is None:
        raise AcceptanceError("approval page did not contain a CSRF token")
    body = urlencode({
        "decision": "approve",
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
            raise AcceptanceError(f"approval POST returned HTTP {response.status}")


def assert_tool_success(response: dict[str, Any], request_id: str) -> dict[str, Any]:
    if response.get("id") != request_id or "result" not in response:
        raise AcceptanceError(f"expected success response for {request_id}: {response}")
    result = response["result"]
    if not isinstance(result, dict):
        raise AcceptanceError(f"result for {request_id} was not an object")
    return result


def run_acceptance(args: argparse.Namespace) -> None:
    work_root = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix="avp-mcp-release-"))
    work_root.mkdir(parents=True, exist_ok=True)
    log(f"work directory: {work_root}")
    try:
        wheel = Path(args.wheel).resolve() if args.wheel else build_wheel(work_root, args.python)
        log(f"wheel under test: {wheel}")
        install_python, proxy = install_wheel(work_root, wheel, args.python)

        home = work_root / "avp-home"
        sandbox = work_root / "sandbox"
        passphrase_file = work_root / "passphrase.txt"
        bundle_path = work_root / "evidence-bundle.json"
        passphrase_file.write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")
        passphrase_file.chmod(0o600)

        agent_name = f"{args.agent_name_prefix}-{int(time.time())}-{secrets.token_hex(4)}"
        path_args = ["--home", str(home)]
        identity_args = [*path_args, "--passphrase-file", str(passphrase_file)]
        env = dict(os.environ)
        env["BROWSER"] = "true"

        init_payload = run_cli_json(proxy, [
            "init",
            "--home", str(home),
            "--agent-name", agent_name,
            "--base-url", args.base_url,
            "--role", args.role,
            "--passphrase-file", str(passphrase_file),
            "--quickstart-filesystem", str(sandbox),
            "--json",
        ], env=env)
        if init_payload.get("downstream", {}).get("configured") is not True:
            raise AcceptanceError("init did not configure quickstart downstream")

        doctor_payload = run_cli_json(proxy, ["doctor", *identity_args, "--full", "--json"], env=env)
        if int(doctor_payload.get("downstream", {}).get("tool_count") or 0) < 1:
            raise AcceptanceError("doctor --full did not report downstream tool_count")

        if not args.skip_backend:
            register_payload = run_cli_json(proxy, ["register", *identity_args, "--json"], env=env)
            if register_payload.get("registered") is not True:
                raise AcceptanceError("register --json did not report registered=true")
            backend_payload = run_cli_json(
                proxy,
                ["doctor", *identity_args, "--check-backend", "--json"],
                env=env,
            )
            if backend_payload.get("backend", {}).get("ok") is not True:
                raise AcceptanceError("doctor --check-backend did not report backend.ok=true")
        else:
            log("skipping backend register/check because --skip-backend was passed")

        client = JsonRpcClient([str(proxy), "run", *identity_args], env=env)
        try:
            initialize = assert_tool_success(
                client.call("initialize-1", "initialize", {"clientInfo": {"name": "release-acceptance"}}),
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
                client.call(
                    "safe-list-1",
                    "tools/call",
                    {"name": "list_workspace", "arguments": {}},
                ),
                "safe-list-1",
            )

            risky_args = {
                "name": "write_file",
                "arguments": {
                    "path": "acceptance-write.txt",
                    "content": "release acceptance write\n",
                },
            }
            risky = client.call("risky-write-1", "tools/call", risky_args)
            error = risky.get("error")
            if not isinstance(error, dict) or error.get("code") != JSONRPC_APPROVAL_REQUIRED:
                raise AcceptanceError(f"expected approval_required error: {risky}")
            data = error.get("data")
            if not isinstance(data, dict):
                raise AcceptanceError(f"approval_required data missing: {risky}")
            approval_url = data.get("approval_url")
            record_id = data.get("record_id")
            if data.get("status") != "approval_required" or not record_id or not approval_url:
                raise AcceptanceError(f"approval_required response missing fields: {data}")
            if (sandbox / "acceptance-write.txt").exists():
                raise AcceptanceError("risky write reached downstream before approval")

            approve_url(str(approval_url))
            retry_result = assert_tool_success(
                client.call("risky-write-2", "tools/call", risky_args),
                "risky-write-2",
            )
            rendered_retry = json.dumps(retry_result, sort_keys=True)
            if "wrote acceptance-write.txt" not in rendered_retry:
                raise AcceptanceError(f"retry did not report downstream write: {retry_result}")
            if (sandbox / "acceptance-write.txt").read_text(encoding="utf-8") != "release acceptance write\n":
                raise AcceptanceError("approved retry did not create expected sandbox file")
        finally:
            client.close()

        events_payload = run_cli_json(proxy, ["events", "list", *path_args, "--limit", "20", "--json"], env=env)
        statuses = {event.get("status") for event in events_payload.get("events", [])}
        if "approved" not in statuses or "executed" not in statuses:
            raise AcceptanceError(f"events list did not include approved/executed records: {events_payload}")

        run([str(proxy), "export-evidence", *identity_args, str(bundle_path)], env=env)
        # Strict offline verification pins signer DIDs out of band: backend
        # DIDs for receipt verification and the proxy identity DID for local
        # approval grants. Bundle-embedded signer lists are not trust anchors.
        backend_signer_dids = trusted_signer_dids_for_base_url(install_python, args.base_url, env=env)
        agent_did = init_payload.get("agent_did")
        if not isinstance(agent_did, str) or not agent_did:
            raise AcceptanceError("init did not return agent_did for verification pins")
        signer_dids = verification_signer_dids(agent_did, backend_signer_dids)
        verify_args = ["verify", str(bundle_path), "--output", "json"]
        for signer_did in signer_dids:
            verify_args += ["--trusted-signer-did", signer_did]
        verify_payload = run_cli_json(proxy, verify_args, env=env)
        if verify_payload.get("status") != "ok":
            raise AcceptanceError(f"verify did not return ok: {verify_payload}")

        print(json.dumps({
            "ok": True,
            "wheel": str(wheel),
            "home": str(home),
            "sandbox": str(sandbox),
            "bundle": str(bundle_path),
            "registered": not args.skip_backend,
            "signed_receipt_count": verify_payload.get("signed_receipt_count"),
            "record_count": verify_payload.get("record_count"),
        }, sort_keys=True), flush=True)
    finally:
        if not args.keep_tmp and args.work_dir is None:
            shutil.rmtree(work_root, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, default=None, help="Use an existing wheel instead of building one")
    parser.add_argument("--work-dir", type=Path, default=None, help="Keep all acceptance artifacts under this directory")
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
        default="agentveil-mcp-proxy-release-acceptance",
        help="Prefix for the temporary backend registration identity",
    )
    parser.add_argument(
        "--skip-backend",
        action="store_true",
        help="Skip register/doctor --check-backend; not acceptable for a public MCP Proxy release gate",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        run_acceptance(args)
    except AcceptanceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
