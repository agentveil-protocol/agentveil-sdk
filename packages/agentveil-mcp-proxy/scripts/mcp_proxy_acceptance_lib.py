"""Shared helpers for MCP Proxy product-path acceptance runners."""

from __future__ import annotations

from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
from typing import Any, Mapping
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parent.parent
JSONRPC_APPROVAL_REQUIRED = -32011
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


class AcceptanceError(RuntimeError):
    """Raised when a product-path acceptance runner fails."""


def log(message: str) -> None:
    print(f"==> {message}", flush=True)


def scrub_install_env(env: dict[str, str]) -> dict[str, str]:
    """Return env without variables that shadow a wheel-only install."""

    clean = dict(env)
    for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSAFEPATH"):
        clean.pop(key, None)
    return clean


def install_venv_root(install_python: Path) -> Path:
    parent = install_python.parent
    if parent.name not in {"bin", "Scripts"}:
        raise AcceptanceError(f"unexpected install interpreter layout: {install_python}")
    return parent.parent


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    output_sink: list[str] | None = None,
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
        if output_sink is not None:
            output_sink.append(result.stdout)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
        if output_sink is not None:
            output_sink.append(result.stderr)
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


def create_venv(venv_dir: Path, python: str, *, output_sink: list[str] | None = None) -> Path:
    run([python, "-m", "venv", str(venv_dir)], output_sink=output_sink)
    interpreter = venv_python(venv_dir)
    if not interpreter.exists():
        raise AcceptanceError(f"venv python not found: {interpreter}")
    return interpreter


def build_wheel(
    work_dir: Path,
    python: str,
    *,
    output_sink: list[str] | None = None,
) -> Path:
    build_venv = work_dir / "build-venv"
    build_python = create_venv(build_venv, python, output_sink=output_sink)
    run(
        [str(build_python), "-m", "pip", "install", "--quiet", "--upgrade", "pip", "build"],
        output_sink=output_sink,
    )
    dist_dir = work_dir / "dist"
    dist_dir.mkdir()
    run(
        [str(build_python), "-m", "build", "--wheel", "--outdir", str(dist_dir)],
        cwd=PACKAGE_ROOT,
        output_sink=output_sink,
    )
    wheels = sorted(dist_dir.glob("agentveil_mcp_proxy-*-py3-none-any.whl"))
    if len(wheels) != 1:
        raise AcceptanceError(f"expected one built wheel, found {len(wheels)} in {dist_dir}")
    return wheels[0]


def install_wheel(
    work_dir: Path,
    wheel: Path,
    python: str,
    *,
    output_sink: list[str] | None = None,
) -> tuple[Path, Path]:
    install_venv = work_dir / "install-venv"
    install_python = create_venv(install_venv, python, output_sink=output_sink)
    run(
        [str(install_python), "-m", "pip", "install", "--quiet", "--upgrade", "pip"],
        output_sink=output_sink,
    )
    run([str(install_python), "-m", "pip", "install", str(wheel)], output_sink=output_sink)
    proxy = venv_bin(install_venv, "agentveil-mcp-proxy")
    if not proxy.exists():
        raise AcceptanceError("agentveil-mcp-proxy console script missing from wheel install")
    return install_python, proxy


def run_cli_json(
    proxy: Path,
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    output_sink: list[str] | None = None,
) -> dict[str, Any]:
    result = run(
        [str(proxy), *args],
        cwd=cwd,
        env=scrub_install_env(env or os.environ),
        output_sink=output_sink,
    )
    return parse_json_output(result, "agentveil-mcp-proxy " + " ".join(args))


def trusted_signer_dids_for_base_url(
    python: Path,
    base_url: str,
    *,
    work_dir: Path | None = None,
    env: dict[str, str] | None = None,
    output_sink: list[str] | None = None,
) -> list[str]:
    code = (
        "import json, sys; "
        "from agentveil_mcp_proxy.cli import trusted_signers_for_base_url; "
        "print(json.dumps(list(trusted_signers_for_base_url(sys.argv[1]))))"
    )
    result = run(
        [str(python), "-c", code, base_url],
        cwd=work_dir,
        env=scrub_install_env(env or os.environ),
        output_sink=output_sink,
    )
    return list(json.loads(result.stdout.strip() or "[]"))


def verification_signer_dids(proxy_identity_did: str, backend_signer_dids: list[str]) -> list[str]:
    pins: list[str] = []
    for signer_did in [proxy_identity_did, *backend_signer_dids]:
        if signer_did and signer_did not in pins:
            pins.append(signer_did)
    return pins


def resolve_git_sha(git_root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(git_root), "rev-parse", "HEAD"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip()


def installed_package_path(
    install_python: Path,
    *,
    work_dir: Path,
    env: dict[str, str] | None = None,
    output_sink: list[str] | None = None,
) -> Path:
    code = (
        "import agentveil_mcp_proxy; "
        "from pathlib import Path; "
        "print(Path(agentveil_mcp_proxy.__file__).resolve())"
    )
    result = run(
        [str(install_python), "-c", code],
        cwd=work_dir,
        env=scrub_install_env(env or os.environ),
        output_sink=output_sink,
    )
    return Path(result.stdout.strip())


def wheel_version_tag(wheel: Path) -> str:
    match = re.fullmatch(r"agentveil_mcp_proxy-(.+)-py3-none-any\.whl", wheel.name)
    if match is None:
        raise AcceptanceError(f"unexpected wheel filename: {wheel.name}")
    return match.group(1)


def assert_installed_from_wheel(
    install_python: Path,
    wheel: Path,
    *,
    work_dir: Path,
    env: dict[str, str] | None = None,
    output_sink: list[str] | None = None,
) -> dict[str, str]:
    expected_version = wheel_version_tag(wheel)
    clean_env = scrub_install_env(env or os.environ)
    show = run(
        [str(install_python), "-m", "pip", "show", "agentveil-mcp-proxy"],
        cwd=work_dir,
        env=clean_env,
        output_sink=output_sink,
    )
    installed_version = ""
    install_location = ""
    for line in show.stdout.splitlines():
        if line.startswith("Version:"):
            installed_version = line.split(":", 1)[1].strip()
        elif line.startswith("Location:"):
            install_location = line.split(":", 1)[1].strip()
    if installed_version != expected_version:
        raise AcceptanceError(
            f"installed version {installed_version!r} does not match wheel {expected_version!r}",
        )
    module_path = installed_package_path(
        install_python,
        work_dir=work_dir,
        env=clean_env,
        output_sink=output_sink,
    )
    venv_root = install_venv_root(install_python).resolve()
    if not str(module_path.resolve()).startswith(str(venv_root)):
        raise AcceptanceError(
            f"installed module path {module_path} is outside install venv {venv_root}",
        )
    if install_location and not str(module_path.resolve()).startswith(str(Path(install_location).resolve())):
        raise AcceptanceError(
            f"installed module path {module_path} is outside pip location {install_location}",
        )
    return {
        "version": installed_version,
        "module_path": str(module_path),
        "install_location": install_location,
    }


def _extract_runnable_mcp_configs(payload: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Return ``(command, args)`` pairs from legacy or client-matrix JSON shapes."""

    configs: list[tuple[str, list[str]]] = []
    legacy_command = payload.get("command")
    legacy_args = payload.get("args")
    if isinstance(legacy_command, str) and isinstance(legacy_args, list) and legacy_args:
        if all(isinstance(item, str) for item in legacy_args):
            configs.append((legacy_command, legacy_args))

    clients = payload.get("clients")
    if isinstance(clients, dict):
        for client_payload in clients.values():
            if not isinstance(client_payload, dict):
                continue
            for document_key in ("local_client_config", "document"):
                document = client_payload.get(document_key)
                if not isinstance(document, dict):
                    continue
                servers = document.get("mcpServers")
                if not isinstance(servers, dict):
                    continue
                for entry in servers.values():
                    if not isinstance(entry, dict):
                        continue
                    command = entry.get("command")
                    args = entry.get("args")
                    if isinstance(command, str) and isinstance(args, list) and args:
                        if all(isinstance(item, str) for item in args):
                            configs.append((command, args))
    return configs


def _json_text_contains_path(text: str, path: Path) -> bool:
    path_text = str(path)
    escaped_path_text = json.dumps(path_text)[1:-1]
    return path_text in text or escaped_path_text in text


def assert_client_config_print_payload(
    payload: dict[str, Any],
    *,
    home: Path,
    passphrase_file: Path,
    proxy_command: Path,
    secret_values: tuple[str, ...] = (),
) -> None:
    """Validate T1 ``client-config print --json`` onboarding output."""

    if payload.get("dry_run") is not True:
        raise AcceptanceError("client-config print must be dry_run=true")
    if payload.get("writes_user_config") is not False:
        raise AcceptanceError("client-config print must not write user config")
    privacy = payload.get("privacy")
    if not isinstance(privacy, dict):
        raise AcceptanceError("client-config print missing privacy block")
    if privacy.get("includes_passphrase") is not False:
        raise AcceptanceError("client-config print must not include passphrase content")
    if privacy.get("includes_private_key") is not False:
        raise AcceptanceError("client-config print must not include private key material")

    summary = payload.get("summary")
    if isinstance(summary, dict):
        summary_text = json.dumps(summary, sort_keys=True)
        if _json_text_contains_path(summary_text, home):
            raise AcceptanceError("client-config print summary must not include raw home path")
        if _json_text_contains_path(summary_text, passphrase_file):
            raise AcceptanceError("client-config print summary must not include raw passphrase file path")
        summary_command = summary.get("command")
        if isinstance(summary_command, str) and summary_command.strip():
            if str(proxy_command) != summary_command and proxy_command.name != summary_command:
                raise AcceptanceError("client-config print summary command must match installed proxy")

    runnable_configs = _extract_runnable_mcp_configs(payload)
    if not runnable_configs:
        raise AcceptanceError("client-config print missing runnable MCP server config")

    matching_configs = [
        (command, args)
        for command, args in runnable_configs
        if args[0] == "run"
        and str(proxy_command) == command
        and "--home" in args
        and str(home) in args
        and "--passphrase-file" in args
        and str(passphrase_file) in args
    ]
    if not matching_configs:
        raise AcceptanceError(
            "client-config print runnable config must invoke proxy run with isolated home and passphrase file",
        )

    clients = payload.get("clients")
    if not isinstance(clients, dict):
        raise AcceptanceError("client-config print missing clients object")
    for client_id in ("cursor", "claude_desktop"):
        if client_id not in clients:
            raise AcceptanceError(f"client-config print missing client {client_id}")
        client_payload = clients[client_id]
        if not isinstance(client_payload, dict):
            raise AcceptanceError(f"client-config print client payload invalid for {client_id}")
        document = client_payload.get("local_client_config") or client_payload.get("document")
        if not isinstance(document, dict) or "mcpServers" not in document:
            raise AcceptanceError(f"client-config print runnable document invalid for {client_id}")

    privacy_scan_text(
        "client_config_print",
        json.dumps(payload, sort_keys=True),
        secret_values=secret_values,
        bundle_mode=False,
        fragments=CLIENT_CONFIG_PRIVACY_FRAGMENTS,
    )


class JsonRpcClient:
    def __init__(
        self,
        command: list[str],
        *,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> None:
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=scrub_install_env(env),
            cwd=str(cwd) if cwd is not None else None,
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
                        f"proxy exited early with {self.process.returncode}; stderr={self.stderr_lines}",
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


def approval_session_token_from_url(approval_url: str) -> str | None:
    """Extract the loopback Approval Center bearer token from an approval URL."""

    marker = "/approval/"
    if marker not in approval_url:
        return None
    _prefix, remainder = approval_url.split(marker, 1)
    token = remainder.split("/", 1)[0]
    return token or None


def approval_api_url(approval_url: str) -> str | None:
    token = approval_session_token_from_url(approval_url)
    if not token:
        return None
    prefix = approval_url.split("/approval/", 1)[0]
    return f"{prefix}/approval/{token}/api/approvals"


def redacted_approval_center_endpoint(api_url: str) -> dict[str, Any]:
    """Return host/port/path metadata for retained gate reports."""

    parsed = urlparse(api_url)
    host = parsed.hostname or "127.0.0.1"
    if parsed.port is not None:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80
    return {
        "host": host,
        "port": port,
        "path_template": "/approval/<redacted>/api/approvals",
    }


def assert_approval_token_absent(
    token: str | None,
    *,
    surfaces: Mapping[str, str],
) -> None:
    """Fail when the Approval Center bearer token appears in retained gate artifacts."""

    if not token:
        return
    leaked_patterns = (token, f"/approval/{token}")
    for label, text in surfaces.items():
        for pattern in leaked_patterns:
            if pattern in text:
                raise AcceptanceError(f"approval center bearer token leaked in {label}")


def check_approval_center_api(approval_url: str, *, record_id: str) -> dict[str, Any]:
    """Probe loopback Approval Center JSON API when pending approval exists."""

    api_url = approval_api_url(approval_url)
    if api_url is None:
        return {"status": "skipped", "reason": "approval_url_unparseable"}
    opener = build_opener()
    try:
        with opener.open(api_url, timeout=10) as response:
            status_code = response.status
            body = response.read().decode("utf-8")
    except Exception:
        return {"status": "skipped", "reason": "api_unreachable"}
    if status_code == 404:
        return {"status": "skipped", "reason": "api_not_available_in_wheel"}
    if status_code != 200:
        raise AcceptanceError(f"approval center API returned HTTP {status_code}")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise AcceptanceError("approval center API did not return JSON") from exc
    if payload.get("ok") is not True:
        raise AcceptanceError(f"approval center API returned non-ok payload: {payload}")
    approvals = payload.get("approvals")
    if not isinstance(approvals, list):
        raise AcceptanceError("approval center API missing approvals list")
    pending = [item for item in approvals if item.get("status") == "pending"]
    if not any(item.get("request_id") == record_id for item in pending):
        raise AcceptanceError(
            f"approval center API pending list did not include record_id={record_id}",
        )
    blob = json.dumps(payload)
    if '"arguments"' in blob:
        raise AcceptanceError("approval center API payload contained raw arguments")
    if "session_id" in blob and "session_id_prefix" not in blob:
        raise AcceptanceError("approval center API payload exposed full session_id")
    return {
        "status": "ok",
        "pending_count": len(pending),
        **redacted_approval_center_endpoint(api_url),
    }


PRIVACY_GLOBAL_FRAGMENTS = (
    "private_key_hex",
    '"private_key"',
    "AKIA",
    "ASIA",
    "sk-ant-",
)
CLIENT_CONFIG_PRIVACY_FRAGMENTS = PRIVACY_GLOBAL_FRAGMENTS
PRIVACY_BUNDLE_EXTRA_FRAGMENTS = ('"arguments"',)


def privacy_scan_text(
    label: str,
    text: str,
    *,
    secret_values: tuple[str, ...] = (),
    bundle_mode: bool = False,
    fragments: tuple[str, ...] | None = None,
) -> None:
    fragments = list(fragments if fragments is not None else PRIVACY_GLOBAL_FRAGMENTS)
    if bundle_mode:
        fragments.extend(PRIVACY_BUNDLE_EXTRA_FRAGMENTS)
    for secret in secret_values:
        if secret and secret in text:
            raise AcceptanceError(f"privacy scan failed for {label}: secret value leaked")
    for fragment in fragments:
        if fragment in text:
            raise AcceptanceError(f"privacy scan failed for {label}: found forbidden fragment {fragment!r}")


def privacy_scan_bundle(bundle_path: Path, *, secret_values: tuple[str, ...] = ()) -> None:
    privacy_scan_text(
        str(bundle_path),
        bundle_path.read_text(encoding="utf-8"),
        secret_values=secret_values,
        bundle_mode=True,
    )


def privacy_scan_events(events_payload: dict[str, Any], *, secret_values: tuple[str, ...] = ()) -> None:
    privacy_scan_text(
        "events",
        json.dumps(events_payload, sort_keys=True),
        secret_values=secret_values,
        bundle_mode=False,
    )
