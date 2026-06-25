"""Stable local Approval Center lifecycle helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from agentveil_mcp_proxy.approval.server import ApprovalServer, ApprovalServerError


MANIFEST_FILENAME = "approval-center.manifest.json"
MANIFEST_SCHEMA_VERSION = 2
HEALTH_TIMEOUT_SECONDS = 2.0
IS_WINDOWS = os.name == "nt"


class PersistentApprovalCenterError(RuntimeError):
    """Raised when the stable Approval Center cannot start or be reused."""


@dataclass(frozen=True)
class ApprovalCenterManifest:
    """On-disk metadata for one stable local Approval Center."""

    schema_version: int
    host: str
    port: int
    session_token: str
    token_hash: str
    internal_register_token: str
    pid: int | None
    started_at: int

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def approval_center_url(self) -> str:
        return f"{self.base_url}/approval/{self.session_token}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "host": self.host,
            "port": self.port,
            "session_token": self.session_token,
            "token_hash": self.token_hash,
            "internal_register_token": self.internal_register_token,
            "pid": self.pid,
            "started_at": self.started_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalCenterManifest:
        return cls(
            schema_version=int(data["schema_version"]),
            host=str(data["host"]),
            port=int(data["port"]),
            session_token=str(data["session_token"]),
            token_hash=str(data["token_hash"]),
            internal_register_token=str(data["internal_register_token"]),
            pid=None if data.get("pid") is None else int(data["pid"]),
            started_at=int(data["started_at"]),
        )


def manifest_path(proxy_dir: Path) -> Path:
    return proxy_dir / MANIFEST_FILENAME


def token_hash_for(session_token: str) -> str:
    return "sha256:" + hashlib.sha256(session_token.encode("utf-8")).hexdigest()


def load_manifest(proxy_dir: Path) -> ApprovalCenterManifest | None:
    path = manifest_path(proxy_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        manifest = ApprovalCenterManifest.from_dict(data)
    except (KeyError, TypeError, ValueError):
        return None
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION:
        return None
    return manifest


def save_manifest(proxy_dir: Path, manifest: ApprovalCenterManifest) -> None:
    path = manifest_path(proxy_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    payload = json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(payload)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def is_process_alive(pid: int | None) -> bool:
    if pid is None or pid <= 0:
        return False
    if IS_WINDOWS:
        return _windows_process_alive(pid)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _windows_process_alive(pid: int) -> bool:
    if pid == os.getpid():
        return True
    try:
        import ctypes
    except ImportError:
        return False

    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x00100000, False, int(pid))
    except (AttributeError, OSError, TypeError, ValueError):
        return False
    if not handle:
        return False
    try:
        wait_timeout = 0x00000102
        return kernel32.WaitForSingleObject(handle, 0) == wait_timeout
    finally:
        kernel32.CloseHandle(handle)


def _health_check(manifest: ApprovalCenterManifest) -> bool:
    try:
        return (
            loopback_get_status(
                manifest.approval_center_url(),
                timeout=HEALTH_TIMEOUT_SECONDS,
            )
            == 200
        )
    except (OSError, TimeoutError, ValueError):
        return False


def loopback_get_status(
    url: str,
    *,
    timeout: float,
) -> int:
    """Fetch loopback Approval Center status without HTTP proxy stacks."""

    status, _body = loopback_http_request("GET", url, timeout=timeout)
    return status


def loopback_json_post(
    url: str,
    *,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: float,
) -> dict[str, Any]:
    """POST JSON to the loopback Approval Center without HTTP proxy stacks."""

    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    status, response_body = loopback_http_request(
        "POST",
        url,
        headers=request_headers,
        body=body,
        timeout=timeout,
    )
    if status >= 400:
        raise OSError(f"loopback Approval Center returned HTTP {status}")
    parsed = json.loads(response_body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("loopback Approval Center returned non-object JSON")
    return parsed


def loopback_http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    timeout: float,
) -> tuple[int, bytes]:
    """Make a minimal HTTP/1.1 request to 127.0.0.1 with bounded reads."""

    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise ValueError("loopback Approval Center URL must be http://127.0.0.1")
    port = parsed.port
    if port is None:
        raise ValueError("loopback Approval Center URL must include a port")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    request_headers = {
        "Host": f"127.0.0.1:{port}",
        "Connection": "close",
    }
    if body:
        request_headers["Content-Length"] = str(len(body))
    if headers:
        request_headers.update(headers)
    header_lines = [f"{method} {path} HTTP/1.1"]
    header_lines.extend(f"{key}: {value}" for key, value in request_headers.items())
    request = ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii") + body
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        response = _read_http_response(sock)
    return _parse_http_response(response)


def _read_http_response(sock: socket.socket) -> bytes:
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    headers, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        raise OSError("loopback Approval Center returned incomplete HTTP headers")
    content_length = _content_length_from_headers(headers)
    while len(body) < content_length:
        chunk = sock.recv(min(4096, content_length - len(body)))
        if not chunk:
            raise OSError("loopback Approval Center returned incomplete HTTP body")
        body += chunk
    return headers + separator + body[:content_length]


def _content_length_from_headers(headers: bytes) -> int:
    for raw_line in headers.splitlines()[1:]:
        name, separator, value = raw_line.partition(b":")
        if separator and name.strip().lower() == b"content-length":
            return int(value.strip())
    raise OSError("loopback Approval Center response missing Content-Length")


def _parse_http_response(response: bytes) -> tuple[int, bytes]:
    headers, _separator, body = response.partition(b"\r\n\r\n")
    status_line = headers.splitlines()[0].decode("ascii", errors="replace")
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise OSError("loopback Approval Center returned invalid status line")
    return int(parts[1]), body


def manifest_is_reachable(manifest: ApprovalCenterManifest) -> bool:
    return _health_check(manifest)


def build_manifest_for_server(server: ApprovalServer) -> ApprovalCenterManifest:
    if not server.is_running:
        raise PersistentApprovalCenterError("approval server is not started")
    if not server.internal_register_token:
        raise PersistentApprovalCenterError(
            "persistent approval center missing internal register token"
        )
    return ApprovalCenterManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        host=server.host,
        port=server.port,
        session_token=server.session_token,
        token_hash=server.token_hash,
        internal_register_token=server.internal_register_token or "",
        pid=os.getpid(),
        started_at=int(time.time()),
    )


def create_persistent_server(
    *,
    proxy_dir: Path,
    evidence_store: Any,
    port: int = 0,
    session_token: str | None = None,
) -> ApprovalServer:
    """Create one ApprovalServer using persisted port/token when available."""

    manifest = load_manifest(proxy_dir)
    resolved_port = port
    resolved_token = session_token
    resolved_internal_token = secrets.token_urlsafe(32)
    if manifest is not None and port == 0:
        resolved_port = manifest.port
    if manifest is not None and session_token is None:
        resolved_token = manifest.session_token
    if manifest is not None and manifest.internal_register_token:
        resolved_internal_token = manifest.internal_register_token
    server = ApprovalServer(
        port=resolved_port,
        session_token=resolved_token,
        internal_register_token=resolved_internal_token,
        evidence_store=evidence_store,
    )
    try:
        server.start()
    except OSError as exc:
        raise PersistentApprovalCenterError(
            f"approval center could not bind to 127.0.0.1:{resolved_port}"
        ) from exc
    return server


__all__ = [
    "ApprovalCenterManifest",
    "PersistentApprovalCenterError",
    "build_manifest_for_server",
    "create_persistent_server",
    "load_manifest",
    "loopback_http_request",
    "loopback_json_post",
    "loopback_get_status",
    "manifest_is_reachable",
    "manifest_path",
    "save_manifest",
]
