"""Stable local Approval Center lifecycle helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from agentveil_mcp_proxy.approval.server import ApprovalServer, ApprovalServerError


MANIFEST_FILENAME = "approval-center.manifest.json"
MANIFEST_SCHEMA_VERSION = 2
HEALTH_TIMEOUT_SECONDS = 2.0


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
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _health_check(manifest: ApprovalCenterManifest) -> bool:
    url = f"{manifest.approval_center_url()}/api/approvals"
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=HEALTH_TIMEOUT_SECONDS) as response:
            return int(response.status) == 200
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


def manifest_is_reachable(manifest: ApprovalCenterManifest) -> bool:
    if not is_process_alive(manifest.pid):
        return False
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
    "manifest_is_reachable",
    "manifest_path",
    "save_manifest",
]
