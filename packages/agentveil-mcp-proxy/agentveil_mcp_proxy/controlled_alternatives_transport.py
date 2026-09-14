# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Per-proxy signed CA transport; no credential discovery or authority claims."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

CONTEXT_VERSION = "1"
_PATHS = {
    "preflight": "/v1/controlled-alternatives/hybrid/preflight",
    "decide": "/v1/controlled-alternatives/hybrid/decide",
}
_FIELDS = frozenset({
    "contract_version", "profile_id", "alternative_id", "operation_ref",
    "action_family", "semantic_category", "invocation_phase", "basename_hash",
})
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_MAX_RESPONSE = 16384
_REQUEST_DEADLINE_SECONDS = 5.0
_MAX_WORKER_INPUT = 8192


def _exchange(url: str, headers: Mapping[str, str], body: str) -> tuple[int, Mapping[str, Any]]:
    """Network-only worker. The parent bounds DNS, I/O and worker lifetime."""
    import httpx

    with httpx.Client(timeout=_REQUEST_DEADLINE_SECONDS, follow_redirects=False) as client:
        with client.stream("POST", url, headers=headers, content=body.encode()) as response:
            if response.status_code != 200:
                return response.status_code, {}
            if response.headers.get("Content-Encoding", "identity").strip().lower() != "identity":
                return 502, {}
            chunks = bytearray()
            for chunk in response.iter_raw():
                if len(chunk) > _MAX_RESPONSE - len(chunks):
                    return 502, {}
                chunks.extend(chunk)
            result = json.loads(chunks)
            return (200, result) if isinstance(result, dict) else (502, {})


def _run_bounded_exchange(url: str, headers: Mapping[str, str], body: str) -> tuple[int, Mapping[str, Any]]:
    data = json.dumps({"url": url, "headers": dict(headers), "body": body}).encode()
    if len(data) > _MAX_WORKER_INPUT:
        return 400, {}
    deadline = time.monotonic() + _REQUEST_DEADLINE_SECONDS
    # Only a single-use signed header crosses this pipe, not the signing key.
    # Execute this exact installed module; -I avoids user Python startup/path hooks.
    process = subprocess.Popen(
        [sys.executable, "-I", str(Path(__file__).resolve())],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 503, {}
        output, _ = process.communicate(data, timeout=remaining)
        if process.returncode != 0 or len(output) > 6 * _MAX_RESPONSE + 1024:
            return 503, {}
        status, payload = json.loads(output)
        if type(status) is not int or not isinstance(payload, dict):
            return 503, {}
        return status, payload
    except (subprocess.TimeoutExpired, ValueError, TypeError):
        return 503, {}
    finally:
        if process.poll() is None:
            process.kill()
        # Reap the owned process and close its pipes even on caller cancellation.
        process.communicate()


def _worker_main() -> None:
    try:
        data = sys.stdin.buffer.read(_MAX_WORKER_INPUT + 1)
        if len(data) > _MAX_WORKER_INPUT:
            result = (400, {})
        else:
            request = json.loads(data)
            result = _exchange(request["url"], request["headers"], request["body"])
    except Exception:
        result = (503, {})
    sys.stdout.write(json.dumps(result))


@dataclass(frozen=True)
class ControlledAlternativeRuntimeContext:
    """Local context supplied by the proxy; transport availability is not authority."""

    request: Callable[[str, Mapping[str, str]], tuple[int, Mapping[str, Any]]] = field(repr=False)
    state_root: str = field(repr=False)
    contract_version: str = CONTEXT_VERSION


def bind_installed_runtime_context(instance: Any, context: Any) -> Any:
    """Opt-in object protocol; existing providers retain their original behavior."""
    if context is None:
        return instance
    if not isinstance(context, ControlledAlternativeRuntimeContext) or context.contract_version != CONTEXT_VERSION:
        raise ValueError("ca_runtime_context_invalid")
    bind = getattr(instance, "bind_runtime_context", None)
    return bind(context) if callable(bind) else instance


def build_controlled_alternative_context(
    *, agent: Any, base_url: str, state_root: Path,
) -> ControlledAlternativeRuntimeContext | None:
    """Use an already loaded identity. Do not register, read keys, or send at startup."""
    try:
        url = urlsplit(base_url)
        if (
            url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in {"", "/"}
        ):
            return None
        key = bytes.fromhex(agent.private_key_hex)
        did = agent.did
        if len(key) != 32 or not isinstance(did, str) or not did.startswith("did:key:"):
            return None
    except (AttributeError, TypeError, ValueError):
        return None

    def request(operation: str, payload: Mapping[str, str]) -> tuple[int, Mapping[str, Any]]:
        try:
            from agentveil.auth import build_auth_header

            if operation not in _PATHS or not isinstance(payload, Mapping):
                return 400, {}
            if operation == "preflight":
                if payload:
                    return 400, {}
                body = b""
            else:
                if set(payload) != _FIELDS or any(
                    not isinstance(v, str) or not _TOKEN.fullmatch(v) for v in payload.values()
                ):
                    return 400, {}
                body = json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode()
            path = _PATHS[operation]
            headers = build_auth_header(key, did, "POST", path, body)
            headers["Accept-Encoding"] = "identity"
            return _run_bounded_exchange(base_url.rstrip("/") + path, headers, body.decode())
        except Exception:
            return 503, {}

    return ControlledAlternativeRuntimeContext(request=request, state_root=str(state_root))


if __name__ == "__main__":
    _worker_main()
