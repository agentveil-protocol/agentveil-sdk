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
CONTEXT_VERSION_V2 = "2"
SUPPORTED_CONTEXT_VERSIONS = frozenset({CONTEXT_VERSION, CONTEXT_VERSION_V2})
_PATHS = {
    "preflight": "/v1/controlled-alternatives/hybrid/preflight",
    "decide": "/v1/controlled-alternatives/hybrid/decide",
    "runtime_status": "/v1/controlled-alternatives/hybrid/runtime-status",
}
_AV02_PATHS = {
    "register": "/v1/controlled-alternatives/av02/runtime/register",
    "evaluate": "/v1/controlled-alternatives/av02/policy/evaluate",
}
_DECISION_KEY_PATH_PREFIX = (
    "/v1/controlled-alternatives/av02/decision-verification-keys/"
)
_DECISION_KEY_RESPONSE_KEYS = frozenset({
    "schema_version",
    "issuer_key_id",
    "algorithm",
    "key_role",
    "public_key_hex",
    "status",
})
_ISSUER_KEY_ID = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_KEY_HEX = re.compile(r"^[0-9a-f]{64}$")
_BOUNDED_EXCHANGE_METHODS = frozenset({"GET", "POST"})
_FIELDS = frozenset({
    "contract_version", "profile_id", "alternative_id", "operation_ref",
    "action_family", "semantic_category", "invocation_phase", "basename_hash",
})
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_CONSOLE_CREDENTIAL = re.compile(r"[A-Za-z0-9._~-]{20,128}\Z")
_OBSERVED_AT = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z"
)
CONSOLE_CREDENTIAL_HEADER = "X-AgentVeil-Console-Credential"
RUNTIME_BINDING_HEADER = "X-AVP-CA-Runtime-Binding"
CONSOLE_ORIGIN = "https://agentveil.dev"
_REGISTER_KEYS = frozenset({
    "schema_version",
    "runtime_version",
    "contract_range",
    "catalog_digest",
    "declared_executor_capabilities",
})
_EVALUATE_KEYS = frozenset({
    "schema_version",
    "runtime_installation_id",
    "operation_nonce",
    "phase",
    "action_family",
    "target_class",
    "requested_executor_capability",
    "policy_context",
})
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_AV02_SHORT_TOKEN = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
_BINDING = re.compile(r"[A-Za-z0-9._~-]{20,128}\Z")
_MAX_RESPONSE = 16384
_REQUEST_DEADLINE_SECONDS = 5.0
_MAX_WORKER_INPUT = 8192


def _exchange(
    url: str,
    headers: Mapping[str, str],
    body: str,
    *,
    method: str = "POST",
) -> tuple[int, Mapping[str, Any]]:
    """Network-only worker. The parent bounds DNS, I/O and worker lifetime."""
    import httpx

    content = body.encode() if method == "POST" and body else None
    with httpx.Client(timeout=_REQUEST_DEADLINE_SECONDS, follow_redirects=False) as client:
        with client.stream(method, url, headers=headers, content=content) as response:
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


def _run_bounded_exchange(
    url: str,
    headers: Mapping[str, str],
    body: str,
    *,
    method: str = "POST",
) -> tuple[int, Mapping[str, Any]]:
    if method not in _BOUNDED_EXCHANGE_METHODS:
        return 400, {}
    data = json.dumps({
        "url": url,
        "headers": dict(headers),
        "body": body,
        "method": method,
    }).encode()
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
            method = request.get("method", "POST")
            if method not in _BOUNDED_EXCHANGE_METHODS:
                result = (400, {})
            else:
                result = _exchange(
                    request["url"],
                    request["headers"],
                    request["body"],
                    method=method,
                )
    except Exception:
        result = (503, {})
    sys.stdout.write(json.dumps(result))


@dataclass(frozen=True)
class ControlledAlternativeRuntimeContext:
    """Local context supplied by the proxy; transport availability is not authority."""

    request: Callable[[str, Mapping[str, str]], tuple[int, Mapping[str, Any]]] = field(repr=False)
    state_root: str = field(repr=False)
    contract_version: str = CONTEXT_VERSION
    heartbeat: Callable[[str, str], tuple[int, Mapping[str, Any]]] | None = field(
        default=None,
        repr=False,
    )
    runtime_register: Callable[[Mapping[str, Any]], tuple[int, Mapping[str, Any]]] | None = field(
        default=None,
        repr=False,
    )
    policy_evaluate: Callable[[Mapping[str, Any]], tuple[int, Mapping[str, Any]]] | None = field(
        default=None,
        repr=False,
    )
    resolve_decision_verification_key: Callable[[str], Mapping[str, Any] | None] | None = field(
        default=None,
        repr=False,
    )


def bind_installed_runtime_context(instance: Any, context: Any) -> Any:
    """Opt-in object protocol; existing providers retain their original behavior."""
    if context is None:
        return instance
    if (
        not isinstance(context, ControlledAlternativeRuntimeContext)
        or context.contract_version not in SUPPORTED_CONTEXT_VERSIONS
    ):
        raise ValueError("ca_runtime_context_invalid")
    bind = getattr(instance, "bind_runtime_context", None)
    return bind(context) if callable(bind) else instance


def _validate_register_payload(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    if set(payload) != _REGISTER_KEYS:
        return None
    if payload.get("schema_version") != "runtime/register/1":
        return None
    for key in ("runtime_version", "contract_range"):
        value = payload.get(key)
        if not isinstance(value, str) or not _AV02_SHORT_TOKEN.fullmatch(value):
            return None
    digest = payload.get("catalog_digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        return None
    capabilities = payload.get("declared_executor_capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        return None
    seen: set[str] = set()
    cleaned: list[str] = []
    for item in capabilities:
        if not isinstance(item, str) or not _CAPABILITY.fullmatch(item):
            return None
        if item in seen:
            return None
        seen.add(item)
        cleaned.append(item)
    return {
        "schema_version": "runtime/register/1",
        "runtime_version": payload["runtime_version"],
        "contract_range": payload["contract_range"],
        "catalog_digest": payload["catalog_digest"],
        "declared_executor_capabilities": cleaned,
    }


def _validate_policy_context(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    keys = frozenset(value.keys())
    expected = frozenset({
        "contains_secret_like_value",
        "destructive_shell_pattern",
        "write_then_execute_risk",
        "credential_exfil_pattern",
        "signal_producer_health",
    })
    if keys != expected:
        return None
    health = value.get("signal_producer_health")
    if health not in {"healthy", "unavailable", "malformed", "unsupported"}:
        return None
    normalized: dict[str, Any] = {"signal_producer_health": health}
    for key in expected - {"signal_producer_health"}:
        item = value.get(key)
        if item is True or item is False or item == "unavailable":
            normalized[key] = item
        else:
            return None
    if health != "healthy" and any(
        normalized[key] != "unavailable"
        for key in expected - {"signal_producer_health"}
    ):
        return None
    return normalized


def _validate_evaluate_payload(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    keys = set(payload)
    if "execute_handle" in keys:
        if keys != _EVALUATE_KEYS | {"execute_handle"}:
            return None
    elif keys != _EVALUATE_KEYS:
        return None
    if payload.get("schema_version") != "policy/evaluate/1":
        return None
    runtime_id = payload.get("runtime_installation_id")
    if not isinstance(runtime_id, str) or not _UUID.fullmatch(runtime_id):
        return None
    nonce = payload.get("operation_nonce")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        return None
    phase = payload.get("phase")
    if phase not in {"propose", "execute", "verify"}:
        return None
    action_family = payload.get("action_family")
    if action_family not in {"filesystem", "shell", "git"}:
        return None
    target_class = payload.get("target_class")
    if target_class not in {"file", "directory", "repository", "process"}:
        return None
    capability = payload.get("requested_executor_capability")
    if not isinstance(capability, str) or not _CAPABILITY.fullmatch(capability):
        return None
    policy_context = _validate_policy_context(payload.get("policy_context"))
    if policy_context is None:
        return None
    execute_handle = payload.get("execute_handle")
    if execute_handle is not None:
        if phase != "execute":
            return None
        if not isinstance(execute_handle, str) or not _NONCE.fullmatch(execute_handle):
            return None
    body = {
        "schema_version": "policy/evaluate/1",
        "runtime_installation_id": runtime_id,
        "operation_nonce": nonce,
        "phase": phase,
        "action_family": action_family,
        "target_class": target_class,
        "requested_executor_capability": capability,
        "policy_context": policy_context,
    }
    if execute_handle is not None:
        body["execute_handle"] = execute_handle
    return body


def _validate_decision_verification_key_response(
    payload: Mapping[str, Any],
    *,
    issuer_key_id: str,
) -> dict[str, str] | None:
    if set(payload) != _DECISION_KEY_RESPONSE_KEYS:
        return None
    if payload.get("schema_version") != "av02-decision-verification-key/1":
        return None
    if payload.get("algorithm") != "Ed25519":
        return None
    if payload.get("key_role") != "controlled_alternatives_decision":
        return None
    if payload.get("status") != "active":
        return None
    response_id = payload.get("issuer_key_id")
    public_key_hex = payload.get("public_key_hex")
    if not isinstance(response_id, str) or response_id != issuer_key_id:
        return None
    if not isinstance(public_key_hex, str) or not _PUBLIC_KEY_HEX.fullmatch(public_key_hex):
        return None
    if public_key_hex != issuer_key_id:
        return None
    return {
        "schema_version": "av02-decision-verification-key/1",
        "issuer_key_id": response_id,
        "algorithm": "Ed25519",
        "key_role": "controlled_alternatives_decision",
        "public_key_hex": public_key_hex,
        "status": "active",
    }


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
            return _run_bounded_exchange(CONSOLE_ORIGIN + path, headers, body.decode())
        except Exception:
            return 503, {}

    from agentveil_mcp_proxy.console_credentials import (
        console_credential_home_for_runtime,
        load_runtime_binding_credential,
    )

    credential_home = console_credential_home_for_runtime(state_root)

    def _binding_token() -> str | None:
        try:
            stored = load_runtime_binding_credential(home=credential_home)
        except Exception:
            return None
        if stored is None:
            return None
        token = stored.token
        if not _BINDING.fullmatch(token):
            return None
        return token

    def _av02_exchange(
        operation: str,
        payload: Mapping[str, Any],
    ) -> tuple[int, Mapping[str, Any]]:
        try:
            from agentveil.auth import build_auth_header

            if operation not in _AV02_PATHS or not isinstance(payload, Mapping):
                return 400, {}
            if operation == "register":
                normalized = _validate_register_payload(payload)
            else:
                normalized = _validate_evaluate_payload(payload)
            if normalized is None:
                return 400, {}
            binding = _binding_token()
            if binding is None:
                return 401, {}
            body = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
            path = _AV02_PATHS[operation]
            headers = build_auth_header(key, did, "POST", path, body, force_v2=True)
            headers[RUNTIME_BINDING_HEADER] = binding
            headers["Accept-Encoding"] = "identity"
            return _run_bounded_exchange(CONSOLE_ORIGIN + path, headers, body.decode())
        except Exception:
            return 503, {}

    def runtime_register(payload: Mapping[str, Any]) -> tuple[int, Mapping[str, Any]]:
        return _av02_exchange("register", payload)

    def policy_evaluate(payload: Mapping[str, Any]) -> tuple[int, Mapping[str, Any]]:
        return _av02_exchange("evaluate", payload)

    def resolve_decision_verification_key(issuer_key_id: str) -> Mapping[str, Any] | None:
        try:
            from agentveil.auth import build_auth_header

            if not isinstance(issuer_key_id, str) or not _ISSUER_KEY_ID.fullmatch(issuer_key_id):
                return None
            binding = _binding_token()
            if binding is None:
                return None
            path = f"{_DECISION_KEY_PATH_PREFIX}{issuer_key_id}"
            body = b""
            headers = build_auth_header(key, did, "GET", path, body, force_v2=True)
            headers[RUNTIME_BINDING_HEADER] = binding
            headers["Accept-Encoding"] = "identity"
            headers.pop("Content-Type", None)
            status, payload = _run_bounded_exchange(
                CONSOLE_ORIGIN + path,
                headers,
                "",
                method="GET",
            )
            if status != 200 or not isinstance(payload, Mapping):
                return None
            return _validate_decision_verification_key_response(
                payload,
                issuer_key_id=issuer_key_id,
            )
        except Exception:
            return None

    def heartbeat(
        console_credential: str,
        observed_at: str,
    ) -> tuple[int, Mapping[str, Any]]:
        try:
            from agentveil.auth import build_auth_header

            if not isinstance(console_credential, str) or not _CONSOLE_CREDENTIAL.fullmatch(
                console_credential
            ):
                return 400, {}
            if not isinstance(observed_at, str) or not _OBSERVED_AT.fullmatch(observed_at):
                return 400, {}
            body = json.dumps(
                {
                    "schema_version": "1",
                    "status": "active",
                    "observed_at": observed_at,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            path = _PATHS["runtime_status"]
            headers = build_auth_header(key, did, "POST", path, body)
            headers[CONSOLE_CREDENTIAL_HEADER] = console_credential
            headers["Accept-Encoding"] = "identity"
            return _run_bounded_exchange(base_url.rstrip("/") + path, headers, body.decode())
        except Exception:
            return 503, {}

    hosted = url.scheme == "https" and url.netloc == "agentveil.dev"
    binding_ready = hosted and _binding_token() is not None
    if binding_ready:
        return ControlledAlternativeRuntimeContext(
            request=request,
            state_root=str(state_root),
            contract_version=CONTEXT_VERSION_V2,
            heartbeat=heartbeat,
            runtime_register=runtime_register,
            policy_evaluate=policy_evaluate,
            resolve_decision_verification_key=resolve_decision_verification_key,
        )
    return ControlledAlternativeRuntimeContext(
        request=request,
        state_root=str(state_root),
        contract_version=CONTEXT_VERSION,
        heartbeat=heartbeat if hosted else None,
    )


if __name__ == "__main__":
    _worker_main()
