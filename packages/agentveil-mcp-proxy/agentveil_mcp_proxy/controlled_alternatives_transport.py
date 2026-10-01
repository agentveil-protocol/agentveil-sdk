# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Per-proxy signed CA transport; no credential discovery or authority claims."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat as stat_mod
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


_AV02_RUNTIME_STATE_SCHEMA = "av02-runtime-state/1"
_AV02_STATE_FILENAME = "av02-runtime-state.json"
_AV02_STATE_REL = "controlled-alternatives"
_AV02_STATE_MAX_BYTES = 4096
_AV02_DECLARED_EXECUTOR_CAPABILITIES = (
    "filesystem.stage_delete.v1",
    "filesystem.restore_staged.v1",
    "filesystem.cleanup_staged.v1",
    "protected_write.prepare_patch.v1",
    "git.prepare_local_change.v1",
    "protected_write.apply_prepared_patch.v1",
)


def _av02_registration_fingerprint() -> str:
    canonical = {
        "runtime_version": "1.0.0",
        "contract_range": "av02.v1",
        "catalog_digest": "aa" * 32,
        "declared_executor_capabilities": list(_AV02_DECLARED_EXECUTOR_CAPABILITIES),
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _coerce_av02_runtime_state(raw: object) -> str | None:
    if not isinstance(raw, dict):
        return None
    if raw.get("schema_version") != _AV02_RUNTIME_STATE_SCHEMA:
        return None
    runtime_id = raw.get("runtime_installation_id")
    fingerprint = raw.get("registration_fingerprint")
    if not isinstance(runtime_id, str) or not _UUID.fullmatch(runtime_id):
        return None
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        return None
    if fingerprint != _av02_registration_fingerprint():
        return None
    return runtime_id


def read_cached_av02_runtime_installation_id(state_root: Path) -> str | None:
    """Recover a validated thin opaque runtime id from the scoped state root only."""

    directory = state_root / _AV02_STATE_REL
    path = directory / _AV02_STATE_FILENAME
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if stat_mod.S_ISLNK(st.st_mode) or not stat_mod.S_ISREG(st.st_mode):
        return None
    if st.st_nlink > 1:
        return None
    if sys.platform != "win32" and st.st_uid not in {0, os.getuid()}:
        return None
    if sys.platform != "win32" and (st.st_mode & 0o077):
        return None
    if st.st_size > _AV02_STATE_MAX_BYTES:
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        raw = os.read(fd, _AV02_STATE_MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if len(raw) > _AV02_STATE_MAX_BYTES:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError):
        return None
    return _coerce_av02_runtime_state(parsed)


def build_controlled_alternative_context(
    *,
    agent: Any,
    base_url: str,
    state_root: Path,
    summary_token: str | None = None,
    canonical_project_root: Path | None = None,
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

    def _hosted_execution_quarantined() -> bool:
        if url.scheme != "https" or url.netloc != "agentveil.dev":
            return False
        if binding_resolution["malformed"]:
            return True
        if _opt_in_blocks_legacy() and _binding_token() is None:
            return True
        if pinned_summary_fingerprint is not None and _binding_token() is None:
            return True
        return False

    def request(operation: str, payload: Mapping[str, str]) -> tuple[int, Mapping[str, Any]]:
        if pinned_summary_fingerprint is not None and not _sync_live_scoped_custody():
            return 401, {}
        if _hosted_execution_quarantined():
            return 401, {}
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
        CredentialError,
        _scoped_opt_in_blocks_legacy,
        console_credential_home_for_runtime,
        load_credential,
        load_runtime_binding_credential,
        load_scoped_runtime_binding_credential,
        resolve_runtime_binding_for_context,
        scoped_runtime_binding_namespace_hash,
        summary_token_fingerprint,
    )
    from agentveil_mcp_proxy.console_project_status_client import (
        build_client_installation_ref,
    )
    from agentveil_mcp_proxy.control_artifacts import (
        ControlArtifactError,
        ensure_control_directory,
    )

    credential_home = console_credential_home_for_runtime(state_root)

    def _opt_in_blocks_legacy() -> bool:
        return _scoped_opt_in_blocks_legacy(did, home=credential_home)

    summary_source = summary_token
    if summary_source is None:
        try:
            summary = load_credential(home=credential_home)
        except Exception:
            summary = None
        summary_source = None if summary is None else summary.token

    binding_resolution: dict[str, object | None] = {
        "token": None,
        "scoped": False,
        "malformed": False,
    }
    pinned_summary_fingerprint: str | None = None

    def _binding_token() -> str | None:
        if binding_resolution["malformed"]:
            return None
        token = binding_resolution["token"]
        if not isinstance(token, str):
            return None
        if not _BINDING.fullmatch(token):
            return None
        return token

    def _apply_binding_resolution(
        summary_token: str,
        *,
        stored_token: str | None,
        scoped_ready: bool,
    ) -> None:
        if binding_resolution["malformed"]:
            binding_resolution["token"] = None
            binding_resolution["scoped"] = False
            return
        binding_resolution["token"] = stored_token
        binding_resolution["scoped"] = scoped_ready

    def _resolve_binding_for_summary(summary_token: str) -> None:
        try:
            stored = resolve_runtime_binding_for_context(
                did,
                summary_token,
                state_root,
            )
        except CredentialError:
            binding_resolution["malformed"] = True
            binding_resolution["token"] = None
            binding_resolution["scoped"] = False
            return
        except Exception:
            binding_resolution["malformed"] = True
            binding_resolution["token"] = None
            binding_resolution["scoped"] = False
            return
        scoped_ready = False
        if stored is not None:
            try:
                scoped_ready = (
                    load_scoped_runtime_binding_credential(
                        did,
                        summary_token,
                        home=state_root,
                    )
                    is not None
                )
            except Exception:
                binding_resolution["malformed"] = True
                scoped_ready = False
        elif _opt_in_blocks_legacy():
            binding_resolution["malformed"] = True
        _apply_binding_resolution(
            summary_token,
            stored_token=None if stored is None else stored.token,
            scoped_ready=scoped_ready,
        )

    def _resolve_legacy_binding_without_summary() -> None:
        if _opt_in_blocks_legacy():
            binding_resolution["malformed"] = True
            binding_resolution["token"] = None
            binding_resolution["scoped"] = False
            return
        try:
            stored = load_runtime_binding_credential(home=credential_home)
        except CredentialError:
            binding_resolution["malformed"] = True
            binding_resolution["token"] = None
            binding_resolution["scoped"] = False
            return
        except Exception:
            binding_resolution["malformed"] = True
            binding_resolution["token"] = None
            binding_resolution["scoped"] = False
            return
        token = None if stored is None else stored.token
        if isinstance(token, str) and not _BINDING.fullmatch(token):
            token = None
        binding_resolution["token"] = token
        binding_resolution["scoped"] = False

    if summary_source is not None:
        _resolve_binding_for_summary(summary_source)
        if binding_resolution["scoped"] is True and summary_source is not None:
            pinned_summary_fingerprint = summary_token_fingerprint(summary_source)
    else:
        _resolve_legacy_binding_without_summary()

    effective_state_root = state_root
    if binding_resolution["scoped"] is True and summary_source is not None:
        namespace = scoped_runtime_binding_namespace_hash(did, summary_source)
        scoped_root = state_root / f"ca-agent-{namespace[:32]}"
        try:
            ensure_control_directory(scoped_root)
        except ControlArtifactError:
            return None
        effective_state_root = scoped_root

    client_installation_ref: str | None = None
    if canonical_project_root is not None:
        client_installation_ref = build_client_installation_ref(
            canonical_project_root=canonical_project_root,
            agent_did=did,
        )
    runtime_installation_id: dict[str, str | None] = {
        "value": read_cached_av02_runtime_installation_id(effective_state_root),
    }

    def _sync_live_scoped_custody() -> bool:
        nonlocal pinned_summary_fingerprint
        if pinned_summary_fingerprint is None:
            return not binding_resolution["malformed"]
        try:
            summary = load_credential(home=credential_home)
        except CredentialError:
            binding_resolution["malformed"] = True
            binding_resolution["token"] = None
            return False
        except Exception:
            binding_resolution["malformed"] = True
            binding_resolution["token"] = None
            return False
        if summary is None:
            binding_resolution["token"] = None
            return False
        try:
            current_fp = summary_token_fingerprint(summary.token)
        except CredentialError:
            binding_resolution["malformed"] = True
            binding_resolution["token"] = None
            return False
        if current_fp != pinned_summary_fingerprint:
            binding_resolution["malformed"] = True
            binding_resolution["token"] = None
            return False
        _resolve_binding_for_summary(summary.token)
        return _binding_token() is not None and not binding_resolution["malformed"]

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
            if not _sync_live_scoped_custody():
                return 401, {}
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
        status, response = _av02_exchange("register", payload)
        if status == 200 and isinstance(response, Mapping):
            runtime_id = response.get("runtime_installation_id")
            if isinstance(runtime_id, str) and _UUID.fullmatch(runtime_id):
                runtime_installation_id["value"] = runtime_id
        return status, response

    def policy_evaluate(payload: Mapping[str, Any]) -> tuple[int, Mapping[str, Any]]:
        return _av02_exchange("evaluate", payload)

    def resolve_decision_verification_key(issuer_key_id: str) -> Mapping[str, Any] | None:
        try:
            from agentveil.auth import build_auth_header

            if not isinstance(issuer_key_id, str) or not _ISSUER_KEY_ID.fullmatch(issuer_key_id):
                return None
            if not _sync_live_scoped_custody():
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

            if not isinstance(observed_at, str) or not _OBSERVED_AT.fullmatch(observed_at):
                return 400, {}
            if binding_resolution["malformed"]:
                return 401, {}
            if pinned_summary_fingerprint is not None:
                if not _sync_live_scoped_custody():
                    return 401, {}
                try:
                    summary = load_credential(home=credential_home)
                except Exception:
                    return 401, {}
                if summary is None or summary.token != console_credential:
                    return 401, {}
            elif not isinstance(console_credential, str) or not _CONSOLE_CREDENTIAL.fullmatch(
                console_credential
            ):
                return 400, {}
            path = _PATHS["runtime_status"]
            scoped_active = binding_resolution["scoped"] is True
            use_schema_v2 = (
                scoped_active
                and runtime_installation_id["value"] is not None
                and client_installation_ref is not None
            )
            if scoped_active and not use_schema_v2:
                return 401, {}
            if _opt_in_blocks_legacy() and not use_schema_v2:
                return 401, {}
            if use_schema_v2:
                binding = _binding_token()
                if binding is None:
                    return 401, {}
                body = json.dumps(
                    {
                        "schema_version": "2",
                        "status": "active",
                        "observed_at": observed_at,
                        "runtime_installation_id": runtime_installation_id["value"],
                        "client_installation_ref": client_installation_ref,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                headers = build_auth_header(key, did, "POST", path, body, force_v2=True)
                headers[CONSOLE_CREDENTIAL_HEADER] = console_credential
                headers[RUNTIME_BINDING_HEADER] = binding
            else:
                body = json.dumps(
                    {
                        "schema_version": "1",
                        "status": "active",
                        "observed_at": observed_at,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                headers = build_auth_header(key, did, "POST", path, body)
                headers[CONSOLE_CREDENTIAL_HEADER] = console_credential
            headers["Accept-Encoding"] = "identity"
            return _run_bounded_exchange(base_url.rstrip("/") + path, headers, body.decode())
        except Exception:
            return 503, {}

    hosted = url.scheme == "https" and url.netloc == "agentveil.dev"
    if _hosted_execution_quarantined():
        return ControlledAlternativeRuntimeContext(
            request=request,
            state_root=str(effective_state_root),
            contract_version=CONTEXT_VERSION_V2,
            heartbeat=heartbeat if hosted else None,
        )
    binding_ready = hosted and _binding_token() is not None and not binding_resolution["malformed"]
    if binding_ready:
        return ControlledAlternativeRuntimeContext(
            request=request,
            state_root=str(effective_state_root),
            contract_version=CONTEXT_VERSION_V2,
            heartbeat=heartbeat,
            runtime_register=runtime_register,
            policy_evaluate=policy_evaluate,
            resolve_decision_verification_key=resolve_decision_verification_key,
        )
    return ControlledAlternativeRuntimeContext(
        request=request,
        state_root=str(effective_state_root),
        contract_version=CONTEXT_VERSION,
        heartbeat=heartbeat if hosted else None,
    )


if __name__ == "__main__":
    _worker_main()
