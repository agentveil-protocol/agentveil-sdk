# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Fixed-origin AV-02 per-agent runtime binding issuance client."""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import urlsplit

from agentveil_mcp_proxy.console_credentials import RUNTIME_BINDING_SCOPE

CONSOLE_ORIGIN = "https://agentveil.dev"
_BINDING_PATH = "/v1/controlled-alternatives/av02/runtime/binding"
_ORIGIN_HOST = "agentveil.dev"
_CONSOLE_CREDENTIAL_HEADER = "X-AgentVeil-Console-Credential"

_REQUEST_BODY = b'{"schema_version":"runtime/binding-request/1"}'
_REQUEST_TIMEOUT_SECONDS = 10.0
_MAX_RESPONSE_BYTES = 16 * 1024

_RESPONSE_KEYS = frozenset({
    "schema_version",
    "runtime_binding_token",
    "scope",
    "result",
})
_BINDING_TOKEN = re.compile(r"[A-Za-z0-9._~-]{20,128}\Z")
_CONSOLE_CREDENTIAL = re.compile(r"[A-Za-z0-9._~-]{20,128}\Z")
_RESULT_VALUES = frozenset({"issued", "existing"})


class AgentBindingClientError(RuntimeError):
    """Bounded binding failure with a short stable code only."""

    def __init__(self, code: str = "runtime_binding_failed"):
        self.code = str(code)
        super().__init__(self.code)


class TransportError(Exception):
    """Low-level transport failure without detail leak."""


@dataclass(frozen=True)
class RawResponse:
    status: int
    content_types: tuple[str, ...]
    body: bytes
    cache_control: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeBindingIssuance:
    """Validated binding response. ``token`` is a secret; do not print."""

    token: str
    scope: str
    result: str

    def __repr__(self) -> str:
        return (
            "RuntimeBindingIssuance("
            f"scope={self.scope!r}, result={self.result!r}, has_token=True)"
        )


Transport = Callable[..., RawResponse]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - urllib contract
        return None


def _urllib_transport(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: float,
) -> RawResponse:
    request = urllib.request.Request(
        url, data=body, method=method, headers=dict(headers)
    )
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        raw = _read_bounded(exc)
        return RawResponse(
            status=int(exc.code),
            content_types=_content_types(exc.headers),
            body=raw,
            cache_control=_cache_control(exc.headers),
        )
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        raise TransportError() from exc
    try:
        raw = _read_bounded(response)
        return RawResponse(
            status=int(response.status),
            content_types=_content_types(response.headers),
            body=raw,
            cache_control=_cache_control(response.headers),
        )
    finally:
        try:
            response.close()
        except OSError:
            pass


def _content_types(headers) -> tuple[str, ...]:
    try:
        values = headers.get_all("Content-Type")
    except AttributeError:
        value = headers.get("Content-Type") if headers else None
        values = [value] if value else []
    return tuple(v for v in (values or ()) if v is not None)


def _cache_control(headers) -> tuple[str, ...]:
    try:
        values = headers.get_all("Cache-Control")
    except AttributeError:
        value = headers.get("Cache-Control") if headers else None
        values = [value] if value else None
    if not values:
        return ()
    return tuple(v for v in values if v is not None)


def _read_bounded(response) -> bytes:
    raw = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise AgentBindingClientError("response_too_large")
    return raw


def _validate_origin(url: str) -> None:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname != _ORIGIN_HOST
        or parts.username
        or parts.password
        or parts.fragment
        or parts.path != _BINDING_PATH
    ):
        raise AgentBindingClientError("invalid_origin")


def _decode_strict_json_object(raw: bytes) -> dict[str, object]:
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise AgentBindingClientError("response_too_large")

    def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        keys = [key for key, _value in pairs]
        if len(keys) != len(set(keys)):
            raise AgentBindingClientError("malformed_body")
        return dict(pairs)

    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise AgentBindingClientError("malformed_body") from exc
    if not isinstance(parsed, dict):
        raise AgentBindingClientError("malformed_body")
    return parsed


def _parse_response(response: RawResponse) -> RuntimeBindingIssuance:
    if response.status != 200:
        raise AgentBindingClientError("unexpected_status")
    if len(response.content_types) != 1:
        raise AgentBindingClientError("bad_content_type")
    content_type = response.content_types[0]
    if "," in content_type or content_type.split(";")[0].strip().lower() != "application/json":
        raise AgentBindingClientError("bad_content_type")
    if not any(value.strip().lower() == "no-store" for value in response.cache_control):
        raise AgentBindingClientError("bad_cache_control")
    parsed = _decode_strict_json_object(response.body)
    if set(parsed) != _RESPONSE_KEYS:
        raise AgentBindingClientError("malformed_body")
    if parsed.get("schema_version") != "runtime/binding-response/1":
        raise AgentBindingClientError("malformed_body")
    if parsed.get("scope") != RUNTIME_BINDING_SCOPE:
        raise AgentBindingClientError("malformed_body")
    result = parsed.get("result")
    if not isinstance(result, str) or result not in _RESULT_VALUES:
        raise AgentBindingClientError("malformed_body")
    token = parsed.get("runtime_binding_token")
    if not isinstance(token, str) or not _BINDING_TOKEN.fullmatch(token):
        raise AgentBindingClientError("malformed_body")
    return RuntimeBindingIssuance(
        token=token,
        scope=RUNTIME_BINDING_SCOPE,
        result=str(result),
    )


class ConsoleAgentBindingClient:
    """Issue scoped AV-02 runtime binding credentials for one verified agent."""

    def __init__(
        self,
        *,
        transport: Transport | None = None,
        timeout: float = _REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self._transport = transport or _urllib_transport
        self._timeout = timeout

    def issue(
        self,
        *,
        agent: object,
        summary_token: str,
    ) -> RuntimeBindingIssuance:
        if not isinstance(summary_token, str) or not _CONSOLE_CREDENTIAL.fullmatch(
            summary_token
        ):
            raise AgentBindingClientError("invalid_summary")
        try:
            key_hex = agent.private_key_hex
            did = agent.did
            key = bytes.fromhex(str(key_hex))
            if len(key) != 32 or not isinstance(did, str) or not did.startswith("did:key:"):
                raise AgentBindingClientError("invalid_agent")
        except (AttributeError, TypeError, ValueError) as exc:
            raise AgentBindingClientError("invalid_agent") from exc

        from agentveil.auth import build_auth_header

        url = CONSOLE_ORIGIN + _BINDING_PATH
        _validate_origin(url)
        headers = build_auth_header(
            key,
            did,
            "POST",
            _BINDING_PATH,
            _REQUEST_BODY,
            force_v2=True,
        )
        headers[_CONSOLE_CREDENTIAL_HEADER] = summary_token
        headers.pop("X-AVP-CA-Runtime-Binding", None)
        try:
            response = self._transport(
                "POST",
                url,
                headers=headers,
                body=_REQUEST_BODY,
                timeout=self._timeout,
            )
        except TransportError as exc:
            raise AgentBindingClientError("transport_failed") from exc
        return _parse_response(response)


__all__ = [
    "AgentBindingClientError",
    "ConsoleAgentBindingClient",
    "RuntimeBindingIssuance",
    "CONSOLE_ORIGIN",
]
