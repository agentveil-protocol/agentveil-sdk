# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Thin client for the hosted AgentVeil Console browser-session attach endpoints.

Narrow standard-library HTTP client against a fixed HTTPS origin. It validates
the bounded wire contract, rejects redirects, limits response sizes, and raises
bounded typed errors without raw body, header, URL, token, or device code.
Transport, clock, and sleep are injectable for deterministic tests; there is no
public arbitrary-origin switch.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import urlsplit

from agentveil_mcp_proxy.console_credentials import CREDENTIAL_SCOPE

CONSOLE_ORIGIN = "https://agentveil.dev"
_ORIGIN_HOST = "agentveil.dev"

_START_PATH = "/console/attach/start"
_CONSUME_PATH = "/console/attach/consume"
_ATTACH_PATH = "/console/attach"

_ATTACH_STATE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_CANONICAL_ATTACH_URI_RE = re.compile(
    rf"^{re.escape(_ATTACH_PATH)}\?state=([A-Za-z0-9_-]{{32,128}})$"
)

_REQUEST_TIMEOUT_SECONDS = 10.0
_MAX_RESPONSE_BYTES = 16 * 1024

_MAX_DEVICE_CODE_LENGTH = 4096
_MAX_TOKEN_LENGTH = 4096
_MAX_ATTACH_URI_LENGTH = 512
_MAX_EXPIRES_IN = 3600
_MAX_INTERVAL = 300

_START_KEYS = frozenset({"device_code", "attach_uri", "expires_in", "interval"})
_PENDING_KEYS = frozenset({"status"})
_CONSUMED_KEYS = frozenset({"status", "token", "scope"})


class AttachClientError(RuntimeError):
    """Bounded typed attach failure with a short stable code only."""

    def __init__(self, code: str = "attach_failed"):
        self.code = str(code)
        super().__init__(self.code)


class TransportError(Exception):
    """Low-level transport failure (timeout, TLS, connection). No detail leak."""


@dataclass(frozen=True)
class RawResponse:
    """A bounded, already-read HTTP response."""

    status: int
    content_types: tuple[str, ...]
    body: bytes


@dataclass(frozen=True)
class AttachStart:
    """Validated ``/start`` result. ``device_code`` is a secret; do not print."""

    device_code: str
    attach_url: str
    expires_in: int
    interval: int


@dataclass(frozen=True)
class AttachToken:
    """Validated consumed token. ``token`` is a secret; do not print."""

    token: str
    scope: str


Transport = Callable[..., RawResponse]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Turn redirect responses into errors instead of following them."""

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
        )
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        raise TransportError() from exc
    try:
        raw = _read_bounded(response)
        return RawResponse(
            status=int(response.status),
            content_types=_content_types(response.headers),
            body=raw,
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


def _read_bounded(response) -> bytes:
    raw = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise AttachClientError("response_too_large")
    return raw


class ConsoleAttachClient:
    """Thin, fixed-origin client for the Console attach wire contract."""

    def __init__(
        self,
        *,
        transport: Transport | None = None,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._transport = transport or _urllib_transport
        self._clock = clock or time.monotonic
        self._sleep = sleeper or time.sleep

    def _post(
        self,
        path: str,
        *,
        json_body: dict | None = None,
    ) -> RawResponse:
        headers = {"Accept": "application/json"}
        body: bytes | None = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            return self._transport(
                "POST",
                CONSOLE_ORIGIN + path,
                headers=headers,
                body=body,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except TransportError as exc:
            raise AttachClientError("transport_failed") from exc

    def start(self) -> AttachStart:
        """Begin browser-session attach without automatic retry by this client."""

        response = self._post(_START_PATH)
        payload = _decode_json_object(response, expected_status=200)
        if set(payload) != _START_KEYS:
            raise AttachClientError("malformed_start")
        return AttachStart(
            device_code=_require_secret_str(
                payload["device_code"], _MAX_DEVICE_CODE_LENGTH, "malformed_start"
            ),
            attach_url=_resolve_attach_url(payload["attach_uri"]),
            expires_in=_require_bounded_int(
                payload["expires_in"], 1, _MAX_EXPIRES_IN, "malformed_start"
            ),
            interval=_require_bounded_int(
                payload["interval"], 1, _MAX_INTERVAL, "malformed_start"
            ),
        )

    def poll_for_token(self, start: AttachStart) -> AttachToken:
        """Poll ``/consume`` on a monotonic deadline until consumed or expired."""

        interval = min(start.interval, start.expires_in)
        deadline = self._clock() + start.expires_in
        while True:
            if self._clock() >= deadline:
                raise AttachClientError("expired")
            response = self._post(
                _CONSUME_PATH, json_body={"device_code": start.device_code}
            )
            payload = _decode_json_object(response, expected_status=200)
            status = payload.get("status")
            if status == "pending":
                if set(payload) != _PENDING_KEYS:
                    raise AttachClientError("malformed_consume")
                remaining = deadline - self._clock()
                if remaining <= 0:
                    raise AttachClientError("expired")
                self._sleep(min(interval, remaining))
                continue
            if status == "consumed":
                if set(payload) != _CONSUMED_KEYS:
                    raise AttachClientError("malformed_consume")
                token = _require_secret_str(
                    payload["token"], _MAX_TOKEN_LENGTH, "malformed_consume"
                )
                if payload["scope"] != CREDENTIAL_SCOPE:
                    raise AttachClientError("unexpected_scope")
                return AttachToken(token=token, scope=CREDENTIAL_SCOPE)
            raise AttachClientError("unexpected_status")


def _decode_json_object(response: RawResponse, *, expected_status: int) -> dict:
    if response.status != expected_status:
        raise AttachClientError("unexpected_status")
    if len(response.content_types) != 1:
        raise AttachClientError("bad_content_type")
    _validate_json_content_type(response.content_types[0])
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise AttachClientError("response_too_large")
    try:
        parsed = json.loads(response.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AttachClientError("malformed_body") from exc
    if not isinstance(parsed, dict):
        raise AttachClientError("malformed_body")
    return parsed


def _validate_json_content_type(value: str) -> None:
    """Accept only ``application/json`` or one non-empty ``charset`` parameter."""

    if "," in value:
        raise AttachClientError("bad_content_type")
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() != "application/json":
        raise AttachClientError("bad_content_type")
    if len(parts) == 1:
        return
    if len(parts) != 2:
        raise AttachClientError("bad_content_type")
    name, _, charset = parts[1].partition("=")
    if name.lower() != "charset":
        raise AttachClientError("bad_content_type")
    if not charset or charset.lower() not in {"utf-8", "utf8"}:
        raise AttachClientError("bad_content_type")


def _require_str(value: object, max_length: int, code: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise AttachClientError(code)
    if not value or len(value) > max_length:
        raise AttachClientError(code)
    return value


def _require_secret_str(value: object, max_length: int, code: str) -> str:
    text = _require_str(value, max_length, code)
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise AttachClientError(code)
    return text


def _require_bounded_int(value: object, low: int, high: int, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AttachClientError(code)
    if value < low or value > high:
        raise AttachClientError(code)
    return value


def _resolve_attach_url(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise AttachClientError("bad_attach_uri")
    if not value or len(value) > _MAX_ATTACH_URI_LENGTH:
        raise AttachClientError("bad_attach_uri")
    match = _CANONICAL_ATTACH_URI_RE.fullmatch(value)
    if match is None:
        raise AttachClientError("bad_attach_uri")
    if not _ATTACH_STATE_RE.fullmatch(match.group(1)):
        raise AttachClientError("bad_attach_uri")
    resolved = CONSOLE_ORIGIN + value
    parts = urlsplit(resolved)
    if parts.scheme != "https" or parts.netloc != _ORIGIN_HOST:
        raise AttachClientError("bad_attach_uri")
    if parts.fragment or parts.username or parts.password:
        raise AttachClientError("bad_attach_uri")
    return resolved


__all__ = [
    "CONSOLE_ORIGIN",
    "AttachClientError",
    "AttachStart",
    "AttachToken",
    "ConsoleAttachClient",
    "RawResponse",
    "TransportError",
]
