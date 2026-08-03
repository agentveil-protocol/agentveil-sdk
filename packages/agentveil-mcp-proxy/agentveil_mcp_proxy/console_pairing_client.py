# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Thin client for the hosted AgentVeil Console pairing endpoints.

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

_START_PATH = "/console/pairing/start"
_CONSUME_PATH = "/console/pairing/consume"
_REVOKE_PATH = "/console/pairing/token/revoke"

_REQUEST_TIMEOUT_SECONDS = 10.0
_MAX_RESPONSE_BYTES = 16 * 1024

_MAX_DEVICE_CODE_LENGTH = 4096
_MAX_USER_CODE_LENGTH = 64
_MAX_TOKEN_LENGTH = 4096
_MAX_VERIFICATION_URI_LENGTH = 512
_MAX_EXPIRES_IN = 3600
_MAX_INTERVAL = 300

_START_KEYS = frozenset(
    {"device_code", "user_code", "verification_uri", "expires_in", "interval"}
)
_PENDING_KEYS = frozenset({"status"})
_CONFIRMED_KEYS = frozenset({"status", "token", "scope"})
_REVOKED_KEYS = frozenset({"status"})

_USER_CODE_RE = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")


class PairingClientError(RuntimeError):
    """Bounded typed pairing failure with a short stable code only."""

    def __init__(self, code: str = "pairing_failed"):
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
class PairingStart:
    """Validated ``/start`` result. ``device_code`` is a secret; do not print."""

    device_code: str
    user_code: str
    verification_url: str
    expires_in: int
    interval: int


@dataclass(frozen=True)
class PairingToken:
    """Validated confirmed token. ``token`` is a secret; do not print."""

    token: str
    scope: str


class RevokeOutcome:
    """Non-secret revoke result codes."""

    REVOKED = "revoked"
    ALREADY_UNAVAILABLE = "already_unavailable"


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
        # 3xx (redirect refused above) and 4xx/5xx arrive here as responses.
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
        raise PairingClientError("response_too_large")
    return raw


class ConsolePairingClient:
    """Thin, fixed-origin client for the Console pairing wire contract."""

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
        bearer_token: str | None = None,
    ) -> RawResponse:
        headers = {"Accept": "application/json"}
        body: bytes | None = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if bearer_token is not None:
            headers["Authorization"] = f"Bearer {bearer_token}"
        try:
            return self._transport(
                "POST",
                CONSOLE_ORIGIN + path,
                headers=headers,
                body=body,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except TransportError as exc:
            raise PairingClientError("transport_failed") from exc

    def start(self) -> PairingStart:
        """Begin pairing without automatic retry by this client."""

        response = self._post(_START_PATH)
        payload = _decode_json_object(response, expected_status=200)
        if set(payload) != _START_KEYS:
            raise PairingClientError("malformed_start")
        return PairingStart(
            device_code=_require_secret_str(
                payload["device_code"], _MAX_DEVICE_CODE_LENGTH, "malformed_start"
            ),
            user_code=_require_user_code(payload["user_code"]),
            verification_url=_resolve_verification_url(payload["verification_uri"]),
            expires_in=_require_bounded_int(
                payload["expires_in"], 1, _MAX_EXPIRES_IN, "malformed_start"
            ),
            interval=_require_bounded_int(
                payload["interval"], 1, _MAX_INTERVAL, "malformed_start"
            ),
        )

    def poll_for_token(self, start: PairingStart) -> PairingToken:
        """Poll ``/consume`` on a monotonic deadline until confirmed or expired."""

        interval = min(start.interval, start.expires_in)
        deadline = self._clock() + start.expires_in
        while True:
            if self._clock() >= deadline:
                raise PairingClientError("expired")
            response = self._post(
                _CONSUME_PATH, json_body={"device_code": start.device_code}
            )
            payload = _decode_json_object(response, expected_status=200)
            status = payload.get("status")
            if status == "pending":
                if set(payload) != _PENDING_KEYS:
                    raise PairingClientError("malformed_consume")
                remaining = deadline - self._clock()
                if remaining <= 0:
                    raise PairingClientError("expired")
                self._sleep(min(interval, remaining))
                continue
            if status == "confirmed":
                if set(payload) != _CONFIRMED_KEYS:
                    raise PairingClientError("malformed_consume")
                token = _require_secret_str(
                    payload["token"], _MAX_TOKEN_LENGTH, "malformed_consume"
                )
                if payload["scope"] != CREDENTIAL_SCOPE:
                    raise PairingClientError("unexpected_scope")
                return PairingToken(token=token, scope=CREDENTIAL_SCOPE)
            raise PairingClientError("unexpected_status")

    def revoke(self, token: str) -> str:
        """Revoke the remote token.

        Returns a :class:`RevokeOutcome` code for ``200 revoked`` and
        ``401/403``. Raises :class:`PairingClientError` on any ambiguous result
        so the caller preserves local custody.
        """

        response = self._post(_REVOKE_PATH, bearer_token=token)
        if response.status in (401, 403):
            return RevokeOutcome.ALREADY_UNAVAILABLE
        payload = _decode_json_object(response, expected_status=200)
        if set(payload) != _REVOKED_KEYS or payload.get("status") != "revoked":
            raise PairingClientError("malformed_revoke")
        return RevokeOutcome.REVOKED


def _decode_json_object(response: RawResponse, *, expected_status: int) -> dict:
    if response.status != expected_status:
        raise PairingClientError("unexpected_status")
    if len(response.content_types) != 1:
        raise PairingClientError("bad_content_type")
    _validate_json_content_type(response.content_types[0])
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise PairingClientError("response_too_large")
    try:
        parsed = json.loads(response.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PairingClientError("malformed_body") from exc
    if not isinstance(parsed, dict):
        raise PairingClientError("malformed_body")
    return parsed


def _validate_json_content_type(value: str) -> None:
    """Accept only ``application/json`` or one non-empty ``charset`` parameter."""

    if "," in value:
        raise PairingClientError("bad_content_type")
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() != "application/json":
        raise PairingClientError("bad_content_type")
    if len(parts) == 1:
        return
    if len(parts) != 2:
        raise PairingClientError("bad_content_type")
    name, _, charset = parts[1].partition("=")
    if name.lower() != "charset":
        raise PairingClientError("bad_content_type")
    if not charset or charset.lower() not in {"utf-8", "utf8"}:
        raise PairingClientError("bad_content_type")


def _require_user_code(value: object) -> str:
    text = _require_str(value, _MAX_USER_CODE_LENGTH, "malformed_start")
    if not _USER_CODE_RE.fullmatch(text):
        raise PairingClientError("malformed_start")
    return text


def _require_str(value: object, max_length: int, code: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise PairingClientError(code)
    if not value or len(value) > max_length:
        raise PairingClientError(code)
    return value


def _require_secret_str(value: object, max_length: int, code: str) -> str:
    text = _require_str(value, max_length, code)
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise PairingClientError(code)
    return text


def _require_bounded_int(value: object, low: int, high: int, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PairingClientError(code)
    if value < low or value > high:
        raise PairingClientError(code)
    return value


def _resolve_verification_url(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise PairingClientError("bad_verification_uri")
    if not value or len(value) > _MAX_VERIFICATION_URI_LENGTH:
        raise PairingClientError("bad_verification_uri")
    if not value.startswith("/") or value.startswith("//"):
        raise PairingClientError("bad_verification_uri")
    if any(ch in value for ch in ("@", "?", "#", "\\")):
        raise PairingClientError("bad_verification_uri")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in value):
        raise PairingClientError("bad_verification_uri")
    resolved = CONSOLE_ORIGIN + value
    parts = urlsplit(resolved)
    if parts.scheme != "https" or parts.netloc != _ORIGIN_HOST:
        raise PairingClientError("bad_verification_uri")
    if parts.query or parts.fragment or parts.username or parts.password:
        raise PairingClientError("bad_verification_uri")
    return resolved


__all__ = [
    "CONSOLE_ORIGIN",
    "ConsolePairingClient",
    "PairingClientError",
    "PairingStart",
    "PairingToken",
    "RawResponse",
    "RevokeOutcome",
    "TransportError",
]
