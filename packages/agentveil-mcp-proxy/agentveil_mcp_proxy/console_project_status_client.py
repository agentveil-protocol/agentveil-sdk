# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Bounded Console project-status upload client.

Fixed-origin, no-redirect HTTPS transport for ``POST /console/project-status/ingest``.
Best-effort sync only: absent or unsafe credentials skip network; transport and
response failures return bounded non-secret result codes without raising.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCOPE,
    CredentialError,
    StoredCredential,
    load_credential,
)

CONSOLE_ORIGIN = "https://agentveil.dev"
_ORIGIN_HOST = "agentveil.dev"
_INGEST_PATH = "/console/project-status/ingest"

_REQUEST_TIMEOUT_SECONDS = 3.0
_MAX_RESPONSE_BYTES = 16 * 1024
_SCHEMA_VERSION = "1"
_SCOPE_STATEMENT = "Configured project routes only"

_CONNECTORS = frozenset({"codex", "claude-code", "cursor", "gemini-cli"})
_CONNECTION_STATES = frozenset({"connected", "disconnected", "stale", "error"})
_ROUTE_STATES = frozenset({"observed", "advisory", "unavailable"})

_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PACKAGE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_MAX_PACKAGE_VERSION_LENGTH = 64

_REQUEST_KEYS = frozenset({
    "schema_version",
    "connector",
    "connection_state",
    "route_state",
    "project_display_label",
    "observed_at",
    "package_version",
})
_REQUIRED_REQUEST_KEYS = _REQUEST_KEYS - {"package_version"}
_RESPONSE_KEYS = frozenset({
    "workspace_id",
    "connector",
    "connection_state",
    "route_state",
    "project_display_label",
    "observed_at",
    "scope_statement",
})


class ProjectStatusClientError(RuntimeError):
    """Bounded client failure with a short stable code only."""

    def __init__(self, code: str = "project_status_failed"):
        self.code = str(code)
        super().__init__(self.code)


class TransportError(Exception):
    """Low-level transport failure without detail leak."""


@dataclass(frozen=True)
class RawResponse:
    status: int
    content_types: tuple[str, ...]
    body: bytes


@dataclass(frozen=True)
class ProjectStatusSummary:
    schema_version: str
    connector: str
    connection_state: str
    route_state: str
    project_display_label: str
    observed_at: str
    package_version: str | None = None


Transport = Callable[..., RawResponse]
LoadCredential = Callable[..., StoredCredential | None]
Clock = Callable[[], float]


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
        raise ProjectStatusClientError("response_too_large")
    return raw


def _validate_json_content_type(value: str) -> None:
    if "," in value:
        raise ProjectStatusClientError("bad_content_type")
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() != "application/json":
        raise ProjectStatusClientError("bad_content_type")
    if len(parts) > 2:
        raise ProjectStatusClientError("bad_content_type")
    if len(parts) == 2 and not parts[1].lower().startswith("charset="):
        raise ProjectStatusClientError("bad_content_type")
    if len(parts) == 2 and len(parts[1].split("=", 1)[1].strip()) == 0:
        raise ProjectStatusClientError("bad_content_type")


def _parse_rfc3339_utc(value: str) -> datetime:
    text = str(value).strip()
    if not text or "T" not in text:
        raise ProjectStatusClientError("invalid_observed_at")
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ProjectStatusClientError("invalid_observed_at") from exc
    if parsed.tzinfo is None:
        raise ProjectStatusClientError("invalid_observed_at")
    return parsed.astimezone(timezone.utc)


def _canonical_observed_at(value: datetime) -> str:
    utc = value.astimezone(timezone.utc)
    text = utc.strftime("%Y-%m-%dT%H:%M:%S")
    micros = utc.microsecond
    if micros:
        text += f".{micros:06d}".rstrip("0").rstrip(".")
    return f"{text}Z"


def _observed_at_now(*, clock: Clock | None = None) -> str:
    if clock is None:
        now = datetime.now(timezone.utc)
    else:
        now = datetime.fromtimestamp(clock(), timezone.utc)
    return _canonical_observed_at(now)


def _validate_connector(value: str) -> str:
    if value not in _CONNECTORS:
        raise ProjectStatusClientError("invalid_connector")
    return value


def _validate_connection_state(value: str) -> str:
    if value not in _CONNECTION_STATES:
        raise ProjectStatusClientError("invalid_connection_state")
    return value


def _validate_route_state(value: str) -> str:
    if value not in _ROUTE_STATES:
        raise ProjectStatusClientError("invalid_route_state")
    return value


def validate_project_display_label(value: str) -> str | None:
    label = str(value).strip()
    if not label or len(label) > 128:
        return None
    if "/" in label or "\\" in label or ".." in label:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in label):
        return None
    if not _LABEL_RE.fullmatch(label):
        return None
    lowered = label.lower()
    for forbidden in ("secret", "token", "password", "apikey", "api_key", "private"):
        if forbidden in lowered:
            return None
    return label


def normalize_package_version(value: str | None) -> str | None:
    if value is None:
        return None
    version = str(value).strip()
    if not version or len(version) > _MAX_PACKAGE_VERSION_LENGTH:
        return None
    if not _PACKAGE_VERSION_RE.fullmatch(version):
        return None
    if "/" in version or "\\" in version or ".." in version:
        return None
    return version


def _route_value_missing(value: object) -> bool:
    return not isinstance(value, str) or value == "missing"


def normalize_connector_status(
    connector_status: Mapping[str, Any],
) -> tuple[str, str] | None:
    """Map connector status dict to ``(connection_state, route_state)`` or skip."""

    raw_status = connector_status.get("status")
    if not isinstance(raw_status, str):
        return None

    mcp_route = connector_status.get("mcp_route")
    hook = connector_status.get("hook")
    proxy_route = connector_status.get("proxy_route")
    if (
        _route_value_missing(mcp_route)
        and _route_value_missing(hook)
        and _route_value_missing(proxy_route)
    ):
        return ("disconnected", "unavailable")

    if raw_status == "protected":
        return ("connected", "observed")
    if raw_status == "advisory":
        return ("connected", "advisory")
    if raw_status == "unsafe":
        return ("error", "unavailable")
    return None


def build_project_status_summary(
    *,
    connector: str,
    connector_status: Mapping[str, Any],
    project_dir: Path,
    package_version: str | None = None,
    observed_at: str | None = None,
    clock: Clock | None = None,
) -> ProjectStatusSummary | None:
    normalized = normalize_connector_status(connector_status)
    if normalized is None:
        return None
    connection_state, route_state = normalized
    label = validate_project_display_label(Path(project_dir).resolve().name)
    if label is None:
        return None
    version = normalize_package_version(package_version)
    if observed_at is not None:
        canonical_observed = _canonical_observed_at(_parse_rfc3339_utc(observed_at))
    else:
        canonical_observed = _observed_at_now(clock=clock)
    return ProjectStatusSummary(
        schema_version=_SCHEMA_VERSION,
        connector=_validate_connector(connector),
        connection_state=_validate_connection_state(connection_state),
        route_state=_validate_route_state(route_state),
        project_display_label=label,
        observed_at=canonical_observed,
        package_version=version,
    )


def summary_to_request_payload(summary: ProjectStatusSummary) -> dict[str, str]:
    payload = {
        "schema_version": summary.schema_version,
        "connector": summary.connector,
        "connection_state": summary.connection_state,
        "route_state": summary.route_state,
        "project_display_label": summary.project_display_label,
        "observed_at": summary.observed_at,
    }
    if summary.package_version is not None:
        payload["package_version"] = summary.package_version
    if set(payload) - _REQUEST_KEYS:
        raise ProjectStatusClientError("invalid_request")
    if not _REQUIRED_REQUEST_KEYS.issubset(payload):
        raise ProjectStatusClientError("invalid_request")
    return payload


def _require_response_string(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ProjectStatusClientError("malformed_body")
    if not allow_empty and not value:
        raise ProjectStatusClientError("malformed_body")
    return value


def _validate_workspace_id(value: object) -> None:
    workspace_id = _require_response_string(value)
    try:
        uuid.UUID(workspace_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ProjectStatusClientError("malformed_body") from exc


def _decode_response_object(
    response: RawResponse,
    *,
    request: ProjectStatusSummary,
) -> None:
    if response.status != 200:
        raise ProjectStatusClientError("unexpected_status")
    if len(response.content_types) != 1:
        raise ProjectStatusClientError("bad_content_type")
    _validate_json_content_type(response.content_types[0])
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise ProjectStatusClientError("response_too_large")
    try:
        parsed = json.loads(response.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProjectStatusClientError("malformed_body") from exc
    if not isinstance(parsed, dict):
        raise ProjectStatusClientError("malformed_body")
    if set(parsed) != _RESPONSE_KEYS:
        raise ProjectStatusClientError("malformed_body")

    _validate_workspace_id(parsed["workspace_id"])
    connector = _require_response_string(parsed["connector"])
    if connector != request.connector:
        raise ProjectStatusClientError("malformed_body")
    connection_state = _require_response_string(parsed["connection_state"])
    if connection_state != request.connection_state:
        raise ProjectStatusClientError("malformed_body")
    route_state = _require_response_string(parsed["route_state"])
    if route_state != request.route_state:
        raise ProjectStatusClientError("malformed_body")
    label = validate_project_display_label(
        _require_response_string(parsed["project_display_label"])
    )
    if label != request.project_display_label:
        raise ProjectStatusClientError("malformed_body")
    response_observed = _canonical_observed_at(
        _parse_rfc3339_utc(_require_response_string(parsed["observed_at"]))
    )
    if response_observed != request.observed_at:
        raise ProjectStatusClientError("malformed_body")
    scope_statement = _require_response_string(parsed["scope_statement"])
    if scope_statement != _SCOPE_STATEMENT:
        raise ProjectStatusClientError("malformed_body")


class ConsoleProjectStatusClient:
    """Fixed-origin client for bounded project-status ingest."""

    def __init__(
        self,
        *,
        transport: Transport | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._transport = transport or _urllib_transport
        self._clock = clock

    def upload(
        self,
        summary: ProjectStatusSummary,
        *,
        bearer_token: str,
    ) -> None:
        payload = summary_to_request_payload(summary)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
        }
        url = CONSOLE_ORIGIN + _INGEST_PATH
        split = urlsplit(url)
        if split.scheme != "https" or split.netloc != _ORIGIN_HOST:
            raise ProjectStatusClientError("invalid_origin")
        try:
            response = self._transport(
                "POST",
                url,
                headers=headers,
                body=body,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except TransportError as exc:
            raise ProjectStatusClientError("transport_failed") from exc
        _decode_response_object(response, request=summary)


def _resolve_credential(
    *,
    home: Path | None,
    load_credential_fn: LoadCredential,
) -> tuple[StoredCredential | None, str | None]:
    try:
        credential = load_credential_fn(home=home)
    except CredentialError:
        return None, "skipped_unsafe_credential"
    if credential is None:
        return None, "skipped_no_credential"
    if credential.scope != CREDENTIAL_SCOPE:
        return None, "skipped_unsafe_credential"
    return credential, None


def sync_project_status(
    *,
    connector: str,
    connector_status: Mapping[str, Any],
    project_dir: Path,
    home: Path | None = None,
    package_version: str | None = None,
    load_credential_fn: LoadCredential = load_credential,
    transport: Transport | None = None,
    clock: Clock | None = None,
) -> str:
    """Best-effort sync returning a short non-secret result code."""

    credential, skip = _resolve_credential(
        home=home,
        load_credential_fn=load_credential_fn,
    )
    if skip is not None:
        return skip

    try:
        summary = build_project_status_summary(
            connector=connector,
            connector_status=connector_status,
            project_dir=project_dir,
            package_version=package_version,
            clock=clock,
        )
    except ProjectStatusClientError:
        return "skipped_invalid"

    if summary is None:
        return "skipped_ambiguous"

    client = ConsoleProjectStatusClient(transport=transport, clock=clock)
    try:
        assert credential is not None
        client.upload(summary, bearer_token=credential.token)
    except ProjectStatusClientError as exc:
        if exc.code in {"transport_failed", "unexpected_status"}:
            return "unavailable"
        return "rejected"
    return "accepted"


__all__ = [
    "CONSOLE_ORIGIN",
    "ConsoleProjectStatusClient",
    "ProjectStatusClientError",
    "ProjectStatusSummary",
    "RawResponse",
    "Transport",
    "TransportError",
    "build_project_status_summary",
    "normalize_connector_status",
    "normalize_package_version",
    "summary_to_request_payload",
    "sync_project_status",
    "validate_project_display_label",
]
