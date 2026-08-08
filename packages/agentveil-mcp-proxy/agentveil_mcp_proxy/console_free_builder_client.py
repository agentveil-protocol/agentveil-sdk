# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Bounded Console free Builder preview download/install client.

Fixed-origin, no-redirect HTTPS transport for Console free-builder eligibility
and package download. Best-effort only: absent or unsafe credentials skip
network; transport and install failures return bounded non-secret result codes
without raising or changing CLI output.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCOPE,
    CredentialError,
    StoredCredential,
    credential_home,
    load_credential,
)
from agentveil_mcp_proxy.console_project_status_client import (
    resolve_private_guardrails_status,
)
from agentveil_mcp_proxy.paid_install import (
    FreeBuilderInstallError,
    FreeBuilderWheelExpectations,
    run_free_builder_install_flow,
)
from agentveil_mcp_proxy.paid_provider import discover_paid_provider

CONSOLE_ORIGIN = "https://agentveil.dev"
_ORIGIN_HOST = "agentveil.dev"
_ELIGIBILITY_PATH = "/console/free-builder/package/eligibility"
_DOWNLOAD_PATH = "/console/free-builder/package/download"

_REQUEST_TIMEOUT_SECONDS = 10.0
_MAX_JSON_RESPONSE_BYTES = 16 * 1024
_MAX_WHEEL_RESPONSE_BYTES = 64 * 1024 * 1024

_PLATFORM_RE = re.compile(r"^[a-z0-9_]{1,16}$")
_PYTHON_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]{1,2}$")
_ARTIFACT_HASH_RE = re.compile(r"^[a-f0-9]{64}$")

_ELIGIBILITY_INELIGIBLE_KEYS = frozenset({"eligible", "error_code"})
_ELIGIBILITY_ELIGIBLE_KEYS = frozenset(
    {
        "eligible",
        "artifact_hash",
        "artifact_size_bytes",
        "package_name",
        "package_version",
    }
)
_DOWNLOAD_REQUEST_KEYS = frozenset({"platform", "python_version"})
_FORBIDDEN_DOWNLOAD_REQUEST_KEYS = frozenset(
    {
        "artifact_id",
        "workspace_id",
        "issuer_reference",
        "capability",
        "plan_id",
        "license_id",
        "entitlement_id",
        "customer_ref",
        "license_key",
        "token",
        "device_token",
        "session_token",
        "presigned_url",
        "workspace",
        "issuer",
        "plan",
    }
)
_DOWNLOAD_ERROR_KEYS = frozenset({"error", "error_code"})


class FreeBuilderClientError(RuntimeError):
    """Bounded client failure with a short stable code only."""

    def __init__(self, code: str = "free_builder_failed"):
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
class FreeBuilderEligibility:
    eligible: bool
    error_code: str | None = None
    artifact_hash: str | None = None
    artifact_size_bytes: int | None = None
    package_name: str | None = None
    package_version: str | None = None


Transport = Callable[..., RawResponse]
LoadCredential = Callable[..., StoredCredential | None]
DiscoverPaidProvider = Callable[[], object]
InstallFreeBuilder = Callable[..., str | None]


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
        raw = _read_bounded(exc, max_bytes=_MAX_JSON_RESPONSE_BYTES)
        return RawResponse(
            status=int(exc.code),
            content_types=_content_types(exc.headers),
            body=raw,
        )
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        raise TransportError() from exc
    try:
        raw = _read_bounded(response, max_bytes=_MAX_WHEEL_RESPONSE_BYTES)
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


def _read_bounded(response, *, max_bytes: int) -> bytes:
    raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise FreeBuilderClientError("response_too_large")
    return raw


def _validate_json_content_type(value: str) -> None:
    if "," in value:
        raise FreeBuilderClientError("bad_content_type")
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() != "application/json":
        raise FreeBuilderClientError("bad_content_type")
    if len(parts) > 2:
        raise FreeBuilderClientError("bad_content_type")
    if len(parts) == 2 and not parts[1].lower().startswith("charset="):
        raise FreeBuilderClientError("bad_content_type")


def _validate_octet_stream_content_type(value: str) -> None:
    if "," in value:
        raise FreeBuilderClientError("bad_content_type")
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() != "application/octet-stream":
        raise FreeBuilderClientError("bad_content_type")


def _validate_platform(value: str) -> str:
    bounded = str(value).strip()
    if not _PLATFORM_RE.fullmatch(bounded):
        raise FreeBuilderClientError("invalid_platform")
    return bounded


def _validate_python_version(value: str) -> str:
    bounded = str(value).strip()
    if not _PYTHON_VERSION_RE.fullmatch(bounded):
        raise FreeBuilderClientError("invalid_python_version")
    return bounded


def build_download_request_payload(*, platform: str, python_version: str) -> dict[str, str]:
    payload = {
        "platform": _validate_platform(platform),
        "python_version": _validate_python_version(python_version),
    }
    if set(payload) != _DOWNLOAD_REQUEST_KEYS:
        raise FreeBuilderClientError("invalid_request")
    return payload


def assert_download_request_public_bounded(payload: Mapping[str, Any]) -> None:
    extra = set(payload) - _DOWNLOAD_REQUEST_KEYS
    forbidden = set(payload) & _FORBIDDEN_DOWNLOAD_REQUEST_KEYS
    if extra or forbidden:
        raise FreeBuilderClientError("invalid_request")


def _require_response_string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise FreeBuilderClientError("malformed_body")
    return value


def _validate_artifact_hash(value: object) -> str:
    digest = _require_response_string(value).lower()
    if not _ARTIFACT_HASH_RE.fullmatch(digest):
        raise FreeBuilderClientError("malformed_body")
    return digest


def _validate_artifact_size_bytes(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FreeBuilderClientError("malformed_body")
    if value <= 0 or value > _MAX_WHEEL_RESPONSE_BYTES:
        raise FreeBuilderClientError("malformed_body")
    return value


def _validate_eligible_package_name(value: object) -> str:
    from agentveil_mcp_proxy.paid_install import validate_bounded_package_name

    try:
        return validate_bounded_package_name(_require_response_string(value))
    except Exception as exc:
        raise FreeBuilderClientError("malformed_body") from exc


def _validate_eligible_package_version(value: object) -> str:
    from agentveil_mcp_proxy.paid_install import validate_bounded_package_version

    try:
        return validate_bounded_package_version(_require_response_string(value))
    except Exception as exc:
        raise FreeBuilderClientError("malformed_body") from exc


def expectations_from_eligibility(
    eligibility: FreeBuilderEligibility,
) -> FreeBuilderWheelExpectations:
    """Build trusted install expectations from a verified eligible response."""

    if not eligibility.eligible:
        raise FreeBuilderClientError("ineligible")
    if (
        eligibility.artifact_hash is None
        or eligibility.artifact_size_bytes is None
        or eligibility.package_name is None
        or eligibility.package_version is None
    ):
        raise FreeBuilderClientError("malformed_body")
    return FreeBuilderWheelExpectations(
        artifact_hash=eligibility.artifact_hash,
        artifact_size_bytes=eligibility.artifact_size_bytes,
        package_name=eligibility.package_name,
        package_version=eligibility.package_version,
    )


def _decode_eligibility_response(response: RawResponse) -> FreeBuilderEligibility:
    if response.status == 404:
        raise FreeBuilderClientError("unavailable")
    if response.status != 200:
        raise FreeBuilderClientError("unexpected_status")
    if len(response.content_types) != 1:
        raise FreeBuilderClientError("bad_content_type")
    _validate_json_content_type(response.content_types[0])
    if len(response.body) > _MAX_JSON_RESPONSE_BYTES:
        raise FreeBuilderClientError("response_too_large")
    try:
        parsed = json.loads(response.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise FreeBuilderClientError("malformed_body") from exc
    if not isinstance(parsed, dict):
        raise FreeBuilderClientError("malformed_body")
    eligible = parsed.get("eligible")
    if not isinstance(eligible, bool):
        raise FreeBuilderClientError("malformed_body")
    if not eligible:
        if set(parsed) - _ELIGIBILITY_INELIGIBLE_KEYS:
            raise FreeBuilderClientError("malformed_body")
        error_code = parsed.get("error_code")
        if error_code is not None and (not isinstance(error_code, str) or not error_code):
            raise FreeBuilderClientError("malformed_body")
        return FreeBuilderEligibility(eligible=False, error_code=error_code)
    if set(parsed) != _ELIGIBILITY_ELIGIBLE_KEYS:
        raise FreeBuilderClientError("malformed_body")
    return FreeBuilderEligibility(
        eligible=True,
        artifact_hash=_validate_artifact_hash(parsed["artifact_hash"]),
        artifact_size_bytes=_validate_artifact_size_bytes(parsed["artifact_size_bytes"]),
        package_name=_validate_eligible_package_name(parsed["package_name"]),
        package_version=_validate_eligible_package_version(parsed["package_version"]),
    )


def _decode_download_error(response: RawResponse) -> None:
    if len(response.content_types) != 1:
        raise FreeBuilderClientError("bad_content_type")
    _validate_json_content_type(response.content_types[0])
    try:
        parsed = json.loads(response.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise FreeBuilderClientError("malformed_body") from exc
    if not isinstance(parsed, dict) or set(parsed) - _DOWNLOAD_ERROR_KEYS:
        raise FreeBuilderClientError("malformed_body")


def _decode_download_wheel(response: RawResponse) -> bytes:
    if response.status == 404:
        raise FreeBuilderClientError("unavailable")
    if response.status != 200:
        _decode_download_error(response)
        raise FreeBuilderClientError("download_denied")
    if len(response.content_types) != 1:
        raise FreeBuilderClientError("bad_content_type")
    _validate_octet_stream_content_type(response.content_types[0])
    if not response.body:
        raise FreeBuilderClientError("empty_wheel")
    if len(response.body) > _MAX_WHEEL_RESPONSE_BYTES:
        raise FreeBuilderClientError("response_too_large")
    return bytes(response.body)


class ConsoleFreeBuilderClient:
    """Fixed-origin client for bounded free Builder preview package delivery."""

    def __init__(
        self,
        *,
        transport: Transport | None = None,
    ) -> None:
        self._transport = transport or _urllib_transport

    def _request(
        self,
        method: str,
        path: str,
        *,
        bearer_token: str,
        body: bytes | None = None,
        accept: str,
        content_type: str | None = None,
    ) -> RawResponse:
        url = CONSOLE_ORIGIN + path
        split = urlsplit(url)
        if split.scheme != "https" or split.netloc != _ORIGIN_HOST:
            raise FreeBuilderClientError("invalid_origin")
        headers = {
            "Accept": accept,
            "Authorization": f"Bearer {bearer_token}",
        }
        if content_type is not None:
            headers["Content-Type"] = content_type
        try:
            return self._transport(
                method,
                url,
                headers=headers,
                body=body,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except TransportError as exc:
            raise FreeBuilderClientError("transport_failed") from exc

    def check_eligibility(self, *, bearer_token: str) -> FreeBuilderEligibility:
        response = self._request(
            "GET",
            _ELIGIBILITY_PATH,
            bearer_token=bearer_token,
            body=None,
            accept="application/json",
        )
        return _decode_eligibility_response(response)

    def download_package(
        self,
        *,
        bearer_token: str,
        platform: str,
        python_version: str,
    ) -> bytes:
        payload = build_download_request_payload(
            platform=platform,
            python_version=python_version,
        )
        assert_download_request_public_bounded(payload)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        response = self._request(
            "POST",
            _DOWNLOAD_PATH,
            bearer_token=bearer_token,
            body=body,
            accept="application/octet-stream",
            content_type="application/json",
        )
        return _decode_download_wheel(response)


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


def _resolve_provider_guard(snapshot: object) -> str | None:
    """Return a skip code when an existing paid provider state blocks free install."""

    try:
        report = resolve_private_guardrails_status(snapshot)
    except Exception:
        return None
    if report == "active":
        return "skipped_already_active"
    if report == "inactive":
        return "skipped_existing_paid_state"
    return None


def sync_free_builder_install(
    *,
    home: Path | None = None,
    platform: str | None = None,
    python_version: str | None = None,
    load_credential_fn: LoadCredential = load_credential,
    discover_paid_provider_fn: DiscoverPaidProvider | None = None,
    transport: Transport | None = None,
    install_flow_fn: InstallFreeBuilder | None = None,
) -> str:
    """Best-effort free Builder install returning a short non-secret result code."""

    credential, skip = _resolve_credential(home=home, load_credential_fn=load_credential_fn)
    if skip is not None:
        return skip

    discover = discover_paid_provider_fn or discover_paid_provider
    try:
        guard = _resolve_provider_guard(discover())
    except Exception:
        return "skipped_provider_unavailable"
    if guard is not None:
        return guard

    from agentveil_mcp_proxy.paid_install import (
        current_platform_name,
        current_python_version,
    )

    resolved_home = credential_home(home)
    resolved_platform = _validate_platform(platform or current_platform_name())
    resolved_python = _validate_python_version(python_version or current_python_version())
    client = ConsoleFreeBuilderClient(transport=transport)

    try:
        assert credential is not None
        eligibility = client.check_eligibility(bearer_token=credential.token)
    except FreeBuilderClientError as exc:
        if exc.code in {"transport_failed", "unavailable"}:
            return "unavailable"
        return "rejected"

    if not eligibility.eligible:
        return "skipped_ineligible"

    try:
        expectations = expectations_from_eligibility(eligibility)
    except FreeBuilderClientError:
        return "rejected"

    try:
        wheel_bytes = client.download_package(
            bearer_token=credential.token,
            platform=resolved_platform,
            python_version=resolved_python,
        )
    except FreeBuilderClientError as exc:
        if exc.code in {"transport_failed", "unavailable"}:
            return "unavailable"
        return "rejected"

    install = install_flow_fn or _default_install_flow
    try:
        install(
            wheel_bytes=wheel_bytes,
            home=resolved_home,
            activation_credential=credential.token,
            expectations=expectations,
            discover_paid_provider_fn=discover,
        )
    except FreeBuilderInstallError:
        return "skipped_install_failed"
    except Exception:
        return "skipped_install_failed"

    try:
        if resolve_private_guardrails_status(discover()) != "active":
            return "skipped_provider_inactive"
    except Exception:
        return "skipped_provider_inactive"

    return "installed"


def _default_install_flow(
    *,
    wheel_bytes: bytes,
    home: Path,
    activation_credential: str,
    expectations: FreeBuilderWheelExpectations,
    discover_paid_provider_fn: DiscoverPaidProvider,
) -> None:
    run_free_builder_install_flow(
        wheel_bytes=wheel_bytes,
        home=home,
        activation_credential=activation_credential,
        expectations=expectations,
        discover_paid_provider_fn=discover_paid_provider_fn,
    )


__all__ = [
    "CONSOLE_ORIGIN",
    "ConsoleFreeBuilderClient",
    "FreeBuilderClientError",
    "FreeBuilderEligibility",
    "RawResponse",
    "Transport",
    "TransportError",
    "assert_download_request_public_bounded",
    "build_download_request_payload",
    "expectations_from_eligibility",
    "sync_free_builder_install",
]
