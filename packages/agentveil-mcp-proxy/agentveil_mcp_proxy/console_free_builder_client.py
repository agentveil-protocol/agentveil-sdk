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
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, TextIO
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
    COMPOSED_BASE_PACKAGE_NAME,
    COMPOSED_BASE_PACKAGE_VERSION,
    COMPOSED_THIN_PACKAGE_VERSION,
    COMPONENT_ROLE_BASE,
    COMPONENT_ROLE_THIN,
    FREE_BUILDER_PACKAGE_NAME,
    FreeBuilderInstallError,
    FreeBuilderWheelExpectations,
    run_free_builder_install_flow,
    run_free_builder_paired_install_flow,
)
from agentveil_mcp_proxy.paid_provider import discover_paid_provider

CONSOLE_ORIGIN = "https://agentveil.dev"
_ORIGIN_HOST = "agentveil.dev"
_ELIGIBILITY_PATH = "/console/free-builder/package/eligibility"
_DOWNLOAD_PATH = "/console/free-builder/package/download"
_ELIGIBILITY_V2_PATH = "/console/free-builder/package/v2/eligibility"
_DOWNLOAD_V2_PATH = "/console/free-builder/package/v2/download"
_V2_CONTRACT_VERSION = "v2"

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
_V2_DOWNLOAD_REQUEST_KEYS = frozenset({"role", "platform", "python_version"})
_V2_ELIGIBILITY_INELIGIBLE_KEYS = frozenset({"eligible", "error_code"})
_V2_ELIGIBILITY_ELIGIBLE_KEYS = frozenset({"eligible", "contract_version", "components"})
_V2_COMPONENT_KEYS = frozenset(
    {
        "role",
        "package_name",
        "package_version",
        "artifact_hash",
        "artifact_size_bytes",
    }
)
_V2_EXPECTED_COMPONENTS: tuple[tuple[str, str, str], ...] = (
    (COMPONENT_ROLE_BASE, COMPOSED_BASE_PACKAGE_NAME, COMPOSED_BASE_PACKAGE_VERSION),
    (COMPONENT_ROLE_THIN, FREE_BUILDER_PACKAGE_NAME, COMPOSED_THIN_PACKAGE_VERSION),
)
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


@dataclass(frozen=True)
class FreeBuilderV2Component:
    role: str
    package_name: str
    package_version: str
    artifact_hash: str
    artifact_size_bytes: int


@dataclass(frozen=True)
class FreeBuilderEligibilityV2:
    eligible: bool
    components: tuple[FreeBuilderV2Component, ...] = ()
    error_code: str | None = None


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


def build_v2_download_request_payload(
    *,
    role: str,
    platform: str,
    python_version: str,
) -> dict[str, str]:
    bounded_role = _require_response_string(role).strip()
    if bounded_role not in {COMPONENT_ROLE_BASE, COMPONENT_ROLE_THIN}:
        raise FreeBuilderClientError("invalid_request")
    payload = {
        "role": bounded_role,
        "platform": _validate_platform(platform),
        "python_version": _validate_python_version(python_version),
    }
    if set(payload) != _V2_DOWNLOAD_REQUEST_KEYS:
        raise FreeBuilderClientError("invalid_request")
    return payload


def assert_download_request_public_bounded(payload: Mapping[str, Any]) -> None:
    allowed = _DOWNLOAD_REQUEST_KEYS | _V2_DOWNLOAD_REQUEST_KEYS
    extra = set(payload) - allowed
    forbidden = set(payload) & _FORBIDDEN_DOWNLOAD_REQUEST_KEYS
    if extra or forbidden:
        raise FreeBuilderClientError("invalid_request")
    if set(payload) == _DOWNLOAD_REQUEST_KEYS or set(payload) == _V2_DOWNLOAD_REQUEST_KEYS:
        return
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
    from agentveil_mcp_proxy.paid_install import validate_free_builder_package_name

    try:
        return validate_free_builder_package_name(_require_response_string(value))
    except Exception as exc:
        raise FreeBuilderClientError("malformed_body") from exc


def _validate_v2_component_package_name(value: object) -> str:
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


def expectations_from_v2_component(
    component: FreeBuilderV2Component,
) -> FreeBuilderWheelExpectations:
    return FreeBuilderWheelExpectations(
        artifact_hash=component.artifact_hash,
        artifact_size_bytes=component.artifact_size_bytes,
        package_name=component.package_name,
        package_version=component.package_version,
    )


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


def _decode_v2_component(entry: object) -> FreeBuilderV2Component:
    if not isinstance(entry, dict):
        raise FreeBuilderClientError("malformed_body")
    if set(entry) != _V2_COMPONENT_KEYS:
        raise FreeBuilderClientError("malformed_body")
    role = _require_response_string(entry["role"]).strip()
    package_name = _validate_v2_component_package_name(entry["package_name"])
    package_version = _validate_eligible_package_version(entry["package_version"])
    return FreeBuilderV2Component(
        role=role,
        package_name=package_name,
        package_version=package_version,
        artifact_hash=_validate_artifact_hash(entry["artifact_hash"]),
        artifact_size_bytes=_validate_artifact_size_bytes(entry["artifact_size_bytes"]),
    )


def _decode_eligibility_v2_response(response: RawResponse) -> FreeBuilderEligibilityV2:
    if response.status == 404:
        raise FreeBuilderClientError("v2_not_found")
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
        if set(parsed) - _V2_ELIGIBILITY_INELIGIBLE_KEYS:
            raise FreeBuilderClientError("malformed_body")
        error_code = parsed.get("error_code")
        if error_code is not None and (not isinstance(error_code, str) or not error_code):
            raise FreeBuilderClientError("malformed_body")
        return FreeBuilderEligibilityV2(eligible=False, error_code=error_code)
    if set(parsed) != _V2_ELIGIBILITY_ELIGIBLE_KEYS:
        raise FreeBuilderClientError("malformed_body")
    contract_version = parsed.get("contract_version")
    if contract_version != _V2_CONTRACT_VERSION:
        raise FreeBuilderClientError("malformed_body")
    components_raw = parsed.get("components")
    if not isinstance(components_raw, list) or len(components_raw) != len(_V2_EXPECTED_COMPONENTS):
        raise FreeBuilderClientError("malformed_body")
    parsed_components = [_decode_v2_component(entry) for entry in components_raw]
    roles = [component.role for component in parsed_components]
    if len(set(roles)) != len(roles):
        raise FreeBuilderClientError("malformed_body")
    for component, expected in zip(parsed_components, _V2_EXPECTED_COMPONENTS, strict=True):
        expected_role, expected_name, expected_version = expected
        if component.role != expected_role:
            raise FreeBuilderClientError("malformed_body")
        if component.package_name != expected_name or component.package_version != expected_version:
            raise FreeBuilderClientError("malformed_body")
    return FreeBuilderEligibilityV2(eligible=True, components=tuple(parsed_components))


def _decode_v2_composed_upgrade_eligibility_response(
    response: RawResponse,
) -> FreeBuilderEligibilityV2:
    """Decode v2 eligibility for composed thin upgrade; base fixed, thin version open."""

    if response.status == 404:
        raise FreeBuilderClientError("v2_not_found")
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
        if set(parsed) - _V2_ELIGIBILITY_INELIGIBLE_KEYS:
            raise FreeBuilderClientError("malformed_body")
        error_code = parsed.get("error_code")
        if error_code is not None and (not isinstance(error_code, str) or not error_code):
            raise FreeBuilderClientError("malformed_body")
        return FreeBuilderEligibilityV2(eligible=False, error_code=error_code)
    if set(parsed) != _V2_ELIGIBILITY_ELIGIBLE_KEYS:
        raise FreeBuilderClientError("malformed_body")
    contract_version = parsed.get("contract_version")
    if contract_version != _V2_CONTRACT_VERSION:
        raise FreeBuilderClientError("malformed_body")
    components_raw = parsed.get("components")
    if not isinstance(components_raw, list) or len(components_raw) != len(_V2_EXPECTED_COMPONENTS):
        raise FreeBuilderClientError("malformed_body")
    parsed_components = [_decode_v2_component(entry) for entry in components_raw]
    roles = [component.role for component in parsed_components]
    if len(set(roles)) != len(roles):
        raise FreeBuilderClientError("malformed_body")
    expected_base_role, expected_base_name, expected_base_version = _V2_EXPECTED_COMPONENTS[0]
    expected_thin_role, expected_thin_name, _expected_thin_version = _V2_EXPECTED_COMPONENTS[1]
    base_component = parsed_components[0]
    thin_component = parsed_components[1]
    if base_component.role != expected_base_role:
        raise FreeBuilderClientError("malformed_body")
    if (
        base_component.package_name != expected_base_name
        or base_component.package_version != expected_base_version
    ):
        raise FreeBuilderClientError("malformed_body")
    if thin_component.role != expected_thin_role:
        raise FreeBuilderClientError("malformed_body")
    if thin_component.package_name != expected_thin_name:
        raise FreeBuilderClientError("malformed_body")
    return FreeBuilderEligibilityV2(eligible=True, components=tuple(parsed_components))


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

    def check_eligibility_v2(
        self,
        *,
        bearer_token: str,
        platform: str,
        python_version: str,
    ) -> FreeBuilderEligibilityV2:
        bounded_platform = _validate_platform(platform)
        bounded_python = _validate_python_version(python_version)
        path = (
            f"{_ELIGIBILITY_V2_PATH}?platform={bounded_platform}"
            f"&python_version={bounded_python}"
        )
        response = self._request(
            "GET",
            path,
            bearer_token=bearer_token,
            body=None,
            accept="application/json",
        )
        return _decode_eligibility_v2_response(response)

    def check_eligibility_v2_for_composed_upgrade(
        self,
        *,
        bearer_token: str,
        platform: str,
        python_version: str,
    ) -> FreeBuilderEligibilityV2:
        bounded_platform = _validate_platform(platform)
        bounded_python = _validate_python_version(python_version)
        path = (
            f"{_ELIGIBILITY_V2_PATH}?platform={bounded_platform}"
            f"&python_version={bounded_python}"
        )
        response = self._request(
            "GET",
            path,
            bearer_token=bearer_token,
            body=None,
            accept="application/json",
        )
        return _decode_v2_composed_upgrade_eligibility_response(response)

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

    def download_package_v2(
        self,
        *,
        bearer_token: str,
        role: str,
        platform: str,
        python_version: str,
    ) -> bytes:
        payload = build_v2_download_request_payload(
            role=role,
            platform=platform,
            python_version=python_version,
        )
        assert_download_request_public_bounded(payload)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        response = self._request(
            "POST",
            _DOWNLOAD_V2_PATH,
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


def resolve_free_builder_install_home(home: Path | None) -> Path:
    """Return the AVP home that receives paid install state."""

    return credential_home(home)


def resolve_free_builder_credential_home(home: Path | None) -> Path:
    """Return the AVP home that stores the Console credential for *home*."""

    from agentveil_mcp_proxy.console_credentials import (
        console_credential_home_for_runtime,
    )

    install_home = resolve_free_builder_install_home(home).expanduser()
    if install_home.name not in (".avp", ".agentveil"):
        return install_home
    credential_home = console_credential_home_for_runtime(install_home)
    if credential_home is None:
        return install_home
    return credential_home.expanduser()


def _resolve_credential_for_setup_sync(
    *,
    home: Path | None,
    load_credential_fn: LoadCredential,
) -> tuple[StoredCredential | None, str | None]:
    try:
        credential = load_credential_fn(home=resolve_free_builder_credential_home(home))
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


_UPGRADE_BOUNDED_PAYLOAD_KEYS = frozenset(
    {
        "action",
        "apply",
        "current_package_name",
        "current_package_version",
        "result_code",
        "target_components",
        "target_install_composition_version",
        "upgrade_available",
    }
)
_UPGRADE_TARGET_COMPONENT_KEYS = frozenset({"role", "package_name", "package_version"})


def _upgrade_skip_before_credential(*, home: Path | None) -> str | None:
    """Install-home and unsafe-runtime preflight before any credential read."""

    install_home = resolve_free_builder_install_home(home).expanduser()
    from agentveil_mcp_proxy.console_credentials import (
        project_runtime_home_automatic_sync_preflight_skip,
    )

    preflight = project_runtime_home_automatic_sync_preflight_skip(install_home)
    if preflight is not None:
        return preflight

    from agentveil_mcp_proxy.paid_activation import bound_avp_home

    with bound_avp_home(install_home):
        return _upgrade_untrusted_local_paths_issue(install_home)


def _upgrade_untrusted_local_paths_issue(home: Path) -> str | None:
    """Reject symlink or untrusted path components before reading paid local state."""

    from agentveil_mcp_proxy.paid_activation import activation_path
    from agentveil_mcp_proxy.paid_install import (
        PaidInstallError,
        _assert_trusted_home_path,
        install_state_path,
        vendor_root,
    )

    try:
        paid_dir = home / "paid"
        _assert_trusted_home_path(home, paid_dir)
        install_path = install_state_path(home)
        if install_path.is_symlink() or install_path.exists():
            _assert_trusted_home_path(home, install_path)
        activation = activation_path(home)
        if activation.is_symlink() or activation.exists():
            _assert_trusted_home_path(home, activation)
        _assert_trusted_home_path(home, vendor_root(home))
    except PaidInstallError:
        return "rejected_ineligible_local_state"
    return None


def _bounded_v2_component_summary(
    components: tuple[FreeBuilderV2Component, ...],
) -> list[dict[str, str]]:
    return [
        {
            "role": component.role,
            "package_name": component.package_name,
            "package_version": component.package_version,
        }
        for component in components
    ]


@dataclass(frozen=True)
class _ComposedUpgradeLocalState:
    current_package_name: str
    current_package_version: str
    installed_thin_version: str


def _bounded_version_sort_key(version: str) -> tuple[int, int, int]:
    from agentveil_mcp_proxy.paid_install import validate_bounded_package_version

    normalized = validate_bounded_package_version(version)
    parts: list[int] = []
    for segment in normalized.split("."):
        digits = ""
        for char in segment:
            if char.isdigit():
                digits += char
            else:
                break
        parts.append(int(digits or "0"))
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def _is_strictly_newer_bounded_version(candidate: str, installed: str) -> bool:
    return _bounded_version_sort_key(candidate) > _bounded_version_sort_key(installed)


def _composed_upgrade_target_issue(
    *,
    installed_thin_version: str,
    components: tuple[FreeBuilderV2Component, ...],
) -> str | None:
    if len(components) != 2:
        return "rejected"
    base_component, thin_component = components
    if (
        base_component.role != COMPONENT_ROLE_BASE
        or base_component.package_name != COMPOSED_BASE_PACKAGE_NAME
        or base_component.package_version != COMPOSED_BASE_PACKAGE_VERSION
    ):
        return "rejected"
    if (
        thin_component.role != COMPONENT_ROLE_THIN
        or thin_component.package_name != FREE_BUILDER_PACKAGE_NAME
    ):
        return "rejected"
    if not _is_strictly_newer_bounded_version(
        thin_component.package_version,
        installed_thin_version,
    ):
        return "rejected"
    return None


def _composed_console_pair_upgrade_context(
    *,
    home: Path,
    discover_paid_provider_fn: DiscoverPaidProvider,
) -> tuple[str | None, _ComposedUpgradeLocalState | None]:
    """Return local composed upgrade context or a rejection when composition is present."""

    from agentveil_mcp_proxy.paid_activation import (
        PaidActivationError,
        TERMINAL_INACTIVE_ACTIVATION_STATUSES,
        activation_path,
        assert_activation_metadata_bounded,
        load_activation_state,
    )
    from agentveil_mcp_proxy.paid_install import (
        BOUNDED_INSTALL_KEYS,
        COMPOSED_INSTALL_COMPOSITION_VERSION,
        INSTALL_SAFETY_STATE_VERIFIED,
        PaidInstallError,
        PROVIDER_ID,
        assert_install_metadata_bounded,
        install_state_path,
        load_install_state,
        resolve_vendored_paid_provider,
        vendor_root,
        _validate_split_install_state,
    )
    from agentveil_mcp_proxy.paid_provider import (
        STATUS_ACTIVE,
        STATUS_MISSING,
        STATUS_WITHIN_GRACE,
    )

    install_path = install_state_path(home)
    install_state = load_install_state(install_path)
    if install_state is None:
        if install_path.is_file():
            try:
                raw_payload = json.loads(install_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                return "rejected_ineligible_local_state", None
            if isinstance(raw_payload, dict) and raw_payload.get(
                "install_composition_version"
            ) is not None:
                return "rejected_ineligible_local_state", None
        return None, None
    if install_state.get("install_composition_version") is None:
        return None, None
    if install_state.get("status") != STATUS_ACTIVE:
        return "rejected_ineligible_local_state", None
    if set(install_state) - BOUNDED_INSTALL_KEYS:
        return "rejected_ineligible_local_state", None
    if install_state.get("install_composition_version") != COMPOSED_INSTALL_COMPOSITION_VERSION:
        return "rejected_ineligible_local_state", None
    if install_state.get("install_safety_state") != INSTALL_SAFETY_STATE_VERIFIED:
        return "rejected_ineligible_local_state", None
    provider_id = install_state.get("provider_id")
    if not isinstance(provider_id, str) or provider_id != PROVIDER_ID:
        return "rejected_ineligible_local_state", None
    try:
        assert_install_metadata_bounded(install_state)
        _validate_split_install_state(install_state)
    except PaidInstallError:
        return "rejected_ineligible_local_state", None

    try:
        snapshot = discover_paid_provider_fn()
    except Exception:
        return "rejected_ineligible_local_state", None

    guard = _resolve_provider_guard(snapshot)
    if guard == "skipped_existing_paid_state":
        return "rejected_paid_terminal_state", None
    if guard != "skipped_already_active":
        return "rejected_ineligible_local_state", None

    discovered_id = getattr(snapshot, "provider_id", None)
    discovered_status = getattr(snapshot, "status", None)
    if discovered_status != STATUS_ACTIVE:
        return "rejected_ineligible_local_state", None
    if discovered_id is not None and str(discovered_id) != provider_id:
        return "rejected_ineligible_local_state", None

    base_vendor = vendor_root(home) / (
        f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}"
    )
    if not base_vendor.is_dir():
        return "rejected_ineligible_local_state", None

    components = install_state.get("install_components")
    if not isinstance(components, list):
        return "rejected_ineligible_local_state", None
    thin_version: str | None = None
    for entry in components:
        if isinstance(entry, dict) and entry.get("role") == COMPONENT_ROLE_THIN:
            version = entry.get("package_version")
            name = entry.get("package_name")
            if isinstance(version, str) and isinstance(name, str):
                if name != FREE_BUILDER_PACKAGE_NAME:
                    return "rejected_ineligible_local_state", None
                thin_version = version
    if thin_version is None:
        return "rejected_ineligible_local_state", None

    thin_vendor = vendor_root(home) / f"{FREE_BUILDER_PACKAGE_NAME}-{thin_version}"
    if not thin_vendor.is_dir():
        return "rejected_ineligible_local_state", None

    if resolve_vendored_paid_provider(home=home) is None:
        return "rejected_ineligible_local_state", None

    activation = load_activation_state(activation_path(home))
    if activation is not None:
        try:
            assert_activation_metadata_bounded(activation)
        except PaidActivationError:
            return "rejected_ineligible_local_state", None
        status = activation.get("status")
        if status in TERMINAL_INACTIVE_ACTIVATION_STATUSES:
            return "rejected_paid_terminal_state", None
        if status in {STATUS_WITHIN_GRACE}:
            return "rejected_paid_terminal_state", None
        if status not in {STATUS_ACTIVE, STATUS_MISSING}:
            return "rejected_ineligible_local_state", None

    current_name = install_state.get("package_name")
    current_version = install_state.get("package_version")
    if not isinstance(current_name, str) or not isinstance(current_version, str):
        return "rejected_ineligible_local_state", None

    return None, _ComposedUpgradeLocalState(
        current_package_name=current_name,
        current_package_version=current_version,
        installed_thin_version=thin_version,
    )


def _legacy_console_thin_upgrade_issue(
    *,
    home: Path,
    discover_paid_provider_fn: DiscoverPaidProvider,
) -> str | None:
    """Return a rejection code when local state is not an active legacy thin install."""

    from agentveil_mcp_proxy.paid_activation import (
        PaidActivationError,
        TERMINAL_INACTIVE_ACTIVATION_STATUSES,
        activation_path,
        assert_activation_metadata_bounded,
        load_activation_state,
    )
    from agentveil_mcp_proxy.paid_install import (
        BOUNDED_INSTALL_KEYS,
        DEFAULT_PACKAGE_NAME,
        FREE_BUILDER_PACKAGE_NAME,
        INSTALL_SAFETY_STATE_VERIFIED,
        PROVIDER_ID,
        install_state_path,
        load_install_state,
        resolve_vendored_paid_provider,
        validate_bounded_package_name,
        validate_bounded_package_version,
        vendor_root,
    )
    from agentveil_mcp_proxy.paid_provider import (
        STATUS_ACTIVE,
        STATUS_MISSING,
        STATUS_WITHIN_GRACE,
    )

    install_path = install_state_path(home)
    install_state = load_install_state(install_path)
    if install_state is None or install_state.get("status") != STATUS_ACTIVE:
        return "rejected_ineligible_local_state"
    if set(install_state) - BOUNDED_INSTALL_KEYS:
        return "rejected_ineligible_local_state"
    if install_state.get("install_composition_version") is not None:
        return "rejected_already_composed"

    safety_state = install_state.get("install_safety_state")
    if safety_state != INSTALL_SAFETY_STATE_VERIFIED:
        return "rejected_ineligible_local_state"

    provider_id = install_state.get("provider_id")
    if not isinstance(provider_id, str) or provider_id != PROVIDER_ID:
        return "rejected_ineligible_local_state"

    try:
        snapshot = discover_paid_provider_fn()
    except Exception:
        return "rejected_ineligible_local_state"

    guard = _resolve_provider_guard(snapshot)
    if guard == "skipped_existing_paid_state":
        return "rejected_paid_terminal_state"
    if guard != "skipped_already_active":
        return "rejected_ineligible_local_state"

    discovered_id = getattr(snapshot, "provider_id", None)
    discovered_status = getattr(snapshot, "status", None)
    if discovered_status != STATUS_ACTIVE:
        return "rejected_ineligible_local_state"
    if discovered_id is not None and str(discovered_id) != provider_id:
        return "rejected_ineligible_local_state"

    package_name = install_state.get("package_name")
    package_version = install_state.get("package_version")
    if not isinstance(package_name, str) or not isinstance(package_version, str):
        return "rejected_ineligible_local_state"
    if package_name == DEFAULT_PACKAGE_NAME:
        return "rejected_paid_license_state"
    try:
        bounded_name = validate_bounded_package_name(package_name)
        bounded_version = validate_bounded_package_version(package_version)
    except Exception:
        return "rejected_ineligible_local_state"
    if bounded_name != FREE_BUILDER_PACKAGE_NAME:
        return "rejected_ineligible_local_state"

    vendor_dir = vendor_root(home) / f"{bounded_name}-{bounded_version}"
    if not vendor_dir.is_dir():
        return "rejected_ineligible_local_state"

    if resolve_vendored_paid_provider(home=home) is None:
        return "rejected_ineligible_local_state"

    activation = load_activation_state(activation_path(home))
    if activation is not None:
        try:
            assert_activation_metadata_bounded(activation)
        except PaidActivationError:
            return "rejected_ineligible_local_state"
        status = activation.get("status")
        if status in TERMINAL_INACTIVE_ACTIVATION_STATUSES:
            return "rejected_paid_terminal_state"
        if status in {STATUS_WITHIN_GRACE}:
            return "rejected_paid_terminal_state"
        if status not in {STATUS_ACTIVE, STATUS_MISSING}:
            return "rejected_ineligible_local_state"

    return None


def format_upgrade_free_builder_human_output(payload: Mapping[str, Any]) -> str:
    lines = [
        f"Upgrade action: {payload['action']}",
        f"Apply: {'yes' if payload.get('apply') else 'no'}",
        f"Result: {payload['result_code']}",
        f"Upgrade available: {'yes' if payload.get('upgrade_available') else 'no'}",
    ]
    current_name = payload.get("current_package_name")
    current_version = payload.get("current_package_version")
    if isinstance(current_name, str) and isinstance(current_version, str):
        lines.append(f"Current package: {current_name}")
        lines.append(f"Current version: {current_version}")
    target_components = payload.get("target_components")
    if isinstance(target_components, list) and target_components:
        lines.append("Target components:")
        for entry in target_components:
            if not isinstance(entry, dict):
                continue
            role = entry.get("role")
            name = entry.get("package_name")
            version = entry.get("package_version")
            if isinstance(role, str) and isinstance(name, str) and isinstance(version, str):
                lines.append(f"  - {role}: {name} {version}")
    composition = payload.get("target_install_composition_version")
    if isinstance(composition, str) and composition:
        lines.append(f"Target composition version: {composition}")
    return "\n".join(lines)


def _build_upgrade_payload(
    *,
    result_code: str,
    apply: bool,
    current_package_name: str | None = None,
    current_package_version: str | None = None,
    target_components: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    from agentveil_mcp_proxy.paid_install import COMPOSED_INSTALL_COMPOSITION_VERSION

    payload: dict[str, Any] = {
        "action": "upgrade-free-builder",
        "apply": bool(apply),
        "result_code": str(result_code),
        "upgrade_available": result_code == "preview_ready",
    }
    if current_package_name is not None:
        payload["current_package_name"] = current_package_name
    if current_package_version is not None:
        payload["current_package_version"] = current_package_version
    if target_components is not None:
        payload["target_components"] = target_components
        payload["target_install_composition_version"] = COMPOSED_INSTALL_COMPOSITION_VERSION
    extra = set(payload) - _UPGRADE_BOUNDED_PAYLOAD_KEYS
    if extra:
        raise FreeBuilderClientError("invalid_upgrade_payload")
    if target_components is not None:
        for entry in target_components:
            if set(entry) != _UPGRADE_TARGET_COMPONENT_KEYS:
                raise FreeBuilderClientError("invalid_upgrade_payload")
    return payload


def upgrade_free_builder_to_paired(
    *,
    home: Path | None = None,
    apply: bool = False,
    platform: str | None = None,
    python_version: str | None = None,
    load_credential_fn: LoadCredential = load_credential,
    discover_paid_provider_fn: DiscoverPaidProvider | None = None,
    transport: Transport | None = None,
    paired_install_flow_fn: Callable[..., None] | None = None,
    composed_thin_upgrade_flow_fn: Callable[..., None] | None = None,
) -> dict[str, Any]:
    """Explicit Console thin or composed-pair upgrade; preview unless apply=True."""

    from agentveil_mcp_proxy.paid_activation import bound_avp_home
    from agentveil_mcp_proxy.paid_install import (
        current_platform_name,
        current_python_version,
        install_state_path,
        load_install_state,
    )

    skip_before_credential = _upgrade_skip_before_credential(home=home)
    if skip_before_credential is not None:
        return _build_upgrade_payload(result_code=skip_before_credential, apply=apply)

    resolved_home = resolve_free_builder_install_home(home).expanduser()
    with bound_avp_home(resolved_home):
        credential, skip = _resolve_credential_for_setup_sync(
            home=home,
            load_credential_fn=load_credential_fn,
        )
        if skip is not None:
            return _build_upgrade_payload(result_code=skip, apply=apply)

        discover = discover_paid_provider_fn or discover_paid_provider
        composed_issue, composed_local = _composed_console_pair_upgrade_context(
            home=resolved_home,
            discover_paid_provider_fn=discover,
        )
        composed_upgrade = composed_local is not None
        if composed_issue is not None and not composed_upgrade:
            return _build_upgrade_payload(result_code=composed_issue, apply=apply)

        if not composed_upgrade:
            local_issue = _legacy_console_thin_upgrade_issue(
                home=resolved_home,
                discover_paid_provider_fn=discover,
            )
            if local_issue is not None:
                return _build_upgrade_payload(result_code=local_issue, apply=apply)

        install_state = load_install_state(install_state_path(resolved_home))
        if install_state is None:
            return _build_upgrade_payload(
                result_code="rejected_ineligible_local_state",
                apply=apply,
            )
        if composed_upgrade and composed_local is not None:
            current_name = composed_local.current_package_name
            current_version = composed_local.current_package_version
            installed_thin_version = composed_local.installed_thin_version
        else:
            current_name = str(install_state.get("package_name"))
            current_version = str(install_state.get("package_version"))
            installed_thin_version = ""

        resolved_platform = _validate_platform(platform or current_platform_name())
        resolved_python = _validate_python_version(python_version or current_python_version())
        client = ConsoleFreeBuilderClient(transport=transport)
        assert credential is not None

        try:
            if composed_upgrade:
                eligibility_v2 = client.check_eligibility_v2_for_composed_upgrade(
                    bearer_token=credential.token,
                    platform=resolved_platform,
                    python_version=resolved_python,
                )
            else:
                eligibility_v2 = client.check_eligibility_v2(
                    bearer_token=credential.token,
                    platform=resolved_platform,
                    python_version=resolved_python,
                )
        except FreeBuilderClientError as exc:
            if exc.code == "v2_not_found":
                return _build_upgrade_payload(result_code="rejected", apply=apply)
            if exc.code in {"transport_failed", "unavailable"}:
                return _build_upgrade_payload(result_code="unavailable", apply=apply)
            return _build_upgrade_payload(result_code="rejected", apply=apply)

        if not eligibility_v2.eligible:
            return _build_upgrade_payload(result_code="skipped_ineligible", apply=apply)
        if len(eligibility_v2.components) != 2:
            return _build_upgrade_payload(result_code="rejected", apply=apply)

        if composed_upgrade:
            target_issue = _composed_upgrade_target_issue(
                installed_thin_version=installed_thin_version,
                components=eligibility_v2.components,
            )
            if target_issue is not None:
                return _build_upgrade_payload(result_code=target_issue, apply=apply)

        target_summary = _bounded_v2_component_summary(eligibility_v2.components)
        if not apply:
            return _build_upgrade_payload(
                result_code="preview_ready",
                apply=False,
                current_package_name=current_name,
                current_package_version=current_version,
                target_components=target_summary,
            )

        thin_component = eligibility_v2.components[1]
        thin_expectations = expectations_from_v2_component(thin_component)

        if composed_upgrade:
            try:
                thin_wheel_bytes = client.download_package_v2(
                    bearer_token=credential.token,
                    role=thin_component.role,
                    platform=resolved_platform,
                    python_version=resolved_python,
                )
            except FreeBuilderClientError as exc:
                if exc.code in {"transport_failed", "unavailable"}:
                    return _build_upgrade_payload(result_code="unavailable", apply=True)
                return _build_upgrade_payload(result_code="rejected", apply=True)

            thin_upgrade = composed_thin_upgrade_flow_fn or _default_composed_thin_upgrade_flow
            try:
                thin_upgrade(
                    thin_wheel_bytes=thin_wheel_bytes,
                    home=resolved_home,
                    thin_expectations=thin_expectations,
                    prior_install_state=install_state,
                )
            except FreeBuilderInstallError:
                return _build_upgrade_payload(result_code="skipped_install_failed", apply=True)
            except Exception:
                return _build_upgrade_payload(result_code="skipped_install_failed", apply=True)

            return _build_upgrade_payload(
                result_code="upgraded",
                apply=True,
                current_package_name=current_name,
                current_package_version=current_version,
                target_components=target_summary,
            )

        base_component = eligibility_v2.components[0]
        base_expectations = expectations_from_v2_component(base_component)

        try:
            base_wheel_bytes = client.download_package_v2(
                bearer_token=credential.token,
                role=base_component.role,
                platform=resolved_platform,
                python_version=resolved_python,
            )
            thin_wheel_bytes = client.download_package_v2(
                bearer_token=credential.token,
                role=thin_component.role,
                platform=resolved_platform,
                python_version=resolved_python,
            )
        except FreeBuilderClientError as exc:
            if exc.code in {"transport_failed", "unavailable"}:
                return _build_upgrade_payload(result_code="unavailable", apply=True)
            return _build_upgrade_payload(result_code="rejected", apply=True)

        paired_install = paired_install_flow_fn or _default_paired_install_flow
        try:
            paired_install(
                base_wheel_bytes=base_wheel_bytes,
                thin_wheel_bytes=thin_wheel_bytes,
                home=resolved_home,
                activation_credential=credential.token,
                base_expectations=base_expectations,
                thin_expectations=thin_expectations,
                discover_paid_provider_fn=discover,
            )
        except FreeBuilderInstallError:
            return _build_upgrade_payload(result_code="skipped_install_failed", apply=True)
        except Exception:
            return _build_upgrade_payload(result_code="skipped_install_failed", apply=True)

        return _build_upgrade_payload(
            result_code="upgraded",
            apply=True,
            current_package_name=current_name,
            current_package_version=current_version,
            target_components=target_summary,
        )


def _emit_upgrade_payload(
    payload: Mapping[str, Any],
    *,
    output_json: bool,
    out: TextIO,
    secrets: tuple[str, ...] = (),
) -> None:
    from agentveil_mcp_proxy.client_config import assert_proxy_cli_json_is_privacy_safe
    from agentveil_mcp_proxy.paid_activation import assert_paid_human_output_no_overclaim
    from agentveil_mcp_proxy.paid_install import scan_paid_output_for_leaks

    bounded = dict(payload)
    if output_json:
        assert_proxy_cli_json_is_privacy_safe(bounded)
        rendered = json.dumps(bounded, sort_keys=True)
    else:
        text = format_upgrade_free_builder_human_output(bounded)
        assert_paid_human_output_no_overclaim(text)
        rendered = text
    scan_paid_output_for_leaks(rendered, secrets=secrets)
    print(rendered, file=out)


def run_paid_upgrade_free_builder_cli(
    *,
    home: Path | None,
    apply: bool = False,
    output_json: bool = False,
    out: TextIO | None = None,
    load_credential_fn: LoadCredential = load_credential,
    discover_paid_provider_fn: DiscoverPaidProvider | None = None,
    transport: Transport | None = None,
    paired_install_flow_fn: Callable[..., None] | None = None,
) -> int:
    """Run bounded preview/apply upgrade for legacy Console free Builder installs."""

    stream = out or sys.stdout
    skip_before_credential = _upgrade_skip_before_credential(home=home)
    if skip_before_credential is not None:
        payload = _build_upgrade_payload(
            result_code=skip_before_credential,
            apply=apply,
        )
        _emit_upgrade_payload(payload, output_json=output_json, out=stream, secrets=())
        return 1

    credential, _skip = _resolve_credential_for_setup_sync(
        home=home,
        load_credential_fn=load_credential_fn,
    )
    secret_markers: tuple[str, ...] = ()
    if credential is not None and credential.token:
        secret_markers = (credential.token,)
    payload = upgrade_free_builder_to_paired(
        home=home,
        apply=apply,
        load_credential_fn=load_credential_fn,
        discover_paid_provider_fn=discover_paid_provider_fn,
        transport=transport,
        paired_install_flow_fn=paired_install_flow_fn,
    )
    _emit_upgrade_payload(payload, output_json=output_json, out=stream, secrets=secret_markers)
    if payload.get("result_code") in {"preview_ready", "upgraded"}:
        return 0
    return 1


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

    install_home = resolve_free_builder_install_home(home)
    from agentveil_mcp_proxy.console_credentials import (
        project_runtime_home_automatic_sync_preflight_skip,
    )

    preflight = project_runtime_home_automatic_sync_preflight_skip(install_home)
    if preflight is not None:
        return preflight

    credential, skip = _resolve_credential_for_setup_sync(
        home=home,
        load_credential_fn=load_credential_fn,
    )
    if skip is not None:
        return skip

    discover = discover_paid_provider_fn or (lambda: discover_paid_provider(home=home))
    try:
        guard = _resolve_provider_guard(discover())
    except Exception:
        return "skipped_provider_unavailable"
    if guard is not None:
        return guard

    from agentveil_mcp_proxy.paid_activation import bound_avp_home
    from agentveil_mcp_proxy.paid_install import (
        current_platform_name,
        current_python_version,
    )

    resolved_home = install_home
    resolved_platform = _validate_platform(platform or current_platform_name())
    resolved_python = _validate_python_version(python_version or current_python_version())
    client = ConsoleFreeBuilderClient(transport=transport)
    assert credential is not None

    try:
        eligibility_v2 = client.check_eligibility_v2(
            bearer_token=credential.token,
            platform=resolved_platform,
            python_version=resolved_python,
        )
    except FreeBuilderClientError as exc:
        if exc.code == "v2_not_found":
            return _sync_free_builder_install_v1(
                client=client,
                credential=credential,
                resolved_home=resolved_home,
                resolved_platform=resolved_platform,
                resolved_python=resolved_python,
                discover=discover,
                install_flow_fn=install_flow_fn,
            )
        if exc.code in {"transport_failed", "unavailable"}:
            return "unavailable"
        return "rejected"

    if not eligibility_v2.eligible:
        return "skipped_ineligible"

    if len(eligibility_v2.components) != 2:
        return "rejected"

    base_component = eligibility_v2.components[0]
    thin_component = eligibility_v2.components[1]
    base_expectations = expectations_from_v2_component(base_component)
    thin_expectations = expectations_from_v2_component(thin_component)

    try:
        base_wheel_bytes = client.download_package_v2(
            bearer_token=credential.token,
            role=base_component.role,
            platform=resolved_platform,
            python_version=resolved_python,
        )
        thin_wheel_bytes = client.download_package_v2(
            bearer_token=credential.token,
            role=thin_component.role,
            platform=resolved_platform,
            python_version=resolved_python,
        )
    except FreeBuilderClientError as exc:
        if exc.code in {"transport_failed", "unavailable"}:
            return "unavailable"
        return "rejected"

    paired_install = _default_paired_install_flow
    try:
        with bound_avp_home(resolved_home):
            paired_install(
                base_wheel_bytes=base_wheel_bytes,
                thin_wheel_bytes=thin_wheel_bytes,
                home=resolved_home,
                activation_credential=credential.token,
                base_expectations=base_expectations,
                thin_expectations=thin_expectations,
                discover_paid_provider_fn=discover,
            )
    except FreeBuilderInstallError:
        return "skipped_install_failed"
    except Exception:
        return "skipped_install_failed"

    return "installed"


def _sync_free_builder_install_v1(
    *,
    client: ConsoleFreeBuilderClient,
    credential: StoredCredential,
    resolved_home: Path,
    resolved_platform: str,
    resolved_python: str,
    discover: DiscoverPaidProvider,
    install_flow_fn: InstallFreeBuilder | None,
) -> str:
    from agentveil_mcp_proxy.console_project_status_client import (
        resolve_private_guardrails_status,
    )

    try:
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


def _default_composed_thin_upgrade_flow(
    *,
    thin_wheel_bytes: bytes,
    home: Path,
    thin_expectations: FreeBuilderWheelExpectations,
    prior_install_state: Mapping[str, Any],
) -> None:
    import contextlib
    import os
    import secrets

    from agentveil_mcp_proxy.paid_activation import utc_now_iso
    from agentveil_mcp_proxy.paid_install import (
        COMPOSED_THIN_ARTIFACT_ID,
        INSTALL_SAFETY_STATE_VERIFIED,
        PROVIDER_ID,
        FreeBuilderInstallError,
        PaidInstallError,
        vendor_root,
        _ComposedInstallComponentSpec,
        _StagedComposedComponent,
        _assert_live_vendored_paid_provider_active,
        _assert_staged_vendored_controlled_alternative_authority_loadable,
        _assert_staged_vendored_controlled_alternative_resolves,
        _assert_trusted_home_path,
        _commit_wheel_cache,
        _discard_staged_composed_component,
        _release_wheel_cache_backup,
        _rollback_composed_install_durable_state,
        _vendor_live_dir,
        _vendor_stage_dir,
        install_state_path,
        install_wheel_to_vendor,
        verify_free_builder_wheel_artifact,
        write_install_state,
    )

    if (
        thin_expectations.artifact_hash is None
        or thin_expectations.artifact_size_bytes is None
        or thin_expectations.package_name is None
        or thin_expectations.package_version is None
    ):
        raise FreeBuilderInstallError("artifact_hash_required")

    target_thin_version = thin_expectations.package_version
    thin_spec = _ComposedInstallComponentSpec(
        role=COMPONENT_ROLE_THIN,
        artifact_id=COMPOSED_THIN_ARTIFACT_ID,
        package_name=FREE_BUILDER_PACKAGE_NAME,
        package_version=target_thin_version,
    )
    verify_free_builder_wheel_artifact(
        thin_wheel_bytes,
        expectations=FreeBuilderWheelExpectations(
            artifact_hash=thin_expectations.artifact_hash,
            artifact_size_bytes=thin_expectations.artifact_size_bytes,
            package_name=thin_spec.package_name,
            package_version=thin_spec.package_version,
        ),
    )

    _assert_trusted_home_path(home, home / "paid")
    _assert_trusted_home_path(home, vendor_root(home))

    wheel_dir = home / "paid" / "cache"
    install_path = install_state_path(home)
    prior_install_bytes = install_path.read_bytes() if install_path.is_file() else None
    prior_activation_bytes = _read_prior_activation_bytes_for_upgrade(home)
    base_live_dir = _vendor_live_dir(
        home,
        package_name=COMPOSED_BASE_PACKAGE_NAME,
        package_version=COMPOSED_BASE_PACKAGE_VERSION,
    )

    wheel_path = wheel_dir / f"{thin_spec.package_name}-{thin_spec.package_version}.whl"
    wheel_stage_path = wheel_dir / (
        f".staging-{thin_spec.package_name}-{thin_spec.package_version}-"
        f"{secrets.token_hex(8)}.whl"
    )
    target_dir = _vendor_live_dir(
        home,
        package_name=thin_spec.package_name,
        package_version=thin_spec.package_version,
    )
    stage_dir = _vendor_stage_dir(
        home,
        package_name=thin_spec.package_name,
        package_version=thin_spec.package_version,
    )
    staged = _StagedComposedComponent(
        spec=thin_spec,
        wheel_stage_path=wheel_stage_path,
        wheel_path=wheel_path,
        stage_dir=stage_dir,
        target_dir=target_dir,
    )
    published_vendors: list[tuple[_StagedComposedComponent, object]] = []
    published_caches: list[tuple[Path, object]] = []

    try:
        wheel_stage_path.parent.mkdir(parents=True, exist_ok=True)
        wheel_stage_path.write_bytes(thin_wheel_bytes)
        os.chmod(wheel_stage_path, 0o600)
        install_wheel_to_vendor(
            home=home,
            wheel_path=wheel_stage_path,
            target_dir=stage_dir,
            expected_package_name=thin_spec.package_name,
            expected_package_version=thin_spec.package_version,
            require_empty_target=True,
        )
        _assert_staged_vendored_controlled_alternative_resolves(
            home=home,
            vendor_dir=stage_dir,
            package_name=thin_spec.package_name,
            package_version=thin_spec.package_version,
        )
        _assert_staged_vendored_controlled_alternative_authority_loadable(
            home=home,
            vendor_dir=stage_dir,
            package_name=thin_spec.package_name,
            package_version=thin_spec.package_version,
        )
        _assert_live_vendored_paid_provider_active(
            home=home,
            vendor_dir=base_live_dir,
            package_name=COMPOSED_BASE_PACKAGE_NAME,
            package_version=COMPOSED_BASE_PACKAGE_VERSION,
            provider_id=PROVIDER_ID,
        )

        prior_components = prior_install_state.get("install_components")
        if not isinstance(prior_components, list):
            raise FreeBuilderInstallError("install_failed")
        next_components: list[dict[str, str]] = []
        for entry in prior_components:
            if not isinstance(entry, dict):
                raise FreeBuilderInstallError("install_failed")
            role = entry.get("role")
            package_name = entry.get("package_name")
            package_version = entry.get("package_version")
            if not isinstance(role, str) or not isinstance(package_name, str):
                raise FreeBuilderInstallError("install_failed")
            if role == COMPONENT_ROLE_THIN:
                package_version = target_thin_version
            elif not isinstance(package_version, str):
                raise FreeBuilderInstallError("install_failed")
            next_components.append(
                {
                    "role": role,
                    "package_name": package_name,
                    "package_version": str(package_version),
                }
            )

        from agentveil_mcp_proxy.paid_provider import STATUS_ACTIVE

        install_state = {
            "status": STATUS_ACTIVE,
            "provider_id": PROVIDER_ID,
            "package_name": COMPOSED_BASE_PACKAGE_NAME,
            "package_version": COMPOSED_BASE_PACKAGE_VERSION,
            "install_composition_version": prior_install_state.get("install_composition_version"),
            "install_components": next_components,
            "public_fallback_available": prior_install_state.get("public_fallback_available", True),
            "error_code": None,
            "last_installed_at": utc_now_iso(),
            "install_safety_state": INSTALL_SAFETY_STATE_VERIFIED,
            "install_safety_reason": None,
        }

        from agentveil_mcp_proxy.paid_install import _publish_staged_vendor

        try:
            vendor_publish_rollback = _publish_staged_vendor(
                home=home,
                stage_dir=staged.stage_dir,
                live_dir=staged.target_dir,
            )
            published_vendors.append((staged, vendor_publish_rollback))
            cache_rollback = _commit_wheel_cache(
                wheel_stage_path=staged.wheel_stage_path,
                wheel_path=staged.wheel_path,
                retain_backup=True,
            )
            published_caches.append((staged.wheel_path, cache_rollback))
            write_install_state(install_path, install_state)
            _assert_live_vendored_paid_provider_active(
                home=home,
                vendor_dir=base_live_dir,
                package_name=COMPOSED_BASE_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
                provider_id=PROVIDER_ID,
            )
            for _wheel_path, cache_rollback in published_caches:
                with contextlib.suppress(Exception):
                    _release_wheel_cache_backup(cache_rollback)
        except Exception as exc:
            _rollback_composed_install_durable_state(
                home=home,
                install_path=install_path,
                prior_install_bytes=prior_install_bytes,
                prior_activation_bytes=prior_activation_bytes,
                published_vendors=published_vendors,
                published_caches=published_caches,
            )
            if isinstance(exc, PaidInstallError):
                raise FreeBuilderInstallError(str(exc.args[0])) from exc
            raise FreeBuilderInstallError("install_publish_failed") from exc
    except PaidInstallError as exc:
        _discard_staged_composed_component(staged)
        _restore_composed_upgrade_durable_bytes(
            home=home,
            install_path=install_path,
            prior_install_bytes=prior_install_bytes,
            prior_activation_bytes=prior_activation_bytes,
        )
        raise FreeBuilderInstallError(str(exc.args[0])) from exc
    except FreeBuilderInstallError:
        _discard_staged_composed_component(staged)
        _restore_composed_upgrade_durable_bytes(
            home=home,
            install_path=install_path,
            prior_install_bytes=prior_install_bytes,
            prior_activation_bytes=prior_activation_bytes,
        )
        raise
    except Exception:
        _discard_staged_composed_component(staged)
        _restore_composed_upgrade_durable_bytes(
            home=home,
            install_path=install_path,
            prior_install_bytes=prior_install_bytes,
            prior_activation_bytes=prior_activation_bytes,
        )
        raise FreeBuilderInstallError("free_builder_install_failed")


def _read_prior_activation_bytes_for_upgrade(home: Path) -> bytes | None:
    from agentveil_mcp_proxy.paid_install import _read_prior_activation_bytes

    return _read_prior_activation_bytes(home)


def _restore_composed_upgrade_durable_bytes(
    *,
    home: Path,
    install_path: Path,
    prior_install_bytes: bytes | None,
    prior_activation_bytes: bytes | None,
) -> None:
    from agentveil_mcp_proxy.paid_activation import activation_path
    from agentveil_mcp_proxy.paid_install import (
        _restore_activation_state_bytes,
        _restore_install_state_bytes,
    )

    _restore_activation_state_bytes(activation_path(home), prior_activation_bytes)
    _restore_install_state_bytes(install_path, prior_install_bytes)


def _default_paired_install_flow(
    *,
    base_wheel_bytes: bytes,
    thin_wheel_bytes: bytes,
    home: Path,
    activation_credential: str,
    base_expectations: FreeBuilderWheelExpectations,
    thin_expectations: FreeBuilderWheelExpectations,
    discover_paid_provider_fn: DiscoverPaidProvider,
) -> None:
    run_free_builder_paired_install_flow(
        base_wheel_bytes=base_wheel_bytes,
        thin_wheel_bytes=thin_wheel_bytes,
        home=home,
        activation_credential=activation_credential,
        base_expectations=base_expectations,
        thin_expectations=thin_expectations,
        discover_paid_provider_fn=discover_paid_provider_fn,
    )


__all__ = [
    "CONSOLE_ORIGIN",
    "ConsoleFreeBuilderClient",
    "FreeBuilderClientError",
    "FreeBuilderEligibility",
    "FreeBuilderEligibilityV2",
    "FreeBuilderV2Component",
    "RawResponse",
    "Transport",
    "TransportError",
    "assert_download_request_public_bounded",
    "build_download_request_payload",
    "build_v2_download_request_payload",
    "expectations_from_eligibility",
    "expectations_from_v2_component",
    "run_paid_upgrade_free_builder_cli",
    "sync_free_builder_install",
    "upgrade_free_builder_to_paired",
]
