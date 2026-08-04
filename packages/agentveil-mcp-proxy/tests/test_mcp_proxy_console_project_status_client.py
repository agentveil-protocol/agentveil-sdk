# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Tests for bounded Console project-status upload client."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCOPE,
    CredentialError,
    StoredCredential,
)
from agentveil_mcp_proxy.console_project_status_client import (
    CONSOLE_ORIGIN,
    ProjectStatusClientError,
    RawResponse,
    TransportError,
    build_project_status_summary,
    normalize_connector_status,
    normalize_package_version,
    summary_to_request_payload,
    sync_project_status,
    validate_project_display_label,
)

TOKEN = "console-device-token-secret"
SECRET = "SECRET_PROJECT_STATUS_CANARY"
WORKSPACE_ID = "11111111-1111-4111-8111-111111111111"
SCOPE_STATEMENT = "Configured project routes only"


def _json_response(status, obj, *, content_type="application/json"):
    body = json.dumps(obj).encode("utf-8")
    content_types = () if content_type is None else (content_type,)
    return RawResponse(status=status, content_types=content_types, body=body)


def _backend_ingest_response_for_request(body: bytes, **overrides):
    payload = json.loads(body.decode("utf-8"))
    response = {
        "workspace_id": WORKSPACE_ID,
        "connector": payload["connector"],
        "connection_state": payload["connection_state"],
        "route_state": payload["route_state"],
        "project_display_label": payload["project_display_label"],
        "observed_at": payload["observed_at"].replace("Z", "+00:00"),
        "scope_statement": SCOPE_STATEMENT,
    }
    response.update(overrides)
    return response


def _advisory_status():
    return {
        "status": "advisory",
        "mcp_route": "present",
        "hook": "present",
        "proxy_route": "present",
    }


class FakeTransport:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, *, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            return item(body=body)
        return item


class BackendEchoTransport:
    def __init__(self, **overrides):
        self.overrides = overrides
        self.calls = []

    def __call__(self, method, url, *, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        return _json_response(
            200,
            _backend_ingest_response_for_request(body, **self.overrides),
        )


def _load_credential_ok(home=None):
    return StoredCredential(scope=CREDENTIAL_SCOPE, token=TOKEN)


@pytest.mark.parametrize("connector", ["codex", "claude-code", "cursor", "gemini-cli"])
def test_build_summary_for_every_connector(connector):
    summary = build_project_status_summary(
        connector=connector,
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/checkout-service"),
        package_version="0.7.37",
        observed_at="2026-08-04T12:00:00Z",
    )
    assert summary is not None
    payload = summary_to_request_payload(summary)
    assert payload["connector"] == connector
    assert set(payload) == {
        "schema_version",
        "connector",
        "connection_state",
        "route_state",
        "project_display_label",
        "observed_at",
        "package_version",
    }
    assert "connector_version" not in payload
    assert "idempotency_key" not in payload


def test_sync_without_credential_makes_zero_transport_calls():
    transport = BackendEchoTransport()

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=lambda home=None: None,
        transport=transport,
    )

    assert result == "skipped_no_credential"
    assert transport.calls == []


def test_sync_with_unsafe_credential_makes_zero_transport_calls():
    transport = BackendEchoTransport()

    def _bad_load(home=None):
        raise CredentialError("credential_invalid")

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_bad_load,
        transport=transport,
    )

    assert result == "skipped_unsafe_credential"
    assert transport.calls == []


def test_sync_accepts_backend_shaped_response_with_plus_zero_offset():
    transport = BackendEchoTransport()

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/checkout-service"),
        package_version="1.2.3",
        clock=lambda: 1_785_844_800.0,
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )

    assert result == "accepted"
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == f"{CONSOLE_ORIGIN}/console/project-status/ingest"
    assert call["timeout"] == 3.0
    assert call["headers"]["Accept"] == "application/json"
    assert call["headers"]["Content-Type"] == "application/json"
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN}"
    payload = json.loads(call["body"].decode("utf-8"))
    assert payload["project_display_label"] == "checkout-service"
    assert payload["package_version"] == "1.2.3"
    assert payload["observed_at"] == "2026-08-04T12:00:00Z"


def test_clock_is_used_for_observed_at():
    summary = build_project_status_summary(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        clock=lambda: 1_722_787_200.0,
    )
    assert summary is not None
    assert summary.observed_at == "2024-08-04T16:00:00Z"


@pytest.mark.parametrize(
    "observed_at",
    [
        "not-a-timestamp",
        "2026-08-04",
        "2026-08-04T12:00:00",
    ],
)
def test_invalid_observed_at_rejected(observed_at):
    with pytest.raises(ProjectStatusClientError, match="invalid_observed_at"):
        build_project_status_summary(
            connector="codex",
            connector_status=_advisory_status(),
            project_dir=Path("/tmp/project"),
            observed_at=observed_at,
        )


@pytest.mark.parametrize("status_code", [301, 401, 403, 404, 409, 429, 500])
def test_http_failures_return_bounded_outcome(status_code):
    transport = FakeTransport([
        lambda body: _json_response(
            status_code,
            _backend_ingest_response_for_request(body),
        )
    ])
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "unavailable"


def test_transport_error_returns_unavailable():
    transport = FakeTransport([TransportError()])
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "unavailable"


@pytest.mark.parametrize(
    "response",
    [
        _json_response(200, {}, content_type="text/plain"),
        RawResponse(status=200, content_types=("application/json", "application/json"), body=b"{}"),
        RawResponse(status=200, content_types=("application/json",), body=b"[]"),
        RawResponse(status=200, content_types=("application/json",), body=b"{\"extra\":1}"),
        RawResponse(status=200, content_types=("application/json",), body=b"x" * 17000),
    ],
)
def test_malformed_response_fails_softly(response):
    transport = FakeTransport([response])
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "rejected"


def test_wrong_scope_statement_is_rejected():
    transport = FakeTransport([
        lambda body: _json_response(
            200,
            _backend_ingest_response_for_request(
                body,
                scope_statement="wrong scope",
            ),
        )
    ])
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "rejected"


_STRING_RESPONSE_FIELDS = (
    "workspace_id",
    "connector",
    "connection_state",
    "route_state",
    "project_display_label",
    "observed_at",
    "scope_statement",
)
_NON_STRING_VALUES = (
    123,
    True,
    None,
    [],
    {},
)


@pytest.mark.parametrize("field", _STRING_RESPONSE_FIELDS)
@pytest.mark.parametrize("bad_value", _NON_STRING_VALUES)
def test_response_rejects_non_string_field_types(field, bad_value):
    transport = FakeTransport([
        lambda body: _json_response(
            200,
            _backend_ingest_response_for_request(body, **{field: bad_value}),
        )
    ])
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        transport=transport,
        clock=lambda: 1_785_844_800.0,
    )
    assert result == "rejected"


def test_no_retry_on_failure():
    transport = FakeTransport([
        TransportError(),
        lambda body: _json_response(200, _backend_ingest_response_for_request(body)),
    ])
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "unavailable"
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "label",
    [
        "checkout-service",
        "service_v2",
        "A1",
    ],
)
def test_valid_project_display_labels(label):
    assert validate_project_display_label(label) == label


@pytest.mark.parametrize(
    "label",
    [
        "/abs/path",
        "../traversal",
        "has space",
        "secret-project",
        "x" * 129,
        "bad label",
        "\x1f",
    ],
)
def test_invalid_project_display_labels(label):
    assert validate_project_display_label(label) is None


def test_ambiguous_connector_status_skips_before_transport():
    transport = BackendEchoTransport()
    result = sync_project_status(
        connector="codex",
        connector_status={
            "status": "unknown",
            "mcp_route": "present",
            "hook": "present",
            "proxy_route": "present",
        },
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "skipped_ambiguous"
    assert transport.calls == []


def test_disconnected_normalization():
    assert normalize_connector_status({
        "status": "unsafe",
        "mcp_route": "missing",
        "hook": "missing",
        "proxy_route": "missing",
    }) == ("disconnected", "unavailable")


def test_protected_normalization():
    assert normalize_connector_status({
        "status": "protected",
        "mcp_route": "present",
        "hook": "present",
        "proxy_route": "present",
    }) == ("connected", "observed")


def test_privacy_canaries_absent_from_request_json():
    transport = BackendEchoTransport()
    sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        package_version="1.2.3",
        load_credential_fn=lambda home=None: StoredCredential(
            scope=CREDENTIAL_SCOPE,
            token=SECRET,
        ),
        transport=transport,
    )
    encoded = transport.calls[0]["body"].decode("utf-8")
    assert SECRET not in encoded
    assert WORKSPACE_ID not in encoded
    assert "/Users/" not in encoded
    assert "approval" not in encoded.lower()


def test_bounded_dev_package_version_is_included():
    summary = build_project_status_summary(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        package_version="0.0.0+dev",
        observed_at="2026-08-04T12:00:00Z",
    )
    assert summary is not None
    payload = summary_to_request_payload(summary)
    assert payload["package_version"] == "0.0.0+dev"


def test_normalize_package_version_accepts_bounded_prerelease():
    assert normalize_package_version("0.7.37") == "0.7.37"
    assert normalize_package_version("0.0.0+dev") == "0.0.0+dev"
