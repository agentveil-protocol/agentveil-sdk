# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Tests for bounded Console project-status upload client."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCOPE,
    CredentialError,
    StoredCredential,
    save_credential,
)
from agentveil_mcp_proxy.console_project_status_client import (
    CONSOLE_ORIGIN,
    ConsoleProjectStatusClient,
    ProjectStatusClientError,
    ProjectStatusSummary,
    RawResponse,
    TransportError,
    best_effort_spawn_hook_project_status,
    build_project_status_summary,
    normalize_connector_status,
    normalize_package_version,
    resolve_controlled_alternatives_installed_readiness,
    resolve_private_guardrails_status,
    summary_to_request_payload,
    sync_project_status,
    validate_project_display_label,
)
from test_mcp_proxy_paid_install import (
    _build_composed_base_wheel,
    _build_composed_thin_wheel,
)
from agentveil_mcp_proxy.paid_install import (
    COMPOSED_BASE_PACKAGE_NAME,
    COMPOSED_BASE_PACKAGE_VERSION,
    COMPOSED_INSTALL_COMPOSITION_VERSION,
    COMPOSED_THIN_PACKAGE_VERSION,
    COMPONENT_ROLE_BASE,
    COMPONENT_ROLE_THIN,
    DEFAULT_PACKAGE_NAME,
    install_wheel_to_vendor,
    install_state_path,
    vendor_root,
    write_install_state,
)
from agentveil_mcp_proxy.paid_provider import (
    ERROR_CONTRACT_INCOMPATIBLE,
    ERROR_PROVIDER_RESPONSE_INVALID,
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_INVALID,
    STATUS_MISSING,
    STATUS_REVOKED,
    STATUS_WITHIN_GRACE,
    PaidProviderSnapshot,
    absent_provider_snapshot,
)

THIN_PACKAGE_NAME = "agentveil-private-policy-thin"

TOKEN = "console-device-token-secret"
SECRET = "SECRET_PROJECT_STATUS_CANARY"
PROVIDER_ID = "private_v1_canary"
PROVIDER_SUMMARY = "Installed private_v1 bridge with policy prompt"
PROVIDER_ERROR = "provider_response_invalid"
WORKSPACE_ID = "11111111-1111-4111-8111-111111111111"
SCOPE_STATEMENT = "Configured project routes only"


def _active_provider_snapshot(**overrides):
    base = PaidProviderSnapshot(
        provider_present=True,
        provider_id=PROVIDER_ID,
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=STATUS_ACTIVE,
        private_provider_enabled=True,
        public_fallback_available=True,
        summary=PROVIDER_SUMMARY,
        error_code=None,
    )
    if not overrides:
        return base
    return PaidProviderSnapshot(**{**base.__dict__, **overrides})


def _inactive_provider_snapshot(status, **overrides):
    base = PaidProviderSnapshot(
        provider_present=True,
        provider_id=PROVIDER_ID,
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=status,
        private_provider_enabled=False,
        public_fallback_available=True,
        summary=None,
        error_code=None,
    )
    if not overrides:
        return base
    return PaidProviderSnapshot(**{**base.__dict__, **overrides})


def _discover(snapshot):
    return lambda: snapshot


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


class _FakeProcess:
    def wait(self):
        return 0


@pytest.mark.parametrize("connector", ["codex", "claude-code", "cursor", "gemini-cli"])
def test_hook_status_refresh_spawns_bounded_connector_status_worker(
    connector, tmp_path, monkeypatch
):
    project = tmp_path / "project"
    runtime_home = project / (".agentveil" if connector == "cursor" else ".avp")
    runtime_home.mkdir(parents=True)
    monkeypatch.setenv("AVP_HOME", str(runtime_home))
    calls = []
    credential_homes = []

    def _load(home=None):
        credential_homes.append(home)
        return StoredCredential(scope=CREDENTIAL_SCOPE, token=TOKEN)

    def _popen(command, **kwargs):
        calls.append((command, kwargs))
        return _FakeProcess()

    best_effort_spawn_hook_project_status(
        connector=connector,
        project_dir=project,
        runtime_home=runtime_home,
        load_credential_fn=_load,
        popen=_popen,
        clock=lambda: 1000.0,
    )

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:5] == [
        command[0],
        "-m",
        "agentveil_mcp_proxy.cli",
        "setup",
        "status",
    ]
    assert command[5:7] == ["--client", connector]
    path_flag = "--workspace" if connector == "cursor" else "--project-dir"
    assert command[7:9] == [path_flag, str(project.resolve())]
    assert command[-1] == "--json"
    assert kwargs["stdin"] is not None
    assert kwargs["stdout"] is not None
    assert kwargs["stderr"] is not None
    assert kwargs["start_new_session"] is True
    assert "AVP_HOME" not in kwargs["env"]
    assert kwargs["env"]["AGENTVEIL_HOOK_STATUS_REFRESH_WORKER"] == "1"
    assert credential_homes == [Path("~/.avp").expanduser()]
    assert (runtime_home / ".console-hook-status-refresh").stat().st_mode & 0o777 == 0o600


def test_hook_status_refresh_requires_credential_and_throttles(tmp_path):
    project = tmp_path / "project"
    runtime_home = project / ".avp"
    runtime_home.mkdir(parents=True)
    calls = []

    best_effort_spawn_hook_project_status(
        connector="codex",
        project_dir=project,
        runtime_home=runtime_home,
        load_credential_fn=lambda home=None: None,
        popen=lambda *args, **kwargs: calls.append(1),
    )
    assert calls == []

    def popen(*args, **kwargs):
        calls.append(1)
        return _FakeProcess()

    best_effort_spawn_hook_project_status(
        connector="codex",
        project_dir=project,
        runtime_home=runtime_home,
        load_credential_fn=_load_credential_ok,
        popen=popen,
    )
    best_effort_spawn_hook_project_status(
        connector="codex",
        project_dir=project,
        runtime_home=runtime_home,
        load_credential_fn=_load_credential_ok,
        popen=popen,
    )
    assert calls == [1]


def test_hook_status_refresh_spawn_failure_isolated_and_retryable(tmp_path):
    project = tmp_path / "project"
    runtime_home = project / ".avp"
    runtime_home.mkdir(parents=True)

    def _failed_popen(*args, **kwargs):
        raise OSError("bounded test failure")

    best_effort_spawn_hook_project_status(
        connector="codex",
        project_dir=project,
        runtime_home=runtime_home,
        load_credential_fn=_load_credential_ok,
        popen=_failed_popen,
    )

    assert not (runtime_home / ".console-hook-status-refresh").exists()


@pytest.mark.parametrize("connector", ["codex", "claude-code", "cursor", "gemini-cli"])
def test_build_summary_for_every_connector(connector):
    summary = build_project_status_summary(
        connector=connector,
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/checkout-service"),
        package_version="0.7.37",
        observed_at="2026-08-04T12:00:00Z",
        private_guardrails_status="unavailable",
    )
    assert summary is not None
    payload = summary_to_request_payload(summary)
    assert payload["connector"] == connector
    assert payload["private_guardrails_status"] == "unavailable"
    assert set(payload) == {
        "schema_version",
        "connector",
        "connection_state",
        "route_state",
        "project_display_label",
        "observed_at",
        "package_version",
        "private_guardrails_status",
    }
    assert "connector_version" not in payload
    assert "idempotency_key" not in payload
    assert "provider_id" not in payload


def test_sync_without_credential_makes_zero_transport_calls():
    transport = BackendEchoTransport()
    discovery_calls = []

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=lambda home=None: None,
        discover_paid_provider_fn=lambda: discovery_calls.append(1) or _active_provider_snapshot(),
        transport=transport,
    )

    assert result == "skipped_no_credential"
    assert transport.calls == []
    assert discovery_calls == []


@pytest.mark.parametrize("status", [401, 403])
def test_sync_reports_rejected_console_credential(status):
    transport = FakeTransport([
        RawResponse(
            status=status,
            content_types=("application/json",),
            body=b'{}',
        )
    ])

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        discover_paid_provider_fn=_discover(absent_provider_snapshot()),
        transport=transport,
    )

    assert result == "credential_rejected"


def test_sync_with_unsafe_credential_makes_zero_transport_calls():
    transport = BackendEchoTransport()
    discovery_calls = []

    def _bad_load(home=None):
        raise CredentialError("credential_invalid")

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_bad_load,
        discover_paid_provider_fn=lambda: discovery_calls.append(1) or _active_provider_snapshot(),
        transport=transport,
    )

    assert result == "skipped_unsafe_credential"
    assert transport.calls == []
    assert discovery_calls == []


def test_sync_accepts_backend_shaped_response_with_plus_zero_offset():
    transport = BackendEchoTransport()

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/checkout-service"),
        package_version="1.2.3",
        clock=lambda: 1_785_844_800.0,
        load_credential_fn=_load_credential_ok,
        discover_paid_provider_fn=_discover(_active_provider_snapshot()),
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
    assert payload["private_guardrails_status"] == "active"


def test_clock_is_used_for_observed_at():
    summary = build_project_status_summary(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        private_guardrails_status="unavailable",
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
            private_guardrails_status="unavailable",
            observed_at=observed_at,
        )


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (301, "unavailable"),
        (401, "credential_rejected"),
        (403, "credential_rejected"),
        (404, "unavailable"),
        (409, "unavailable"),
        (429, "unavailable"),
        (500, "unavailable"),
    ],
)
def test_http_failures_return_bounded_outcome(status_code, expected):
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
    assert result == expected


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


def test_bounded_dev_package_version_is_included():
    summary = build_project_status_summary(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        package_version="0.0.0+dev",
        observed_at="2026-08-04T12:00:00Z",
        private_guardrails_status="inactive",
    )
    assert summary is not None
    payload = summary_to_request_payload(summary)
    assert payload["package_version"] == "0.0.0+dev"
    assert payload["private_guardrails_status"] == "inactive"


def test_normalize_package_version_accepts_bounded_prerelease():
    assert normalize_package_version("0.7.37") == "0.7.37"
    assert normalize_package_version("0.0.0+dev") == "0.0.0+dev"


def test_resolve_active_provider_snapshot():
    assert resolve_private_guardrails_status(_active_provider_snapshot()) == "active"


@pytest.mark.parametrize("status", [STATUS_EXPIRED, STATUS_REVOKED, STATUS_DISABLED])
def test_resolve_explicit_inactive_provider_snapshot(status):
    assert (
        resolve_private_guardrails_status(_inactive_provider_snapshot(status))
        == "inactive"
    )


@pytest.mark.parametrize(
    "snapshot",
    [
        absent_provider_snapshot(),
        absent_provider_snapshot(error_code=ERROR_PROVIDER_RESPONSE_INVALID),
        _active_provider_snapshot(provider_present=False, status=STATUS_MISSING),
        _active_provider_snapshot(status=STATUS_MISSING),
        _active_provider_snapshot(status=STATUS_ERROR, error_code=ERROR_PROVIDER_RESPONSE_INVALID),
        _active_provider_snapshot(status=STATUS_INVALID),
        _active_provider_snapshot(status=STATUS_WITHIN_GRACE),
        _active_provider_snapshot(
            provider_contract_version="2",
            error_code=ERROR_CONTRACT_INCOMPATIBLE,
        ),
        _active_provider_snapshot(private_provider_enabled=False),
        _inactive_provider_snapshot(STATUS_EXPIRED, private_provider_enabled=True),
        _inactive_provider_snapshot(STATUS_REVOKED, error_code=PROVIDER_ERROR),
    ],
)
def test_resolve_unavailable_provider_snapshots(snapshot):
    assert resolve_private_guardrails_status(snapshot) == "unavailable"


def test_discovery_exception_maps_to_unavailable_and_does_not_raise():
    transport = BackendEchoTransport()

    def _explode():
        raise RuntimeError("discovery must not leak")

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        discover_paid_provider_fn=_explode,
        transport=transport,
    )

    assert result == "accepted"
    payload = json.loads(transport.calls[0]["body"].decode("utf-8"))
    assert payload["private_guardrails_status"] == "unavailable"
    assert "discovery must not leak" not in json.dumps(payload)


@pytest.mark.parametrize("bad_snapshot", [None, {"status": "active"}, object()])
def test_malformed_discovery_result_maps_to_unavailable(bad_snapshot):
    transport = BackendEchoTransport()

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        discover_paid_provider_fn=lambda: bad_snapshot,
        transport=transport,
    )

    assert result == "accepted"
    payload = json.loads(transport.calls[0]["body"].decode("utf-8"))
    assert payload["private_guardrails_status"] == "unavailable"


@pytest.mark.parametrize("bad_value", ["enabled", "ACTIVE", "", "active "])
def test_build_summary_rejects_non_allowlisted_local_report(bad_value):
    with pytest.raises(ProjectStatusClientError, match="invalid_private_guardrails_status"):
        build_project_status_summary(
            connector="codex",
            connector_status=_advisory_status(),
            project_dir=Path("/tmp/project"),
            private_guardrails_status=bad_value,
        )


def _manual_summary(*, private_guardrails_status):
    return ProjectStatusSummary(
        schema_version="1",
        connector="codex",
        connection_state="connected",
        route_state="advisory",
        project_display_label="project",
        observed_at="2026-08-04T12:00:00Z",
        private_guardrails_status=private_guardrails_status,
    )


@pytest.mark.parametrize("bad_value", [None, True, 123, [], {}])
def test_summary_to_request_payload_rejects_non_string_local_report(bad_value):
    with pytest.raises(ProjectStatusClientError, match="invalid_private_guardrails_status"):
        summary_to_request_payload(_manual_summary(private_guardrails_status=bad_value))


def test_response_with_eighth_local_report_field_is_rejected():
    transport = FakeTransport([
        lambda body: _json_response(
            200,
            {
                **_backend_ingest_response_for_request(body),
                "private_guardrails_status": "active",
            },
        )
    ])
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        discover_paid_provider_fn=_discover(_active_provider_snapshot()),
        transport=transport,
    )
    assert result == "rejected"


def test_provider_failure_does_not_raise_from_sync():
    transport = BackendEchoTransport()

    def _explode():
        raise RuntimeError("boom")

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        load_credential_fn=_load_credential_ok,
        discover_paid_provider_fn=_explode,
        transport=transport,
    )
    assert result in {"accepted", "rejected", "unavailable"}


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
        discover_paid_provider_fn=_discover(_active_provider_snapshot(
            summary="policy prompt command /Users/me/secret",
            error_code=PROVIDER_ERROR,
        )),
        transport=transport,
    )
    encoded = transport.calls[0]["body"].decode("utf-8")
    for forbidden in (
        SECRET,
        WORKSPACE_ID,
        PROVIDER_ID,
        PROVIDER_SUMMARY,
        PROVIDER_ERROR,
        "/Users/",
        "approval",
        "policy",
        "prompt",
        "command",
    ):
        assert forbidden not in encoded
    payload = json.loads(encoded)
    assert set(payload.keys()) <= {
        "schema_version",
        "connector",
        "connection_state",
        "route_state",
        "project_display_label",
        "observed_at",
        "package_version",
        "private_guardrails_status",
        "controlled_alternatives_status",
        "controlled_alternatives_package_version",
    }
    assert payload["private_guardrails_status"] == "unavailable"


@pytest.mark.parametrize("runtime_name", [".avp", ".agentveil"])
def test_sync_symlink_project_runtime_home_skips_before_credential_and_network(
    tmp_path,
    monkeypatch,
    runtime_name,
):
    global_home = tmp_path / "global.avp"
    global_home.mkdir()
    project_home = tmp_path / "project" / runtime_name
    project_home.parent.mkdir(parents=True)
    project_home.symlink_to(global_home)
    project = tmp_path / "project"
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_credentials._global_console_credential_home",
        lambda: global_home,
    )
    save_credential(TOKEN, home=global_home)
    credential_homes: list[Path | None] = []
    provider_homes: list[Path | None] = []

    def _load_credential(*, home=None):
        credential_homes.append(home)
        return StoredCredential(scope=CREDENTIAL_SCOPE, token=TOKEN)

    def _discover(*, home=None):
        provider_homes.append(home)
        return absent_provider_snapshot()

    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        _discover,
    )
    transport = BackendEchoTransport()

    result = sync_project_status(
        connector="codex" if runtime_name == ".avp" else "cursor",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=project_home,
        load_credential_fn=_load_credential,
        transport=transport,
    )

    assert result == "skipped_unsafe_runtime_home"
    assert credential_homes == []
    assert provider_homes == []
    assert len(transport.calls) == 0


def test_sync_project_status_separates_credential_and_provider_homes(
    tmp_path,
    monkeypatch,
):
    global_home = tmp_path / "global.avp"
    global_home.mkdir()
    project_home = tmp_path / "project" / ".avp"
    project_home.mkdir(parents=True)
    project = tmp_path / "project"
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_credentials._global_console_credential_home",
        lambda: global_home,
    )
    save_credential(TOKEN, home=global_home)

    credential_homes: list[Path | None] = []
    provider_homes: list[Path | None] = []

    def _load_credential(*, home=None):
        credential_homes.append(home)
        return StoredCredential(scope=CREDENTIAL_SCOPE, token=TOKEN)

    def _discover(*, home=None):
        provider_homes.append(home)
        return absent_provider_snapshot()

    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        _discover,
    )
    transport = BackendEchoTransport()

    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=project_home,
        load_credential_fn=_load_credential,
        transport=transport,
    )

    assert result == "accepted"
    assert credential_homes == [global_home]
    assert provider_homes == [project_home]
    payload = json.loads(transport.calls[0]["body"].decode("utf-8"))
    assert payload["private_guardrails_status"] == "unavailable"


def test_sync_project_status_cursor_home_uses_global_credential(
    tmp_path,
    monkeypatch,
):
    global_home = tmp_path / "global.avp"
    global_home.mkdir()
    project_home = tmp_path / "project" / ".agentveil"
    project_home.mkdir(parents=True)
    project = tmp_path / "project"
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_credentials._global_console_credential_home",
        lambda: global_home,
    )
    save_credential(TOKEN, home=global_home)

    credential_homes: list[Path | None] = []

    def _load_credential(*, home=None):
        credential_homes.append(home)
        return StoredCredential(scope=CREDENTIAL_SCOPE, token=TOKEN)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        lambda *, home=None: absent_provider_snapshot(),
    )
    transport = BackendEchoTransport()

    result = sync_project_status(
        connector="cursor",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=project_home,
        load_credential_fn=_load_credential,
        transport=transport,
    )

    assert result == "accepted"
    assert credential_homes == [global_home]


def _install_verified_composed_ca_home(home: Path, tmp_path: Path) -> None:
    base_wheel, _ = _build_composed_base_wheel(tmp_path / "wheel-base")
    thin_wheel, _ = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    install_wheel_to_vendor(
        home=home,
        wheel_path=base_wheel,
        target_dir=vendor_root(home)
        / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}",
        expected_package_name=COMPOSED_BASE_PACKAGE_NAME,
        expected_package_version=COMPOSED_BASE_PACKAGE_VERSION,
        require_empty_target=True,
    )
    install_wheel_to_vendor(
        home=home,
        wheel_path=thin_wheel,
        target_dir=vendor_root(home)
        / f"{THIN_PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}",
        expected_package_name=THIN_PACKAGE_NAME,
        expected_package_version=COMPOSED_THIN_PACKAGE_VERSION,
        require_empty_target=True,
    )
    write_install_state(
        install_state_path(home),
        {
            "status": STATUS_ACTIVE,
            "provider_id": "private_v1",
            "package_name": COMPOSED_BASE_PACKAGE_NAME,
            "package_version": COMPOSED_BASE_PACKAGE_VERSION,
            "public_fallback_available": True,
            "error_code": None,
            "last_installed_at": "2026-08-08T12:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
            "install_composition_version": COMPOSED_INSTALL_COMPOSITION_VERSION,
            "install_components": [
                {
                    "role": COMPONENT_ROLE_BASE,
                    "package_name": COMPOSED_BASE_PACKAGE_NAME,
                    "package_version": COMPOSED_BASE_PACKAGE_VERSION,
                },
                {
                    "role": COMPONENT_ROLE_THIN,
                    "package_name": THIN_PACKAGE_NAME,
                    "package_version": COMPOSED_THIN_PACKAGE_VERSION,
                },
            ],
        },
    )


@pytest.mark.parametrize("connector", ["codex", "claude-code", "cursor", "gemini-cli"])
def test_verified_paired_install_reports_controlled_alternatives_installed_ready(
    connector,
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    home.mkdir()
    project = tmp_path / "checkout-service"
    project.mkdir()
    _install_verified_composed_ca_home(home, tmp_path)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        lambda *, home=None: absent_provider_snapshot(),
    )
    transport = BackendEchoTransport()

    result = sync_project_status(
        connector=connector,
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=home,
        load_credential_fn=_load_credential_ok,
        transport=transport,
        clock=lambda: 1_785_844_800.0,
    )

    assert result == "accepted"
    payload = json.loads(transport.calls[0]["body"].decode("utf-8"))
    assert payload["connector"] == connector
    assert payload["controlled_alternatives_status"] == "installed_ready"
    assert payload["controlled_alternatives_package_version"] == COMPOSED_THIN_PACKAGE_VERSION
    assert set(payload.keys()) == {
        "schema_version",
        "connector",
        "connection_state",
        "route_state",
        "project_display_label",
        "observed_at",
        "private_guardrails_status",
        "controlled_alternatives_status",
        "controlled_alternatives_package_version",
    }


def test_installed_ready_payload_carries_only_bounded_readiness_metadata(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    home.mkdir()
    project = tmp_path / "checkout-service"
    project.mkdir()
    _install_verified_composed_ca_home(home, tmp_path)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        lambda *, home=None: absent_provider_snapshot(),
    )
    transport = BackendEchoTransport()
    sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=home,
        load_credential_fn=lambda home=None: StoredCredential(
            scope=CREDENTIAL_SCOPE,
            token=SECRET,
        ),
        transport=transport,
        clock=lambda: 1_785_844_800.0,
    )
    encoded = transport.calls[0]["body"].decode("utf-8")
    payload = json.loads(encoded)
    assert payload["controlled_alternatives_status"] == "installed_ready"
    assert (
        payload["controlled_alternatives_package_version"]
        == COMPOSED_THIN_PACKAGE_VERSION
    )
    assert set(payload.keys()) == {
        "schema_version",
        "connector",
        "connection_state",
        "route_state",
        "project_display_label",
        "observed_at",
        "private_guardrails_status",
        "controlled_alternatives_status",
        "controlled_alternatives_package_version",
    }
    assert all(isinstance(value, str) for value in payload.values())
    for forbidden in (
        SECRET,
        TOKEN,
        str(home),
        str(project.resolve()),
        "private_v1",
        PROVIDER_ID,
        "controlled_provider",
        "authority",
        "provider_id",
        "install_components",
        "sha256",
        "hash",
        '"controlled_alternatives_status": "active"',
        '"controlled_alternatives_status":"active"',
    ):
        assert forbidden not in encoded


def test_project_status_summary_preserves_active_only_heartbeat_contract():
    with pytest.raises(
        ProjectStatusClientError,
        match="invalid_controlled_alternatives_status",
    ):
        build_project_status_summary(
            connector="codex",
            connector_status=_advisory_status(),
            project_dir=Path("/tmp/project"),
            private_guardrails_status="unavailable",
            controlled_alternatives_status="active",
            controlled_alternatives_package_version="0.1.4",
        )
    summary = build_project_status_summary(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/project"),
        private_guardrails_status="active",
        controlled_alternatives_status="installed_ready",
        controlled_alternatives_package_version="0.1.4",
    )
    assert summary is not None
    payload = summary_to_request_payload(summary)
    assert payload["private_guardrails_status"] == "active"
    assert payload["controlled_alternatives_status"] == "installed_ready"
    assert payload["controlled_alternatives_status"] != "active"


@pytest.mark.parametrize(
    "patch_target",
    [
        "agentveil_mcp_proxy.paid_install.resolve_vendored_controlled_alternative_provider",
        "agentveil_mcp_proxy.paid_install.resolve_vendored_controlled_alternative_authority",
    ],
)
def test_incomplete_or_untrusted_ca_install_omits_readiness_fields(
    tmp_path,
    monkeypatch,
    patch_target,
):
    home = tmp_path / "avp-home"
    home.mkdir()
    project = tmp_path / "checkout-service"
    project.mkdir()
    _install_verified_composed_ca_home(home, tmp_path)

    def _fail(*args, **kwargs):
        return None, "vendored_provider_missing"

    monkeypatch.setattr(patch_target, _fail)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        lambda *, home=None: absent_provider_snapshot(),
    )
    transport = BackendEchoTransport()
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=home,
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "accepted"
    payload = json.loads(transport.calls[0]["body"].decode("utf-8"))
    assert "controlled_alternatives_status" not in payload
    assert "controlled_alternatives_package_version" not in payload


def test_missing_base_vendor_omits_ca_readiness_when_thin_and_metadata_intact(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    home.mkdir()
    project = tmp_path / "checkout-service"
    project.mkdir()
    _install_verified_composed_ca_home(home, tmp_path)
    base_vendor = (
        vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}"
    )
    shutil.rmtree(base_vendor)
    assert base_vendor.exists() is False
    assert resolve_controlled_alternatives_installed_readiness(home=home) is None
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        lambda *, home=None: absent_provider_snapshot(),
    )
    transport = BackendEchoTransport()
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=home,
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "accepted"
    payload = json.loads(transport.calls[0]["body"].decode("utf-8"))
    assert "controlled_alternatives_status" not in payload
    assert "controlled_alternatives_package_version" not in payload


def test_legacy_install_state_omits_ca_fields_when_resolvers_succeed(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    home.mkdir()
    project = tmp_path / "checkout-service"
    project.mkdir()
    _install_verified_composed_ca_home(home, tmp_path)
    assert resolve_controlled_alternatives_installed_readiness(home=home) is not None
    write_install_state(
        install_state_path(home),
        {
            "status": STATUS_ACTIVE,
            "provider_id": "private_v1",
            "package_name": DEFAULT_PACKAGE_NAME,
            "package_version": COMPOSED_THIN_PACKAGE_VERSION,
            "public_fallback_available": True,
            "error_code": None,
            "last_installed_at": "2026-08-08T12:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
        },
    )
    assert resolve_controlled_alternatives_installed_readiness(home=home) is None
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        lambda *, home=None: absent_provider_snapshot(),
    )
    transport = BackendEchoTransport()
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=home,
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "accepted"
    payload = json.loads(transport.calls[0]["body"].decode("utf-8"))
    assert "controlled_alternatives_status" not in payload
    assert "controlled_alternatives_package_version" not in payload


def test_incomplete_or_untrusted_ca_install_omits_readiness_on_resolver_exception(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    home.mkdir()
    project = tmp_path / "checkout-service"
    project.mkdir()

    def _explode(*args, **kwargs):
        raise RuntimeError("resolver must not leak")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.paid_install.resolve_vendored_controlled_alternative_provider",
        _explode,
    )
    transport = BackendEchoTransport()
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=home,
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    assert result == "accepted"
    payload = json.loads(transport.calls[0]["body"].decode("utf-8"))
    assert "controlled_alternatives_status" not in payload


def test_installed_ready_report_does_not_serialize_provider_authority_or_paths(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    home.mkdir()
    project = tmp_path / "checkout-service"
    project.mkdir()
    _install_verified_composed_ca_home(home, tmp_path)
    assert resolve_controlled_alternatives_installed_readiness(home=home) is not None
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        lambda *, home=None: absent_provider_snapshot(),
    )
    transport = BackendEchoTransport()
    sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=home,
        load_credential_fn=_load_credential_ok,
        transport=transport,
    )
    encoded = transport.calls[0]["body"].decode("utf-8")
    assert str(home) not in encoded
    assert "controlled_provider" not in encoded
    assert "private_v1" not in encoded
    assert "agentveil-private-policy" not in encoded
    assert "vendored" not in encoded
    assert "authority" not in encoded.lower()
    payload = json.loads(encoded)
    assert payload["controlled_alternatives_status"] == "installed_ready"
    assert payload["controlled_alternatives_package_version"] == COMPOSED_THIN_PACKAGE_VERSION


def _installed_ready_summary(*, private_guardrails_status="unavailable", package_version=None):
    return build_project_status_summary(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=Path("/tmp/checkout-service"),
        package_version=package_version,
        private_guardrails_status=private_guardrails_status,
        controlled_alternatives_status="installed_ready",
        controlled_alternatives_package_version=COMPOSED_THIN_PACKAGE_VERSION,
        observed_at="2026-08-04T12:00:00Z",
    )


def test_readiness_unsupported_retries_once_without_ca_fields():
    summary = _installed_ready_summary()
    assert summary is not None
    transport = FakeTransport([
        RawResponse(status=400, content_types=("application/json",), body=b"{}"),
        lambda body: _json_response(200, _backend_ingest_response_for_request(body)),
    ])
    client = ConsoleProjectStatusClient(transport=transport)
    client.upload(summary, bearer_token=TOKEN)
    assert len(transport.calls) == 2
    first = json.loads(transport.calls[0]["body"].decode("utf-8"))
    second = json.loads(transport.calls[1]["body"].decode("utf-8"))
    assert first["controlled_alternatives_status"] == "installed_ready"
    assert "controlled_alternatives_status" not in second
    assert "controlled_alternatives_package_version" not in second


def test_new_server_accepts_readiness_without_fallback_retry(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    home.mkdir()
    project = tmp_path / "checkout-service"
    project.mkdir()
    _install_verified_composed_ca_home(home, tmp_path)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        lambda *, home=None: absent_provider_snapshot(),
    )
    transport = BackendEchoTransport()
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=home,
        load_credential_fn=_load_credential_ok,
        transport=transport,
        clock=lambda: 1_785_844_800.0,
    )
    assert result == "accepted"
    assert len(transport.calls) == 1
    payload = json.loads(transport.calls[0]["body"].decode("utf-8"))
    assert payload["controlled_alternatives_status"] == "installed_ready"


def test_old_server_fallback_preserves_ordinary_project_status_payload():
    summary = _installed_ready_summary(
        private_guardrails_status="active",
        package_version="1.2.3",
    )
    assert summary is not None
    transport = FakeTransport([
        RawResponse(status=400, content_types=("application/json",), body=b"{}"),
        lambda body: _json_response(200, _backend_ingest_response_for_request(body)),
    ])
    client = ConsoleProjectStatusClient(transport=transport)
    client.upload(summary, bearer_token=TOKEN)
    first = json.loads(transport.calls[0]["body"].decode("utf-8"))
    second = json.loads(transport.calls[1]["body"].decode("utf-8"))
    ordinary_keys = {
        "schema_version",
        "connector",
        "connection_state",
        "route_state",
        "project_display_label",
        "observed_at",
        "private_guardrails_status",
        "package_version",
    }
    assert ordinary_keys.issubset(first)
    assert ordinary_keys.issubset(second)
    for key in ordinary_keys:
        assert second[key] == first[key]
    assert second["observed_at"] == "2026-08-04T12:00:00Z"


@pytest.mark.parametrize(
    "response_item",
    [
        RawResponse(status=401, content_types=("application/json",), body=b"{}"),
        RawResponse(status=403, content_types=("application/json",), body=b"{}"),
        RawResponse(status=409, content_types=("application/json",), body=b"{}"),
        RawResponse(status=413, content_types=("application/json",), body=b"{}"),
        RawResponse(status=415, content_types=("application/json",), body=b"{}"),
        RawResponse(status=500, content_types=("application/json",), body=b"{}"),
        RawResponse(status=301, content_types=("application/json",), body=b"{}"),
        TransportError(),
        _json_response(200, {}, content_type="text/plain"),
    ],
)
def test_readiness_fallback_does_not_retry_auth_conflict_or_server_failures(
    response_item,
):
    summary = _installed_ready_summary()
    assert summary is not None
    transport = FakeTransport([
        response_item,
        lambda body: _json_response(200, _backend_ingest_response_for_request(body)),
    ])
    client = ConsoleProjectStatusClient(transport=transport)
    with pytest.raises(ProjectStatusClientError):
        client.upload(summary, bearer_token=TOKEN)
    assert len(transport.calls) == 1


def test_readiness_fallback_never_serializes_private_or_credential_fields(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    home.mkdir()
    project = tmp_path / "checkout-service"
    project.mkdir()
    _install_verified_composed_ca_home(home, tmp_path)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.discover_paid_provider",
        lambda *, home=None: _active_provider_snapshot(
            summary="policy prompt command /Users/me/secret",
            error_code=PROVIDER_ERROR,
        ),
    )
    transport = FakeTransport([
        RawResponse(status=400, content_types=("application/json",), body=b"{}"),
        lambda body: _json_response(200, _backend_ingest_response_for_request(body)),
    ])
    result = sync_project_status(
        connector="codex",
        connector_status=_advisory_status(),
        project_dir=project,
        runtime_home=home,
        load_credential_fn=lambda home=None: StoredCredential(
            scope=CREDENTIAL_SCOPE,
            token=SECRET,
        ),
        transport=transport,
        clock=lambda: 1_785_844_800.0,
    )
    assert result == "accepted"
    assert len(transport.calls) == 2
    for call in transport.calls:
        encoded = call["body"].decode("utf-8")
        for forbidden in (
            SECRET,
            WORKSPACE_ID,
            PROVIDER_ID,
            PROVIDER_SUMMARY,
            PROVIDER_ERROR,
            "/Users/",
            "approval",
            "policy",
            "prompt",
            "command",
            str(home),
            "private_v1",
            "authority",
            "provider_id",
        ):
            assert forbidden not in encoded
        payload = json.loads(encoded)
        assert payload.get("controlled_alternatives_status") != "active"
        assert set(payload.keys()) <= {
            "schema_version",
            "connector",
            "connection_state",
            "route_state",
            "project_display_label",
            "observed_at",
            "package_version",
            "private_guardrails_status",
            "controlled_alternatives_status",
            "controlled_alternatives_package_version",
        }
    fallback = json.loads(transport.calls[1]["body"].decode("utf-8"))
    assert "controlled_alternatives_status" not in fallback
    assert "controlled_alternatives_package_version" not in fallback


def test_readiness_fallback_does_not_retry_twice_on_repeated_400():
    summary = _installed_ready_summary()
    assert summary is not None
    transport = FakeTransport([
        RawResponse(status=400, content_types=("application/json",), body=b"{}"),
        RawResponse(status=400, content_types=("application/json",), body=b"{}"),
    ])
    client = ConsoleProjectStatusClient(transport=transport)
    with pytest.raises(ProjectStatusClientError, match="unexpected_status"):
        client.upload(summary, bearer_token=TOKEN)
    assert len(transport.calls) == 2
