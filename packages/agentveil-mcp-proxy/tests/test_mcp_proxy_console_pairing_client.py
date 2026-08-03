# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Wire-contract tests for the Console pairing client."""

from __future__ import annotations

import json

import pytest

from agentveil_mcp_proxy.console_pairing_client import (
    CONSOLE_ORIGIN,
    ConsolePairingClient,
    PairingClientError,
    RawResponse,
    RevokeOutcome,
    TransportError,
    _NoRedirectHandler,
)

DEVICE_CODE = "device-code-secret-xyz"
USER_CODE = "WXYZ-1234"
TOKEN = "confirmed-device-token-secret"


def _json_response(status, obj, *, content_type="application/json"):
    body = json.dumps(obj).encode("utf-8")
    content_types = () if content_type is None else (content_type,)
    return RawResponse(status=status, content_types=content_types, body=body)


def _raw(status, body_bytes, *, content_types=("application/json",)):
    return RawResponse(status=status, content_types=content_types, body=body_bytes)


def _start_payload(**overrides):
    payload = {
        "device_code": DEVICE_CODE,
        "user_code": USER_CODE,
        "verification_uri": "/console/pairing",
        "expires_in": 600,
        "interval": 5,
    }
    payload.update(overrides)
    return payload


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
            return item()
        return item


class PendingTransport:
    """Return pending consume responses for bounded polling proof."""

    def __init__(self):
        self.calls = 0

    def __call__(self, method, url, *, headers, body, timeout):
        self.calls += 1
        return _json_response(200, {"status": "pending"})


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _client(responses, clock=None):
    clk = clock or FakeClock()
    return ConsolePairingClient(
        transport=FakeTransport(responses),
        clock=clk,
        sleeper=clk.sleep,
    )


# --- start positives -------------------------------------------------------


def test_start_success_resolves_fixed_origin_url():
    transport = FakeTransport([_json_response(200, _start_payload())])
    client = ConsolePairingClient(transport=transport)

    start = client.start()

    assert start.verification_url == f"{CONSOLE_ORIGIN}/console/pairing"
    assert start.user_code == USER_CODE
    assert start.device_code == DEVICE_CODE
    assert start.expires_in == 600
    assert start.interval == 5
    call = transport.calls[0]
    assert call["url"] == f"{CONSOLE_ORIGIN}/console/pairing/start"
    assert call["method"] == "POST"
    assert call["headers"]["Accept"] == "application/json"


# --- start negatives -------------------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 429, 500, 503])
def test_start_non_200_status_fails_closed(status):
    client = _client([_json_response(status, _start_payload())])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "unexpected_status"


def test_start_transport_failure_is_bounded():
    client = _client([TransportError()])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "transport_failed"


def test_start_rejects_non_json_content_type():
    client = _client(
        [_json_response(200, _start_payload(), content_type="text/html")]
    )
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "bad_content_type"


def test_start_rejects_duplicate_content_type():
    client = _client(
        [
            RawResponse(
                status=200,
                content_types=("application/json", "application/json"),
                body=json.dumps(_start_payload()).encode("utf-8"),
            )
        ]
    )
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "bad_content_type"


def test_start_rejects_missing_content_type():
    client = _client([_json_response(200, _start_payload(), content_type=None)])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "bad_content_type"


def test_start_rejects_oversized_body():
    client = _client([_raw(200, b"{" + b" " * (16 * 1024 + 1))])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "response_too_large"


def test_start_rejects_non_object_body():
    client = _client([_raw(200, b"[1, 2, 3]")])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "malformed_body"


@pytest.mark.parametrize(
    "overrides",
    [
        {"extra": "field"},
        {"device_code": ""},
        {"device_code": 123},
        {"user_code": ""},
    ],
)
def test_start_rejects_malformed_fields(overrides):
    client = _client([_json_response(200, _start_payload(**overrides))])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "malformed_start"


def test_start_rejects_missing_field():
    payload = _start_payload()
    del payload["interval"]
    client = _client([_json_response(200, payload)])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "malformed_start"


@pytest.mark.parametrize(
    "expires_in",
    [0, -1, True, 10 ** 9, "600", 1.5],
)
def test_start_rejects_bad_expires_in(expires_in):
    client = _client([_json_response(200, _start_payload(expires_in=expires_in))])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "malformed_start"


@pytest.mark.parametrize(
    "interval",
    [0, -1, True, 10 ** 9, "5"],
)
def test_start_rejects_bad_interval(interval):
    client = _client([_json_response(200, _start_payload(interval=interval))])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "malformed_start"


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.example/console/pairing",
        "//evil.example/console/pairing",
        "http://agentveil.dev/console/pairing",
        "/console/pairing?next=https://evil.example",
        "/console/pairing#frag",
        "https://user:pass@agentveil.dev/console/pairing",
        "console/pairing",
        "/path/with@userinfo",
        123,
        "",
    ],
)
def test_start_rejects_malicious_verification_uri(uri):
    client = _client([_json_response(200, _start_payload(verification_uri=uri))])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code in {"bad_verification_uri", "malformed_start"}


# --- poll / consume --------------------------------------------------------


def test_poll_pending_then_confirmed_returns_token():
    clock = FakeClock()
    transport = FakeTransport(
        [
            _json_response(200, {"status": "pending"}),
            _json_response(
                200,
                {"status": "confirmed", "token": TOKEN, "scope": "bounded_summary_upload"},
            ),
        ]
    )
    client = ConsolePairingClient(
        transport=transport, clock=clock, sleeper=clock.sleep
    )
    start = _start(_start_payload())

    result = client.poll_for_token(start)

    assert result.token == TOKEN
    assert result.scope == "bounded_summary_upload"
    consume_call = transport.calls[0]
    assert consume_call["url"] == f"{CONSOLE_ORIGIN}/console/pairing/consume"
    assert json.loads(consume_call["body"]) == {"device_code": DEVICE_CODE}
    assert clock.now > 0  # a bounded sleep occurred between pending and confirm


def test_poll_is_bounded_and_never_runs_forever():
    clock = FakeClock()
    transport = PendingTransport()
    client = ConsolePairingClient(
        transport=transport, clock=clock, sleeper=clock.sleep
    )
    start = _start(_start_payload(expires_in=10, interval=5))

    with pytest.raises(PairingClientError) as exc:
        client.poll_for_token(start)

    assert exc.value.code == "expired"
    assert transport.calls <= 5


@pytest.mark.parametrize("status", [400, 409, 500, 503])
def test_poll_non_200_fails_closed(status):
    client = _client([_json_response(status, {"status": "pending"})])
    with pytest.raises(PairingClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert exc.value.code == "unexpected_status"


def test_poll_unknown_status_fails_closed():
    client = _client([_json_response(200, {"status": "elsewhere"})])
    with pytest.raises(PairingClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert exc.value.code == "unexpected_status"


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "confirmed", "scope": "bounded_summary_upload"},
        {"status": "confirmed", "token": "", "scope": "bounded_summary_upload"},
        {"status": "confirmed", "token": TOKEN, "scope": "bounded_summary_upload", "x": 1},
    ],
)
def test_poll_confirmed_malformed_fails_closed(payload):
    client = _client([_json_response(200, payload)])
    with pytest.raises(PairingClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert exc.value.code == "malformed_consume"


def test_poll_confirmed_wrong_scope_fails_closed():
    client = _client(
        [_json_response(200, {"status": "confirmed", "token": TOKEN, "scope": "other"})]
    )
    with pytest.raises(PairingClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert exc.value.code == "unexpected_scope"


def test_poll_pending_malformed_fails_closed():
    client = _client([_json_response(200, {"status": "pending", "x": 1})])
    with pytest.raises(PairingClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert exc.value.code == "malformed_consume"


# --- revoke ----------------------------------------------------------------


def test_revoke_success_returns_revoked_and_sends_bearer():
    transport = FakeTransport([_json_response(200, {"status": "revoked"})])
    client = ConsolePairingClient(transport=transport)

    outcome = client.revoke(TOKEN)

    assert outcome == RevokeOutcome.REVOKED
    call = transport.calls[0]
    assert call["url"] == f"{CONSOLE_ORIGIN}/console/pairing/token/revoke"
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize("status", [401, 403])
def test_revoke_unauthorized_reports_already_unavailable(status):
    client = _client([_json_response(status, {"status": "revoked"})])
    assert client.revoke(TOKEN) == RevokeOutcome.ALREADY_UNAVAILABLE


def test_revoke_transport_failure_is_ambiguous():
    client = _client([TransportError()])
    with pytest.raises(PairingClientError) as exc:
        client.revoke(TOKEN)
    assert exc.value.code == "transport_failed"


@pytest.mark.parametrize(
    "response",
    [
        _json_response(500, {"status": "revoked"}),
        _json_response(200, {"status": "pending"}),
        _json_response(200, {"status": "revoked", "x": 1}),
        _json_response(200, {"status": "revoked"}, content_type="text/plain"),
    ],
)
def test_revoke_ambiguous_results_raise(response):
    client = _client([response])
    with pytest.raises(PairingClientError):
        client.revoke(TOKEN)


# --- secret canary ---------------------------------------------------------


def test_errors_never_leak_device_code_or_token():
    cases = [
        (_client([_json_response(200, _start_payload(verification_uri="//evil"))]), "start"),
        (_client([_json_response(500, {})]), "start"),
        (_client([TransportError()]), "start"),
    ]
    for client, _ in cases:
        try:
            client.start()
        except PairingClientError as exc:
            assert DEVICE_CODE not in str(exc)
            assert TOKEN not in str(exc)


def test_no_redirect_handler_refuses_redirects():
    handler = _NoRedirectHandler()
    assert handler.redirect_request(None, None, None, None, None, None) is None


# --- C4-003: user_code terminal-control rejection --------------------------


@pytest.mark.parametrize(
    "user_code",
    [
        "WXYZ\x1b[31m1234",
        "WXYZ\x071234",
        "WXYZ 1234",
        "wxyz-1234",
        "WXYZ--1234",
        "-WXYZ",
        "WXYZ-",
    ],
)
def test_start_rejects_unsafe_user_code(user_code):
    client = _client([_json_response(200, _start_payload(user_code=user_code))])
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "malformed_start"


def test_start_accepts_bounded_human_user_code():
    client = _client([_json_response(200, _start_payload(user_code="ABCD-2468"))])
    start = client.start()
    assert start.user_code == "ABCD-2468"


# --- C4-004: strict Content-Type parsing -----------------------------------


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json; charset=utf-8, text/html",
        "application/json; charset=",
        "application/json; charset=utf-8; boundary=x",
        "application/json; boundary=x",
        "text/html",
    ],
)
def test_start_rejects_non_strict_json_content_type(content_type):
    client = _client(
        [_json_response(200, _start_payload(), content_type=content_type)]
    )
    with pytest.raises(PairingClientError) as exc:
        client.start()
    assert exc.value.code == "bad_content_type"


def test_start_accepts_json_with_utf8_charset():
    client = _client(
        [
            _json_response(
                200,
                _start_payload(),
                content_type="application/json; charset=utf-8",
            )
        ]
    )
    assert client.start().user_code == USER_CODE


# --- helpers ---------------------------------------------------------------


def _start(payload):
    from agentveil_mcp_proxy.console_pairing_client import PairingStart

    return PairingStart(
        device_code=payload["device_code"],
        user_code=payload["user_code"],
        verification_url=f"{CONSOLE_ORIGIN}{payload['verification_uri']}",
        expires_in=payload["expires_in"],
        interval=payload["interval"],
    )
