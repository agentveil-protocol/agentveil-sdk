# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Wire-contract tests for the Console browser-session attach client."""

from __future__ import annotations

import json

import pytest

from agentveil_mcp_proxy.console_attach_client import (
    CONSOLE_ORIGIN,
    AttachClientError,
    ConsoleAttachClient,
    RawResponse,
    TransportError,
    _NoRedirectHandler,
)

DEVICE_CODE = "device-code-secret-xyz"
TOKEN = "confirmed-device-token-secret"
ATTACH_STATE = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
ATTACH_URI = f"/console/attach?state={ATTACH_STATE}"


def _json_response(status, obj, *, content_type="application/json"):
    body = json.dumps(obj).encode("utf-8")
    content_types = () if content_type is None else (content_type,)
    return RawResponse(status=status, content_types=content_types, body=body)


def _raw(status, body_bytes, *, content_types=("application/json",)):
    return RawResponse(status=status, content_types=content_types, body=body_bytes)


def _start_payload(**overrides):
    payload = {
        "device_code": DEVICE_CODE,
        "attach_uri": ATTACH_URI,
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
    return ConsoleAttachClient(
        transport=FakeTransport(responses),
        clock=clk,
        sleeper=clk.sleep,
    )


def test_start_success_resolves_fixed_origin_url():
    transport = FakeTransport([_json_response(200, _start_payload())])
    client = ConsoleAttachClient(transport=transport)

    start = client.start()

    assert start.attach_url == f"{CONSOLE_ORIGIN}{ATTACH_URI}"
    assert start.device_code == DEVICE_CODE
    assert start.expires_in == 600
    assert start.interval == 5
    call = transport.calls[0]
    assert call["url"] == f"{CONSOLE_ORIGIN}/console/attach/start"
    assert call["method"] == "POST"
    assert call["headers"]["Accept"] == "application/json"


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 429, 500, 503])
def test_start_non_200_status_fails_closed(status):
    client = _client([_json_response(status, _start_payload())])
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code == "unexpected_status"


def test_start_transport_failure_is_bounded():
    client = _client([TransportError()])
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code == "transport_failed"


def test_start_rejects_non_json_content_type():
    client = _client(
        [_json_response(200, _start_payload(), content_type="text/html")]
    )
    with pytest.raises(AttachClientError) as exc:
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
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code == "bad_content_type"


def test_start_rejects_missing_content_type():
    client = _client([_json_response(200, _start_payload(), content_type=None)])
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code == "bad_content_type"


def test_start_rejects_oversized_body():
    client = _client([_raw(200, b"{" + b" " * (16 * 1024 + 1))])
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code == "response_too_large"


def test_start_rejects_non_object_body():
    client = _client([_raw(200, b"[1, 2, 3]")])
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code == "malformed_body"


@pytest.mark.parametrize(
    "overrides",
    [
        {"extra": "field"},
        {"device_code": ""},
        {"device_code": 123},
        {"attach_uri": ""},
        {"user_code": "SHOULD-NOT-EXIST"},
    ],
)
def test_start_rejects_malformed_fields(overrides):
    client = _client([_json_response(200, _start_payload(**overrides))])
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code in {"malformed_start", "bad_attach_uri"}


def test_start_rejects_missing_field():
    payload = _start_payload()
    del payload["interval"]
    client = _client([_json_response(200, payload)])
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code == "malformed_start"


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.example/console/attach",
        "//evil.example/console/attach",
        "http://agentveil.dev/console/attach",
        "/console/attach",
        f"/console/attach?state={ATTACH_STATE}&next=https://evil.example",
        "/console/attach?next=https://evil.example",
        f"/console/attach?state={ATTACH_STATE}#frag",
        "/console/attach#frag",
        "https://user:pass@agentveil.dev/console/attach",
        "console/attach",
        "/path/with@userinfo",
        "/console/attach?state=short",
        "/console/attach?state=",
        "/console/attach?state=abcDEF123_-.~",
        123,
        "",
    ],
)
def test_start_rejects_malicious_attach_uri(uri):
    client = _client([_json_response(200, _start_payload(attach_uri=uri))])
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code in {"bad_attach_uri", "malformed_start"}


def test_start_accepts_private_backend_attach_uri_shape():
    client = _client([_json_response(200, _start_payload())])
    start = client.start()
    assert start.attach_url == f"{CONSOLE_ORIGIN}{ATTACH_URI}"


def test_start_accepts_backend_like_attach_uri():
    backend_state = "abcDEF1234567890abcdefghijklmnopQRSTuvwx"
    uri = f"/console/attach?state={backend_state}"
    client = _client([_json_response(200, _start_payload(attach_uri=uri))])
    assert client.start().attach_url == f"{CONSOLE_ORIGIN}{uri}"


@pytest.mark.parametrize(
    "uri",
    [
        f"/console/attach?state={ATTACH_STATE}&state=",
        f"/console/attach?state=&state={ATTACH_STATE}",
        f"/console/attach?state={ATTACH_STATE}&state={ATTACH_STATE}",
        f"/console/attach?state={ATTACH_STATE}%5F",
    ],
)
def test_start_rejects_duplicate_or_encoded_state_query(uri):
    client = _client([_json_response(200, _start_payload(attach_uri=uri))])
    with pytest.raises(AttachClientError) as exc:
        client.start()
    assert exc.value.code == "bad_attach_uri"


def test_poll_pending_then_consumed_returns_token():
    clock = FakeClock()
    transport = FakeTransport(
        [
            _json_response(200, {"status": "pending"}),
            _json_response(
                200,
                {"status": "consumed", "token": TOKEN, "scope": "bounded_summary_upload"},
            ),
        ]
    )
    client = ConsoleAttachClient(
        transport=transport, clock=clock, sleeper=clock.sleep
    )
    start = _start(_start_payload())

    result = client.poll_for_token(start)

    assert result.token == TOKEN
    assert result.scope == "bounded_summary_upload"
    consume_call = transport.calls[0]
    assert consume_call["url"] == f"{CONSOLE_ORIGIN}/console/attach/consume"
    assert json.loads(consume_call["body"]) == {"device_code": DEVICE_CODE}
    assert clock.now > 0


def test_poll_is_bounded_and_never_runs_forever():
    clock = FakeClock()
    transport = PendingTransport()
    client = ConsoleAttachClient(
        transport=transport, clock=clock, sleeper=clock.sleep
    )
    start = _start(_start_payload(expires_in=10, interval=5))

    with pytest.raises(AttachClientError) as exc:
        client.poll_for_token(start)

    assert exc.value.code == "expired"
    assert transport.calls <= 5


@pytest.mark.parametrize("status", [400, 409, 500, 503])
def test_poll_non_200_fails_closed(status):
    client = _client([_json_response(status, {"status": "pending"})])
    with pytest.raises(AttachClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert exc.value.code == "unexpected_status"


def test_poll_unknown_status_fails_closed():
    client = _client([_json_response(200, {"status": "elsewhere"})])
    with pytest.raises(AttachClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert exc.value.code == "unexpected_status"


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        (
            {"status": "consumed", "scope": "bounded_summary_upload"},
            "malformed_consume",
        ),
        (
            {"status": "consumed", "token": "", "scope": "bounded_summary_upload"},
            "malformed_consume",
        ),
        (
            {"status": "consumed", "token": TOKEN, "scope": "other"},
            "unexpected_scope",
        ),
    ],
)
def test_poll_consumed_malformed_fails_closed(payload, expected_error):
    client = _client([_json_response(200, payload)])
    with pytest.raises(AttachClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert exc.value.code == expected_error


def test_poll_pending_malformed_fails_closed():
    client = _client([_json_response(200, {"status": "pending", "x": 1})])
    with pytest.raises(AttachClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert exc.value.code == "malformed_consume"


def test_errors_never_leak_device_code_or_token():
    cases = [
        (_client([_json_response(200, _start_payload(attach_uri="//evil"))]), "start"),
        (_client([_json_response(500, {})]), "start"),
        (_client([TransportError()]), "start"),
    ]
    for client, _ in cases:
        try:
            client.start()
        except AttachClientError as exc:
            assert DEVICE_CODE not in str(exc)
            assert TOKEN not in str(exc)


def test_no_redirect_handler_refuses_redirects():
    handler = _NoRedirectHandler()
    assert handler.redirect_request(None, None, None, None, None, None) is None


def test_consume_errors_never_leak_device_code_or_token():
    client = _client([_json_response(500, {"status": "pending"})])
    with pytest.raises(AttachClientError) as exc:
        client.poll_for_token(_start(_start_payload()))
    assert DEVICE_CODE not in str(exc.value)
    assert TOKEN not in str(exc.value)


def _start(payload):
    from agentveil_mcp_proxy.console_attach_client import AttachStart

    return AttachStart(
        device_code=payload["device_code"],
        attach_url=f"{CONSOLE_ORIGIN}{payload['attach_uri']}",
        expires_in=payload["expires_in"],
        interval=payload["interval"],
    )
