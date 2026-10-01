"""Per-process CA transport boundaries with generated identity and HTTP transport."""

import gzip
import hashlib
import io
import json
import os
import sys
import re
import secrets
import socketserver
import threading
import time
from types import SimpleNamespace

import httpx
from nacl.signing import SigningKey
import pytest

from agentveil_mcp_proxy import controlled_alternatives as ca
from agentveil_mcp_proxy import controlled_alternatives_transport as transport
from agentveil_mcp_proxy.console_credentials import (
    save_credential,
    save_runtime_binding_credential,
)


@pytest.fixture
def identity():
    key = SigningKey.generate()
    return key, SimpleNamespace(private_key_hex=bytes(key).hex(), did="did:key:test-identity")


def context(identity, tmp_path, *, base_url="https://agentveil.example"):
    return transport.build_controlled_alternative_context(
        agent=identity[1], base_url=base_url, state_root=tmp_path,
    )


def mock_http(monkeypatch, handler):
    # Unit-test signed exchange separately from the real worker lifetime probes.
    monkeypatch.setattr(transport, "_run_bounded_exchange", transport._exchange)
    real = httpx.Client
    def streaming_handler(request):
        response = handler(request)
        if response.is_stream_consumed:
            return httpx.Response(response.status_code, headers=response.headers, stream=httpx.ByteStream(response.content))
        return response
    def client(**kwargs):
        assert kwargs["follow_redirects"] is False
        assert kwargs["timeout"] == transport._REQUEST_DEADLINE_SECONDS
        return real(transport=httpx.MockTransport(streaming_handler), **kwargs)
    monkeypatch.setattr(httpx, "Client", client)


def test_signs_exact_bounded_body_without_disclosing_identity(identity, tmp_path, monkeypatch):
    seen = []
    def handler(request):
        seen.append(request)
        header = dict(re.findall(r'(\w+)="([^"]+)"', request.headers["Authorization"]))
        message = f'POST:{request.url.path}:{header["ts"]}:{header["nonce"]}:{hashlib.sha256(request.content).hexdigest()}'
        identity[0].verify_key.verify(message.encode(), bytes.fromhex(header["sig"]))
        assert header["did"] == identity[1].did
        assert request.headers["Accept-Encoding"] == "identity"
        return httpx.Response(200, json={"ok": True})
    mock_http(monkeypatch, handler)
    bound = context(identity, tmp_path)
    assert seen == []  # constructing a context is not a network or authority action
    assert bound.request("preflight", {}) == (200, {"ok": True})
    assert seen[0].url.path.endswith("/hybrid/preflight")
    assert identity[1].private_key_hex not in repr(bound)
    assert str(tmp_path) not in repr(bound)


def test_runtime_heartbeat_uses_signed_fixed_path_and_distinct_credential_header(
    identity,
    tmp_path,
    monkeypatch,
):
    credential = "console-device-token-canary-001"
    observed_at = "2026-09-15T12:00:00Z"
    seen = []

    def handler(request):
        seen.append(request)
        assert request.url.path == "/v1/controlled-alternatives/hybrid/runtime-status"
        assert request.headers[transport.CONSOLE_CREDENTIAL_HEADER] == credential
        assert request.headers["Accept-Encoding"] == "identity"
        assert json.loads(request.content) == {
            "schema_version": "1",
            "status": "active",
            "observed_at": observed_at,
        }
        header = dict(
            re.findall(r'(\w+)="([^"]+)"', request.headers["Authorization"])
        )
        message = (
            f'POST:{request.url.path}:{header["ts"]}:{header["nonce"]}:'
            f"{hashlib.sha256(request.content).hexdigest()}"
        )
        identity[0].verify_key.verify(message.encode(), bytes.fromhex(header["sig"]))
        return httpx.Response(
            200,
            json={
                "schema_version": "1",
                "status": "active",
                "observed_at": observed_at,
                "result": "accepted",
            },
        )

    mock_http(monkeypatch, handler)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert callable(bound.heartbeat)
    assert bound.heartbeat(credential, observed_at) == (
        200,
        {
            "schema_version": "1",
            "status": "active",
            "observed_at": observed_at,
            "result": "accepted",
        },
    )
    assert len(seen) == 1
    assert credential not in repr(bound)


@pytest.mark.parametrize(
    ("credential", "observed_at"),
    [
        ("short", "2026-09-15T12:00:00Z"),
        ("console device token canary", "2026-09-15T12:00:00Z"),
        ("console-device-token-canary-001", "/Users/canary"),
        ("console-device-token-canary-001", "2026-09-15T12:00:00+00:00"),
    ],
)
def test_invalid_runtime_heartbeat_never_reaches_network(
    identity,
    tmp_path,
    monkeypatch,
    credential,
    observed_at,
):
    mock_http(monkeypatch, lambda _request: pytest.fail("unexpected HTTP request"))
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert callable(bound.heartbeat)
    assert bound.heartbeat(credential, observed_at) == (400, {})


def test_runtime_heartbeat_is_absent_for_non_console_origin(identity, tmp_path) -> None:
    bound = context(identity, tmp_path, base_url="https://self-hosted.example")
    assert bound is not None
    assert bound.heartbeat is None


@pytest.mark.parametrize("payload", [{"path": "/private/canary"}, {"content": "secret"}, {"token": "canary"}])
def test_forbidden_payload_never_reaches_network(identity, tmp_path, monkeypatch, payload):
    def handler(request):
        pytest.fail("unexpected HTTP request")
    mock_http(monkeypatch, handler)
    bound = context(identity, tmp_path)
    assert bound.request("decide", payload) == (400, {})
    assert bound.request("preflight", payload) == (400, {})
    assert bound.request("https://untrusted.example", {}) == (400, {})


@pytest.mark.parametrize("url", ["http://agentveil.example", "https://u:p@agentveil.example", "https://agentveil.example/x", "https://agentveil.example?x=1", "https://agentveil.example#x"])
def test_invalid_endpoint_has_no_transport(identity, tmp_path, url):
    assert transport.build_controlled_alternative_context(agent=identity[1], base_url=url, state_root=tmp_path) is None


@pytest.mark.parametrize("response,expected", [
    (httpx.Response(302, headers={"Location": "https://other.example"}), 302),
    (httpx.Response(200, content=b"x" * 17000), 502),
    (httpx.Response(200, json=[]), 502),
    (httpx.Response(401, text="token=private-canary"), 401),
])
def test_untrusted_response_is_bounded(identity, tmp_path, monkeypatch, response, expected):
    calls = []
    def handler(request):
        calls.append(request)
        return response
    mock_http(monkeypatch, handler)
    assert context(identity, tmp_path).request("preflight", {}) == (expected, {})
    assert len(calls) == 1


def test_deadline_kills_and_reaps_slow_system_resolver(identity, tmp_path, monkeypatch):
    actual_module = transport.__file__
    marker = tmp_path / "resolver-entered"
    wrapper = tmp_path / "slow_resolver.py"
    wrapper.write_text(
        "import runpy, socket, time\nfrom pathlib import Path\n"
        f"def slow(*a, **k):\n    Path({str(marker)!r}).touch()\n    time.sleep(10)\n    raise socket.gaierror()\n"
        "socket.getaddrinfo = slow\n"
        f"runpy.run_path({actual_module!r}, run_name='__main__')\n"
    )
    monkeypatch.setattr(transport, "__file__", str(wrapper))
    monkeypatch.setattr(transport, "_REQUEST_DEADLINE_SECONDS", 1.0)
    processes = []
    real = transport.subprocess.Popen
    def capture(*args, **kwargs):
        assert identity[1].private_key_hex not in repr(args)
        process = real(*args, **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(transport.subprocess, "Popen", capture)
    started = time.monotonic()
    assert context(identity, tmp_path).request("preflight", {}) == (503, {})
    assert time.monotonic() - started < 2.0
    assert marker.exists()
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert processes[0].stdin.closed and processes[0].stdout.closed


def test_compressed_response_is_rejected_before_body_or_decoder(identity, tmp_path, monkeypatch):
    compressed = gzip.compress(b"x" * 1_048_576)
    assert len(compressed) < transport._MAX_RESPONSE
    class Compressed(httpx.SyncByteStream):
        read = False
        closed = False
        def __iter__(self):
            self.read = True
            yield compressed
        def close(self):
            self.closed = True
    stream = Compressed()
    def forbidden_decoder(_self):
        pytest.fail("compressed response must not instantiate a decoder")
    monkeypatch.setattr(httpx.Response, "_get_content_decoder", forbidden_decoder)
    mock_http(monkeypatch, lambda _r: httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=stream))
    assert context(identity, tmp_path).request("preflight", {}) == (502, {})
    assert not stream.read
    assert stream.closed


def test_oversized_raw_chunk_is_rejected_and_stream_closed(identity, tmp_path, monkeypatch):
    class Oversized(httpx.SyncByteStream):
        closed = False
        exhausted = False
        def __iter__(self):
            yield b"x" * (transport._MAX_RESPONSE + 1)
            self.exhausted = True
            yield b"should not be consumed"
        def close(self):
            self.closed = True
    stream = Oversized()
    mock_http(monkeypatch, lambda _r: httpx.Response(200, stream=stream))
    assert context(identity, tmp_path).request("preflight", {}) == (502, {})
    assert stream.closed and not stream.exhausted


@pytest.mark.parametrize("phase", ["headers", "body", "healthy", "gzip"])
def test_real_socket_drip_hits_deadline_and_disconnects(identity, tmp_path, monkeypatch, phase):
    disconnected = threading.Event()
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            self.request.recv(16384)
            try:
                if phase == "healthy":
                    self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{"ok":true}')
                    return
                if phase == "gzip":
                    compressed = gzip.compress(b"x" * 1_048_576)
                    self.request.sendall(f"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {len(compressed)}\r\n\r\n".encode() + compressed)
                    return
                if phase == "headers":
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                else:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 111\r\n\r\n")
                for _ in range(100):
                    self.request.sendall(b" ")
                    time.sleep(0.02)
                if phase == "headers":
                    self.request.sendall(b"\r\nContent-Length: 11\r\n\r\n")
                self.request.sendall(b'{"ok":true}')
            except (BrokenPipeError, ConnectionResetError):
                disconnected.set()
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
    server = Server(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01))
    worker.start()
    processes = []
    real = transport.subprocess.Popen
    def capture(*args, **kwargs):
        process = real(*args, **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(transport.subprocess, "Popen", capture)
    monkeypatch.setattr(transport, "_REQUEST_DEADLINE_SECONDS", 1.0)
    try:
        started = time.monotonic()
        # Directly exercise the process exchange with a test-only HTTP endpoint.
        result = transport._run_bounded_exchange(f"http://127.0.0.1:{server.server_address[1]}/", {}, "")
        if phase in {"headers", "body"}:
            assert result == (503, {})
            assert disconnected.wait(timeout=1)
        elif phase == "gzip":
            assert result == (502, {})
        else:
            assert result == (200, {"ok": True})
        assert time.monotonic() - started < 2.0
        assert len(processes) == 1 and processes[0].poll() is not None
        assert processes[0].stdin.closed and processes[0].stdout.closed
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert not worker.is_alive()


def test_context_bound_before_authority_and_descriptor(identity, tmp_path):
    bound = context(identity, tmp_path)
    seen = []
    class Authority:
        def bind_runtime_context(self, value):
            assert value is bound
            seen.append("authority-bound")
            return {"authority_present": True, "authority_id": ca.CONTROLLED_ALTERNATIVE_AUTHORITY_ID,
                    "contract_version": "1", "status": "active", "scope": ca.CONTROLLED_ALTERNATIVE_AUTHORITY_SCOPE}
    class Provider:
        def bind_runtime_context(self, value):
            assert value is bound
            seen.append("provider-bound")
            return self
        def descriptor(self):
            assert seen == ["authority-bound", "provider-bound"]
            return ca.ControlledAlternativeProviderDescriptor(
                provider_id=ca.CONTROLLED_ALTERNATIVE_PROVIDER_ID, contract_version="1",
                profile_id=ca.CONTROLLED_ALTERNATIVES_PROFILE_ID, alternative_ids=ca.CONTROLLED_ALTERNATIVE_IDS,
            )
    ca.set_controlled_alternative_authority_loader(lambda: Authority())
    ca.set_controlled_alternative_provider_loader(lambda: Provider())
    try:
        authority = ca.discover_controlled_alternative_authority(runtime_context=bound)
        discovered = ca.discover_controlled_alternative_provider(authority=authority, runtime_context=bound)
        assert discovered.available is True
    finally:
        ca.set_controlled_alternative_authority_loader(None)
        ca.set_controlled_alternative_provider_loader(None)


BINDING_TOKEN = "paired-runtime-binding-token-001"
SUMMARY_TOKEN = "bounded-summary-upload-token-001"
CAPABILITY = "filesystem.stage_delete.v1"
RUNTIME_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ISSUER_KEY_ID = "ab" * 32
PUBLIC_KEY_HEX = ISSUER_KEY_ID
MISMATCHED_PUBLIC_KEY_HEX = "cd" * 32


def _healthy_context() -> dict[str, object]:
    return {
        "contains_secret_like_value": False,
        "destructive_shell_pattern": False,
        "write_then_execute_risk": False,
        "credential_exfil_pattern": False,
        "signal_producer_health": "healthy",
    }


def _register_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "runtime/register/1",
        "runtime_version": "1.0.0",
        "contract_range": "av02.v1",
        "catalog_digest": "aa" * 32,
        "declared_executor_capabilities": [CAPABILITY],
    }
    payload.update(overrides)
    return payload


def _evaluate_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "policy/evaluate/1",
        "runtime_installation_id": RUNTIME_ID,
        "operation_nonce": secrets.token_urlsafe(32),
        "phase": "propose",
        "action_family": "filesystem",
        "target_class": "file",
        "requested_executor_capability": CAPABILITY,
        "policy_context": _healthy_context(),
    }
    payload.update(overrides)
    return payload


def _install_binding(tmp_path):
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    save_runtime_binding_credential(BINDING_TOKEN, home=tmp_path)


def test_av02_transport_uses_exact_normative_paths_and_payloads(
    identity, tmp_path, monkeypatch,
):
    seen = []
    register_payload = _register_payload()
    evaluate_payload = _evaluate_payload()
    key_path = f"{transport._DECISION_KEY_PATH_PREFIX}{ISSUER_KEY_ID}"

    def handler(request):
        seen.append(request)
        if request.url.path == transport._AV02_PATHS["register"]:
            assert request.method == "POST"
            assert json.loads(request.content) == register_payload
            assert request.headers[transport.RUNTIME_BINDING_HEADER] == BINDING_TOKEN
            assert transport.CONSOLE_CREDENTIAL_HEADER not in request.headers
            return httpx.Response(
                200,
                json={
                    "schema_version": "runtime/register-response/1",
                    "runtime_installation_id": RUNTIME_ID,
                },
            )
        if request.url.path == transport._AV02_PATHS["evaluate"]:
            assert request.method == "POST"
            assert json.loads(request.content) == evaluate_payload
            assert request.headers[transport.RUNTIME_BINDING_HEADER] == BINDING_TOKEN
            return httpx.Response(
                200,
                json={"ok": False, "error_code": "av02_disabled"},
            )
        if request.url.path == key_path:
            assert request.method == "GET"
            assert request.content in {b"", None}
            assert request.headers[transport.RUNTIME_BINDING_HEADER] == BINDING_TOKEN
            return httpx.Response(
                200,
                json={
                    "schema_version": "av02-decision-verification-key/1",
                    "issuer_key_id": ISSUER_KEY_ID,
                    "algorithm": "Ed25519",
                    "key_role": "controlled_alternatives_decision",
                    "public_key_hex": PUBLIC_KEY_HEX,
                    "status": "active",
                },
            )
        pytest.fail(f"unexpected path {request.url.path}")

    mock_http(monkeypatch, handler)
    _install_binding(tmp_path)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.contract_version == transport.CONTEXT_VERSION_V2
    assert callable(bound.runtime_register)
    assert callable(bound.policy_evaluate)
    assert callable(bound.resolve_decision_verification_key)
    assert bound.runtime_register(register_payload) == (
        200,
        {
            "schema_version": "runtime/register-response/1",
            "runtime_installation_id": RUNTIME_ID,
        },
    )
    assert bound.policy_evaluate(evaluate_payload) == (
        200,
        {"ok": False, "error_code": "av02_disabled"},
    )
    assert bound.resolve_decision_verification_key(ISSUER_KEY_ID) == {
        "schema_version": "av02-decision-verification-key/1",
        "issuer_key_id": ISSUER_KEY_ID,
        "algorithm": "Ed25519",
        "key_role": "controlled_alternatives_decision",
        "public_key_hex": PUBLIC_KEY_HEX,
        "status": "active",
    }
    assert {item.url.path for item in seen} == set(transport._AV02_PATHS.values()) | {key_path}


def test_av02_transport_signs_exact_body_without_secret_output(
    identity, tmp_path, monkeypatch,
):
    seen = []
    key_path = f"{transport._DECISION_KEY_PATH_PREFIX}{ISSUER_KEY_ID}"

    def handler(request):
        seen.append(request)
        header = dict(re.findall(r'(\w+)="([^"]+)"', request.headers["Authorization"]))
        assert header.get("v") == "2"
        body = request.content or b""
        message = (
            f'v2:{request.method}:{request.url.path}::{header["ts"]}:{header["nonce"]}:'
            f"{hashlib.sha256(body).hexdigest()}"
        )
        identity[0].verify_key.verify(message.encode(), bytes.fromhex(header["sig"]))
        if request.url.path == key_path:
            return httpx.Response(
                200,
                json={
                    "schema_version": "av02-decision-verification-key/1",
                    "issuer_key_id": ISSUER_KEY_ID,
                    "algorithm": "Ed25519",
                    "key_role": "controlled_alternatives_decision",
                    "public_key_hex": PUBLIC_KEY_HEX,
                    "status": "active",
                },
            )
        return httpx.Response(200, json={"ok": True})

    mock_http(monkeypatch, handler)
    _install_binding(tmp_path)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.runtime_register(_register_payload()) == (200, {"ok": True})
    assert bound.resolve_decision_verification_key(ISSUER_KEY_ID) is not None
    assert len(seen) == 2
    assert seen[1].method == "GET"
    assert seen[1].url.path == key_path
    assert BINDING_TOKEN not in repr(bound)
    assert SUMMARY_TOKEN not in repr(bound)
    assert PUBLIC_KEY_HEX not in repr(bound)
    assert identity[1].private_key_hex not in repr(bound)


def test_av02_transport_without_binding_never_reaches_network(
    identity, tmp_path, monkeypatch,
):
    mock_http(monkeypatch, lambda _request: pytest.fail("unexpected HTTP request"))
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.contract_version == transport.CONTEXT_VERSION
    assert bound.runtime_register is None
    assert bound.policy_evaluate is None
    assert bound.resolve_decision_verification_key is None
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    rebound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert rebound.runtime_register is None
    assert rebound.resolve_decision_verification_key is None


def test_av02_transport_uses_dedicated_binding_credential_only(
    identity, tmp_path, monkeypatch,
):
    headers_seen: list[str] = []

    def handler(request):
        headers_seen.append(request.headers[transport.RUNTIME_BINDING_HEADER])
        return httpx.Response(
            200,
            json={
                "schema_version": "runtime/register-response/1",
                "runtime_installation_id": RUNTIME_ID,
            },
        )

    mock_http(monkeypatch, handler)
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    save_runtime_binding_credential(BINDING_TOKEN, home=tmp_path)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    status, _payload = bound.runtime_register(_register_payload())
    assert status == 200
    assert headers_seen == [BINDING_TOKEN]
    assert SUMMARY_TOKEN not in headers_seen


def test_av02_transport_requests_use_fresh_signed_nonce(
    identity, tmp_path, monkeypatch,
):
    nonces: list[str] = []

    def handler(request):
        header = dict(re.findall(r'(\w+)="([^"]+)"', request.headers["Authorization"]))
        nonces.append(header["nonce"])
        return httpx.Response(
            200,
            json={
                "schema_version": "runtime/register-response/1",
                "runtime_installation_id": RUNTIME_ID,
            },
        )

    mock_http(monkeypatch, handler)
    _install_binding(tmp_path)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.runtime_register is not None
    bound.runtime_register(_register_payload())
    bound.runtime_register(_register_payload())
    assert len(nonces) == 2
    assert nonces[0] != nonces[1]


def test_av02_transport_preserves_handle_without_persisting_or_logging_it(
    identity, tmp_path, monkeypatch,
):
    execute_handle = secrets.token_urlsafe(32)
    binding_path = tmp_path / "console" / "runtime-binding-credential.json"

    def handler(request):
        return httpx.Response(
            200,
            json={
                "schema_version": "policy/decision-response/1",
                "execute_handle": execute_handle,
            },
        )

    mock_http(monkeypatch, handler)
    _install_binding(tmp_path)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.policy_evaluate is not None
    status, payload = bound.policy_evaluate(_evaluate_payload(phase="execute"))
    assert status == 200
    assert payload.get("execute_handle") == execute_handle
    assert execute_handle not in repr(bound)
    if binding_path.exists():
        assert execute_handle not in binding_path.read_text(encoding="utf-8")


def test_attach_and_transport_preserve_legacy_baseline_without_runtime_binding(
    identity, tmp_path, monkeypatch,
):
    mock_http(monkeypatch, lambda _request: pytest.fail("unexpected HTTP request"))
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.contract_version == transport.CONTEXT_VERSION
    assert bound.runtime_register is None
    assert bound.policy_evaluate is None
    assert bound.resolve_decision_verification_key is None
    legacy = context(identity, tmp_path, base_url="https://agentveil.example")
    assert legacy.runtime_register is None
    assert legacy.policy_evaluate is None
    assert legacy.resolve_decision_verification_key is None


def test_decision_verification_key_rejects_mismatched_public_key_hex(
    identity, tmp_path, monkeypatch,
):
    binding_path = tmp_path / "console" / "runtime-binding-credential.json"
    mock_http(monkeypatch, lambda _request: pytest.fail("unexpected HTTP request"))
    assert context(identity, tmp_path, base_url="https://agentveil.dev").resolve_decision_verification_key is None

    def handler(_request):
        return httpx.Response(
            200,
            json={
                "schema_version": "av02-decision-verification-key/1",
                "issuer_key_id": ISSUER_KEY_ID,
                "algorithm": "Ed25519",
                "key_role": "controlled_alternatives_decision",
                "public_key_hex": MISMATCHED_PUBLIC_KEY_HEX,
                "status": "active",
            },
        )

    mock_http(monkeypatch, handler)
    _install_binding(tmp_path)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.resolve_decision_verification_key is not None
    assert bound.resolve_decision_verification_key(ISSUER_KEY_ID) is None
    assert MISMATCHED_PUBLIC_KEY_HEX not in repr(bound)
    if binding_path.exists():
        stored = binding_path.read_text(encoding="utf-8")
        assert MISMATCHED_PUBLIC_KEY_HEX not in stored
        assert ISSUER_KEY_ID not in stored


def test_decision_key_resolution_never_persists_public_key_material(
    identity, tmp_path, monkeypatch,
):
    binding_path = tmp_path / "console" / "runtime-binding-credential.json"

    def handler(_request):
        return httpx.Response(
            200,
            json={
                "schema_version": "av02-decision-verification-key/1",
                "issuer_key_id": ISSUER_KEY_ID,
                "algorithm": "Ed25519",
                "key_role": "controlled_alternatives_decision",
                "public_key_hex": PUBLIC_KEY_HEX,
                "status": "active",
            },
        )

    mock_http(monkeypatch, handler)
    _install_binding(tmp_path)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.resolve_decision_verification_key is not None
    assert bound.resolve_decision_verification_key(ISSUER_KEY_ID) is not None
    if binding_path.exists():
        assert PUBLIC_KEY_HEX not in binding_path.read_text(encoding="utf-8")


def test_bind_installed_runtime_context_accepts_explicit_v2_duck_consumer(
    identity, tmp_path,
):
    _install_binding(tmp_path)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.contract_version == transport.CONTEXT_VERSION_V2

    class ThinConsumer:
        def __init__(self) -> None:
            self.context = None

        def bind_runtime_context(self, context):
            if getattr(context, "contract_version", None) != "2":
                raise ValueError("expected_v2")
            for name in (
                "runtime_register",
                "policy_evaluate",
                "resolve_decision_verification_key",
                "state_root",
            ):
                if not callable(getattr(context, name, None)) and name != "state_root":
                    raise ValueError(f"missing_{name}")
            if not isinstance(context.state_root, str):
                raise ValueError("missing_state_root")
            self.context = context
            return self

    consumer = transport.bind_installed_runtime_context(ThinConsumer(), bound)
    assert consumer.context is bound


def test_runtime_heartbeat_never_sends_runtime_binding_header(
    identity, tmp_path, monkeypatch,
):
    seen = []

    def handler(request):
        seen.append(request)
        assert transport.RUNTIME_BINDING_HEADER not in request.headers
        return httpx.Response(200, json={"ok": True})

    mock_http(monkeypatch, handler)
    _install_binding(tmp_path)
    bound = context(identity, tmp_path, base_url="https://agentveil.dev")
    assert bound.heartbeat(SUMMARY_TOKEN, "2026-09-15T12:00:00Z") == (200, {"ok": True})
    assert seen[0].headers[transport.CONSOLE_CREDENTIAL_HEADER] == SUMMARY_TOKEN


def test_build_context_uses_canonical_root_for_client_installation_ref(
    identity, tmp_path,
):
    from agentveil_mcp_proxy.console_credentials import (
        save_credential,
        save_scoped_runtime_binding_credential,
    )
    from agentveil_mcp_proxy.console_project_status_client import (
        build_client_installation_ref,
    )

    project = tmp_path / "workspace"
    project.mkdir()
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=identity[1].did,
        summary_token=SUMMARY_TOKEN,
        home=tmp_path,
    )
    expected_ref = build_client_installation_ref(
        canonical_project_root=project,
        agent_did=identity[1].did,
    )
    runtime_id = RUNTIME_ID
    from agentveil_mcp_proxy.console_credentials import scoped_runtime_binding_namespace_hash

    state_dir = tmp_path / (
        "ca-agent-" + scoped_runtime_binding_namespace_hash(identity[1].did, SUMMARY_TOKEN)[:32]
    )
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    ca_dir = state_dir / "controlled-alternatives"
    ca_dir.mkdir()
    os.chmod(ca_dir, 0o700)
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "runtime_version": "1.0.0",
                "contract_range": "av02.v1",
                "catalog_digest": "aa" * 32,
                "declared_executor_capabilities": list(
                    transport._AV02_DECLARED_EXECUTOR_CAPABILITIES
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    state_file = ca_dir / "av02-runtime-state.json"
    state_file.write_text(
        json.dumps(
            {
                "schema_version": "av02-runtime-state/1",
                "runtime_installation_id": runtime_id,
                "registration_fingerprint": fingerprint,
            }
        ),
        encoding="utf-8",
    )
    import stat as stat_mod

    os.chmod(state_file, stat_mod.S_IRUSR | stat_mod.S_IWUSR)
    assert transport.read_cached_av02_runtime_installation_id(state_dir) == runtime_id
    assert expected_ref is not None
    bound = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        summary_token=SUMMARY_TOKEN,
        canonical_project_root=project,
    )
    assert bound is not None and bound.heartbeat is not None


def test_correlation_root_matches_between_status_and_run_proxy_paths(
    identity, tmp_path,
):
    from agentveil_mcp_proxy.cli import init_proxy, proxy_paths, run_proxy
    from agentveil_mcp_proxy.console_project_status_client import (
        build_client_installation_ref,
        correlation_root_for_client_installation_ref,
    )

    project = tmp_path / "service"
    project.mkdir()
    profile = project / "product-profile"
    workspace = profile / "workspace"
    workspace.mkdir(parents=True)
    home = project / ".avp"
    init_proxy(home=home, agent_name="proxy", plaintext=True)
    config_path = proxy_paths(home).config_path
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "product-route",
        "command": sys.executable,
        "args": ["-c", "import time; time.sleep(3600)"],
        "env": {"PRODUCT_ROUTE_PROFILE_ROOT": str(profile)},
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    captured: dict[str, object] = {}

    def capture_build(**kwargs):
        captured["canonical_project_root"] = kwargs.get("canonical_project_root")
        return transport.build_controlled_alternative_context(**kwargs)

    import agentveil_mcp_proxy.cli as proxy_cli

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(proxy_cli, "build_controlled_alternative_context", capture_build)
    try:
        assert run_proxy(
            home=home,
            client_in=io.StringIO(""),
            out=io.StringIO(),
            approval_ui_mode="none",
        ) == 0
    finally:
        monkeypatch.undo()
    status_root = correlation_root_for_client_installation_ref(
        project_dir=project,
        runtime_home=home,
    )
    assert status_root == workspace.resolve()
    assert captured["canonical_project_root"] == status_root
    assert build_client_installation_ref(
        canonical_project_root=status_root,
        agent_did=identity[1].did,
    ) is not None


def test_context_without_active_authority_does_not_load_provider(identity, tmp_path):
    loaded = []
    ca.set_controlled_alternative_authority_loader(lambda: None)
    ca.set_controlled_alternative_provider_loader(lambda: loaded.append(True))
    try:
        bound = context(identity, tmp_path)
        authority = ca.discover_controlled_alternative_authority(runtime_context=bound)
        assert not ca.discover_controlled_alternative_provider(authority=authority, runtime_context=bound).available
        assert loaded == []
    finally:
        ca.set_controlled_alternative_authority_loader(None)
        ca.set_controlled_alternative_provider_loader(None)


SUMMARY_TOKEN = "bounded-summary-upload-token-0123456789ab"
SUMMARY_TOKEN_B = "bounded-summary-upload-token-b0123456789ab"
BINDING_TOKEN = "issued-runtime-binding-token-0123456789ab"
LEGACY_BINDING = "legacy-global-runtime-binding-token-0123456789ab"


def _patch_heartbeat_exchange(monkeypatch):
    exchanges = []

    def capture(url, headers, body, method="POST"):
        exchanges.append(body)
        return 200, {"schema_version": "1", "status": "active"}

    monkeypatch.setattr(transport, "_run_bounded_exchange", capture)
    return exchanges


def test_opted_in_fresh_context_source_change_never_sends_schema1_heartbeat(
    identity, tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.console_credentials import (
        save_scoped_runtime_binding_credential,
    )

    save_runtime_binding_credential(LEGACY_BINDING, home=tmp_path)
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=identity[1].did,
        summary_token=SUMMARY_TOKEN,
        home=tmp_path,
    )
    save_credential(SUMMARY_TOKEN_B, home=tmp_path)
    exchanges = _patch_heartbeat_exchange(monkeypatch)
    bound = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=tmp_path,
    )
    assert bound is not None and bound.heartbeat is not None
    assert bound.heartbeat(SUMMARY_TOKEN_B, "2026-09-15T12:00:00Z") == (401, {})
    assert exchanges == []


def test_unreadable_scoped_source_marker_never_sends_schema1_heartbeat(
    identity, tmp_path, monkeypatch,
):
    import agentveil_mcp_proxy.console_credentials as creds

    save_runtime_binding_credential(LEGACY_BINDING, home=tmp_path)
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    marker = (
        creds.credential_directory(tmp_path)
        / creds._scoped_source_marker_filename(identity[1].did)
    )
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(b"{not-json")
    os.chmod(marker, 0o600)
    exchanges = _patch_heartbeat_exchange(monkeypatch)
    bound = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        summary_token=SUMMARY_TOKEN,
    )
    assert bound is not None and bound.heartbeat is not None
    assert bound.heartbeat(SUMMARY_TOKEN, "2026-09-15T12:00:00Z") == (401, {})
    assert exchanges == []


def test_malformed_scoped_binding_never_sends_schema1_heartbeat(
    identity, tmp_path, monkeypatch,
):
    import agentveil_mcp_proxy.console_credentials as creds
    from agentveil_mcp_proxy.console_credentials import (
        save_scoped_runtime_binding_credential,
        scoped_runtime_binding_namespace_hash,
    )

    save_runtime_binding_credential(LEGACY_BINDING, home=tmp_path)
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=identity[1].did,
        summary_token=SUMMARY_TOKEN,
        home=tmp_path,
    )
    namespace = scoped_runtime_binding_namespace_hash(identity[1].did, SUMMARY_TOKEN)
    directory = creds.credential_directory(tmp_path)
    bad_file = directory / f"runtime-binding-scoped-{namespace}.json"
    bad_file.write_text("{", encoding="utf-8")
    os.chmod(bad_file, 0o600)
    exchanges = _patch_heartbeat_exchange(monkeypatch)
    bound = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        summary_token=SUMMARY_TOKEN,
    )
    assert bound is not None and bound.heartbeat is not None
    assert bound.heartbeat(SUMMARY_TOKEN, "2026-09-15T12:00:00Z") == (401, {})
    assert exchanges == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX scoped filename custody")
@pytest.mark.parametrize(
    "corrupt",
    [
        "malformed_json",
        "symlink",
        "world_readable",
    ],
)
def test_malformed_scoped_binding_without_marker_never_sends_schema1_heartbeat(
    identity, tmp_path, monkeypatch, corrupt,
):
    import agentveil_mcp_proxy.console_credentials as creds
    from agentveil_mcp_proxy.console_credentials import (
        scoped_runtime_binding_namespace_hash,
    )

    save_runtime_binding_credential(LEGACY_BINDING, home=tmp_path)
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    namespace = scoped_runtime_binding_namespace_hash(identity[1].did, SUMMARY_TOKEN)
    directory = creds.credential_directory(tmp_path)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    bad_file = directory / f"runtime-binding-scoped-{namespace}.json"
    if corrupt == "malformed_json":
        bad_file.write_text("{", encoding="utf-8")
        os.chmod(bad_file, 0o600)
    elif corrupt == "symlink":
        real = tmp_path / "real-scoped.json"
        real.write_text("{}", encoding="utf-8")
        os.symlink(real, bad_file)
    else:
        bad_file.write_text("{}", encoding="utf-8")
        os.chmod(bad_file, 0o644)
    assert not (
        directory / creds._scoped_source_marker_filename(identity[1].did)
    ).exists()
    exchanges = _patch_heartbeat_exchange(monkeypatch)
    bound = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        summary_token=SUMMARY_TOKEN,
    )
    assert bound is not None and bound.heartbeat is not None
    assert bound.heartbeat(SUMMARY_TOKEN, "2026-09-15T12:00:00Z") == (401, {})
    assert exchanges == []


def test_resolve_failure_sticky_malformed_blocks_schema1_heartbeat(
    identity, tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.console_credentials import CredentialError

    save_runtime_binding_credential(LEGACY_BINDING, home=tmp_path)
    save_credential(SUMMARY_TOKEN, home=tmp_path)

    def _fail(*_args, **_kwargs):
        raise CredentialError("credential_unreadable")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_credentials.resolve_runtime_binding_for_context",
        _fail,
    )
    exchanges = _patch_heartbeat_exchange(monkeypatch)
    bound = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        summary_token=SUMMARY_TOKEN,
    )
    assert bound is not None and bound.heartbeat is not None
    assert bound.heartbeat(SUMMARY_TOKEN, "2026-09-15T12:00:00Z") == (401, {})
    assert exchanges == []


def test_second_scoped_load_failure_sticky_malformed_blocks_schema1_heartbeat(
    identity, tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.console_credentials import (
        CredentialError,
        load_scoped_runtime_binding_credential,
        save_scoped_runtime_binding_credential,
    )

    save_runtime_binding_credential(LEGACY_BINDING, home=tmp_path)
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=identity[1].did,
        summary_token=SUMMARY_TOKEN,
        home=tmp_path,
    )
    real_load = load_scoped_runtime_binding_credential
    calls = {"count": 0}

    def _load(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] >= 2:
            raise CredentialError("credential_invalid")
        return real_load(*args, **kwargs)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_credentials.load_scoped_runtime_binding_credential",
        _load,
    )
    exchanges = _patch_heartbeat_exchange(monkeypatch)
    bound = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=tmp_path,
        summary_token=SUMMARY_TOKEN,
    )
    assert bound is not None and bound.heartbeat is not None
    assert bound.heartbeat(SUMMARY_TOKEN, "2026-09-15T12:00:00Z") == (401, {})
    assert exchanges == []


def test_hosted_scoped_custody_failure_quarantines_hybrid_and_provider(
    identity, tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.console_credentials import (
        save_scoped_runtime_binding_credential,
        scoped_runtime_binding_namespace_hash,
    )
    from agentveil_mcp_proxy.controlled_alternatives_runtime import (
        bind_controlled_alternative_runtime,
    )

    hybrid_calls: list[str] = []

    def blocked_exchange(url, headers, body, method="POST"):
        hybrid_calls.append(url)
        return 401, {}

    monkeypatch.setattr(transport, "_run_bounded_exchange", blocked_exchange)
    project = tmp_path / "workspace"
    project.mkdir()
    home = project / ".avp"
    home.mkdir()
    save_runtime_binding_credential(LEGACY_BINDING, home=home)
    save_credential(SUMMARY_TOKEN, home=home)
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=identity[1].did,
        summary_token=SUMMARY_TOKEN,
        home=home,
    )
    namespace = scoped_runtime_binding_namespace_hash(identity[1].did, SUMMARY_TOKEN)
    bad = home / "console" / f"runtime-binding-scoped-{namespace}.json"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("{", encoding="utf-8")
    os.chmod(bad, 0o600)
    runtime_context = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=home,
        canonical_project_root=project,
    )
    assert runtime_context is not None
    assert runtime_context.contract_version == transport.CONTEXT_VERSION_V2
    assert runtime_context.runtime_register is None
    assert runtime_context.request("preflight", {}) == (401, {})
    assert hybrid_calls == []
    bound = bind_controlled_alternative_runtime(
        home=home,
        downstream={"name": "synthetic", "command": "noop", "cwd": str(project)},
        runtime_context=runtime_context,
    )
    assert bound is None


_HYBRID_DECIDE_PAYLOAD = {
    "contract_version": "1",
    "profile_id": "controlled-alternatives-profile",
    "alternative_id": "filesystem-stage-delete",
    "operation_ref": "op-ref-canary-001",
    "action_family": "filesystem",
    "semantic_category": "write",
    "invocation_phase": "propose",
    "basename_hash": "ab" * 32,
}


@pytest.mark.parametrize("failure_mode", ["scoped_custody", "summary_source"])
def test_live_pinned_scoped_state_blocks_hybrid_preflight_and_decide(
    identity, tmp_path, monkeypatch, failure_mode,
):
    from agentveil_mcp_proxy.console_credentials import (
        save_scoped_runtime_binding_credential,
        scoped_runtime_binding_namespace_hash,
    )

    exchanges: list[str] = []

    def exchange_ok(url, headers, body, method="POST"):
        exchanges.append(url)
        return 200, {"ok": True}

    monkeypatch.setattr(transport, "_run_bounded_exchange", exchange_ok)
    save_runtime_binding_credential(LEGACY_BINDING, home=tmp_path)
    save_credential(SUMMARY_TOKEN, home=tmp_path)
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=identity[1].did,
        summary_token=SUMMARY_TOKEN,
        home=tmp_path,
    )
    runtime_context = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=tmp_path,
    )
    assert runtime_context is not None
    assert runtime_context.contract_version == transport.CONTEXT_VERSION_V2
    assert runtime_context.request("preflight", {}) == (200, {"ok": True})
    assert len(exchanges) == 1
    if failure_mode == "scoped_custody":
        namespace = scoped_runtime_binding_namespace_hash(identity[1].did, SUMMARY_TOKEN)
        bad = tmp_path / "console" / f"runtime-binding-scoped-{namespace}.json"
        bad.write_text("{", encoding="utf-8")
        os.chmod(bad, 0o600)
    else:
        save_credential(SUMMARY_TOKEN_B, home=tmp_path)
    assert runtime_context.request("preflight", {}) == (401, {})
    assert runtime_context.request("decide", _HYBRID_DECIDE_PAYLOAD) == (401, {})
    assert len(exchanges) == 1


def test_legacy_binding_without_summary_retains_av02_transport(
    identity, tmp_path, monkeypatch,
):
    def register_ok(url, headers, body, method="POST"):
        return 200, {
            "schema_version": "runtime/register-response/1",
            "runtime_installation_id": RUNTIME_ID,
        }

    monkeypatch.setattr(transport, "_run_bounded_exchange", register_ok)
    save_runtime_binding_credential(BINDING_TOKEN, home=tmp_path)
    runtime_context = transport.build_controlled_alternative_context(
        agent=identity[1],
        base_url="https://agentveil.dev",
        state_root=tmp_path,
    )
    assert runtime_context.contract_version == transport.CONTEXT_VERSION_V2
    assert callable(runtime_context.runtime_register)

    class LegacyAv02Consumer:
        def bind_runtime_context(self, context):
            for name in (
                "request",
                "heartbeat",
                "runtime_register",
                "policy_evaluate",
                "resolve_decision_verification_key",
                "state_root",
            ):
                if not callable(getattr(context, name, None)) and name != "state_root":
                    raise ValueError(f"missing_{name}")
            if not isinstance(context.state_root, str):
                raise ValueError("missing_state_root")
            self.context = context
            return self

    consumer = transport.bind_installed_runtime_context(
        LegacyAv02Consumer(),
        runtime_context,
    )
    assert consumer.context is runtime_context
    status, _payload = runtime_context.runtime_register(_register_payload())
    assert status == 200
