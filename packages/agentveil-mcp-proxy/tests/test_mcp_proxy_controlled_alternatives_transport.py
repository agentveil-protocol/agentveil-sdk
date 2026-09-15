"""Per-process CA transport boundaries with generated identity and HTTP transport."""

import gzip
import hashlib
import json
import re
import socketserver
import threading
import time
from types import SimpleNamespace

import httpx
from nacl.signing import SigningKey
import pytest

from agentveil_mcp_proxy import controlled_alternatives as ca
from agentveil_mcp_proxy import controlled_alternatives_transport as transport


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
