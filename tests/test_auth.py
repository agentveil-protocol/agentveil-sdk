"""Tests for AVP authentication: signature generation and header format."""

import hashlib
import re
import time

import pytest
from nacl.signing import VerifyKey

from agentveil.auth import build_auth_header, canonicalize_query_params
from agentveil.agent import AVPAgent


class TestBuildAuthHeader:
    """AVP-Sig authentication header construction."""

    def test_header_format(self, private_key, did):
        headers = build_auth_header(private_key, did, "POST", "/v1/attestations")
        auth = headers["Authorization"]
        assert auth.startswith("AVP-Sig ")
        assert f'did="{did}"' in auth
        assert 'ts="' in auth
        assert 'nonce="' in auth
        assert 'sig="' in auth

    def test_content_type_is_json(self, private_key, did):
        headers = build_auth_header(private_key, did, "GET", "/v1/health")
        assert headers["Content-Type"] == "application/json"

    def test_signature_is_valid_ed25519(self, private_key, did, public_key):
        body = b'{"test": true}'
        headers = build_auth_header(private_key, did, "POST", "/v1/test", body)
        auth = headers["Authorization"]

        # Extract components
        ts = re.search(r'ts="(\d+)"', auth).group(1)
        nonce = re.search(r'nonce="([^"]+)"', auth).group(1)
        sig_hex = re.search(r'sig="([^"]+)"', auth).group(1)

        # Reconstruct signed message
        body_hash = hashlib.sha256(body).hexdigest()
        message = f"POST:/v1/test:{ts}:{nonce}:{body_hash}"

        # Verify signature
        verify_key = VerifyKey(public_key)
        signature = bytes.fromhex(sig_hex)
        verify_key.verify(message.encode(), signature)  # raises if invalid

    def test_v2_signature_binds_canonical_query(self, private_key, did, public_key):
        body = b""
        params = {
            "role": "party",
            "status": "OPEN",
            "limit": 10,
            "offset": 0,
        }
        headers = build_auth_header(
            private_key,
            did,
            "GET",
            "/v1/remediation/cases",
            body,
            params=params,
        )
        auth = headers["Authorization"]
        assert 'v="2"' in auth

        ts = re.search(r'ts="(\d+)"', auth).group(1)
        nonce = re.search(r'nonce="([^"]+)"', auth).group(1)
        sig_hex = re.search(r'sig="([^"]+)"', auth).group(1)

        body_hash = hashlib.sha256(body).hexdigest()
        query = canonicalize_query_params(params)
        message = f"v2:GET:/v1/remediation/cases:{query}:{ts}:{nonce}:{body_hash}"

        verify_key = VerifyKey(public_key)
        signature = bytes.fromhex(sig_hex)
        verify_key.verify(message.encode(), signature)

    def test_v2_signature_applies_to_any_method_with_query(self, private_key, did, public_key):
        body = b'{"approved":true}'
        params = {"force": "true"}
        headers = build_auth_header(
            private_key,
            did,
            "POST",
            "/v1/remediation/cases/123/resolve",
            body,
            params=params,
        )
        auth = headers["Authorization"]
        assert 'v="2"' in auth

        ts = re.search(r'ts="(\d+)"', auth).group(1)
        nonce = re.search(r'nonce="([^"]+)"', auth).group(1)
        sig_hex = re.search(r'sig="([^"]+)"', auth).group(1)

        body_hash = hashlib.sha256(body).hexdigest()
        query = canonicalize_query_params(params)
        message = f"v2:POST:/v1/remediation/cases/123/resolve:{query}:{ts}:{nonce}:{body_hash}"

        verify_key = VerifyKey(public_key)
        signature = bytes.fromhex(sig_hex)
        verify_key.verify(message.encode(), signature)

    def test_v2_canonical_query_is_stable(self):
        params = {"b": "hello world", "a": ["2", "1"], "empty": ""}
        assert canonicalize_query_params(params) == "a=1&a=2&b=hello%20world&empty="

    def test_v2_canonical_query_encodes_spaces_as_percent_20(self):
        assert canonicalize_query_params({"reason": "foo bar"}) == "reason=foo%20bar"

    def test_timestamp_is_current(self, private_key, did):
        before = int(time.time())
        headers = build_auth_header(private_key, did, "GET", "/v1/health")
        after = int(time.time())

        ts = int(re.search(r'ts="(\d+)"', headers["Authorization"]).group(1))
        assert before <= ts <= after

    def test_nonce_is_unique(self, private_key, did):
        h1 = build_auth_header(private_key, did, "GET", "/v1/health")
        h2 = build_auth_header(private_key, did, "GET", "/v1/health")
        nonce1 = re.search(r'nonce="([^"]+)"', h1["Authorization"]).group(1)
        nonce2 = re.search(r'nonce="([^"]+)"', h2["Authorization"]).group(1)
        assert nonce1 != nonce2

    def test_empty_body_uses_empty_hash(self, private_key, did):
        headers = build_auth_header(private_key, did, "GET", "/v1/health", b"")
        auth = headers["Authorization"]
        sig_hex = re.search(r'sig="([^"]+)"', auth).group(1)
        assert len(sig_hex) == 128  # Ed25519 signature = 64 bytes = 128 hex

    def test_different_bodies_produce_different_signatures(self, private_key, did):
        h1 = build_auth_header(private_key, did, "POST", "/v1/test", b'{"a":1}')
        h2 = build_auth_header(private_key, did, "POST", "/v1/test", b'{"a":2}')
        sig1 = re.search(r'sig="([^"]+)"', h1["Authorization"]).group(1)
        sig2 = re.search(r'sig="([^"]+)"', h2["Authorization"]).group(1)
        assert sig1 != sig2


class TestQuerylessForceV2:
    """Explicit AVP-Sig v2 opt-in for queryless requests."""

    def _verify_v2_message(self, auth: str, *, method: str, path: str, body: bytes, public_key: bytes, query: str = ""):
        ts = re.search(r'ts="(\d+)"', auth).group(1)
        nonce = re.search(r'nonce="([^"]+)"', auth).group(1)
        sig_hex = re.search(r'sig="([^"]+)"', auth).group(1)
        body_hash = hashlib.sha256(body).hexdigest()
        message = f"v2:{method}:{path}:{query}:{ts}:{nonce}:{body_hash}"
        VerifyKey(public_key).verify(message.encode(), bytes.fromhex(sig_hex))

    def test_queryless_force_v2_emits_v2_and_verifies(self, private_key, did, public_key):
        headers = build_auth_header(
            private_key,
            did,
            "GET",
            "/v1/runtime/decide",
            force_v2=True,
        )
        auth = headers["Authorization"]
        assert 'v="2"' in auth
        self._verify_v2_message(
            auth,
            method="GET",
            path="/v1/runtime/decide",
            body=b"",
            public_key=public_key,
        )

    def test_queryless_force_v2_binds_post_body(self, private_key, did, public_key):
        body = b'{"action":"write_file"}'
        headers = build_auth_header(
            private_key,
            did,
            "POST",
            "/v1/runtime/decide",
            body,
            force_v2=True,
        )
        auth = headers["Authorization"]
        assert 'v="2"' in auth
        self._verify_v2_message(
            auth,
            method="POST",
            path="/v1/runtime/decide",
            body=body,
            public_key=public_key,
        )

    def test_queryless_default_remains_v1(self, private_key, did, public_key):
        body = b""
        headers = build_auth_header(private_key, did, "GET", "/v1/health", body)
        auth = headers["Authorization"]
        assert 'v="2"' not in auth

        ts = re.search(r'ts="(\d+)"', auth).group(1)
        nonce = re.search(r'nonce="([^"]+)"', auth).group(1)
        sig_hex = re.search(r'sig="([^"]+)"', auth).group(1)
        body_hash = hashlib.sha256(body).hexdigest()
        message = f"GET:/v1/health:{ts}:{nonce}:{body_hash}"
        VerifyKey(public_key).verify(message.encode(), bytes.fromhex(sig_hex))

    def test_empty_params_dict_is_v1_by_default_and_v2_when_forced(self, private_key, did, public_key):
        default_headers = build_auth_header(
            private_key,
            did,
            "GET",
            "/v1/health",
            params={},
        )
        assert 'v="2"' not in default_headers["Authorization"]

        forced_headers = build_auth_header(
            private_key,
            did,
            "GET",
            "/v1/health",
            params={},
            force_v2=True,
        )
        assert 'v="2"' in forced_headers["Authorization"]
        self._verify_v2_message(
            forced_headers["Authorization"],
            method="GET",
            path="/v1/health",
            body=b"",
            public_key=public_key,
        )

    def test_force_v2_false_matches_legacy_default(self, private_key, did):
        legacy = build_auth_header(private_key, did, "POST", "/v1/test", b"{}")
        explicit = build_auth_header(
            private_key,
            did,
            "POST",
            "/v1/test",
            b"{}",
            force_v2=False,
        )
        for key in ("Authorization", "Content-Type"):
            legacy_auth = legacy[key]
            explicit_auth = explicit[key]
            if key == "Authorization":
                assert ('v="2"' in legacy_auth) == ('v="2"' in explicit_auth)
                assert legacy_auth.startswith("AVP-Sig ")
                assert explicit_auth.startswith("AVP-Sig ")
            else:
                assert legacy_auth == explicit_auth

    @pytest.mark.parametrize("invalid_force_v2", [1, 0, "true", "false", None, []])
    def test_non_boolean_force_v2_is_rejected(self, private_key, did, invalid_force_v2):
        with pytest.raises(TypeError, match="force_v2 must be a bool"):
            build_auth_header(
                private_key,
                did,
                "GET",
                "/v1/health",
                force_v2=invalid_force_v2,
            )

    def test_agent_auth_headers_remain_legacy_without_force_v2(self, private_key, did, public_key):
        agent = AVPAgent("https://example.com", private_key)
        assert agent._did == did

        queryless = agent._auth_headers("GET", "/v1/health")
        assert 'v="2"' not in queryless["Authorization"]

        with_query = agent._auth_headers(
            "GET",
            "/v1/remediation/cases",
            params={"status": "OPEN"},
        )
        assert 'v="2"' in with_query["Authorization"]
        self._verify_v2_message(
            with_query["Authorization"],
            method="GET",
            path="/v1/remediation/cases",
            body=b"",
            public_key=public_key,
            query=canonicalize_query_params({"status": "OPEN"}),
        )
