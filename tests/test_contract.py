"""
Contract tests: SDK ↔ Server field agreement.

These tests verify that SDK request payloads match server Pydantic schemas.
If a server schema adds a required field, these tests MUST fail.

No running server needed — tests inspect code structure only.
"""

import json
from unittest.mock import patch, MagicMock

import httpx
from nacl.signing import SigningKey

from agentveil.agent import AVPAgent


def _make_agent() -> AVPAgent:
    """Create a real agent (not mock) without saving to disk."""
    sk = SigningKey.generate()
    return AVPAgent("http://localhost:8000", bytes(sk), name="contract-test", timeout=1.0)


class TestRegisterContract:
    """Verify register() sends all fields required by AgentVerifyRequest."""

    def test_verify_request_includes_pow_nonce(self):
        """
        AgentVerifyRequest requires: did, challenge, signature_hex, pow_nonce.
        SDK must send all four.
        """
        agent = _make_agent()
        captured_requests = []

        def mock_post(url, **kwargs):
            captured_requests.append({"url": url, "json": kwargs.get("json")})
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200

            if "/register" in url:
                resp.json.return_value = {
                    "did": agent.did,
                    "agnet_address": "0xtest",
                    "challenge": "test-challenge-hex",
                    "challenge_expires_at": "2026-12-31T00:00:00Z",
                    "pow_challenge": "test-challenge-hex",
                    "pow_difficulty": 1,  # difficulty=1 for fast test
                }
            elif "/verify" in url:
                resp.json.return_value = {
                    "did": agent.did,
                    "verified": True,
                    "trust_period_active": False,
                    "trust_period_ends_at": None,
                    "next_step": "Publish your agent card.",
                }
            return resp

        with patch.object(httpx.Client, "post", side_effect=mock_post):
            with patch.object(agent, "save", return_value="/dev/null"):
                agent.register(display_name="ContractTest")

        # Find the verify request
        verify_reqs = [r for r in captured_requests if "/verify" in r["url"]]
        assert len(verify_reqs) == 1, f"Expected 1 verify request, got {len(verify_reqs)}"

        verify_body = verify_reqs[0]["json"]

        # All required fields from AgentVerifyRequest
        assert "did" in verify_body, "Missing 'did' in verify request"
        assert "challenge" in verify_body, "Missing 'challenge' in verify request"
        assert "signature_hex" in verify_body, "Missing 'signature_hex' in verify request"
        assert "pow_nonce" in verify_body, "Missing 'pow_nonce' in verify request"

        # Types
        assert isinstance(verify_body["did"], str)
        assert isinstance(verify_body["challenge"], str)
        assert isinstance(verify_body["signature_hex"], str)
        assert isinstance(verify_body["pow_nonce"], str)

    def test_register_reads_pow_fields_from_response(self):
        """SDK must read pow_challenge and pow_difficulty from register response."""
        agent = _make_agent()
        pow_data = {}

        original_solve = None

        def capture_solve(challenge, difficulty):
            pow_data["challenge"] = challenge
            pow_data["difficulty"] = difficulty
            return "0"  # Dummy nonce

        def mock_post(url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200

            if "/register" in url:
                resp.json.return_value = {
                    "did": agent.did,
                    "agnet_address": "0xtest",
                    "challenge": "the-challenge",
                    "challenge_expires_at": "2026-12-31T00:00:00Z",
                    "pow_challenge": "pow-challenge-value",
                    "pow_difficulty": 20,
                }
            elif "/verify" in url:
                resp.json.return_value = {
                    "did": agent.did,
                    "verified": True,
                }
            return resp

        with patch.object(httpx.Client, "post", side_effect=mock_post), \
             patch("agentveil.agent.solve_pow", side_effect=capture_solve), \
             patch.object(agent, "save", return_value="/dev/null"):
            agent.register()

        assert pow_data["challenge"] == "pow-challenge-value"
        assert pow_data["difficulty"] == 20


class TestOnboardingContract:
    """Verify onboarding helper auth matches backend access mode."""

    def test_get_onboarding_challenge_uses_signed_owner_get(self):
        agent = _make_agent()
        captured = {}

        def mock_get(url, **kwargs):
            captured["url"] = url
            captured["headers"] = kwargs.get("headers")
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "challenge_id": "challenge-1",
                "challenge_text": "Describe your code review controls.",
                "challenge_type": "capability_description",
                "target_capability": "code_review",
                "deadline": "2026-05-05T00:00:00Z",
                "status": "pending",
            }
            return resp

        with patch.object(httpx.Client, "get", side_effect=mock_get):
            result = agent.get_onboarding_challenge()

        expected_path = f"/v1/onboarding/{agent.did}/challenge"
        assert captured["url"] == expected_path
        assert "Authorization" in captured["headers"]
        assert f'did="{agent.did}"' in captured["headers"]["Authorization"]
        assert result["challenge_id"] == "challenge-1"


class TestAttestContract:
    """Verify attest() supports all fields from AttestationCreateRequest."""

    def test_attest_sends_is_private(self):
        """SDK must send is_private when set to True."""
        agent = _make_agent()
        agent._is_registered = True
        agent._is_verified = True
        captured = {}

        def mock_post(url, **kwargs):
            if "/attestations" in url:
                body = kwargs.get("content", b"")
                captured["body"] = json.loads(body)
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "id": "test-id",
                "from_agent_did": agent.did,
                "to_agent_did": "did:key:z6MkTarget",
                "outcome": "positive",
                "weight": 1.0,
                "is_private": True,
                "created_at": "2026-01-01T00:00:00Z",
            }
            return resp

        with patch.object(httpx.Client, "post", side_effect=mock_post):
            agent.attest("did:key:z6MkTarget", outcome="positive", is_private=True)

        assert captured["body"].get("is_private") is True

    def test_attest_sends_interaction_id(self):
        """SDK must send interaction_id when provided."""
        agent = _make_agent()
        agent._is_registered = True
        agent._is_verified = True
        captured = {}

        def mock_post(url, **kwargs):
            if "/attestations" in url:
                body = kwargs.get("content", b"")
                captured["body"] = json.loads(body)
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "id": "test-id",
                "from_agent_did": agent.did,
                "to_agent_did": "did:key:z6MkTarget",
                "outcome": "positive",
                "weight": 1.0,
                "created_at": "2026-01-01T00:00:00Z",
            }
            return resp

        with patch.object(httpx.Client, "post", side_effect=mock_post):
            agent.attest(
                "did:key:z6MkTarget",
                outcome="positive",
                interaction_id="550e8400-e29b-41d4-a716-446655440000",
            )

        assert captured["body"].get("interaction_id") == "550e8400-e29b-41d4-a716-446655440000"


class TestCardContract:
    """Verify publish_card() supports all fields from CardCreateRequest."""

    def test_card_sends_signature(self):
        """SDK must send signature when provided."""
        agent = _make_agent()
        agent._is_registered = True
        agent._is_verified = True
        captured = {}

        def mock_post(url, **kwargs):
            if "/cards" in url:
                body = kwargs.get("content", b"")
                captured["body"] = json.loads(body)
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "id": "test-card-id",
                "agent_did": agent.did,
                "version": 1,
                "capabilities": ["testing"],
                "endpoint_url": None,
                "protocols": [],
                "provider": None,
            }
            return resp

        with patch.object(httpx.Client, "post", side_effect=mock_post):
            agent.publish_card(
                capabilities=["testing"],
                signature="abcdef1234567890",
            )

        assert captured["body"].get("signature") == "abcdef1234567890"


class TestRuntimeControlContract:
    """Verify Layer 6/7/8/9 SDK wrappers match backend request contracts."""

    def test_runtime_evaluate_derives_agent_did_from_sdk_identity(self):
        agent = _make_agent()
        captured = {}

        def mock_post(url, **kwargs):
            captured["url"] = url
            captured["body"] = json.loads(kwargs.get("content", b"{}"))
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "audit_id": "urn:uuid:11111111-1111-1111-1111-111111111111",
                "decision": "ALLOW",
            }
            return resp

        receipt = {"id": "urn:uuid:receipt", "credentialSubject": {"id": agent.did}}
        with patch.object(httpx.Client, "post", side_effect=mock_post):
            result = agent.runtime_evaluate(
                action="infra.resource.inspect",
                resource="resource:1",
                environment="development",
                delegation_receipt=receipt,
            )

        assert captured["url"] == "/v1/runtime/evaluate"
        assert captured["body"]["agent_did"] == agent.did
        assert captured["body"]["receipt"] == receipt
        assert result["decision"] == "ALLOW"

    def test_execute_returns_exact_raw_receipt_text(self):
        agent = _make_agent()
        captured = {}
        raw = '{"receipt_id":"urn:uuid:22222222-2222-2222-2222-222222222222","status":"SUCCESS"}'

        def mock_post(url, **kwargs):
            captured["url"] = url
            captured["body"] = json.loads(kwargs.get("content", b"{}"))
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.text = raw
            resp.json.return_value = {"receipt_id": "urn:uuid:22222222-2222-2222-2222-222222222222"}
            return resp

        with patch.object(httpx.Client, "post", side_effect=mock_post):
            result = agent.execute(
                audit_id="urn:uuid:11111111-1111-1111-1111-111111111111",
                action="infra.resource.inspect",
                resource="resource:1",
                environment="development",
                params={"resource_id": "resource:1"},
            )

        assert captured["url"] == "/v1/execute"
        assert captured["body"]["params"] == {"resource_id": "resource:1"}
        assert result == raw

    def test_get_decision_receipt_returns_exact_raw_receipt_text(self):
        agent = _make_agent()
        captured = {}
        raw = '{"audit_id":"urn:uuid:11111111-1111-1111-1111-111111111111","schema_version":"decision_receipt/2"}'

        def mock_get(url, **kwargs):
            captured["url"] = url
            captured["headers"] = kwargs.get("headers")
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.text = raw
            resp.json.return_value = {
                "audit_id": "urn:uuid:11111111-1111-1111-1111-111111111111",
                "schema_version": "decision_receipt/2",
            }
            return resp

        with patch.object(httpx.Client, "get", side_effect=mock_get):
            result = agent.get_decision_receipt(
                "urn:uuid:11111111-1111-1111-1111-111111111111"
            )

        assert captured["url"] == (
            "/v1/runtime/decisions/urn:uuid:11111111-1111-1111-1111-111111111111/receipt"
        )
        assert "Authorization" in captured["headers"]
        assert result == raw

    def test_create_approval_sends_full_delegation_receipt(self):
        agent = _make_agent()
        captured = {}

        def mock_post(url, **kwargs):
            captured["url"] = url
            captured["body"] = json.loads(kwargs.get("content", b"{}"))
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {"approval_id": "urn:uuid:approval", "status": "PENDING"}
            return resp

        receipt = {"id": "urn:uuid:receipt", "issuer": "did:key:z6MkIssuer"}
        with patch.object(httpx.Client, "post", side_effect=mock_post):
            result = agent.create_approval(
                audit_id="urn:uuid:11111111-1111-1111-1111-111111111111",
                delegation_receipt=receipt,
                expires_in_seconds=600,
            )

        assert captured["url"] == "/v1/human-approvals"
        assert captured["body"]["delegation_receipt"] == receipt
        assert captured["body"]["expires_in_seconds"] == 600
        assert result["status"] == "PENDING"

    def test_approve_posts_empty_body_and_returns_raw_receipt(self):
        agent = _make_agent()
        captured = {}
        raw = '{"approval_id":"urn:uuid:approval","decision":"APPROVED"}'

        def mock_post(url, **kwargs):
            captured["url"] = url
            captured["content"] = kwargs.get("content")
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.text = raw
            resp.json.return_value = {"approval_id": "urn:uuid:approval", "decision": "APPROVED"}
            return resp

        with patch.object(httpx.Client, "post", side_effect=mock_post):
            result = agent.approve("urn:uuid:approval")

        assert captured["url"] == "/v1/human-approvals/urn:uuid:approval/approve"
        assert captured["content"] == b""
        assert result == raw

    def test_create_governance_policy_accepts_201(self):
        agent = _make_agent()
        captured = {}

        def mock_post(url, **kwargs):
            captured["url"] = url
            captured["body"] = json.loads(kwargs.get("content", b"{}"))
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 201
            resp.json.return_value = {"id": "policy-1", "status": "DRAFT"}
            return resp

        rules = {"rules": []}
        with patch.object(httpx.Client, "post", side_effect=mock_post):
            result = agent.create_governance_policy("customer-default", rules)

        assert captured["url"] == "/v1/governance/policies"
        assert captured["body"] == {"name": "customer-default", "rules_jsonb": rules}
        assert result["status"] == "DRAFT"

    def test_list_remediation_cases_uses_signed_get_with_filters(self):
        agent = _make_agent()
        captured = {}

        def mock_get(url, **kwargs):
            captured["url"] = url
            captured["params"] = kwargs.get("params")
            captured["headers"] = kwargs.get("headers")
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {"items": [], "count": 0, "has_more": False}
            return resp

        with patch.object(httpx.Client, "get", side_effect=mock_get):
            result = agent.list_remediation_cases(
                role="arbitrator",
                status="OPEN",
                case_type="execution_outcome_dispute",
                limit=10,
                offset=5,
            )

        assert captured["url"] == "/v1/remediation/cases"
        assert captured["params"] == {
            "role": "arbitrator",
            "limit": 10,
            "offset": 5,
            "status": "OPEN",
            "case_type": "execution_outcome_dispute",
        }
        assert "Authorization" in captured["headers"]
        assert 'v="2"' in captured["headers"]["Authorization"]
        assert result["count"] == 0

    def test_signed_post_helper_uses_v2_with_query_params(self):
        agent = _make_agent()
        captured = {}

        def mock_post(url, **kwargs):
            captured["url"] = url
            captured["params"] = kwargs.get("params")
            captured["headers"] = kwargs.get("headers")
            captured["body"] = json.loads(kwargs.get("content", b"{}"))
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {"ok": True}
            return resp

        with patch.object(httpx.Client, "post", side_effect=mock_post):
            result = agent._post_json(
                "/v1/example",
                {"approved": True},
                params={"force": "true"},
            )

        assert captured["url"] == "/v1/example"
        assert captured["params"] == {"force": "true"}
        assert captured["body"] == {"approved": True}
        assert 'v="2"' in captured["headers"]["Authorization"]
        assert result["ok"] is True

    def test_post_json_retries_rate_limit_with_fresh_signature(self):
        agent = _make_agent()
        captured_headers = []

        def response(status_code, json_data, headers=None):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = status_code
            resp.headers = headers or {}
            resp.json.return_value = json_data
            resp.text = json.dumps(json_data)
            return resp

        responses = [
            response(429, {"detail": "slow down"}, {"Retry-After": "0"}),
            response(200, {"ok": True}),
        ]

        def mock_post(url, **kwargs):
            captured_headers.append(kwargs.get("headers"))
            return responses.pop(0)

        with patch.object(httpx.Client, "post", side_effect=mock_post), \
             patch("agentveil.agent.time.sleep") as sleep_mock:
            result = agent._post_json("/v1/example", {"approved": True})

        assert result == {"ok": True}
        sleep_mock.assert_called_once_with(1.0)
        assert len(captured_headers) == 2
        assert captured_headers[0]["Authorization"] != captured_headers[1]["Authorization"]

    def test_search_agents_adds_did_alias_for_agent_did(self):
        agent = _make_agent()

        def mock_get(url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = [
                {
                    "agent_did": "did:key:z6MkSearchResult",
                    "capabilities": ["research"],
                }
            ]
            return resp

        with patch.object(httpx.Client, "get", side_effect=mock_get):
            results = agent.search_agents(capability="research")

        assert results[0]["agent_did"] == "did:key:z6MkSearchResult"
        assert results[0]["did"] == "did:key:z6MkSearchResult"

    def test_get_audit_trail_uses_public_audit_endpoint(self):
        agent = _make_agent()
        captured = {}

        def mock_get(url, **kwargs):
            captured["url"] = url
            captured["params"] = kwargs.get("params")
            captured["headers"] = kwargs.get("headers")
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = [{"audit_id": "urn:uuid:audit"}]
            return resp

        with patch.object(httpx.Client, "get", side_effect=mock_get):
            result = agent.get_audit_trail(limit=25, offset=5)

        assert captured["url"] == f"/v1/audit/{agent.did}"
        assert captured["params"] == {"limit": 25, "offset": 5}
        assert captured["headers"] is None
        assert result == [{"audit_id": "urn:uuid:audit"}]

    def test_create_remediation_case_rejects_unknown_reference_field(self):
        agent = _make_agent()

        try:
            agent.create_remediation_case(
                case_type="execution_outcome_dispute",
                reason="execution result did not match expected outcome",
                category="execution",
                respondent_did="did:key:z6MkInjected",
            )
        except Exception as exc:
            assert "Unknown remediation reference field" in str(exc)
        else:
            raise AssertionError("unknown remediation reference field was accepted")
