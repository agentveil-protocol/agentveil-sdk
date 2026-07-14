"""Client-side bounding for Runtime Gate install_clone_context."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
from nacl.signing import SigningKey

from agentveil.agent import AVPAgent, _public_key_to_did
from agentveil.exceptions import AVPValidationError
from agentveil.runtime_install_clone import validate_install_clone_context

AGENT_SEED = bytes.fromhex("44" * 32)


def _bounded_context(**overrides):
    payload = {
        "operation": "install",
        "source_ref": "src_package_route_builtin",
        "source_ref_kind": "workspace_registry",
        "user_pinned_source": False,
        "intent_source": "user_direct",
        "target_source": "workspace_registry",
        "tool_source": "approved_registry",
        "metadata_influence": "none",
        "requested_package": "pkg_package_route_builtin",
        "expected_package": "pkg_package_route_builtin",
    }
    payload.update(overrides)
    return payload


def test_validate_install_clone_context_accepts_bounded_payload():
    bounded = validate_install_clone_context(_bounded_context())
    assert bounded["source_ref"] == "src_package_route_builtin"
    assert "artifact_id" not in bounded


def test_validate_install_clone_context_rejects_extra_keys():
    with pytest.raises(AVPValidationError, match="forbidden keys"):
        validate_install_clone_context(_bounded_context(artifact_id="art_x"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"source_ref": "https://evil.example/pkg.whl"},
        {"source_ref": "/Users/secret/proj"},
        {"requested_package": "raw-secret-package-name"},
        {"intent_source": "not_a_real_intent"},
        {"operation": "download"},
    ],
)
def test_validate_install_clone_context_rejects_raw_or_invalid(overrides):
    with pytest.raises(AVPValidationError):
        validate_install_clone_context(_bounded_context(**overrides))


def test_avp_agent_runtime_evaluate_rejects_raw_context_before_http_post():
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="privacy-probe", timeout=2.0)
    posted = {"called": False}

    def mock_post(*_args, **_kwargs):
        posted["called"] = True
        raise AssertionError("HTTP post must not run for invalid install_clone_context")

    with patch.object(httpx.Client, "post", side_effect=mock_post):
        with pytest.raises(AVPValidationError):
            agent.runtime_evaluate(
                action="package.pip_install",
                resource="redacted",
                environment="mcp_proxy",
                delegation_receipt={"id": "grant"},
                payload_hash="sha256:" + ("a" * 64),
                risk_class="write",
                policy_context_hash="sha256:" + ("b" * 64),
                install_clone_context=_bounded_context(
                    source_ref="https://evil.example/pkg.whl",
                    requested_package="/Users/secret/proj",
                ),
            )
    assert posted["called"] is False


def test_avp_agent_runtime_evaluate_posts_only_bounded_context():
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="bounded-probe", timeout=2.0)
    captured: dict[str, object] = {}

    def mock_post(url, **kwargs):
        body = json.loads(kwargs["content"])
        captured["url"] = url
        captured["body"] = body
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {"decision": "ALLOW", "audit_id": "urn:uuid:x"}
        return response

    with patch.object(httpx.Client, "post", side_effect=mock_post):
        agent.runtime_evaluate(
            action="package.pip_install",
            resource="redacted",
            environment="mcp_proxy",
            delegation_receipt={"id": "grant"},
            payload_hash="sha256:" + ("a" * 64),
            risk_class="write",
            policy_context_hash="sha256:" + ("b" * 64),
            install_clone_context=_bounded_context(),
        )

    body = captured["body"]
    assert captured["url"] == "/v1/runtime/evaluate"
    assert body["install_clone_context"]["source_ref"] == "src_package_route_builtin"
    body_text = json.dumps(body, sort_keys=True)
    assert "https://" not in body_text
    assert "/Users/" not in body_text
    assert _public_key_to_did(bytes(SigningKey(AGENT_SEED).verify_key)) == body["agent_did"]
