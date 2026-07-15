"""Client-side bounding for Runtime Gate install_clone_context."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
from nacl.signing import SigningKey

from agentveil.agent import AVPAgent, _public_key_to_did
from agentveil.exceptions import AVPValidationError
from agentveil.runtime_install_clone import (
    validate_install_clone_context,
    validate_metadata_evidence_slot,
)

AGENT_SEED = bytes.fromhex("44" * 32)
VALID_HASH = "sha256:" + ("ab" * 32)


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


def test_validate_install_clone_context_accepts_bounded_metadata_evidence():
    bounded = validate_install_clone_context(
        _bounded_context(
            readme={
                "signal_code": "install_hint",
                "evidence_ref": "ev_readme_001",
                "content_hash": VALID_HASH,
            },
            tool_output={"signal_code": "package_reference"},
            mcp_schema={
                "signal_code": "tool_declares_install",
                "evidence_ref": "ev_mcp_schema_package_route",
            },
            file_metadata={"signal_code": "config_package_ref"},
        )
    )
    assert bounded["readme"]["signal_code"] == "install_hint"
    assert bounded["tool_output"]["signal_code"] == "package_reference"
    assert bounded["mcp_schema"]["evidence_ref"] == "ev_mcp_schema_package_route"
    assert bounded["file_metadata"]["signal_code"] == "config_package_ref"
    text = json.dumps(bounded, sort_keys=True)
    assert "raw_readme" not in text
    assert "https://" not in text


def test_validate_install_clone_context_rejects_extra_keys():
    with pytest.raises(AVPValidationError, match="forbidden keys"):
        validate_install_clone_context(_bounded_context(artifact_id="art_x"))


def test_validate_install_clone_context_rejects_unknown_evidence_slot_fields():
    with pytest.raises(AVPValidationError, match="forbidden keys"):
        validate_install_clone_context(
            _bounded_context(
                readme={
                    "signal_code": "install_hint",
                    "raw_readme": "pip install evil",
                }
            )
        )


def test_validate_install_clone_context_rejects_wrong_channel_signal_code():
    with pytest.raises(AVPValidationError, match="signal_code"):
        validate_install_clone_context(
            _bounded_context(readme={"signal_code": "package_reference"})
        )


def test_validate_install_clone_context_rejects_raw_url_in_content_hash():
    with pytest.raises(AVPValidationError):
        validate_install_clone_context(
            _bounded_context(
                readme={
                    "signal_code": "install_hint",
                    "content_hash": "https://evil.example/readme.md",
                }
            )
        )


def test_validate_metadata_evidence_slot_rejects_without_echoing_raw_input():
    with pytest.raises(AVPValidationError) as exc_info:
        validate_metadata_evidence_slot(
            "readme",
            {
                "signal_code": "install_hint",
                "content_hash": "https://evil.example/secret-readme",
            },
        )
    assert "evil.example" not in str(exc_info.value)
    assert "secret-readme" not in str(exc_info.value)


@pytest.mark.parametrize(
    "overrides",
    [
        {"source_ref": "https://evil.example/pkg.whl"},
        {"source_ref": "/Users/secret/proj"},
        {"requested_package": "raw-secret-package-name"},
        {"intent_source": "not_a_real_intent"},
        {"operation": "download"},
        {"readme_signal": {"signal_code": "install_hint"}},
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
            install_clone_context=_bounded_context(
                mcp_schema={
                    "signal_code": "tool_declares_install",
                    "evidence_ref": "ev_mcp_schema_package_route",
                },
                readme={
                    "signal_code": "install_hint",
                    "evidence_ref": "ev_readme_001",
                    "content_hash": VALID_HASH,
                },
            ),
        )

    body = captured["body"]
    assert captured["url"] == "/v1/runtime/evaluate"
    assert body["install_clone_context"]["source_ref"] == "src_package_route_builtin"
    assert body["install_clone_context"]["mcp_schema"]["signal_code"] == "tool_declares_install"
    assert body["install_clone_context"]["readme"]["signal_code"] == "install_hint"
    body_text = json.dumps(body, sort_keys=True)
    assert "https://" not in body_text
    assert "/Users/" not in body_text
    assert "pip install" not in body_text
    assert _public_key_to_did(bytes(SigningKey(AGENT_SEED).verify_key)) == body["agent_did"]
