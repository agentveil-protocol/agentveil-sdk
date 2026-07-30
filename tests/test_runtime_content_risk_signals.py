"""Strict public Runtime Gate content-risk wire contract tests."""

from __future__ import annotations

import pytest

from agentveil.exceptions import AVPValidationError
from agentveil.runtime_content_risk_signals import (
    PAID_POLICY_ROUTE_KIND_MCP_TOOLS_CALL,
    validate_content_risk_signals,
    validate_paid_policy_route_kind,
)


def _signals(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "contains_secret_like_value": False,
        "destructive_shell_pattern": False,
        "write_then_execute_risk": False,
        "credential_exfil_pattern": False,
    }
    payload.update(overrides)
    return payload


def test_content_risk_signals_accept_only_the_closed_boolean_vocabulary() -> None:
    assert validate_content_risk_signals(_signals(destructive_shell_pattern=True)) == {
        "contains_secret_like_value": False,
        "destructive_shell_pattern": True,
        "write_then_execute_risk": False,
        "credential_exfil_pattern": False,
    }


def test_paid_policy_route_kind_accepts_only_the_non_sensitive_mcp_marker() -> None:
    assert validate_paid_policy_route_kind("mcp_tools_call") == (
        PAID_POLICY_ROUTE_KIND_MCP_TOOLS_CALL
    )
    with pytest.raises(AVPValidationError):
        validate_paid_policy_route_kind("github.create_issue")


def test_paid_policy_route_kind_requires_the_bounded_signal_object() -> None:
    from agentveil.agent import AVPAgent

    agent = AVPAgent("https://agentveil.dev", bytes.fromhex("44" * 32))
    with pytest.raises(AVPValidationError, match="requires content_risk_signals"):
        agent.runtime_evaluate(
            action="privacy.redacted",
            resource="sha256:" + ("a" * 64),
            environment="unknown",
            delegation_receipt={"id": "grant"},
            paid_policy_route_kind=PAID_POLICY_ROUTE_KIND_MCP_TOOLS_CALL,
        )


@pytest.mark.parametrize(
    "payload",
    [
        _signals(destructive_shell_pattern="true"),
        _signals(raw_payload="AKIA0123456789ABCDEF"),
        {"contains_secret_like_value": False},
    ],
)
def test_content_risk_signals_reject_values_or_fields_that_could_leak_content(
    payload: dict[str, object],
) -> None:
    with pytest.raises(AVPValidationError):
        validate_content_risk_signals(payload)
