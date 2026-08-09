# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

import pytest

from agentveil_mcp_proxy.hook_policy import HookDisposition, resolve_hook_disposition
from agentveil_mcp_proxy.policy import PolicyDecision, PolicyEvaluation, RiskClass


def _evaluation(decision: PolicyDecision, risk: RiskClass) -> PolicyEvaluation:
    return PolicyEvaluation(
        decision=decision,
        risk_class=risk,
        policy_id="hook-test",
        policy_rule_id=None,
        policy_context_hash="bounded",
        matched_rule_ids=(),
    )


@pytest.mark.parametrize("decision", [PolicyDecision.ALLOW, PolicyDecision.OBSERVE])
def test_safe_policy_outcomes_allow(decision: PolicyDecision) -> None:
    assert resolve_hook_disposition(_evaluation(decision, RiskClass.READ)) is HookDisposition.ALLOW


def test_controlled_route_call_passes_through_to_proxy_authority() -> None:
    result = resolve_hook_disposition(
        _evaluation(PolicyDecision.APPROVAL, RiskClass.WRITE),
        controlled_route_call=True,
    )
    assert result is HookDisposition.ALLOW


def test_native_write_redirect_requires_real_ready_route() -> None:
    evaluation = _evaluation(PolicyDecision.APPROVAL, RiskClass.WRITE)
    assert resolve_hook_disposition(
        evaluation,
        native_write_redirect_supported=True,
        redirect_route_ready=True,
    ) is HookDisposition.REDIRECT
    assert resolve_hook_disposition(
        evaluation,
        native_write_redirect_supported=True,
        redirect_route_ready=False,
    ) is HookDisposition.HARD_BLOCK


@pytest.mark.parametrize(
    "decision,risk",
    [
        (PolicyDecision.BLOCK, RiskClass.DESTRUCTIVE),
        (PolicyDecision.ASK_BACKEND, RiskClass.UNKNOWN),
        # claim-check: allow production risk enum in hard-block negative test.
        (PolicyDecision.APPROVAL, RiskClass.PRODUCTION),
    ],
)
def test_dangerous_or_unknown_authority_stays_hard_blocked(
    decision: PolicyDecision,
    risk: RiskClass,
) -> None:
    assert resolve_hook_disposition(
        _evaluation(decision, risk),
        native_write_redirect_supported=True,
        redirect_route_ready=True,
    ) is HookDisposition.HARD_BLOCK
