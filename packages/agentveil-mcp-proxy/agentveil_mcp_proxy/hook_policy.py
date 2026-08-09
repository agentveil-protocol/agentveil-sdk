# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Shared connector-neutral policy outcome for native client hooks."""

from __future__ import annotations

from enum import Enum

from agentveil_mcp_proxy.policy import PolicyDecision, PolicyEvaluation


class HookDisposition(str, Enum):
    """Bounded outcome shared by native hook adapters."""

    ALLOW = "allow"
    REDIRECT = "redirect"
    HARD_BLOCK = "hard_block"


def resolve_hook_disposition(
    evaluation: PolicyEvaluation,
    *,
    controlled_route_call: bool = False,
    native_write_redirect_supported: bool = False,
    redirect_route_ready: bool = False,
) -> HookDisposition:
    """Resolve one policy evaluation without inventing hook-side approval."""

    if controlled_route_call:
        return HookDisposition.ALLOW
    if evaluation.decision in (PolicyDecision.ALLOW, PolicyDecision.OBSERVE):
        return HookDisposition.ALLOW
    if (
        evaluation.decision is PolicyDecision.APPROVAL
        and evaluation.risk_class.value == "write"
        and native_write_redirect_supported
        and redirect_route_ready
    ):
        return HookDisposition.REDIRECT
    return HookDisposition.HARD_BLOCK


__all__ = ["HookDisposition", "resolve_hook_disposition"]
