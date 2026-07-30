"""Bounded content-risk signal wire validation for Runtime Gate requests.

This contract deliberately accepts only boolean local findings. Raw MCP
arguments, prompt text, paths, URLs, tokens, rule identifiers, and payload
hashes do not belong in this object.
"""

from __future__ import annotations

from typing import Any, Mapping

from agentveil.exceptions import AVPValidationError


CONTENT_RISK_SIGNAL_KEYS = frozenset({
    "contains_secret_like_value",
    "destructive_shell_pattern",
    "write_then_execute_risk",
    "credential_exfil_pattern",
})
PAID_POLICY_ROUTE_KIND_MCP_TOOLS_CALL = "mcp_tools_call"


def validate_content_risk_signals(value: Mapping[str, Any]) -> dict[str, bool]:
    """Return the strict, privacy-bounded content-risk signal object."""

    if not isinstance(value, Mapping):
        raise AVPValidationError("content_risk_signals invalid")
    if set(value) != CONTENT_RISK_SIGNAL_KEYS:
        raise AVPValidationError("content_risk_signals keys invalid")
    normalized: dict[str, bool] = {}
    for key in CONTENT_RISK_SIGNAL_KEYS:
        item = value.get(key)
        if type(item) is not bool:
            raise AVPValidationError("content_risk_signals values invalid")
        normalized[key] = item
    return normalized


def validate_paid_policy_route_kind(value: Any) -> str:
    """Accept the only bounded route marker used by the paid provider."""

    if value != PAID_POLICY_ROUTE_KIND_MCP_TOOLS_CALL:
        raise AVPValidationError("paid_policy_route_kind invalid")
    return value
