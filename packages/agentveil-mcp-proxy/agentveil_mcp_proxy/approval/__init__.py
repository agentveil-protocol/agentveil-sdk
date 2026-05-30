"""Local approval surface primitives for MCP Proxy."""

from agentveil_mcp_proxy.approval.headless import (
    HEADLESS_POLICY_SCHEMA_VERSION,
    HeadlessPolicy,
    HeadlessPolicyError,
    HeadlessPreApproval,
)
from agentveil_mcp_proxy.approval.manager import (
    APPROVAL_SCOPE_EXACT,
    APPROVAL_SCOPE_SIMILAR_5M,
    ApprovalFlowError,
    ApprovalManager,
    ApprovalOutcome,
)
from agentveil_mcp_proxy.approval.notification import ApprovalNotifier, NotificationResult
from agentveil_mcp_proxy.approval.server import (
    SECURITY_HEADERS,
    ApprovalPrompt,
    ApprovalServer,
    ApprovalServerDecision,
    ApprovalServerError,
    ApprovalServerGone,
)

__all__ = [
    "APPROVAL_SCOPE_EXACT",
    "APPROVAL_SCOPE_SIMILAR_5M",
    "HEADLESS_POLICY_SCHEMA_VERSION",
    "SECURITY_HEADERS",
    "ApprovalFlowError",
    "ApprovalManager",
    "ApprovalNotifier",
    "ApprovalOutcome",
    "ApprovalPrompt",
    "ApprovalServer",
    "ApprovalServerDecision",
    "ApprovalServerError",
    "ApprovalServerGone",
    "HeadlessPolicy",
    "HeadlessPolicyError",
    "HeadlessPreApproval",
    "NotificationResult",
]
