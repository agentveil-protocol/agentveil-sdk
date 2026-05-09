"""Experimental MCP proxy config and policy primitives.

This package currently includes the P1 config/policy foundation, the P2
minimal CLI, and the P3 MCP pass-through skeleton. It does not implement
backend Runtime Gate calls, approval UI, or enforcement yet.
"""

from agentveil_mcp_proxy.cli import init_proxy, load_proxy_config, proxy_paths, run_proxy
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough, PassthroughError
from agentveil_mcp_proxy.policy import (
    ApprovalConfig,
    AvpConfig,
    DecisionMode,
    FallbackConfig,
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluation,
    PolicyMatch,
    PolicyReloadResult,
    PolicyRule,
    PolicyRuntime,
    PrivacyConfig,
    ProxyConfig,
    ProxyConfigError,
    RiskClass,
    TimeoutAction,
    ToolCallContext,
    builtin_policy_pack,
    policy_context_hash,
)

__all__ = [
    "ApprovalConfig",
    "AvpConfig",
    "DecisionMode",
    "DownstreamConfig",
    "FallbackConfig",
    "McpPassthrough",
    "PassthroughError",
    "PolicyConfig",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyEvaluation",
    "PolicyMatch",
    "PolicyReloadResult",
    "PolicyRule",
    "PolicyRuntime",
    "PrivacyConfig",
    "ProxyConfig",
    "ProxyConfigError",
    "RiskClass",
    "TimeoutAction",
    "ToolCallContext",
    "builtin_policy_pack",
    "init_proxy",
    "load_proxy_config",
    "policy_context_hash",
    "proxy_paths",
    "run_proxy",
]
