"""MCP proxy config, policy, and Runtime Gate primitives.

This package currently includes the P1 config/policy foundation, the P2
minimal CLI, the P3 MCP pass-through skeleton, P4 local classification with
privacy hashing, and P5 Runtime Gate enforcement. Approval UI, WAL evidence,
and circuit breaking remain future slices.
"""

from agentveil_mcp_proxy.classification import (
    ClassifiedToolCall,
    ToolCallClassifier,
    extract_resource,
    infer_risk_class,
    sha256_jcs,
    sha256_text,
)
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
from agentveil_mcp_proxy.runtime_gate import (
    RuntimeGateClient,
    RuntimeGateDecision,
    RuntimeGateError,
    RuntimeGateUnavailableError,
    RuntimeGateUntrustedError,
)

__all__ = [
    "ApprovalConfig",
    "AvpConfig",
    "ClassifiedToolCall",
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
    "RuntimeGateClient",
    "RuntimeGateDecision",
    "RuntimeGateError",
    "RuntimeGateUnavailableError",
    "RuntimeGateUntrustedError",
    "TimeoutAction",
    "ToolCallClassifier",
    "ToolCallContext",
    "builtin_policy_pack",
    "extract_resource",
    "infer_risk_class",
    "init_proxy",
    "load_proxy_config",
    "policy_context_hash",
    "proxy_paths",
    "run_proxy",
    "sha256_jcs",
    "sha256_text",
]
