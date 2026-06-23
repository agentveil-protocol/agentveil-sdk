"""Product route catalog and policy for one stable local AgentVeil MCP surface.

Phase 1 defines the explicit accepted local tool catalog and a deterministic
``product_route`` policy. Phase 2 adds the composite ``product`` stdio downstream.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping

from agentveil_mcp_proxy.classification import infer_risk_class
from agentveil_mcp_proxy.policy import (
    POLICY_SCHEMA_VERSION,
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluation,
    PolicyMatch,
    PolicyRule,
    ProxyConfig,
    RiskClass,
    ToolCallContext,
    builtin_policy_pack,
)
from agentveil_mcp_proxy.role_presets import PRODUCT_ROUTE_SETUP_PROFILE
from agentveil_mcp_proxy.product_route_local_fixtures import (
    ProductRouteProfile,
    PRODUCT_ROUTE_WORKSPACE_DIRNAME,
    prepare_product_route_profile,
    resolve_product_route_profile,
)

PRODUCT_ROUTE_POLICY_ID: Final = "product_route"
PRODUCT_ROUTE_DOWNSTREAM_NAME: Final = "product"

PRODUCT_ROUTE_ACCEPTED_PACKS: Final[tuple[str, ...]] = (
    "filesystem",
    "git",
    "package",
    "github",
)

FILESYSTEM_PRODUCT_TOOLS: Final[tuple[str, ...]] = (
    "list_workspace",
    "instruction_surface_status",
    "write_file",
    "delete_file",
    "rmdir_tree",
    "move_file",
    "copy_file",
    "chmod_file",
    "create_symlink",
)

GIT_PRODUCT_TOOLS: Final[tuple[str, ...]] = (
    "git_status",
    "git_log",
    "git_diff",
    "git_show",
    "git_branch",
    "git_add",
    "git_commit",
    "git_checkout",
    "git_create_branch",
    "git_reset",
    "git_clean",
    "git_rebase",
    "git_push",
    "instruction_surface_status",
)

PACKAGE_PRODUCT_TOOLS: Final[tuple[str, ...]] = (
    "package_list_manifest",
    "package_inspect_state",
    "package_risk_status",
    "pip_install",
    "pip_uninstall",
    "pip_update",
    "pip_run_script",
)

GITHUB_PRODUCT_TOOLS: Final[tuple[str, ...]] = (
    "get_repository",
    "list_issues",
    "get_issue",
    "list_pull_requests",
    "get_pull_request",
    "list_comments",
    "list_branches",
    "list_files",
    "list_secret_names",
    "get_repository_settings",
    "list_workflow_runs",
    "list_workflows",
    "get_workflow",
    "list_ci_jobs",
    "get_ci_job",
    "get_package_metadata",
    "untrusted_context_status",
    "github_target_snapshot",
    "ci_repo_target_snapshot",
    "create_comment",
    "create_issue",
    "update_issue",
    "add_labels",
    "remove_labels",
    "request_review",
    "merge_pull_request",
    "close_issue",
    "delete_branch",
    "create_release",
    "update_repository_settings",
    "manage_secret",
    "rerun_workflow",
    "cancel_workflow",
    "dispatch_workflow",
    "publish_package",
    "deploy_release",
    "run_remote_command",
    "get_secret",
    "get_env_secret",
)

_PACK_TOOL_SEQUENCES: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("filesystem", FILESYSTEM_PRODUCT_TOOLS),
    ("git", GIT_PRODUCT_TOOLS),
    ("package", PACKAGE_PRODUCT_TOOLS),
    ("github", GITHUB_PRODUCT_TOOLS),
)


def _merge_product_tool_catalog(
    pack_sequences: tuple[tuple[str, tuple[str, ...]], ...],
) -> tuple[str, ...]:
    """Return catalog tools in stable pack order with intentional first-owner dedupe."""

    catalog: list[str] = []
    seen: set[str] = set()
    for _pack, tools in pack_sequences:
        for tool in tools:
            if tool in seen:
                continue
            seen.add(tool)
            catalog.append(tool)
    return tuple(catalog)


PRODUCT_ROUTE_TOOL_CATALOG: Final[tuple[str, ...]] = _merge_product_tool_catalog(_PACK_TOOL_SEQUENCES)


def _build_tool_pack_map() -> dict[str, str]:
    owners: dict[str, str] = {}
    for pack, tools in _PACK_TOOL_SEQUENCES:
        for tool in tools:
            owners.setdefault(tool, pack)
    return owners


PRODUCT_ROUTE_TOOL_PACK: Final[Mapping[str, str]] = _build_tool_pack_map()


def product_route_tool_pack(tool: str) -> str | None:
    """Return the owning accepted pack for one catalog tool."""

    return PRODUCT_ROUTE_TOOL_PACK.get(tool)


def product_route_rule_id(*, pack: str, tool: str) -> str:
    """Return the deterministic product-route policy rule id for one catalog tool."""

    return f"product_route::{pack}::{tool}"


@dataclass(frozen=True)
class ProductRoutePolicyExpectation:
    """Expected local policy outcome for one catalog tool on the product route."""

    tool: str
    pack: str
    decision: PolicyDecision
    risk_class: RiskClass
    policy_rule_id: str
    source_pack_rule_id: str


def _minimal_proxy_config(*, policy: PolicyConfig) -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "proxy",
            "trusted_signer_dids": ["did:example:product-route-policy-test"],
        },
        "policy": {
            "id": policy.id,
            "policy_schema_version": policy.policy_schema_version,
            "default_decision": policy.default_decision.value,
            "default_risk_class": policy.default_risk_class.value,
            "rules": [
                {
                    "id": rule.id,
                    "source": rule.source,
                    "decision": rule.decision.value,
                    "match": {
                        key: list(getattr(rule.match, key))
                        for key in (
                            "server",
                            "tool",
                            "action",
                            "risk_class",
                            "role",
                            "authority",
                            "action_family",
                        )
                        if getattr(rule.match, key)
                    },
                    **(
                        {"risk_class": rule.risk_class.value}
                        if rule.risk_class is not None
                        else {}
                    ),
                }
                for rule in policy.rules
            ],
        },
    })


def _pack_policy_expectation(*, pack: str, tool: str) -> ProductRoutePolicyExpectation:
    pack_policy = builtin_policy_pack(pack)
    engine = PolicyEngine(_minimal_proxy_config(policy=pack_policy))
    risk = infer_risk_class(f"{pack}.{tool}", tool=tool, resource=None, arguments={})
    evaluation = engine.evaluate(
        ToolCallContext(server=pack, tool=tool, risk_class=risk),
    )
    return ProductRoutePolicyExpectation(
        tool=tool,
        pack=pack,
        decision=evaluation.decision,
        risk_class=evaluation.risk_class,
        policy_rule_id=product_route_rule_id(pack=pack, tool=tool),
        source_pack_rule_id=evaluation.policy_rule_id,
    )


def build_product_route_policy_expectations() -> tuple[ProductRoutePolicyExpectation, ...]:
    """Return deterministic per-tool expectations copied from accepted pack policies."""

    return tuple(
        _pack_policy_expectation(pack=PRODUCT_ROUTE_TOOL_PACK[tool], tool=tool)
        for tool in PRODUCT_ROUTE_TOOL_CATALOG
    )


def build_product_route_policy() -> PolicyConfig:
    """Build the product-route policy using exact catalog tool rules only.

    Wildcard pack rules are not concatenated. Each catalog tool gets one exact
    ``match.tool`` rule with ``match.server`` omitted so evaluation uses the
    stable downstream name ``product`` without cross-pack shadowing.
    """

    rules: list[PolicyRule] = []
    for expectation in build_product_route_policy_expectations():
        rules.append(
            PolicyRule(
                id=expectation.policy_rule_id,
                source="builtin",
                decision=expectation.decision,
                risk_class=expectation.risk_class,
                match=PolicyMatch(tool=(expectation.tool,)),
            ),
        )
    return PolicyConfig(
        id=PRODUCT_ROUTE_POLICY_ID,
        policy_schema_version=POLICY_SCHEMA_VERSION,
        default_decision=PolicyDecision.ASK_BACKEND,
        default_risk_class=RiskClass.UNKNOWN,
        rules=tuple(rules),
    )


_PRODUCT_ROUTE_POLICY_ENGINE: PolicyEngine | None = None


def build_product_route_policy_engine() -> PolicyEngine:
    """Return a policy engine configured for the product route downstream."""

    global _PRODUCT_ROUTE_POLICY_ENGINE
    if _PRODUCT_ROUTE_POLICY_ENGINE is None:
        _PRODUCT_ROUTE_POLICY_ENGINE = PolicyEngine(
            _minimal_proxy_config(policy=build_product_route_policy()),
        )
    return _PRODUCT_ROUTE_POLICY_ENGINE


def evaluate_product_route_tool(
    tool: str,
    *,
    arguments: Mapping[str, object] | None = None,
) -> PolicyEvaluation:
    """Evaluate one catalog tool as brokered through ``product`` downstream."""

    pack = product_route_tool_pack(tool)
    if pack is None:
        raise KeyError(f"{tool!r} is not in PRODUCT_ROUTE_TOOL_CATALOG")
    args = {} if arguments is None else dict(arguments)
    risk = infer_risk_class(
        f"{PRODUCT_ROUTE_DOWNSTREAM_NAME}.{tool}",
        tool=tool,
        resource=None,
        arguments=args,
    )
    return build_product_route_policy_engine().evaluate(
        ToolCallContext(
            server=PRODUCT_ROUTE_DOWNSTREAM_NAME,
            tool=tool,
            risk_class=risk,
        ),
    )


def build_product_route_downstream_env(profile: ProductRouteProfile) -> dict[str, str]:
    """Return deterministic env entries for the composite ``product`` downstream."""

    return {
        "GIT_OUTCOME_LOG": str(profile.git_outcome_log),
        "GITHUB_OUTCOME_LOG": str(profile.github_outcome_log),
        "PACKAGE_OUTCOME_LOG": str(profile.package_outcome_log),
        "LOCAL_DIST_DIR": str(profile.package_dist),
        "PRODUCT_ROUTE_PROFILE_ROOT": str(profile.root),
    }


def build_product_route_downstream_config(profile_root: Path) -> dict[str, Any]:
    """Return proxy downstream config for the composite product route stdio server."""

    profile_root = profile_root.expanduser().resolve()
    profile = resolve_product_route_profile(profile_root)
    server_path = Path(__file__).with_name("product_route_downstream.py")
    return {
        "name": PRODUCT_ROUTE_DOWNSTREAM_NAME,
        "command": sys.executable,
        "args": [str(server_path), str(profile_root)],
        "env": build_product_route_downstream_env(profile),
        "response_timeout_seconds": 10.0,
    }


def initialize_product_route_profile(profile_root: Path) -> ProductRouteProfile:
    """Materialize the local product route profile fixtures and return layout."""

    return prepare_product_route_profile(profile_root)


__all__ = [
    "FILESYSTEM_PRODUCT_TOOLS",
    "GITHUB_PRODUCT_TOOLS",
    "GIT_PRODUCT_TOOLS",
    "PACKAGE_PRODUCT_TOOLS",
    "PRODUCT_ROUTE_ACCEPTED_PACKS",
    "PRODUCT_ROUTE_DOWNSTREAM_NAME",
    "PRODUCT_ROUTE_POLICY_ID",
    "PRODUCT_ROUTE_SETUP_PROFILE",
    "PRODUCT_ROUTE_TOOL_CATALOG",
    "PRODUCT_ROUTE_TOOL_PACK",
    "PRODUCT_ROUTE_WORKSPACE_DIRNAME",
    "ProductRoutePolicyExpectation",
    "build_product_route_downstream_config",
    "build_product_route_downstream_env",
    "build_product_route_policy",
    "build_product_route_policy_engine",
    "build_product_route_policy_expectations",
    "evaluate_product_route_tool",
    "initialize_product_route_profile",
    "product_route_rule_id",
    "product_route_tool_pack",
]
