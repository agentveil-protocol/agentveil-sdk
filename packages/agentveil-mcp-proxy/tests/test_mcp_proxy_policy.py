"""P1 tests for MCP proxy config schema and internal local policy engine.

These tests intentionally do not start MCP transport, do not call AVP backend,
and do not exercise approval UI. P1 is only the local config/policy foundation.
"""

from __future__ import annotations

import re

import pytest

from agentveil_mcp_proxy import (
    DecisionMode,
    FallbackConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyRuntime,
    ProxyConfig,
    ProxyConfigError,
    RiskClass,
    RoleAuthorityMode,
    ToolCallContext,
    ToolSurfaceConfig,
    ToolSurfaceMode,
    builtin_policy_pack,
    policy_context_hash,
)
from agentveil_mcp_proxy.cli import quickstart_filesystem_downstream
from agentveil_mcp_proxy.policy import (
    PRODUCT_ROUTE_SETUP_PROFILE,
    SAFE_AUTOPILOT_SETUP_PROFILE,
    build_controlled_path_metadata,
)


TRUSTED_SIGNER_DID = "did:key:z6MktrustedSigner"


def _base_config(**overrides):
    data = {
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "local-proxy",
            "trusted_signer_dids": [TRUSTED_SIGNER_DID],
        },
        "mode": "protect",
        "privacy": {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "fallback": {
            "read": "allow",
            "write": "approval",
            "destructive": "block",
            "production": "block",
            "financial": "block",
            "unknown": "approval",
        },
        "approval": {
            "approval_timeout_seconds": 300,
            "on_timeout": "deny",
        },
        "policy": {
            "id": "test-policy",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "unknown",
            "rules": [],
        },
    }
    data.update(overrides)
    return data


def _pack_config(name: str) -> ProxyConfig:
    pack = builtin_policy_pack(name)

    def match_dict(rule):
        data = {}
        if rule.match.server:
            data["server"] = list(rule.match.server)
        if rule.match.tool:
            data["tool"] = list(rule.match.tool)
        if rule.match.action:
            data["action"] = list(rule.match.action)
        if rule.match.risk_class:
            data["risk_class"] = [risk.value for risk in rule.match.risk_class]
        return data

    return ProxyConfig.from_dict(_base_config(policy={
        "id": pack.id,
        "policy_schema_version": 1,
        "rules": [
            {
                "id": rule.id,
                "source": rule.source,
                "decision": rule.decision.value,
                "risk_class": rule.risk_class.value if rule.risk_class else None,
                "match": match_dict(rule),
            }
            for rule in pack.rules
        ],
    }))


def _evaluate_builtin_pack(name: str, *, server: str, tool: str):
    return PolicyEngine(_pack_config(name)).evaluate({
        "server": server,
        "tool": tool,
    })


def test_proxy_config_schema_requires_version_and_trusted_signers():
    cfg = ProxyConfig.from_dict(_base_config())
    assert cfg.proxy_config_schema_version == 1
    assert cfg.policy.policy_schema_version == 1
    assert cfg.avp.trusted_signer_dids == (TRUSTED_SIGNER_DID,)
    assert cfg.privacy.payload == "hash_only"
    assert cfg.approval.approval_timeout_seconds == 300
    assert cfg.approval.on_timeout.value == "deny"
    assert cfg.approval.ui_open_mode.value == "browser"

    bad_approval_mode = _base_config()
    bad_approval_mode["approval"] = {
        **bad_approval_mode["approval"],
        "ui_open_mode": "popup",
    }
    with pytest.raises(ProxyConfigError, match="approval.ui_open_mode"):
        ProxyConfig.from_dict(bad_approval_mode)

    with pytest.raises(ProxyConfigError, match="proxy_config_schema_version must be 1"):
        ProxyConfig.from_dict(_base_config(proxy_config_schema_version=2))

    bad_avp = dict(_base_config()["avp"])
    bad_avp["trusted_signer_dids"] = []
    with pytest.raises(ProxyConfigError, match="trusted_signer_dids"):
        ProxyConfig.from_dict(_base_config(avp=bad_avp))


def test_policy_schema_rejects_invalid_vocab_and_raw_payload_modes():
    bad_policy = dict(_base_config()["policy"])
    bad_policy["policy_schema_version"] = 2
    with pytest.raises(ProxyConfigError, match="policy_schema_version must be 1"):
        ProxyConfig.from_dict(_base_config(policy=bad_policy))

    bad_policy = dict(_base_config()["policy"])
    bad_policy["rules"] = [{"id": "bad", "decision": "permit"}]
    with pytest.raises(ProxyConfigError, match="decision"):
        ProxyConfig.from_dict(_base_config(policy=bad_policy))

    bad_privacy = dict(_base_config()["privacy"])
    bad_privacy["payload"] = "plain"
    with pytest.raises(ProxyConfigError, match="privacy.payload must be hash_only"):
        ProxyConfig.from_dict(_base_config(privacy=bad_privacy))

    bad_fallback = dict(_base_config()["fallback"])
    bad_fallback["write"] = "ask_backend"
    with pytest.raises(ProxyConfigError, match="fallback.write"):
        ProxyConfig.from_dict(_base_config(fallback=bad_fallback))


def test_fallback_defaults_do_not_fail_open():
    # B5 hardening: a Runtime Gate outage must never silently forward. No default
    # claim-check: allow "never" describes the asserted defaults below; verified by this test
    # fallback is ALLOW; read in particular is APPROVAL, not ALLOW.
    defaults = FallbackConfig()

    assert defaults.read is PolicyDecision.APPROVAL
    assert defaults.for_risk(RiskClass.READ) is PolicyDecision.APPROVAL
    assert PolicyDecision.ALLOW not in {
        defaults.read,
        defaults.write,
        defaults.destructive,
        defaults.production,  # claim-check: allow "production" is a FallbackConfig field name here, not a production claim
        defaults.financial,
        defaults.unknown,
    }

    # A config that omits the read fallback inherits the safe default.
    inherited = FallbackConfig.from_dict({"write": "block"})
    assert inherited.for_risk(RiskClass.READ) is PolicyDecision.APPROVAL


def test_fallback_read_allow_remains_an_explicit_operator_opt_in():
    # Explicit fail-open is still supported as an operator-accepted risk.
    explicit = FallbackConfig.from_dict({"read": "allow"})

    assert explicit.for_risk(RiskClass.READ) is PolicyDecision.ALLOW


def test_ask_backend_semantics_in_protect_mode():
    policy = dict(_base_config()["policy"])
    policy["rules"] = [
        {
            "id": "github-write",
            "decision": "ask_backend",
            "risk_class": "write",
            "match": {"server": "github", "tool": "create_*"},
        }
    ]
    cfg = ProxyConfig.from_dict(_base_config(policy=policy))
    result = PolicyEngine(cfg).evaluate({
        "server": "github",
        "tool": "create_issue",
        "risk_class": "write",
    })
    assert result.decision is PolicyDecision.ASK_BACKEND
    assert result.would_decision is None
    assert result.risk_class is RiskClass.WRITE
    assert result.policy_rule_id == "github-write"


def test_observe_mode_returns_observe_with_would_decision():
    policy = dict(_base_config()["policy"])
    policy["rules"] = [
        {
            "id": "delete-needs-block",
            "decision": "block",
            "risk_class": "destructive",
            "match": {"server": "filesystem", "tool": "delete_*"},
        }
    ]
    cfg = ProxyConfig.from_dict(_base_config(mode="observe", policy=policy))
    result = PolicyEngine(cfg).evaluate(ToolCallContext(
        server="filesystem",
        tool="delete_file",
        risk_class=RiskClass.DESTRUCTIVE,
    ))
    assert result.decision is PolicyDecision.OBSERVE
    assert result.would_decision is PolicyDecision.BLOCK
    assert result.risk_class is RiskClass.DESTRUCTIVE
    assert result.policy_context_hash == policy_context_hash(
        policy_id="test-policy",
        policy_rule_id="delete-needs-block",
        risk_class=RiskClass.DESTRUCTIVE,
        decision_mode=DecisionMode.OBSERVE,
    )


def test_stricter_wins_by_default():
    policy = dict(_base_config()["policy"])
    policy["rules"] = [
        {
            "id": "broad-allow",
            "decision": "allow",
            "risk_class": "read",
            "match": {"server": "filesystem", "tool": "*"},
        },
        {
            "id": "delete-block",
            "decision": "block",
            "risk_class": "destructive",
            "match": {"server": "filesystem", "tool": "delete_*"},
        },
    ]
    cfg = ProxyConfig.from_dict(_base_config(policy=policy))
    result = PolicyEngine(cfg).evaluate({
        "server": "filesystem",
        "tool": "delete_file",
        "risk_class": "destructive",
    })
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "delete-block"
    assert set(result.matched_rule_ids) == {"broad-allow", "delete-block"}


def test_user_override_must_be_intentional_to_weaken_builtin_policy():
    policy = dict(_base_config()["policy"])
    policy["rules"] = [
        {
            "id": "builtin-delete-block",
            "source": "builtin",
            "decision": "block",
            "risk_class": "destructive",
            "match": {"server": "filesystem", "tool": "delete_*"},
        },
        {
            "id": "user-delete-allow",
            "source": "user",
            "decision": "allow",
            "risk_class": "destructive",
            "match": {"server": "filesystem", "tool": "delete_*"},
        },
    ]
    cfg = ProxyConfig.from_dict(_base_config(policy=policy))
    result = PolicyEngine(cfg).evaluate({
        "server": "filesystem",
        "tool": "delete_file",
        "risk_class": "destructive",
    })
    assert result.decision is PolicyDecision.BLOCK
    assert result.intentional_override_applied is False

    policy["rules"][1]["intentional_override"] = True
    cfg = ProxyConfig.from_dict(_base_config(policy=policy))
    result = PolicyEngine(cfg).evaluate({
        "server": "filesystem",
        "tool": "delete_file",
        "risk_class": "destructive",
    })
    assert result.decision is PolicyDecision.ALLOW
    assert result.policy_rule_id == "user-delete-allow"
    assert result.intentional_override_applied is True

    policy["rules"].append({
        "id": "user-delete-still-block",
        "source": "user",
        "decision": "block",
        "risk_class": "destructive",
        "match": {"server": "filesystem", "tool": "delete_*"},
    })
    cfg = ProxyConfig.from_dict(_base_config(policy=policy))
    result = PolicyEngine(cfg).evaluate({
        "server": "filesystem",
        "tool": "delete_file",
        "risk_class": "destructive",
    })
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "user-delete-still-block"
    assert result.intentional_override_applied is False


def test_malformed_hot_reload_keeps_last_good_policy_and_emits_event():
    good = ProxyConfig.from_dict(_base_config())
    runtime = PolicyRuntime(good)

    bad = _base_config()
    bad["policy"] = dict(bad["policy"])
    bad["policy"]["rules"] = [{"id": "bad", "decision": "permit"}]

    result = runtime.reload_from_dict(bad)
    assert result.applied is False
    assert result.config is good
    assert runtime.config is good
    assert result.event["type"] == "policy_reload_failed"
    assert result.event["kept_policy_id"] == "test-policy"

    reloaded = _base_config()
    reloaded["policy"] = dict(reloaded["policy"])
    reloaded["policy"]["id"] = "new-policy"
    result = runtime.reload_from_dict(reloaded)
    assert result.applied is True
    assert runtime.config.policy.id == "new-policy"
    assert runtime.events[-1]["type"] == "policy_reload_applied"


def test_runtime_events_buffer_is_bounded_and_drops_oldest():
    good = ProxyConfig.from_dict(_base_config())
    runtime = PolicyRuntime(good, max_events=3)

    bad = _base_config()
    bad["policy"] = dict(bad["policy"])
    bad["policy"]["rules"] = [{"id": "bad", "decision": "permit"}]

    for _ in range(5):
        runtime.reload_from_dict(bad)

    assert len(runtime.events) == 3
    assert all(event["type"] == "policy_reload_failed" for event in runtime.events)

    with pytest.raises(ValueError, match="max_events must be positive"):
        PolicyRuntime(good, max_events=0)


def test_policy_context_hash_is_stable_and_metadata_only():
    a = policy_context_hash(
        policy_id="p",
        policy_rule_id="r",
        risk_class="write",
        decision_mode="protect",
    )
    b = policy_context_hash(
        decision_mode="protect",
        risk_class=RiskClass.WRITE,
        policy_rule_id="r",
        policy_id="p",
    )
    c = policy_context_hash(
        policy_id="p",
        policy_rule_id="r",
        risk_class="read",
        decision_mode="protect",
    )
    assert a == b
    assert a != c
    assert re.fullmatch(r"[0-9a-f]{64}", a)


def test_builtin_policy_packs_are_metadata_only_and_match_expected_rules():
    cfg = _pack_config("github")
    read = PolicyEngine(cfg).evaluate({"server": "github", "tool": "get_file_contents"})
    write = PolicyEngine(cfg).evaluate({"server": "github", "tool": "create_issue"})
    destructive = PolicyEngine(cfg).evaluate({"server": "github", "tool": "delete_branch"})
    assert read.decision is PolicyDecision.ALLOW
    assert read.risk_class is RiskClass.READ
    assert write.decision is PolicyDecision.APPROVAL
    assert write.risk_class is RiskClass.WRITE
    assert destructive.decision is PolicyDecision.APPROVAL
    assert destructive.risk_class is RiskClass.DESTRUCTIVE

    with pytest.raises(ProxyConfigError, match="unknown built-in policy pack"):
        builtin_policy_pack("aws")


def test_filesystem_pack_blocks_purge_tools():
    result = _evaluate_builtin_pack("filesystem", server="filesystem", tool="purge_logs")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "filesystem-delete"


def test_filesystem_pack_blocks_truncate_tools():
    result = _evaluate_builtin_pack("filesystem", server="filesystem", tool="truncate_table")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "filesystem-delete"


def test_filesystem_pack_blocks_wipe_tools():
    result = _evaluate_builtin_pack("filesystem", server="filesystem", tool="wipe_disk")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "filesystem-delete"


def test_filesystem_pack_blocks_format_tools():
    result = _evaluate_builtin_pack("filesystem", server="filesystem", tool="format_volume")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "filesystem-delete"


def test_filesystem_pack_blocks_rm_exact_tool():
    result = _evaluate_builtin_pack("filesystem", server="filesystem", tool="rm")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "filesystem-delete"


def test_filesystem_pack_blocks_rmdir_tools():
    result = _evaluate_builtin_pack("filesystem", server="filesystem", tool="rmdir_tree")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "filesystem-delete"


def test_filesystem_pack_blocks_unlink_tools():
    result = _evaluate_builtin_pack("filesystem", server="filesystem", tool="unlink_file")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "filesystem-delete"


def test_filesystem_pack_blocks_clean_tools():
    result = _evaluate_builtin_pack("filesystem", server="filesystem", tool="clean_temp")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "filesystem-delete"


def test_github_pack_blocks_secret_value_reads():
    result = _evaluate_builtin_pack("github", server="github", tool="get_secret")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "github-secrets-block"


def test_github_pack_approval_required_for_create_comment():
    result = _evaluate_builtin_pack("github", server="github", tool="create_comment")
    assert result.decision is PolicyDecision.APPROVAL
    assert result.policy_rule_id == "github-write"


def test_github_pack_approval_required_for_merge_pull_request():
    result = _evaluate_builtin_pack("github", server="github", tool="merge_pull_request")
    assert result.decision is PolicyDecision.APPROVAL
    assert result.policy_rule_id == "github-write"


def test_github_pack_allows_list_secret_names():
    result = _evaluate_builtin_pack("github", server="github", tool="list_secret_names")
    assert result.decision is PolicyDecision.ALLOW
    assert result.policy_rule_id == "github-read"


def test_github_pack_blocks_env_secret_reads():
    result = _evaluate_builtin_pack("github", server="github", tool="get_env_secret")
    assert result.decision is PolicyDecision.BLOCK
    assert result.policy_rule_id == "github-secrets-block"


@pytest.mark.parametrize("tool", [
    "dispatch_workflow",
    "publish_package",
    "deploy_release",
    "run_remote_command",
])
def test_github_pack_approval_required_for_ci_repo_privileged_tools(tool: str):
    result = _evaluate_builtin_pack("github", server="github", tool=tool)
    assert result.decision is PolicyDecision.APPROVAL
    assert result.policy_rule_id == "github-write"


def test_github_pack_allows_ci_repo_read_tools():
    for tool in (
        "list_workflows",
        "get_workflow",
        "list_ci_jobs",
        "get_ci_job",
        "get_package_metadata",
        "ci_repo_target_snapshot",
    ):
        result = _evaluate_builtin_pack("github", server="github", tool=tool)
        assert result.decision is PolicyDecision.ALLOW, tool
        assert result.policy_rule_id == "github-read", tool


def test_github_pack_approval_required_for_revoke_tools():
    result = _evaluate_builtin_pack("github", server="github", tool="revoke_token")
    assert result.decision is PolicyDecision.APPROVAL
    assert result.policy_rule_id == "github-destructive"


def test_github_pack_approval_required_for_destroy_tools():
    result = _evaluate_builtin_pack("github", server="github", tool="destroy_repository")
    assert result.decision is PolicyDecision.APPROVAL
    assert result.policy_rule_id == "github-destructive"


def test_github_pack_approval_required_for_drop_tools():
    result = _evaluate_builtin_pack("github", server="github", tool="drop_ref")
    assert result.decision is PolicyDecision.APPROVAL
    assert result.policy_rule_id == "github-destructive"


def test_git_pack_allows_status_and_log_read_tools():
    for tool in ("git_status", "git_log", "git_diff", "git_show", "git_branch"):
        result = _evaluate_builtin_pack("git", server="git", tool=tool)
        assert result.decision is PolicyDecision.ALLOW, tool
        assert result.risk_class is RiskClass.READ, tool
        assert result.policy_rule_id == "git-read", tool


def test_git_pack_approval_required_for_add_and_commit_write_tools():
    for tool in ("git_add", "git_commit", "git_checkout", "git_create_branch"):
        result = _evaluate_builtin_pack("git", server="git", tool=tool)
        assert result.decision is PolicyDecision.APPROVAL, tool
        assert result.risk_class is RiskClass.WRITE, tool
        assert result.policy_rule_id == "git-write", tool


def test_git_pack_approval_required_for_reset_destructive_tool():
    for tool in ("git_reset", "git_clean", "git_rebase"):
        result = _evaluate_builtin_pack("git", server="git", tool=tool)
        assert result.decision is PolicyDecision.APPROVAL, tool
        assert result.risk_class is RiskClass.DESTRUCTIVE, tool
        assert result.policy_rule_id == "git-destructive", tool


def test_git_pack_approval_required_for_push_remote_tool():
    result = PolicyEngine(_pack_config("git")).evaluate(
        # claim-check: allow internal risk class input for remote git policy.
        {"server": "git", "tool": "git_push", "risk_class": "production"}
    )
    assert result.decision is PolicyDecision.APPROVAL
    assert result.risk_class is RiskClass.PRODUCTION
    assert result.policy_rule_id == "git-remote"


def test_git_pack_server_glob_does_not_shadow_github_pack():
    # Negative test: the git pack's server matchers must not match the
    # "github" server name.
    result = _evaluate_builtin_pack("git", server="github", tool="git_status")
    assert result.policy_rule_id != "git-read"


def test_package_pack_allows_manifest_and_state_read_tools():
    for tool in ("package_list_manifest", "package_inspect_state", "package_risk_status"):
        result = _evaluate_builtin_pack("package", server="package", tool=tool)
        assert result.decision is PolicyDecision.ALLOW, tool
        assert result.risk_class is RiskClass.READ, tool
        assert result.policy_rule_id == "package-read", tool


def test_package_pack_approval_required_for_pip_write_tools():
    for tool in ("pip_install", "pip_uninstall", "pip_update"):
        result = _evaluate_builtin_pack("package", server="package", tool=tool)
        assert result.decision is PolicyDecision.APPROVAL, tool
        assert result.risk_class is RiskClass.WRITE, tool
        assert result.policy_rule_id == "package-write", tool


def test_package_pack_approval_required_for_pip_run_script():
    result = _evaluate_builtin_pack("package", server="package", tool="pip_run_script")
    assert result.decision is PolicyDecision.APPROVAL
    assert result.risk_class is RiskClass.DESTRUCTIVE
    assert result.policy_rule_id == "package-script"


def test_fetch_pack_ask_backend_for_public_read():
    # Bug 2: a benign public fetch (classifier sets risk_class READ) is routed to
    # the backend, not left on the default rule.
    result = PolicyEngine(_pack_config("fetch")).evaluate(
        {"server": "fetch", "tool": "fetch", "risk_class": "read"}
    )
    assert result.decision is PolicyDecision.ASK_BACKEND
    assert result.risk_class is RiskClass.READ
    assert result.policy_rule_id == "fetch-read"


def test_fetch_pack_blocks_ssrf_metadata_production_risk():
    # Bug 2: a fetch the classifier maps to PRODUCTION (cloud metadata /  # claim-check: allow "PRODUCTION" is policy vocabulary in this test.
    # link-local SSRF target) gets the local block decision before approval.
    # claim-check: allow "PRODUCTION" and "production" are expected policy
    # vocabulary values in this regression test.
    result = PolicyEngine(_pack_config("fetch")).evaluate(
        {"server": "fetch", "tool": "fetch", "risk_class": "production"}  # claim-check: allow "production" is policy vocabulary.
    )
    assert result.decision is PolicyDecision.BLOCK
    assert result.risk_class is RiskClass.PRODUCTION  # claim-check: allow "PRODUCTION" is expected enum vocabulary.
    assert result.policy_rule_id == "fetch-network-block"


# --- B9 declared tool surface config ---

def test_tool_surface_dataclass_default_is_off_empty_allow():
    surface = ToolSurfaceConfig()
    assert surface.mode is ToolSurfaceMode.OFF
    assert surface.allow == ()


def test_proxy_config_without_tool_surface_defaults_off():
    # Backward compatibility: omitting the block keeps enforcement off.
    config = ProxyConfig.from_dict(_base_config())
    assert config.tool_surface.mode is ToolSurfaceMode.OFF
    assert config.tool_surface.allow == ()


def test_tool_surface_parses_modes_and_allow_forms():
    off = ToolSurfaceConfig.from_dict({"mode": "off"})
    observe = ToolSurfaceConfig.from_dict({"mode": "observe", "allow": "get_*"})
    enforce = ToolSurfaceConfig.from_dict({"mode": "enforce", "allow": ["get_*", "list_*"]})
    assert off.mode is ToolSurfaceMode.OFF
    assert observe.mode is ToolSurfaceMode.OBSERVE
    assert observe.allow == ("get_*",)
    assert enforce.mode is ToolSurfaceMode.ENFORCE
    assert enforce.allow == ("get_*", "list_*")


def test_tool_surface_empty_allow_list_is_accepted_as_no_patterns():
    surface = ToolSurfaceConfig.from_dict({"mode": "enforce", "allow": []})
    assert surface.allow == ()
    # Empty allowlist declares nothing.
    assert surface.is_declared("read_file") is False


def test_tool_surface_is_declared_exact_and_glob():
    surface = ToolSurfaceConfig.from_dict({"mode": "enforce", "allow": ["read_file", "list_*"]})
    assert surface.is_declared("read_file") is True
    assert surface.is_declared("list_dir") is True
    assert surface.is_declared("write_file") is False
    # fnmatchcase is case-sensitive.
    assert surface.is_declared("READ_FILE") is False


def test_tool_surface_rejects_invalid_mode():
    with pytest.raises(ProxyConfigError, match="tool_surface.mode"):
        ToolSurfaceConfig.from_dict({"mode": "blocklist"})


def test_tool_surface_rejects_non_string_allow_and_unknown_field():
    with pytest.raises(ProxyConfigError, match="tool_surface.allow"):
        ToolSurfaceConfig.from_dict({"mode": "enforce", "allow": [123]})
    with pytest.raises(ProxyConfigError, match="tool_surface.allow"):
        ToolSurfaceConfig.from_dict({"mode": "enforce", "allow": 5})
    with pytest.raises(ProxyConfigError, match="tool_surface"):
        ToolSurfaceConfig.from_dict({"mode": "off", "deny": ["x"]})


def test_proxy_config_wires_tool_surface_block():
    config = ProxyConfig.from_dict(_base_config(tool_surface={"mode": "enforce", "allow": ["get_*"]}))
    assert config.tool_surface.mode is ToolSurfaceMode.ENFORCE
    assert config.tool_surface.is_declared("get_issue") is True
    assert config.tool_surface.is_declared("delete_repo") is False


def test_tool_surface_rejects_non_object_values():
    # A present-but-non-object value must fail loudly, not silently disable
    # enforcement. Only an omitted block (None) or empty object defaults to off.
    for bad in ([], "", 0):
        with pytest.raises(ProxyConfigError, match="tool_surface must be an object"):
            ToolSurfaceConfig.from_dict(bad)
    assert ToolSurfaceConfig.from_dict(None).mode is ToolSurfaceMode.OFF
    assert ToolSurfaceConfig.from_dict({}).mode is ToolSurfaceMode.OFF


def test_proxy_config_rejects_non_object_tool_surface():
    for bad in ([], "", 0):
        with pytest.raises(ProxyConfigError, match="tool_surface must be an object"):
            ProxyConfig.from_dict(_base_config(tool_surface=bad))


def test_role_authority_requires_role_when_enforced():
    with pytest.raises(ProxyConfigError, match="role_authority.role"):
        ProxyConfig.from_dict(_base_config(role_authority={"mode": "enforce"}))


def test_reviewer_role_blocks_implementation_action_family():
    config = ProxyConfig.from_dict(_base_config(
        role_authority={"mode": "enforce", "role": "reviewer", "authority": "review_only"},
        policy={
            "id": "role-authority-policy",
            "policy_schema_version": 1,
            "default_decision": "allow",
            "default_risk_class": "read",
            "rules": [],
        },
    ))
    evaluation = PolicyEngine(config).evaluate(ToolCallContext(
        server="fake-downstream",
        tool="write_file",
        action="fake-downstream.write_file",
        risk_class=RiskClass.WRITE,
        role="reviewer",
        authority="review_only",
        action_family="write",
    ))
    assert evaluation.decision is PolicyDecision.BLOCK
    assert evaluation.policy_rule_id == "role_authority_reviewer_blocks_implementation"
    assert evaluation.reason == "role_authority_denied"


def test_persisted_safe_autopilot_setup_profile_enables_write_approval(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    payload = _base_config(
        setup_profile=SAFE_AUTOPILOT_SETUP_PROFILE,
        role_preset="reviewer",
        role_authority={"mode": "enforce", "role": "reviewer", "authority": "review_only"},
        policy={
            "id": "filesystem",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "unknown",
            "rules": [
                {
                    "id": "filesystem-write",
                    "source": "builtin",
                    "decision": "approval",
                    "risk_class": "write",
                    "match": {
                        "server": ["filesystem", "fs", "*filesystem*"],
                        "tool": ["write_*"],
                    },
                },
            ],
        },
        downstream=quickstart_filesystem_downstream(sandbox),
    )
    config = ProxyConfig.from_dict(payload)
    assert config.setup_profile == SAFE_AUTOPILOT_SETUP_PROFILE
    evaluation = PolicyEngine(config).evaluate(ToolCallContext(
        server="filesystem",
        tool="write_file",
        action="filesystem.write_file",
        risk_class=RiskClass.WRITE,
        role="reviewer",
        authority="review_only",
        action_family="write",
    ))
    assert evaluation.decision is PolicyDecision.APPROVAL
    assert evaluation.policy_rule_id == "filesystem-write"


def test_persisted_product_route_setup_profile_ignores_enforced_reviewer_role():
    from agentveil_mcp_proxy.product_route import build_product_route_policy

    pack = build_product_route_policy()

    def match_dict(rule):
        data = {}
        if rule.match.server:
            data["server"] = list(rule.match.server)
        if rule.match.tool:
            data["tool"] = list(rule.match.tool)
        if rule.match.action:
            data["action"] = list(rule.match.action)
        if rule.match.risk_class:
            data["risk_class"] = [risk.value for risk in rule.match.risk_class]
        return data

    config = ProxyConfig.from_dict(_base_config(
        setup_profile=PRODUCT_ROUTE_SETUP_PROFILE,
        role_preset="reviewer",
        role_authority={"mode": "enforce", "role": "reviewer", "authority": "review_only"},
        policy={
            "id": pack.id,
            "policy_schema_version": 1,
            "default_decision": pack.default_decision.value,
            "default_risk_class": pack.default_risk_class.value,
            "rules": [
                {
                    "id": rule.id,
                    "source": rule.source,
                    "decision": rule.decision.value,
                    "risk_class": rule.risk_class.value if rule.risk_class else None,
                    "match": match_dict(rule),
                }
                for rule in pack.rules
            ],
        },
    ))
    evaluation = PolicyEngine(config).evaluate(ToolCallContext(
        server="product",
        tool="git_add",
        action="git.git_add",
        risk_class=RiskClass.WRITE,
        role="reviewer",
        authority="review_only",
        action_family="write",
    ))
    assert evaluation.decision is PolicyDecision.APPROVAL
    assert evaluation.policy_rule_id == "product_route::git::git_add"


def test_reviewer_quickstart_without_safe_autopilot_setup_profile_still_blocks_write(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    config = ProxyConfig.from_dict(_base_config(
        role_preset="reviewer",
        role_authority={"mode": "enforce", "role": "reviewer", "authority": "review_only"},
        policy={
            "id": "filesystem",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "unknown",
            "rules": [
                {
                    "id": "filesystem-write",
                    "source": "builtin",
                    "decision": "approval",
                    "risk_class": "write",
                    "match": {
                        "server": ["filesystem", "fs", "*filesystem*"],
                        "tool": ["write_*"],
                    },
                },
            ],
        },
        downstream=quickstart_filesystem_downstream(sandbox),
    ))
    assert config.setup_profile is None
    evaluation = PolicyEngine(config).evaluate(ToolCallContext(
        server="filesystem",
        tool="write_file",
        action="filesystem.write_file",
        risk_class=RiskClass.WRITE,
        role="reviewer",
        authority="review_only",
        action_family="write",
    ))
    assert evaluation.decision is PolicyDecision.BLOCK
    assert evaluation.policy_rule_id == "role_authority_reviewer_blocks_implementation"
    assert evaluation.reason == "role_authority_denied"


def test_safe_autopilot_quickstart_write_requires_approval_not_role_block(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    config = ProxyConfig.from_dict(_base_config(
        setup_profile=SAFE_AUTOPILOT_SETUP_PROFILE,
        role_preset="reviewer",
        role_authority={"mode": "enforce", "role": "reviewer", "authority": "review_only"},
        policy={
            "id": "filesystem",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "unknown",
            "rules": [
                {
                    "id": "filesystem-write",
                    "source": "builtin",
                    "decision": "approval",
                    "risk_class": "write",
                    "match": {
                        "server": ["filesystem", "fs", "*filesystem*"],
                        "tool": ["write_*"],
                    },
                },
            ],
        },
        downstream=quickstart_filesystem_downstream(sandbox),
    ))
    evaluation = PolicyEngine(config).evaluate(ToolCallContext(
        server="filesystem",
        tool="write_file",
        action="filesystem.write_file",
        risk_class=RiskClass.WRITE,
        role="reviewer",
        authority="review_only",
        action_family="write",
    ))
    assert evaluation.decision is PolicyDecision.APPROVAL
    assert evaluation.policy_rule_id == "filesystem-write"
    assert evaluation.reason is None


def test_reviewer_role_allows_read_action_family():
    config = ProxyConfig.from_dict(_base_config(
        role_authority={"mode": "enforce", "role": "reviewer", "authority": "review_only"},
        policy={
            "id": "role-authority-policy",
            "policy_schema_version": 1,
            "default_decision": "allow",
            "default_risk_class": "read",
            "rules": [],
        },
    ))
    evaluation = PolicyEngine(config).evaluate(ToolCallContext(
        server="fake-downstream",
        tool="read_file",
        action="fake-downstream.read_file",
        risk_class=RiskClass.READ,
        role="reviewer",
        authority="review_only",
        action_family="read",
    ))
    assert evaluation.decision is PolicyDecision.ALLOW


def test_proxy_config_wires_role_authority():
    config = ProxyConfig.from_dict(_base_config(
        role_authority={"mode": "enforce", "role": "reviewer", "authority": "review_only"},
    ))
    assert config.role_authority.mode is RoleAuthorityMode.ENFORCE
    assert config.role_authority.role == "reviewer"
    assert config.role_authority.authority == "review_only"


def test_readonly_role_blocks_mutation_action_family():
    config = ProxyConfig.from_dict(_base_config(
        role_authority={"mode": "enforce", "role": "readonly", "authority": "read_only"},
        policy={
            "id": "role-authority-policy",
            "policy_schema_version": 1,
            "default_decision": "allow",
            "default_risk_class": "read",
            "rules": [],
        },
    ))
    evaluation = PolicyEngine(config).evaluate(ToolCallContext(
        server="fake-downstream",
        tool="write_file",
        action="fake-downstream.write_file",
        risk_class=RiskClass.WRITE,
        role="readonly",
        authority="read_only",
        action_family="write",
    ))
    assert evaluation.decision is PolicyDecision.BLOCK
    assert evaluation.policy_rule_id == "role_authority_readonly_blocks_mutation"
    assert evaluation.reason == "role_authority_denied"


def test_controlled_path_metadata_includes_authority_record():
    metadata = build_controlled_path_metadata(
        fixture_id="allow-tool",
        tool_name="read_file",
        policy_decision="allow",
        policy_rule_id="allow-tool",
        approval_status="executed",
        execution_status="executed",
        target_reached=True,
        request_id="req-read-1",
        action_family="read",
    )

    authority = metadata["authority_record"]
    assert authority["authority_status"] == "allowed"
    assert authority["authority_source"] == "read_only"
    assert authority["safe_first_step_id"] == "read_only_review"
    assert "safe_first_step" not in metadata
