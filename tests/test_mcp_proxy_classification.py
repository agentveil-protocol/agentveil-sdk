"""P4 tests for MCP tool classification and privacy hashing."""

from __future__ import annotations

import io
import json
import sys

from agentveil_mcp_proxy.classification import (
    HASH_PREFIX,
    REDACTED,
    ToolCallClassifier,
    extract_resource,
    infer_risk_class,
    sha256_jcs,
)
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough
from agentveil_mcp_proxy.policy import PolicyDecision, ProxyConfig, RiskClass, builtin_policy_pack


SECRET = "SECRET_PROJECT_INTERNAL"


def _json_line(message: dict) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def _responses(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _policy_to_dict(name: str) -> dict:
    policy = builtin_policy_pack(name)
    rules = []
    for rule in policy.rules:
        match = {}
        if rule.match.server:
            match["server"] = list(rule.match.server)
        if rule.match.tool:
            match["tool"] = list(rule.match.tool)
        if rule.match.action:
            match["action"] = list(rule.match.action)
        if rule.match.risk_class:
            match["risk_class"] = [risk.value for risk in rule.match.risk_class]
        item = {
            "id": rule.id,
            "source": rule.source,
            "decision": rule.decision.value,
            "match": match,
        }
        if rule.risk_class is not None:
            item["risk_class"] = rule.risk_class.value
        rules.append(item)
    return {
        "id": policy.id,
        "policy_schema_version": policy.policy_schema_version,
        "default_decision": policy.default_decision.value,
        "default_risk_class": policy.default_risk_class.value,
        "rules": rules,
    }


def _config(*, privacy: dict | None = None, policy_pack: str = "github") -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
        },
        "mode": "protect",
        "privacy": privacy or {
            "action": "redacted",
            "resource": "hash",
            "payload": "hash_only",
            "evidence_upload": False,
        },
        "fallback": {},
        "approval": {},
        "policy": _policy_to_dict(policy_pack),
        "downstream": {},
    })


def _echo_downstream(tmp_path):
    script = tmp_path / "echo_downstream.py"
    script.write_text(
        """
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    print(json.dumps({
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {"content": [{"type": "text", "text": "forwarded"}]},
    }), flush=True)
""".lstrip(),
        encoding="utf-8",
    )
    return script


def test_payload_hash_is_jcs_stable_and_default_metadata_is_privacy_safe():
    classifier = ToolCallClassifier(_config(), server_name="github")
    first = classifier.classify(
        tool="create_issue",
        arguments={
            "owner": "private-org",
            "repo": "secret-repo",
            "title": SECRET,
            "body": {"b": 2, "a": 1},
        },
    )
    second = classifier.classify(
        tool="create_issue",
        arguments={
            "body": {"a": 1, "b": 2},
            "title": SECRET,
            "repo": "secret-repo",
            "owner": "private-org",
        },
    )

    assert first.payload_hash == second.payload_hash
    assert first.payload_hash.startswith(HASH_PREFIX)
    assert first.action == REDACTED
    assert first.resource is not None
    assert first.resource.startswith(HASH_PREFIX)
    assert first.resource_plain == "github:private-org/secret-repo"
    assert first.risk_class is RiskClass.WRITE
    assert first.policy_evaluation.decision is PolicyDecision.ASK_BACKEND
    assert first.policy_evaluation.policy_rule_id == "github-write"

    metadata = first.backend_metadata()
    assert metadata["action_hash"] is None
    assert metadata["resource_hash"] == first.resource_hash
    assert "server" not in metadata
    assert "policy_id" not in metadata
    assert "policy_rule_id" not in metadata
    metadata_text = json.dumps(metadata, sort_keys=True)
    assert SECRET not in metadata_text
    assert "secret-repo" not in metadata_text
    assert "create_issue" not in metadata_text
    assert first.local_evidence_metadata()["policy_rule_id"] == "github-write"


def test_privacy_modes_control_action_and_resource_representation():
    plain = ToolCallClassifier(_config(privacy={
        "action": "plain",
        "resource": "plain",
        "payload": "hash_only",
        "evidence_upload": False,
    }), server_name="github").classify(
        tool="create_issue",
        arguments={"owner": "acme", "repo": "payments"},
    )
    assert plain.action == "github.create_issue"
    assert plain.resource == "github:acme/payments"

    hashed = ToolCallClassifier(_config(privacy={
        "action": "hash",
        "resource": "redacted",
        "payload": "hash_only",
        "evidence_upload": False,
    }), server_name="github").classify(
        tool="create_issue",
        arguments={"owner": "acme", "repo": "payments"},
    )
    assert hashed.action == hashed.action_hash
    assert hashed.action.startswith(HASH_PREFIX)
    assert hashed.resource == REDACTED
    assert hashed.resource_hash is not None
    metadata = hashed.backend_metadata()
    assert metadata["action_hash"] == hashed.action_hash
    assert metadata["resource_hash"] is None
    assert metadata["payload_hash"].startswith(HASH_PREFIX)


def test_extract_resource_priority_order_is_stable():
    cases = [
        ({"owner": "acme", "repo": "foo"}, "github:acme/foo"),
        ({"owner": "acme", "repository": "foo"}, "github:acme/foo"),
        ({"owner": "acme", "repo": "foo", "path": "/some/file"}, "github:acme/foo"),
        ({"resource": "x", "uri": "y", "path": "z"}, "resource:x"),
        ({"uri": "x", "url": "y", "path": "z"}, "uri:x"),
        ({"path": "/etc/passwd", "branch": "main"}, "path:/etc/passwd"),
        ({"branch": "main", "issue_number": 42}, "branch:main"),
        ({"resource": "", "path": "/foo"}, "path:/foo"),
        ({"issue_number": 42}, "issue_number:42"),
        ({"resource": True}, None),
        ({}, None),
        ({"unknown_key": "value"}, None),
    ]

    for arguments, expected in cases:
        assert extract_resource(arguments) == expected


def test_extract_resource_does_not_recognize_repo_alone_as_combo():
    assert extract_resource({"repo": "foo"}) == "repo:foo"
    assert extract_resource({"owner": "acme"}) is None


def test_risk_inference_covers_core_vocab():
    assert infer_risk_class("github.get_issue", tool="get_issue") is RiskClass.READ
    assert infer_risk_class("github.create_issue", tool="create_issue") is RiskClass.WRITE
    assert infer_risk_class("filesystem.delete_file", tool="delete_file") is RiskClass.DESTRUCTIVE
    assert infer_risk_class("deploy.release", tool="deploy_release") is RiskClass.PRODUCTION
    assert infer_risk_class("payment.transfer", tool="transfer_funds") is RiskClass.FINANCIAL
    assert infer_risk_class("custom.inspect", tool="custom_action") is RiskClass.UNKNOWN


def test_risk_inference_destructive_wins_over_financial_compounds():
    assert infer_risk_class("billing.delete_payment", tool="delete_payment") is RiskClass.DESTRUCTIVE
    assert infer_risk_class("billing.drop_billing_table", tool="drop_billing_table") is RiskClass.DESTRUCTIVE
    assert infer_risk_class("auth.revoke_payment_token", tool="revoke_payment_token") is RiskClass.DESTRUCTIVE
    assert (
        infer_risk_class("bank.transfer_to_destroy_account", tool="transfer_to_destroy_account")
        is RiskClass.DESTRUCTIVE
    )


def test_risk_inference_destructive_wins_over_production_compounds():
    assert infer_risk_class("deploy.drop_prod_db", tool="drop_prod_db") is RiskClass.DESTRUCTIVE
    assert infer_risk_class("auth.revoke_prod_access", tool="revoke_prod_access") is RiskClass.DESTRUCTIVE


def test_infer_risk_class_recognizes_purge_as_destructive():
    assert infer_risk_class("database.purge_database", tool="purge_database") is (
        RiskClass.DESTRUCTIVE
    )


def test_infer_risk_class_recognizes_truncate_as_destructive():
    assert infer_risk_class("database.truncate_table", tool="truncate_table") is (
        RiskClass.DESTRUCTIVE
    )


def test_infer_risk_class_recognizes_wipe_as_destructive():
    assert infer_risk_class("storage.wipe_disk", tool="wipe_disk") is RiskClass.DESTRUCTIVE


def test_infer_risk_class_recognizes_format_as_destructive():
    assert infer_risk_class("storage.format_volume", tool="format_volume") is (
        RiskClass.DESTRUCTIVE
    )


def test_infer_risk_class_recognizes_rm_as_destructive():
    assert infer_risk_class("filesystem.rm", tool="rm") is RiskClass.DESTRUCTIVE


def test_infer_risk_class_recognizes_rmdir_as_destructive():
    assert infer_risk_class("filesystem.rmdir_tree", tool="rmdir_tree") is (
        RiskClass.DESTRUCTIVE
    )


def test_infer_risk_class_recognizes_unlink_as_destructive():
    assert infer_risk_class("filesystem.unlink_file", tool="unlink_file") is (
        RiskClass.DESTRUCTIVE
    )


def test_infer_risk_class_recognizes_clean_as_destructive():
    assert infer_risk_class("filesystem.clean_temp", tool="clean_temp") is RiskClass.DESTRUCTIVE


def test_infer_risk_class_destructive_wins_over_read_on_compound():
    assert infer_risk_class("filesystem.purge_files", tool="purge_files") is (
        RiskClass.DESTRUCTIVE
    )


def test_risk_inference_does_not_over_classify_substring_collisions():
    assert infer_risk_class("github.get_infrastructure", tool="get_infrastructure") is RiskClass.READ
    assert infer_risk_class("github.list_endpoints", tool="list_endpoints") is RiskClass.READ


def test_passthrough_classifies_tools_call_without_changing_downstream_behavior(tmp_path):
    classifier = ToolCallClassifier(_config(), server_name="github")
    seen = []
    passthrough = McpPassthrough(
        DownstreamConfig(
            command=sys.executable,
            args=("-u", str(_echo_downstream(tmp_path))),
            name="github",
        ),
        classifier=classifier,
        on_tool_call=seen.append,
    )
    client_out = io.StringIO()
    client_in = io.StringIO(_json_line({
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "create_issue",
            "arguments": {"owner": "acme", "repo": "private", "title": SECRET},
        },
    }))

    assert passthrough.run_stdio(client_in, client_out) == 0
    assert _responses(client_out.getvalue()) == [{
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {"content": [{"type": "text", "text": "forwarded"}]},
    }]
    assert len(seen) == 1
    metadata_text = json.dumps(seen[0].backend_metadata(), sort_keys=True)
    assert seen[0].policy_evaluation.policy_rule_id == "github-write"
    assert seen[0].payload_hash == sha256_jcs({"owner": "acme", "repo": "private", "title": SECRET})
    assert SECRET not in metadata_text
    assert "private" not in metadata_text
