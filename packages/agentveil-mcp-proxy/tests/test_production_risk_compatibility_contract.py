"""C0-4B: public proof of production-risk vocabulary compatibility.

claim-check: ignore-file bounded compatibility vocabulary and negative tests,
not a customer-readiness claim.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any, Mapping

import pytest
from nacl.signing import SigningKey

from agentveil.delegation import _public_key_to_did
from agentveil_mcp_proxy.classification import ToolCallClassifier, infer_risk_class
from agentveil_mcp_proxy.policy import ProxyConfig, RiskClass, builtin_policy_pack
from agentveil_mcp_proxy.runtime_gate import (
    CANONICAL_RUNTIME_ENVIRONMENTS,
    RuntimeGateClient,
)

# claim-check: allow "production" is frozen vocabulary, not readiness.
_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "fixtures"
    / "production_risk_compatibility_public_contract.json"
)
_WIRE_CONTRACT_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "fixtures"
    / "runtime_gate_public_wire_contract.json"
)
_HANDOFF_TOP_LEVEL_KEYS = frozenset(
    {
        "contract_version",
        "vocabulary_version",
        "vocabulary_hash",
        "mapping_metadata",
    }
)
_HANDOFF_CONTRACT_VERSION = "avp.production.risk_compatibility.v1"
_HANDOFF_VOCABULARY_VERSION = "production_risk_vocabulary/1"
_PUBLIC_RISK_CLASS_VALUES = (
    "read",
    "write",
    "destructive",
    "production",  # claim-check: allow RiskClass.PRODUCTION legacy label.
    "financial",
    "unknown",
)
_ABSENT_REQUEST_FIELDS = ("impact_class", "canonical_impact_class")
_PRODUCTION_LEGACY_TOOLS = (
    "git_push",
    "merge_pull_request",
    "create_release",
    "deploy_release",
)
_FORBIDDEN_MARKERS = (
    "team",
    "team_context",
    "entitlement",
    "provider",
    "route_id",
    "route_catalog",
    "customer",
    "signer",
    "payload",
    "credential",
    "token",
    "secret",
    "policy",
    "approval",
    "protected",
    "private",
    "dispatch",
    "billing",
    "hosted_accounting",
    "kms",
    "s3",
    "enterprise",
    "license_id",
    "workspace_id",
    "database",
    "db_",
    "resolver",
    "threshold",
    "source_truth",
)
_BACKEND_DID = _public_key_to_did(bytes(SigningKey(bytes.fromhex("11" * 32)).verify_key))


def _fixture() -> dict[str, Any]:
    return json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


def _wire_contract() -> dict[str, Any]:
    return json.loads(_WIRE_CONTRACT_PATH.read_text(encoding="utf-8"))


def _compatibility_table_from_metadata(meta: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Rebuild the frozen compatibility table from bounded mapping metadata."""

    impact_projection = set(meta["impact_projection_values"])
    table: dict[str, dict[str, Any]] = {}
    for key in meta["legacy_values"]:
        if key == "production":
            table[key] = {
                "kind": meta["production_legacy_kind"],
                "projected_impact_hint": None,
            }
            continue
        assert key in impact_projection
        table[key] = {
            "kind": "impact_projection",
            "projected_impact_hint": key,
        }
    assert impact_projection == {
        key for key, row in table.items() if row["kind"] == "impact_projection"
    }
    return table


def compute_vocabulary_hash_from_fixture(data: Mapping[str, Any]) -> str:
    """Self-verify vocabulary_hash from fixture contract fields + mapping_metadata."""

    meta = data["mapping_metadata"]
    table = _compatibility_table_from_metadata(meta)
    document = {
        "contract_version": data["contract_version"],
        "vocabulary_version": data["vocabulary_version"],
        "legacy_values": sorted(meta["legacy_values"]),
        "canonical_impact_values": list(meta["canonical_impact_values"]),
        "canonical_environment_values": list(meta["canonical_environment_values"]),
        "table": {
            key: {
                "kind": row["kind"],
                "projected_impact_hint": row["projected_impact_hint"],
            }
            for key, row in sorted(table.items())
        },
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _policy_to_dict(name: str) -> dict:
    policy = builtin_policy_pack(name)
    rules = []
    for rule in policy.rules:
        match: dict = {}
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


def _config(*, policy_pack: str = "git") -> ProxyConfig:
    return ProxyConfig.from_dict(
        {
            "proxy_config_schema_version": 1,
            "avp": {
                "base_url": "https://agentveil.dev",
                "agent_name": "agentveil-mcp-proxy",
                "trusted_signer_dids": [_BACKEND_DID],
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
                # claim-check: allow "production" is a fallback risk-class key in test config.
                "production": "block",
                "financial": "block",
                "unknown": "approval",
            },
            "approval": {},
            "policy": _policy_to_dict(policy_pack),
            "downstream": {},
        }
    )


def test_fixture_is_exact_c0_4a_handoff_manifest() -> None:
    data = _fixture()
    assert set(data) == _HANDOFF_TOP_LEVEL_KEYS
    meta = data["mapping_metadata"]

    assert data["contract_version"] == _HANDOFF_CONTRACT_VERSION
    assert data["vocabulary_version"] == _HANDOFF_VOCABULARY_VERSION
    assert meta["legacy_values"] == [
        "destructive",
        "financial",
        "production",
        "read",
        "unknown",
        "write",
    ]
    assert meta["canonical_impact_values"] == [
        "read",
        "write",
        "destructive",
        "irreversible",
        "financial",
        "unknown",
    ]
    assert meta["canonical_environment_values"] == [
        "production",  # claim-check: allow finite public environment enum value.
        "staging",
        "development",
        "unknown",
    ]
    assert meta["production_legacy_kind"] == "environment_compatibility_check"
    assert meta["impact_projection_values"] == [
        "destructive",
        "financial",
        "read",
        "unknown",
        "write",
    ]


def test_vocabulary_hash_is_recomputed_from_fixture_metadata() -> None:
    data = _fixture()
    recomputed = compute_vocabulary_hash_from_fixture(data)
    assert data["vocabulary_hash"] == recomputed
    assert recomputed.startswith("sha256:")
    assert len(recomputed) == len("sha256:") + 64
    assert recomputed == compute_vocabulary_hash_from_fixture(data)


def test_fixture_is_public_safe_bounded_vocabulary_only() -> None:
    serialized = json.dumps(_fixture(), sort_keys=True).lower()
    for marker in _FORBIDDEN_MARKERS:
        assert marker not in serialized


def test_public_risk_class_matches_legacy_vocabulary_exactly() -> None:
    data = _fixture()
    public_values = [member.value for member in RiskClass]
    assert public_values == list(_PUBLIC_RISK_CLASS_VALUES)
    assert sorted(public_values) == data["mapping_metadata"]["legacy_values"]


def test_production_absent_from_canonical_impact_and_present_as_environment_compat() -> None:
    meta = _fixture()["mapping_metadata"]
    assert "production" not in meta["canonical_impact_values"]
    assert "production" not in meta["impact_projection_values"]
    assert "production" in meta["canonical_environment_values"]
    assert "production" in meta["legacy_values"]
    assert meta["production_legacy_kind"] == "environment_compatibility_check"
    assert RiskClass.PRODUCTION.value == "production"


def test_runtime_gate_request_keeps_risk_class_and_environment_separate() -> None:
    wire = _wire_contract()["request"]
    top_level = set(wire["top_level_fields"]["required"]) | set(
        wire["top_level_fields"]["optional"]
    )
    assert "risk_class" in top_level
    assert "environment" in top_level
    for forbidden in _ABSENT_REQUEST_FIELDS:
        assert forbidden not in top_level

    config = _config(policy_pack="git")
    classification = ToolCallClassifier(config, server_name="git").classify(
        tool="git_push",
        arguments={"repo_path": "/tmp/repo"},
    )
    assert classification.risk_class is RiskClass.PRODUCTION
    metadata = classification.backend_metadata()
    assert metadata["risk_class"] == "production"
    assert "environment" not in metadata
    for forbidden in _ABSENT_REQUEST_FIELDS:
        assert forbidden not in metadata

    client = RuntimeGateClient(
        agent=object(),
        config=config,
        control_grant={"id": "grant"},
        environment="staging",
    )
    request = client._build_request(classification)
    assert request.risk_class == "production"
    assert request.environment == "staging"
    assert request.risk_class != request.environment


def test_runtime_gate_environment_is_not_derived_from_classified_risk_class() -> None:
    config = _config(policy_pack="git")
    classification = ToolCallClassifier(config, server_name="git").classify(
        tool="git_push",
        arguments={"repo_path": "/tmp/repo"},
    )
    assert classification.risk_class is RiskClass.PRODUCTION

    client = RuntimeGateClient(
        agent=object(),
        config=config,
        control_grant={"id": "grant"},
        environment="development",
    )
    request = client._build_request(classification)
    assert request.environment == "development"
    assert request.risk_class == "production"
    assert client.environment == "development"
    assert set(CANONICAL_RUNTIME_ENVIRONMENTS) == set(
        _fixture()["mapping_metadata"]["canonical_environment_values"]
    )

    source = inspect.getsource(RuntimeGateClient._build_request)
    compact = source.replace(" ", "")
    assert "environment=self.environment" in compact
    assert "environment=classification" not in compact
    for line in source.splitlines():
        if "environment=" in line.replace(" ", "") and "risk_class" in line:
            pytest.fail(f"environment derived from risk_class: {line.strip()}")


@pytest.mark.parametrize("tool", list(_PRODUCTION_LEGACY_TOOLS))
def test_legacy_production_tools_remain_risk_class_production(tool: str) -> None:
    server = "git" if tool == "git_push" else "github"
    action = f"{server}.{tool}"
    assert infer_risk_class(action, tool=tool) is RiskClass.PRODUCTION


def test_module_does_not_import_private_avp() -> None:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.append(node.module)
    for name in imported:
        assert not name.startswith("app")
        assert "production_risk_normalization" not in name
        assert "production_route_catalog" not in name
        assert name.split(".", 1)[0] in {
            "ast",
            "hashlib",
            "inspect",
            "json",
            "pathlib",
            "typing",
            "pytest",
            "nacl",
            "agentveil",
            "agentveil_mcp_proxy",
            "__future__",
        }
