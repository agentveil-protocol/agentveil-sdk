"""Focused tests for bounded metadata evidence collectors."""

from __future__ import annotations

import json
import re

from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.metadata_evidence_collectors import (
    collect_install_metadata_evidence,
)
from agentveil_mcp_proxy.policy import ProxyConfig, builtin_policy_pack


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


def _config(*, policy_pack: str = "package") -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
        },
        "mode": "protect",
        "privacy": {
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


def test_collector_readme_install_hint_emits_bounded_slot_only():
    raw = "To install run: pip install secret-evil-package from https://evil.example"
    slots = collect_install_metadata_evidence(
        tool="pip_install",
        arguments={"readme": raw, "package_name": "secret-evil-package"},
    )
    assert slots["readme"]["signal_code"] == "install_hint"
    assert slots["readme"]["evidence_ref"] == "ev_readme_install_hint"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", slots["readme"]["content_hash"])
    text = json.dumps(slots, sort_keys=True)
    assert raw not in text
    assert "secret-evil-package" not in text
    assert "evil.example" not in text
    assert "https://" not in text


def test_collector_tool_output_install_command():
    raw = "$ pip install agentveil-route-test-pkg\nSuccessfully installed agentveil-route-test-pkg"
    slots = collect_install_metadata_evidence(
        tool="pip_install",
        arguments={"tool_output": raw},
    )
    assert slots["tool_output"]["signal_code"] == "install_command"
    assert slots["tool_output"]["evidence_ref"] == "ev_tool_output_install_command"
    text = json.dumps(slots, sort_keys=True)
    assert raw not in text
    assert "agentveil-route-test-pkg" not in text


def test_collector_tool_output_package_reference():
    slots = collect_install_metadata_evidence(
        tool="pip_install",
        arguments={"prior_tool_output": "Requirement already satisfied: demo"},
    )
    assert slots["tool_output"]["signal_code"] == "package_reference"


def test_collector_file_metadata_lockfile_and_config():
    lock_slots = collect_install_metadata_evidence(
        tool="pip_install",
        arguments={"file_kind": "lockfile"},
    )
    assert lock_slots["file_metadata"]["signal_code"] == "lockfile_dependency"
    assert lock_slots["file_metadata"]["evidence_ref"] == "ev_file_metadata_lockfile_dependency"

    config_slots = collect_install_metadata_evidence(
        tool="pip_install",
        arguments={"file_name": "setup.cfg"},
    )
    assert config_slots["file_metadata"]["signal_code"] == "config_package_ref"


def test_collector_ignores_path_like_file_names():
    slots = collect_install_metadata_evidence(
        tool="pip_install",
        arguments={"file_name": "/Users/secret/proj/requirements.txt"},
    )
    assert "file_metadata" not in slots


def test_collector_returns_empty_without_surfaces():
    assert collect_install_metadata_evidence(
        tool="pip_install",
        arguments={"package_name": "raw-secret-package-name", "project_path": "/Users/secret"},
    ) == {}


def test_classify_package_install_with_readme_surface_emits_readme_slot():
    classified = ToolCallClassifier(_config(), server_name="package").classify(
        tool="pip_install",
        arguments={
            "package_name": "raw-secret-package-name",
            "project_path": "/Users/secret/proj",
            "readme_excerpt": "Install via pip install my-pkg",
            "tool_output": "pip install my-pkg",
            "lockfile_name": "poetry.lock",
            "sk_live_do_not_leak": "sk_live_do_not_leak",
        },
    )
    context = classified.backend_metadata()["install_clone_context"]
    assert context["readme"]["signal_code"] == "install_hint"
    assert context["tool_output"]["signal_code"] == "install_command"
    assert context["file_metadata"]["signal_code"] == "lockfile_dependency"
    assert context["mcp_schema"]["signal_code"] == "tool_declares_install"
    text = json.dumps(classified.backend_metadata(), sort_keys=True)
    for forbidden in (
        "raw-secret-package-name",
        "/Users/secret",
        "Install via",
        "my-pkg",
        "poetry.lock",
        "sk_live_do_not_leak",
        "https://",
    ):
        assert forbidden not in text


def test_classify_non_package_still_omits_install_clone_context():
    classified = ToolCallClassifier(_config(policy_pack="github"), server_name="github").classify(
        tool="create_issue",
        arguments={"readme": "pip install evil", "title": "x"},
    )
    assert "install_clone_context" not in classified.backend_metadata()
