"""Local paid content-risk bridge tests."""

from __future__ import annotations

import json

from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.policy import ProxyConfig
import agentveil_mcp_proxy.classification as classification_module


SECRET = "AKIA0123456789ABCDEF"


def _config() -> ProxyConfig:
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
        "policy": {
            "id": "content-risk-test",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "write",
            "rules": [],
        },
        "downstream": {},
    })


def test_paid_signal_provider_findings_are_bounded_before_backend_metadata(
    monkeypatch,
) -> None:
    findings = {
        "contains_secret_like_value": True,
        "destructive_shell_pattern": False,
        "write_then_execute_risk": False,
        "credential_exfil_pattern": False,
    }
    monkeypatch.setattr(
        classification_module,
        "derive_content_risk_signals",
        lambda arguments: findings,
    )

    classification = ToolCallClassifier(_config(), server_name="filesystem").classify(
        tool="write_file",
        arguments={"path": ".env", "content": f"AWS_ACCESS_KEY_ID={SECRET}"},
    )

    metadata = classification.backend_metadata()
    assert metadata["content_risk_signals"] == findings
    assert "content_risk_signals" not in classification.local_evidence_metadata()
    serialized = json.dumps(metadata, sort_keys=True)
    assert SECRET not in serialized
    assert "AWS_ACCESS_KEY_ID" not in serialized
    assert ".env" not in serialized


def test_core_metadata_is_unchanged_when_no_paid_signal_provider_is_installed(
    monkeypatch,
) -> None:
    monkeypatch.setattr(classification_module, "derive_content_risk_signals", lambda arguments: None)
    classification = ToolCallClassifier(_config(), server_name="filesystem").classify(
        tool="write_file",
        arguments={"path": "notes.txt", "content": "ordinary notes"},
    )

    assert "content_risk_signals" not in classification.backend_metadata()
