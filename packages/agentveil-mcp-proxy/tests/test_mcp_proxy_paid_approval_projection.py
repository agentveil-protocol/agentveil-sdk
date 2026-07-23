"""Public consumption of Runtime Gate paid_approval_center_projection."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path

import httpx

from agentveil_mcp_proxy.approval import ApprovalManager, ApprovalServer
from agentveil_mcp_proxy.approval.persistent import (
    build_manifest_for_server,
    create_persistent_server,
    save_manifest,
)
from agentveil_mcp_proxy.approval.server import approval_prompt_to_dict
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus
from agentveil_mcp_proxy.runtime_gate import (
    PAID_APPROVAL_PROJECTION_KIND_ACTIVE,
    PAID_APPROVAL_PROJECTION_KIND_CORE_FALLBACK,
    PAID_APPROVAL_PROJECTION_SCHEMA_VERSION,
    RuntimeGateClient,
    RuntimeGateDecision,
    normalize_paid_approval_center_projection,
)

from test_mcp_proxy_approval import (
    NoopNotifier,
    SECRET,
    TOKEN_RE,
    _classification,
    _config,
    _post_decision,
    _prompt_not_expired,
    _write_rule,
)
from test_mcp_proxy_runtime_gate import (
    AUDIT_ID,
    RecordingAgent,
    _classification as _runtime_classification,
    _config as _runtime_config,
    _decision_receipt,
)

FORBIDDEN_MARKERS = (
    "avp_live_",
    "avp_ent_",
    "entitlement_token",
    "install_token",
    "license_key",
    "artifact_id",
    "art_pkg_",
    "backend_url",
    "https://",
    "http://",
    "/Users/",
    "/private/",
    "rule_graph",
    "raw_payload",
    "customer_id",
    SECRET,
    "ghp_private",
)


def _active_projection(**overrides) -> dict:
    payload = {
        "schema_version": PAID_APPROVAL_PROJECTION_SCHEMA_VERSION,
        "projection_kind": PAID_APPROVAL_PROJECTION_KIND_ACTIVE,
        "provider_status": "active",
        "plan_family": "builder",
        "private_provider_enabled": True,
        "core_fallback_active": False,
        "decision": "allow",
        "reason_code": "paid_provider_active",
        "selection_reason": "deterministic_precedence",
        "summary": "Paid policy reviewed this tool call.",
        "capability_labels": ["Tools call routing"],
        "activation_source": "public_activation_install",
        "paid_policy_tightened": False,
    }
    payload.update(overrides)
    return payload


def _fallback_projection(**overrides) -> dict:
    payload = _active_projection(
        projection_kind=PAID_APPROVAL_PROJECTION_KIND_CORE_FALLBACK,
        provider_status="core_fallback",
        private_provider_enabled=False,
        core_fallback_active=True,
        reason_code="activation_missing",
        selection_reason="public_activation_missing",
        summary="Private policy unavailable — Core fallback active",
        paid_policy_tightened=False,
    )
    payload.update(overrides)
    return payload


def test_normalize_accepts_active_projection():
    normalized = normalize_paid_approval_center_projection(_active_projection())
    assert normalized is not None
    assert normalized["projection_kind"] == PAID_APPROVAL_PROJECTION_KIND_ACTIVE
    assert normalized["private_provider_enabled"] is True


def test_normalize_rejects_extra_keys_and_forbidden_markers():
    assert normalize_paid_approval_center_projection(
        _active_projection(**{"rule_graph": {"x": 1}})
    ) is None
    assert normalize_paid_approval_center_projection(
        _active_projection(summary="see https://evil.example/secret")
    ) is None
    assert normalize_paid_approval_center_projection("not-a-mapping") is None
    assert normalize_paid_approval_center_projection(None) is None


def test_normalize_rejects_inconsistent_active_flags():
    assert normalize_paid_approval_center_projection(
        _active_projection(private_provider_enabled=False)
    ) is None
    assert normalize_paid_approval_center_projection(
        _active_projection(core_fallback_active=True)
    ) is None
    assert normalize_paid_approval_center_projection(
        _fallback_projection(private_provider_enabled=True)
    ) is None


class _ProjectionAgent(RecordingAgent):
    def __init__(
        self,
        *,
        projection: dict | None,
        inject_top_level: bool = False,
        decision: str = "WAITING_FOR_HUMAN_APPROVAL",
    ):
        super().__init__(decision=decision)
        self.projection = projection
        self.inject_top_level = inject_top_level

    def runtime_evaluate(self, **kwargs):
        self.calls.append(kwargs)
        signed_projection = None if self.inject_top_level else self.projection
        response = {
            "audit_id": AUDIT_ID,
            "decision": self.decision,
            "decision_receipt_jcs": _decision_receipt(
                kwargs,
                decision=self.decision,
                approval_id=(
                    "urn:uuid:approval"
                    if self.decision == "WAITING_FOR_HUMAN_APPROVAL"
                    else None
                ),
                seed=self.seed,
                omit_fields=self.omit_receipt_fields,
                paid_approval_center_projection=signed_projection,
            ),
        }
        if self.inject_top_level and self.projection is not None:
            response["paid_approval_center_projection"] = self.projection
        return response


def test_runtime_gate_carries_normalized_paid_projection():
    config = _runtime_config()
    agent = _ProjectionAgent(projection=_active_projection())
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    result = client.evaluate(_runtime_classification(config))
    assert result.decision == "WAITING_FOR_HUMAN_APPROVAL"
    assert result.paid_approval_center_projection is not None
    assert (
        result.paid_approval_center_projection["projection_kind"]
        == PAID_APPROVAL_PROJECTION_KIND_ACTIVE
    )


def test_runtime_gate_ignores_unsigned_top_level_paid_projection():
    config = _runtime_config()
    agent = _ProjectionAgent(projection=_active_projection(), inject_top_level=True)
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    result = client.evaluate(_runtime_classification(config))
    assert result.decision == "WAITING_FOR_HUMAN_APPROVAL"
    assert result.paid_approval_center_projection is None


def test_runtime_gate_omits_malformed_paid_projection():
    config = _runtime_config()
    agent = _ProjectionAgent(
        projection=_active_projection(summary="leak entitlement_token=secret")
    )
    client = RuntimeGateClient(agent=agent, config=config, control_grant={"id": "grant"})
    result = client.evaluate(_runtime_classification(config))
    assert result.paid_approval_center_projection is None


def test_active_projection_renders_on_approval_card():
    server = ApprovalServer()
    server.start()
    try:
        metadata = {
            "action_family": "write",
            "policy_decision": "approval",
            "approval_status": "pending",
            "execution_status": "not_reached",
            "target_reached": False,
            "paid_approval_center_projection": _active_projection(),
        }
        prompt = replace(_prompt_not_expired("paid-active"), action_gate_metadata=metadata)
        url = server.register(prompt)
        with httpx.Client(follow_redirects=False) as client:
            response = client.get(url)
            assert response.status_code == 200
            html = response.text
            assert 'data-paid-projection="paid_active"' in html
            assert "Paid policy review" in html
            assert "Paid policy reviewed this tool call." in html
            assert "builder" in html
            for marker in FORBIDDEN_MARKERS:
                assert marker not in html
            csrf = TOKEN_RE.search(html)
            assert csrf is not None
            deny = _post_decision(client, url, decision="deny", csrf=csrf.group(1))
            assert deny.status_code == 200
    finally:
        server.stop()


def test_ordinary_card_without_projection_has_no_paid_section():
    server = ApprovalServer()
    server.start()
    try:
        url = server.register(_prompt_not_expired("ordinary"))
        html = httpx.get(url).text
        assert "Paid policy review" not in html
        assert "data-paid-projection" not in html
        assert "Approve" in html
    finally:
        server.stop()


def test_malformed_projection_omits_section_but_form_works():
    server = ApprovalServer()
    server.start()
    try:
        metadata = {
            "policy_decision": "approval",
            "paid_approval_center_projection": {
                "projection_kind": "paid_active",
                "summary": "bad",
                "extra": True,
            },
        }
        prompt = replace(_prompt_not_expired("malformed"), action_gate_metadata=metadata)
        url = server.register(prompt)
        with httpx.Client(follow_redirects=False) as client:
            html = client.get(url).text
            assert "Paid policy review" not in html
            csrf = TOKEN_RE.search(html)
            assert csrf is not None
            response = _post_decision(
                client, url, decision="approve", csrf=csrf.group(1)
            )
            assert response.status_code == 200
    finally:
        server.stop()


def test_core_fallback_projection_does_not_show_active_paid_wording():
    server = ApprovalServer()
    server.start()
    try:
        metadata = {
            "policy_decision": "approval",
            "paid_approval_center_projection": _fallback_projection(),
        }
        prompt = replace(_prompt_not_expired("fallback"), action_gate_metadata=metadata)
        html = httpx.get(server.register(prompt)).text
        assert 'data-paid-projection="paid_active"' not in html
        assert "Paid policy review" not in html
        assert "private_provider_enabled" not in html
    finally:
        server.stop()


def test_manager_stores_projection_from_runtime_decision(tmp_path: Path):
    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    server = ApprovalServer()
    server.start()
    try:
        manager = ApprovalManager(
            evidence_store=store,
            approval_server=server,
            config=_config(policy_rule=_write_rule()),
            client_id=f"cursor:pid:{os.getpid()}",
            session_id="session-paid-proj",
            headless=False,
            wait_for_decision=False,
            notifier=NoopNotifier(),
        )
        decision = RuntimeGateDecision(
            decision="WAITING_FOR_HUMAN_APPROVAL",
            audit_id=AUDIT_ID,
            approval_id="urn:uuid:approval",
            receipt_digest="a" * 64,
            receipt_body={"decision": "WAITING_FOR_HUMAN_APPROVAL"},
            paid_approval_center_projection=_active_projection(),
        )
        outcome = manager.request_approval(
            _classification(),
            runtime_decision=decision,
            reason="runtime_gate_waiting_for_human_approval",
        )
        assert outcome.status == ApprovalStatus.PENDING.value
        pending = store.get_pending(outcome.request_id)
        assert pending is not None
        assert pending.action_gate_metadata_jcs is not None
        metadata = json.loads(pending.action_gate_metadata_jcs)
        assert metadata["paid_approval_center_projection"]["projection_kind"] == "paid_active"
        html = httpx.get(server.approval_url(outcome.request_id)).text
        assert "Paid policy review" in html
        for marker in FORBIDDEN_MARKERS:
            assert marker not in html
    finally:
        server.stop()
        store.close()


def test_persistent_center_renders_paid_projection_and_allows_deny(tmp_path: Path):
    config = _config(policy_rule=_write_rule())
    proxy_dir = tmp_path / "mcp-proxy"
    proxy_dir.mkdir(parents=True)
    store = ApprovalEvidenceStore(proxy_dir / "evidence.sqlite")
    server = create_persistent_server(proxy_dir=proxy_dir, evidence_store=store)
    save_manifest(proxy_dir, build_manifest_for_server(server))
    manager = ApprovalManager(
        evidence_store=store,
        approval_server=server,
        config=config,
        client_id=f"github:pid:{os.getpid()}",
        headless=False,
        wait_for_decision=False,
        notifier=NoopNotifier(),
    )
    try:
        decision = RuntimeGateDecision(
            decision="WAITING_FOR_HUMAN_APPROVAL",
            audit_id=AUDIT_ID,
            approval_id=None,
            receipt_digest="b" * 64,
            receipt_body={"decision": "WAITING_FOR_HUMAN_APPROVAL"},
            paid_approval_center_projection=_active_projection(),
        )
        outcome = manager.request_approval(
            _classification(config),
            runtime_decision=decision,
            reason="runtime_gate_waiting_for_human_approval",
        )
        url = server.approval_url(outcome.request_id)
        with httpx.Client(follow_redirects=False) as client:
            html = client.get(url).text
            assert "Paid policy review" in html
            assert 'data-paid-projection="paid_active"' in html
            prompt = server.prompt_for(outcome.request_id)
            assert prompt is not None
            restored = approval_prompt_to_dict(prompt)
            assert restored["action_gate_metadata"]["paid_approval_center_projection"][
                "projection_kind"
            ] == "paid_active"
            csrf = TOKEN_RE.search(html)
            assert csrf is not None
            response = _post_decision(
                client,
                url,
                decision="deny",
                csrf=csrf.group(1),
            )
            assert response.status_code == 200
        pending = store.get_pending(outcome.request_id)
        assert pending is not None
        assert pending.status == ApprovalStatus.DENIED.value
    finally:
        server.stop()
        store.close()
