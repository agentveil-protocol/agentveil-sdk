"""CA3 public runtime adapter tests (inert until bound)."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

import pytest

from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.controlled_alternatives import (
    CONTROLLED_ALTERNATIVE_IDS,
    CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
    CONTROLLED_ALTERNATIVE_PROVIDER_ID,
    CONTROLLED_ALTERNATIVES_PROFILE_ID,
    GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
    build_controlled_alternative_tool_schema,
    validate_provider_descriptor,
)
from agentveil_mcp_proxy.controlled_alternatives_runtime import (
    ControlledAlternativeRuntimeBinding,
    apply_controlled_alternative_policy,
    bind_controlled_alternative_runtime,
    execute_controlled_alternative,
    inject_controlled_alternative_tool,
)
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough
from agentveil_mcp_proxy.policy import PolicyDecision, PolicyEvaluation, ProxyConfig, RiskClass

STAGE = "filesystem.stage_delete.v1"
RESTORE = "filesystem.restore_staged.v1"
CLEANUP = "filesystem.cleanup_staged.v1"
SECRET_PATH = "secret.txt"
QUARANTINE_ID = "cafebabedeadbeef0123456789abcdef"


def _descriptor():
    return validate_provider_descriptor({
        "provider_id": CONTROLLED_ALTERNATIVE_PROVIDER_ID,
        "contract_version": CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
        "profile_id": CONTROLLED_ALTERNATIVES_PROFILE_ID,
        "alternative_ids": list(CONTROLLED_ALTERNATIVE_IDS),
    })


class _FakeProvider:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.calls: list[str] = []
        self.staged: dict[str, str] = {}
        self.fail_mode: str | None = None
        self.drifted = False

    def descriptor(self) -> dict[str, object]:
        return {
            "provider_id": CONTROLLED_ALTERNATIVE_PROVIDER_ID,
            "contract_version": CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
            "profile_id": CONTROLLED_ALTERNATIVES_PROFILE_ID,
            "alternative_ids": list(CONTROLLED_ALTERNATIVE_IDS),
        }

    def _base(self, request, *, status: str, target: bool, rollback: bool, error: str | None = None, qid: str | None = None):
        payload = {
            "contract_version": "1",
            "alternative_id": request.alternative_id,
            "operation_ref": request.operation_ref,
            "result_status": status,
            "outcome_class_candidate": (
                "COMPLETED_WITH_ALTERNATIVE" if status == "success" else "ALTERNATIVE_UNAVAILABLE"
            ),
            "target_reached": target,
            "rollback_available": rollback,
        }
        if error is not None:
            payload["error_code"] = error
        if qid is not None:
            payload["quarantine_entry_id"] = qid
        return payload

    def propose(self, request):
        self.calls.append(f"propose:{request.alternative_id}")
        if self.fail_mode == "raise":
            raise RuntimeError("provider-boom")
        if self.fail_mode == "drift":
            self.drifted = True
        if request.alternative_id in {
            "protected_write.prepare_patch.v1",
            "git.prepare_local_change.v1",
        }:
            return self._base(request, status="unavailable", target=False, rollback=False, error="internal_error")
        return self._base(request, status="success", target=False, rollback=False)

    def execute(self, request):
        self.calls.append(f"execute:{request.alternative_id}")
        if self.fail_mode == "partial" and request.alternative_id == STAGE:
            path = request.resource_locator.normalized_path
            if isinstance(path, str) and Path(path).is_file():
                self.staged[QUARANTINE_ID] = Path(path).read_text(encoding="utf-8")
                Path(path).unlink()
            return self._base(
                request,
                status="error",
                target=True,
                rollback=True,
                error="atomic_relocation_unavailable",
                qid=QUARANTINE_ID,
            )
        if request.alternative_id in {
            "protected_write.prepare_patch.v1",
            "git.prepare_local_change.v1",
        }:
            return self._base(request, status="unavailable", target=False, rollback=False, error="internal_error")
        if request.alternative_id == STAGE:
            path = request.resource_locator.normalized_path
            if isinstance(path, str) and Path(path).is_file():
                self.staged[QUARANTINE_ID] = Path(path).read_text(encoding="utf-8")
                Path(path).unlink()
            return self._base(request, status="success", target=True, rollback=True, qid=QUARANTINE_ID)
        if request.alternative_id == RESTORE:
            restored = self.workspace / SECRET_PATH
            restored.write_text(self.staged.get(request.resource_locator.quarantine_entry_id, "ok"), encoding="utf-8")
            return self._base(request, status="success", target=True, rollback=False)
        return self._base(request, status="success", target=True, rollback=False)

    def verify(self, request):
        self.calls.append(f"verify:{request.alternative_id}")
        if self.fail_mode == "verify":
            return self._base(request, status="error", target=False, rollback=False, error="mechanism_verification_failed")
        if self.fail_mode == "verify_raise":
            raise RuntimeError("verify-boom")
        if self.fail_mode == "verify_malformed":
            payload = self._base(request, status="success", target=True, rollback=True, qid=QUARANTINE_ID)
            payload["secret"] = "leak"
            return payload
        if request.alternative_id in {
            "protected_write.prepare_patch.v1",
            "git.prepare_local_change.v1",
        }:
            return self._base(request, status="unavailable", target=False, rollback=False, error="internal_error")
        if request.alternative_id == STAGE:
            return self._base(request, status="success", target=True, rollback=True, qid=QUARANTINE_ID)
        return self._base(request, status="success", target=True, rollback=False)


def _binding(tmp_path: Path) -> ControlledAlternativeRuntimeBinding:
    workspace = tmp_path / "workspace"
    home = workspace / ".avp"
    workspace.mkdir(exist_ok=True)
    home.mkdir(exist_ok=True)
    (workspace / SECRET_PATH).write_text("secret-bytes", encoding="utf-8")
    provider = _FakeProvider(workspace)
    descriptor = _descriptor()
    return ControlledAlternativeRuntimeBinding(
        provider=provider,
        descriptor=descriptor,
        schema=build_controlled_alternative_tool_schema(descriptor),
        workspace_root=str(workspace.resolve()),
        state_root=str(home.resolve()),
        route_id="sha256:" + ("ab" * 32),
        st_dev=workspace.stat().st_dev,
    )



def _recheck_payload(binding: ControlledAlternativeRuntimeBinding, **overrides: object) -> dict:
    payload = {
        "route_id": binding.route_id,
        "action_hash": "a",
        "recheck_action_hash": "a",
        "resource_hash": "r",
        "recheck_resource_hash": "r",
        "payload_hash": "p",
        "recheck_payload_hash": "p",
        "policy_context_hash": "c",
        "recheck_policy_context_hash": "c",
        "policy_decision": "observe",
        "recheck_policy_decision": "observe",
        "session_id": None,
        "recheck_session_id": None,
        "approved": None,
        "recheck_approved": None,
    }
    payload.update(overrides)
    return payload


def _ok_recheck(binding: ControlledAlternativeRuntimeBinding):
    return lambda: _recheck_payload(binding)


def _config(*, mode: str = "observe") -> ProxyConfig:
    return ProxyConfig.from_dict({
        "proxy_config_schema_version": 1,
        "avp": {
            "base_url": "https://agentveil.dev",
            "agent_name": "agentveil-mcp-proxy",
            "trusted_signer_dids": ["did:key:z6MktrustedSigner"],
        },
        "mode": mode,
        "privacy": {"action": "redacted", "resource": "hash", "payload": "hash_only", "evidence_upload": False},
        "fallback": {},
        "approval": {},
        "policy": {
            "id": "default",
            "policy_schema_version": 1,
            "default_decision": "ask_backend",
            "default_risk_class": "unknown",
            "rules": [],
        },
        "downstream": {},
    })


def test_inject_appends_only_when_bound() -> None:
    response = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "read_file"}]}}
    assert inject_controlled_alternative_tool(response, None) == response


def test_inject_and_stage_restore_cleanup(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        binding,
    )
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert names == ["read_file", GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME]
    secret = Path(binding.workspace_root) / SECRET_PATH
    staged = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
        recheck=_ok_recheck(binding),
    )
    assert staged["mechanism_status"] == "success"
    assert staged["quarantine_entry_id"] == QUARANTINE_ID
    assert staged["terminal_outcome"] == "COMPLETED_WITH_ALTERNATIVE"
    assert staged["verification_level"] == "public_source_absent"
    assert not secret.exists()
    assert QUARANTINE_ID not in f"{binding!r}"
    restored = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": RESTORE, "input": {"quarantine_entry_id": QUARANTINE_ID}},
        recheck=_ok_recheck(binding),
    )
    assert restored["mechanism_status"] == "success"
    assert "terminal_outcome" not in restored
    assert restored["verification_level"] == "mechanism_verified"
    assert secret.exists()
    cleaned = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": CLEANUP, "input": {"quarantine_entry_id": QUARANTINE_ID}},
        recheck=_ok_recheck(binding),
    )
    assert cleaned["mechanism_status"] == "success"
    assert "terminal_outcome" not in cleaned
    unavailable = execute_controlled_alternative(
        binding=binding,
        arguments={
            "alternative_id": "git.prepare_local_change.v1",
            "input": {"worktree_path": "."},
        },
    )
    assert unavailable["mechanism_status"] == "unavailable"
    assert [item.split(":", 1)[0] for item in binding.provider.calls if item.startswith(("propose", "execute", "verify")) and "git." in item] == ["propose"]
    assert not any(item.startswith("execute:git.") for item in binding.provider.calls)


def test_bind_rejects_global_state_root(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside-home"
    outside.mkdir()
    bound = bind_controlled_alternative_runtime(
        home=outside,
        downstream={"name": "fs", "command": "python", "args": [], "cwd": str(workspace)},
    )
    assert bound is None


def test_recheck_drift_blocks_execute(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.provider.fail_mode = "drift"
    post_propose = {"count": 0}

    def recheck():
        post_propose["count"] += 1
        assert any(item.startswith("propose:") for item in binding.provider.calls)
        assert not any(item.startswith("execute:") for item in binding.provider.calls)
        payload = _recheck_payload(binding)
        if binding.provider.drifted:
            payload["recheck_action_hash"] = "drifted"
        return payload

    secret = Path(binding.workspace_root) / SECRET_PATH
    result = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
        recheck=recheck,
    )
    assert post_propose["count"] == 1
    assert result["mechanism_status"] == "error"
    assert not any(item.startswith("execute:") for item in binding.provider.calls)
    assert secret.exists()


def test_cleanup_policy_is_hard_h() -> None:
    evaluation = PolicyEvaluation(
        decision=PolicyDecision.ALLOW,
        risk_class=RiskClass.UNKNOWN,
        policy_id="default",
        policy_rule_id="default",
        policy_context_hash="sha256:" + ("11" * 32),
        matched_rule_ids=(),
    )
    coerced, risk, family = apply_controlled_alternative_policy(
        alternative_id=CLEANUP,
        evaluation=evaluation,
        action_family="unknown",
    )
    assert coerced.decision is PolicyDecision.APPROVAL
    assert risk is RiskClass.DESTRUCTIVE
    assert family == "delete"
    ask = apply_controlled_alternative_policy(
        alternative_id=CLEANUP,
        evaluation=replace_decision(evaluation, PolicyDecision.ASK_BACKEND),
        action_family="unknown",
    )[0]
    assert ask.decision is PolicyDecision.BLOCK
    cleanup_local_block = apply_controlled_alternative_policy(
        alternative_id=CLEANUP,
        evaluation=replace_decision(evaluation, PolicyDecision.BLOCK),
        action_family="unknown",
    )[0]
    assert cleanup_local_block.decision is PolicyDecision.BLOCK


def test_write_ask_backend_is_not_rewritten_to_local_approval() -> None:
    evaluation = PolicyEvaluation(
        decision=PolicyDecision.ASK_BACKEND,
        risk_class=RiskClass.UNKNOWN,
        policy_id="default",
        policy_rule_id="default",
        policy_context_hash="sha256:" + ("11" * 32),
        matched_rule_ids=(),
    )
    coerced, risk, family = apply_controlled_alternative_policy(
        alternative_id=STAGE,
        evaluation=evaluation,
        action_family="unknown",
    )
    assert coerced.decision is PolicyDecision.ASK_BACKEND
    assert risk is RiskClass.WRITE
    assert family == "write"


def replace_decision(evaluation: PolicyEvaluation, decision: PolicyDecision) -> PolicyEvaluation:
    return replace(evaluation, decision=decision)


def test_classifier_maps_nested_alternative(tmp_path: Path) -> None:
    classifier = ToolCallClassifier(_config(), server_name="downstream")
    staged = classifier.classify(
        tool=GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
    )
    assert staged.risk_class is RiskClass.WRITE
    assert staged.action_family == "write"
    assert staged.policy_evaluation.decision is PolicyDecision.OBSERVE
    assert SECRET_PATH not in f"{staged!r}{staged.resource}{staged.resource_plain}"
    other = classifier.classify(
        tool=GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
        arguments={"alternative_id": STAGE, "input": {"path": "other.txt"}},
    )
    assert staged.resource_hash != other.resource_hash
    assert staged.resource_hash is not None
    cleanup = classifier.classify(
        tool=GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
        arguments={"alternative_id": CLEANUP, "input": {"quarantine_entry_id": QUARANTINE_ID}},
    )
    assert cleanup.risk_class is RiskClass.DESTRUCTIVE
    assert cleanup.policy_evaluation.decision is PolicyDecision.APPROVAL
    assert QUARANTINE_ID not in f"{cleanup!r}{cleanup.resource}{cleanup.resource_plain}"
    other_cleanup = classifier.classify(
        tool=GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
        arguments={"alternative_id": CLEANUP, "input": {"quarantine_entry_id": "aa" * 16}},
    )
    assert cleanup.resource_hash != other_cleanup.resource_hash
    worktree_a = classifier.classify(
        tool=GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
        arguments={"alternative_id": STAGE, "input": {"worktree_path": "wt-a"}},
    )
    worktree_b = classifier.classify(
        tool=GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
        arguments={"alternative_id": STAGE, "input": {"worktree_path": "wt-b"}},
    )
    assert worktree_a.resource_hash != worktree_b.resource_hash
    assert "wt-a" not in f"{worktree_a!r}{worktree_a.resource}{worktree_a.resource_plain}"
    _assert_no_locator_canaries(
        json.dumps(staged.backend_metadata())
        + json.dumps(staged.local_evidence_metadata())
        + json.dumps(cleanup.backend_metadata()),
        _binding(tmp_path),
    )


def test_passthrough_absent_binding_does_not_add_tool() -> None:
    passthrough = McpPassthrough(DownstreamConfig(command="python", args=(), name="plain"))
    injected = passthrough._inject_controlled_alternative_list(
        {"result": {"tools": [{"name": "read_file"}]}}
    )
    assert [tool["name"] for tool in injected["result"]["tools"]] == ["read_file"]


def test_passthrough_bound_call_never_forwards_downstream(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    classifier = ToolCallClassifier(_config(mode="observe"), server_name="plain")
    passthrough = McpPassthrough(
        DownstreamConfig(command="python", args=(), name="plain"),
        classifier=classifier,
        controlled_runtime=binding,
    )
    passthrough._tool_schemas.update_from_response(
        {"result": {"tools": [binding.schema, {"name": "read_file"}]}}
    )
    before = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        json.dumps({
            "jsonrpc": "2.0",
            "id": "ca-1",
            "method": "tools/call",
            "params": {
                "name": GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
                "arguments": {"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
            },
        })
    )
    assert passthrough._downstream_tool_calls_forwarded == before
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "success"
    assert body["quarantine_entry_id"] == QUARANTINE_ID
    dumped = json.dumps(responses)
    assert SECRET_PATH not in dumped
    assert str(binding.workspace_root) not in dumped


def test_collision_does_not_duplicate_generic_tool(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME}]}},
        binding,
    )
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert names == [GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME]


def test_collision_disables_synthetic_ownership_and_never_forwards(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    colliding = {
        "result": {
            "tools": [
                {"name": GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME},
                {"name": "read_file"},
            ]
        }
    }
    injected = passthrough._inject_controlled_alternative_list(colliding)
    assert [tool["name"] for tool in injected["result"]["tools"]] == [
        GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
        "read_file",
    ]
    passthrough._tool_schemas.update_from_response(injected)
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = list(binding.provider.calls)
    forwarded = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _generic_line("col", STAGE, {"path": SECRET_PATH})
    )
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"
    assert binding.provider.calls == before
    assert secret.exists()



def _generic_line(call_id: str, alternative_id: str, nested: dict) -> str:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {
            "name": GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
            "arguments": {"alternative_id": alternative_id, "input": nested},
        },
    })


def _bound_passthrough(tmp_path: Path, *, mode: str = "observe", approval_manager=None):
    binding = _binding(tmp_path)
    classifier = ToolCallClassifier(_config(mode=mode), server_name="plain")
    passthrough = McpPassthrough(
        DownstreamConfig(command="python", args=(), name="plain"),
        classifier=classifier,
        approval_manager=approval_manager,
        controlled_runtime=binding,
    )
    passthrough._tool_schemas.update_from_response(
        {"result": {"tools": [binding.schema, {"name": "read_file"}]}}
    )
    return binding, passthrough


class _BoundRecord:
    def __init__(self, classification, request_id: str) -> None:
        self.request_id = request_id
        self.payload_hash = classification.payload_hash
        self.resource_hash = classification.resource_hash
        self.tool_name = classification.tool
        self.action_gate_metadata_jcs = None
        self.granted_by_request_id = None
        self.status = None


def _cleanup_metadata_jcs(
    binding: ControlledAlternativeRuntimeBinding,
    *,
    omit: tuple[str, ...] = (),
    extra: dict | None = None,
) -> str:
    payload = {
        "controlled_alternative_id": CLEANUP,
        "project_scope_fingerprint": binding.route_id,
    }
    if extra:
        payload.update(extra)
    for key in omit:
        payload.pop(key, None)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _assert_no_locator_canaries(blob: str, binding: ControlledAlternativeRuntimeBinding) -> None:
    assert SECRET_PATH not in blob
    assert QUARANTINE_ID not in blob
    assert str(binding.workspace_root) not in blob
    assert str(binding.state_root) not in blob


class _BoundStore:
    def __init__(self) -> None:
        self.records: dict[str, _BoundRecord] = {}

    def get_pending(self, request_id: str):
        return self.records.get(request_id)


class _DecisionManager:
    def __init__(
        self,
        status: str,
        *,
        bind: bool = False,
        incomplete: bool = False,
        link_parent: bool = False,
        missing_parent: bool = False,
    ) -> None:
        self.status = status
        self.requests = 0
        self.evidence_store = _BoundStore() if bind else None
        self.session_id = "sess-ca3"
        self.client_id = "client-ca3"
        self._incomplete = incomplete
        self.metadata_jcs: str | None = None
        self.link_parent = link_parent
        self.missing_parent = missing_parent
        self.parent_payload_hash: str | None = None
        self.parent_resource_hash: str | None = None
        self.child_payload_hash: str | None = None
        self.child_resource_hash: str | None = None

    def request_approval(self, classification, *args, **kwargs):
        self.requests += 1
        from agentveil_mcp_proxy.approval.manager import ApprovalOutcome
        from agentveil_mcp_proxy.evidence import ApprovalStatus
        if isinstance(self.evidence_store, _BoundStore):
            record = _BoundRecord(classification, "apr-ca3")
            if self._incomplete:
                record.payload_hash = None
            if self.child_payload_hash is not None:
                record.payload_hash = self.child_payload_hash
            if self.child_resource_hash is not None:
                record.resource_hash = self.child_resource_hash
            if self.link_parent:
                record.granted_by_request_id = "apr-parent"
                if not self.missing_parent:
                    parent = _BoundRecord(classification, "apr-parent")
                    parent.status = ApprovalStatus.APPROVED.value
                    parent.action_gate_metadata_jcs = self.metadata_jcs
                    if self.parent_payload_hash is not None:
                        parent.payload_hash = self.parent_payload_hash
                    if self.parent_resource_hash is not None:
                        parent.resource_hash = self.parent_resource_hash
                    self.evidence_store.records["apr-parent"] = parent
            elif self.metadata_jcs is not None:
                record.action_gate_metadata_jcs = self.metadata_jcs
            self.evidence_store.records["apr-ca3"] = record
        return ApprovalOutcome(request_id="apr-ca3", status=self.status, reason=self.status)

    def pre_cancelled_outcome(self, request_id):
        return None

    def consume_prebind_cancellation(self, request_id):
        return None


def test_passthrough_recheck_after_propose_blocks_classifier_and_session_drift(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    original = passthrough.classifier.classify_jsonrpc
    post_propose_classifies = {"n": 0}

    def drifting_classify(message):
        classified = original(message)
        if classified is None:
            return None
        if any(item.startswith("propose:") for item in binding.provider.calls):
            post_propose_classifies["n"] += 1
            return replace(classified, action_hash="sha256:" + ("dd" * 32))
        return classified

    passthrough.classifier.classify_jsonrpc = drifting_classify
    secret = Path(binding.workspace_root) / SECRET_PATH
    responses = passthrough.handle_client_line(
        _generic_line("drift-cls", STAGE, {"path": SECRET_PATH})
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert post_propose_classifies["n"] >= 1
    assert body["mechanism_status"] == "error"
    assert not any(item.startswith("execute:") for item in binding.provider.calls)
    assert secret.exists()

    manager = _DecisionManager("approved")
    binding, passthrough = _bound_passthrough(tmp_path, approval_manager=manager)
    original_propose = binding.provider.propose

    def drifting_propose(request):
        result = original_propose(request)
        manager.session_id = "sess-changed"
        return result

    binding.provider.propose = drifting_propose
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = list(binding.provider.calls)
    responses = passthrough.handle_client_line(
        _generic_line("drift-sess", STAGE, {"path": SECRET_PATH})
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert any(item.startswith("propose:") for item in binding.provider.calls)
    assert not any(item.startswith("execute:") for item in binding.provider.calls)
    assert body["mechanism_status"] == "error"
    assert secret.exists()
    assert before == []


def test_malformed_and_forged_input_never_calls_provider(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    before = list(binding.provider.calls)
    forged = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": RESTORE, "input": {"quarantine_entry_id": "not-hex"}},
    )
    escaped = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": "../outside.txt"}},
    )
    missing = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {}},
    )
    assert forged["mechanism_status"] == "error"
    assert escaped["mechanism_status"] == "error"
    assert missing["mechanism_status"] == "error"
    assert binding.provider.calls == before


def test_stage_partial_error_retains_id_and_target_truth(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.provider.fail_mode = "partial"
    secret = Path(binding.workspace_root) / SECRET_PATH
    result = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
        recheck=_ok_recheck(binding),
    )
    assert result["mechanism_status"] == "error"
    assert result["error_code"] == "atomic_relocation_unavailable"
    assert result["quarantine_entry_id"] == QUARANTINE_ID
    assert result["target_reached"] is True
    assert "terminal_outcome" not in result
    assert not secret.exists()
    assert not any(item.startswith("verify:") for item in binding.provider.calls)


def test_provider_exception_and_verify_failure_fail_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.provider.fail_mode = "raise"
    exploded = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
        recheck=_ok_recheck(binding),
    )
    assert exploded["mechanism_status"] == "error"
    assert exploded["error_code"] == "internal_error"
    assert (Path(binding.workspace_root) / SECRET_PATH).exists()
    assert not any(item == "execute" or item.startswith("execute:") for item in binding.provider.calls)
    binding.provider.fail_mode = "verify"
    binding.provider.calls.clear()
    verified = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
        recheck=_ok_recheck(binding),
    )
    assert verified["mechanism_status"] == "error"
    assert verified["error_code"] == "mechanism_verification_failed"
    assert verified["target_reached"] is True
    assert verified["rollback_available"] is True
    assert verified["quarantine_entry_id"] == QUARANTINE_ID
    assert verified["verification_level"] == "not_verified"
    assert "terminal_outcome" not in verified
    assert not (Path(binding.workspace_root) / SECRET_PATH).exists()



def test_stage_protect_ask_backend_does_not_substitute_local_approval(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect")
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = list(binding.provider.calls)
    responses = passthrough.handle_client_line(
        _generic_line("ask-w", STAGE, {"path": SECRET_PATH})
    )
    assert "error" in responses[0]
    assert responses[0]["error"]["data"]["reason"] == "runtime_gate_not_configured"
    assert binding.provider.calls == before
    assert secret.exists()


def test_verify_exception_and_malformed_preserve_effect_truth(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.provider.fail_mode = "verify_raise"
    raised = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
        recheck=_ok_recheck(binding),
    )
    assert raised["mechanism_status"] == "error"
    assert raised["error_code"] == "internal_error"
    assert raised["target_reached"] is True
    assert raised["quarantine_entry_id"] == QUARANTINE_ID
    assert "terminal_outcome" not in raised
    binding = _binding(tmp_path)
    binding.provider.fail_mode = "verify_malformed"
    malformed = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
        recheck=_ok_recheck(binding),
    )
    assert malformed["mechanism_status"] == "error"
    assert malformed["target_reached"] is True
    assert malformed["quarantine_entry_id"] == QUARANTINE_ID
    assert "terminal_outcome" not in malformed


def test_cleanup_cannot_execute_on_allow_observe_or_ask(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path, mode="observe")
    before = list(binding.provider.calls)
    observe = passthrough.handle_client_line(
        _generic_line("c-obs", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    assert "error" in observe[0]
    # claim-check: allow "blocked" is the JSON-RPC error status vocabulary.
    assert observe[0]["error"]["data"]["status"] in {"approval_required", "blocked"}
    assert binding.provider.calls == before
    _, protect = _bound_passthrough(tmp_path, mode="protect")
    protect_binding = protect.controlled_runtime
    assert protect_binding is not None
    protect_before = list(protect_binding.provider.calls)
    asked = protect.handle_client_line(
        _generic_line("c-ask", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    assert asked[0]["error"]["data"].get("reason") in {
        "controlled_alternative_cleanup_ask_backend_fail_closed",
        "local_policy_block",
    } or asked[0]["error"]["data"]["status"] in {"policy_denied", "blocked"}  # claim-check: allow "blocked" is JSON-RPC status vocabulary.
    assert protect_binding.provider.calls == protect_before


def test_cleanup_without_binding_record_executes_zero_phases(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalStatus

    manager = _DecisionManager(ApprovalStatus.APPROVED.value)
    binding, passthrough = _bound_passthrough(tmp_path, mode="observe", approval_manager=manager)
    responses = passthrough.handle_client_line(
        _generic_line("c-none", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "error"
    assert not any(item.startswith("propose:") for item in binding.provider.calls)
    incomplete = _DecisionManager(ApprovalStatus.APPROVED.value, bind=True, incomplete=True)
    incomplete_binding, incomplete_pt = _bound_passthrough(
        tmp_path, mode="observe", approval_manager=incomplete
    )
    incomplete_pt.handle_client_line(
        _generic_line("c-inc", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    assert not any(item.startswith("propose:") for item in incomplete_binding.provider.calls)


def test_cleanup_approved_retry_executes_once_and_denies_never_execute(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalStatus

    manager = _DecisionManager(ApprovalStatus.APPROVED.value, bind=True)
    binding, passthrough = _bound_passthrough(tmp_path, mode="observe", approval_manager=manager)
    manager.metadata_jcs = _cleanup_metadata_jcs(binding)
    approved = passthrough.handle_client_line(
        _generic_line("c-ok", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    body = json.loads(approved[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "success"
    assert "terminal_outcome" not in body
    assert body["verification_level"] == "mechanism_verified"
    exported = json.dumps(list(passthrough.security_events)) + repr(passthrough) + repr(binding)
    _assert_no_locator_canaries(exported, binding)
    assert SECRET_PATH not in json.dumps(approved)
    assert str(binding.workspace_root) not in json.dumps(approved)
    assert manager.requests == 1
    assert [item for item in binding.provider.calls if ":" in item] == [
        f"propose:{CLEANUP}",
        f"execute:{CLEANUP}",
        f"verify:{CLEANUP}",
    ]

    deny = _DecisionManager(ApprovalStatus.DENIED.value)
    denied_binding, denied_pt = _bound_passthrough(tmp_path, mode="observe", approval_manager=deny)
    denied = denied_pt.handle_client_line(
        _generic_line("c-deny", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    assert "error" in denied[0]
    assert not any(item.startswith("propose:") for item in denied_binding.provider.calls)

    expired = _DecisionManager("expired")
    expired_binding, expired_pt = _bound_passthrough(tmp_path, mode="observe", approval_manager=expired)
    timed = expired_pt.handle_client_line(
        _generic_line("c-exp", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    assert "error" in timed[0]
    assert not any(item.startswith("propose:") for item in expired_binding.provider.calls)

    cancelled = _DecisionManager(ApprovalStatus.CANCELLED.value)
    cancel_binding, cancel_pt = _bound_passthrough(tmp_path, mode="observe", approval_manager=cancelled)
    cancelled_resp = cancel_pt.handle_client_line(
        _generic_line("c-can", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    assert cancelled_resp == []
    assert not any(item.startswith("propose:") for item in cancel_binding.provider.calls)


def _cleanup_bound_call(tmp_path: Path, metadata_jcs: str):
    from agentveil_mcp_proxy.evidence import ApprovalStatus

    manager = _DecisionManager(ApprovalStatus.APPROVED.value, bind=True)
    binding, passthrough = _bound_passthrough(tmp_path, mode="observe", approval_manager=manager)
    manager.metadata_jcs = metadata_jcs
    responses = passthrough.handle_client_line(
        _generic_line("c-bind", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    dumped = json.dumps(list(passthrough.security_events)) + repr(passthrough) + repr(binding) + repr(manager)
    _assert_no_locator_canaries(dumped, binding)
    assert SECRET_PATH not in json.dumps(responses)
    assert str(binding.workspace_root) not in json.dumps(responses)
    return binding, responses


def test_cleanup_missing_or_wrong_route_executes_zero_phases(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    missing_binding, missing = _cleanup_bound_call(
        tmp_path, _cleanup_metadata_jcs(binding, omit=("project_scope_fingerprint",))
    )
    assert missing_binding.provider.calls == []
    assert json.loads(missing[0]["result"]["content"][0]["text"])["mechanism_status"] == "error"
    wrong_binding, _wrong = _cleanup_bound_call(
        tmp_path,
        _cleanup_metadata_jcs(binding, extra={"project_scope_fingerprint": "sha256:" + ("cd" * 32)}),
    )
    assert wrong_binding.provider.calls == []


def test_cleanup_missing_or_wrong_alternative_id_executes_zero_phases(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    missing_binding, _missing = _cleanup_bound_call(
        tmp_path, _cleanup_metadata_jcs(binding, omit=("controlled_alternative_id",))
    )
    assert missing_binding.provider.calls == []
    wrong_binding, _wrong = _cleanup_bound_call(
        tmp_path, _cleanup_metadata_jcs(binding, extra={"controlled_alternative_id": STAGE})
    )
    assert wrong_binding.provider.calls == []


def test_cleanup_malformed_binding_metadata_executes_zero_phases(tmp_path: Path) -> None:
    binding, responses = _cleanup_bound_call(tmp_path, "{")
    assert binding.provider.calls == []
    assert json.loads(responses[0]["result"]["content"][0]["text"])["mechanism_status"] == "error"


def _linked_cleanup_call(
    tmp_path: Path,
    metadata_jcs: str | None,
    *,
    missing_parent: bool = False,
    parent_payload_hash: str | None = None,
    parent_resource_hash: str | None = None,
    child_payload_hash: str | None = None,
    child_resource_hash: str | None = None,
):
    from agentveil_mcp_proxy.evidence import ApprovalStatus

    manager = _DecisionManager(
        ApprovalStatus.APPROVED.value,
        bind=True,
        link_parent=True,
        missing_parent=missing_parent,
    )
    manager.metadata_jcs = metadata_jcs
    manager.parent_payload_hash = parent_payload_hash
    manager.parent_resource_hash = parent_resource_hash
    manager.child_payload_hash = child_payload_hash
    manager.child_resource_hash = child_resource_hash
    binding, passthrough = _bound_passthrough(tmp_path, mode="observe", approval_manager=manager)
    responses = passthrough.handle_client_line(
        _generic_line("c-link", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
    )
    dumped = json.dumps(list(passthrough.security_events)) + repr(passthrough) + repr(binding)
    _assert_no_locator_canaries(dumped, binding)
    assert SECRET_PATH not in json.dumps(responses)
    assert str(binding.workspace_root) not in json.dumps(responses)
    return binding, responses


def test_cleanup_real_approval_retry_executes_once(tmp_path: Path) -> None:
    import httpx
    from test_mcp_proxy_approval import _get_csrf, _manager, _post_decision
    from agentveil_mcp_proxy.evidence import ApprovalStatus

    manager, store, server, _cli = _manager(
        tmp_path,
        config=_config(mode="observe"),
        wait_for_decision=False,
    )
    try:
        binding, passthrough = _bound_passthrough(
            tmp_path, mode="observe", approval_manager=manager
        )
        first = passthrough.handle_client_line(
            _generic_line("c-real", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
        )
        assert first[0]["error"]["data"]["status"] == "approval_required"
        parent_id = first[0]["error"]["data"]["record_id"]
        parent = store.get_pending(parent_id)
        assert parent is not None
        parent_meta = json.loads(parent.action_gate_metadata_jcs)
        assert parent_meta["controlled_alternative_id"] == CLEANUP
        assert parent_meta["project_scope_fingerprint"] == binding.route_id
        with httpx.Client() as client:
            csrf = _get_csrf(client, server.approval_url(parent_id))
            posted = _post_decision(
                client,
                server.approval_url(parent_id),
                decision="approve",
                csrf=csrf,
            )
        assert posted.status_code == 200
        deadline = time.monotonic() + 2
        approved_parent = store.get_pending(parent_id)
        while (
            approved_parent is not None
            and approved_parent.status != ApprovalStatus.APPROVED.value
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
            approved_parent = store.get_pending(parent_id)
        assert approved_parent is not None
        assert approved_parent.status == ApprovalStatus.APPROVED.value
        retry = passthrough.handle_client_line(
            _generic_line("c-real", CLEANUP, {"quarantine_entry_id": QUARANTINE_ID})
        )
        body = json.loads(retry[0]["result"]["content"][0]["text"])
        assert body["mechanism_status"] == "success"
        assert body["verification_level"] == "mechanism_verified"
        assert "terminal_outcome" not in body
        assert [item for item in binding.provider.calls if ":" in item] == [
            f"propose:{CLEANUP}",
            f"execute:{CLEANUP}",
            f"verify:{CLEANUP}",
        ]
        child_rows = [
            record
            for record in store.list_records()
            if getattr(record, "granted_by_request_id", None) == parent_id
        ]
        assert len(child_rows) == 1
        exported = json.dumps(list(passthrough.security_events)) + repr(passthrough) + repr(binding)
        _assert_no_locator_canaries(exported, binding)
        assert SECRET_PATH not in json.dumps(first + retry)
        assert str(binding.workspace_root) not in json.dumps(first + retry)
    finally:
        server.stop()
        store.close()


def test_cleanup_missing_parent_authority_executes_zero_phases(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    linked, responses = _linked_cleanup_call(
        tmp_path,
        _cleanup_metadata_jcs(binding),
        missing_parent=True,
    )
    assert linked.provider.calls == []
    assert json.loads(responses[0]["result"]["content"][0]["text"])["mechanism_status"] == "error"


def test_cleanup_parent_wrong_route_or_alternative_executes_zero_phases(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    wrong_route, _route_resp = _linked_cleanup_call(
        tmp_path,
        _cleanup_metadata_jcs(binding, extra={"project_scope_fingerprint": "sha256:" + ("cd" * 32)}),
    )
    assert wrong_route.provider.calls == []
    wrong_alt, _alt_resp = _linked_cleanup_call(
        tmp_path,
        _cleanup_metadata_jcs(binding, extra={"controlled_alternative_id": STAGE}),
    )
    assert wrong_alt.provider.calls == []


def test_cleanup_parent_or_child_hash_mismatch_executes_zero_phases(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    metadata = _cleanup_metadata_jcs(binding)
    stale = "sha256:" + ("ee" * 32)
    parent_payload, _pp = _linked_cleanup_call(
        tmp_path, metadata, parent_payload_hash=stale
    )
    assert parent_payload.provider.calls == []
    parent_resource, _pr = _linked_cleanup_call(
        tmp_path, metadata, parent_resource_hash=stale
    )
    assert parent_resource.provider.calls == []
    child_payload, _cp = _linked_cleanup_call(
        tmp_path, metadata, child_payload_hash=stale
    )
    assert child_payload.provider.calls == []
    child_resource, _cr = _linked_cleanup_call(
        tmp_path, metadata, child_resource_hash=stale
    )
    assert child_resource.provider.calls == []


def test_forged_generic_call_without_binding_never_forwards() -> None:
    passthrough = McpPassthrough(DownstreamConfig(command="python", args=(), name="plain"))
    passthrough._tool_schemas.update_from_response(
        {"result": {"tools": [{"name": "read_file"}]}}
    )
    before = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _generic_line("forge", STAGE, {"path": SECRET_PATH})
    )
    assert passthrough._downstream_tool_calls_forwarded == before
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"


def test_privacy_canaries_absent_from_events_and_repr(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    responses = passthrough.handle_client_line(
        _generic_line("priv", STAGE, {"path": SECRET_PATH})
    )
    assert passthrough.classifier is not None
    classified = passthrough.classifier.classify(
        tool=GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
    )
    dumped_result = json.dumps(responses)
    assert SECRET_PATH not in dumped_result
    assert str(binding.workspace_root) not in dumped_result
    blob = json.dumps(list(passthrough.security_events)) + repr(passthrough) + repr(binding)
    blob += json.dumps(classified.backend_metadata()) + json.dumps(classified.local_evidence_metadata())
    blob += f"{classified!r}{classified.resource}{classified.resource_plain}"
    _assert_no_locator_canaries(blob, binding)


def test_isolated_vendored_853adf5_wheel_stage_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib
    import subprocess
    import sys

    import agentveil_mcp_proxy.controlled_alternatives as ca_mod
    from test_mcp_proxy_controlled_alternatives import (
        _active_paid_snapshot,
        _install_active_controlled_alternative_vendor,
        _no_global_controlled_entries,
    )

    private_root = Path(
        "/Users/olegboiko/Desktop/AVP/.worktrees/controlled-alternatives-ca3-private-filesystem-v1"
    )
    head = subprocess.check_output(
        ["git", "-C", str(private_root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    assert head == "853adf57cb821fa21432575df032537bdc352343"
    workspace = tmp_path / "workspace"
    home = workspace / ".avp"
    workspace.mkdir(exist_ok=True)
    home.mkdir(exist_ok=True)
    secret = workspace / SECRET_PATH
    secret.write_text("wheel-secret", encoding="utf-8")
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    built = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            str(private_root / "private_packages" / "agentveil_private_policy"),
            "-w",
            str(wheel_dir),
            "--no-deps",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    monkeypatch.setenv("AVP_HOME", str(home))
    monkeypatch.setattr(ca_mod, "entry_points", _no_global_controlled_entries)
    _install_active_controlled_alternative_vendor(home, wheel_bytes=wheels[0].read_bytes())
    residue_before = {name for name in sys.modules if name.startswith("agentveil_private_policy")}
    bound = bind_controlled_alternative_runtime(
        home=home,
        downstream={"name": "fs", "command": "python", "args": [], "cwd": str(workspace)},
        paid_snapshot=_active_paid_snapshot(),
    )
    assert bound is not None
    classifier = ToolCallClassifier(_config(mode="observe"), server_name="fs")
    passthrough = McpPassthrough(
        DownstreamConfig(command="python", args=(), name="fs"),
        classifier=classifier,
        controlled_runtime=bound,
    )
    listed = passthrough._inject_controlled_alternative_list(
        {"result": {"tools": [{"name": "read_file"}]}}
    )
    assert [tool["name"] for tool in listed["result"]["tools"]] == [
        "read_file",
        GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
    ]
    passthrough._tool_schemas.update_from_response(listed)
    forwarded = passthrough._downstream_tool_calls_forwarded
    staged_resp = passthrough.handle_client_line(
        _generic_line("w-stage", STAGE, {"path": SECRET_PATH})
    )
    staged = json.loads(staged_resp[0]["result"]["content"][0]["text"])
    assert staged["mechanism_status"] == "success"
    assert staged["terminal_outcome"] == "COMPLETED_WITH_ALTERNATIVE"
    assert staged["verification_level"] == "public_source_absent"
    assert "quarantine_entry_id" in staged
    assert not secret.exists()
    restored_resp = passthrough.handle_client_line(
        _generic_line("w-rest", RESTORE, {"quarantine_entry_id": staged["quarantine_entry_id"]})
    )
    restored = json.loads(restored_resp[0]["result"]["content"][0]["text"])
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    dumped = json.dumps(staged_resp + restored_resp)
    assert SECRET_PATH not in dumped
    assert str(bound.workspace_root) not in dumped
    assert restored["mechanism_status"] == "success"
    assert "terminal_outcome" not in restored
    assert restored["verification_level"] == "mechanism_verified"
    assert secret.exists()
    assert secret.read_text(encoding="utf-8") == "wheel-secret"
    vendor = str((home / "paid").resolve())
    assert vendor not in sys.path
    assert hashlib.sha256(wheels[0].read_bytes()).hexdigest()
    leftover = {name for name in sys.modules if name.startswith("agentveil_private_policy")} - residue_before
    for name in leftover:
        sys.modules.pop(name, None)
    assert SECRET_PATH not in repr(bound)
    assert staged["quarantine_entry_id"] not in repr(bound)


def test_direct_allow_classes_do_not_call_provider_and_stay_within_baseline(
    tmp_path: Path,
) -> None:
    import hashlib
    import importlib.util
    import sys

    from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough

    runner_path = Path(
        "/Users/olegboiko/Desktop/AVP/.worktrees/controlled-alternatives-ca3-performance-baseline-v1"
        "/tests/private_policy/test_controlled_alternatives_performance_baseline.py"
    )
    canonical_path = Path(
        "/Users/olegboiko/Desktop/AVP/.worktrees/controlled-alternatives-ca3-performance-baseline-v1"
        "/workspace/memory/controlled_alternatives_performance_baseline_2026-08-26.json"
    )
    assert hashlib.sha256(canonical_path.read_bytes()).hexdigest() == (
        "0c0d62f9bf1eefcce8dc78da7b66be938396400fcd4162dda5d83d7eb8e82ca9"
    )
    spec = importlib.util.spec_from_file_location("ca3_perf_runner", runner_path)
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    canonical = json.loads(canonical_path.read_text(encoding="utf-8"))
    binding = _binding(tmp_path)
    script = tmp_path / "fake_downstream.py"
    script.write_text(runner.FAKE_DOWNSTREAM_SOURCE, encoding="utf-8")
    passthrough = McpPassthrough(
        DownstreamConfig(command=sys.executable, args=("-u", str(script)), name="baseline-fake"),
        controlled_runtime=binding,
    )
    probe = runner._SendProbe(passthrough)
    classes = {}
    try:
        passthrough.start()
        runner._handshake(passthrough)
        probe.install()
        for spec_row in runner.CLASS_SPECS:
            for index in range(runner.WARMUP_COUNT):
                runner._one_call(passthrough, probe, spec_row, f"warmup-{spec_row['class_id']}-{index}")
            pre_samples = []
            completion_samples = []
            for index in range(runner.MEASURED_COUNT):
                pre_ms, completion_ms = runner._one_call(
                    passthrough,
                    probe,
                    spec_row,
                    f"meas-{spec_row['class_id']}-{index}",
                )
                pre_samples.append(pre_ms)
                completion_samples.append(completion_ms)
            classes[spec_row["class_id"]] = {
                "pre_result": runner.summary_stats(pre_samples),
                "completion": runner.summary_stats(completion_samples),
            }
    finally:
        passthrough.stop()
    assert binding.provider.calls == []
    for spec_row in runner.CLASS_SPECS:
        class_id = spec_row["class_id"]
        base = canonical["classes"][class_id]
        current = classes[class_id]
        pre_budget = max(base["pre_result"]["p95"] * 0.05, 2.0)
        completion_budget = max(base["completion"]["p95"] * 0.05, 10.0)
        assert current["pre_result"]["p95"] <= base["pre_result"]["p95"] + pre_budget
        assert current["completion"]["p95"] <= base["completion"]["p95"] + completion_budget
