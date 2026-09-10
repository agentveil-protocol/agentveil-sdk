"""CA3 public runtime adapter tests (inert until bound)."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

import pytest

from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.controlled_alternatives import (
    AUTHORITY_FORBIDDEN_RESULT_KEYS,
    APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
    CONTROLLED_ALTERNATIVE_IDS,
    CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
    CONTROLLED_ALTERNATIVE_PROVIDER_ID,
    CONTROLLED_ALTERNATIVES_PROFILE_ID,
    GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
    SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME,
    SEMANTIC_CLEANUP_STAGED_TOOL_NAME,
    SEMANTIC_GIT_OPERATION_TOOL_NAME,
    SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
    SEMANTIC_PREPARE_PATCH_TOOL_NAME,
    SEMANTIC_RESTORE_STAGED_TOOL_NAME,
    SEMANTIC_STAGE_DELETE_TOOL_NAME,
    STAGE_DELETE_RESTORE_HANDOFF_NOTE,
    build_controlled_alternative_tool_schema,
    build_semantic_controlled_alternative_tool_schemas,
    validate_provider_descriptor,
)
from agentveil_mcp_proxy.controlled_alternatives_runtime import (
    ControlledAlternativeRuntimeBinding,
    apply_controlled_alternative_policy,
    bind_controlled_alternative_runtime,
    execute_controlled_alternative,
    inject_controlled_alternative_tool,
    semantic_tool_is_projected,
)
from agentveil_mcp_proxy.passthrough import DownstreamConfig, McpPassthrough
from agentveil_mcp_proxy.policy import PolicyDecision, PolicyEvaluation, ProxyConfig, RiskClass

STAGE = "filesystem.stage_delete.v1"
RESTORE = "filesystem.restore_staged.v1"
CLEANUP = "filesystem.cleanup_staged.v1"
PREPARE = "protected_write.prepare_patch.v1"
APPLY = APPLY_PREPARED_PATCH_ALTERNATIVE_ID
GIT = "git.prepare_local_change.v1"
SECRET_PATH = "secret.txt"
SECRET_PATCH = "*** Begin Patch\nsecret-bytes\n*** End Patch"
QUARANTINE_ID = "cafebabedeadbeef0123456789abcdef"
PREPARED_REF = "d00df00ddeadbeef0123456789abcdef"
PREPARED_HASH = "ab" * 32


def _descriptor():
    return validate_provider_descriptor({
        "provider_id": CONTROLLED_ALTERNATIVE_PROVIDER_ID,
        "contract_version": CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
        "profile_id": CONTROLLED_ALTERNATIVES_PROFILE_ID,
        "alternative_ids": list(CONTROLLED_ALTERNATIVE_IDS),
    })


def _expected_controlled_tool_names(descriptor) -> list[str]:
    semantic = [schema["name"] for schema in build_semantic_controlled_alternative_tool_schemas(descriptor)]
    return [GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME, *semantic]


class _FakeProvider:
    def __init__(self, workspace: Path, *, alternative_ids: tuple[str, ...] | list[str] | None = None) -> None:
        self.workspace = workspace
        self.calls: list[str] = []
        self.requests: list[object] = []
        self.staged: dict[str, str] = {}
        self.fail_mode: str | None = None
        self.drifted = False
        self.git_ready = False
        self.alternative_ids = (
            list(alternative_ids) if alternative_ids is not None else list(CONTROLLED_ALTERNATIVE_IDS)
        )

    def descriptor(self) -> dict[str, object]:
        return {
            "provider_id": CONTROLLED_ALTERNATIVE_PROVIDER_ID,
            "contract_version": CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
            "profile_id": CONTROLLED_ALTERNATIVES_PROFILE_ID,
            "alternative_ids": list(self.alternative_ids),
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

    def _prepared(self, request, *, status: str = "success"):
        payload = self._base(request, status=status, target=False, rollback=False)
        if status == "success":
            payload["outcome_class_candidate"] = "PREPARED_FOR_APPROVAL"
            payload["prepared_artifact_ref"] = PREPARED_REF
            payload["prepared_artifact_hash"] = PREPARED_HASH
        else:
            payload["error_code"] = "internal_error"
        return payload

    def _applied(self, request, *, status: str = "success"):
        payload = self._base(request, status=status, target=False, rollback=False)
        if status != "success":
            payload["error_code"] = "internal_error"
        return payload

    def propose(self, request):
        self.calls.append(f"propose:{request.alternative_id}")
        self.requests.append(request)
        if self.fail_mode == "raise":
            raise RuntimeError("provider-boom")
        if self.fail_mode == "drift":
            self.drifted = True
        if request.alternative_id == GIT:
            if self.git_ready:
                return self._base(request, status="success", target=False, rollback=False)
            return self._base(request, status="unavailable", target=False, rollback=False, error="internal_error")
        if request.alternative_id == PREPARE:
            return self._prepared(request)
        if request.alternative_id == APPLY:
            return self._applied(request)
        return self._base(request, status="success", target=False, rollback=False)

    def execute(self, request):
        self.calls.append(f"execute:{request.alternative_id}")
        self.requests.append(request)
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
        if request.alternative_id == GIT:
            if self.git_ready:
                return self._base(request, status="success", target=False, rollback=False)
            return self._base(request, status="unavailable", target=False, rollback=False, error="internal_error")
        if request.alternative_id == PREPARE:
            return self._prepared(request)
        if request.alternative_id == APPLY:
            return self._applied(request)
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
        self.requests.append(request)
        if self.fail_mode == "verify":
            return self._base(request, status="error", target=False, rollback=False, error="mechanism_verification_failed")
        if self.fail_mode == "verify_raise":
            raise RuntimeError("verify-boom")
        if self.fail_mode == "verify_malformed":
            payload = self._base(request, status="success", target=True, rollback=True, qid=QUARANTINE_ID)
            payload["secret"] = "leak"
            return payload
        if request.alternative_id == GIT:
            if self.git_ready:
                return self._base(request, status="success", target=False, rollback=False)
            return self._base(request, status="unavailable", target=False, rollback=False, error="internal_error")
        if request.alternative_id == PREPARE:
            return self._prepared(request)
        if request.alternative_id == APPLY:
            return self._applied(request)
        if request.alternative_id == STAGE:
            return self._base(request, status="success", target=True, rollback=True, qid=QUARANTINE_ID)
        return self._base(request, status="success", target=True, rollback=False)


def _binding(tmp_path: Path) -> ControlledAlternativeRuntimeBinding:
    workspace = tmp_path / "workspace"
    home = workspace / ".avp"
    workspace.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)
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
        semantic_schemas=build_semantic_controlled_alternative_tool_schemas(descriptor),
    )


def _apply_descriptor():
    return validate_provider_descriptor({
        "provider_id": CONTROLLED_ALTERNATIVE_PROVIDER_ID,
        "contract_version": CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
        "profile_id": CONTROLLED_ALTERNATIVES_PROFILE_ID,
        "alternative_ids": list(CONTROLLED_ALTERNATIVE_IDS) + [APPLY],
    })


def _apply_input() -> dict[str, str]:
    return {
        "prepared_artifact_ref": PREPARED_REF,
        "prepared_artifact_hash": PREPARED_HASH,
    }


def _apply_binding(tmp_path: Path) -> ControlledAlternativeRuntimeBinding:
    workspace = tmp_path / "workspace"
    home = workspace / ".avp"
    workspace.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)
    (workspace / SECRET_PATH).write_text("secret-bytes", encoding="utf-8")
    descriptor = _apply_descriptor()
    provider = _FakeProvider(workspace, alternative_ids=descriptor.alternative_ids)
    return ControlledAlternativeRuntimeBinding(
        provider=provider,
        descriptor=descriptor,
        schema=build_controlled_alternative_tool_schema(descriptor),
        workspace_root=str(workspace.resolve()),
        state_root=str(home.resolve()),
        route_id="sha256:" + ("ab" * 32),
        st_dev=workspace.stat().st_dev,
        semantic_schemas=build_semantic_controlled_alternative_tool_schemas(descriptor),
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
    assert names == ["read_file", *_expected_controlled_tool_names(_descriptor())]
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
        {"result": {"tools": [binding.schema, *binding.semantic_schemas, {"name": "read_file"}]}}
    )
    return binding, passthrough


def _apply_bound_passthrough(tmp_path: Path, *, mode: str = "observe", approval_manager=None):
    binding = _apply_binding(tmp_path)
    classifier = ToolCallClassifier(_config(mode=mode), server_name="plain")
    passthrough = McpPassthrough(
        DownstreamConfig(command="python", args=(), name="plain"),
        classifier=classifier,
        approval_manager=approval_manager,
        controlled_runtime=binding,
    )
    passthrough._tool_schemas.update_from_response(
        {"result": {"tools": [binding.schema, *binding.semantic_schemas, {"name": "read_file"}]}}
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
    if not private_root.is_dir():
        pytest.skip("requires local private CA3 filesystem provider worktree")
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
        *_expected_controlled_tool_names(_descriptor()),
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
    if not runner_path.is_file() or not canonical_path.is_file():
        pytest.skip("requires local private CA3 performance baseline fixture")
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


def _semantic_line(call_id: str, tool_name: str, arguments: dict) -> str:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    })


def test_semantic_stage_delete_passthrough_never_forwards(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    passthrough._tool_schemas.update_from_response(
        {"result": {"tools": [binding.schema, *binding.semantic_schemas, {"name": "read_file"}]}}
    )
    before = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line("sem-stage", SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": SECRET_PATH})
    )
    assert passthrough._downstream_tool_calls_forwarded == before
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "success"
    assert body["quarantine_entry_id"] == QUARANTINE_ID


def test_forged_semantic_call_without_binding_never_forwards() -> None:
    passthrough = McpPassthrough(DownstreamConfig(command="python", args=(), name="plain"))
    passthrough._tool_schemas.update_from_response(
        {"result": {"tools": [{"name": "read_file"}]}}
    )
    before = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line("forge-sem", SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": SECRET_PATH})
    )
    assert passthrough._downstream_tool_calls_forwarded == before
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"


def test_semantic_catalog_collision_blocks_injection(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": SEMANTIC_STAGE_DELETE_TOOL_NAME}]}},
        binding,
    )
    assert [tool["name"] for tool in listed["result"]["tools"]] == [SEMANTIC_STAGE_DELETE_TOOL_NAME]


def test_malformed_semantic_call_returns_bounded_local_error(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    passthrough._tool_schemas.update_from_response(
        {"result": {"tools": [*binding.semantic_schemas]}}
    )
    responses = passthrough.handle_client_line(
        _semantic_line("bad-sem", SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": SECRET_PATH, "extra": 1})
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "error"
    assert body["error_code"] == "request_malformed"
    assert binding.provider.calls == []


def test_malformed_semantic_cleanup_has_zero_approval_provider_downstream(tmp_path: Path) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    before_downstream = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line(
            "bad-cleanup",
            SEMANTIC_CLEANUP_STAGED_TOOL_NAME,
            {"quarantine_entry_id": QUARANTINE_ID, "extra": 1},
        )
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "error"
    assert body["error_code"] == "request_malformed"
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == before_downstream


def test_absent_binding_semantic_cleanup_has_zero_approval_provider_downstream() -> None:
    manager = _DecisionManager("pending")
    passthrough = McpPassthrough(
        DownstreamConfig(command="python", args=(), name="plain"),
        classifier=ToolCallClassifier(_config(mode="protect"), server_name="plain"),
        approval_manager=manager,
        controlled_runtime=None,
    )
    before_downstream = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line(
            "absent-cleanup",
            SEMANTIC_CLEANUP_STAGED_TOOL_NAME,
            {"quarantine_entry_id": QUARANTINE_ID},
        )
    )
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"
    assert manager.requests == 0
    assert passthrough._downstream_tool_calls_forwarded == before_downstream


def test_unprojected_semantic_cleanup_has_zero_approval_provider_downstream(tmp_path: Path) -> None:
    from dataclasses import replace

    manager = _DecisionManager("pending")
    binding = _binding(tmp_path)
    projected = tuple(
        schema
        for schema in binding.semantic_schemas
        if schema.get("name") != SEMANTIC_CLEANUP_STAGED_TOOL_NAME
    )
    binding = replace(binding, semantic_schemas=projected)
    passthrough = McpPassthrough(
        DownstreamConfig(command="python", args=(), name="plain"),
        classifier=ToolCallClassifier(_config(mode="protect"), server_name="plain"),
        approval_manager=manager,
        controlled_runtime=binding,
    )
    passthrough._tool_schemas.update_from_response(
        {"result": {"tools": [binding.schema, *binding.semantic_schemas]}}
    )
    before_downstream = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line(
            "unproj-cleanup",
            SEMANTIC_CLEANUP_STAGED_TOOL_NAME,
            {"quarantine_entry_id": QUARANTINE_ID},
        )
    )
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == before_downstream


def test_semantic_restore_and_cleanup_happy_paths(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    staged = passthrough.handle_client_line(
        _semantic_line("sem-stage", SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": SECRET_PATH})
    )
    staged_body = json.loads(staged[0]["result"]["content"][0]["text"])
    assert staged_body["mechanism_status"] == "success"
    qid = staged_body["quarantine_entry_id"]
    restored = passthrough.handle_client_line(
        _semantic_line("sem-restore", SEMANTIC_RESTORE_STAGED_TOOL_NAME, {"quarantine_entry_id": qid})
    )
    restored_body = json.loads(restored[0]["result"]["content"][0]["text"])
    assert restored_body["mechanism_status"] == "success"
    from agentveil_mcp_proxy.evidence import ApprovalStatus

    manager = _DecisionManager(ApprovalStatus.APPROVED.value, bind=True)
    cleanup_binding, cleanup_pt = _bound_passthrough(tmp_path, mode="observe", approval_manager=manager)
    manager.metadata_jcs = _cleanup_metadata_jcs(cleanup_binding)
    cleaned = cleanup_pt.handle_client_line(
        _semantic_line("sem-cleanup", SEMANTIC_CLEANUP_STAGED_TOOL_NAME, {"quarantine_entry_id": qid})
    )
    cleaned_body = json.loads(cleaned[0]["result"]["content"][0]["text"])
    assert cleaned_body["mechanism_status"] == "success"
    assert manager.requests == 1
    assert [item for item in cleanup_binding.provider.calls if item.startswith("execute:")] == [
        f"execute:{CLEANUP}",
    ]


class _LineageManager:
    def __init__(
        self,
        store,
        *,
        session_id: str = "sess-sem-lineage",
        client_id: str = "client-sem-lineage",
    ) -> None:
        self.evidence_store = store
        self.session_id = session_id
        self.client_id = client_id
        self.requests = 0

    def request_approval(self, *_args, **_kwargs):
        self.requests += 1
        raise AssertionError("semantic redirect lineage tests must not request approval")


def _redirect_lineage_claim_count(store_path: Path) -> int:
    import sqlite3

    if not store_path.exists():
        return 0
    with sqlite3.connect(store_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM redirect_lineage_claims").fetchone()
    return int(row[0])


def _follow_up_metadata(store_path: Path, request_id: str) -> dict | None:
    import sqlite3

    if not store_path.exists():
        return None
    with sqlite3.connect(store_path) as conn:
        row = conn.execute(
            "SELECT action_gate_metadata_jcs FROM pending_approvals WHERE request_id = ?",
            (request_id,),
        ).fetchone()
    if row is None or not isinstance(row[0], str) or not row[0]:
        return None
    parsed = json.loads(row[0])
    return parsed if isinstance(parsed, dict) else None


def _seed_controlled_stage_delete_origin(
    store,
    manager: _LineageManager,
    binding: ControlledAlternativeRuntimeBinding,
    classifier: ToolCallClassifier,
    *,
    original_request_id: str = "orig-sem-delete",
    path: str = SECRET_PATH,
    created_at: int | None = None,
) -> str:
    from agentveil_mcp_proxy.client_guidance import (
        NATIVE_CONTROLLED_STAGE_DELETE_PLAYBOOK_ID,
        NATIVE_REDIRECT_ORIGIN_REASON,
    )
    from agentveil_mcp_proxy.classification import sha256_text
    from agentveil_mcp_proxy.policy import build_redirect_automation_metadata

    classified = classifier.classify(
        tool=SEMANTIC_STAGE_DELETE_TOOL_NAME,
        arguments={"path": path},
    )
    assert classified is not None
    metadata = build_redirect_automation_metadata(
        fixture_id="semantic-lineage",
        tool_name="apply_patch",
        policy_decision="block",
        policy_rule_id=None,
        approval_status="blocked",  # claim-check: allow tested bounded evidence status.
        execution_status="blocked",  # claim-check: allow tested bounded evidence status.
        target_reached=False,
        request_id=original_request_id,
        payload_hash=classified.payload_hash,
        action_family="filesystem",
        redirect_role="original",
        redirect_playbook_id=NATIVE_CONTROLLED_STAGE_DELETE_PLAYBOOK_ID,
        original_request_id=original_request_id,
        project_scope_fingerprint=binding.route_id,
    )
    metadata["native_hook_denied"] = True
    metadata["follow_up_tool"] = SEMANTIC_STAGE_DELETE_TOOL_NAME
    metadata_jcs = json.dumps(metadata, separators=(",", ":"), sort_keys=True)
    store.record_terminal_deny(
        request_id=original_request_id,
        session_id=manager.session_id,
        client_id=manager.client_id,
        downstream_server=classified.server,
        tool_name="apply_patch",
        risk_class="write",
        resource_hash=classified.resource_hash,
        payload_hash=classified.payload_hash,
        policy_id="semantic-lineage-test",
        policy_rule_id=None,
        policy_context_hash=sha256_text("semantic-lineage-test").removeprefix("sha256:"),
        created_at=created_at or int(time.time()),
        reason=NATIVE_REDIRECT_ORIGIN_REASON,
        action_gate_metadata_jcs=metadata_jcs,
    )
    return original_request_id


def _semantic_redirect_line(
    call_id: str,
    tool_name: str,
    arguments: dict,
    *,
    original_request_id: str,
    playbook_id: str = "controlled_stage_delete",
) -> str:
    payload = dict(arguments)
    payload["redirect_context"] = {
        "original_request_id": original_request_id,
        "redirect_playbook_id": playbook_id,
    }
    return _semantic_line(call_id, tool_name, payload)


def _lineage_passthrough(
    tmp_path: Path,
    store,
    manager: _LineageManager,
):
    binding = _binding(tmp_path)
    classifier = ToolCallClassifier(_config(mode="observe"), server_name="plain")
    passthrough = McpPassthrough(
        DownstreamConfig(command="python", args=(), name="plain"),
        classifier=classifier,
        approval_manager=manager,
        controlled_runtime=binding,
    )
    passthrough._tool_schemas.update_from_response(
        {"result": {"tools": [binding.schema, *binding.semantic_schemas, {"name": "read_file"}]}}
    )
    passthrough._current_project_scope_fingerprint = lambda **_kwargs: binding.route_id  # type: ignore[method-assign]
    return binding, passthrough, classifier, store.db_path


def test_semantic_redirect_context_records_verified_lineage_and_single_execute(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    manager = _LineageManager(store)
    binding, passthrough, classifier, store_path = _lineage_passthrough(tmp_path, store, manager)
    original_request_id = _seed_controlled_stage_delete_origin(
        store,
        manager,
        binding,
        classifier,
    )
    responses = passthrough.handle_client_line(
        _semantic_redirect_line(
            "sem-lineage",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=original_request_id,
        )
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "success"
    assert manager.requests == 0
    assert passthrough._downstream_tool_calls_forwarded == 0
    assert [item for item in binding.provider.calls if item.startswith("execute:")] == [f"execute:{STAGE}"]
    assert store_path is not None
    assert _redirect_lineage_claim_count(store_path) == 1
    follow_meta = _follow_up_metadata(store_path, "sem-lineage")
    assert follow_meta is not None
    assert follow_meta.get("lineage_status") == "verified"
    assert follow_meta.get("original_request_id") == original_request_id
    assert follow_meta.get("redirect_playbook_id") == "controlled_stage_delete"


def test_semantic_redirect_replay_and_invalid_contexts_execute_zero(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore
    from agentveil_mcp_proxy.role_doctor import INVALID_REDIRECT_CONTEXT, REDIRECT_LINEAGE_MAX_AGE_SECONDS

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    manager = _LineageManager(store)
    binding, passthrough, classifier, store_path = _lineage_passthrough(tmp_path, store, manager)
    original_request_id = _seed_controlled_stage_delete_origin(
        store,
        manager,
        binding,
        classifier,
    )
    line = _semantic_redirect_line(
        "sem-replay",
        SEMANTIC_STAGE_DELETE_TOOL_NAME,
        {"path": SECRET_PATH},
        original_request_id=original_request_id,
    )
    first = passthrough.handle_client_line(line)
    assert json.loads(first[0]["result"]["content"][0]["text"])["mechanism_status"] == "success"
    execute_after_first = [item for item in binding.provider.calls if item.startswith("execute:")]
    replay = passthrough.handle_client_line(line)
    assert "error" in replay[0]
    assert replay[0]["error"]["data"]["reason"] == INVALID_REDIRECT_CONTEXT
    assert [item for item in binding.provider.calls if item.startswith("execute:")] == execute_after_first

    wrong_tool = passthrough.handle_client_line(
        _semantic_redirect_line(
            "sem-wrong-tool",
            SEMANTIC_RESTORE_STAGED_TOOL_NAME,
            {"quarantine_entry_id": QUARANTINE_ID},
            original_request_id=original_request_id,
        )
    )
    assert "error" in wrong_tool[0]
    assert wrong_tool[0]["error"]["data"]["reason"] in {
        INVALID_REDIRECT_CONTEXT,
        "unsupported_redirect_playbook",
    }

    wrong_target_store = ApprovalEvidenceStore(tmp_path / "evidence-target.sqlite")
    wrong_target_manager = _LineageManager(wrong_target_store)
    wrong_target_binding, wrong_target_pt, wrong_target_cls, _ = _lineage_passthrough(
        tmp_path / "target",
        wrong_target_store,
        wrong_target_manager,
    )
    other_origin = _seed_controlled_stage_delete_origin(
        wrong_target_store,
        wrong_target_manager,
        wrong_target_binding,
        wrong_target_cls,
        path="other.txt",
    )
    wrong_target = wrong_target_pt.handle_client_line(
        _semantic_redirect_line(
            "sem-wrong-target",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=other_origin,
        )
    )
    assert "error" in wrong_target[0]

    original_session_manager = _LineageManager(store, session_id="sess-sem-lineage")
    wrong_session_manager = _LineageManager(store, session_id="sess-other")
    wrong_session_binding, wrong_session_pt, wrong_session_cls, _ = _lineage_passthrough(
        tmp_path / "session",
        store,
        wrong_session_manager,
    )
    session_origin = _seed_controlled_stage_delete_origin(
        store,
        original_session_manager,
        wrong_session_binding,
        wrong_session_cls,
        original_request_id="orig-sem-session",
    )
    wrong_session_pt._current_project_scope_fingerprint = lambda **_kwargs: wrong_session_binding.route_id  # type: ignore[method-assign]
    wrong_session = wrong_session_pt.handle_client_line(
        _semantic_redirect_line(
            "sem-wrong-session",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=session_origin,
        )
    )
    assert "error" in wrong_session[0]

    wrong_route_store = ApprovalEvidenceStore(tmp_path / "evidence-route.sqlite")
    wrong_route_manager = _LineageManager(wrong_route_store)
    wrong_route_binding, wrong_route_pt, wrong_route_cls, _ = _lineage_passthrough(
        tmp_path / "route",
        wrong_route_store,
        wrong_route_manager,
    )
    wrong_route_pt._current_project_scope_fingerprint = lambda **_kwargs: "sha256:" + ("cd" * 32)  # type: ignore[method-assign]
    route_origin = _seed_controlled_stage_delete_origin(
        wrong_route_store,
        wrong_route_manager,
        wrong_route_binding,
        wrong_route_cls,
        original_request_id="orig-sem-route",
    )
    wrong_route = wrong_route_pt.handle_client_line(
        _semantic_redirect_line(
            "sem-wrong-route",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=route_origin,
        )
    )
    assert "error" in wrong_route[0]

    stale_store = ApprovalEvidenceStore(tmp_path / "evidence-stale.sqlite")
    stale_manager = _LineageManager(stale_store)
    stale_binding, stale_pt, stale_cls, _ = _lineage_passthrough(
        tmp_path / "stale",
        stale_store,
        stale_manager,
    )
    stale_origin = _seed_controlled_stage_delete_origin(
        stale_store,
        stale_manager,
        stale_binding,
        stale_cls,
        created_at=int(time.time()) - REDIRECT_LINEAGE_MAX_AGE_SECONDS - 5,
    )
    stale = stale_pt.handle_client_line(
        _semantic_redirect_line(
            "sem-stale",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=stale_origin,
        )
    )
    assert "error" in stale[0]

    forged = passthrough.handle_client_line(
        _semantic_redirect_line(
            "sem-forged",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id="missing-origin",
        )
    )
    assert "error" in forged[0]
    assert store_path is not None
    assert _redirect_lineage_claim_count(store_path) == 1


def test_semantic_catalog_collision_with_redirect_context_has_zero_effects(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    manager = _LineageManager(store)
    binding, passthrough, classifier, store_path = _lineage_passthrough(tmp_path, store, manager)
    original_request_id = _seed_controlled_stage_delete_origin(
        store,
        manager,
        binding,
        classifier,
    )
    passthrough._controlled_catalog_collision = True
    before_downstream = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_redirect_line(
            "sem-collision",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=original_request_id,
        )
    )
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == before_downstream
    assert store_path is not None
    assert _redirect_lineage_claim_count(store_path) == 0


def test_semantic_redirect_errors_do_not_leak_private_paths(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    manager = _LineageManager(store)
    binding, passthrough, classifier, _store_path = _lineage_passthrough(tmp_path, store, manager)
    original_request_id = _seed_controlled_stage_delete_origin(
        store,
        manager,
        binding,
        classifier,
    )
    passthrough.handle_client_line(
        _semantic_redirect_line(
            "sem-privacy",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=original_request_id,
        )
    )
    replay = passthrough.handle_client_line(
        _semantic_redirect_line(
            "sem-privacy-replay",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=original_request_id,
        )
    )
    error_blob = json.dumps(replay) + json.dumps(list(passthrough.security_events)) + repr(passthrough)
    assert SECRET_PATH not in error_blob
    assert str(binding.workspace_root) not in error_blob
    assert str(binding.state_root) not in error_blob


def test_semantic_redirect_propose_failure_does_not_claim_lineage(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    manager = _LineageManager(store)
    binding, passthrough, classifier, store_path = _lineage_passthrough(tmp_path, store, manager)
    binding.provider.fail_mode = "raise"
    original_request_id = _seed_controlled_stage_delete_origin(
        store,
        manager,
        binding,
        classifier,
    )
    responses = passthrough.handle_client_line(
        _semantic_redirect_line(
            "sem-propose-fail",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=original_request_id,
        )
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "error"
    assert any(item.startswith("propose:") for item in binding.provider.calls)
    assert not any(item.startswith("execute:") for item in binding.provider.calls)
    assert store_path is not None
    assert _redirect_lineage_claim_count(store_path) == 0


def test_semantic_redirect_recheck_drift_does_not_claim_lineage(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    manager = _LineageManager(store)
    binding, passthrough, classifier, store_path = _lineage_passthrough(tmp_path, store, manager)
    original_request_id = _seed_controlled_stage_delete_origin(
        store,
        manager,
        binding,
        classifier,
    )
    original_classify = passthrough.classifier.classify_jsonrpc

    def drifting_classify(message):
        classified = original_classify(message)
        if classified is None:
            return None
        if any(item.startswith("propose:") for item in binding.provider.calls):
            return replace(classified, action_hash="sha256:" + ("dd" * 32))
        return classified

    passthrough.classifier.classify_jsonrpc = drifting_classify
    responses = passthrough.handle_client_line(
        _semantic_redirect_line(
            "sem-recheck-drift",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=original_request_id,
        )
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "error"
    assert any(item.startswith("propose:") for item in binding.provider.calls)
    assert not any(item.startswith("execute:") for item in binding.provider.calls)
    assert store_path is not None
    assert _redirect_lineage_claim_count(store_path) == 0


def test_semantic_redirect_claim_failure_after_recheck_has_zero_execute(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore
    from agentveil_mcp_proxy.role_doctor import INVALID_REDIRECT_CONTEXT

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    manager = _LineageManager(store)
    binding, passthrough, classifier, store_path = _lineage_passthrough(tmp_path, store, manager)
    original_request_id = _seed_controlled_stage_delete_origin(
        store,
        manager,
        binding,
        classifier,
    )
    real_finalize = passthrough._finalize_redirect_lineage_claim

    def failing_finalize(request_id, classification):
        return passthrough._redirect_context_error_response(
            request_id,
            reason=INVALID_REDIRECT_CONTEXT,
            message="invalid redirect_context",
        )

    passthrough._finalize_redirect_lineage_claim = failing_finalize  # type: ignore[method-assign]
    responses = passthrough.handle_client_line(
        _semantic_redirect_line(
            "sem-claim-fail",
            SEMANTIC_STAGE_DELETE_TOOL_NAME,
            {"path": SECRET_PATH},
            original_request_id=original_request_id,
        )
    )
    assert "error" in responses[0]
    assert responses[0]["error"]["data"]["reason"] == INVALID_REDIRECT_CONTEXT
    assert any(item.startswith("propose:") for item in binding.provider.calls)
    assert not any(item.startswith("execute:") for item in binding.provider.calls)
    assert store_path is not None
    assert _redirect_lineage_claim_count(store_path) == 0
    passthrough._finalize_redirect_lineage_claim = real_finalize  # type: ignore[method-assign]


def test_semantic_redirect_replay_claims_once_executes_once(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore
    from agentveil_mcp_proxy.role_doctor import INVALID_REDIRECT_CONTEXT

    store = ApprovalEvidenceStore(tmp_path / "evidence.sqlite")
    manager = _LineageManager(store)
    binding, passthrough, classifier, store_path = _lineage_passthrough(tmp_path, store, manager)
    original_request_id = _seed_controlled_stage_delete_origin(
        store,
        manager,
        binding,
        classifier,
    )
    line = _semantic_redirect_line(
        "sem-once",
        SEMANTIC_STAGE_DELETE_TOOL_NAME,
        {"path": SECRET_PATH},
        original_request_id=original_request_id,
    )
    first = passthrough.handle_client_line(line)
    assert json.loads(first[0]["result"]["content"][0]["text"])["mechanism_status"] == "success"
    execute_count = len([item for item in binding.provider.calls if item.startswith("execute:")])
    claim_count = _redirect_lineage_claim_count(store_path)
    replay = passthrough.handle_client_line(line)
    assert "error" in replay[0]
    assert replay[0]["error"]["data"]["reason"] == INVALID_REDIRECT_CONTEXT
    assert len([item for item in binding.provider.calls if item.startswith("execute:")]) == execute_count
    assert _redirect_lineage_claim_count(store_path) == claim_count == 1


def test_stage_result_projection_exposes_quarantine_entry_id_for_restore(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    staged = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": SECRET_PATH}},
        recheck=_ok_recheck(binding),
    )
    assert next(iter(staged)) == "quarantine_entry_id"
    assert staged["quarantine_entry_id"] == QUARANTINE_ID
    assert staged["restore_handoff"] == STAGE_DELETE_RESTORE_HANDOFF_NOTE
    assert "agentveil_restore_staged" in staged["restore_handoff"]
    assert AUTHORITY_FORBIDDEN_RESULT_KEYS.isdisjoint(staged)
    dumped = json.dumps(staged)
    assert SECRET_PATH not in dumped
    assert str(binding.workspace_root) not in dumped
    assert "/Users/" not in dumped
    assert "authority_grant" not in dumped
    restored = execute_controlled_alternative(
        binding=binding,
        arguments={
            "alternative_id": RESTORE,
            "input": {"quarantine_entry_id": staged["quarantine_entry_id"]},
        },
        recheck=_ok_recheck(binding),
    )
    assert restored["mechanism_status"] == "success"
    assert "restore_handoff" not in restored
    wrong = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": RESTORE, "input": {"quarantine_entry_id": "not-hex"}},
        recheck=_ok_recheck(binding),
    )
    assert wrong["mechanism_status"] == "error"
    assert "restore_handoff" not in wrong
    listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        binding,
    )
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME in names
    assert SEMANTIC_RESTORE_STAGED_TOOL_NAME in names
    assert SEMANTIC_CLEANUP_STAGED_TOOL_NAME in names
    cleanup_schema = next(
        tool for tool in listed["result"]["tools"] if tool["name"] == SEMANTIC_CLEANUP_STAGED_TOOL_NAME
    )
    assert "approval" in cleanup_schema["description"].lower()
    assert "autonomous next step" in cleanup_schema["description"].lower()


def _assert_prepare_privacy(blob: str, binding: ControlledAlternativeRuntimeBinding) -> None:
    assert SECRET_PATCH not in blob
    assert "*** Begin Patch" not in blob
    assert str(binding.workspace_root) not in blob
    assert str(binding.state_root) not in blob
    assert binding.route_id not in blob
    assert "/Users/" not in blob
    assert "agentveil_private_policy" not in blob
    assert "approval_granted" not in blob


def test_catalog_advertises_prepare_only_when_protected_write_id_present(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        binding,
    )
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert SEMANTIC_PREPARE_PATCH_TOOL_NAME in names
    assert names.count(SEMANTIC_PREPARE_PATCH_TOOL_NAME) == 1
    assert SEMANTIC_STAGE_DELETE_TOOL_NAME in names
    assert SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME in names
    assert names.count(SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME) == 1
    assert "agentveil_prepare_local_change" not in names
    assert inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        None,
    )["result"]["tools"] == [{"name": "read_file"}]
    unprojected = replace(
        binding,
        semantic_schemas=tuple(
            schema
            for schema in binding.semantic_schemas
            if schema.get("name") != SEMANTIC_PREPARE_PATCH_TOOL_NAME
        ),
    )
    assert semantic_tool_is_projected(binding, SEMANTIC_PREPARE_PATCH_TOOL_NAME)
    assert not semantic_tool_is_projected(unprojected, SEMANTIC_PREPARE_PATCH_TOOL_NAME)
    omitted = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        unprojected,
    )
    assert SEMANTIC_PREPARE_PATCH_TOOL_NAME not in [
        tool["name"] for tool in omitted["result"]["tools"]
    ]


def test_semantic_prepare_maps_trusted_locator_and_does_not_mutate_target(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = secret.read_text(encoding="utf-8")
    result = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": PREPARE, "input": {"path": SECRET_PATH, "patch": SECRET_PATCH}},
        recheck=_ok_recheck(binding),
    )
    assert result["mechanism_status"] == "success"
    assert result["verification_level"] == "mechanism_verified"
    assert result["prepared_artifact_ref"] == PREPARED_REF
    assert result["prepared_artifact_hash"] == PREPARED_HASH
    assert result["outcome_class_candidate"] == "PREPARED_FOR_APPROVAL"
    assert result["target_reached"] is False
    assert "terminal_outcome" not in result
    assert SECRET_PATCH not in json.dumps(result)
    assert secret.read_text(encoding="utf-8") == before
    assert secret.exists()
    phases = [item for item in binding.provider.calls if item.startswith(("propose:", "execute:", "verify:"))]
    assert phases == [
        f"propose:{PREPARE}",
        f"execute:{PREPARE}",
        f"verify:{PREPARE}",
    ]
    request = binding.provider.requests[0]
    assert request.alternative_id == PREPARE
    assert request.action_family == "write"
    assert request.semantic_category == "filesystem"
    assert request.resource_locator.locator_kind == "protected_write_target"
    assert request.resource_locator.workspace_root == binding.workspace_root
    assert request.resource_locator.state_root == binding.state_root
    assert request.resource_locator.route_id == binding.route_id
    assert request.resource_locator.st_dev == binding.st_dev
    assert request.bounded_local_input is not None
    assert request.bounded_local_input.patch == SECRET_PATCH
    assert not hasattr(request.bounded_local_input, "path")
    _assert_prepare_privacy(f"{result!r}{result}{binding!r}{request!r}{request}", binding)


def test_semantic_prepare_passthrough_happy_path(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = secret.read_text(encoding="utf-8")
    forwarded = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line(
            "sem-prep",
            SEMANTIC_PREPARE_PATCH_TOOL_NAME,
            {"path": SECRET_PATH, "patch": SECRET_PATCH},
        )
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert body["mechanism_status"] == "success"
    assert body["prepared_artifact_ref"] == PREPARED_REF
    assert body["prepared_artifact_hash"] == PREPARED_HASH
    assert body["outcome_class_candidate"] == "PREPARED_FOR_APPROVAL"
    assert "terminal_outcome" not in body
    assert SECRET_PATCH not in json.dumps(responses)
    assert secret.read_text(encoding="utf-8") == before
    assert [item for item in binding.provider.calls if item.startswith(("propose:", "execute:", "verify:"))] == [
        f"propose:{PREPARE}",
        f"execute:{PREPARE}",
        f"verify:{PREPARE}",
    ]
    _assert_prepare_privacy(json.dumps(responses), binding)


def test_malformed_semantic_prepare_has_zero_approval_provider_downstream(tmp_path: Path) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    before_downstream = passthrough._downstream_tool_calls_forwarded
    cases = (
        {"path": SECRET_PATH, "patch": SECRET_PATCH, "extra": 1},
        {"path": "/tmp/notes.txt", "patch": SECRET_PATCH},
        {"path": "../secret.txt", "patch": SECRET_PATCH},
        {"path": r"C:\secret.txt", "patch": SECRET_PATCH},
        {"path": "C:/secret.txt", "patch": SECRET_PATCH},
        {"path": SECRET_PATH + "\n", "patch": SECRET_PATCH},
        {"path": SECRET_PATH, "patch": 123},
        {"path": SECRET_PATH, "patch": SECRET_PATCH, "approval_granted": True},
        {"path": SECRET_PATH, "patch": SECRET_PATCH, "workspace_root": "/tmp"},
    )
    for index, arguments in enumerate(cases):
        responses = passthrough.handle_client_line(
            _semantic_line(f"bad-prep-{index}", SEMANTIC_PREPARE_PATCH_TOOL_NAME, arguments)
        )
        body = json.loads(responses[0]["result"]["content"][0]["text"])
        assert body["mechanism_status"] == "error"
        assert body["error_code"] == "request_malformed"
        assert "prepared_artifact_ref" not in body
        _assert_prepare_privacy(json.dumps(responses), binding)
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == before_downstream


def test_unprojected_and_forged_semantic_prepare_never_reach_provider(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    passthrough._tool_schemas.update_from_response(
        {
            "result": {
                "tools": [
                    schema
                    for schema in binding.semantic_schemas
                    if schema.get("name") != SEMANTIC_PREPARE_PATCH_TOOL_NAME
                ]
            }
        }
    )
    projected = replace(
        binding,
        semantic_schemas=tuple(
            schema
            for schema in binding.semantic_schemas
            if schema.get("name") != SEMANTIC_PREPARE_PATCH_TOOL_NAME
        ),
    )
    passthrough.controlled_runtime = projected
    responses = passthrough.handle_client_line(
        _semantic_line(
            "unproj-prep",
            SEMANTIC_PREPARE_PATCH_TOOL_NAME,
            {"path": SECRET_PATH, "patch": SECRET_PATCH},
        )
    )
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"
    assert projected.provider.calls == []
    forged = McpPassthrough(DownstreamConfig(command="python", args=(), name="plain"))
    forged._tool_schemas.update_from_response({"result": {"tools": [{"name": "read_file"}]}})
    forged_responses = forged.handle_client_line(
        _semantic_line(
            "forge-prep",
            SEMANTIC_PREPARE_PATCH_TOOL_NAME,
            {"path": SECRET_PATH, "patch": SECRET_PATCH},
        )
    )
    assert forged_responses[0]["error"]["data"]["reason"] == "unknown_tool"


def test_ca3_stage_restore_remain_green_with_prepare_catalog(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    secret = Path(binding.workspace_root) / SECRET_PATH
    staged = json.loads(
        passthrough.handle_client_line(
            _semantic_line("ca3-stage", SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": SECRET_PATH})
        )[0]["result"]["content"][0]["text"]
    )
    assert staged["terminal_outcome"] == "COMPLETED_WITH_ALTERNATIVE"
    assert not secret.exists()
    qid = staged["quarantine_entry_id"]
    restored = json.loads(
        passthrough.handle_client_line(
            _semantic_line("ca3-restore", SEMANTIC_RESTORE_STAGED_TOOL_NAME, {"quarantine_entry_id": qid})
        )[0]["result"]["content"][0]["text"]
    )
    assert restored["mechanism_status"] == "success"
    assert secret.exists()
    listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        binding,
    )
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert SEMANTIC_PREPARE_PATCH_TOOL_NAME in names
    assert SEMANTIC_STAGE_DELETE_TOOL_NAME in names
    assert SEMANTIC_RESTORE_STAGED_TOOL_NAME in names
    assert SEMANTIC_CLEANUP_STAGED_TOOL_NAME in names
    assert SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME in names
    assert SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME not in names


def _assert_git_intent_denied_payload(body: dict[str, object]) -> None:
    assert body == {
        "mechanism_status": "error",
        "error_code": "git_intent_denied",
        "result_status": "denied",
        "decision": "denied",
        "target_reached": False,
        "rollback_available": False,
        "verification_level": "not_verified",
    }


def _assert_git_privacy(blob: str, binding: ControlledAlternativeRuntimeBinding) -> None:
    lowered = blob.lower()
    assert str(binding.workspace_root) not in blob
    assert str(binding.state_root) not in blob
    assert binding.route_id not in blob
    assert "/Users/" not in blob
    assert "/private/" not in blob
    assert "agentveil_private_policy" not in blob
    assert "approval_granted" not in blob
    assert "diff --git" not in lowered
    assert "origin/main" not in lowered
    assert SECRET_PATH not in blob
    assert SECRET_PATCH not in blob


def test_catalog_advertises_git_only_when_projected(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        binding,
    )
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME in names
    assert names.count(SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME) == 1
    assert SEMANTIC_GIT_OPERATION_TOOL_NAME in names
    assert names.count(SEMANTIC_GIT_OPERATION_TOOL_NAME) == 1
    git_schema = next(
        tool for tool in listed["result"]["tools"] if tool["name"] == SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME
    )
    git_operation = next(
        tool for tool in listed["result"]["tools"] if tool["name"] == SEMANTIC_GIT_OPERATION_TOOL_NAME
    )
    assert set(git_schema["inputSchema"]["required"]) == {"worktree_path"}
    assert set(git_schema["inputSchema"]["properties"]) == {"worktree_path", "intent"}
    assert set(git_operation["inputSchema"]["required"]) == {"worktree_path", "operation"}
    assert set(git_operation["inputSchema"]["properties"]) == {"worktree_path", "operation"}
    _assert_git_privacy(json.dumps(listed), binding)
    assert semantic_tool_is_projected(binding, SEMANTIC_GIT_OPERATION_TOOL_NAME)
    unprojected = replace(
        binding,
        semantic_schemas=tuple(
            schema
            for schema in binding.semantic_schemas
            if schema.get("name") not in {
                SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
                SEMANTIC_GIT_OPERATION_TOOL_NAME,
            }
        ),
    )
    assert semantic_tool_is_projected(binding, SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME)
    assert not semantic_tool_is_projected(unprojected, SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME)
    assert not semantic_tool_is_projected(unprojected, SEMANTIC_GIT_OPERATION_TOOL_NAME)
    omitted = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        unprojected,
    )
    assert SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME not in [
        tool["name"] for tool in omitted["result"]["tools"]
    ]
    assert SEMANTIC_GIT_OPERATION_TOOL_NAME not in [
        tool["name"] for tool in omitted["result"]["tools"]
    ]


def test_semantic_git_maps_trusted_locator_without_bounded_local_input(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.provider.git_ready = True
    result = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": GIT, "input": {"worktree_path": "."}},
        recheck=_ok_recheck(binding),
    )
    assert result["mechanism_status"] == "success"
    assert result["verification_level"] == "mechanism_verified"
    assert result["target_reached"] is False
    assert "terminal_outcome" not in result
    assert "prepared_artifact_ref" not in result
    assert "diff" not in json.dumps(result).lower()
    phases = [item for item in binding.provider.calls if item.startswith(("propose:", "execute:", "verify:"))]
    assert phases == [
        f"propose:{GIT}",
        f"execute:{GIT}",
        f"verify:{GIT}",
    ]
    request = binding.provider.requests[0]
    assert request.alternative_id == GIT
    assert request.action_family == "write"
    assert request.semantic_category == "git"
    assert request.resource_locator.locator_kind == "git_worktree"
    assert request.resource_locator.workspace_root == binding.workspace_root
    assert request.resource_locator.state_root == binding.state_root
    assert request.resource_locator.route_id == binding.route_id
    assert request.resource_locator.st_dev == binding.st_dev
    assert request.bounded_local_input is None
    _assert_git_privacy(f"{result!r}{result}{binding!r}{request!r}{request}", binding)


def test_semantic_git_passthrough_happy_path(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    binding.provider.git_ready = True
    forwarded = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line(
            "sem-git",
            SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
            {"worktree_path": "."},
        )
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert body["mechanism_status"] == "success"
    assert body["verification_level"] == "mechanism_verified"
    assert body["target_reached"] is False
    assert "terminal_outcome" not in body
    assert [item for item in binding.provider.calls if item.startswith(("propose:", "execute:", "verify:"))] == [
        f"propose:{GIT}",
        f"execute:{GIT}",
        f"verify:{GIT}",
    ]
    request = binding.provider.requests[0]
    assert request.resource_locator.locator_kind == "git_worktree"
    assert request.bounded_local_input is None
    _assert_git_privacy(json.dumps(responses) + f"{request!r}", binding)


def test_malformed_semantic_git_has_zero_approval_provider_downstream(tmp_path: Path) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    binding.provider.git_ready = True
    before_downstream = passthrough._downstream_tool_calls_forwarded
    cases = (
        {"worktree_path": ".", "extra": 1},
        {"worktree_path": "/tmp/repo"},
        {"worktree_path": "../repo"},
        {"worktree_path": r"C:\secret"},
        {"worktree_path": "C:/secret"},
        {"worktree_path": ".\n"},
        {"worktree_path": " . "},
        {"worktree_path": " repo"},
        {"worktree_path": "repo "},
        {"worktree_path": "\t."},
        {"worktree_path": ".\t"},
        {"worktree_path": 123},
        {"worktree_path": ".", "approval_granted": True},
        {"worktree_path": ".", "workspace_root": "/tmp"},
        {"path": "."},
        {},
    )
    for index, arguments in enumerate(cases):
        responses = passthrough.handle_client_line(
            _semantic_line(f"bad-git-{index}", SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME, arguments)
        )
        body = json.loads(responses[0]["result"]["content"][0]["text"])
        assert body["mechanism_status"] == "error"
        assert body["error_code"] in {"request_malformed", "result_unsafe"}
        _assert_git_privacy(json.dumps(responses), binding)
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == before_downstream


def test_git_prepare_for_review_intent_still_routes_without_provider_intent(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.provider.git_ready = True
    result = execute_controlled_alternative(
        binding=binding,
        arguments={
            "alternative_id": GIT,
            "input": {"worktree_path": ".", "intent": "prepare_for_review"},
        },
        recheck=_ok_recheck(binding),
    )
    assert result["mechanism_status"] == "success"
    assert result["target_reached"] is False
    request = binding.provider.requests[0]
    assert request.alternative_id == GIT
    assert request.bounded_local_input is None
    assert not hasattr(request, "intent")
    _assert_git_privacy(f"{result!r}{result}{request!r}{request}", binding)
    assert "prepare_for_review" not in f"{request!r}"


def test_git_commit_and_push_intents_fail_closed_before_approval_provider_downstream(
    tmp_path: Path,
) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    binding.provider.git_ready = True
    forwarded = passthrough._downstream_tool_calls_forwarded
    observe_binding, observe = _bound_passthrough(tmp_path)
    observe_binding.provider.git_ready = True
    observe_forwarded = observe._downstream_tool_calls_forwarded
    for index, intent in enumerate(("commit", "push")):
        execute_denied = execute_controlled_alternative(
            binding=binding,
            arguments={
                "alternative_id": GIT,
                "input": {"worktree_path": ".", "intent": intent},
            },
            recheck=_ok_recheck(binding),
        )
        _assert_git_intent_denied_payload(execute_denied)
        semantic = passthrough.handle_client_line(
            _semantic_line(
                f"git-int-sem-{index}",
                SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
                {"worktree_path": ".", "intent": intent},
            )
        )
        semantic_body = json.loads(semantic[0]["result"]["content"][0]["text"])
        _assert_git_intent_denied_payload(semantic_body)
        generic = observe.handle_client_line(
            _generic_line(f"git-int-gen-{index}", GIT, {"worktree_path": ".", "intent": intent})
        )
        generic_body = json.loads(generic[0]["result"]["content"][0]["text"])
        _assert_git_intent_denied_payload(generic_body)
        _assert_git_privacy(json.dumps(semantic) + json.dumps(generic), binding)
        assert "git_intent_denied" in semantic[0]["result"]["content"][0]["text"]
        assert generic_body["error_code"] != "request_malformed"
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert observe_binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert observe._downstream_tool_calls_forwarded == observe_forwarded


def test_git_operation_prepare_for_review_routes_existing_git_prepare(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    binding.provider.git_ready = True
    forwarded = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line(
            "git-op-prep",
            SEMANTIC_GIT_OPERATION_TOOL_NAME,
            {"worktree_path": ".", "operation": "prepare_for_review"},
        )
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "success"
    assert body["target_reached"] is False
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    request = binding.provider.requests[0]
    assert request.alternative_id == GIT
    assert request.bounded_local_input is None
    assert not hasattr(request, "operation")
    assert not hasattr(request, "intent")
    _assert_git_privacy(json.dumps(responses) + f"{request!r}", binding)
    assert "prepare_for_review" not in f"{request!r}"


def test_git_operation_commit_and_push_fail_closed_before_approval_provider_downstream(
    tmp_path: Path,
) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    binding.provider.git_ready = True
    forwarded = passthrough._downstream_tool_calls_forwarded
    for index, operation in enumerate(("commit", "push")):
        responses = passthrough.handle_client_line(
            _semantic_line(
                f"git-op-deny-{index}",
                SEMANTIC_GIT_OPERATION_TOOL_NAME,
                {"worktree_path": ".", "operation": operation},
            )
        )
        body = json.loads(responses[0]["result"]["content"][0]["text"])
        _assert_git_intent_denied_payload(body)
        _assert_git_privacy(json.dumps(responses), binding)
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == forwarded


def test_malformed_git_operation_stays_malformed_not_structured_deny(tmp_path: Path) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    binding.provider.git_ready = True
    forwarded = passthrough._downstream_tool_calls_forwarded
    cases = (
        {"worktree_path": ".", "operation": "rebase"},
        {"worktree_path": ".", "operation": "COMMIT"},
        {"worktree_path": ".", "operation": " commit"},
        {"worktree_path": ".", "operation": 123},
        {"worktree_path": "."},
    )
    for index, arguments in enumerate(cases):
        responses = passthrough.handle_client_line(
            _semantic_line(
                f"bad-git-op-{index}",
                SEMANTIC_GIT_OPERATION_TOOL_NAME,
                arguments,
            )
        )
        body = json.loads(responses[0]["result"]["content"][0]["text"])
        assert body["mechanism_status"] == "error"
        assert body["error_code"] in {"request_malformed", "result_unsafe"}
        assert body["error_code"] != "git_intent_denied"
        assert body.get("result_status") != "denied"
        assert "decision" not in body
        _assert_git_privacy(json.dumps(responses), binding)
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == forwarded


def test_malformed_git_intent_stays_malformed_not_structured_deny(tmp_path: Path) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    binding.provider.git_ready = True
    forwarded = passthrough._downstream_tool_calls_forwarded
    cases = (
        {"worktree_path": ".", "intent": "rebase"},
        {"worktree_path": ".", "intent": "COMMIT"},
        {"worktree_path": ".", "intent": " commit"},
        {"worktree_path": ".", "intent": 123},
    )
    for index, arguments in enumerate(cases):
        responses = passthrough.handle_client_line(
            _semantic_line(f"bad-git-intent-{index}", SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME, arguments)
        )
        body = json.loads(responses[0]["result"]["content"][0]["text"])
        assert body["mechanism_status"] == "error"
        assert body["error_code"] in {"request_malformed", "result_unsafe"}
        assert body["error_code"] != "git_intent_denied"
        assert body.get("result_status") != "denied"
        assert "decision" not in body
        _assert_git_privacy(json.dumps(responses), binding)
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == forwarded


def test_unprojected_and_forged_semantic_git_never_reach_provider(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    binding.provider.git_ready = True
    passthrough._tool_schemas.update_from_response(
        {
            "result": {
                "tools": [
                    schema
                    for schema in binding.semantic_schemas
                    if schema.get("name") != SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME
                ]
            }
        }
    )
    projected = replace(
        binding,
        semantic_schemas=tuple(
            schema
            for schema in binding.semantic_schemas
            if schema.get("name") != SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME
        ),
    )
    passthrough.controlled_runtime = projected
    responses = passthrough.handle_client_line(
        _semantic_line(
            "unproj-git",
            SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
            {"worktree_path": "."},
        )
    )
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"
    assert projected.provider.calls == []
    forged = McpPassthrough(DownstreamConfig(command="python", args=(), name="plain"))
    forged._tool_schemas.update_from_response({"result": {"tools": [{"name": "read_file"}]}})
    forged_responses = forged.handle_client_line(
        _semantic_line("forge-git", SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME, {"worktree_path": "."})
    )
    assert forged_responses[0]["error"]["data"]["reason"] == "unknown_tool"


def test_semantic_git_unavailable_has_zero_execute(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    result = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": GIT, "input": {"worktree_path": "."}},
    )
    assert result["mechanism_status"] == "unavailable"
    assert [item.split(":", 1)[0] for item in binding.provider.calls if item.startswith(("propose", "execute", "verify")) and "git." in item] == ["propose"]
    assert not any(item.startswith("execute:git.") for item in binding.provider.calls)
    _assert_git_privacy(f"{result!r}{result}", binding)


def test_semantic_git_protect_mode_has_zero_provider_calls(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect")
    binding.provider.git_ready = True
    before = list(binding.provider.calls)
    responses = passthrough.handle_client_line(
        _semantic_line("git-protect", SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME, {"worktree_path": "."})
    )
    assert "error" in responses[0]
    assert responses[0]["error"]["data"]["reason"] == "runtime_gate_not_configured"
    assert binding.provider.calls == before


def test_semantic_git_denied_never_reaches_provider(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalStatus

    deny = _DecisionManager(ApprovalStatus.DENIED.value)
    denied_binding, denied_pt = _bound_passthrough(tmp_path, mode="protect", approval_manager=deny)
    denied_binding.provider.git_ready = True
    denied = denied_pt.handle_client_line(
        _semantic_line("git-deny", SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME, {"worktree_path": "."})
    )
    assert "error" in denied[0]
    assert not any(item.startswith("propose:") for item in denied_binding.provider.calls)


def test_semantic_git_recheck_drift_blocks_execute(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.provider.git_ready = True
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

    result = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": GIT, "input": {"worktree_path": "."}},
        recheck=recheck,
    )
    assert post_propose["count"] == 1
    assert result["mechanism_status"] == "error"
    assert not any(item.startswith("execute:") for item in binding.provider.calls)


def _assert_apply_privacy(blob: str, binding: ControlledAlternativeRuntimeBinding) -> None:
    assert SECRET_PATCH not in blob
    assert "*** Begin Patch" not in blob
    assert str(binding.workspace_root) not in blob
    assert str(binding.state_root) not in blob
    assert binding.route_id not in blob
    assert "/Users/" not in blob
    assert "agentveil_private_policy" not in blob
    assert "approval_granted" not in blob
    assert SECRET_PATH not in blob


def test_catalog_advertises_apply_only_when_apply_id_present(tmp_path: Path) -> None:
    old_binding = _binding(tmp_path)
    old_listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        old_binding,
    )
    old_names = [tool["name"] for tool in old_listed["result"]["tools"]]
    assert SEMANTIC_PREPARE_PATCH_TOOL_NAME in old_names
    assert SEMANTIC_STAGE_DELETE_TOOL_NAME in old_names
    assert SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME not in old_names
    binding = _apply_binding(tmp_path)
    listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        binding,
    )
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME in names
    assert names.count(SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME) == 1
    assert SEMANTIC_PREPARE_PATCH_TOOL_NAME in names
    assert SEMANTIC_STAGE_DELETE_TOOL_NAME in names
    assert semantic_tool_is_projected(binding, SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME)
    assert not semantic_tool_is_projected(old_binding, SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME)


def test_apply_policy_is_ordinary_write_not_cleanup() -> None:
    evaluation = PolicyEvaluation(
        decision=PolicyDecision.ASK_BACKEND,
        risk_class=RiskClass.UNKNOWN,
        policy_id="default",
        policy_rule_id="default",
        policy_context_hash="sha256:" + ("11" * 32),
        matched_rule_ids=(),
    )
    coerced, risk, family = apply_controlled_alternative_policy(
        alternative_id=APPLY,
        evaluation=evaluation,
        action_family="unknown",
    )
    assert coerced.decision is PolicyDecision.ASK_BACKEND
    assert risk is RiskClass.WRITE
    assert family == "write"
    allow = apply_controlled_alternative_policy(
        alternative_id=APPLY,
        evaluation=replace_decision(evaluation, PolicyDecision.ALLOW),
        action_family="unknown",
    )[0]
    assert allow.decision is PolicyDecision.ALLOW


def test_semantic_apply_maps_trusted_locator_and_does_not_mutate_target(tmp_path: Path) -> None:
    binding = _apply_binding(tmp_path)
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = secret.read_text(encoding="utf-8")
    result = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": APPLY, "input": _apply_input()},
        recheck=_ok_recheck(binding),
    )
    assert result["mechanism_status"] == "success"
    assert result["verification_level"] == "mechanism_verified"
    assert result["target_reached"] is False
    assert "terminal_outcome" not in result
    assert "prepared_artifact_ref" not in result
    assert "prepared_artifact_hash" not in result
    assert secret.read_text(encoding="utf-8") == before
    assert secret.exists()
    phases = [item for item in binding.provider.calls if item.startswith(("propose:", "execute:", "verify:"))]
    assert phases == [
        f"propose:{APPLY}",
        f"execute:{APPLY}",
        f"verify:{APPLY}",
    ]
    request = binding.provider.requests[0]
    assert request.alternative_id == APPLY
    assert request.action_family == "write"
    assert request.semantic_category == "filesystem"
    assert request.resource_locator.locator_kind == "prepared_write_artifact"
    assert request.resource_locator.normalized_path is None
    assert request.resource_locator.workspace_root == binding.workspace_root
    assert request.resource_locator.state_root == binding.state_root
    assert request.resource_locator.route_id == binding.route_id
    assert request.resource_locator.st_dev == binding.st_dev
    assert request.bounded_local_input is not None
    assert request.bounded_local_input.prepared_artifact_ref == PREPARED_REF
    assert request.bounded_local_input.prepared_artifact_hash == PREPARED_HASH
    assert request.bounded_local_input.patch is None
    _assert_apply_privacy(f"{result!r}{result}{binding!r}{request!r}{request}", binding)


def test_semantic_apply_passthrough_happy_path(tmp_path: Path) -> None:
    binding, passthrough = _apply_bound_passthrough(tmp_path)
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = secret.read_text(encoding="utf-8")
    forwarded = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line("sem-apply", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, _apply_input())
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert body["mechanism_status"] == "success"
    assert body["target_reached"] is False
    assert "terminal_outcome" not in body
    assert "prepared_artifact_ref" not in body
    assert secret.read_text(encoding="utf-8") == before
    assert [item for item in binding.provider.calls if item.startswith(("propose:", "execute:", "verify:"))] == [
        f"propose:{APPLY}",
        f"execute:{APPLY}",
        f"verify:{APPLY}",
    ]
    _assert_apply_privacy(json.dumps(responses), binding)


def test_malformed_semantic_apply_has_zero_approval_provider_downstream(tmp_path: Path) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _apply_bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    before_downstream = passthrough._downstream_tool_calls_forwarded
    cases = (
        {**_apply_input(), "extra": 1},
        {**_apply_input(), "path": SECRET_PATH},
        {**_apply_input(), "patch": SECRET_PATCH},
        {**_apply_input(), "workspace_root": "/tmp"},
        {**_apply_input(), "state_root": "/tmp"},
        {**_apply_input(), "route_id": "r1"},
        {**_apply_input(), "approval_granted": True},
        {**_apply_input(), "allow": True},
        {"prepared_artifact_ref": "/tmp/artifact", "prepared_artifact_hash": PREPARED_HASH},
        {"prepared_artifact_ref": "../artifact", "prepared_artifact_hash": PREPARED_HASH},
        {"prepared_artifact_ref": r"C:\artifact", "prepared_artifact_hash": PREPARED_HASH},
        {"prepared_artifact_ref": "allow", "prepared_artifact_hash": PREPARED_HASH},
        {"prepared_artifact_ref": PREPARED_REF, "prepared_artifact_hash": "AB" * 32},
        {"prepared_artifact_ref": PREPARED_REF},
        {"prepared_artifact_hash": PREPARED_HASH},
        {},
    )
    for index, arguments in enumerate(cases):
        responses = passthrough.handle_client_line(
            _semantic_line(f"bad-apply-{index}", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, arguments)
        )
        body = json.loads(responses[0]["result"]["content"][0]["text"])
        assert body["mechanism_status"] == "error"
        assert body["error_code"] == "request_malformed"
        _assert_apply_privacy(json.dumps(responses), binding)
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == before_downstream


def test_apply_protect_mode_has_zero_provider_calls(tmp_path: Path) -> None:
    binding, passthrough = _apply_bound_passthrough(tmp_path, mode="protect")
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = list(binding.provider.calls)
    responses = passthrough.handle_client_line(
        _semantic_line("apply-protect", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, _apply_input())
    )
    assert "error" in responses[0]
    assert responses[0]["error"]["data"]["reason"] == "runtime_gate_not_configured"
    assert binding.provider.calls == before
    assert secret.exists()


def test_apply_denied_stale_and_mismatched_approval_never_reach_provider(tmp_path: Path) -> None:
    from agentveil_mcp_proxy.evidence import ApprovalStatus

    deny = _DecisionManager(ApprovalStatus.DENIED.value)
    denied_binding, denied_pt = _apply_bound_passthrough(tmp_path, mode="protect", approval_manager=deny)
    denied = denied_pt.handle_client_line(
        _semantic_line("apply-deny", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, _apply_input())
    )
    assert "error" in denied[0]
    assert not any(item.startswith("propose:") for item in denied_binding.provider.calls)

    stale = _DecisionManager("expired")
    stale_binding, stale_pt = _apply_bound_passthrough(tmp_path, mode="protect", approval_manager=stale)
    timed = stale_pt.handle_client_line(
        _semantic_line("apply-stale", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, _apply_input())
    )
    assert "error" in timed[0]
    assert not any(item.startswith("propose:") for item in stale_binding.provider.calls)

    mismatched = _DecisionManager(ApprovalStatus.APPROVED.value, bind=True)
    mismatch_binding, mismatch_pt = _apply_bound_passthrough(
        tmp_path, mode="protect", approval_manager=mismatched
    )
    mismatched_resp = mismatch_pt.handle_client_line(
        _semantic_line("apply-mismatch", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, _apply_input())
    )
    assert "error" in mismatched_resp[0]
    assert not any(item.startswith("propose:") for item in mismatch_binding.provider.calls)


def test_apply_recheck_drift_blocks_execute(tmp_path: Path) -> None:
    binding = _apply_binding(tmp_path)
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
        arguments={"alternative_id": APPLY, "input": _apply_input()},
        recheck=recheck,
    )
    assert post_propose["count"] == 1
    assert result["mechanism_status"] == "error"
    assert not any(item.startswith("execute:") for item in binding.provider.calls)
    assert secret.exists()


def test_apply_session_drift_after_propose_has_zero_execute(tmp_path: Path) -> None:
    manager = _DecisionManager("approved")
    binding, passthrough = _apply_bound_passthrough(tmp_path, approval_manager=manager)
    original_propose = binding.provider.propose

    def drifting_propose(request):
        result = original_propose(request)
        manager.session_id = "sess-changed"
        return result

    binding.provider.propose = drifting_propose
    secret = Path(binding.workspace_root) / SECRET_PATH
    responses = passthrough.handle_client_line(
        _semantic_line("apply-sess", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, _apply_input())
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "error"
    assert not any(item.startswith("execute:") for item in binding.provider.calls)
    assert secret.exists()


def test_unprojected_and_forged_semantic_apply_never_reach_provider(tmp_path: Path) -> None:
    binding, passthrough = _apply_bound_passthrough(tmp_path)
    passthrough._tool_schemas.update_from_response(
        {
            "result": {
                "tools": [
                    schema
                    for schema in binding.semantic_schemas
                    if schema.get("name") != SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME
                ]
            }
        }
    )
    projected = replace(
        binding,
        semantic_schemas=tuple(
            schema
            for schema in binding.semantic_schemas
            if schema.get("name") != SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME
        ),
    )
    passthrough.controlled_runtime = projected
    responses = passthrough.handle_client_line(
        _semantic_line("unproj-apply", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, _apply_input())
    )
    assert responses[0]["error"]["data"]["reason"] == "unknown_tool"
    assert projected.provider.calls == []
    forged = McpPassthrough(DownstreamConfig(command="python", args=(), name="plain"))
    forged._tool_schemas.update_from_response({"result": {"tools": [{"name": "read_file"}]}})
    forged_responses = forged.handle_client_line(
        _semantic_line("forge-apply", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, _apply_input())
    )
    assert forged_responses[0]["error"]["data"]["reason"] == "unknown_tool"


def test_ca3_and_prepare_remain_green_with_apply_catalog(tmp_path: Path) -> None:
    binding, passthrough = _apply_bound_passthrough(tmp_path)
    secret = Path(binding.workspace_root) / SECRET_PATH
    staged = json.loads(
        passthrough.handle_client_line(
            _semantic_line("ca4-stage", SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": SECRET_PATH})
        )[0]["result"]["content"][0]["text"]
    )
    assert staged["terminal_outcome"] == "COMPLETED_WITH_ALTERNATIVE"
    qid = staged["quarantine_entry_id"]
    restored = json.loads(
        passthrough.handle_client_line(
            _semantic_line("ca4-restore", SEMANTIC_RESTORE_STAGED_TOOL_NAME, {"quarantine_entry_id": qid})
        )[0]["result"]["content"][0]["text"]
    )
    assert restored["mechanism_status"] == "success"
    assert secret.exists()
    prepared = json.loads(
        passthrough.handle_client_line(
            _semantic_line(
                "ca4-prep",
                SEMANTIC_PREPARE_PATCH_TOOL_NAME,
                {"path": SECRET_PATH, "patch": SECRET_PATCH},
            )
        )[0]["result"]["content"][0]["text"]
    )
    assert prepared["prepared_artifact_ref"] == PREPARED_REF
    assert secret.read_text(encoding="utf-8") == "secret-bytes"
    applied = json.loads(
        passthrough.handle_client_line(
            _semantic_line("ca4-apply", SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME, _apply_input())
        )[0]["result"]["content"][0]["text"]
    )
    assert applied["mechanism_status"] == "success"
    assert secret.read_text(encoding="utf-8") == "secret-bytes"
    listed = inject_controlled_alternative_tool(
        {"result": {"tools": [{"name": "read_file"}]}},
        binding,
    )
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME in names
    assert SEMANTIC_PREPARE_PATCH_TOOL_NAME in names
    assert SEMANTIC_STAGE_DELETE_TOOL_NAME in names


UNSAFE_DELETE_PATH = "secrets.env"
UNSAFE_WRITE_PATH = "locked_config.yaml"
UNSAFE_DELETE_BYTES = "token=do-not-copy\n"
UNSAFE_WRITE_BYTES = "lock: true\n"


def _plant_unsafe_targets(binding: ControlledAlternativeRuntimeBinding) -> tuple[Path, Path]:
    workspace = Path(binding.workspace_root)
    deleted = workspace / UNSAFE_DELETE_PATH
    locked = workspace / UNSAFE_WRITE_PATH
    deleted.write_text(UNSAFE_DELETE_BYTES, encoding="utf-8")
    locked.write_text(UNSAFE_WRITE_BYTES, encoding="utf-8")
    return deleted, locked


def _assert_unsafe_denied_payload(payload: dict, *, blob: str, binding: ControlledAlternativeRuntimeBinding) -> None:
    assert payload["mechanism_status"] == "error"
    assert payload["error_code"] == "request_malformed"
    assert payload["target_reached"] is False
    assert payload["rollback_available"] is False
    assert "quarantine_entry_id" not in payload
    assert "prepared_artifact_ref" not in payload
    assert "prepared_artifact_hash" not in payload
    assert "terminal_outcome" not in payload
    assert UNSAFE_DELETE_PATH not in blob
    assert UNSAFE_WRITE_PATH not in blob
    assert UNSAFE_DELETE_BYTES not in blob
    assert UNSAFE_WRITE_BYTES not in blob
    _assert_no_locator_canaries(blob, binding)


def test_unsafe_stage_delete_execute_has_zero_provider_and_leaves_target(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    deleted, _locked = _plant_unsafe_targets(binding)
    result = execute_controlled_alternative(
        binding=binding,
        arguments={"alternative_id": STAGE, "input": {"path": UNSAFE_DELETE_PATH}},
        recheck=_ok_recheck(binding),
    )
    _assert_unsafe_denied_payload(result, blob=f"{result!r}", binding=binding)
    assert deleted.read_text(encoding="utf-8") == UNSAFE_DELETE_BYTES
    assert binding.provider.calls == []


def test_unsafe_prepare_execute_has_zero_provider_and_leaves_target(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    _deleted, locked = _plant_unsafe_targets(binding)
    result = execute_controlled_alternative(
        binding=binding,
        arguments={
            "alternative_id": PREPARE,
            "input": {"path": UNSAFE_WRITE_PATH, "patch": SECRET_PATCH},
        },
        recheck=_ok_recheck(binding),
    )
    _assert_unsafe_denied_payload(result, blob=f"{result!r}{SECRET_PATCH}", binding=binding)
    assert locked.read_text(encoding="utf-8") == UNSAFE_WRITE_BYTES
    assert binding.provider.calls == []


def test_unsafe_semantic_and_generic_stage_delete_fail_close_before_approval(
    tmp_path: Path,
) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    deleted, _locked = _plant_unsafe_targets(binding)
    forwarded = passthrough._downstream_tool_calls_forwarded
    semantic = passthrough.handle_client_line(
        _semantic_line("unsafe-sem-del", SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": UNSAFE_DELETE_PATH})
    )
    semantic_body = json.loads(semantic[0]["result"]["content"][0]["text"])
    _assert_unsafe_denied_payload(semantic_body, blob=json.dumps(semantic), binding=binding)
    observe_binding, observe = _bound_passthrough(tmp_path)
    observe_deleted, _observe_locked = _plant_unsafe_targets(observe_binding)
    observe_forwarded = observe._downstream_tool_calls_forwarded
    generic = observe.handle_client_line(
        _generic_line("unsafe-gen-del", STAGE, {"path": UNSAFE_DELETE_PATH})
    )
    generic_body = json.loads(generic[0]["result"]["content"][0]["text"])
    _assert_unsafe_denied_payload(generic_body, blob=json.dumps(generic), binding=observe_binding)
    assert deleted.read_text(encoding="utf-8") == UNSAFE_DELETE_BYTES
    assert observe_deleted.read_text(encoding="utf-8") == UNSAFE_DELETE_BYTES
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert observe_binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert observe._downstream_tool_calls_forwarded == observe_forwarded


def test_unsafe_semantic_and_generic_prepare_fail_close_before_approval(tmp_path: Path) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    _deleted, locked = _plant_unsafe_targets(binding)
    forwarded = passthrough._downstream_tool_calls_forwarded
    semantic = passthrough.handle_client_line(
        _semantic_line(
            "unsafe-sem-prep",
            SEMANTIC_PREPARE_PATCH_TOOL_NAME,
            {"path": UNSAFE_WRITE_PATH, "patch": SECRET_PATCH},
        )
    )
    semantic_body = json.loads(semantic[0]["result"]["content"][0]["text"])
    _assert_unsafe_denied_payload(semantic_body, blob=json.dumps(semantic), binding=binding)
    observe_binding, observe = _bound_passthrough(tmp_path)
    _observe_deleted, observe_locked = _plant_unsafe_targets(observe_binding)
    observe_forwarded = observe._downstream_tool_calls_forwarded
    generic = observe.handle_client_line(
        _generic_line("unsafe-gen-prep", PREPARE, {"path": UNSAFE_WRITE_PATH, "patch": SECRET_PATCH})
    )
    generic_body = json.loads(generic[0]["result"]["content"][0]["text"])
    _assert_unsafe_denied_payload(generic_body, blob=json.dumps(generic), binding=observe_binding)
    assert locked.read_text(encoding="utf-8") == UNSAFE_WRITE_BYTES
    assert observe_locked.read_text(encoding="utf-8") == UNSAFE_WRITE_BYTES
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert observe_binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert observe._downstream_tool_calls_forwarded == observe_forwarded


@pytest.mark.parametrize(
    "path",
    [".env", ".env.local", "id_rsa", "credentials.json", "tls.pem", "nested/secrets.env"],
)
def test_adversarial_secret_stage_delete_variants_fail_close(tmp_path: Path, path: str) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    target = Path(binding.workspace_root, path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("keep\n", encoding="utf-8")
    forwarded = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line("adv-del", SEMANTIC_STAGE_DELETE_TOOL_NAME, {"path": path})
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["error_code"] == "request_malformed"
    assert body["target_reached"] is False
    assert target.read_text(encoding="utf-8") == "keep\n"
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert path not in responses[0]["result"]["content"][0]["text"]


def test_observe_unsafe_targets_do_not_become_safe_alternatives(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    deleted, locked = _plant_unsafe_targets(binding)
    forwarded = passthrough._downstream_tool_calls_forwarded
    stage = json.loads(
        passthrough.handle_client_line(
            _generic_line("obs-del", STAGE, {"path": UNSAFE_DELETE_PATH})
        )[0]["result"]["content"][0]["text"]
    )
    prepare = json.loads(
        passthrough.handle_client_line(
            _generic_line("obs-prep", PREPARE, {"path": UNSAFE_WRITE_PATH, "patch": SECRET_PATCH})
        )[0]["result"]["content"][0]["text"]
    )
    assert stage["error_code"] == "request_malformed"
    assert prepare["error_code"] == "request_malformed"
    assert deleted.exists()
    assert locked.read_text(encoding="utf-8") == UNSAFE_WRITE_BYTES
    assert binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == forwarded


ADD_FILE_PATCH = "*** Begin Patch\n*** Add File: created.txt\n+hello\n*** End Patch"
UPDATE_FILE_PATCH = "*** Begin Patch\n*** Update File: secret.txt\n*** End Patch"


def test_add_file_prepare_fails_closed_before_approval_provider_downstream(tmp_path: Path) -> None:
    manager = _DecisionManager("pending")
    binding, passthrough = _bound_passthrough(tmp_path, mode="protect", approval_manager=manager)
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = secret.read_text(encoding="utf-8")
    forwarded = passthrough._downstream_tool_calls_forwarded
    semantic = passthrough.handle_client_line(
        _semantic_line(
            "create-sem",
            SEMANTIC_PREPARE_PATCH_TOOL_NAME,
            {"path": "created.txt", "patch": ADD_FILE_PATCH},
        )
    )
    semantic_body = json.loads(semantic[0]["result"]["content"][0]["text"])
    assert semantic_body["error_code"] == "request_malformed"
    assert semantic_body["target_reached"] is False
    assert "prepared_artifact_ref" not in semantic_body
    observe_binding, observe = _bound_passthrough(tmp_path)
    observe_secret = Path(observe_binding.workspace_root) / SECRET_PATH
    observe_before = observe_secret.read_text(encoding="utf-8")
    observe_forwarded = observe._downstream_tool_calls_forwarded
    generic = observe.handle_client_line(
        _generic_line("create-gen", PREPARE, {"path": "created.txt", "patch": ADD_FILE_PATCH})
    )
    generic_body = json.loads(generic[0]["result"]["content"][0]["text"])
    assert generic_body["error_code"] == "request_malformed"
    assert generic_body["target_reached"] is False
    assert "prepared_artifact_ref" not in generic_body
    assert secret.read_text(encoding="utf-8") == before
    assert observe_secret.read_text(encoding="utf-8") == observe_before
    assert not (Path(binding.workspace_root) / "created.txt").exists()
    assert not (Path(observe_binding.workspace_root) / "created.txt").exists()
    assert manager.requests == 0
    assert binding.provider.calls == []
    assert observe_binding.provider.calls == []
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert observe._downstream_tool_calls_forwarded == observe_forwarded
    assert "created.txt" not in semantic[0]["result"]["content"][0]["text"]
    assert ADD_FILE_PATCH not in json.dumps(semantic)
    assert ADD_FILE_PATCH not in json.dumps(generic)


def test_existing_file_update_prepare_still_routes(tmp_path: Path) -> None:
    binding, passthrough = _bound_passthrough(tmp_path)
    secret = Path(binding.workspace_root) / SECRET_PATH
    before = secret.read_text(encoding="utf-8")
    forwarded = passthrough._downstream_tool_calls_forwarded
    responses = passthrough.handle_client_line(
        _semantic_line(
            "update-prep",
            SEMANTIC_PREPARE_PATCH_TOOL_NAME,
            {"path": SECRET_PATH, "patch": UPDATE_FILE_PATCH},
        )
    )
    body = json.loads(responses[0]["result"]["content"][0]["text"])
    assert body["mechanism_status"] == "success"
    assert body["prepared_artifact_ref"] == PREPARED_REF
    assert body["prepared_artifact_hash"] == PREPARED_HASH
    assert secret.read_text(encoding="utf-8") == before
    assert passthrough._downstream_tool_calls_forwarded == forwarded
    assert [item for item in binding.provider.calls if item.startswith(("propose:", "execute:", "verify:"))] == [
        f"propose:{PREPARE}",
        f"execute:{PREPARE}",
        f"verify:{PREPARE}",
    ]
