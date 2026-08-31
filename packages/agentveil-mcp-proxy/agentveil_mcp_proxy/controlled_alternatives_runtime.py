# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Public Controlled Alternatives runtime adapter (CA3).

Binds a cached installed provider plus trusted roots at startup and executes
the local generic tool after ordinary policy/authority. The generic tool is not forwarded downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Callable, Mapping

from agentveil_mcp_proxy.client_config import downstream_startup_fingerprint
from agentveil_mcp_proxy.client_guidance import trusted_project_workspace_root_from_downstream
from agentveil_mcp_proxy.controlled_alternatives import (
    CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
    CONTROLLED_ALTERNATIVES_PROFILE_ID,
    ERROR_REQUEST_MALFORMED,
    GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
    RESERVED_CONTROLLED_ALTERNATIVE_TOOL_NAMES,
    ControlledAlternativeProvider,
    ControlledAlternativeProviderResult,
    ControlledAlternativeValidationError,
    build_controlled_alternative_tool_schema,
    build_semantic_controlled_alternative_tool_schemas,
    discover_controlled_alternative_provider,
    is_semantic_controlled_alternative_tool,
    normalize_semantic_tool_call,
    semantic_alternative_id_for_tool,
    validate_controlled_alternative_local_input,
    validate_provider_request,
    validate_provider_result,
)
from agentveil_mcp_proxy.paid_provider import PaidProviderSnapshot, discover_paid_provider
from agentveil_mcp_proxy.policy import PolicyDecision, PolicyEvaluation, RiskClass
from agentveil_mcp_proxy.role_doctor import (
    canonical_project_workspace_root_hash,
    project_scope_fingerprint,
)

_HEX32 = frozenset("0123456789abcdef")
_STAGE_DELETE = "filesystem.stage_delete.v1"
_RESTORE = "filesystem.restore_staged.v1"
_CLEANUP = "filesystem.cleanup_staged.v1"
_WRITE_ALTERNATIVES = frozenset({_STAGE_DELETE, _RESTORE})
_JSONRPC_VERSION = "2.0"


class ControlledAlternativeExecutionAbort(Exception):
    """Stop before provider execute after successful propose and re-check."""

    def __init__(self, abort_response: Any = None) -> None:
        self.abort_response = abort_response
        super().__init__()


@dataclass(frozen=True)
class ControlledAlternativeRuntimeBinding:
    """Process-lifetime local binding for one compatible installed provider."""

    provider: ControlledAlternativeProvider = field(repr=False, compare=False)
    descriptor: Any = field(repr=False)
    schema: dict[str, Any]
    workspace_root: str = field(repr=False)
    state_root: str = field(repr=False)
    route_id: str = field(repr=False)
    st_dev: int = field(repr=False)
    semantic_schemas: tuple[dict[str, Any], ...] = ()


def bind_controlled_alternative_runtime(
    *,
    home: Path,
    downstream: Mapping[str, Any],
    paid_snapshot: PaidProviderSnapshot | None = None,
) -> ControlledAlternativeRuntimeBinding | None:
    """Return a cached runtime binding, or None when the tool must stay hidden."""

    try:
        snapshot = paid_snapshot if paid_snapshot is not None else discover_paid_provider()
        discovered = discover_controlled_alternative_provider(snapshot)
        if not discovered.available or discovered.descriptor is None or discovered.provider is None:
            return None
        workspace = trusted_project_workspace_root_from_downstream(dict(downstream))
        if workspace is None:
            return None
        workspace_root = _canonical_existing_dir(workspace)
        state_root = _canonical_existing_dir(Path(home))
        if workspace_root is None or state_root is None:
            return None
        if not _path_is_inside(state_root, workspace_root, strict=True):
            return None
        workspace_stat = os.stat(workspace_root)
        state_stat = os.stat(state_root)
        if workspace_stat.st_dev != state_stat.st_dev:
            return None
        startup = downstream_startup_fingerprint(dict(downstream))
        workspace_hash = canonical_project_workspace_root_hash(Path(workspace_root))
        server = downstream.get("name")
        if not isinstance(server, str) or not server.strip() or startup is None or workspace_hash is None:
            return None
        route_id = project_scope_fingerprint(
            downstream_server=server.strip(),
            downstream_startup_fingerprint=startup,
            project_workspace_root_hash=workspace_hash,
        )
        if not isinstance(route_id, str) or not route_id:
            return None
        schema = build_controlled_alternative_tool_schema(discovered.descriptor)
        semantic_schemas = build_semantic_controlled_alternative_tool_schemas(discovered.descriptor)
        return ControlledAlternativeRuntimeBinding(
            provider=discovered.provider,
            descriptor=discovered.descriptor,
            schema=schema,
            semantic_schemas=semantic_schemas,
            workspace_root=workspace_root,
            state_root=state_root,
            route_id=route_id,
            st_dev=int(workspace_stat.st_dev),
        )
    except Exception:
        return None


def controlled_alternative_catalog_collision(response: Any) -> bool:
    """Return True when downstream already advertises a reserved controlled tool name."""

    if not isinstance(response, dict):
        return False
    result = response.get("result")
    if not isinstance(result, Mapping):
        return False
    tools = result.get("tools")
    if not isinstance(tools, list):
        return False
    return any(
        isinstance(tool, Mapping)
        and tool.get("name") in RESERVED_CONTROLLED_ALTERNATIVE_TOOL_NAMES
        for tool in tools
    )


def inject_controlled_alternative_tool(
    response: Any,
    binding: ControlledAlternativeRuntimeBinding | None,
) -> Any:
    """Append generic and semantic controlled tools to a tools/list-shaped response."""

    if binding is None or not isinstance(response, dict):
        return response
    if controlled_alternative_catalog_collision(response):
        return response
    result = response.get("result")
    if not isinstance(result, Mapping):
        return response
    tools = result.get("tools")
    if not isinstance(tools, list):
        return response
    names = {
        tool.get("name")
        for tool in tools
        if isinstance(tool, Mapping) and isinstance(tool.get("name"), str)
    }
    additions = [dict(binding.schema), *[dict(schema) for schema in binding.semantic_schemas]]
    appended = list(tools)
    for schema in additions:
        name = schema.get("name")
        if not isinstance(name, str) or name in names:
            continue
        appended.append(schema)
        names.add(name)
    if appended == tools:
        return response
    injected = dict(response)
    injected_result = dict(result)
    injected_result["tools"] = appended
    injected["result"] = injected_result
    return injected


def alternative_id_from_arguments(arguments: Mapping[str, Any] | None) -> str | None:
    if not isinstance(arguments, Mapping):
        return None
    value = arguments.get("alternative_id")
    return value if isinstance(value, str) and value else None


def alternative_id_from_tool_call(tool_name: str, arguments: Mapping[str, Any] | None) -> str | None:
    if tool_name == GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME:
        return alternative_id_from_arguments(arguments)
    if is_semantic_controlled_alternative_tool(tool_name):
        return semantic_alternative_id_for_tool(tool_name)
    return None


def normalize_controlled_alternative_arguments(
    tool_name: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    if tool_name == GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME:
        if not isinstance(arguments, Mapping):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        return dict(arguments)
    if is_semantic_controlled_alternative_tool(tool_name):
        return normalize_semantic_tool_call(tool_name, arguments)
    raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)


def semantic_resource_label(tool_name: str, arguments: Mapping[str, Any]) -> str | None:
    if not is_semantic_controlled_alternative_tool(tool_name):
        return None
    for key in ("path", "quarantine_entry_id", "worktree_path"):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return f"{key}:redacted"
    return None


def semantic_resource_exact(tool_name: str, arguments: Mapping[str, Any]) -> str | None:
    if not is_semantic_controlled_alternative_tool(tool_name):
        return None
    for key in ("path", "quarantine_entry_id", "worktree_path"):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return f"{key}:{value}"
    return None


def semantic_tool_is_projected(
    binding: ControlledAlternativeRuntimeBinding,
    tool_name: str,
) -> bool:
    if not is_semantic_controlled_alternative_tool(tool_name):
        return False
    return any(
        isinstance(schema.get("name"), str) and schema.get("name") == tool_name
        for schema in binding.semantic_schemas
    )


def nested_resource_exact(arguments: Mapping[str, Any]) -> str | None:
    """Return `key:exact-locator` for hashing only, not for display, repr, or export."""

    nested = arguments.get("input")
    if not isinstance(nested, Mapping):
        return None
    for key in ("path", "quarantine_entry_id", "worktree_path"):
        value = nested.get(key)
        if isinstance(value, str) and value:
            return f"{key}:{value}"
    return None


def nested_resource_label(arguments: Mapping[str, Any]) -> str | None:
    nested = arguments.get("input")
    if not isinstance(nested, Mapping):
        return None
    for key in ("path", "quarantine_entry_id", "worktree_path"):
        value = nested.get(key)
        if isinstance(value, str) and value:
            return f"{key}:redacted"
    return None


def apply_controlled_alternative_policy(
    *,
    alternative_id: str | None,
    evaluation: PolicyEvaluation,
    action_family: str,
) -> tuple[PolicyEvaluation, RiskClass, str]:
    """Map frozen alternatives onto ordinary write A-R or cleanup H."""

    if alternative_id in _WRITE_ALTERNATIVES or alternative_id in {
        "protected_write.prepare_patch.v1",
        "git.prepare_local_change.v1",
    }:
        return (
            replace(
                evaluation,
                risk_class=RiskClass.WRITE,
                reason=evaluation.reason or "controlled_alternative_write",
            ),
            RiskClass.WRITE,
            "write",
        )
    if alternative_id == _CLEANUP:
        decision = evaluation.decision
        if decision is PolicyDecision.BLOCK:
            coerced = PolicyDecision.BLOCK
        elif decision is PolicyDecision.ASK_BACKEND:
            coerced = PolicyDecision.BLOCK
        else:
            coerced = PolicyDecision.APPROVAL
        return (
            replace(
                evaluation,
                decision=coerced,
                risk_class=RiskClass.DESTRUCTIVE,
                reason=(
                    "controlled_alternative_cleanup_ask_backend_fail_closed"
                    if decision is PolicyDecision.ASK_BACKEND
                    else evaluation.reason or "controlled_alternative_cleanup"
                ),
            ),
            RiskClass.DESTRUCTIVE,
            "delete",
        )
    return evaluation, evaluation.risk_class, action_family


def execute_controlled_alternative(
    *,
    binding: ControlledAlternativeRuntimeBinding,
    arguments: Mapping[str, Any],
    invocation_phase: str = "execute",
    recheck: Callable[[], Mapping[str, Any] | None] | None = None,
    before_execute: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Run propose → re-check → execute → verify and project a bounded result."""

    del invocation_phase
    try:
        alternative_id = alternative_id_from_arguments(arguments)
        if alternative_id is None:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        raw_input = arguments.get("input")
        if not isinstance(raw_input, Mapping):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        local = validate_controlled_alternative_local_input(alternative_id, raw_input)
        locator = _build_locator(binding, alternative_id, local)
        operation_ref = secrets.token_hex(16)[:32]
        correlation = arguments.get("correlation_token")
        correlation_token = correlation if isinstance(correlation, str) else None
        path = locator.get("normalized_path") if isinstance(locator, dict) else None
        propose = _invoke_phase(
            binding,
            "propose",
            alternative_id=alternative_id,
            operation_ref=operation_ref,
            locator=locator,
            correlation_token=correlation_token,
            local_input=raw_input,
        )
        if propose.target_reached:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        if propose.result_status != "success":
            return _project_local_result(
                alternative_id,
                local,
                propose,
                verified=False,
                normalized_path=path if isinstance(path, str) else None,
            )
        if not callable(recheck):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        snapshot = recheck()
        if not _recheck_authorized(snapshot, binding):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        if callable(before_execute):
            before_execute()
        executed = _invoke_phase(
            binding,
            "execute",
            alternative_id=alternative_id,
            operation_ref=operation_ref,
            locator=locator,
            correlation_token=correlation_token,
            local_input=raw_input,
        )
        if executed.result_status != "success":
            return _project_local_result(
                alternative_id,
                local,
                executed,
                verified=False,
                normalized_path=path if isinstance(path, str) else None,
            )
        try:
            verified = _invoke_phase(
                binding,
                "verify",
                alternative_id=alternative_id,
                operation_ref=operation_ref,
                locator=locator,
                correlation_token=correlation_token,
                local_input=raw_input,
            )
        except ControlledAlternativeValidationError as exc:
            return _project_post_effect_error(
                executed,
                error_code=str(exc.args[0]) if exc.args else ERROR_REQUEST_MALFORMED,
            )
        except Exception:
            return _project_post_effect_error(executed, error_code="internal_error")
        if verified.result_status != "success":
            return _project_post_effect_error(
                executed,
                error_code=verified.error_code or "mechanism_verification_failed",
            )
        return _project_local_result(
            alternative_id,
            local,
            verified,
            verified=True,
            normalized_path=path if isinstance(path, str) else None,
        )
    except ControlledAlternativeExecutionAbort:
        raise
    except ControlledAlternativeValidationError as exc:
        return {
            "mechanism_status": "error",
            "error_code": str(exc.args[0]) if exc.args else ERROR_REQUEST_MALFORMED,
            "target_reached": False,
            "rollback_available": False,
            "verification_level": "not_verified",
        }
    except Exception:
        return {
            "mechanism_status": "error",
            "error_code": "internal_error",
            "target_reached": False,
            "rollback_available": False,
            "verification_level": "not_verified",
        }


def local_mcp_result(request_id: Any, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": _JSONRPC_VERSION,
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(dict(payload), separators=(",", ":"), ensure_ascii=False),
                }
            ],
        },
    }


def _canonical_existing_dir(path: Path) -> str | None:
    try:
        if not path.exists() or not path.is_dir() or path.is_symlink():
            return None
        resolved = path.resolve()
        if not resolved.is_dir() or resolved.is_symlink():
            return None
        if os.path.realpath(path) != str(resolved):
            return None
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            return None
        value = str(resolved)
        if os.path.normpath(value) != value:
            return None
        return value
    except OSError:
        return None


def _path_is_inside(inner: str, outer: str, *, strict: bool) -> bool:
    inner_drive, inner_tail = os.path.splitdrive(os.path.normcase(inner))
    outer_drive, outer_tail = os.path.splitdrive(os.path.normcase(outer))
    if inner_drive != outer_drive:
        return False
    inner_parts = tuple(part for part in inner_tail.split(os.sep) if part)
    outer_parts = tuple(part for part in outer_tail.split(os.sep) if part)
    if inner_parts[: len(outer_parts)] != outer_parts:
        return False
    if len(inner_parts) == len(outer_parts):
        return not strict
    return True


def _normalize_workspace_path(workspace_root: str, raw_path: str) -> str:
    if os.path.isabs(raw_path):
        candidate = raw_path
    else:
        candidate = os.path.join(workspace_root, raw_path)
    real_workspace = os.path.realpath(workspace_root)
    real_target = os.path.realpath(candidate)
    if not _path_is_inside(real_target, real_workspace, strict=False):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if os.path.normpath(real_target) != real_target:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return real_target


def _require_hex32(value: str) -> str:
    if len(value) != 32 or any(char not in _HEX32 for char in value):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return value


def _build_locator(
    binding: ControlledAlternativeRuntimeBinding,
    alternative_id: str,
    local: Any,
) -> dict[str, Any]:
    locator: dict[str, Any] = {
        "workspace_root": binding.workspace_root,
        "state_root": binding.state_root,
        "route_id": binding.route_id,
        "st_dev": binding.st_dev,
    }
    if alternative_id == _STAGE_DELETE:
        if not isinstance(local.path, str):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        locator["locator_kind"] = "filesystem_path"
        locator["normalized_path"] = _normalize_workspace_path(binding.workspace_root, local.path)
        return locator
    if alternative_id in {_RESTORE, _CLEANUP}:
        if not isinstance(local.quarantine_entry_id, str):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        locator["locator_kind"] = "quarantine_entry"
        locator["quarantine_entry_id"] = _require_hex32(local.quarantine_entry_id)
        return locator
    if alternative_id == "protected_write.prepare_patch.v1":
        if not isinstance(local.path, str):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        locator["locator_kind"] = "protected_write_target"
        locator["normalized_path"] = _normalize_workspace_path(binding.workspace_root, local.path)
        return locator
    if not isinstance(local.worktree_path, str):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    locator["locator_kind"] = "git_worktree"
    locator["normalized_path"] = _normalize_workspace_path(binding.workspace_root, local.worktree_path)
    return locator


def _recheck_authorized(snapshot: Mapping[str, Any] | None, binding: ControlledAlternativeRuntimeBinding) -> bool:
    if not isinstance(snapshot, Mapping):
        return False
    if snapshot.get("route_id") != binding.route_id:
        return False
    required = (
        "action_hash",
        "recheck_action_hash",
        "resource_hash",
        "recheck_resource_hash",
        "payload_hash",
        "recheck_payload_hash",
        "policy_context_hash",
        "recheck_policy_context_hash",
        "policy_decision",
        "recheck_policy_decision",
        "session_id",
        "recheck_session_id",
        "approved",
        "recheck_approved",
    )
    if any(key not in snapshot for key in required):
        return False
    pairs = (
        ("action_hash", "recheck_action_hash"),
        ("resource_hash", "recheck_resource_hash"),
        ("payload_hash", "recheck_payload_hash"),
        ("policy_context_hash", "recheck_policy_context_hash"),
        ("policy_decision", "recheck_policy_decision"),
        ("session_id", "recheck_session_id"),
        ("approved", "recheck_approved"),
    )
    if not all(snapshot.get(left) == snapshot.get(right) for left, right in pairs):  # claim-check: allow Python all() over bounded recheck pairs.
        return False
    for key in ("action_hash", "payload_hash", "policy_context_hash", "policy_decision"):
        value = snapshot.get(key)
        if not isinstance(value, str) or not value:
            return False
    resource = snapshot.get("resource_hash")
    if resource is not None and (not isinstance(resource, str) or not resource):
        return False
    return True


def _invoke_phase(
    binding: ControlledAlternativeRuntimeBinding,
    phase: str,
    *,
    alternative_id: str,
    operation_ref: str,
    locator: Mapping[str, Any],
    correlation_token: str | None,
    local_input: Mapping[str, Any],
) -> ControlledAlternativeProviderResult:
    payload: dict[str, Any] = {
        "contract_version": CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION,
        "profile_id": CONTROLLED_ALTERNATIVES_PROFILE_ID,
        "alternative_id": alternative_id,
        "operation_ref": operation_ref,
        "action_family": "delete" if alternative_id.split(".", 1)[0] == "filesystem" else "write",
        "semantic_category": "filesystem" if alternative_id.startswith("filesystem.") else "git",
        "invocation_phase": phase,
        "resource_locator": dict(locator),
    }
    if correlation_token is not None:
        payload["correlation_token"] = correlation_token
        payload["resource_locator"]["correlation_token"] = correlation_token
    if alternative_id == "protected_write.prepare_patch.v1":
        payload["bounded_local_input"] = {"patch": local_input.get("patch")}
    request = validate_provider_request(payload)
    method = getattr(binding.provider, phase)
    raw = method(request)
    return validate_provider_result(raw)


def _project_local_result(
    alternative_id: str,
    local: Any,
    result: ControlledAlternativeProviderResult,
    *,
    verified: bool = False,
    normalized_path: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "mechanism_status": result.result_status,
        "target_reached": result.target_reached,
        "rollback_available": result.rollback_available,
        "verification_level": (
            "mechanism_verified"
            if verified and result.result_status == "success"
            else "not_verified"
        ),
    }
    if result.result_status != "success" and result.error_code:
        payload["error_code"] = result.error_code
    if result.quarantine_entry_id is not None:
        payload["quarantine_entry_id"] = result.quarantine_entry_id
    if alternative_id == _STAGE_DELETE and result.result_status == "success" and result.target_reached:
        source = normalized_path if isinstance(normalized_path, str) else getattr(local, "path", None)
        if verified and isinstance(source, str) and _source_absent(source):
            payload["verification_level"] = "public_source_absent"
            payload["terminal_outcome"] = "COMPLETED_WITH_ALTERNATIVE"
    return payload


def _project_post_effect_error(
    executed: ControlledAlternativeProviderResult,
    *,
    error_code: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "mechanism_status": "error",
        "error_code": error_code,
        "target_reached": executed.target_reached,
        "rollback_available": executed.rollback_available,
        "verification_level": "not_verified",
    }
    if executed.quarantine_entry_id is not None:
        payload["quarantine_entry_id"] = executed.quarantine_entry_id
    return payload


def _source_absent(raw_path: str) -> bool:
    try:
        return not os.path.lexists(raw_path)
    except OSError:
        return False
