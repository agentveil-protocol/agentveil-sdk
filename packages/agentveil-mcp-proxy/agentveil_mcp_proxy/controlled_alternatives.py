# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Inert public Controlled Alternatives provider seam (CA1).

This module defines bounded contract types, validation, optional discovery, and
an inert generic tool schema builder. It is not imported from live MCP runtime
paths in CA1.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import wraps
from importlib.metadata import entry_points
from typing import Any, Callable, Mapping, Protocol

from agentveil_mcp_proxy.paid_provider import (
    FORBIDDEN_PRIVATE_MARKERS,
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    PaidProviderSnapshot,
    contains_private_provider_marker,
)

CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP = (
    "agentveil_mcp_proxy.controlled_alternative_providers"
)
CONTROLLED_ALTERNATIVE_PROVIDER_ID = "private_v1"
CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION = "1"
CONTROLLED_ALTERNATIVES_PROFILE_ID = "controlled_alternatives_coding_v1"
GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME = "agentveil_controlled_alternative"

CONTROLLED_ALTERNATIVE_IDS: tuple[str, ...] = (
    "filesystem.stage_delete.v1",
    "filesystem.restore_staged.v1",
    "filesystem.cleanup_staged.v1",
    "protected_write.prepare_patch.v1",
    "git.prepare_local_change.v1",
)

INVOCATION_PHASES = frozenset({"propose", "execute", "verify"})
RESULT_STATUSES = frozenset({"success", "error", "unavailable"})
OUTCOME_CLASS_CANDIDATES = frozenset({
    "COMPLETED_DIRECTLY",
    "COMPLETED_WITH_ALTERNATIVE",
    "PREPARED_FOR_APPROVAL",
    "DENIED",
    "ALTERNATIVE_UNAVAILABLE",
})
LOCATOR_KINDS = frozenset({
    "filesystem_path",
    "quarantine_entry",
    "protected_write_target",
    "git_worktree",
})

MECHANISM_ERROR_CODES = frozenset({
    "contract_incompatible",
    "alternative_unknown",
    "request_malformed",
    "resource_locator_invalid",
    "atomic_relocation_unavailable",
    "quarantine_capacity_exceeded",
    "restore_conflict",
    "cleanup_required",
    "mechanism_verification_failed",
    "execution_interrupted",
    "internal_error",
})

# claim-check: allow "allow" is a frozen forbidden provider authority-key token, not a runtime grant.
AUTHORITY_FORBIDDEN_REQUEST_KEYS = frozenset({
    "allow",
    "decision",
    "authority_grant",
    "approval_granted",
    "approval_binding_ref",
    "human_authority_required",
    "policy_changed",
})
AUTHORITY_FORBIDDEN_RESULT_KEYS = AUTHORITY_FORBIDDEN_REQUEST_KEYS

MAX_GENERIC_INPUT_FIELDS = 8
MAX_RESOURCE_LOCATOR_FIELDS = 8
MAX_NORMALIZED_PATH_BYTES = 4096
MAX_ROUTE_ID_BYTES = 128
MAX_QUARANTINE_ENTRY_ID_BYTES = 64
MAX_PATCH_BYTES = 262144
MAX_OPERATION_REF_BYTES = 64
MAX_ALTERNATIVE_ID_BYTES = 128
MAX_CORRELATION_TOKEN_BYTES = 64
MAX_BOUNDED_SUMMARY_BYTES = 240
MAX_ERROR_CODE_BYTES = 64
MAX_REQUEST_TOP_LEVEL_KEYS = 16
MAX_RESULT_TOP_LEVEL_KEYS = 12

ERROR_CONTRACT_INCOMPATIBLE = "contract_incompatible"
ERROR_DESCRIPTOR_INVALID = "descriptor_invalid"
ERROR_DISCOVERY_INELIGIBLE = "discovery_ineligible"
ERROR_DISCOVERY_ENTRYPOINT_MISSING = "discovery_entrypoint_missing"
ERROR_DISCOVERY_DUPLICATE_ENTRYPOINT = "discovery_entrypoint_duplicate"
ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED = "discovery_entrypoint_load_failed"
ERROR_REQUEST_MALFORMED = "request_malformed"
ERROR_RESULT_UNSAFE = "result_unsafe"

_LOCAL_INPUT_REQUIRED_KEYS: dict[str, frozenset[str]] = {
    "filesystem.stage_delete.v1": frozenset({"path"}),
    "filesystem.restore_staged.v1": frozenset({"quarantine_entry_id"}),
    "filesystem.cleanup_staged.v1": frozenset({"quarantine_entry_id"}),
    "protected_write.prepare_patch.v1": frozenset({"path", "patch"}),
    "git.prepare_local_change.v1": frozenset({"worktree_path"}),
}

_TRUSTED_ROOT_FIELDS = frozenset({"workspace_root", "state_root"})

_LOCATOR_SPECS: dict[str, dict[str, Any]] = {
    "filesystem.stage_delete.v1": {
        "kind": "filesystem_path",
        "required": frozenset({"locator_kind", "normalized_path", "route_id", "st_dev"}) | _TRUSTED_ROOT_FIELDS,
        "optional": frozenset({"correlation_token"}),
        "forbidden": frozenset({"quarantine_entry_id"}),
    },
    "filesystem.restore_staged.v1": {
        "kind": "quarantine_entry",
        "required": frozenset({"locator_kind", "quarantine_entry_id", "route_id", "st_dev"}) | _TRUSTED_ROOT_FIELDS,
        "optional": frozenset({"correlation_token"}),
        "forbidden": frozenset({"normalized_path"}),
    },
    "filesystem.cleanup_staged.v1": {
        "kind": "quarantine_entry",
        "required": frozenset({"locator_kind", "quarantine_entry_id", "route_id", "st_dev"}) | _TRUSTED_ROOT_FIELDS,
        "optional": frozenset({"correlation_token"}),
        "forbidden": frozenset({"normalized_path"}),
    },
    "protected_write.prepare_patch.v1": {
        "kind": "protected_write_target",
        "required": frozenset({"locator_kind", "normalized_path", "route_id", "st_dev"}) | _TRUSTED_ROOT_FIELDS,
        "optional": frozenset({"correlation_token"}),
        "forbidden": frozenset({"quarantine_entry_id"}),
    },
    "git.prepare_local_change.v1": {
        "kind": "git_worktree",
        "required": frozenset({"locator_kind", "normalized_path", "route_id", "st_dev"}) | _TRUSTED_ROOT_FIELDS,
        "optional": frozenset({"correlation_token"}),
        "forbidden": frozenset({"quarantine_entry_id"}),
    },
}


class ControlledAlternativeValidationError(ValueError):
    """Bounded validation failure for Controlled Alternatives seam types."""


def _total(error_code: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except ControlledAlternativeValidationError:
                raise
            except Exception:
                raise ControlledAlternativeValidationError(error_code) from None

        return wrapper

    return decorator


@dataclass(frozen=True)
class ControlledAlternativeProviderDescriptor:
    provider_id: str
    contract_version: str
    profile_id: str
    alternative_ids: tuple[str, ...]


@dataclass(frozen=True)
class ControlledAlternativeLocalInput:
    alternative_id: str
    path: str | None = None
    quarantine_entry_id: str | None = None
    patch: str | None = None
    worktree_path: str | None = None

    def __repr__(self) -> str:
        return (
            "ControlledAlternativeLocalInput("
            f"alternative_id={self.alternative_id!r}, "
            "path='***', "
            "quarantine_entry_id='***', "
            "patch='***', "
            "worktree_path='***')"
        )

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class ControlledAlternativeBoundedLocalInput:
    alternative_id: str
    patch: str

    def __repr__(self) -> str:
        return (
            "ControlledAlternativeBoundedLocalInput("
            f"alternative_id={self.alternative_id!r}, "
            "patch='***')"
        )

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class ControlledAlternativeResourceLocator:
    locator_kind: str
    workspace_root: str
    state_root: str
    normalized_path: str | None = None
    quarantine_entry_id: str | None = None
    route_id: str | None = None
    st_dev: int | None = None
    correlation_token: str | None = None

    def __repr__(self) -> str:
        return (
            "ControlledAlternativeResourceLocator("
            f"locator_kind={self.locator_kind!r}, "
            "workspace_root='***', "
            "state_root='***', "
            "normalized_path='***', "
            "quarantine_entry_id='***', "
            "route_id='***', "
            "st_dev='***', "
            "correlation_token='***')"
        )

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class ControlledAlternativeProviderRequest:
    contract_version: str
    profile_id: str
    alternative_id: str
    operation_ref: str
    action_family: str
    semantic_category: str
    invocation_phase: str
    resource_locator: ControlledAlternativeResourceLocator
    correlation_token: str | None = None
    bounded_local_input: ControlledAlternativeBoundedLocalInput | None = None

    def __repr__(self) -> str:
        return (
            "ControlledAlternativeProviderRequest("
            f"contract_version={self.contract_version!r}, "
            f"profile_id={self.profile_id!r}, "
            f"alternative_id={self.alternative_id!r}, "
            f"operation_ref={self.operation_ref!r}, "
            f"action_family={self.action_family!r}, "
            f"semantic_category={self.semantic_category!r}, "
            f"invocation_phase={self.invocation_phase!r}, "
            "resource_locator='***', "
            "correlation_token='***', "
            "bounded_local_input='***')"
        )

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class ControlledAlternativeProviderResult:
    contract_version: str
    alternative_id: str
    operation_ref: str
    result_status: str
    outcome_class_candidate: str
    target_reached: bool
    rollback_available: bool
    error_code: str | None = None
    bounded_summary: str | None = None

    def __repr__(self) -> str:
        return (
            "ControlledAlternativeProviderResult("
            f"contract_version={self.contract_version!r}, "
            f"alternative_id={self.alternative_id!r}, "
            f"operation_ref={self.operation_ref!r}, "
            f"result_status={self.result_status!r}, "
            f"outcome_class_candidate={self.outcome_class_candidate!r}, "
            f"target_reached={self.target_reached!r}, "
            f"rollback_available={self.rollback_available!r}, "
            f"error_code={self.error_code!r}, "
            "bounded_summary='***')"
        )

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class ControlledAlternativeDiscoveryResult:
    available: bool
    descriptor: ControlledAlternativeProviderDescriptor | None = None
    error_code: str | None = None


class ControlledAlternativeProvider(Protocol):
    """Bounded in-process provider surface for future private wheel integration."""

    def descriptor(self) -> Mapping[str, Any] | ControlledAlternativeProviderDescriptor:
        ...

    def propose(
        self,
        request: ControlledAlternativeProviderRequest,
    ) -> ControlledAlternativeProviderResult:
        ...

    def execute(
        self,
        request: ControlledAlternativeProviderRequest,
    ) -> ControlledAlternativeProviderResult:
        ...

    def verify(
        self,
        request: ControlledAlternativeProviderRequest,
    ) -> ControlledAlternativeProviderResult:
        ...


_provider_loader: Callable[[], ControlledAlternativeProvider | None] | None = None


def set_controlled_alternative_provider_loader(
    loader: Callable[[], ControlledAlternativeProvider | None] | None,
) -> None:
    """Install or clear a test-only provider loader."""

    global _provider_loader
    _provider_loader = loader


def _bounded_local_text(value: Any, *, max_bytes: int) -> str:
    if not isinstance(value, str):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    text = value.strip()
    if not text or len(text.encode("utf-8")) > max_bytes:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return text


def _bounded_exported_text(value: Any, *, max_bytes: int, error_code: str) -> str:
    if not isinstance(value, str):
        raise ControlledAlternativeValidationError(error_code)
    text = value.strip()
    if not text or len(text.encode("utf-8")) > max_bytes:
        raise ControlledAlternativeValidationError(error_code)
    if contains_private_provider_marker(text):
        raise ControlledAlternativeValidationError(ERROR_RESULT_UNSAFE)
    lowered = text.lower()
    if any(marker in lowered for marker in FORBIDDEN_PRIVATE_MARKERS):
        raise ControlledAlternativeValidationError(ERROR_RESULT_UNSAFE)
    return text


def _assert_no_extra_keys(
    raw: Mapping[str, Any],
    allowed: frozenset[str],
    *,
    error_code: str,
) -> None:
    extra = set(raw) - allowed
    if extra:
        raise ControlledAlternativeValidationError(error_code)


def _assert_no_authority_keys(raw: Mapping[str, Any]) -> None:
    for key in raw:
        if str(key).lower() in AUTHORITY_FORBIDDEN_REQUEST_KEYS:
            raise ControlledAlternativeValidationError(ERROR_RESULT_UNSAFE)


def _require_key(raw: Mapping[str, Any], key: str, *, error_code: str) -> Any:
    if key not in raw:
        raise ControlledAlternativeValidationError(error_code)
    return raw[key]


def _require_mapping(raw: Any, *, error_code: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise ControlledAlternativeValidationError(error_code)
    return raw


def _require_st_dev(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return value


def _bounded_absolute_normalized_path(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if len(value.encode("utf-8")) > MAX_NORMALIZED_PATH_BYTES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return value


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


def _descriptor_mapping(
    raw: Mapping[str, Any] | ControlledAlternativeProviderDescriptor,
) -> Mapping[str, Any]:
    if isinstance(raw, ControlledAlternativeProviderDescriptor):
        return {
            "provider_id": raw.provider_id,
            "contract_version": raw.contract_version,
            "profile_id": raw.profile_id,
            "alternative_ids": raw.alternative_ids,
        }
    return _require_mapping(raw, error_code=ERROR_DESCRIPTOR_INVALID)


def _result_mapping(
    raw: Mapping[str, Any] | ControlledAlternativeProviderResult,
) -> Mapping[str, Any]:
    if isinstance(raw, ControlledAlternativeProviderResult):
        mapping: dict[str, Any] = {
            "contract_version": raw.contract_version,
            "alternative_id": raw.alternative_id,
            "operation_ref": raw.operation_ref,
            "result_status": raw.result_status,
            "outcome_class_candidate": raw.outcome_class_candidate,
            "target_reached": raw.target_reached,
            "rollback_available": raw.rollback_available,
        }
        if raw.error_code is not None:
            mapping["error_code"] = raw.error_code
        if raw.bounded_summary is not None:
            mapping["bounded_summary"] = raw.bounded_summary
        return mapping
    return _require_mapping(raw, error_code=ERROR_REQUEST_MALFORMED)


@_total(ERROR_REQUEST_MALFORMED)
def validate_controlled_alternative_local_input(
    alternative_id: str,
    raw_input: Mapping[str, Any],
) -> ControlledAlternativeLocalInput:
    """Validate one family-specific local input object."""

    alt = _bounded_local_text(alternative_id, max_bytes=MAX_ALTERNATIVE_ID_BYTES)
    if alt not in CONTROLLED_ALTERNATIVE_IDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    payload = _require_mapping(raw_input, error_code=ERROR_REQUEST_MALFORMED)
    if len(payload) > MAX_GENERIC_INPUT_FIELDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    required = _LOCAL_INPUT_REQUIRED_KEYS[alt]
    _assert_no_authority_keys(payload)
    _assert_no_extra_keys(payload, required, error_code=ERROR_REQUEST_MALFORMED)
    if set(payload) != required:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)

    if alt == "filesystem.stage_delete.v1":
        return ControlledAlternativeLocalInput(
            alternative_id=alt,
            path=_bounded_local_text(_require_key(payload, "path", error_code=ERROR_REQUEST_MALFORMED), max_bytes=MAX_NORMALIZED_PATH_BYTES),
        )
    if alt in {"filesystem.restore_staged.v1", "filesystem.cleanup_staged.v1"}:
        return ControlledAlternativeLocalInput(
            alternative_id=alt,
            quarantine_entry_id=_bounded_local_text(
                _require_key(payload, "quarantine_entry_id", error_code=ERROR_REQUEST_MALFORMED),
                max_bytes=MAX_QUARANTINE_ENTRY_ID_BYTES,
            ),
        )
    if alt == "protected_write.prepare_patch.v1":
        return ControlledAlternativeLocalInput(
            alternative_id=alt,
            path=_bounded_local_text(_require_key(payload, "path", error_code=ERROR_REQUEST_MALFORMED), max_bytes=MAX_NORMALIZED_PATH_BYTES),
            patch=_bounded_local_text(_require_key(payload, "patch", error_code=ERROR_REQUEST_MALFORMED), max_bytes=MAX_PATCH_BYTES),
        )
    return ControlledAlternativeLocalInput(
        alternative_id=alt,
        worktree_path=_bounded_local_text(
            _require_key(payload, "worktree_path", error_code=ERROR_REQUEST_MALFORMED),
            max_bytes=MAX_NORMALIZED_PATH_BYTES,
        ),
    )


@_total(ERROR_REQUEST_MALFORMED)
def validate_resource_locator(
    raw: Mapping[str, Any],
    *,
    alternative_id: str,
) -> ControlledAlternativeResourceLocator:
    """Validate one in-process-only resource locator for a frozen alternative."""

    payload = _require_mapping(raw, error_code=ERROR_REQUEST_MALFORMED)
    if len(payload) > MAX_RESOURCE_LOCATOR_FIELDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    alt = _bounded_local_text(alternative_id, max_bytes=MAX_ALTERNATIVE_ID_BYTES)
    spec = _LOCATOR_SPECS.get(alt)
    if spec is None:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    allowed = spec["required"] | spec["optional"]
    _assert_no_authority_keys(payload)
    if set(payload) & spec["forbidden"]:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    _assert_no_extra_keys(payload, allowed, error_code=ERROR_REQUEST_MALFORMED)
    if not spec["required"] <= set(payload):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)

    locator_kind = _bounded_local_text(
        _require_key(payload, "locator_kind", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=64,
    )
    if locator_kind != spec["kind"] or locator_kind not in LOCATOR_KINDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)

    workspace_root = _bounded_absolute_normalized_path(
        _require_key(payload, "workspace_root", error_code=ERROR_REQUEST_MALFORMED),
    )
    state_root = _bounded_absolute_normalized_path(
        _require_key(payload, "state_root", error_code=ERROR_REQUEST_MALFORMED),
    )
    if not _path_is_inside(state_root, workspace_root, strict=True):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)

    normalized_path = None
    if "normalized_path" in payload:
        normalized_path = _bounded_local_text(
            payload["normalized_path"],
            max_bytes=MAX_NORMALIZED_PATH_BYTES,
        )
    quarantine_entry_id = None
    if "quarantine_entry_id" in payload:
        quarantine_entry_id = _bounded_local_text(
            payload["quarantine_entry_id"],
            max_bytes=MAX_QUARANTINE_ENTRY_ID_BYTES,
        )
    route_id = _bounded_local_text(
        _require_key(payload, "route_id", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=MAX_ROUTE_ID_BYTES,
    )
    st_dev = _require_st_dev(_require_key(payload, "st_dev", error_code=ERROR_REQUEST_MALFORMED))
    correlation_token = None
    if "correlation_token" in payload:
        correlation_token = _bounded_local_text(
            payload["correlation_token"],
            max_bytes=MAX_CORRELATION_TOKEN_BYTES,
        )
    return ControlledAlternativeResourceLocator(
        locator_kind=locator_kind,
        workspace_root=workspace_root,
        state_root=state_root,
        normalized_path=normalized_path,
        quarantine_entry_id=quarantine_entry_id,
        route_id=route_id,
        st_dev=st_dev,
        correlation_token=correlation_token,
    )


@_total(ERROR_DESCRIPTOR_INVALID)
def validate_provider_descriptor(
    raw: Mapping[str, Any] | ControlledAlternativeProviderDescriptor,
) -> ControlledAlternativeProviderDescriptor:
    """Validate one bounded provider descriptor."""

    payload = _descriptor_mapping(raw)
    allowed = frozenset({"provider_id", "contract_version", "profile_id", "alternative_ids"})
    _assert_no_authority_keys(payload)
    _assert_no_extra_keys(payload, allowed, error_code=ERROR_DESCRIPTOR_INVALID)
    provider_id = _bounded_exported_text(
        _require_key(payload, "provider_id", error_code=ERROR_DESCRIPTOR_INVALID),
        max_bytes=64,
        error_code=ERROR_DESCRIPTOR_INVALID,
    )
    contract_version = _bounded_exported_text(
        _require_key(payload, "contract_version", error_code=ERROR_DESCRIPTOR_INVALID),
        max_bytes=8,
        error_code=ERROR_DESCRIPTOR_INVALID,
    )
    profile_id = _bounded_exported_text(
        _require_key(payload, "profile_id", error_code=ERROR_DESCRIPTOR_INVALID),
        max_bytes=128,
        error_code=ERROR_DESCRIPTOR_INVALID,
    )
    if provider_id != CONTROLLED_ALTERNATIVE_PROVIDER_ID:
        raise ControlledAlternativeValidationError(ERROR_DESCRIPTOR_INVALID)
    if contract_version != CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION:
        raise ControlledAlternativeValidationError(ERROR_CONTRACT_INCOMPATIBLE)
    if profile_id != CONTROLLED_ALTERNATIVES_PROFILE_ID:
        raise ControlledAlternativeValidationError(ERROR_CONTRACT_INCOMPATIBLE)
    alternatives = _require_key(payload, "alternative_ids", error_code=ERROR_DESCRIPTOR_INVALID)
    if not isinstance(alternatives, (list, tuple)):
        raise ControlledAlternativeValidationError(ERROR_DESCRIPTOR_INVALID)
    alt_items: list[str] = []
    for item in alternatives:
        if not isinstance(item, str):
            raise ControlledAlternativeValidationError(ERROR_DESCRIPTOR_INVALID)
        alt_items.append(
            _bounded_exported_text(item, max_bytes=MAX_ALTERNATIVE_ID_BYTES, error_code=ERROR_DESCRIPTOR_INVALID)
        )
    alt_tuple = tuple(alt_items)
    if alt_tuple != CONTROLLED_ALTERNATIVE_IDS:
        raise ControlledAlternativeValidationError(ERROR_DESCRIPTOR_INVALID)
    return ControlledAlternativeProviderDescriptor(
        provider_id=provider_id,
        contract_version=contract_version,
        profile_id=profile_id,
        alternative_ids=alt_tuple,
    )


def _cross_check_request(
    *,
    alternative_id: str,
    resource_locator: ControlledAlternativeResourceLocator,
    correlation_token: str | None,
    bounded_local_input: ControlledAlternativeBoundedLocalInput | None,
) -> None:
    if (
        correlation_token is not None
        and resource_locator.correlation_token is not None
        and correlation_token != resource_locator.correlation_token
    ):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if alternative_id == "protected_write.prepare_patch.v1":
        if bounded_local_input is None:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        if bounded_local_input.alternative_id != alternative_id:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        if resource_locator.normalized_path is None:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        return
    if bounded_local_input is not None:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)


def _validate_provider_bounded_local_input(
    alternative_id: str,
    raw_input: Mapping[str, Any],
) -> ControlledAlternativeBoundedLocalInput:
    if alternative_id != "protected_write.prepare_patch.v1":
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    payload = _require_mapping(raw_input, error_code=ERROR_REQUEST_MALFORMED)
    if len(payload) > MAX_GENERIC_INPUT_FIELDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    allowed = frozenset({"patch"})
    _assert_no_authority_keys(payload)
    _assert_no_extra_keys(payload, allowed, error_code=ERROR_REQUEST_MALFORMED)
    if set(payload) != allowed:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return ControlledAlternativeBoundedLocalInput(
        alternative_id=alternative_id,
        patch=_bounded_local_text(
            _require_key(payload, "patch", error_code=ERROR_REQUEST_MALFORMED),
            max_bytes=MAX_PATCH_BYTES,
        ),
    )


@_total(ERROR_REQUEST_MALFORMED)
def validate_provider_request(raw: Mapping[str, Any]) -> ControlledAlternativeProviderRequest:
    """Validate one in-process provider request."""

    payload = _require_mapping(raw, error_code=ERROR_REQUEST_MALFORMED)
    if len(payload) > MAX_REQUEST_TOP_LEVEL_KEYS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    allowed = frozenset({
        "contract_version",
        "profile_id",
        "alternative_id",
        "operation_ref",
        "action_family",
        "semantic_category",
        "invocation_phase",
        "resource_locator",
        "correlation_token",
        "bounded_local_input",
    })
    _assert_no_authority_keys(payload)
    _assert_no_extra_keys(payload, allowed, error_code=ERROR_REQUEST_MALFORMED)

    contract_version = _bounded_exported_text(
        _require_key(payload, "contract_version", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=8,
        error_code=ERROR_CONTRACT_INCOMPATIBLE,
    )
    if contract_version != CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION:
        raise ControlledAlternativeValidationError(ERROR_CONTRACT_INCOMPATIBLE)
    profile_id = _bounded_exported_text(
        _require_key(payload, "profile_id", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=128,
        error_code=ERROR_CONTRACT_INCOMPATIBLE,
    )
    if profile_id != CONTROLLED_ALTERNATIVES_PROFILE_ID:
        raise ControlledAlternativeValidationError(ERROR_CONTRACT_INCOMPATIBLE)
    alternative_id = _bounded_local_text(
        _require_key(payload, "alternative_id", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=MAX_ALTERNATIVE_ID_BYTES,
    )
    if alternative_id not in CONTROLLED_ALTERNATIVE_IDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    operation_ref = _bounded_local_text(
        _require_key(payload, "operation_ref", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=MAX_OPERATION_REF_BYTES,
    )
    action_family = _bounded_local_text(
        _require_key(payload, "action_family", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=64,
    )
    semantic_category = _bounded_local_text(
        _require_key(payload, "semantic_category", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=64,
    )
    invocation_phase = _bounded_local_text(
        _require_key(payload, "invocation_phase", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=16,
    )
    if invocation_phase not in INVOCATION_PHASES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    resource_locator = validate_resource_locator(
        _require_key(payload, "resource_locator", error_code=ERROR_REQUEST_MALFORMED),
        alternative_id=alternative_id,
    )
    correlation_token = None
    if "correlation_token" in payload:
        correlation_token = _bounded_local_text(
            payload["correlation_token"],
            max_bytes=MAX_CORRELATION_TOKEN_BYTES,
        )
    bounded_local_input = None
    if "bounded_local_input" in payload:
        local_raw = _require_mapping(payload["bounded_local_input"], error_code=ERROR_REQUEST_MALFORMED)
        bounded_local_input = _validate_provider_bounded_local_input(alternative_id, local_raw)
    _cross_check_request(
        alternative_id=alternative_id,
        resource_locator=resource_locator,
        correlation_token=correlation_token,
        bounded_local_input=bounded_local_input,
    )
    return ControlledAlternativeProviderRequest(
        contract_version=contract_version,
        profile_id=profile_id,
        alternative_id=alternative_id,
        operation_ref=operation_ref,
        action_family=action_family,
        semantic_category=semantic_category,
        invocation_phase=invocation_phase,
        resource_locator=resource_locator,
        correlation_token=correlation_token,
        bounded_local_input=bounded_local_input,
    )


@_total(ERROR_REQUEST_MALFORMED)
def validate_provider_result(
    raw: Mapping[str, Any] | ControlledAlternativeProviderResult,
) -> ControlledAlternativeProviderResult:
    """Validate one bounded mechanism result from a private provider."""

    payload = _result_mapping(raw)
    if len(payload) > MAX_RESULT_TOP_LEVEL_KEYS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    allowed = frozenset({
        "contract_version",
        "alternative_id",
        "operation_ref",
        "result_status",
        "outcome_class_candidate",
        "target_reached",
        "rollback_available",
        "error_code",
        "bounded_summary",
    })
    _assert_no_authority_keys(payload)
    _assert_no_extra_keys(payload, allowed, error_code=ERROR_REQUEST_MALFORMED)

    contract_version = _bounded_exported_text(
        _require_key(payload, "contract_version", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=8,
        error_code=ERROR_CONTRACT_INCOMPATIBLE,
    )
    if contract_version != CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION:
        raise ControlledAlternativeValidationError(ERROR_CONTRACT_INCOMPATIBLE)
    alternative_id = _bounded_exported_text(
        _require_key(payload, "alternative_id", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=MAX_ALTERNATIVE_ID_BYTES,
        error_code=ERROR_REQUEST_MALFORMED,
    )
    if alternative_id not in CONTROLLED_ALTERNATIVE_IDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    operation_ref = _bounded_exported_text(
        _require_key(payload, "operation_ref", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=MAX_OPERATION_REF_BYTES,
        error_code=ERROR_REQUEST_MALFORMED,
    )
    result_status = _bounded_exported_text(
        _require_key(payload, "result_status", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=16,
        error_code=ERROR_REQUEST_MALFORMED,
    )
    if result_status not in RESULT_STATUSES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    outcome_class_candidate = _bounded_exported_text(
        _require_key(payload, "outcome_class_candidate", error_code=ERROR_REQUEST_MALFORMED),
        max_bytes=64,
        error_code=ERROR_REQUEST_MALFORMED,
    )
    if outcome_class_candidate not in OUTCOME_CLASS_CANDIDATES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    target_reached = _require_key(payload, "target_reached", error_code=ERROR_REQUEST_MALFORMED)
    rollback_available = _require_key(payload, "rollback_available", error_code=ERROR_REQUEST_MALFORMED)
    if type(target_reached) is not bool or type(rollback_available) is not bool:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)

    error_code = None
    bounded_summary = None
    if result_status != "success":
        error_code = _bounded_exported_text(
            _require_key(payload, "error_code", error_code=ERROR_REQUEST_MALFORMED),
            max_bytes=MAX_ERROR_CODE_BYTES,
            error_code=ERROR_REQUEST_MALFORMED,
        )
        if error_code not in MECHANISM_ERROR_CODES:
            error_code = "internal_error"
    elif "error_code" in payload and payload["error_code"] is not None:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if "bounded_summary" in payload and payload["bounded_summary"] is not None:
        bounded_summary = _bounded_exported_text(
            payload["bounded_summary"],
            max_bytes=MAX_BOUNDED_SUMMARY_BYTES,
            error_code=ERROR_REQUEST_MALFORMED,
        )

    return ControlledAlternativeProviderResult(
        contract_version=contract_version,
        alternative_id=alternative_id,
        operation_ref=operation_ref,
        result_status=result_status,
        outcome_class_candidate=outcome_class_candidate,
        target_reached=target_reached,
        rollback_available=rollback_available,
        error_code=error_code,
        bounded_summary=bounded_summary,
    )


def _paid_snapshot_eligible(snapshot: Any) -> bool:
    if not isinstance(snapshot, PaidProviderSnapshot):
        return False
    try:
        return (
            snapshot.provider_present is True
            and snapshot.provider_id == CONTROLLED_ALTERNATIVE_PROVIDER_ID
            and snapshot.provider_contract_version == PUBLIC_PAID_PROVIDER_CONTRACT_VERSION
            and snapshot.status == STATUS_ACTIVE
            and snapshot.private_provider_enabled is True
        )
    except Exception:
        return False


def _iter_controlled_alternative_entry_points() -> Any:
    try:
        return entry_points(group=CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP)
    except TypeError:
        return entry_points().get(CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP, ())


def _load_provider_object(loaded: Any) -> tuple[ControlledAlternativeProvider | None, str | None]:
    try:
        provider = loaded() if callable(loaded) else loaded
    except Exception:
        return None, ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    if provider is None:
        return None, ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    return provider, None


def _load_named_entry_point(entry: Any) -> tuple[ControlledAlternativeProvider | None, str | None]:
    try:
        loaded = entry.load()
    except Exception:
        return None, ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    return _load_provider_object(loaded)


def _resolve_provider() -> tuple[ControlledAlternativeProvider | None, str | None]:
    if _provider_loader is not None:
        try:
            loaded = _provider_loader()
        except Exception:
            return None, ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
        return _load_provider_object(loaded)

    try:
        discovered = _iter_controlled_alternative_entry_points()
        matches = [
            entry
            for entry in discovered
            if getattr(entry, "name", None) == CONTROLLED_ALTERNATIVE_PROVIDER_ID
        ]
    except Exception:
        return None, ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    if len(matches) > 1:
        return None, ERROR_DISCOVERY_DUPLICATE_ENTRYPOINT
    if len(matches) == 1:
        return _load_named_entry_point(matches[0])
    return _resolve_vendored_controlled_alternative_provider()


def _map_vendored_controlled_alternative_error(code: str) -> str:
    if code in {"vendored_provider_missing", "handoff_hook_missing"}:
        return ERROR_DISCOVERY_ENTRYPOINT_MISSING
    if code in {"vendored_provider_multiple", "handoff_hook_multiple"}:
        return ERROR_DISCOVERY_DUPLICATE_ENTRYPOINT
    return ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED


def _resolve_vendored_controlled_alternative_provider() -> tuple[
    ControlledAlternativeProvider | None,
    str | None,
]:
    try:
        from agentveil_mcp_proxy.paid_install import (
            resolve_vendored_controlled_alternative_provider,
        )

        provider, error = resolve_vendored_controlled_alternative_provider()
    except Exception:
        return None, ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED
    if error is not None:
        return None, _map_vendored_controlled_alternative_error(error)
    if provider is None:
        return None, ERROR_DISCOVERY_ENTRYPOINT_MISSING
    return provider, None


def discover_controlled_alternative_provider(
    paid_snapshot: PaidProviderSnapshot | None,
) -> ControlledAlternativeDiscoveryResult:
    """Discover one compatible installed provider when paid activation is eligible."""

    if not _paid_snapshot_eligible(paid_snapshot):
        return ControlledAlternativeDiscoveryResult(
            available=False,
            error_code=ERROR_DISCOVERY_INELIGIBLE,
        )
    provider, resolve_error = _resolve_provider()
    if resolve_error is not None:
        return ControlledAlternativeDiscoveryResult(available=False, error_code=resolve_error)
    if provider is None:
        return ControlledAlternativeDiscoveryResult(
            available=False,
            error_code=ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED,
        )
    try:
        descriptor = validate_provider_descriptor(provider.descriptor())
    except ControlledAlternativeValidationError as exc:
        code = str(exc.args[0]) if exc.args else ERROR_DESCRIPTOR_INVALID
        return ControlledAlternativeDiscoveryResult(available=False, error_code=code)
    except Exception:
        return ControlledAlternativeDiscoveryResult(
            available=False,
            error_code=ERROR_DESCRIPTOR_INVALID,
        )
    return ControlledAlternativeDiscoveryResult(available=True, descriptor=descriptor)


def _input_schema_for_alternative(alternative_id: str) -> dict[str, Any]:
    if alternative_id == "filesystem.stage_delete.v1":
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "maxLength": MAX_NORMALIZED_PATH_BYTES},
            },
        }
    if alternative_id in {"filesystem.restore_staged.v1", "filesystem.cleanup_staged.v1"}:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["quarantine_entry_id"],
            "properties": {
                "quarantine_entry_id": {"type": "string", "maxLength": MAX_QUARANTINE_ENTRY_ID_BYTES},
            },
        }
    if alternative_id == "protected_write.prepare_patch.v1":
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["path", "patch"],
            "properties": {
                "path": {"type": "string", "maxLength": MAX_NORMALIZED_PATH_BYTES},
                "patch": {"type": "string", "maxLength": MAX_PATCH_BYTES},
            },
        }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["worktree_path"],
        "properties": {
            "worktree_path": {"type": "string", "maxLength": MAX_NORMALIZED_PATH_BYTES},
        },
    }


def _branch_schema_for_alternative(alternative_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["alternative_id", "input"],
        "properties": {
            "alternative_id": {"const": alternative_id},
            "input": _input_schema_for_alternative(alternative_id),
            "correlation_token": {
                "type": "string",
                "maxLength": MAX_CORRELATION_TOKEN_BYTES,
            },
        },
    }


@_total(ERROR_DESCRIPTOR_INVALID)
def build_controlled_alternative_tool_schema(
    descriptor: ControlledAlternativeProviderDescriptor,
) -> dict[str, Any]:
    """Return one deterministic inert MCP tool descriptor for a compatible provider."""

    validated = validate_provider_descriptor(descriptor)
    return {
        "name": GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
        "description": (
            "Invoke one frozen controlled alternative using bounded local input only. "
            "Public MCP proxy owns authority and terminal outcomes."
        ),
        "inputSchema": {
            "oneOf": [_branch_schema_for_alternative(alt) for alt in validated.alternative_ids],
        },
    }


__all__ = [
    "CONTROLLED_ALTERNATIVE_IDS",
    "CONTROLLED_ALTERNATIVE_PROVIDER_CONTRACT_VERSION",
    "CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP",
    "CONTROLLED_ALTERNATIVE_PROVIDER_ID",
    "CONTROLLED_ALTERNATIVES_PROFILE_ID",
    "ControlledAlternativeDiscoveryResult",
    "ControlledAlternativeLocalInput",
    "ControlledAlternativeProvider",
    "ControlledAlternativeProviderDescriptor",
    "ControlledAlternativeProviderRequest",
    "ControlledAlternativeProviderResult",
    "ControlledAlternativeResourceLocator",
    "ControlledAlternativeValidationError",
    "ERROR_CONTRACT_INCOMPATIBLE",
    "ERROR_DESCRIPTOR_INVALID",
    "ERROR_DISCOVERY_DUPLICATE_ENTRYPOINT",
    "ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED",
    "ERROR_DISCOVERY_ENTRYPOINT_MISSING",
    "ERROR_DISCOVERY_INELIGIBLE",
    "ERROR_REQUEST_MALFORMED",
    "ERROR_RESULT_UNSAFE",
    "GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME",
    "build_controlled_alternative_tool_schema",
    "discover_controlled_alternative_provider",
    "set_controlled_alternative_provider_loader",
    "validate_controlled_alternative_local_input",
    "validate_provider_descriptor",
    "validate_provider_request",
    "validate_provider_result",
    "validate_resource_locator",
]
