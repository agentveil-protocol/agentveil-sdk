# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Inert public Controlled Alternatives provider seam (CA1).

This module defines bounded contract types, validation, optional discovery, and
an inert generic tool schema builder. It is not imported from live MCP runtime
paths in CA1.
"""

from __future__ import annotations

import ntpath
import os
from dataclasses import dataclass, field
from functools import wraps
from importlib.metadata import entry_points
from types import MappingProxyType
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
SEMANTIC_STAGE_DELETE_TOOL_NAME = "agentveil_stage_delete"
SEMANTIC_RESTORE_STAGED_TOOL_NAME = "agentveil_restore_staged"
SEMANTIC_CLEANUP_STAGED_TOOL_NAME = "agentveil_cleanup_staged"
SEMANTIC_PREPARE_PATCH_TOOL_NAME = "agentveil_prepare_patch"
SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME = "agentveil_apply_prepared_patch"
SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME = "agentveil_prepare_git_change"
SEMANTIC_GIT_OPERATION_TOOL_NAME = "agentveil_git_operation"
SEMANTIC_WRITE_FILE_TOOL_NAME = "agentveil_write_file"
AGENTVEIL_WRITE_FILE_DOWNSTREAM_TOOL_NAME = "write_file"
APPLY_PREPARED_PATCH_ALTERNATIVE_ID = "protected_write.apply_prepared_patch.v1"
PREPARE_GIT_CHANGE_ALTERNATIVE_ID = "git.prepare_local_change.v1"

RESTORE_QUARANTINE_ENTRY_ID_INSTRUCTION = (
    "Pass the quarantine_entry_id returned by agentveil_stage_delete."
)
STAGE_DELETE_RESTORE_HANDOFF_NOTE = (
    "Pass this quarantine_entry_id to agentveil_restore_staged. "
    "Local restore reference only; not authority or approval."
)
_SEMANTIC_ALTERNATIVE_DESCRIPTIONS: Mapping[str, str] = MappingProxyType({
    "filesystem.stage_delete.v1": (
        "Prefer this AgentVeil tool for recoverable deletion of one bounded workspace "
        "file or directory. Call agentveil_stage_delete with path before native delete; "
        "native destructive delete may be denied. Autonomous only when policy allows. "
        "On success, the result includes quarantine_entry_id. "
        f"{RESTORE_QUARANTINE_ENTRY_ID_INSTRUCTION} "
        "The ID is a local restore reference only; it is not authority or approval."
    ),
    "filesystem.restore_staged.v1": (
        "Restore one staged quarantine entry back into the workspace using "
        "agentveil_restore_staged(quarantine_entry_id). "
        f"{RESTORE_QUARANTINE_ENTRY_ID_INSTRUCTION} "
        "Autonomous only when policy allows. The ID is a local restore reference only; "
        "it is not authority or approval."
    ),
    "filesystem.cleanup_staged.v1": (
        "Permanently clean up one staged quarantine entry using "
        "agentveil_cleanup_staged(quarantine_entry_id). Requires explicit approval. "
        "This is not the autonomous next step after stage or restore."
    ),
    "protected_write.prepare_patch.v1": (
        "Prepare a bounded patch for a protected update of one existing workspace file. "
        "Call agentveil_prepare_patch with path and patch. This is not for ordinary file "
        "creation or ordinary direct writes; use native or direct write tools for those. "
        "This prepares an artifact only; it does not apply the patch or mutate the target "
        "file. Autonomous only when policy allows. On success, the result includes "
        "prepared_artifact_ref and prepared_artifact_hash. These are local preparation "
        "references only; they are not authority or approval."
    ),
    "protected_write.apply_prepared_patch.v1": (
        "Apply one previously prepared protected-write artifact using "
        "agentveil_apply_prepared_patch(prepared_artifact_ref, prepared_artifact_hash). "
        "Pass only the bounded ref and hash returned by agentveil_prepare_patch. "
        "Do not send patch text, paths, or approval fields. Autonomous only when "
        "policy allows. The ref and hash are local mechanism inputs only; they are "
        "not authority or approval."
    ),
    "git.prepare_local_change.v1": (
        "Prefer this AgentVeil tool to prepare a local Git change for review. "
        "Call agentveil_prepare_git_change with worktree_path and optional intent. "
        "Allowed intent is prepare_for_review; omitting intent is the same review-prep "
        "path. If the requested action is commit or push, call with intent=commit or "
        "intent=push; those intents are denied and the bounded denial is the controlled "
        "completion signal. This prepares a local change only; it "
        "does not commit, push, merge, or apply. Autonomous only when policy allows. "
        "Local preparation only; not authority or approval."
    ),
})
FILESYSTEM_SEMANTIC_ALTERNATIVE_IDS: frozenset[str] = frozenset({
    "filesystem.stage_delete.v1",
    "filesystem.restore_staged.v1",
    "filesystem.cleanup_staged.v1",
})
SEMANTIC_TOOL_BY_ALTERNATIVE_ID: Mapping[str, str] = MappingProxyType({
    "filesystem.stage_delete.v1": SEMANTIC_STAGE_DELETE_TOOL_NAME,
    "filesystem.restore_staged.v1": SEMANTIC_RESTORE_STAGED_TOOL_NAME,
    "filesystem.cleanup_staged.v1": SEMANTIC_CLEANUP_STAGED_TOOL_NAME,
    "protected_write.prepare_patch.v1": SEMANTIC_PREPARE_PATCH_TOOL_NAME,
    APPLY_PREPARED_PATCH_ALTERNATIVE_ID: SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME,
    PREPARE_GIT_CHANGE_ALTERNATIVE_ID: SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME,
})
SEMANTIC_ALTERNATIVE_ID_BY_TOOL: Mapping[str, str] = MappingProxyType({
    **{
        tool_name: alternative_id
        for alternative_id, tool_name in SEMANTIC_TOOL_BY_ALTERNATIVE_ID.items()
    },
    SEMANTIC_GIT_OPERATION_TOOL_NAME: PREPARE_GIT_CHANGE_ALTERNATIVE_ID,
})
SEMANTIC_CONTROLLED_ALTERNATIVE_TOOL_NAMES: frozenset[str] = frozenset(
    SEMANTIC_ALTERNATIVE_ID_BY_TOOL
)
RESERVED_CONTROLLED_ALTERNATIVE_TOOL_NAMES: frozenset[str] = frozenset({
    GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME,
    *SEMANTIC_CONTROLLED_ALTERNATIVE_TOOL_NAMES,
})

CONTROLLED_ALTERNATIVE_IDS: tuple[str, ...] = (
    "filesystem.stage_delete.v1",
    "filesystem.restore_staged.v1",
    "filesystem.cleanup_staged.v1",
    "protected_write.prepare_patch.v1",
    PREPARE_GIT_CHANGE_ALTERNATIVE_ID,
)
OPTIONAL_CONTROLLED_ALTERNATIVE_IDS: frozenset[str] = frozenset({
    APPLY_PREPARED_PATCH_ALTERNATIVE_ID,
})
KNOWN_CONTROLLED_ALTERNATIVE_IDS: frozenset[str] = (
    frozenset(CONTROLLED_ALTERNATIVE_IDS) | OPTIONAL_CONTROLLED_ALTERNATIVE_IDS
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
    "prepared_write_artifact",
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
MAX_PREPARED_ARTIFACT_REF_BYTES = 64
MAX_PREPARED_ARTIFACT_REF_CHARS = 32
MAX_PREPARED_ARTIFACT_HASH_CHARS = 64
MAX_PATCH_BYTES = 262144
MAX_AGENTVEIL_WRITE_FILE_CONTENT_BYTES = 262144
MAX_OPERATION_REF_BYTES = 64
MAX_ALTERNATIVE_ID_BYTES = 128
MAX_CORRELATION_TOKEN_BYTES = 64
MAX_BOUNDED_SUMMARY_BYTES = 240
MAX_ERROR_CODE_BYTES = 64
MAX_REQUEST_TOP_LEVEL_KEYS = 16
MAX_RESULT_TOP_LEVEL_KEYS = 14

ERROR_CONTRACT_INCOMPATIBLE = "contract_incompatible"
ERROR_DESCRIPTOR_INVALID = "descriptor_invalid"
ERROR_DISCOVERY_INELIGIBLE = "discovery_ineligible"
ERROR_DISCOVERY_ENTRYPOINT_MISSING = "discovery_entrypoint_missing"
ERROR_DISCOVERY_DUPLICATE_ENTRYPOINT = "discovery_entrypoint_duplicate"
ERROR_DISCOVERY_ENTRYPOINT_LOAD_FAILED = "discovery_entrypoint_load_failed"
ERROR_REQUEST_MALFORMED = "request_malformed"
ERROR_RESULT_UNSAFE = "result_unsafe"
ERROR_GIT_INTENT_DENIED = "git_intent_denied"
GIT_INTENT_PREPARE_FOR_REVIEW = "prepare_for_review"
GIT_INTENT_COMMIT = "commit"
GIT_INTENT_PUSH = "push"
GIT_INTENT_FORBIDDEN = frozenset({GIT_INTENT_COMMIT, GIT_INTENT_PUSH})
GIT_INTENT_VALUES = (
    GIT_INTENT_PREPARE_FOR_REVIEW,
    GIT_INTENT_COMMIT,
    GIT_INTENT_PUSH,
)
MAX_GIT_INTENT_BYTES = 32


def git_intent_denied_local_payload() -> dict[str, Any]:
    """Bounded local MCP denial for explicit commit/push Git intent."""

    return {
        "mechanism_status": "error",
        "error_code": ERROR_GIT_INTENT_DENIED,
        "result_status": "denied",
        "decision": "denied",
        "target_reached": False,
        "rollback_available": False,
        "verification_level": "not_verified",
    }


def projected_controlled_alternative_validation_payload(
    exc: ControlledAlternativeValidationError,
) -> dict[str, Any]:
    """Project one public validation error onto the local MCP result shape."""

    code = str(exc.args[0]) if exc.args else ERROR_REQUEST_MALFORMED
    if code == ERROR_GIT_INTENT_DENIED:
        return git_intent_denied_local_payload()
    return {
        "mechanism_status": "error",
        "error_code": ERROR_REQUEST_MALFORMED,
        "target_reached": False,
        "rollback_available": False,
        "verification_level": "not_verified",
    }


_UNSAFE_STAGE_DELETE_BASENAMES = frozenset({
    "secrets.env",
    ".env",
    ".envrc",
    ".netrc",
    ".pgpass",
    ".htpasswd",
    "credentials",
    "credentials.json",
    "credentials.yml",
    "credentials.yaml",
    "id_rsa",
    "id_rsa.pub",
    "id_dsa",
    "id_dsa.pub",
    "id_ecdsa",
    "id_ecdsa.pub",
    "id_ed25519",
    "id_ed25519.pub",
})
_UNSAFE_STAGE_DELETE_SUFFIXES = (".pem", ".p12", ".pfx")
_UNSAFE_LOCKED_CONFIG_BASENAMES = frozenset({
    "locked_config.yaml",
    "locked_config.yml",
    "locked_config.json",
    "locked_config.toml",
    "locked_config.ini",
    "locked_config.cfg",
})
_UNSAFE_REDIRECT_ALTERNATIVE_IDS = frozenset({
    "filesystem.stage_delete.v1",
    "protected_write.prepare_patch.v1",
})


def _path_components_for_eligibility(raw_path: str) -> tuple[str, ...]:
    text = raw_path.replace("\\", "/")
    _drive, tail = ntpath.splitdrive(text)
    return tuple(part for part in tail.split("/") if part and part not in {".", ".."})


def _component_is_secret_or_credential(name: str) -> bool:
    lowered = name.lower()
    if lowered in _UNSAFE_STAGE_DELETE_BASENAMES:
        return True
    if lowered.startswith(".env."):
        return True
    return lowered.endswith(_UNSAFE_STAGE_DELETE_SUFFIXES)


def _component_is_locked_config(name: str) -> bool:
    lowered = name.lower()
    if lowered in _UNSAFE_LOCKED_CONFIG_BASENAMES:
        return True
    return lowered.startswith("locked_config.")


def controlled_alternative_target_is_ineligible(alternative_id: str, raw_path: Any) -> bool:
    """Return True when a public request path must not become a stage/apply alternative."""

    if alternative_id not in _UNSAFE_REDIRECT_ALTERNATIVE_IDS:
        return False
    if not isinstance(raw_path, str) or not raw_path:
        return False
    if raw_path != raw_path.strip() or any(ord(ch) < 32 for ch in raw_path):
        return True
    parts = _path_components_for_eligibility(raw_path)
    if alternative_id == "filesystem.stage_delete.v1":
        return any(_component_is_secret_or_credential(part) for part in parts)
    return any(_component_is_locked_config(part) for part in parts)


def _reject_ineligible_controlled_alternative_target(alternative_id: str, raw_path: Any) -> None:
    if controlled_alternative_target_is_ineligible(alternative_id, raw_path):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)


def _require_optional_git_intent(payload: Mapping[str, Any]) -> str | None:
    """Return allowlisted review-prep intent or reject invalid input. Do not coerce."""

    if "intent" not in payload:
        return None
    raw = payload["intent"]
    if not isinstance(raw, str):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if raw != raw.strip() or not raw or any(ord(ch) < 32 for ch in raw):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    encoded = raw.encode("utf-8")
    if len(encoded) > MAX_GIT_INTENT_BYTES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if raw in GIT_INTENT_FORBIDDEN:
        raise ControlledAlternativeValidationError(ERROR_GIT_INTENT_DENIED)
    if raw != GIT_INTENT_PREPARE_FOR_REVIEW:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return raw


def _require_git_operation(payload: Mapping[str, Any]) -> str:
    """Return allowlisted Git operation or reject invalid input. Do not coerce."""

    if "operation" not in payload:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    raw = payload["operation"]
    if not isinstance(raw, str):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if raw != raw.strip() or not raw or any(ord(ch) < 32 for ch in raw):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    encoded = raw.encode("utf-8")
    if len(encoded) > MAX_GIT_INTENT_BYTES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if raw in GIT_INTENT_FORBIDDEN:
        raise ControlledAlternativeValidationError(ERROR_GIT_INTENT_DENIED)
    if raw != GIT_INTENT_PREPARE_FOR_REVIEW:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return raw


_LOCAL_INPUT_REQUIRED_KEYS: dict[str, frozenset[str]] = {
    "filesystem.stage_delete.v1": frozenset({"path"}),
    "filesystem.restore_staged.v1": frozenset({"quarantine_entry_id"}),
    "filesystem.cleanup_staged.v1": frozenset({"quarantine_entry_id"}),
    "protected_write.prepare_patch.v1": frozenset({"path", "patch"}),
    APPLY_PREPARED_PATCH_ALTERNATIVE_ID: frozenset({
        "prepared_artifact_ref",
        "prepared_artifact_hash",
    }),
    "git.prepare_local_change.v1": frozenset({"worktree_path"}),
}
_LOCAL_INPUT_OPTIONAL_KEYS: dict[str, frozenset[str]] = {
    PREPARE_GIT_CHANGE_ALTERNATIVE_ID: frozenset({"intent"}),
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
    APPLY_PREPARED_PATCH_ALTERNATIVE_ID: {
        "kind": "prepared_write_artifact",
        "required": frozenset({"locator_kind", "route_id", "st_dev"}) | _TRUSTED_ROOT_FIELDS,
        "optional": frozenset({"correlation_token"}),
        "forbidden": frozenset({"normalized_path", "quarantine_entry_id"}),
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
    prepared_artifact_ref: str | None = None
    prepared_artifact_hash: str | None = None

    def __repr__(self) -> str:
        return (
            "ControlledAlternativeLocalInput("
            f"alternative_id={self.alternative_id!r}, "
            "path='***', "
            "quarantine_entry_id='***', "
            "patch='***', "
            "worktree_path='***', "
            "prepared_artifact_ref='***', "
            "prepared_artifact_hash='***')"
        )

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class ControlledAlternativeBoundedLocalInput:
    alternative_id: str
    patch: str | None = None
    prepared_artifact_ref: str | None = None
    prepared_artifact_hash: str | None = None

    def __repr__(self) -> str:
        return (
            "ControlledAlternativeBoundedLocalInput("
            f"alternative_id={self.alternative_id!r}, "
            "patch='***', "
            "prepared_artifact_ref='***', "
            "prepared_artifact_hash='***')"
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
    quarantine_entry_id: str | None = None
    prepared_artifact_ref: str | None = None
    prepared_artifact_hash: str | None = None

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
            "bounded_summary='***', "
            "quarantine_entry_id='***', "
            "prepared_artifact_ref='***', "
            "prepared_artifact_hash='***')"
        )

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class ControlledAlternativeDiscoveryResult:
    available: bool
    descriptor: ControlledAlternativeProviderDescriptor | None = None
    error_code: str | None = None
    provider: Any = field(default=None, repr=False, compare=False)


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


def _reject_untrusted_workspace_relpath(value: str) -> None:
    """Reject absolute, traversal, drive, or control-character agent paths.

    Do not coerce these into a workspace-relative path. Drive-prefix detection
    uses ntpath in addition to os.path for Windows drive-prefix detection.
    """

    if (
        os.path.isabs(value)
        or os.path.splitdrive(value)[0]
        or ntpath.splitdrive(value)[0]
        or value.startswith("~")
    ):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if any(ord(ch) < 32 for ch in value):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    parts = value.replace("\\", "/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)


def _reject_untrusted_git_worktree_relpath(value: str) -> None:
    """Reject untrusted Git worktree paths while allowing `.` for the workspace root."""

    if value != value.strip():
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if value == ".":
        return
    _reject_untrusted_workspace_relpath(value)


_PREPARE_PATCH_ADD_FILE_PREFIX = "*** Add File:"


def _prepare_patch_is_clear_create(patch: str) -> bool:
    for raw_line in patch.splitlines():
        if raw_line.startswith(_PREPARE_PATCH_ADD_FILE_PREFIX):
            return True
    return False


def _reject_create_file_prepare_patch(value: str) -> None:
    if _prepare_patch_is_clear_create(value):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)


def _reject_untrusted_patch_text(value: str) -> None:
    if "\0" in value:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    _reject_create_file_prepare_patch(value)


def normalize_agentveil_write_file_call(arguments: Mapping[str, Any]) -> dict[str, str]:
    """Return exact downstream write_file arguments for the AgentVeil-owned write alias."""

    payload = _require_mapping(arguments, error_code=ERROR_REQUEST_MALFORMED)
    if len(payload) > MAX_GENERIC_INPUT_FIELDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    required = frozenset({"path", "content"})
    _assert_no_authority_keys(payload)
    _assert_no_extra_keys(payload, required, error_code=ERROR_REQUEST_MALFORMED)
    if set(payload) != required:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    raw_path = payload["path"]
    content = payload["content"]
    if not isinstance(raw_path, str) or not isinstance(content, str):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if raw_path != raw_path.strip():
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if len(raw_path.encode("utf-8")) > MAX_NORMALIZED_PATH_BYTES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    _reject_untrusted_workspace_relpath(raw_path)
    if "\0" in content or len(content.encode("utf-8")) > MAX_AGENTVEIL_WRITE_FILE_CONTENT_BYTES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return {"path": raw_path, "content": content}


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


_RESULT_QUARANTINE_ENTRY_ID_ALPHABET = frozenset("0123456789abcdef")
_STAGE_DELETE_ALTERNATIVE_ID = "filesystem.stage_delete.v1"


def _require_result_quarantine_entry_id(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 32:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if len(value.encode("utf-8")) > MAX_QUARANTINE_ENTRY_ID_BYTES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if any(char not in _RESULT_QUARANTINE_ENTRY_ID_ALPHABET for char in value):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return value


def _validate_result_quarantine_entry_id(
    payload: Mapping[str, Any],
    *,
    alternative_id: str,
    result_status: str,
    target_reached: bool,
    rollback_available: bool,
) -> str | None:
    present = "quarantine_entry_id" in payload
    entry_id = None
    if present:
        entry_id = _require_result_quarantine_entry_id(payload["quarantine_entry_id"])
    stage_delete = alternative_id == _STAGE_DELETE_ALTERNATIVE_ID
    if stage_delete and not target_reached and rollback_available:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if stage_delete and result_status == "success" and target_reached and not rollback_available:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    required = stage_delete and target_reached and rollback_available
    if required:
        if entry_id is None:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        return entry_id
    if present:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return None


_PREPARED_WRITE_ALTERNATIVE_ID = "protected_write.prepare_patch.v1"
_PREPARED_WRITE_SUCCESS_OUTCOME = "PREPARED_FOR_APPROVAL"
_PREPARED_ARTIFACT_HASH_ALPHABET = frozenset("0123456789abcdef")
_PREPARED_ARTIFACT_REF_ALPHABET = _PREPARED_ARTIFACT_HASH_ALPHABET
_PREPARED_ARTIFACT_REF_PATH_MARKERS = (
    "/",
    "\\",
    ":",
    "~",
    "..",
)
_PREPARED_ARTIFACT_REF_AUTHORITY_MARKERS = frozenset({
    *AUTHORITY_FORBIDDEN_RESULT_KEYS,
    "approval",
    "approval_id",
    "evidence",
    "evidence_id",
    "authority",
    "bounded_summary",
    "operation_ref",
    "quarantine_entry_id",
})


def _prepared_artifact_ref_is_path_like(value: str) -> bool:
    if value.startswith((".", "~")):
        return True
    if os.path.isabs(value):
        return True
    lowered = value.lower()
    if any(marker in lowered for marker in ("/users/", "/home/", "/private/", "/var/", "/tmp/", "c:\\")):
        return True
    return any(marker in value for marker in _PREPARED_ARTIFACT_REF_PATH_MARKERS)


def _prepared_artifact_ref_is_authority_like(value: str) -> bool:
    lowered = value.lower()
    if lowered in _PREPARED_ARTIFACT_REF_AUTHORITY_MARKERS:
        return True
    return any(marker in lowered for marker in _PREPARED_ARTIFACT_REF_AUTHORITY_MARKERS)


def _require_prepared_artifact_hash(value: Any) -> str:
    if not isinstance(value, str) or len(value) != MAX_PREPARED_ARTIFACT_HASH_CHARS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if any(char not in _PREPARED_ARTIFACT_HASH_ALPHABET for char in value):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return value


def _require_prepared_artifact_ref(
    value: Any,
    *,
    operation_ref: str,
    bounded_summary: str | None,
) -> str:
    if not isinstance(value, str):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    encoded_len = len(value.encode("utf-8"))
    if not value or encoded_len > MAX_PREPARED_ARTIFACT_REF_BYTES:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if _prepared_artifact_ref_is_path_like(value):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if _prepared_artifact_ref_is_authority_like(value):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if value == operation_ref or (bounded_summary is not None and value == bounded_summary):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if contains_private_provider_marker(value):
        raise ControlledAlternativeValidationError(ERROR_RESULT_UNSAFE)
    lowered = value.lower()
    if any(marker in lowered for marker in FORBIDDEN_PRIVATE_MARKERS):
        raise ControlledAlternativeValidationError(ERROR_RESULT_UNSAFE)
    if len(value) != MAX_PREPARED_ARTIFACT_REF_CHARS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if any(char not in _PREPARED_ARTIFACT_REF_ALPHABET for char in value):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return value


def _validate_result_prepared_artifact(
    payload: Mapping[str, Any],
    *,
    alternative_id: str,
    result_status: str,
    outcome_class_candidate: str,
    target_reached: bool,
    rollback_available: bool,
    operation_ref: str,
    bounded_summary: str | None,
) -> tuple[str | None, str | None]:
    ref_present = "prepared_artifact_ref" in payload
    hash_present = "prepared_artifact_hash" in payload
    artifact_ref = None
    artifact_hash = None
    if ref_present:
        artifact_ref = _require_prepared_artifact_ref(
            payload["prepared_artifact_ref"],
            operation_ref=operation_ref,
            bounded_summary=bounded_summary,
        )
    if hash_present:
        artifact_hash = _require_prepared_artifact_hash(payload["prepared_artifact_hash"])
    required = (
        alternative_id == _PREPARED_WRITE_ALTERNATIVE_ID
        and result_status == "success"
        and outcome_class_candidate == _PREPARED_WRITE_SUCCESS_OUTCOME
        and target_reached is False
        and rollback_available is False
    )
    if required:
        if artifact_ref is None or artifact_hash is None:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        return artifact_ref, artifact_hash
    if ref_present or hash_present:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return None, None


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
        if raw.quarantine_entry_id is not None:
            mapping["quarantine_entry_id"] = raw.quarantine_entry_id
        if raw.prepared_artifact_ref is not None:
            mapping["prepared_artifact_ref"] = raw.prepared_artifact_ref
        if raw.prepared_artifact_hash is not None:
            mapping["prepared_artifact_hash"] = raw.prepared_artifact_hash
        return mapping
    return _require_mapping(raw, error_code=ERROR_REQUEST_MALFORMED)


@_total(ERROR_REQUEST_MALFORMED)
def validate_controlled_alternative_local_input(
    alternative_id: str,
    raw_input: Mapping[str, Any],
) -> ControlledAlternativeLocalInput:
    """Validate one family-specific local input object."""

    alt = _bounded_local_text(alternative_id, max_bytes=MAX_ALTERNATIVE_ID_BYTES)
    if alt not in KNOWN_CONTROLLED_ALTERNATIVE_IDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    payload = _require_mapping(raw_input, error_code=ERROR_REQUEST_MALFORMED)
    if len(payload) > MAX_GENERIC_INPUT_FIELDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    required = _LOCAL_INPUT_REQUIRED_KEYS[alt]
    optional = _LOCAL_INPUT_OPTIONAL_KEYS.get(alt, frozenset())
    allowed = required | optional
    _assert_no_authority_keys(payload)
    _assert_no_extra_keys(payload, allowed, error_code=ERROR_REQUEST_MALFORMED)
    if not required <= set(payload):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)

    if alt == "filesystem.stage_delete.v1":
        raw_path = _require_key(payload, "path", error_code=ERROR_REQUEST_MALFORMED)
        _reject_ineligible_controlled_alternative_target(alt, raw_path)
        return ControlledAlternativeLocalInput(
            alternative_id=alt,
            path=_bounded_local_text(raw_path, max_bytes=MAX_NORMALIZED_PATH_BYTES),
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
        raw_path = _require_key(payload, "path", error_code=ERROR_REQUEST_MALFORMED)
        raw_patch = _require_key(payload, "patch", error_code=ERROR_REQUEST_MALFORMED)
        _reject_ineligible_controlled_alternative_target(alt, raw_path)
        patch = _bounded_local_text(raw_patch, max_bytes=MAX_PATCH_BYTES)
        _reject_untrusted_patch_text(patch)
        return ControlledAlternativeLocalInput(
            alternative_id=alt,
            path=_bounded_local_text(raw_path, max_bytes=MAX_NORMALIZED_PATH_BYTES),
            patch=patch,
        )
    if alt == APPLY_PREPARED_PATCH_ALTERNATIVE_ID:
        return ControlledAlternativeLocalInput(
            alternative_id=alt,
            prepared_artifact_ref=_require_prepared_artifact_ref(
                _require_key(payload, "prepared_artifact_ref", error_code=ERROR_REQUEST_MALFORMED),
                operation_ref="",
                bounded_summary=None,
            ),
            prepared_artifact_hash=_require_prepared_artifact_hash(
                _require_key(payload, "prepared_artifact_hash", error_code=ERROR_REQUEST_MALFORMED),
            ),
        )
    _require_optional_git_intent(payload)
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
    required = CONTROLLED_ALTERNATIVE_IDS
    if alt_tuple[: len(required)] != required:
        raise ControlledAlternativeValidationError(ERROR_DESCRIPTOR_INVALID)
    extra = alt_tuple[len(required) :]
    if extra not in {(), (APPLY_PREPARED_PATCH_ALTERNATIVE_ID,)}:
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
    if alternative_id == APPLY_PREPARED_PATCH_ALTERNATIVE_ID:
        if bounded_local_input is None:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        if bounded_local_input.alternative_id != alternative_id:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        if resource_locator.normalized_path is not None:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        if (
            bounded_local_input.prepared_artifact_ref is None
            or bounded_local_input.prepared_artifact_hash is None
        ):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        return
    if bounded_local_input is not None:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)


def _validate_provider_bounded_local_input(
    alternative_id: str,
    raw_input: Mapping[str, Any],
) -> ControlledAlternativeBoundedLocalInput:
    payload = _require_mapping(raw_input, error_code=ERROR_REQUEST_MALFORMED)
    if len(payload) > MAX_GENERIC_INPUT_FIELDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    if alternative_id == "protected_write.prepare_patch.v1":
        allowed = frozenset({"patch"})
        _assert_no_authority_keys(payload)
        _assert_no_extra_keys(payload, allowed, error_code=ERROR_REQUEST_MALFORMED)
        if set(payload) != allowed:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        patch = _bounded_local_text(
            _require_key(payload, "patch", error_code=ERROR_REQUEST_MALFORMED),
            max_bytes=MAX_PATCH_BYTES,
        )
        _reject_untrusted_patch_text(patch)
        return ControlledAlternativeBoundedLocalInput(
            alternative_id=alternative_id,
            patch=patch,
        )
    if alternative_id == APPLY_PREPARED_PATCH_ALTERNATIVE_ID:
        allowed = frozenset({"prepared_artifact_ref", "prepared_artifact_hash"})
        _assert_no_authority_keys(payload)
        _assert_no_extra_keys(payload, allowed, error_code=ERROR_REQUEST_MALFORMED)
        if set(payload) != allowed:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        return ControlledAlternativeBoundedLocalInput(
            alternative_id=alternative_id,
            prepared_artifact_ref=_require_prepared_artifact_ref(
                _require_key(payload, "prepared_artifact_ref", error_code=ERROR_REQUEST_MALFORMED),
                operation_ref="",
                bounded_summary=None,
            ),
            prepared_artifact_hash=_require_prepared_artifact_hash(
                _require_key(payload, "prepared_artifact_hash", error_code=ERROR_REQUEST_MALFORMED),
            ),
        )
    raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)


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
    if alternative_id not in KNOWN_CONTROLLED_ALTERNATIVE_IDS:
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
        "quarantine_entry_id",
        "prepared_artifact_ref",
        "prepared_artifact_hash",
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
    if alternative_id not in KNOWN_CONTROLLED_ALTERNATIVE_IDS:
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
    quarantine_entry_id = _validate_result_quarantine_entry_id(
        payload,
        alternative_id=alternative_id,
        result_status=result_status,
        target_reached=target_reached,
        rollback_available=rollback_available,
    )
    prepared_artifact_ref, prepared_artifact_hash = _validate_result_prepared_artifact(
        payload,
        alternative_id=alternative_id,
        result_status=result_status,
        outcome_class_candidate=outcome_class_candidate,
        target_reached=target_reached,
        rollback_available=rollback_available,
        operation_ref=operation_ref,
        bounded_summary=bounded_summary,
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
        quarantine_entry_id=quarantine_entry_id,
        prepared_artifact_ref=prepared_artifact_ref,
        prepared_artifact_hash=prepared_artifact_hash,
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
    return ControlledAlternativeDiscoveryResult(
        available=True,
        descriptor=descriptor,
        provider=provider,
    )


def _input_schema_for_alternative(alternative_id: str) -> dict[str, Any]:
    if alternative_id == "filesystem.stage_delete.v1":
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "string",
                    "maxLength": MAX_NORMALIZED_PATH_BYTES,
                    "description": (
                        "Bounded workspace-relative path to stage. On success, pass the "
                        "returned quarantine_entry_id to agentveil_restore_staged."
                    ),
                },
            },
        }
    if alternative_id == "filesystem.restore_staged.v1":
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["quarantine_entry_id"],
            "properties": {
                "quarantine_entry_id": {
                    "type": "string",
                    "maxLength": MAX_QUARANTINE_ENTRY_ID_BYTES,
                    "description": (
                        f"{RESTORE_QUARANTINE_ENTRY_ID_INSTRUCTION} "
                        "Local restore reference only; not authority or approval."
                    ),
                },
            },
        }
    if alternative_id == "filesystem.cleanup_staged.v1":
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["quarantine_entry_id"],
            "properties": {
                "quarantine_entry_id": {
                    "type": "string",
                    "maxLength": MAX_QUARANTINE_ENTRY_ID_BYTES,
                    "description": (
                        "Quarantine entry ID for permanent cleanup. Requires explicit "
                        "approval. Not the autonomous next step after stage or restore."
                    ),
                },
            },
        }
    if alternative_id == "protected_write.prepare_patch.v1":
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["path", "patch"],
            "properties": {
                "path": {
                    "type": "string",
                    "maxLength": MAX_NORMALIZED_PATH_BYTES,
                    "description": (
                        "Bounded workspace-relative path of an existing file to update. "
                        "This tool does not create a new file, apply the patch, or mutate "
                        "the target file."
                    ),
                },
                "patch": {
                    "type": "string",
                    "maxLength": MAX_PATCH_BYTES,
                    "description": (
                        "Bounded update patch for an existing file. Do not send Add File "
                        "or create-file payloads. Local preparation reference only; not "
                        "authority or approval."
                    ),
                },
            },
        }
    if alternative_id == APPLY_PREPARED_PATCH_ALTERNATIVE_ID:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["prepared_artifact_ref", "prepared_artifact_hash"],
            "properties": {
                "prepared_artifact_ref": {
                    "type": "string",
                    "minLength": MAX_PREPARED_ARTIFACT_REF_CHARS,
                    "maxLength": MAX_PREPARED_ARTIFACT_REF_CHARS,
                    "description": (
                        "Bounded prepared artifact reference returned by "
                        "agentveil_prepare_patch. Local mechanism input only; not "
                        "authority or approval."
                    ),
                },
                "prepared_artifact_hash": {
                    "type": "string",
                    "minLength": MAX_PREPARED_ARTIFACT_HASH_CHARS,
                    "maxLength": MAX_PREPARED_ARTIFACT_HASH_CHARS,
                    "description": (
                        "Bounded hash of the prepared artifact. Local mechanism "
                        "input only; not authority or approval."
                    ),
                },
            },
        }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["worktree_path"],
        "properties": {
            "worktree_path": {
                "type": "string",
                "maxLength": MAX_NORMALIZED_PATH_BYTES,
                "description": (
                    "Bounded workspace-relative Git worktree path to prepare. "
                    "Use . for the current managed workspace. This tool does not "
                    "commit, push, merge, or apply."
                ),
            },
            "intent": {
                "type": "string",
                "enum": list(GIT_INTENT_VALUES),
                "description": (
                    "Allowlisted Git intent. prepare_for_review is the review-prep "
                    "path. commit and push are denied. Omit this field for the same "
                    "review-prep path. Local mechanism input only; not authority or "
                    "approval."
                ),
            },
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


def is_semantic_controlled_alternative_tool(tool_name: Any) -> bool:
    if not isinstance(tool_name, str):
        return False
    return tool_name in SEMANTIC_ALTERNATIVE_ID_BY_TOOL


def is_controlled_alternative_tool_name(tool_name: str) -> bool:
    return (
        tool_name == GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME
        or is_semantic_controlled_alternative_tool(tool_name)
    )


def semantic_alternative_id_for_tool(tool_name: Any) -> str | None:
    if not isinstance(tool_name, str):
        return None
    return SEMANTIC_ALTERNATIVE_ID_BY_TOOL.get(tool_name)


def semantic_tool_name_for_alternative_id(alternative_id: Any) -> str | None:
    if not isinstance(alternative_id, str):
        return None
    return SEMANTIC_TOOL_BY_ALTERNATIVE_ID.get(alternative_id)


@_total(ERROR_REQUEST_MALFORMED)
def normalize_semantic_tool_call(
    tool_name: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    """Map one semantic MCP tool call onto the generic controlled-alternative shape."""

    alternative_id = semantic_alternative_id_for_tool(tool_name)
    if alternative_id is None:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    payload = _require_mapping(arguments, error_code=ERROR_REQUEST_MALFORMED)
    if tool_name == SEMANTIC_GIT_OPERATION_TOOL_NAME:
        return _normalize_semantic_git_operation_call(payload)
    if alternative_id == PREPARE_GIT_CHANGE_ALTERNATIVE_ID:
        raw_worktree = payload.get("worktree_path")
        if not isinstance(raw_worktree, str):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        _reject_untrusted_git_worktree_relpath(raw_worktree)
    local = validate_controlled_alternative_local_input(alternative_id, payload)
    if alternative_id == "filesystem.stage_delete.v1":
        raw_path = payload.get("path")
        if not isinstance(raw_path, str):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        _reject_untrusted_workspace_relpath(raw_path)
        nested = {"path": local.path}
    elif alternative_id in {"filesystem.restore_staged.v1", "filesystem.cleanup_staged.v1"}:
        nested = {"quarantine_entry_id": local.quarantine_entry_id}
    elif alternative_id == "protected_write.prepare_patch.v1":
        raw_path = payload.get("path")
        raw_patch = payload.get("patch")
        if not isinstance(raw_path, str) or not isinstance(raw_patch, str):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        _reject_untrusted_workspace_relpath(raw_path)
        nested = {"path": local.path, "patch": local.patch}
    elif alternative_id == APPLY_PREPARED_PATCH_ALTERNATIVE_ID:
        if local.prepared_artifact_ref is None or local.prepared_artifact_hash is None:
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        nested = {
            "prepared_artifact_ref": local.prepared_artifact_ref,
            "prepared_artifact_hash": local.prepared_artifact_hash,
        }
    elif alternative_id == PREPARE_GIT_CHANGE_ALTERNATIVE_ID:
        raw_worktree = payload.get("worktree_path")
        if (
            not isinstance(raw_worktree, str)
            or local.worktree_path is None
            or raw_worktree != local.worktree_path
        ):
            raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
        nested = {"worktree_path": raw_worktree}
        if "intent" in payload:
            nested["intent"] = payload["intent"]
    else:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return {"alternative_id": alternative_id, "input": nested}


def _normalize_semantic_git_operation_call(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Map agentveil_git_operation onto the existing public Git prepare path."""

    if len(payload) > MAX_GENERIC_INPUT_FIELDS:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    allowed = frozenset({"worktree_path", "operation"})
    _assert_no_authority_keys(payload)
    _assert_no_extra_keys(payload, allowed, error_code=ERROR_REQUEST_MALFORMED)
    if not allowed <= set(payload):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    _require_git_operation(payload)
    raw_worktree = payload.get("worktree_path")
    if not isinstance(raw_worktree, str):
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    _reject_untrusted_git_worktree_relpath(raw_worktree)
    local = validate_controlled_alternative_local_input(
        PREPARE_GIT_CHANGE_ALTERNATIVE_ID,
        {"worktree_path": raw_worktree},
    )
    if local.worktree_path is None or raw_worktree != local.worktree_path:
        raise ControlledAlternativeValidationError(ERROR_REQUEST_MALFORMED)
    return {
        "alternative_id": PREPARE_GIT_CHANGE_ALTERNATIVE_ID,
        "input": {
            "worktree_path": raw_worktree,
            "intent": GIT_INTENT_PREPARE_FOR_REVIEW,
        },
    }


def _git_operation_input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["worktree_path", "operation"],
        "properties": {
            "worktree_path": {
                "type": "string",
                "maxLength": MAX_NORMALIZED_PATH_BYTES,
                "description": (
                    "Bounded workspace-relative Git worktree path. Use . for the "
                    "current managed workspace. This tool does not commit, push, "
                    "merge, or apply."
                ),
            },
            "operation": {
                "type": "string",
                "enum": list(GIT_INTENT_VALUES),
                "description": (
                    "Allowlisted Git operation. prepare_for_review prepares a local "
                    "change for review. commit and push are not authorized and are "
                    "denied; that bounded denial is the controlled completion signal. "
                    "Local mechanism input only; not authority or approval."
                ),
            },
        },
    }


def build_semantic_git_operation_tool_schema() -> dict[str, Any]:
    return {
        "name": SEMANTIC_GIT_OPERATION_TOOL_NAME,
        "description": (
            "Prefer this AgentVeil tool for Git operations in this managed workspace. "
            "Call agentveil_git_operation with worktree_path and operation before native "
            "Git. Allowed operation is prepare_for_review, commit, or push. "
            "prepare_for_review prepares a local change for review. commit and push are "
            "not authorized and are denied; for explicit commit or push requests, "
            "that bounded denial is the controlled completion signal. This does not commit, push, merge, or "
            "apply. Autonomous only when policy allows. Local preparation only; not "
            "authority or approval."
        ),
        "inputSchema": _git_operation_input_schema(),
    }


def build_agentveil_write_file_tool_schema() -> dict[str, Any]:
    return {
        "name": SEMANTIC_WRITE_FILE_TOOL_NAME,
        "description": (
            "Write one bounded workspace-relative text file through the AgentVeil MCP "
            "proxy route. Use this for ordinary in-scope file creation or ordinary "
            "direct writes instead of protected patch preparation. This is not a "
            "controlled alternative, not authority, and not approval; AgentVeil still "
            "classifies and enforces policy before forwarding to the downstream "
            "write_file tool."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["path", "content"],
            "properties": {
                "path": {
                    "type": "string",
                    "maxLength": MAX_NORMALIZED_PATH_BYTES,
                    "description": (
                        "Exact bounded workspace-relative path to write. Absolute, "
                        "traversal, drive-style, whitespace-padded, and control-character "
                        "paths are rejected."
                    ),
                },
                "content": {
                    "type": "string",
                    "maxLength": MAX_AGENTVEIL_WRITE_FILE_CONTENT_BYTES,
                    "description": (
                        "Bounded text content to write. This field is forwarded to the "
                        "downstream write_file tool after AgentVeil policy enforcement."
                    ),
                },
            },
        },
    }


def _tools_list_entries(response: Any) -> list[Any] | None:
    if not isinstance(response, Mapping):
        return None
    result = response.get("result")
    if not isinstance(result, Mapping):
        return None
    tools = result.get("tools")
    return tools if isinstance(tools, list) else None


def agentveil_write_file_catalog_collision(response: Any) -> bool:
    tools = _tools_list_entries(response)
    if tools is None:
        return False
    return any(
        isinstance(tool, Mapping)
        and tool.get("name") == SEMANTIC_WRITE_FILE_TOOL_NAME
        for tool in tools
    )


def inject_agentveil_write_file_tool(response: Any) -> Any:
    """Append the AgentVeil-owned direct write alias when downstream has write_file."""

    tools = _tools_list_entries(response)
    if tools is None or agentveil_write_file_catalog_collision(response):
        return response
    names = {
        tool.get("name")
        for tool in tools
        if isinstance(tool, Mapping) and isinstance(tool.get("name"), str)
    }
    if AGENTVEIL_WRITE_FILE_DOWNSTREAM_TOOL_NAME not in names:
        return response
    injected = dict(response)
    result = dict(injected["result"])
    result["tools"] = [*tools, build_agentveil_write_file_tool_schema()]
    injected["result"] = result
    return injected


def build_semantic_controlled_alternative_tool_schema(alternative_id: Any) -> dict[str, Any]:
    if not isinstance(alternative_id, str):
        raise ControlledAlternativeValidationError(ERROR_DESCRIPTOR_INVALID)
    tool_name = semantic_tool_name_for_alternative_id(alternative_id)
    if tool_name is None:
        raise ControlledAlternativeValidationError(ERROR_DESCRIPTOR_INVALID)
    description = _SEMANTIC_ALTERNATIVE_DESCRIPTIONS.get(alternative_id)
    if description is None:
        raise ControlledAlternativeValidationError(ERROR_DESCRIPTOR_INVALID)
    return {
        "name": tool_name,
        "description": description,
        "inputSchema": _input_schema_for_alternative(alternative_id),
    }


@_total(ERROR_DESCRIPTOR_INVALID)
def build_semantic_controlled_alternative_tool_schemas(
    descriptor: ControlledAlternativeProviderDescriptor,
) -> tuple[dict[str, Any], ...]:
    """Return descriptor-driven semantic tool schemas for advertised alternatives."""

    validated = validate_provider_descriptor(descriptor)
    schemas: list[dict[str, Any]] = []
    for alternative_id in validated.alternative_ids:
        if alternative_id not in SEMANTIC_TOOL_BY_ALTERNATIVE_ID:
            continue
        schemas.append(build_semantic_controlled_alternative_tool_schema(alternative_id))
        if alternative_id == PREPARE_GIT_CHANGE_ALTERNATIVE_ID:
            schemas.append(build_semantic_git_operation_tool_schema())
    return tuple(schemas)


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
    "AGENTVEIL_WRITE_FILE_DOWNSTREAM_TOOL_NAME",
    "FILESYSTEM_SEMANTIC_ALTERNATIVE_IDS",
    "APPLY_PREPARED_PATCH_ALTERNATIVE_ID",
    "PREPARE_GIT_CHANGE_ALTERNATIVE_ID",
    "GENERIC_CONTROLLED_ALTERNATIVE_TOOL_NAME",
    "KNOWN_CONTROLLED_ALTERNATIVE_IDS",
    "OPTIONAL_CONTROLLED_ALTERNATIVE_IDS",
    "RESERVED_CONTROLLED_ALTERNATIVE_TOOL_NAMES",
    "RESTORE_QUARANTINE_ENTRY_ID_INSTRUCTION",
    "SEMANTIC_WRITE_FILE_TOOL_NAME",
    "SEMANTIC_ALTERNATIVE_ID_BY_TOOL",
    "SEMANTIC_APPLY_PREPARED_PATCH_TOOL_NAME",
    "SEMANTIC_CLEANUP_STAGED_TOOL_NAME",
    "SEMANTIC_CONTROLLED_ALTERNATIVE_TOOL_NAMES",
    "SEMANTIC_PREPARE_GIT_CHANGE_TOOL_NAME",
    "SEMANTIC_GIT_OPERATION_TOOL_NAME",
    "SEMANTIC_PREPARE_PATCH_TOOL_NAME",
    "SEMANTIC_RESTORE_STAGED_TOOL_NAME",
    "SEMANTIC_STAGE_DELETE_TOOL_NAME",
    "SEMANTIC_TOOL_BY_ALTERNATIVE_ID",
    "STAGE_DELETE_RESTORE_HANDOFF_NOTE",
    "build_controlled_alternative_tool_schema",
    "build_agentveil_write_file_tool_schema",
    "build_semantic_controlled_alternative_tool_schema",
    "build_semantic_controlled_alternative_tool_schemas",
    "agentveil_write_file_catalog_collision",
    "controlled_alternative_target_is_ineligible",
    "discover_controlled_alternative_provider",
    "inject_agentveil_write_file_tool",
    "is_controlled_alternative_tool_name",
    "is_semantic_controlled_alternative_tool",
    "normalize_agentveil_write_file_call",
    "normalize_semantic_tool_call",
    "semantic_alternative_id_for_tool",
    "semantic_tool_name_for_alternative_id",
    "set_controlled_alternative_provider_loader",
    "validate_controlled_alternative_local_input",
    "validate_provider_descriptor",
    "validate_provider_request",
    "validate_provider_result",
    "validate_resource_locator",
]
